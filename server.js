const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error("Erreur : DATABASE_URL n'est pas configuree.");
  process.exit(1);
}

if (
  !process.env.CLOUDINARY_CLOUD_NAME ||
  !process.env.CLOUDINARY_API_KEY ||
  !process.env.CLOUDINARY_API_SECRET
) {
  console.error("Erreur : les variables Cloudinary ne sont pas configurees.");
  process.exit(1);
}

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 3 },
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg", "image/jpg", "image/png", "image/webp"];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error("Format non autorise. Utilisez JPG, PNG ou WEBP."));
    }
    cb(null, true);
  }
});

function uploadToCloudinary(buffer, folder, publicId) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      {
        folder: folder,
        public_id: publicId,
        resource_type: "image",
        transformation: [
          { width: 800, height: 800, crop: "limit" },
          { quality: "auto" },
          { fetch_format: "auto" }
        ]
      },
      (error, result) => {
        if (error) return reject(error);
        resolve(result);
      }
    );
    stream.end(buffer);
  });
}

async function deleteFromCloudinary(publicId) {
  if (!publicId) return;
  try {
    const urlParts = publicId.split("/upload/");
    if (urlParts.length < 2) return;
    let path = urlParts[1];
    if (path.startsWith("v")) path = path.replace(/^v\d+\//, "");
    const cleanId = path.replace(/\.[^.]+$/, "");
    await cloudinary.uploader.destroy(cleanId, { invalidate: true });
  } catch (error) {
    console.error("Erreur suppression Cloudinary :", error.message);
  }
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false }
});

pool.on("error", (error) => {
  console.error("Erreur de base de donnees :", error.message);
});

app.use(express.urlencoded({ extended: true, limit: "20kb" }));
app.use(express.json({ limit: "20kb" }));
app.disable("x-powered-by");

const SESSION_COOKIE = "tm_admin_session";
const SESSION_DURATION = 4 * 60 * 60 * 1000;
const PRO_COOKIE = "tm_pro_session";

const ALLOWED_STATUSES = ["pending", "under_review", "approved", "rejected", "corrections_requested"];

const STATUS_LABELS = {
  pending: "En attente",
  under_review: "En cours d'examen",
  approved: "Approuvee",
  rejected: "Refusee",
  corrections_requested: "Corrections demandees"
};

const JOB_STATUSES = ["pending", "approved", "rejected", "closed"];

const JOB_STATUS_LABELS = {
  pending: "En attente",
  approved: "Approuvee",
  rejected: "Refusee",
  closed: "Cloturee"
};

const GDPR_REQUEST_TYPES = ["access", "deletion", "rectification", "opposition"];

const GDPR_TYPE_LABELS = {
  access: "Acces aux donnees",
  deletion: "Suppression du compte",
  rectification: "Rectification",
  opposition: "Opposition"
};

const GDPR_STATUSES = ["pending", "processed", "rejected"];

const GDPR_STATUS_LABELS = {
  pending: "En attente",
  processed: "Traitee",
  rejected: "Refusee"
};

const JOB_CONTRACT_TYPES = [
  "CDI", "CDD", "Stage", "Interim", "Freelance", "Apprentissage", "Autre"
];

const OFFER_DURATION_DAYS = 15;

const CONTACT_PREFERENCES = ["whatsapp", "email"];

const CONTACT_PREFERENCE_LABELS = {
  whatsapp: "WhatsApp",
  email: "Email"
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => {
    const entities = {
      "&": "&amp;", "<": "&lt;", ">": "&gt;",
      '"': "&quot;", "'": "&#39;"
    };
    return entities[character];
  });
}

function safeEqual(first, second) {
  const firstBuffer = Buffer.from(String(first));
  const secondBuffer = Buffer.from(String(second));
  if (firstBuffer.length !== secondBuffer.length) return false;
  return crypto.timingSafeEqual(firstBuffer, secondBuffer);
}

function createSessionToken(payload) {
  const secret = process.env.ADMIN_SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("ADMIN_SESSION_SECRET doit contenir au moins 32 caracteres.");
  }
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.createHmac("sha256", secret).update(encodedPayload).digest("base64url");
  return `${encodedPayload}.${signature}`;
}

function verifySessionToken(token) {
  try {
    if (!token || !process.env.ADMIN_SESSION_SECRET) return null;
    const parts = token.split(".");
    if (parts.length !== 2) return null;
    const [encodedPayload, signature] = parts;
    const expectedSignature = crypto
      .createHmac("sha256", process.env.ADMIN_SESSION_SECRET)
      .update(encodedPayload)
      .digest("base64url");
    if (!safeEqual(signature, expectedSignature)) return null;
    const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));
    if (payload.expiresAt <= Date.now() || typeof payload.csrf !== "string") return null;
    return payload;
  } catch {
    return null;
  }
}

function readCookie(req, name) {
  const cookieHeader = req.headers.cookie || "";
  for (const item of cookieHeader.split(";")) {
    const separator = item.indexOf("=");
    if (separator === -1) continue;
    const key = item.slice(0, separator).trim();
    const value = item.slice(separator + 1).trim();
    if (key === name) return value;
  }
  return null;
}

function setSessionCookie(res, token) {
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_DURATION / 1000}`);
}

function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`);
}

function setProCookie(res, code) {
  res.setHeader("Set-Cookie", `${PRO_COOKIE}=${code}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_DURATION / 1000}`);
}

function clearProCookie(res) {
  res.setHeader("Set-Cookie", `${PRO_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`);
}

function requireAdmin(req, res, next) {
  const token = readCookie(req, SESSION_COOKIE);
  const session = verifySessionToken(token);
  if (!session) {
    clearSessionCookie(res);
    return res.redirect(303, "/admin");
  }
  req.adminSession = session;
  next();
}

function verifyCsrf(req, res, next) {
  const submittedToken = req.body.csrfToken;
  const sessionToken = req.adminSession?.csrf;
  if (typeof submittedToken !== "string" || typeof sessionToken !== "string" || !safeEqual(submittedToken, sessionToken)) {
    return res.status(403).send(
      page("Requete refusee", "<h1>Requete refusee</h1><p>Veuillez actualiser la page et reessayer.</p>", null)
    );
  }
  next();
}

function generateProCode() {
  const digits = Math.floor(10000 + Math.random() * 90000);
  return `TM${digits}`;
}

async function generateUniqueProCode() {
  let code;
  let exists = true;
  let attempts = 0;
  while (exists && attempts < 20) {
    code = generateProCode();
    const result = await pool.query("SELECT id FROM professional_applications WHERE pro_code = $1", [code]);
    exists = result.rows.length > 0;
    attempts += 1;
  }
  if (exists) throw new Error("Impossible de generer un code unique.");
  return code;
}

async function getConnectedPro(req) {
  const proCodeCookie = readCookie(req, PRO_COOKIE);
  if (!proCodeCookie) return null;
  try {
    const result = await pool.query(
      `SELECT * FROM professional_applications WHERE pro_code = $1 AND status = 'approved'`,
      [proCodeCookie]
    );
    if (!result.rows.length) return null;
    return { pro: result.rows[0], code: proCodeCookie };
  } catch (error) {
    console.error("Erreur getConnectedPro :", error.message);
    return null;
  }
}

function getDisplayName(person) {
  if (person.company_name && person.company_name.trim()) {
    return person.company_name.trim();
  }
  return person.full_name;
}

function buildMenu(proConnected) {
  if (proConnected) {
    return `
      <nav>
        <a href="/">Professionnels</a>
        <a href="/emplois">Emploi</a>
        <a href="/mon-espace-pro">Mon espace pro</a>
        <a href="/publier-emploi">📢 Publier une offre</a>
        <form action="/mon-espace-pro/logout" method="POST" style="display:inline">
          <button type="submit" style="background:transparent;border:none;color:white;padding:8px 14px;border-radius:6px;font-size:14px;font-weight:500;cursor:pointer;font-family:inherit">Deconnexion</button>
        </form>
      </nav>
    `;
  }

  return `
    <nav>
      <a href="/">Professionnels</a>
      <a href="/emplois">Emploi</a>
      <a href="/devenir-professionnel">Devenir pro</a>
      <a href="/mon-espace-pro">Espace pro</a>
      <a href="/contact">Contact</a>
    </nav>
  `;
}

function page(title, content, proConnected) {
  return `
    <!DOCTYPE html>
    <html lang="fr">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="description" content="TrouveMoi - La plateforme de mise en relation entre clients et professionnels au Benin.">
      <title>${escapeHtml(title)} - TrouveMoi</title>

      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
          padding: 0; background: #f4f7fb; color: #222;
          line-height: 1.6; min-height: 100vh;
          display: flex; flex-direction: column;
        }

        /* HEADER */

        header {
          background: linear-gradient(135deg, #087f5b 0%, #0a9d70 100%);
          color: white; padding: 18px 20px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.1);
          position: sticky; top: 0; z-index: 100;
        }

        .header-content {
          max-width: 1100px; margin: 0 auto;
          display: flex; flex-wrap: wrap;
          justify-content: space-between; align-items: center; gap: 12px;
        }

        .logo {
          font-size: 26px; font-weight: 800; color: white;
          text-decoration: none; letter-spacing: -0.5px;
          display: flex; align-items: center; gap: 8px;
        }

        .logo::before { content: "🔍"; font-size: 24px; }
        .tagline { font-size: 13px; opacity: 0.9; margin-top: 2px; }

        nav { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }

        nav a, nav button {
          color: white; text-decoration: none;
          padding: 8px 14px; border-radius: 6px;
          font-size: 14px; font-weight: 500;
          transition: background 0.2s;
        }

        nav a:hover, nav button:hover { background: rgba(255,255,255,0.15); }

        /* MAIN */

        main {
          max-width: 1100px; width: 100%;
          margin: 0 auto; padding: 24px 20px; flex: 1;
        }

        .card {
          background: white; padding: 24px; margin-bottom: 20px;
          border-radius: 12px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.06);
          transition: box-shadow 0.2s;
        }

        .card:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.08); }

        /* TITRES HIERARCHISES */

        h1 {
          font-size: 28px; margin-bottom: 16px;
          color: #087f5b; line-height: 1.3;
          border-left: 5px solid #087f5b;
          padding-left: 14px;
        }

        h2 {
          font-size: 22px; margin-bottom: 14px;
          color: #1e40af; line-height: 1.3;
          border-left: 4px solid #3b82f6;
          padding-left: 12px;
        }

        h3 {
          font-size: 18px; margin-bottom: 10px;
          color: #475467; line-height: 1.3;
          border-left: 3px solid #94a3b8;
          padding-left: 10px;
        }

        p { margin-bottom: 12px; }

        /* LABELS ET VALEURS */

        .label { font-weight: 700; color: #1a1a1a; }
        .value { color: #333; }

        /* FORMULAIRES */

        label {
          display: block; margin-top: 8px; margin-bottom: 4px;
          font-weight: 600; font-size: 14px; color: #333;
        }

        input, textarea, select {
          width: 100%; padding: 12px 14px; margin-bottom: 14px;
          border: 1px solid #ddd; border-radius: 8px;
          font-size: 15px; font-family: inherit; background: white;
          transition: border-color 0.2s, box-shadow 0.2s;
        }

        input:focus, textarea:focus, select:focus {
          outline: none; border-color: #087f5b;
          box-shadow: 0 0 0 3px rgba(8,127,91,0.1);
        }

        textarea { resize: vertical; min-height: 100px; }

        input[type="file"] {
          padding: 10px; background: #f9fafb;
          border: 2px dashed #ccc; cursor: pointer;
        }

        input[type="file"]:hover { border-color: #087f5b; background: #f0fdf9; }

        input[type="checkbox"], input[type="radio"] { width: auto; margin-right: 8px; }

        /* BOUTONS */

        button, .button {
          display: inline-block; border: none;
          background: #087f5b; color: white;
          padding: 12px 20px; border-radius: 8px;
          cursor: pointer; text-decoration: none;
          text-align: center; font-size: 15px; font-weight: 600;
          transition: background 0.2s, transform 0.1s;
          margin-right: 8px; margin-bottom: 8px;
          font-family: inherit;
        }

        button:hover, .button:hover { background: #0a6b4d; transform: translateY(-1px); }

        .danger { background: #b42318; }
        .danger:hover { background: #9a1d13; }
        .secondary { background: #475467; }
        .secondary:hover { background: #344054; }
        .warning { background: #f59e0b; }
        .warning:hover { background: #d97706; }
        .success { background: #0a9d70; }
        .success:hover { background: #087f5b; }
        .info { background: #3b82f6; }
        .info:hover { background: #1e40af; }

        .muted { color: #667085; font-size: 14px; }

        /* BOUTONS DE CONTACT */

        .contact-buttons {
          display: flex; flex-wrap: wrap; gap: 10px; margin-top: 16px;
        }

        .contact-buttons .button { flex: 1 1 140px; margin: 0; }

        .whatsapp { background: #25d366; }
        .whatsapp:hover { background: #1da851; }
        .email { background: #475467; }
        .email:hover { background: #344054; }
        .share { background: #4267b2; }
        .share:hover { background: #365899; }

        /* PHOTOS */

        .photos-grid {
          display: flex; flex-wrap: wrap; gap: 12px; margin: 16px 0;
        }

        .photos-grid img {
          max-width: 280px; max-height: 280px;
          border-radius: 10px; border: 2px solid #e5e7eb;
          object-fit: cover;
        }

        .photo-profil { border: 3px solid #087f5b !important; }
        .photo-identite { border: 3px solid #b42318 !important; }
        .photo-activite { border: 3px solid #475467 !important; }

        .photo-label {
          font-size: 12px; color: #667085;
          text-align: center; margin-top: 4px; font-weight: 600;
        }

        .photo-block { display: flex; flex-direction: column; align-items: center; }

        .help-text {
          font-size: 13px; color: #667085;
          margin-bottom: 12px; font-style: italic;
        }

        .hidden { display: none !important; }

        .actions { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }

        /* STATS */

        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 16px; margin-bottom: 24px;
        }

        .stat-card {
          background: white; padding: 24px;
          border-radius: 12px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.06);
          border-left: 4px solid #087f5b;
          transition: transform 0.2s, box-shadow 0.2s;
        }

        .stat-card:hover {
          transform: translateY(-2px);
          box-shadow: 0 6px 20px rgba(0,0,0,0.1);
        }

        .stat-card.warning { border-left-color: #f59e0b; }
        .stat-card.danger { border-left-color: #b42318; }
        .stat-card.info { border-left-color: #3b82f6; }

        .stat-icon { font-size: 32px; margin-bottom: 8px; }

        .stat-number {
          font-size: 36px; font-weight: 800;
          color: #1a1a1a; line-height: 1; margin-bottom: 6px;
        }

        .stat-label { font-size: 14px; color: #667085; font-weight: 500; }

        .stat-link {
          display: inline-block; margin-top: 10px;
          font-size: 13px; color: #087f5b;
          text-decoration: none; font-weight: 600;
        }

        .stat-link:hover { text-decoration: underline; }

        /* CODE PRO */

        .pro-code-box {
          background: linear-gradient(135deg, #087f5b 0%, #0a9d70 100%);
          color: white; padding: 24px; border-radius: 12px;
          text-align: center; margin: 16px 0;
        }

        .pro-code-value {
          font-size: 42px; font-weight: 800;
          letter-spacing: 4px; margin: 12px 0;
          font-family: "Courier New", monospace;
        }

        .pro-code-label {
          font-size: 14px; opacity: 0.9;
          text-transform: uppercase; letter-spacing: 1px;
        }

        /* BADGES */

        .badge {
          display: inline-block;
          padding: 4px 12px;
          border-radius: 20px;
          font-size: 12px;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .badge-pending { background: #fef3c7; color: #92400e; }
        .badge-approved { background: #d1fae5; color: #065f46; }
        .badge-rejected { background: #fee2e2; color: #991b1b; }
        .badge-closed { background: #e5e7eb; color: #374151; }
        .badge-processed { background: #d1fae5; color: #065f46; }
        .badge-new { background: #b42318; color: white; margin-left: 6px; padding: 2px 8px; font-size: 11px; }

        /* ALERTES */

        .alert {
          padding: 16px 20px; border-radius: 8px;
          margin-bottom: 16px; border-left: 4px solid;
        }

        .alert-success { background: #d1fae5; border-color: #0a9d70; color: #065f46; }
        .alert-danger { background: #fee2e2; border-color: #b42318; color: #991b1b; }
        .alert-warning { background: #fef3c7; border-color: #f59e0b; color: #92400e; }
        .alert-info { background: #dbeafe; border-color: #3b82f6; color: #1e40af; }

        /* BANDEAU PRO CONNECTE - BLEU PROFOND */

        .pro-welcome {
          background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
          color: white;
          padding: 28px;
          border-radius: 12px;
          margin-bottom: 20px;
          box-shadow: 0 4px 20px rgba(30,64,175,0.3);
        }

        .pro-welcome h2 {
          color: white;
          border: none;
          padding: 0;
          margin-bottom: 8px;
          font-size: 24px;
        }

        .pro-welcome p {
          opacity: 0.95;
          margin-bottom: 16px;
          font-size: 15px;
        }

        .pro-welcome .actions { margin: 0; }

        .pro-welcome .button {
          background: white;
          color: #1e40af;
        }

        .pro-welcome .button:hover {
          background: #f0f4ff;
          transform: translateY(-1px);
        }

        .pro-welcome .button.secondary {
          background: rgba(255,255,255,0.25);
          color: white;
        }

        .pro-welcome .button.secondary:hover {
          background: rgba(255,255,255,0.35);
        }

        /* BANDEAU ALERTES ADMIN */

        .admin-alerts {
          background: #fff7ed;
          border: 1px solid #fdba74;
          border-left: 5px solid #ea580c;
          padding: 20px;
          border-radius: 10px;
          margin-bottom: 20px;
        }

        .admin-alerts h3 {
          color: #9a3412;
          border: none;
          padding: 0;
          margin-bottom: 12px;
          font-size: 17px;
        }

        .admin-alerts ul {
          list-style: none;
          margin: 0;
        }

        .admin-alerts li {
          padding: 8px 0;
          border-bottom: 1px solid #fed7aa;
          color: #7c2d12;
        }

        .admin-alerts li:last-child { border-bottom: none; }

        .admin-alerts a {
          color: #9a3412;
          font-weight: 700;
          text-decoration: none;
        }

        .admin-alerts a:hover { text-decoration: underline; }

        /* GRILLE DE CARTES PROS */

        .pros-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
          gap: 20px;
          margin-top: 20px;
        }

        .pro-card {
          background: white;
          border-radius: 12px;
          overflow: hidden;
          box-shadow: 0 2px 8px rgba(0,0,0,0.08);
          transition: transform 0.2s, box-shadow 0.2s;
          display: flex;
          flex-direction: column;
        }

        .pro-card:hover {
          transform: translateY(-4px);
          box-shadow: 0 8px 24px rgba(0,0,0,0.12);
        }

        .pro-card-image {
          width: 100%;
          height: 180px;
          background: linear-gradient(135deg, #087f5b 0%, #0a9d70 100%);
          display: flex;
          align-items: center;
          justify-content: center;
          overflow: hidden;
        }

        .pro-card-image img {
          width: 100%;
          height: 100%;
          object-fit: cover;
        }

        .pro-card-image-placeholder {
          font-size: 60px;
          color: white;
          opacity: 0.5;
        }

        .pro-card-body {
          padding: 16px;
          flex: 1;
          display: flex;
          flex-direction: column;
        }

        .pro-card-profession {
          font-size: 13px;
          font-weight: 700;
          color: #087f5b;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          margin-bottom: 6px;
        }

        .pro-card-name {
          font-size: 17px;
          font-weight: 700;
          color: #1a1a1a;
          margin-bottom: 8px;
          line-height: 1.3;
        }

        .pro-card-location {
          font-size: 14px;
          color: #667085;
          margin-bottom: 14px;
        }

        .pro-card-location::before {
          content: "📍 ";
        }

        .pro-card-button {
          display: block;
          width: 100%;
          background: #087f5b;
          color: white;
          padding: 10px 16px;
          border-radius: 6px;
          text-align: center;
          text-decoration: none;
          font-weight: 600;
          font-size: 14px;
          margin-top: auto;
          transition: background 0.2s;
        }

        .pro-card-button:hover { background: #0a6b4d; }

        /* PAGE PROFIL DETAILLE */

        .pro-header {
          background: linear-gradient(135deg, #087f5b 0%, #0a9d70 100%);
          color: white;
          padding: 32px 24px;
          border-radius: 12px;
          margin-bottom: 20px;
        }

        .pro-header h1 {
          color: white;
          border: none;
          padding: 0;
          font-size: 30px;
          margin-bottom: 8px;
        }

        .pro-header .profession {
          font-size: 18px;
          opacity: 0.95;
          margin-bottom: 8px;
          font-weight: 600;
        }

        .pro-header .location {
          font-size: 15px;
          opacity: 0.9;
        }

        /* CHECKBOX BLOCK */

        .checkbox-block {
          background: #f9fafb;
          padding: 16px;
          border-radius: 8px;
          margin: 12px 0;
          border: 1px solid #e5e7eb;
        }

        .checkbox-block label {
          display: flex;
          align-items: flex-start;
          margin: 0;
          font-weight: 500;
        }

        .checkbox-block input[type="checkbox"],
        .checkbox-block input[type="radio"] {
          margin-top: 5px;
        }

        /* FOOTER */

        footer {
          background: #1a1a1a; color: #ccc;
          padding: 32px 20px 20px; margin-top: 40px;
        }

        .footer-content {
          max-width: 1100px; margin: 0 auto;
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 24px;
        }

        .footer-col h4 {
          color: white; margin-bottom: 12px;
          font-size: 15px; text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .footer-col a {
          display: block; color: #aaa;
          text-decoration: none; padding: 4px 0; font-size: 14px;
        }

        .footer-col a:hover { color: #0a9d70; }

        .footer-bottom {
          max-width: 1100px; margin: 24px auto 0;
          padding-top: 20px; border-top: 1px solid #333;
          text-align: center; font-size: 13px; color: #888;
        }

        /* RESPONSIVE */

        @media (max-width: 600px) {
          header { padding: 14px 16px; }
          .header-content { flex-direction: column; text-align: center; }
          .logo { font-size: 22px; }
          nav { justify-content: center; }
          nav a, nav button { padding: 6px 10px; font-size: 13px; }
          main { padding: 16px 12px; }
          .card { padding: 16px; }
          h1 { font-size: 22px; }
          h2 { font-size: 18px; }
          h3 { font-size: 16px; }
          .photos-grid img { max-width: 100%; }
          .contact-buttons .button { flex: 1 1 100%; }
          .stat-number { font-size: 28px; }
          .pro-code-value { font-size: 32px; letter-spacing: 2px; }
          .pros-grid { grid-template-columns: 1fr; }
          .pro-header h1 { font-size: 22px; }
        }
      </style>
    </head>

    <body>
      <header>
        <div class="header-content">
          <div>
            <a href="/" class="logo">TrouveMoi</a>
            <div class="tagline">Trouvez le bon professionnel au Benin</div>
          </div>

          ${buildMenu(proConnected)}
        </div>
      </header>

      <main>
        ${content}
      </main>

      <footer>
        <div class="footer-content">
          <div class="footer-col">
            <h4>TrouveMoi</h4>
            <p style="color:#aaa;font-size:14px">La plateforme beninoise de mise en relation entre clients et professionnels.</p>
          </div>

          <div class="footer-col">
            <h4>Navigation</h4>
            <a href="/">Professionnels</a>
            <a href="/emplois">Offres d'emploi</a>
            <a href="/devenir-professionnel">Devenir professionnel</a>
            <a href="/mon-espace-pro">Espace pro</a>
          </div>

          <div class="footer-col">
            <h4>Informations</h4>
            <a href="/a-propos">A propos</a>
            <a href="/contact">Contact</a>
            <a href="/conditions">Conditions d'utilisation</a>
            <a href="/confidentialite">Politique de confidentialite</a>
          </div>

          <div class="footer-col">
            <h4>Contact</h4>
            <a href="/contact">Nous ecrire</a>
            <a href="mailto:contact@trouvemoi.bj">contact@trouvemoi.bj</a>
          </div>
        </div>

        <div class="footer-bottom">
          &copy; ${new Date().getFullYear()} TrouveMoi. Tous droits reserves.
        </div>
      </footer>
    </body>
    </html>
  `;
}

function normalizePhone(value) {
  return String(value || "").trim().replace(/[()\s.-]/g, "");
}

function validPhone(value) {
  return /^\+?[0-9]{8,15}$/.test(value);
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 254;
}

function jobContactButtons(job) {
  const buttons = [];
  if (job.contact_phone) {
    buttons.push(`<a class="button" href="tel:${escapeHtml(normalizePhone(job.contact_phone))}">📞 Appeler le recruteur</a>`);
  }
  if (job.contact_whatsapp) {
    const whatsapp = normalizePhone(job.contact_whatsapp).replace(/^\+/, "");
    buttons.push(`<a class="button whatsapp" href="https://wa.me/${escapeHtml(whatsapp)}?text=${encodeURIComponent("Bonjour, j'ai consulte votre offre d'emploi sur TrouveMoi et je souhaite obtenir plus d'informations.")}" target="_blank" rel="noopener noreferrer">💬 Contacter sur WhatsApp</a>`);
  }
  if (job.contact_email) {
    buttons.push(`<a class="button email" href="mailto:${escapeHtml(job.contact_email)}?subject=${encodeURIComponent("Candidature - " + job.job_title)}">✉️ Envoyer un e-mail</a>`);
  }
  return buttons.length ? `<div class="contact-buttons">${buttons.join("")}</div>` : "";
}

/* PAGE D'ACCUEIL */

app.get("/", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);

    const profession = String(req.query.profession || "").trim().slice(0, 150);
    const city = String(req.query.city || "").trim().slice(0, 100);
    const neighborhood = String(req.query.neighborhood || "").trim().slice(0, 150);

    const citiesResult = await pool.query(
      "SELECT id, name FROM cities ORDER BY display_order ASC"
    );

    const professionsResult = await pool.query(
      "SELECT id, name, category FROM professions ORDER BY display_order ASC"
    );

    let query = `
      SELECT
        id, full_name, company_name, phone, phone_public, city, neighborhood,
        profession, experience, service_description, service_area, availability,
        photo_activite_url
      FROM professional_applications
      WHERE status = 'approved'
    `;

    const values = [];

    if (profession) {
      values.push(`%${profession}%`);
      query += ` AND profession ILIKE $${values.length}`;
    }

    if (city) {
      values.push(city);
      query += ` AND city = $${values.length}`;
    }

    if (neighborhood) {
      values.push(neighborhood);
      query += ` AND neighborhood = $${values.length}`;
    }

    query += " ORDER BY created_at DESC LIMIT 50";

    const result = await pool.query(query, values);

    const cityOptions = citiesResult.rows.map((c) => `
      <option value="${escapeHtml(c.name)}" ${city === c.name ? "selected" : ""}>
        ${escapeHtml(c.name)}
      </option>
    `).join("");

    let neighborhoodOptions = "";

    if (city) {
      const cityResult = await pool.query(
        "SELECT id FROM cities WHERE name = $1", [city]
      );

      if (cityResult.rows.length) {
        const neighborhoodsResult = await pool.query(
          `SELECT name FROM neighborhoods WHERE city_id = $1 ORDER BY name ASC`,
          [cityResult.rows[0].id]
        );

        neighborhoodOptions = neighborhoodsResult.rows.map((n) => `
          <option value="${escapeHtml(n.name)}" ${neighborhood === n.name ? "selected" : ""}>
            ${escapeHtml(n.name)}
          </option>
        `).join("");
      }
    }

    const professionsByCategory = {};

    for (const p of professionsResult.rows) {
      const cat = p.category || "Autres";
      if (!professionsByCategory[cat]) professionsByCategory[cat] = [];
      professionsByCategory[cat].push(p.name);
    }

    const professionOptions = Object.entries(professionsByCategory)
      .map(([category, names]) => {
        const options = names.map((name) => `
          <option value="${escapeHtml(name)}" ${profession === name ? "selected" : ""}>
            ${escapeHtml(name)}
          </option>
        `).join("");
        return `<optgroup label="${escapeHtml(category)}">${options}</optgroup>`;
      }).join("");

    /* CARTES RESUMÉES DES PROS */

    const prosCards = result.rows.map((person) => {
      const displayName = getDisplayName(person);

      const photoHtml = person.photo_activite_url
        ? `<img src="${escapeHtml(person.photo_activite_url)}" alt="${escapeHtml(person.profession)}">`
        : `<div class="pro-card-image-placeholder">👤</div>`;

      return `
        <article class="pro-card">
          <div class="pro-card-image">
            ${photoHtml}
          </div>

          <div class="pro-card-body">
            <div class="pro-card-profession">${escapeHtml(person.profession)}</div>
            <div class="pro-card-name">${escapeHtml(displayName)}</div>
            <div class="pro-card-location">${escapeHtml(person.city)}${person.neighborhood ? ` - ${escapeHtml(person.neighborhood)}` : ""}</div>

            <a class="pro-card-button" href="/pro/${encodeURIComponent(person.id)}">
              Voir le profil →
            </a>
          </div>
        </article>
      `;
    }).join("");

    const welcomeBanner = proConnected ? `
      <div class="pro-welcome">
        <h2>🎉 Bonjour ${escapeHtml(getDisplayName(proConnected.pro))} !</h2>
        <p>Votre candidature est approuvee. Vous pouvez des maintenant gerer vos offres d'emploi.</p>
        <div class="actions">
          <a class="button" href="/mon-espace-pro">🏠 Mon espace pro</a>
          <a class="button secondary" href="/mon-espace-pro">👁️ Voir mon code</a>
          <a class="button secondary" href="/publier-emploi">📢 Publier une offre</a>
        </div>
      </div>
    ` : "";

    const content = `
      ${welcomeBanner}

      <section class="card">
        <h1>Rechercher un professionnel</h1>

        <form action="/" method="GET">
          <label for="profession">Metier ou service</label>
          <select id="profession" name="profession">
            <option value="">Tous les metiers</option>
            ${professionOptions}
          </select>

          <label for="city">Ville</label>
          <select id="city" name="city">
            <option value="">Toutes les villes</option>
            ${cityOptions}
          </select>

          ${city && neighborhoodOptions ? `
            <label for="neighborhood">Quartier</label>
            <select id="neighborhood" name="neighborhood">
              <option value="">Tous les quartiers</option>
              ${neighborhoodOptions}
            </select>
          ` : ""}

          <button type="submit">Rechercher</button>
        </form>

        <a class="button" href="/devenir-professionnel">Devenir professionnel</a>
        <a class="button secondary" href="/emplois">Consulter les offres d'emploi</a>
      </section>

      <h2>Professionnels disponibles (${result.rows.length})</h2>

      ${prosCards || `
        <section class="card">
          <p>Aucun professionnel approuve ne correspond a votre recherche.</p>
        </section>
      `}

      ${result.rows.length ? `
        <div class="pros-grid">
          ${prosCards}
        </div>
      ` : ""}

      <p style="text-align:center;margin-top:32px">
        <a href="/devenir-professionnel">Proposer mes services</a>
      </p>
    `;

    res.send(page("Accueil", content, proConnected));
  } catch (error) {
    console.error("Erreur sur la page d'accueil :", error.message);
    res.status(500).send(
      page("Erreur", "<h2>Une erreur technique est survenue.</h2>", null)
    );
  }
});

/* PAGE PROFIL DETAILLE D'UN PRO */

app.get("/pro/:id", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id < 1) {
      return res.status(404).send(
        page("Profil introuvable", `
          <section class="card">
            <h2>Profil introuvable</h2>
            <p>Ce professionnel n'existe pas ou n'est plus disponible.</p>
            <a class="button" href="/">Retour a l'accueil</a>
          </section>
        `, proConnected)
      );
    }

    const result = await pool.query(
      `SELECT
        id, full_name, company_name, phone, phone_public, city, neighborhood,
        profession, experience, service_description, service_area, availability,
        photo_activite_url
       FROM professional_applications
       WHERE id = $1 AND status = 'approved'`,
      [id]
    );

    if (!result.rows.length) {
      return res.status(404).send(
        page("Profil introuvable", `
          <section class="card">
            <h2>Profil introuvable</h2>
            <p>Ce professionnel n'existe pas ou n'est plus disponible.</p>
            <a class="button" href="/">Retour a l'accueil</a>
          </section>
        `, proConnected)
      );
    }

    const person = result.rows[0];
    const displayName = getDisplayName(person);
    const phoneClean = normalizePhone(person.phone || "");
    const whatsappNumber = phoneClean.replace(/^\+/, "");
    const phonePublic = person.phone_public === true;

    const shareText = encodeURIComponent(
      "Decouvrez " + displayName + " (" + person.profession + ") sur TrouveMoi"
    );
    const shareUrl = encodeURIComponent(
      "https://trouvemoi-4mk0.onrender.com/pro/" + person.id
    );

    /* AUTRES PROS DE LA MEME VILLE */

    const sameCityResult = await pool.query(
      `SELECT id, full_name, company_name, profession, city, neighborhood, photo_activite_url
       FROM professional_applications
       WHERE status = 'approved' AND city = $1 AND id != $2
       ORDER BY created_at DESC LIMIT 4`,
      [person.city, person.id]
    );

    /* AUTRES PROS DU MEME METIER */

    const sameProfessionResult = await pool.query(
      `SELECT id, full_name, company_name, profession, city, neighborhood, photo_activite_url
       FROM professional_applications
       WHERE status = 'approved' AND profession = $1 AND id != $2
       ORDER BY created_at DESC LIMIT 4`,
      [person.profession, person.id]
    );

    /* BOUTONS DE CONTACT */

    let contactButtons = "";

    if (phonePublic && phoneClean) {
      contactButtons = `
        <div class="contact-buttons">
          <a class="button" href="tel:${escapeHtml(phoneClean)}">📞 Appeler</a>
          <a class="button whatsapp" href="https://wa.me/${escapeHtml(whatsappNumber)}?text=${encodeURIComponent("Bonjour, je vous contacte via TrouveMoi pour votre service de " + person.profession + ".")}" target="_blank" rel="noopener noreferrer">💬 WhatsApp</a>
          <a class="button share" href="https://wa.me/?text=${shareText}%20-%20${shareUrl}" target="_blank" rel="noopener noreferrer">📤 Partager</a>
        </div>
      `;
    } else {
      contactButtons = `
        <div class="alert alert-info" style="margin-top:16px">
          📩 Ce professionnel a choisi de ne pas afficher son numero publiquement.
          Pour le contacter, cliquez ci-dessous. Votre demande sera transmise
          par l'administration (cela peut prendre quelques jours).
        </div>
        <div class="contact-buttons">
          <a class="button" href="/contact?pro=${encodeURIComponent(person.id)}">📩 Contacter ce professionnel</a>
          <a class="button share" href="https://wa.me/?text=${shareText}%20-%20${shareUrl}" target="_blank" rel="noopener noreferrer">📤 Partager</a>
        </div>
      `;
    }

    /* CONSTRUCTION DES CARTES D'AUTRES PROS */

    function buildMiniCards(rows) {
      return rows.map((p) => {
        const name = getDisplayName(p);
        const photo = p.photo_activite_url
          ? `<img src="${escapeHtml(p.photo_activite_url)}" alt="${escapeHtml(p.profession)}">`
          : `<div class="pro-card-image-placeholder">👤</div>`;

        return `
          <article class="pro-card">
            <div class="pro-card-image">
              ${photo}
            </div>
            <div class="pro-card-body">
              <div class="pro-card-profession">${escapeHtml(p.profession)}</div>
              <div class="pro-card-name">${escapeHtml(name)}</div>
              <div class="pro-card-location">${escapeHtml(p.city)}</div>
              <a class="pro-card-button" href="/pro/${encodeURIComponent(p.id)}">
                Voir le profil →
              </a>
            </div>
          </article>
        `;
      }).join("");
    }

    const sameCityCards = buildMiniCards(sameCityResult.rows);
    const sameProfessionCards = buildMiniCards(sameProfessionResult.rows);

    const content = `
      <div class="pro-header">
        <h1>${escapeHtml(displayName)}</h1>
        <div class="profession">${escapeHtml(person.profession)}</div>
        <div class="location">📍 ${escapeHtml(person.city)}${person.neighborhood ? ` - ${escapeHtml(person.neighborhood)}` : ""}</div>
      </div>

      <section class="card">
        ${person.photo_activite_url ? `
          <div class="photos-grid">
            <div class="photo-block">
              <img src="${escapeHtml(person.photo_activite_url)}" alt="Photo d'activite" class="photo-activite">
              <div class="photo-label">Activite</div>
            </div>
          </div>
        ` : ""}

        ${person.experience ? `<p><span class="label">Experience :</span> <span class="value">${escapeHtml(person.experience)}</span></p>` : ""}

        <h2>Description des services</h2>
        <p>${escapeHtml(person.service_description).replace(/\n/g, "<br>")}</p>

        ${person.service_area ? `<p><span class="label">Zone d'intervention :</span> <span class="value">${escapeHtml(person.service_area)}</span></p>` : ""}
        ${person.availability ? `<p><span class="label">Disponibilite :</span> <span class="value">${escapeHtml(person.availability)}</span></p>` : ""}

        ${contactButtons}

        <p style="margin-top:24px">
          <a class="button secondary" href="/">← Retour a l'accueil</a>
        </p>
      </section>

      ${sameProfessionCards ? `
        <h2>Autres professionnels en ${escapeHtml(person.profession)}</h2>
        <div class="pros-grid" style="margin-bottom:24px">
          ${sameProfessionCards}
        </div>
      ` : ""}

      ${sameCityCards ? `
        <h2>Autres professionnels a ${escapeHtml(person.city)}</h2>
        <div class="pros-grid" style="margin-bottom:24px">
          ${sameCityCards}
        </div>
      ` : ""}
    `;

    res.send(page(displayName, content, proConnected));
  } catch (error) {
    console.error("Erreur page profil :", error.message);
    res.status(500).send(
      page("Erreur", "<h2>Une erreur technique est survenue.</h2>", null)
    );
  }
});

/* FORMULAIRE PROFESSIONNEL */

app.get("/devenir-professionnel", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);

    const citiesResult = await pool.query(
      "SELECT id, name FROM cities ORDER BY display_order ASC"
    );

    const professionsResult = await pool.query(
      "SELECT id, name, category FROM professions ORDER BY display_order ASC"
    );

    const cityOptions = citiesResult.rows.map((c) => `
      <option value="${escapeHtml(c.name)}">${escapeHtml(c.name)}</option>
    `).join("");

    const professionsByCategory = {};

    for (const p of professionsResult.rows) {
      const cat = p.category || "Autres";
      if (!professionsByCategory[cat]) professionsByCategory[cat] = [];
      professionsByCategory[cat].push(p.name);
    }

    const professionOptions = Object.entries(professionsByCategory)
      .map(([category, names]) => {
        const options = names.map((name) => `
          <option value="${escapeHtml(name)}">${escapeHtml(name)}</option>
        `).join("");
        return `<optgroup label="${escapeHtml(category)}">${options}</optgroup>`;
      }).join("");

    const content = `
      <section class="card">
        <h1>Devenir professionnel sur TrouveMoi</h1>

        <p>
          Remplissez le formulaire pour soumettre votre candidature.
          Votre profil sera examine par notre equipe avant publication.
        </p>

        <p class="help-text">
          Une fois approuve, vous recevrez un code professionnel unique
          (ex : TM12345) qui vous permettra de publier des offres d'emploi
          depuis votre espace personnel.
        </p>

        <form action="/candidatures" method="POST" enctype="multipart/form-data">
          <label for="full_name">Nom et prenoms *</label>
          <input id="full_name" name="full_name" required maxlength="150">

          <label for="company_name">Nom de la societe ou de l'etablissement (facultatif)</label>
          <input id="company_name" name="company_name" maxlength="200" placeholder="Ex. : Ets Dupont & Fils">
          <p class="help-text">
            Si vous remplissez ce champ, c'est ce nom qui apparaitra publiquement sur la plateforme.
            Sinon, votre nom et prenom s'afficheront.
          </p>

          <label for="phone">Telephone *</label>
          <input id="phone" name="phone" type="tel" required maxlength="30" placeholder="+229...">

          <div class="checkbox-block">
            <label>
              <input type="checkbox" name="phone_public" value="yes" checked>
              <span>
                <strong>J'accepte que mon numero de telephone soit visible publiquement</strong>
                <br>
                <span class="muted">
                  Cela permet aux clients de vous contacter directement
                  (appel ou WhatsApp) depuis la plateforme.
                </span>
              </span>
            </label>

            <div class="alert alert-warning" style="margin-top:12px;margin-bottom:0">
              ⚠️ <strong>Si vous refusez</strong> que votre numero soit public :
              <ul style="margin-left:20px;margin-top:8px">
                <li>Les clients ne pourront <strong>PAS</strong> vous contacter directement</li>
                <li>Ils devront passer par l'administration de TrouveMoi</li>
                <li>Votre mise en relation prendra <strong>PLUS DE TEMPS</strong> (delai administratif)</li>
                <li>Vous risquez de perdre des opportunites</li>
              </ul>
              <p style="margin-top:8px;margin-bottom:0">
                <strong>Nous vous recommandons fortement de laisser cette case cochee.</strong>
              </p>
            </div>
          </div>

          <h3>Comment souhaitez-vous recevoir votre code professionnel ? *</h3>

          <p class="help-text">
            Apres approbation de votre candidature, nous vous enverrons votre code
            professionnel unique. Choisissez le moyen qui vous convient le mieux.
          </p>

          <div class="checkbox-block">
            <label>
              <input type="radio" name="contact_preference" value="whatsapp" required>
              <span>
                <strong>📱 Par WhatsApp</strong>
                <br>
                <span class="muted">Nous vous enverrons votre code par WhatsApp.</span>
              </span>
            </label>

            <div id="whatsapp-number-block" class="hidden" style="margin-top:12px;margin-left:30px">
              <label for="whatsapp_number">Numero WhatsApp (si different de votre numero principal)</label>
              <input id="whatsapp_number" name="whatsapp_number" type="tel" maxlength="30" placeholder="+229...">
            </div>
          </div>

          <div class="checkbox-block">
            <label>
              <input type="radio" name="contact_preference" value="email" required>
              <span>
                <strong>✉️ Par email</strong>
                <br>
                <span class="muted">Nous vous enverrons votre code par email.</span>
              </span>
            </label>

            <div id="email-block" class="hidden" style="margin-top:12px;margin-left:30px">
              <label for="contact_email">Adresse email *</label>
              <input id="contact_email" name="contact_email" type="email" maxlength="254" placeholder="vous@exemple.com">
            </div>
          </div>

          <label for="city">Ville *</label>
          <select id="city" name="city" required>
            <option value="">Choisissez votre ville</option>
            ${cityOptions}
          </select>

          <label for="neighborhood">Quartier</label>
          <select id="neighborhood" name="neighborhood">
            <option value="">Choisissez d'abord une ville</option>
          </select>

          <div id="neighborhood-other-block" class="hidden">
            <label for="neighborhood_other">Precisez votre quartier</label>
            <input id="neighborhood_other" name="neighborhood_other" maxlength="150" placeholder="Ex. : mon quartier">
          </div>

          <label for="profession">Profession ou service propose *</label>
          <select id="profession" name="profession" required>
            <option value="">Choisissez un metier</option>
            ${professionOptions}
            <option value="__AUTRE__">Autre (precisez)</option>
          </select>

          <div id="profession-other-block" class="hidden">
            <label for="profession_other">Precisez votre metier ou service *</label>
            <input id="profession_other" name="profession_other" maxlength="150" placeholder="Ex. : reparateur de drones">
          </div>

          <label for="experience">Experience</label>
          <select id="experience" name="experience">
            <option value="">Selectionnez une option</option>
            <option value="Debutant">Debutant</option>
            <option value="Moins de 2 ans">Moins de 2 ans</option>
            <option value="2 a 5 ans">2 a 5 ans</option>
            <option value="Plus de 5 ans">Plus de 5 ans</option>
          </select>

          <label for="service_description">Description des services *</label>
          <textarea id="service_description" name="service_description" rows="5" required maxlength="3000" placeholder="Decrivez vos services, votre savoir-faire, vos specialites..."></textarea>

          <label for="service_area">Zones d'intervention</label>
          <input id="service_area" name="service_area" maxlength="300" placeholder="Ex. : Cotonou et environs">

          <label for="availability">Disponibilite</label>
          <select id="availability" name="availability">
            <option value="">Selectionnez une option</option>
            <option value="Disponible immediatement">Disponible immediatement</option>
            <option value="Sur rendez-vous">Sur rendez-vous</option>
            <option value="A temps partiel">A temps partiel</option>
          </select>

          <hr style="margin:24px 0;border:none;border-top:1px solid #e5e7eb">

          <h3>Photos</h3>

          <p class="help-text">
            Formats acceptes : JPG, PNG, WEBP. Taille max : 5 Mo par photo.
          </p>

          <label for="photo_profil">Photo de profil * (privee, visible par l'administration)</label>
          <input id="photo_profil" name="photo_profil" type="file" accept="image/jpeg,image/jpg,image/png,image/webp" required>

          <label for="photo_identite">Photo d'identite * (privee, visible par l'administration)</label>
          <input id="photo_identite" name="photo_identite" type="file" accept="image/jpeg,image/jpg,image/png,image/webp" required>

          <label for="photo_activite">Photo d'activite (optionnelle, visible publiquement)</label>
          <input id="photo_activite" name="photo_activite" type="file" accept="image/jpeg,image/jpg,image/png,image/webp">

          <div class="checkbox-block">
            <label>
              <input type="checkbox" name="gdpr_consent" value="yes" required>
              <span>
                J'accepte que mes donnees soient traitees conformement a la
                <a href="/confidentialite" target="_blank">Politique de confidentialite</a>.
                Je dispose de droits d'acces, de rectification, de suppression et d'opposition.
              </span>
            </label>
          </div>

          <button type="submit">Envoyer ma candidature</button>
        </form>

        <p><a href="/">Retour a l'accueil</a></p>
      </section>

      <script>
        const citySelect = document.getElementById('city');
        const neighborhoodSelect = document.getElementById('neighborhood');
        const neighborhoodOtherBlock = document.getElementById('neighborhood-other-block');
        const professionSelect = document.getElementById('profession');
        const professionOtherBlock = document.getElementById('profession-other-block');
        const whatsappRadio = document.querySelector('input[name="contact_preference"][value="whatsapp"]');
        const emailRadio = document.querySelector('input[name="contact_preference"][value="email"]');
        const whatsappNumberBlock = document.getElementById('whatsapp-number-block');
        const emailBlock = document.getElementById('email-block');

        citySelect.addEventListener('change', async function() {
          const city = citySelect.value;
          neighborhoodSelect.innerHTML = '';

          if (!city) {
            neighborhoodSelect.innerHTML = '<option value="">Choisissez d\\'abord une ville</option>';
            neighborhoodOtherBlock.classList.add('hidden');
            return;
          }

          neighborhoodSelect.innerHTML = '<option value="">Chargement...</option>';

          try {
            const response = await fetch('/api/neighborhoods?city=' + encodeURIComponent(city));
            const data = await response.json();

            neighborhoodSelect.innerHTML = '<option value="">Choisissez un quartier</option>';

            for (const n of data.neighborhoods) {
              const opt = document.createElement('option');
              opt.value = n;
              opt.textContent = n;
              neighborhoodSelect.appendChild(opt);
            }

            const otherOpt = document.createElement('option');
            otherOpt.value = '__AUTRE__';
            otherOpt.textContent = 'Autre (precisez)';
            neighborhoodSelect.appendChild(otherOpt);

            neighborhoodOtherBlock.classList.remove('hidden');
          } catch (e) {
            neighborhoodSelect.innerHTML = '<option value="">Erreur de chargement</option>';
          }
        });

        neighborhoodSelect.addEventListener('change', function() {
          if (neighborhoodSelect.value === '__AUTRE__') {
            neighborhoodOtherBlock.classList.remove('hidden');
          }
        });

        professionSelect.addEventListener('change', function() {
          if (professionSelect.value === '__AUTRE__') {
            professionOtherBlock.classList.remove('hidden');
          } else {
            professionOtherBlock.classList.add('hidden');
          }
        });

        whatsappRadio.addEventListener('change', function() {
          if (whatsappRadio.checked) {
            whatsappNumberBlock.classList.remove('hidden');
            emailBlock.classList.add('hidden');
          }
        });

        emailRadio.addEventListener('change', function() {
          if (emailRadio.checked) {
            emailBlock.classList.remove('hidden');
            whatsappNumberBlock.classList.add('hidden');
          }
        });
      </script>
    `;

    res.send(page("Devenir professionnel", content, proConnected));
  } catch (error) {
    console.error("Erreur sur le formulaire professionnel :", error.message);
    res.status(500).send(
      page("Erreur", "<h2>Une erreur technique est survenue.</h2>", null)
    );
  }
});

/* API QUARTIERS */

app.get("/api/neighborhoods", async (req, res) => {
  try {
    const city = String(req.query.city || "").trim();

    if (!city) {
      return res.json({ neighborhoods: [] });
    }

    const cityResult = await pool.query(
      "SELECT id FROM cities WHERE name = $1", [city]
    );

    if (!cityResult.rows.length) {
      return res.json({ neighborhoods: [] });
    }

    const neighborhoodsResult = await pool.query(
      `SELECT name FROM neighborhoods WHERE city_id = $1 ORDER BY name ASC`,
      [cityResult.rows[0].id]
    );

    res.json({
      neighborhoods: neighborhoodsResult.rows.map((n) => n.name)
    });
  } catch (error) {
    console.error("Erreur API quartiers :", error.message);
    res.status(500).json({ neighborhoods: [] });
  }
});

/* ENREGISTREMENT DES CANDIDATURES */

app.post(
  "/candidatures",
  upload.fields([
    { name: "photo_profil", maxCount: 1 },
    { name: "photo_identite", maxCount: 1 },
    { name: "photo_activite", maxCount: 1 }
  ]),
  async (req, res) => {
    const {
      full_name, company_name, phone, phone_public, city, neighborhood, neighborhood_other,
      profession, profession_other, experience, service_description,
      service_area, availability, gdpr_consent,
      contact_preference, whatsapp_number, contact_email
    } = req.body;

    const files = req.files || {};
    const photoProfil = files.photo_profil?.[0];
    const photoIdentite = files.photo_identite?.[0];
    const photoActivite = files.photo_activite?.[0];

    if (gdpr_consent !== "yes") {
      return res.status(400).send(
        page("Consentement requis", `
          <section class="card">
            <h2>Consentement RGPD obligatoire</h2>
            <p>Vous devez accepter la Politique de confidentialite pour soumettre votre candidature.</p>
            <a href="/devenir-professionnel">Retour au formulaire</a>
          </section>
        `, null)
      );
    }

    const pref = typeof contact_preference === "string" ? contact_preference.trim() : "";

    if (!CONTACT_PREFERENCES.includes(pref)) {
      return res.status(400).send(
        page("Choix de contact manquant", `
          <section class="card">
            <h2>Vous devez choisir comment recevoir votre code</h2>
            <p>Retournez au formulaire et selectionnez WhatsApp ou Email.</p>
            <a href="/devenir-professionnel">Retour au formulaire</a>
          </section>
        `, null)
      );
    }

    let finalWhatsappNumber = null;
    let finalContactEmail = null;

    if (pref === "whatsapp") {
      finalWhatsappNumber = typeof whatsapp_number === "string" && whatsapp_number.trim()
        ? normalizePhone(whatsapp_number).slice(0, 30)
        : normalizePhone(phone).slice(0, 30);

      if (!validPhone(finalWhatsappNumber)) {
        return res.status(400).send(
          page("Numero WhatsApp invalide", `
            <section class="card">
              <h2>Le numero WhatsApp est invalide.</h2>
              <a href="/devenir-professionnel">Retour au formulaire</a>
            </section>
          `, null)
        );
      }
    }

    if (pref === "email") {
      finalContactEmail = typeof contact_email === "string" ? contact_email.trim().slice(0, 254) : "";

      if (!finalContactEmail || !validEmail(finalContactEmail)) {
        return res.status(400).send(
          page("Email invalide", `
            <section class="card">
              <h2>L'adresse email est invalide.</h2>
              <a href="/devenir-professionnel">Retour au formulaire</a>
            </section>
          `, null)
        );
      }
    }

    let finalNeighborhood = null;

    if (neighborhood === "__AUTRE__") {
      finalNeighborhood = typeof neighborhood_other === "string"
        ? neighborhood_other.trim().slice(0, 150) || null : null;
    } else if (typeof neighborhood === "string" && neighborhood.trim()) {
      finalNeighborhood = neighborhood.trim().slice(0, 150);
    }

    let finalProfession = null;

    if (profession === "__AUTRE__") {
      finalProfession = typeof profession_other === "string"
        ? profession_other.trim().slice(0, 150) || null : null;
    } else if (typeof profession === "string" && profession.trim()) {
      finalProfession = profession.trim().slice(0, 150);
    }

    if (
      typeof full_name !== "string" ||
      typeof phone !== "string" ||
      typeof city !== "string" ||
      typeof service_description !== "string" ||
      !full_name.trim() || !phone.trim() || !city.trim() ||
      !finalProfession || !service_description.trim()
    ) {
      return res.status(400).send(
        page("Informations manquantes", `
          <section class="card">
            <h2>Informations manquantes ou invalides</h2>
            <p>Verifiez que vous avez bien rempli le nom, le telephone, la ville, le metier et la description.</p>
            <a href="/devenir-professionnel">Retour au formulaire</a>
          </section>
        `, null)
      );
    }

    if (!photoProfil || !photoIdentite) {
      return res.status(400).send(
        page("Photos obligatoires", `
          <section class="card">
            <h2>Photos obligatoires manquantes</h2>
            <p>La photo de profil et la photo d'identite sont obligatoires.</p>
            <a href="/devenir-professionnel">Retour au formulaire</a>
          </section>
        `, null)
      );
    }

    let photoProfilUrl = null;
    let photoIdentiteUrl = null;
    let photoActiviteUrl = null;

    try {
      const timestamp = Date.now();

      const profilResult = await uploadToCloudinary(
        photoProfil.buffer, "trouvemoi/profils", `profil_${timestamp}`
      );
      photoProfilUrl = profilResult.secure_url;

      const identiteResult = await uploadToCloudinary(
        photoIdentite.buffer, "trouvemoi/identites", `identite_${timestamp}`
      );
      photoIdentiteUrl = identiteResult.secure_url;

      if (photoActivite) {
        const activiteResult = await uploadToCloudinary(
          photoActivite.buffer, "trouvemoi/activites", `activite_${timestamp}`
        );
        photoActiviteUrl = activiteResult.secure_url;
      }
    } catch (uploadError) {
      console.error("Erreur d'upload Cloudinary :", uploadError.message);
      return res.status(500).send(
        page("Erreur d'upload", `
          <section class="card">
            <h2>Impossible de televerser les photos.</h2>
            <p>Veuillez reessayer avec des images plus petites.</p>
            <a href="/devenir-professionnel">Retour au formulaire</a>
          </section>
        `, null)
      );
    }

    const phoneIsPublic = phone_public === "yes";

    const finalCompanyName = typeof company_name === "string" && company_name.trim()
      ? company_name.trim().slice(0, 200)
      : null;

    try {
      const result = await pool.query(`
        INSERT INTO professional_applications (
          full_name, company_name, phone, phone_public, city, neighborhood, profession,
          experience, service_description, service_area, availability, npi,
          photo_profil_url, photo_identite_url, photo_activite_url,
          contact_preference, whatsapp_number, contact_email,
          pro_code, status
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,$12,$13,$14,$15,$16,$17,NULL,'pending')
        RETURNING id
      `, [
        full_name.trim().slice(0, 150),
        finalCompanyName,
        phone.trim().slice(0, 30),
        phoneIsPublic,
        city.trim().slice(0, 100),
        finalNeighborhood,
        finalProfession,
        typeof experience === "string" ? experience.slice(0, 100) || null : null,
        service_description.trim().slice(0, 3000),
        typeof service_area === "string" ? service_area.trim().slice(0, 300) || null : null,
        typeof availability === "string" ? availability.slice(0, 100) || null : null,
        photoProfilUrl,
        photoIdentiteUrl,
        photoActiviteUrl,
        pref,
        finalWhatsappNumber,
        finalContactEmail
      ]);

      res.status(201).send(
        page("Candidature envoyee", `
          <section class="card">
            <h1>Candidature envoyee avec succes !</h1>
            <p>Votre candidature a bien ete enregistree.</p>
            <p><span class="label">Reference :</span> <span class="value">${escapeHtml(result.rows[0].id)}</span></p>
            <p>Votre profil ne sera visible qu'apres approbation.</p>
            <p class="help-text">
              Une fois approuve, vous recevrez votre code professionnel unique
              ${pref === "whatsapp" ? "par WhatsApp" : "par email"}.
            </p>
            <a class="button" href="/">Retour a l'accueil</a>
          </section>
        `, null)
      );
    } catch (error) {
      console.error("Erreur lors de l'enregistrement :", error.message);
      res.status(500).send(
        page("Erreur", "<section class='card'><h2>Impossible d'enregistrer la candidature.</h2><p>Veuillez reessayer plus tard.</p></section>", null)
      );
    }
  }
);

/* PAGE DE RECHERCHE DES EMPLOIS */

app.get("/emplois", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);

    const keyword = String(req.query.keyword || "").trim().slice(0, 150);
    const city = String(req.query.city || "").trim().slice(0, 100);
    const contract = String(req.query.contract || "").trim().slice(0, 50);

    let query = `
      SELECT
        id, company_name, job_title, city, contract_type, salary,
        description, qualifications, contact_phone, contact_whatsapp,
        contact_email, deadline, created_at, expires_at
      FROM job_offers
      WHERE status = 'approved'
        AND (deadline IS NULL OR deadline >= CURRENT_DATE)
        AND (expires_at IS NULL OR expires_at > NOW())
    `;

    const values = [];

    if (keyword) {
      values.push(`%${keyword}%`);
      query += ` AND (job_title ILIKE $${values.length} OR company_name ILIKE $${values.length} OR description ILIKE $${values.length})`;
    }

    if (city) {
      values.push(`%${city}%`);
      query += ` AND city ILIKE $${values.length}`;
    }

    if (contract && JOB_CONTRACT_TYPES.includes(contract)) {
      values.push(contract);
      query += ` AND contract_type = $${values.length}`;
    }

    query += " ORDER BY created_at DESC LIMIT 100";

    const result = await pool.query(query, values);

    const jobs = result.rows.map((job) => `
      <article class="card">
        <h2>${escapeHtml(job.job_title)}</h2>
        <p><span class="label">Entreprise :</span> <span class="value">${escapeHtml(job.company_name)}</span></p>
        <p><span class="label">Ville :</span> <span class="value">${escapeHtml(job.city)}</span></p>
        <p><span class="label">Contrat :</span> <span class="value">${escapeHtml(job.contract_type)}</span></p>
        ${job.salary ? `<p><span class="label">Salaire :</span> <span class="value">${escapeHtml(job.salary)}</span></p>` : ""}
        <p>${escapeHtml(job.description).replace(/\n/g, "<br>")}</p>
        ${job.qualifications ? `<p><span class="label">Profil recherche :</span> <span class="value">${escapeHtml(job.qualifications).replace(/\n/g, "<br>")}</span></p>` : ""}
        ${job.deadline ? `<p><span class="label">Date limite :</span> <span class="value">${escapeHtml(job.deadline)}</span></p>` : ""}
        ${jobContactButtons(job)}
      </article>
    `).join("");

    const contractOptions = JOB_CONTRACT_TYPES.map((type) => `
      <option value="${escapeHtml(type)}" ${contract === type ? "selected" : ""}>
        ${escapeHtml(type)}
      </option>
    `).join("");

    res.send(
      page("Offres d'emploi", `
        <section class="card">
          <h1>Rechercher un emploi</h1>

          <form action="/emplois" method="GET">
            <label for="keyword">Metier, poste ou entreprise</label>
            <input id="keyword" name="keyword" value="${escapeHtml(keyword)}" placeholder="Ex. : commercial">

            <label for="city">Ville</label>
            <input id="city" name="city" value="${escapeHtml(city)}" placeholder="Ex. : Cotonou">

            <label for="contract">Type de contrat</label>
            <select id="contract" name="contract">
              <option value="">Tous les contrats</option>
              ${contractOptions}
            </select>

            <button type="submit">Rechercher</button>
          </form>

          <a class="button" href="/publier-emploi">Publier une offre (pros uniquement)</a>
        </section>

        <h2>Offres disponibles (${result.rows.length})</h2>

        ${jobs || `
          <section class="card">
            <p>Aucune offre ne correspond a votre recherche pour le moment.</p>
          </section>
        `}
      `, proConnected)
    );
  } catch (error) {
    console.error("Erreur lors de la recherche d'emplois :", error.message);
    res.status(500).send(
      page("Erreur", "<section class='card'><h2>Impossible de charger les offres d'emploi.</h2></section>", null)
    );
  }
});

/* FORMULAIRE DE PUBLICATION D'EMPLOI */

app.get("/publier-emploi", async (req, res) => {
  const proConnected = await getConnectedPro(req);

  if (!proConnected) {
    return res.send(page("Publier une offre", `
      <section class="card">
        <div class="alert alert-warning">
          ⚠️ Pour publier une offre d'emploi, vous devez etre un
          <strong>professionnel approuve sur TrouveMoi</strong>.
        </div>

        <h1>Publier une offre d'emploi</h1>

        <p>
          La publication d'offres d'emploi est reservee aux professionnels
          verifies de la plateforme. Cette regle nous permet de lutter
          efficacement contre les arnaques.
        </p>

        <h2>Vous etes deja professionnel sur TrouveMoi ?</h2>

        <p>Connectez-vous avec votre code professionnel :</p>

        <form action="/mon-espace-pro/login" method="POST">
          <label for="pro_code">Code professionnel</label>
          <input id="pro_code" name="pro_code" required maxlength="10" placeholder="TM12345" style="text-transform:uppercase">

          <button type="submit">Se connecter</button>
        </form>

        <h2>Vous n'etes pas encore inscrit ?</h2>

        <p>
          Inscrivez-vous comme professionnel, faites verifier votre identite,
          et recevez votre code professionnel unique.
        </p>

        <a class="button" href="/devenir-professionnel">Devenir professionnel</a>
        <a class="button secondary" href="/contact">Nous contacter</a>
      </section>
    `, null));
  }

  const contractOptions = JOB_CONTRACT_TYPES.map((type) => `
    <option value="${escapeHtml(type)}">${escapeHtml(type)}</option>
  `).join("");

  res.send(page("Publier une offre", `
    <section class="card">
      <div class="alert alert-success">
        ✅ Connecte en tant que <strong>${escapeHtml(getDisplayName(proConnected.pro))}</strong>
        (${escapeHtml(proConnected.pro.profession)}) — Code : <strong>${escapeHtml(proConnected.code)}</strong>
      </div>

      <h1>Publier une offre d'emploi</h1>

      <p>
        Votre offre sera examinee par l'administration avant publication.
        Duree de publication : <strong>${OFFER_DURATION_DAYS} jours</strong>,
        renouvelable depuis votre espace personnel.
      </p>

      <form action="/offres-emploi" method="POST">
        <label for="company_name">Nom de l'entreprise ou du recruteur *</label>
        <input id="company_name" name="company_name" required maxlength="200" value="${escapeHtml(getDisplayName(proConnected.pro))}">

        <label for="job_title">Intitule du poste *</label>
        <input id="job_title" name="job_title" required maxlength="200">

        <label for="city">Ville *</label>
        <input id="city" name="city" required maxlength="100" value="${escapeHtml(proConnected.pro.city)}">

        <label for="contract_type">Type de contrat *</label>
        <select id="contract_type" name="contract_type" required>
          <option value="">Choisir</option>
          ${contractOptions}
        </select>

        <label for="salary">Salaire (facultatif)</label>
        <input id="salary" name="salary" maxlength="100" placeholder="Ex. : 100 000 FCFA/mois">

        <label for="description">Description du poste *</label>
        <textarea id="description" name="description" required maxlength="8000" rows="6"></textarea>

        <label for="qualifications">Qualifications et competences recherchees</label>
        <textarea id="qualifications" name="qualifications" maxlength="4000" rows="4"></textarea>

        <fieldset style="border:1px solid #ddd;border-radius:8px;padding:14px">
          <legend>Moyens de contact (au moins un obligatoire) *</legend>

          <label><input style="width:auto" type="checkbox" id="use_phone" name="use_phone" value="yes"> Appel direct</label>
          <label for="contact_phone">Numero de telephone</label>
          <input id="contact_phone" name="contact_phone" type="tel" maxlength="30" placeholder="+229...">

          <label><input style="width:auto" type="checkbox" id="use_whatsapp" name="use_whatsapp" value="yes"> WhatsApp</label>
          <label for="contact_whatsapp">Numero WhatsApp</label>
          <input id="contact_whatsapp" name="contact_whatsapp" type="tel" maxlength="30" placeholder="+229...">

          <label><input style="width:auto" type="checkbox" id="use_email" name="use_email" value="yes"> E-mail</label>
          <label for="contact_email">Adresse e-mail</label>
          <input id="contact_email" name="contact_email" type="email" maxlength="254" placeholder="recrutement@entreprise.com">
        </fieldset>

        <label for="deadline">Date limite de candidature (facultatif)</label>
        <input id="deadline" name="deadline" type="date">

        <button type="submit">Soumettre l'offre</button>
      </form>

      <p><a href="/mon-espace-pro">Mon espace pro</a> — <a href="/emplois">Voir les offres</a></p>
    </section>

    <script>
      const form = document.querySelector('form');
      form.addEventListener('submit', function(event) {
        const methods = [
          ['use_phone', 'contact_phone'],
          ['use_whatsapp', 'contact_whatsapp'],
          ['use_email', 'contact_email']
        ];
        const selected = methods.filter(([check]) => document.getElementById(check).checked);
        if (!selected.length) {
          event.preventDefault();
          alert('Choisissez au moins un moyen de contact.');
          return;
        }
        const missing = selected.find(([check, field]) => !document.getElementById(field).value.trim());
        if (missing) {
          event.preventDefault();
          alert('Veuillez renseigner les coordonnees de chaque moyen de contact selectionne.');
        }
      });
    </script>
  `, proConnected));
});

/* ENREGISTREMENT DES OFFRES */

app.post("/offres-emploi", async (req, res) => {
  const proConnected = await getConnectedPro(req);

  if (!proConnected) {
    clearProCookie(res);
    return res.status(403).send(
      page("Acces refuse", `
        <section class="card">
          <h2>Acces refuse</h2>
          <p>Vous devez etre connecte en tant que professionnel verifie pour publier une offre.</p>
          <a class="button" href="/publier-emploi">Retour</a>
        </section>
      `, null)
    );
  }

  const {
    company_name, job_title, city, contract_type, salary, description,
    qualifications, contact_phone, contact_whatsapp, contact_email,
    deadline, use_phone, use_whatsapp, use_email
  } = req.body;

  const company = typeof company_name === "string" ? company_name.trim() : "";
  const title = typeof job_title === "string" ? job_title.trim() : "";
  const jobCity = typeof city === "string" ? city.trim() : "";
  const contract = typeof contract_type === "string" ? contract_type.trim() : "";
  const jobDescription = typeof description === "string" ? description.trim() : "";

  const phone = use_phone === "yes" && typeof contact_phone === "string" ? normalizePhone(contact_phone) : null;
  const whatsapp = use_whatsapp === "yes" && typeof contact_whatsapp === "string" ? normalizePhone(contact_whatsapp) : null;
  const email = use_email === "yes" && typeof contact_email === "string" ? contact_email.trim() : null;
  const jobDeadline = typeof deadline === "string" && deadline.trim() ? deadline.trim() : null;

  if (!company || !title || !jobCity || !jobDescription || !JOB_CONTRACT_TYPES.includes(contract)) {
    return res.status(400).send(
      page("Informations manquantes", `
        <section class="card">
          <h2>Informations obligatoires manquantes ou invalides.</h2>
          <a href="/publier-emploi">Retour au formulaire</a>
        </section>
      `, proConnected)
    );
  }

  if (!phone && !whatsapp && !email) {
    return res.status(400).send(
      page("Contact obligatoire", `
        <section class="card">
          <h2>Choisissez au moins un moyen de contact et renseignez ses coordonnees.</h2>
          <a href="/publier-emploi">Retour au formulaire</a>
        </section>
      `, proConnected)
    );
  }

  try {
    await pool.query(`
      INSERT INTO job_offers (
        company_name, job_title, city, contract_type, salary, description,
        qualifications, contact_phone, contact_whatsapp, contact_email,
        deadline, status, pro_id, expires_at
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending',$12, NOW() + INTERVAL '${OFFER_DURATION_DAYS} days')
    `, [
      company.slice(0, 200), title.slice(0, 200), jobCity.slice(0, 100), contract,
      typeof salary === "string" ? salary.trim().slice(0, 100) || null : null,
      jobDescription.slice(0, 8000),
      typeof qualifications === "string" ? qualifications.trim().slice(0, 4000) || null : null,
      phone, whatsapp, email, jobDeadline, proConnected.pro.id
    ]);

    res.status(201).send(
      page("Offre soumise", `
        <section class="card">
          <h1>Votre offre a bien ete soumise</h1>
          <p>Merci ! Votre offre est en attente de verification par l'administration.</p>
          <p>Duree de publication prevue : ${OFFER_DURATION_DAYS} jours apres approbation.</p>
          <a class="button" href="/mon-espace-pro">Mon espace pro</a>
          <a class="button secondary" href="/emplois">Voir les offres</a>
        </section>
      `, proConnected)
    );
  } catch (error) {
    console.error("Erreur lors de l'enregistrement de l'offre :", error.message);
    res.status(500).send(
      page("Erreur", `
        <section class="card">
          <h2>Impossible d'enregistrer l'offre pour le moment.</h2>
          <p>Veuillez reessayer plus tard.</p>
        </section>
      `, proConnected)
    );
  }
});

/* ESPACE PROFESSIONNEL */

app.get("/mon-espace-pro", async (req, res) => {
  const proConnected = await getConnectedPro(req);

  if (!proConnected) {
    return res.send(page("Espace pro", `
      <section class="card">
        <h1>Mon espace professionnel</h1>
        <p>Connectez-vous avec votre code professionnel pour gerer vos offres d'emploi.</p>

        <form action="/mon-espace-pro/login" method="POST">
          <label for="pro_code">Code professionnel</label>
          <input id="pro_code" name="pro_code" required maxlength="10" placeholder="TM12345" style="text-transform:uppercase;font-size:20px;letter-spacing:2px;text-align:center;font-family:'Courier New',monospace">
          <button type="submit">Se connecter</button>
        </form>

        <p class="help-text" style="margin-top:16px">
          Pas encore de code ? Vous recevrez votre code apres approbation
          de votre candidature par l'administration.
        </p>

        <p>
          <a href="/devenir-professionnel">Devenir professionnel</a> —
          <a href="/contact">Contacter l'administration</a>
        </p>
      </section>
    `, null));
  }

  let offers = [];
  let gdprRequests = [];

  try {
    const offersResult = await pool.query(
      `SELECT id, company_name, job_title, city, contract_type, salary,
              description, qualifications, contact_phone, contact_whatsapp,
              contact_email, deadline, status, created_at, expires_at
       FROM job_offers
       WHERE pro_id = $1
       ORDER BY created_at DESC`,
      [proConnected.pro.id]
    );

    offers = offersResult.rows;

    const gdprResult = await pool.query(
      `SELECT id, request_type, status, created_at, processed_at
       FROM gdpr_requests
       WHERE pro_id = $1
       ORDER BY created_at DESC
       LIMIT 20`,
      [proConnected.pro.id]
    );

    gdprRequests = gdprResult.rows;
  } catch (error) {
    console.error("Erreur espace pro :", error.message);
    return res.status(500).send(page("Erreur", "<h2>Erreur technique.</h2>", proConnected));
  }

  const now = new Date();

  const offersHtml = offers.map((offer) => {
    const expired = offer.expires_at && new Date(offer.expires_at) < now;
    const statusLabel = JOB_STATUS_LABELS[offer.status] || offer.status;
    const isPublic = offer.status === "approved" && !expired;

    return `
      <article class="card">
        <h2>${escapeHtml(offer.job_title)}</h2>

        <p>
          <span class="badge badge-${offer.status}">${escapeHtml(statusLabel)}</span>
          ${isPublic ? `<span class="badge badge-approved">En ligne</span>` : ""}
          ${expired ? `<span class="badge badge-rejected">Expiree</span>` : ""}
        </p>

        <p><span class="label">Entreprise :</span> <span class="value">${escapeHtml(offer.company_name)}</span></p>
        <p><span class="label">Ville :</span> <span class="value">${escapeHtml(offer.city)}</span></p>
        <p><span class="label">Contrat :</span> <span class="value">${escapeHtml(offer.contract_type)}</span></p>
        ${offer.salary ? `<p><span class="label">Salaire :</span> <span class="value">${escapeHtml(offer.salary)}</span></p>` : ""}
        <p><span class="label">Description :</span> <span class="value">${escapeHtml(offer.description).replace(/\n/g, "<br>")}</span></p>
        ${offer.qualifications ? `<p><span class="label">Qualifications :</span> <span class="value">${escapeHtml(offer.qualifications).replace(/\n/g, "<br>")}</span></p>` : ""}
        ${offer.deadline ? `<p><span class="label">Date limite :</span> <span class="value">${escapeHtml(offer.deadline)}</span></p>` : ""}

        ${offer.expires_at ? `
          <p class="muted">
            Expire le : ${new Date(offer.expires_at).toLocaleDateString("fr-FR")}
            ${expired ? "(expiree)" : ""}
          </p>
        ` : ""}

        <p class="muted">Creee le : ${new Date(offer.created_at).toLocaleDateString("fr-FR")}</p>

        <div class="actions">
          ${offer.status === "approved" && !expired ? `
            <form action="/mon-espace-pro/offre/${encodeURIComponent(offer.id)}/close" method="POST" style="display:inline">
              <button class="warning" type="submit">🔒 Cloturer</button>
            </form>
          ` : ""}

          ${offer.status === "closed" ? `
            <form action="/mon-espace-pro/offre/${encodeURIComponent(offer.id)}/reopen" method="POST" style="display:inline">
              <button class="success" type="submit">🔓 Rouvrir</button>
            </form>
          ` : ""}

          ${expired && offer.status !== "closed" ? `
            <form action="/mon-espace-pro/offre/${encodeURIComponent(offer.id)}/renew" method="POST" style="display:inline">
              <button class="success" type="submit">🔄 Renouveler ${OFFER_DURATION_DAYS}j</button>
            </form>
          ` : ""}

          ${offer.status === "approved" && !expired ? `
            <form action="/mon-espace-pro/offre/${encodeURIComponent(offer.id)}/renew" method="POST" style="display:inline">
              <button class="secondary" type="submit">🔄 Prolonger ${OFFER_DURATION_DAYS}j</button>
            </form>
          ` : ""}

          <a class="button secondary" href="/mon-espace-pro/offre/${encodeURIComponent(offer.id)}/modifier">✏️ Modifier</a>
        </div>
      </article>
    `;
  }).join("");

  const gdprHtml = gdprRequests.map((req) => `
    <article class="card" style="padding:16px">
      <p>
        <span class="badge badge-${req.status}">${escapeHtml(GDPR_STATUS_LABELS[req.status] || req.status)}</span>
        <strong>${escapeHtml(GDPR_TYPE_LABELS[req.request_type] || req.request_type)}</strong>
      </p>
      <p class="muted">
        Demande le : ${new Date(req.created_at).toLocaleString("fr-FR")}
        ${req.processed_at ? ` — Traitee le : ${new Date(req.processed_at).toLocaleString("fr-FR")}` : ""}
      </p>
    </article>
  `).join("");

  const phoneStatus = proConnected.pro.phone_public
    ? `<span class="badge badge-approved">Public</span> Votre numero est visible publiquement.`
    : `<span class="badge badge-closed">Prive</span> Votre numero n'est <strong>pas visible</strong> publiquement.`;

  let contactInfoBlock = "";

  if (proConnected.pro.contact_preference === "whatsapp" && proConnected.pro.whatsapp_number) {
    contactInfoBlock = `<p><span class="label">Reception du code :</span> <span class="value">WhatsApp (${escapeHtml(proConnected.pro.whatsapp_number)})</span></p>`;
  } else if (proConnected.pro.contact_preference === "email" && proConnected.pro.contact_email) {
    contactInfoBlock = `<p><span class="label">Reception du code :</span> <span class="value">Email (${escapeHtml(proConnected.pro.contact_email)})</span></p>`;
  }

  const companyBlock = proConnected.pro.company_name
    ? `<p><span class="label">Societe / Etablissement :</span> <span class="value">${escapeHtml(proConnected.pro.company_name)}</span></p>`
    : "";

  const displayName = getDisplayName(proConnected.pro);

  res.send(page("Mon espace pro", `
    <section class="card">
      <h1>Bonjour ${escapeHtml(displayName)} 👋</h1>

      <div class="pro-code-box">
        <div class="pro-code-label">Votre code professionnel</div>
        <div class="pro-code-value">${escapeHtml(proConnected.code)}</div>
        <div class="pro-code-label">Gardez-le precieusement</div>
      </div>

      <p class="help-text">
        Ce code vous permet de vous connecter a votre espace et de publier
        des offres d'emploi. Ne le partagez avec personne.
      </p>

      <div class="actions">
        <a class="button" href="/publier-emploi">📢 Publier une offre</a>
        <a class="button secondary" href="/">🌐 Voir le site</a>
      </div>

      <form action="/mon-espace-pro/logout" method="POST" style="display:inline">
        <button class="danger" type="submit">Se deconnecter</button>
      </form>
    </section>

    <section class="card">
      <h2>Mes informations</h2>
      ${companyBlock}
      <p><span class="label">Nom et prenoms :</span> <span class="value">${escapeHtml(proConnected.pro.full_name)}</span></p>
      <p><span class="label">Profession :</span> <span class="value">${escapeHtml(proConnected.pro.profession)}</span></p>
      <p><span class="label">Ville :</span> <span class="value">${escapeHtml(proConnected.pro.city)}</span></p>
      ${proConnected.pro.neighborhood ? `<p><span class="label">Quartier :</span> <span class="value">${escapeHtml(proConnected.pro.neighborhood)}</span></p>` : ""}
      <p><span class="label">Telephone :</span> <span class="value">${escapeHtml(proConnected.pro.phone)}</span></p>
      <p><span class="label">Visibilite du numero :</span> ${phoneStatus}</p>
      ${contactInfoBlock}
      ${proConnected.pro.experience ? `<p><span class="label">Experience :</span> <span class="value">${escapeHtml(proConnected.pro.experience)}</span></p>` : ""}
      <p><span class="label">Description :</span> <span class="value">${escapeHtml(proConnected.pro.service_description)}</span></p>

      <div class="actions">
        <a class="button secondary" href="/mon-espace-pro/modifier-telephone">Modifier la visibilite de mon numero</a>
      </div>
    </section>

    <section class="card">
      <h2>Mes offres d'emploi (${offers.length})</h2>
    </section>

    ${offersHtml || `
      <section class="card">
        <p class="muted">Vous n'avez pas encore publie d'offre d'emploi.</p>
        <a class="button" href="/publier-emploi">Publier ma premiere offre</a>
      </section>
    `}

    <section class="card">
      <h2>Mes droits sur mes donnees</h2>
      <p class="help-text">
        Conformement a la loi beninoise sur la protection des donnees personnelles,
        vous disposez de droits sur vos donnees : acces, rectification, suppression, opposition.
      </p>

      <div class="actions">
        <a class="button" href="/mon-espace-pro/mes-donnees">📥 Telecharger mes donnees</a>

        <form action="/mon-espace-pro/demande-suppression" method="POST" style="display:inline">
          <button class="danger" type="submit">🗑️ Demander la suppression de mon compte</button>
        </form>
      </div>

      ${gdprHtml ? `
        <h3 style="margin-top:24px">Historique de mes demandes</h3>
        ${gdprHtml}
      ` : ""}
    </section>
  `, proConnected));
});

/* CONNEXION ESPACE PRO */

app.post("/mon-espace-pro/login", async (req, res) => {
  const code = String(req.body.pro_code || "").trim().toUpperCase();

  if (!/^TM\d{5}$/.test(code)) {
    return res.status(400).send(
      page("Code invalide", `
        <section class="card">
          <h2>Code invalide</h2>
          <p>Le code doit etre au format TM12345.</p>
          <a href="/mon-espace-pro">Reessayer</a>
        </section>
      `, null)
    );
  }

  try {
    const result = await pool.query(
      `SELECT id FROM professional_applications WHERE pro_code = $1 AND status = 'approved'`,
      [code]
    );

    if (!result.rows.length) {
      return res.status(401).send(
        page("Code incorrect", `
          <section class="card">
            <h2>Code incorrect ou compte non approuve</h2>
            <p>Verifiez votre code ou contactez l'administration.</p>
            <a class="button" href="/mon-espace-pro">Reessayer</a>
            <a class="button secondary" href="/contact">Contacter l'administration</a>
          </section>
        `, null)
      );
    }

    setProCookie(res, code);
    res.redirect(303, "/mon-espace-pro");
  } catch (error) {
    console.error("Erreur login pro :", error.message);
    res.status(500).send(page("Erreur", "<h2>Erreur technique.</h2>", null));
  }
});

/* DECONNEXION ESPACE PRO */

app.post("/mon-espace-pro/logout", (req, res) => {
  clearProCookie(res);
  res.redirect(303, "/mon-espace-pro");
});

/* MODIFIER VISIBILITE DU TELEPHONE */

app.get("/mon-espace-pro/modifier-telephone", async (req, res) => {
  const proConnected = await getConnectedPro(req);

  if (!proConnected) {
    clearProCookie(res);
    return res.redirect(303, "/mon-espace-pro");
  }

  res.send(page("Modifier la visibilite", `
    <section class="card">
      <h1>Visibilite de mon numero</h1>

      <p class="help-text">
        Choisissez si votre numero doit etre visible publiquement sur TrouveMoi.
      </p>

      <form action="/mon-espace-pro/modifier-telephone" method="POST">
        <div class="checkbox-block">
          <label>
            <input type="checkbox" name="phone_public" value="yes" ${proConnected.pro.phone_public ? "checked" : ""}>
            <span>
              <strong>J'accepte que mon numero soit visible publiquement</strong>
              <br>
              <span class="muted">Les clients pourront vous contacter directement par appel ou WhatsApp.</span>
            </span>
          </label>
        </div>

        <div class="alert alert-warning">
          ⚠️ Si vous refusez que votre numero soit public, les clients devront
          passer par l'administration de TrouveMoi. Cela peut prendre plusieurs jours
          et vous risquez de perdre des opportunites.
        </div>

        <button type="submit">Enregistrer</button>
        <a class="button secondary" href="/mon-espace-pro">Annuler</a>
      </form>
    </section>
  `, proConnected));
});

app.post("/mon-espace-pro/modifier-telephone", async (req, res) => {
  const proConnected = await getConnectedPro(req);

  if (!proConnected) {
    clearProCookie(res);
    return res.redirect(303, "/mon-espace-pro");
  }

  const phonePublic = req.body.phone_public === "yes";

  try {
    await pool.query(
      `UPDATE professional_applications SET phone_public = $1 WHERE id = $2`,
      [phonePublic, proConnected.pro.id]
    );
  } catch (error) {
    console.error("Erreur maj visibilite :", error.message);
  }

  res.redirect(303, "/mon-espace-pro");
});

/* TELECHARGER MES DONNEES */

app.get("/mon-espace-pro/mes-donnees", async (req, res) => {
  const proConnected = await getConnectedPro(req);

  if (!proConnected) {
    clearProCookie(res);
    return res.redirect(303, "/mon-espace-pro");
  }

  try {
    const offersResult = await pool.query(
      `SELECT id, company_name, job_title, city, contract_type, salary,
              description, qualifications, contact_phone, contact_whatsapp,
              contact_email, deadline, status, created_at, expires_at
       FROM job_offers WHERE pro_id = $1`,
      [proConnected.pro.id]
    );

    const gdprResult = await pool.query(
      `SELECT id, request_type, status, created_at, processed_at
       FROM gdpr_requests WHERE pro_id = $1`,
      [proConnected.pro.id]
    );

    const exportData = {
      export_date: new Date().toISOString(),
      plateforme: "TrouveMoi",
      utilisateur: {
        nom: proConnected.pro.full_name,
        societe: proConnected.pro.company_name,
        telephone: proConnected.pro.phone,
        telephone_public: proConnected.pro.phone_public,
        ville: proConnected.pro.city,
        quartier: proConnected.pro.neighborhood,
        profession: proConnected.pro.profession,
        experience: proConnected.pro.experience,
        description: proConnected.pro.service_description,
        zone_intervention: proConnected.pro.service_area,
        disponibilite: proConnected.pro.availability,
        code_professionnel: proConnected.code,
        preference_contact: proConnected.pro.contact_preference,
        whatsapp_number: proConnected.pro.whatsapp_number,
        contact_email: proConnected.pro.contact_email,
        date_inscription: proConnected.pro.created_at
      },
      photos: {
        profil_privee: proConnected.pro.photo_profil_url,
        identite_privee: proConnected.pro.photo_identite_url,
        activite_publique: proConnected.pro.photo_activite_url
      },
      offres_emploi: offersResult.rows,
      demandes_rgpd: gdprResult.rows
    };

    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="trouvemoi-donnees-${proConnected.code}.json"`
    );
    res.send(JSON.stringify(exportData, null, 2));
  } catch (error) {
    console.error("Erreur export donnees :", error.message);
    res.status(500).send(page("Erreur", "<h2>Impossible de generer l'export.</h2>", proConnected));
  }
});

/* DEMANDE DE SUPPRESSION DE COMPTE */

app.post("/mon-espace-pro/demande-suppression", async (req, res) => {
  const proConnected = await getConnectedPro(req);

  if (!proConnected) {
    clearProCookie(res);
    return res.redirect(303, "/mon-espace-pro");
  }

  try {
    const existing = await pool.query(
      `SELECT id FROM gdpr_requests
       WHERE pro_id = $1 AND request_type = 'deletion' AND status = 'pending'`,
      [proConnected.pro.id]
    );

    if (existing.rows.length) {
      return res.send(page("Demande deja en cours", `
        <section class="card">
          <div class="alert alert-warning">
            ⚠️ Vous avez deja une demande de suppression en cours de traitement.
          </div>
          <p>Votre demande sera traitee par l'administration dans les plus brefs delais.</p>
          <a class="button" href="/mon-espace-pro">Retour a mon espace</a>
        </section>
      `, proConnected));
    }

    await pool.query(
      `INSERT INTO gdpr_requests (pro_id, request_type, status, message)
       VALUES ($1, 'deletion', 'pending', $2)`,
      [proConnected.pro.id, "Demande de suppression de compte depuis l'espace pro"]
    );

    res.send(page("Demande envoyee", `
      <section class="card">
        <h1>Demande de suppression envoyee</h1>
        <p>Votre demande a bien ete enregistree.</p>
        <p>
          L'administration de TrouveMoi va traiter votre demande. Cela peut prendre
          <strong>quelques jours</strong>.
        </p>
        <a class="button" href="/mon-espace-pro">Retour a mon espace</a>
      </section>
    `, proConnected));
  } catch (error) {
    console.error("Erreur demande suppression :", error.message);
    res.status(500).send(page("Erreur", "<h2>Erreur technique.</h2>", proConnected));
  }
});

/* CLOTURER UNE OFFRE */

app.post("/mon-espace-pro/offre/:id/close", async (req, res) => {
  const proConnected = await getConnectedPro(req);

  if (!proConnected) {
    clearProCookie(res);
    return res.redirect(303, "/mon-espace-pro");
  }

  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/mon-espace-pro");

  try {
    await pool.query(
      `UPDATE job_offers SET status = 'closed' WHERE id = $1 AND pro_id = $2`,
      [id, proConnected.pro.id]
    );
  } catch (error) {
    console.error("Erreur cloture :", error.message);
  }

  res.redirect(303, "/mon-espace-pro");
});

/* ROUVRIR UNE OFFRE */

app.post("/mon-espace-pro/offre/:id/reopen", async (req, res) => {
  const proConnected = await getConnectedPro(req);

  if (!proConnected) {
    clearProCookie(res);
    return res.redirect(303, "/mon-espace-pro");
  }

  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/mon-espace-pro");

  try {
    await pool.query(
      `UPDATE job_offers
       SET status = 'approved',
           expires_at = NOW() + INTERVAL '${OFFER_DURATION_DAYS} days'
       WHERE id = $1 AND pro_id = $2`,
      [id, proConnected.pro.id]
    );
  } catch (error) {
    console.error("Erreur reouverture :", error.message);
  }

  res.redirect(303, "/mon-espace-pro");
});

/* RENOUVELER UNE OFFRE */

app.post("/mon-espace-pro/offre/:id/renew", async (req, res) => {
  const proConnected = await getConnectedPro(req);

  if (!proConnected) {
    clearProCookie(res);
    return res.redirect(303, "/mon-espace-pro");
  }

  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/mon-espace-pro");

  try {
    await pool.query(
      `UPDATE job_offers
       SET expires_at = GREATEST(COALESCE(expires_at, NOW()), NOW()) + INTERVAL '${OFFER_DURATION_DAYS} days',
           status = CASE WHEN status = 'closed' THEN status ELSE 'approved' END
       WHERE id = $1 AND pro_id = $2`,
      [id, proConnected.pro.id]
    );
  } catch (error) {
    console.error("Erreur renouvellement :", error.message);
  }

  res.redirect(303, "/mon-espace-pro");
});

/* MODIFIER UNE OFFRE */

app.get("/mon-espace-pro/offre/:id/modifier", async (req, res) => {
  const proConnected = await getConnectedPro(req);

  if (!proConnected) {
    clearProCookie(res);
    return res.redirect(303, "/mon-espace-pro");
  }

  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/mon-espace-pro");

  try {
    const offerResult = await pool.query(
      `SELECT * FROM job_offers WHERE id = $1 AND pro_id = $2`,
      [id, proConnected.pro.id]
    );

    if (!offerResult.rows.length) return res.redirect(303, "/mon-espace-pro");

    const offer = offerResult.rows[0];

    const contractOptions = JOB_CONTRACT_TYPES.map((type) => `
      <option value="${escapeHtml(type)}" ${offer.contract_type === type ? "selected" : ""}>
        ${escapeHtml(type)}
      </option>
    `).join("");

    res.send(page("Modifier une offre", `
      <section class="card">
        <h1>Modifier l'offre</h1>
        <p class="help-text">
          Toute modification remettra l'offre en attente de validation par l'administration.
        </p>

        <form action="/mon-espace-pro/offre/${encodeURIComponent(offer.id)}/modifier" method="POST">
          <label for="company_name">Nom de l'entreprise ou du recruteur *</label>
          <input id="company_name" name="company_name" required maxlength="200" value="${escapeHtml(offer.company_name)}">

          <label for="job_title">Intitule du poste *</label>
          <input id="job_title" name="job_title" required maxlength="200" value="${escapeHtml(offer.job_title)}">

          <label for="city">Ville *</label>
          <input id="city" name="city" required maxlength="100" value="${escapeHtml(offer.city)}">

          <label for="contract_type">Type de contrat *</label>
          <select id="contract_type" name="contract_type" required>
            <option value="">Choisir</option>
            ${contractOptions}
          </select>

          <label for="salary">Salaire (facultatif)</label>
          <input id="salary" name="salary" maxlength="100" value="${escapeHtml(offer.salary || "")}">

          <label for="description">Description du poste *</label>
          <textarea id="description" name="description" required maxlength="8000" rows="6">${escapeHtml(offer.description)}</textarea>

          <label for="qualifications">Qualifications et competences recherchees</label>
          <textarea id="qualifications" name="qualifications" maxlength="4000" rows="4">${escapeHtml(offer.qualifications || "")}</textarea>

          <fieldset style="border:1px solid #ddd;border-radius:8px;padding:14px">
            <legend>Moyens de contact (au moins un obligatoire) *</legend>

            <label><input style="width:auto" type="checkbox" id="use_phone" name="use_phone" value="yes" ${offer.contact_phone ? "checked" : ""}> Appel direct</label>
            <label for="contact_phone">Numero de telephone</label>
            <input id="contact_phone" name="contact_phone" type="tel" maxlength="30" value="${escapeHtml(offer.contact_phone || "")}">

            <label><input style="width:auto" type="checkbox" id="use_whatsapp" name="use_whatsapp" value="yes" ${offer.contact_whatsapp ? "checked" : ""}> WhatsApp</label>
            <label for="contact_whatsapp">Numero WhatsApp</label>
            <input id="contact_whatsapp" name="contact_whatsapp" type="tel" maxlength="30" value="${escapeHtml(offer.contact_whatsapp || "")}">

            <label><input style="width:auto" type="checkbox" id="use_email" name="use_email" value="yes" ${offer.contact_email ? "checked" : ""}> E-mail</label>
            <label for="contact_email">Adresse e-mail</label>
            <input id="contact_email" name="contact_email" type="email" maxlength="254" value="${escapeHtml(offer.contact_email || "")}">
          </fieldset>

          <label for="deadline">Date limite de candidature (facultatif)</label>
          <input id="deadline" name="deadline" type="date" value="${escapeHtml(offer.deadline || "")}">

          <button type="submit">Enregistrer les modifications</button>
          <a class="button secondary" href="/mon-espace-pro">Annuler</a>
        </form>
      </section>
    `, proConnected));
  } catch (error) {
    console.error("Erreur modif :", error.message);
    res.redirect(303, "/mon-espace-pro");
  }
});

app.post("/mon-espace-pro/offre/:id/modifier", async (req, res) => {
  const proConnected = await getConnectedPro(req);

  if (!proConnected) {
    clearProCookie(res);
    return res.redirect(303, "/mon-espace-pro");
  }

  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/mon-espace-pro");

  const {
    company_name, job_title, city, contract_type, salary, description,
    qualifications, contact_phone, contact_whatsapp, contact_email,
    deadline, use_phone, use_whatsapp, use_email
  } = req.body;

  const company = typeof company_name === "string" ? company_name.trim() : "";
  const title = typeof job_title === "string" ? job_title.trim() : "";
  const jobCity = typeof city === "string" ? city.trim() : "";
  const contract = typeof contract_type === "string" ? contract_type.trim() : "";
  const jobDescription = typeof description === "string" ? description.trim() : "";

  const phone = use_phone === "yes" && typeof contact_phone === "string" ? normalizePhone(contact_phone) : null;
  const whatsapp = use_whatsapp === "yes" && typeof contact_whatsapp === "string" ? normalizePhone(contact_whatsapp) : null;
  const email = use_email === "yes" && typeof contact_email === "string" ? contact_email.trim() : null;
  const jobDeadline = typeof deadline === "string" && deadline.trim() ? deadline.trim() : null;

  if (!company || !title || !jobCity || !jobDescription || !JOB_CONTRACT_TYPES.includes(contract)) {
    return res.redirect(303, "/mon-espace-pro/offre/" + id + "/modifier");
  }

  if (!phone && !whatsapp && !email) {
    return res.redirect(303, "/mon-espace-pro/offre/" + id + "/modifier");
  }

  try {
    await pool.query(`
      UPDATE job_offers
      SET company_name = $1, job_title = $2, city = $3, contract_type = $4,
          salary = $5, description = $6, qualifications = $7,
          contact_phone = $8, contact_whatsapp = $9, contact_email = $10,
          deadline = $11, status = 'pending'
      WHERE id = $12 AND pro_id = $13
    `, [
      company.slice(0, 200), title.slice(0, 200), jobCity.slice(0, 100), contract,
      typeof salary === "string" ? salary.trim().slice(0, 100) || null : null,
      jobDescription.slice(0, 8000),
      typeof qualifications === "string" ? qualifications.trim().slice(0, 4000) || null : null,
      phone, whatsapp, email, jobDeadline, id, proConnected.pro.id
    ]);
  } catch (error) {
    console.error("Erreur modif POST :", error.message);
  }

  res.redirect(303, "/mon-espace-pro");
});

/* CONNEXION ADMINISTRATEUR */

const loginAttempts = new Map();

app.get("/admin", (req, res) => {
  const session = verifySessionToken(readCookie(req, SESSION_COOKIE));

  if (session) {
    return res.redirect(303, "/admin/dashboard");
  }

  const content = `
    <section class="card">
      <h1>Administration TrouveMoi</h1>
      <p>Connectez-vous pour gerer les candidatures, les offres d'emploi et les messages recus.</p>

      <form action="/admin/login" method="POST">
        <label for="password">Mot de passe administrateur</label>
        <input id="password" name="password" type="password" required maxlength="300" autocomplete="current-password">
        <button type="submit">Se connecter</button>
      </form>

      <p><a href="/">Retour au site</a></p>
    </section>
  `;

  res.setHeader("Cache-Control", "no-store");
  res.send(page("Connexion administrateur", content, null));
});

app.post("/admin/login", (req, res) => {
  const now = Date.now();
  const address = req.ip || "unknown";
  const record = loginAttempts.get(address);

  if (record && now - record.startedAt > 15 * 60 * 1000) {
    loginAttempts.delete(address);
  }

  const current = loginAttempts.get(address);

  if (current && current.count >= 5) {
    return res.status(429).send(
      page("Trop de tentatives", `
        <h2>Trop de tentatives de connexion.</h2>
        <p>Veuillez patienter 15 minutes avant de reessayer.</p>
      `, null)
    );
  }

  const configuredPassword = process.env.ADMIN_PASSWORD;
  const submittedPassword = req.body.password;

  if (!configuredPassword || typeof submittedPassword !== "string" || !safeEqual(submittedPassword, configuredPassword)) {
    if (current) {
      current.count += 1;
    } else {
      loginAttempts.set(address, { count: 1, startedAt: now });
    }

    return res.status(401).send(
      page("Connexion refusee", `
        <section class="card">
          <h2>Identifiants incorrects.</h2>
          <p><a href="/admin">Reessayer</a></p>
        </section>
      `, null)
    );
  }

  loginAttempts.delete(address);

  if (!process.env.ADMIN_SESSION_SECRET || process.env.ADMIN_SESSION_SECRET.length < 32) {
    console.error("ADMIN_SESSION_SECRET est absente ou trop courte.");
    return res.status(500).send(
      page("Configuration incomplete", `<h2>La configuration securisee de l'administration est incomplete.</h2>`, null)
    );
  }

  const session = {
    expiresAt: Date.now() + SESSION_DURATION,
    csrf: crypto.randomBytes(32).toString("hex")
  };

  setSessionCookie(res, createSessionToken(session));
  res.setHeader("Cache-Control", "no-store");
  res.redirect(303, "/admin/dashboard");
});

/* MENU ADMIN (avec badge RGPD) */

async function adminMenu(current, csrf) {
  let gdprCount = 0;
  let prosPendingCount = 0;

  try {
    const gdprResult = await pool.query(
      "SELECT COUNT(*) FROM gdpr_requests WHERE status = 'pending'"
    );
    gdprCount = Number(gdprResult.rows[0].count);

    const prosResult = await pool.query(
      "SELECT COUNT(*) FROM professional_applications WHERE status = 'pending'"
    );
    prosPendingCount = Number(prosResult.rows[0].count);
  } catch (error) {
    console.error("Erreur comptage admin :", error.message);
  }

  const links = [
    { href: "/admin/dashboard", label: "📊 Tableau de bord", badge: 0 },
    { href: "/admin/candidatures", label: "📋 Candidatures", badge: prosPendingCount },
    { href: "/admin/emplois", label: "💼 Offres d'emploi", badge: 0 },
    { href: "/admin/messages", label: "📩 Messages", badge: 0 },
    { href: "/admin/rgpd", label: "🔐 Demandes RGPD", badge: gdprCount }
  ];

  return `
    <section class="card">
      <div class="actions">
        ${links.map((link) => `
          <a class="button ${current === link.href ? "" : "secondary"}" href="${link.href}">
            ${link.label}${link.badge > 0 ? ` <span class="badge badge-new">${link.badge}</span>` : ""}
          </a>
        `).join("")}
        <a class="button secondary" href="/" target="_blank">🌐 Voir le site</a>
      </div>

      <form action="/admin/logout" method="POST" style="display:inline">
        <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
        <button class="danger" type="submit">Se deconnecter</button>
      </form>
    </section>
  `;
}

/* TABLEAU DE BORD */

app.get("/admin/dashboard", requireAdmin, async (req, res) => {
  try {
    const prosApproved = await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status = 'approved'");
    const prosPending = await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status = 'pending'");
    const jobsApproved = await pool.query("SELECT COUNT(*) FROM job_offers WHERE status = 'approved' AND (expires_at IS NULL OR expires_at > NOW())");
    const jobsPending = await pool.query("SELECT COUNT(*) FROM job_offers WHERE status = 'pending'");
    const jobsClosed = await pool.query("SELECT COUNT(*) FROM job_offers WHERE status = 'closed'");
    const messagesUnread = await pool.query("SELECT COUNT(*) FROM contact_messages WHERE is_read = false");
    const gdprPending = await pool.query("SELECT COUNT(*) FROM gdpr_requests WHERE status = 'pending'");

    const stats = {
      prosApproved: Number(prosApproved.rows[0].count),
      prosPending: Number(prosPending.rows[0].count),
      jobsApproved: Number(jobsApproved.rows[0].count),
      jobsPending: Number(jobsPending.rows[0].count),
      jobsClosed: Number(jobsClosed.rows[0].count),
      messagesUnread: Number(messagesUnread.rows[0].count),
      gdprPending: Number(gdprPending.rows[0].count)
    };

    /* BANDEAU D'ALERTES */

    const alerts = [];

    if (stats.gdprPending > 0) {
      alerts.push(`🔐 <strong>${stats.gdprPending}</strong> demande(s) RGPD en attente — <a href="/admin/rgpd">Traiter maintenant</a>`);
    }

    if (stats.prosPending > 0) {
      alerts.push(`📋 <strong>${stats.prosPending}</strong> candidature(s) de pro en attente — <a href="/admin/candidatures">Traiter maintenant</a>`);
    }

    if (stats.jobsPending > 0) {
      alerts.push(`📝 <strong>${stats.jobsPending}</strong> offre(s) d'emploi en attente — <a href="/admin/emplois">Traiter maintenant</a>`);
    }

    if (stats.messagesUnread > 0) {
      alerts.push(`📩 <strong>${stats.messagesUnread}</strong> message(s) non lu(s) — <a href="/admin/messages">Lire les messages</a>`);
    }

    const alertsBlock = alerts.length > 0 ? `
      <div class="admin-alerts">
        <h3>🔔 Vous avez des choses a traiter</h3>
        <ul>
          ${alerts.map((a) => `<li>${a}</li>`).join("")}
        </ul>
      </div>
    ` : "";

    const menuHtml = await adminMenu("/admin/dashboard", req.adminSession.csrf);

    res.setHeader("Cache-Control", "no-store");

    res.send(page("Tableau de bord", `
      <section class="card">
        <h1>Tableau de bord</h1>
        <p class="muted">Bienvenue dans votre espace d'administration.</p>
      </section>

      ${alertsBlock}

      ${menuHtml}

      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-icon">👥</div>
          <div class="stat-number">${stats.prosApproved}</div>
          <div class="stat-label">Pros approuves</div>
          <a class="stat-link" href="/admin/candidatures">Voir les candidatures →</a>
        </div>

        <div class="stat-card ${stats.prosPending > 0 ? "warning" : ""}">
          <div class="stat-icon">⏳</div>
          <div class="stat-number">${stats.prosPending}</div>
          <div class="stat-label">Candidatures en attente</div>
          <a class="stat-link" href="/admin/candidatures">Traiter maintenant →</a>
        </div>

        <div class="stat-card info">
          <div class="stat-icon">💼</div>
          <div class="stat-number">${stats.jobsApproved}</div>
          <div class="stat-label">Offres en ligne</div>
          <a class="stat-link" href="/admin/emplois">Voir les offres →</a>
        </div>

        <div class="stat-card ${stats.jobsPending > 0 ? "warning" : ""}">
          <div class="stat-icon">📝</div>
          <div class="stat-number">${stats.jobsPending}</div>
          <div class="stat-label">Offres en attente</div>
          <a class="stat-link" href="/admin/emplois">Traiter maintenant →</a>
        </div>

        <div class="stat-card">
          <div class="stat-icon">🔒</div>
          <div class="stat-number">${stats.jobsClosed}</div>
          <div class="stat-label">Offres cloturees</div>
          <a class="stat-link" href="/admin/emplois">Voir →</a>
        </div>

        <div class="stat-card ${stats.messagesUnread > 0 ? "danger" : ""}">
          <div class="stat-icon">📩</div>
          <div class="stat-number">${stats.messagesUnread}</div>
          <div class="stat-label">Messages non lus</div>
          <a class="stat-link" href="/admin/messages">Lire les messages →</a>
        </div>

        <div class="stat-card ${stats.gdprPending > 0 ? "danger" : ""}">
          <div class="stat-icon">🔐</div>
          <div class="stat-number">${stats.gdprPending}</div>
          <div class="stat-label">Demandes RGPD en attente</div>
          <a class="stat-link" href="/admin/rgpd">Traiter →</a>
        </div>
      </div>
    `, null));
  } catch (error) {
    console.error("Erreur du tableau de bord :", error.message);
    res.status(500).send(page("Erreur", "<h2>Impossible de charger le tableau de bord.</h2>", null));
  }
});

/* ADMIN : CANDIDATURES */

app.get("/admin/candidatures", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, full_name, company_name, phone, phone_public, city, neighborhood, profession,
             experience, service_description, service_area, availability,
             status, created_at, photo_profil_url, photo_identite_url,
             photo_activite_url, pro_code,
             contact_preference, whatsapp_number, contact_email
      FROM professional_applications
      ORDER BY CASE WHEN status = 'pending' THEN 0 ELSE 1 END, created_at DESC
      LIMIT 200
    `);

    const applications = result.rows.map((candidate) => {
      const statusOptions = ALLOWED_STATUSES.map((status) => `
        <option value="${status}" ${candidate.status === status ? "selected" : ""}>
          ${STATUS_LABELS[status]}
        </option>
      `).join("");

      const phoneVisibility = candidate.phone_public
        ? `<span class="badge badge-approved">Public</span>`
        : `<span class="badge badge-closed">Prive</span>`;

      const photos = `
        <div class="photos-grid">
          ${candidate.photo_profil_url ? `
            <div class="photo-block">
              <img src="${escapeHtml(candidate.photo_profil_url)}" alt="Photo de profil" class="photo-profil">
              <div class="photo-label">Profil (privee)</div>
            </div>
          ` : ""}
          ${candidate.photo_identite_url ? `
            <div class="photo-block">
              <img src="${escapeHtml(candidate.photo_identite_url)}" alt="Photo d'identite" class="photo-identite">
              <div class="photo-label">Identite (privee)</div>
            </div>
          ` : ""}
          ${candidate.photo_activite_url ? `
            <div class="photo-block">
              <img src="${escapeHtml(candidate.photo_activite_url)}" alt="Photo d'activite" class="photo-activite">
              <div class="photo-label">Activite (publique)</div>
            </div>
          ` : ""}
        </div>
      `;

      let codeBlock = "";

      if (candidate.pro_code) {
        const pref = candidate.contact_preference;
        let sendButton = `<p class="help-text">Aucune preference de contact enregistree.</p>`;

        if (pref === "whatsapp") {
          const waNumber = candidate.whatsapp_number || candidate.phone;
          const cleanNumber = normalizePhone(waNumber).replace(/^\+/, "");
          const waMessage = encodeURIComponent(
            `Bonjour ${getDisplayName(candidate)}, votre candidature sur TrouveMoi a ete approuvee ✅\n\nVotre code professionnel est : ${candidate.pro_code}\n\nConservez-le precieusement : il vous permet de vous connecter a votre espace pro et de publier des offres d'emploi.\n\nEspace pro : https://trouvemoi-4mk0.onrender.com/mon-espace-pro`
          );

          sendButton = `
            <p><span class="label">Preference :</span> <span class="value">📱 WhatsApp</span></p>
            <p class="muted">Numero : ${escapeHtml(waNumber)}</p>
            <a class="button whatsapp" href="https://wa.me/${escapeHtml(cleanNumber)}?text=${waMessage}" target="_blank" rel="noopener noreferrer">📱 Envoyer le code par WhatsApp</a>
          `;
        } else if (pref === "email") {
          const emailAddr = candidate.contact_email || "";
          const subject = encodeURIComponent("Votre code professionnel TrouveMoi");
          const body = encodeURIComponent(
            `Bonjour ${getDisplayName(candidate)},\n\nVotre candidature sur TrouveMoi a ete approuvee.\n\nVotre code professionnel est : ${candidate.pro_code}\n\nConservez-le precieusement.\n\nEspace pro : https://trouvemoi-4mk0.onrender.com/mon-espace-pro\n\nL'equipe TrouveMoi`
          );

          sendButton = `
            <p><span class="label">Preference :</span> <span class="value">✉️ Email</span></p>
            <p class="muted">Adresse : ${escapeHtml(emailAddr)}</p>
            <a class="button email" href="mailto:${escapeHtml(emailAddr)}?subject=${subject}&body=${body}">✉️ Envoyer le code par email</a>
          `;
        }

        codeBlock = `
          <div class="pro-code-box" style="margin:16px 0">
            <div class="pro-code-label">Code professionnel</div>
            <div class="pro-code-value">${escapeHtml(candidate.pro_code)}</div>
            <div class="pro-code-label">A communiquer au pro</div>
          </div>
          <div class="card" style="background:#f0fdf9;border:1px solid #0a9d70">
            <h3 style="margin-top:0">📤 Envoyer le code au professionnel</h3>
            ${sendButton}
          </div>
        `;
      } else {
        codeBlock = `<p class="help-text">Aucun code genere (le pro doit etre approuve pour en recevoir un).</p>`;
      }

      const companyBlock = candidate.company_name
        ? `<p><span class="label">Societe :</span> <span class="value">${escapeHtml(candidate.company_name)}</span></p>`
        : "";

      return `
        <article class="card">
          <h2>${escapeHtml(candidate.full_name)}</h2>
          ${photos}

          <p><span class="label">Reference :</span> <span class="value">${escapeHtml(candidate.id)}</span></p>
          ${companyBlock}
          <p><span class="label">Telephone prive :</span> <span class="value">${escapeHtml(candidate.phone)}</span> ${phoneVisibility}</p>
          <p><span class="label">Ville :</span> <span class="value">${escapeHtml(candidate.city)}</span></p>
          <p><span class="label">Quartier :</span> <span class="value">${escapeHtml(candidate.neighborhood || "Non renseigne")}</span></p>
          <p><span class="label">Profession :</span> <span class="value">${escapeHtml(candidate.profession)}</span></p>
          <p><span class="label">Experience :</span> <span class="value">${escapeHtml(candidate.experience || "Non renseignee")}</span></p>
          <p><span class="label">Description :</span> <span class="value">${escapeHtml(candidate.service_description)}</span></p>
          <p><span class="label">Zone :</span> <span class="value">${escapeHtml(candidate.service_area || "Non renseignee")}</span></p>
          <p><span class="label">Disponibilite :</span> <span class="value">${escapeHtml(candidate.availability || "Non renseignee")}</span></p>
          <p><span class="label">Statut actuel :</span> <span class="value">${escapeHtml(STATUS_LABELS[candidate.status] || candidate.status)}</span></p>
          <p class="muted">Recue le : ${escapeHtml(candidate.created_at)}</p>

          ${codeBlock}

          <form action="/admin/candidatures/${encodeURIComponent(candidate.id)}/status" method="POST">
            <input type="hidden" name="csrfToken" value="${escapeHtml(req.adminSession.csrf)}">
            <label for="status-${escapeHtml(candidate.id)}">Changer le statut</label>
            <select id="status-${escapeHtml(candidate.id)}" name="status">${statusOptions}</select>
            <button type="submit">Enregistrer le statut</button>
          </form>

          <form action="/admin/candidatures/${encodeURIComponent(candidate.id)}/supprimer" method="POST" style="margin-top:12px">
            <input type="hidden" name="csrfToken" value="${escapeHtml(req.adminSession.csrf)}">
            <button class="danger" type="submit" onclick="return confirm('Supprimer DEFINITIVEMENT ce professionnel ? Cette action est irreversible (compte + photos + offres).');">🗑️ Supprimer definitivement</button>
          </form>
        </article>
      `;
    }).join("");

    const menuHtml = await adminMenu("/admin/candidatures", req.adminSession.csrf);

    res.setHeader("Cache-Control", "no-store");

    res.send(page("Candidatures", `
      <section class="card">
        <h1>Candidatures professionnelles</h1>
        <p>Total affiche : ${result.rows.length} candidature(s)</p>
        <p class="help-text">
          Lorsque vous approuvez une candidature, un code professionnel unique est genere automatiquement.
          Utilisez le bouton WhatsApp ou Email pour lui envoyer son code.
        </p>
      </section>

      ${menuHtml}

      ${applications || `<section class="card"><p>Aucune candidature pour le moment.</p></section>`}
    `, null));
  } catch (error) {
    console.error("Erreur candidatures :", error.message);
    res.status(500).send(page("Erreur", "<h2>Impossible de charger les candidatures.</h2>", null));
  }
});

/* ADMIN : SUPPRIMER DEFINITIVEMENT UNE CANDIDATURE */

app.post("/admin/candidatures/:id/supprimer", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/candidatures");

  try {
    const proResult = await pool.query(
      `SELECT id, photo_profil_url, photo_identite_url, photo_activite_url
       FROM professional_applications WHERE id = $1`,
      [id]
    );

    if (!proResult.rows.length) return res.redirect(303, "/admin/candidatures");

    const pro = proResult.rows[0];

    await deleteFromCloudinary(pro.photo_profil_url);
    await deleteFromCloudinary(pro.photo_identite_url);
    await deleteFromCloudinary(pro.photo_activite_url);

    await pool.query(`DELETE FROM gdpr_requests WHERE pro_id = $1`, [id]);
    await pool.query(`DELETE FROM job_offers WHERE pro_id = $1`, [id]);
    await pool.query(`DELETE FROM professional_applications WHERE id = $1`, [id]);
  } catch (error) {
    console.error("Erreur suppression RGPD :", error.message);
  }

  res.redirect(303, "/admin/candidatures");
});

/* ADMIN : OFFRES D'EMPLOI */

app.get("/admin/emplois", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT j.id, j.company_name, j.job_title, j.city, j.contract_type,
             j.salary, j.description, j.qualifications, j.contact_phone,
             j.contact_whatsapp, j.contact_email, j.deadline, j.status,
             j.created_at, j.expires_at, j.pro_id,
             p.full_name AS pro_name, p.company_name AS pro_company, p.pro_code AS pro_code
      FROM job_offers j
      LEFT JOIN professional_applications p ON p.id = j.pro_id
      ORDER BY CASE WHEN j.status = 'pending' THEN 0 ELSE 1 END, j.created_at DESC
      LIMIT 200
    `);

    const offers = result.rows.map((job) => {
      const statusOptions = JOB_STATUSES.map((status) => `
        <option value="${status}" ${job.status === status ? "selected" : ""}>${JOB_STATUS_LABELS[status]}</option>
      `).join("");

      const expired = job.expires_at && new Date(job.expires_at) < new Date();

      const proDisplay = job.pro_company || job.pro_name || "Inconnu";

      const proBlock = job.pro_name ? `
        <div style="background:#f0fdf9;padding:12px;border-radius:8px;margin:12px 0;border-left:4px solid #087f5b">
          <p style="margin:0"><span class="label">📢 Publiee par :</span> <span class="value">${escapeHtml(proDisplay)}</span></p>
          ${job.pro_code ? `<p style="margin:4px 0 0 0"><span class="label">Code pro :</span> <code>${escapeHtml(job.pro_code)}</code></p>` : ""}
        </div>
      ` : `<p class="help-text">⚠️ Publiee avant la mise en place des pros verifies</p>`;

      return `
        <article class="card">
          <h2>${escapeHtml(job.job_title)}</h2>
          <p><span class="badge badge-${job.status}">${escapeHtml(JOB_STATUS_LABELS[job.status] || job.status)}</span></p>

          ${proBlock}

          <p><span class="label">Entreprise/recruteur :</span> <span class="value">${escapeHtml(job.company_name)}</span></p>
          <p><span class="label">Ville :</span> <span class="value">${escapeHtml(job.city)}</span></p>
          <p><span class="label">Contrat :</span> <span class="value">${escapeHtml(job.contract_type)}</span></p>
          ${job.salary ? `<p><span class="label">Salaire :</span> <span class="value">${escapeHtml(job.salary)}</span></p>` : ""}
          <p><span class="label">Description :</span> <span class="value">${escapeHtml(job.description).replace(/\n/g, "<br>")}</span></p>
          ${job.qualifications ? `<p><span class="label">Qualifications :</span> <span class="value">${escapeHtml(job.qualifications).replace(/\n/g, "<br>")}</span></p>` : ""}
          <p><span class="label">Contact telephone :</span> <span class="value">${escapeHtml(job.contact_phone || "Non fourni")}</span></p>
          <p><span class="label">Contact WhatsApp :</span> <span class="value">${escapeHtml(job.contact_whatsapp || "Non fourni")}</span></p>
          <p><span class="label">Contact e-mail :</span> <span class="value">${escapeHtml(job.contact_email || "Non fourni")}</span></p>
          <p><span class="label">Date limite :</span> <span class="value">${escapeHtml(job.deadline || "Non renseignee")}</span></p>
          ${job.expires_at ? `<p><span class="label">Expire le :</span> <span class="value">${new Date(job.expires_at).toLocaleDateString("fr-FR")}</span> ${expired ? `<span class="badge badge-rejected">Expiree</span>` : ""}</p>` : ""}

          <form action="/admin/emplois/${encodeURIComponent(job.id)}/status" method="POST">
            <input type="hidden" name="csrfToken" value="${escapeHtml(req.adminSession.csrf)}">
            <label for="job-status-${escapeHtml(job.id)}">Statut de l'offre</label>
            <select id="job-status-${escapeHtml(job.id)}" name="status">${statusOptions}</select>
            <button type="submit">Enregistrer le statut</button>
          </form>

          <div class="actions">
            <form action="/admin/emplois/${encodeURIComponent(job.id)}/renew" method="POST" style="display:inline">
              <input type="hidden" name="csrfToken" value="${escapeHtml(req.adminSession.csrf)}">
              <button class="success" type="submit">🔄 Prolonger ${OFFER_DURATION_DAYS}j</button>
            </form>
          </div>
        </article>
      `;
    }).join("");

    const menuHtml = await adminMenu("/admin/emplois", req.adminSession.csrf);

    res.setHeader("Cache-Control", "no-store");

    res.send(page("Offres d'emploi", `
      <section class="card">
        <h1>Gestion des offres d'emploi</h1>
        <p>Total affiche : ${result.rows.length} offre(s)</p>
        <p class="help-text">Les offres expirent automatiquement apres ${OFFER_DURATION_DAYS} jours.</p>
      </section>

      ${menuHtml}

      ${offers || `<section class="card"><p>Aucune offre soumise pour le moment.</p></section>`}
    `, null));
  } catch (error) {
    console.error("Erreur gestion offres :", error.message);
    res.status(500).send(page("Erreur", "<h2>Impossible de charger les offres.</h2>", null));
  }
});

/* ADMIN : PROLONGER UNE OFFRE */

app.post("/admin/emplois/:id/renew", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/emplois");

  try {
    await pool.query(
      `UPDATE job_offers
       SET expires_at = GREATEST(COALESCE(expires_at, NOW()), NOW()) + INTERVAL '${OFFER_DURATION_DAYS} days',
           status = CASE WHEN status = 'pending' THEN status ELSE 'approved' END
       WHERE id = $1`,
      [id]
    );
  } catch (error) {
    console.error("Erreur prolongation admin :", error.message);
  }

  res.redirect(303, "/admin/emplois");
});

/* ADMIN : CHANGER STATUT OFFRE */

app.post("/admin/emplois/:id/status", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  const status = req.body.status;

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).send(page("Reference invalide", "<h2>Reference d'offre invalide.</h2>", null));
  }

  if (!JOB_STATUSES.includes(status)) {
    return res.status(400).send(page("Statut invalide", "<h2>Statut non autorise.</h2>", null));
  }

  try {
    if (status === "approved") {
      await pool.query(
        `UPDATE job_offers
         SET status = $1,
             expires_at = CASE
               WHEN expires_at IS NULL OR expires_at < NOW()
                 THEN NOW() + INTERVAL '${OFFER_DURATION_DAYS} days'
               ELSE expires_at
             END
         WHERE id = $2`,
        [status, id]
      );
    } else {
      await pool.query(`UPDATE job_offers SET status = $1 WHERE id = $2`, [status, id]);
    }

    res.redirect(303, "/admin/emplois");
  } catch (error) {
    console.error("Erreur statut offre :", error.message);
    res.status(500).send(page("Erreur", "<h2>Impossible de modifier le statut de l'offre.</h2>", null));
  }
});

/* ADMIN : CHANGER STATUT CANDIDATURE */

app.post("/admin/candidatures/:id/status", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  const status = req.body.status;

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).send(page("Reference invalide", "<h2>Reference de candidature invalide.</h2>", null));
  }

  if (!ALLOWED_STATUSES.includes(status)) {
    return res.status(400).send(page("Statut invalide", "<h2>Statut non autorise.</h2>", null));
  }

  try {
    const existing = await pool.query("SELECT pro_code FROM professional_applications WHERE id = $1", [id]);

    if (!existing.rows.length) {
      return res.status(404).send(page("Candidature introuvable", "<h2>Cette candidature n'existe pas.</h2>", null));
    }

    const currentCode = existing.rows[0].pro_code;

    if (status === "approved" && !currentCode) {
      const newCode = await generateUniqueProCode();
      await pool.query(
        `UPDATE professional_applications SET status = $1, pro_code = $2 WHERE id = $3`,
        [status, newCode, id]
      );
    } else {
      await pool.query(`UPDATE professional_applications SET status = $1 WHERE id = $2`, [status, id]);
    }

    res.redirect(303, "/admin/candidatures");
  } catch (error) {
    console.error("Erreur statut candidature :", error.message);
    res.status(500).send(page("Erreur", "<h2>Impossible de modifier le statut.</h2>", null));
  }
});

/* ADMIN : MESSAGES */

app.get("/admin/messages", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT m.id, m.name, m.email, m.phone, m.subject, m.message, m.is_read, m.created_at, m.pro_id,
             p.full_name AS pro_name, p.company_name AS pro_company, p.profession AS pro_profession
      FROM contact_messages m
      LEFT JOIN professional_applications p ON p.id = m.pro_id
      ORDER BY CASE WHEN m.is_read = false THEN 0 ELSE 1 END, m.created_at DESC
      LIMIT 200
    `);

    const messages = result.rows.map((msg) => {
      const replyEmail = msg.email ? `
        <a class="button email" href="mailto:${escapeHtml(msg.email)}?subject=${encodeURIComponent("Re: " + (msg.subject || "Votre message sur TrouveMoi"))}">✉️ Repondre par email</a>
      ` : "";

      const replyWhatsapp = msg.phone ? `
        <a class="button whatsapp" href="https://wa.me/${escapeHtml(normalizePhone(msg.phone).replace(/^\+/, ""))}?text=${encodeURIComponent("Bonjour " + msg.name + ", suite a votre message sur TrouveMoi concernant : " + (msg.subject || "votre demande"))}" target="_blank" rel="noopener noreferrer">💬 Repondre par WhatsApp</a>
      ` : "";

      const proDisplay = msg.pro_company || msg.pro_name || "";

      const proBlock = msg.pro_id && msg.pro_name ? `
        <div class="alert alert-info">
          📩 Message concernant le professionnel <strong>${escapeHtml(proDisplay)}</strong>
          (${escapeHtml(msg.pro_profession || "")}) — un client souhaite le contacter.
        </div>
      ` : "";

      return `
        <article class="card">
          <h2>${msg.is_read ? "📖" : "📩"} ${escapeHtml(msg.subject || "Sans objet")}</h2>
          ${proBlock}
          <p><span class="label">De :</span> <span class="value">${escapeHtml(msg.name)}</span></p>
          <p><span class="label">E-mail :</span> <span class="value">${escapeHtml(msg.email || "Non renseigne")}</span></p>
          <p><span class="label">Telephone :</span> <span class="value">${escapeHtml(msg.phone || "Non renseigne")}</span></p>
          <p><span class="label">Message :</span></p>
          <p style="background:#f9fafb;padding:12px;border-radius:8px">${escapeHtml(msg.message).replace(/\n/g, "<br>")}</p>
          <p class="muted">Recu le : ${escapeHtml(msg.created_at)}</p>

          <div class="actions">
            ${replyEmail}
            ${replyWhatsapp}
            ${!msg.is_read ? `
              <form action="/admin/messages/${encodeURIComponent(msg.id)}/read" method="POST" style="display:inline">
                <input type="hidden" name="csrfToken" value="${escapeHtml(req.adminSession.csrf)}">
                <button class="secondary" type="submit">✅ Marquer comme lu</button>
              </form>
            ` : ""}
            <form action="/admin/messages/${encodeURIComponent(msg.id)}/delete" method="POST" style="display:inline">
              <input type="hidden" name="csrfToken" value="${escapeHtml(req.adminSession.csrf)}">
              <button class="danger" type="submit">🗑️ Supprimer</button>
            </form>
          </div>
        </article>
      `;
    }).join("");

    const menuHtml = await adminMenu("/admin/messages", req.adminSession.csrf);

    res.setHeader("Cache-Control", "no-store");

    res.send(page("Messages", `
      <section class="card">
        <h1>Messages recus</h1>
        <p>Total : ${result.rows.length} message(s)</p>
      </section>

      ${menuHtml}

      ${messages || `<section class="card"><p>Aucun message pour le moment.</p></section>`}
    `, null));
  } catch (error) {
    console.error("Erreur messages :", error.message);
    res.status(500).send(page("Erreur", "<h2>Impossible de charger les messages.</h2>", null));
  }
});

app.post("/admin/messages/:id/read", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/messages");

  try {
    await pool.query("UPDATE contact_messages SET is_read = true WHERE id = $1", [id]);
  } catch (error) {
    console.error("Erreur marquage lu :", error.message);
  }
  res.redirect(303, "/admin/messages");
});

app.post("/admin/messages/:id/delete", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/messages");

  try {
    await pool.query("DELETE FROM contact_messages WHERE id = $1", [id]);
  } catch (error) {
    console.error("Erreur suppression message :", error.message);
  }
  res.redirect(303, "/admin/messages");
});

/* ADMIN : DEMANDES RGPD */

app.get("/admin/rgpd", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT g.id, g.request_type, g.status, g.message, g.created_at, g.processed_at,
             g.pro_id, p.full_name AS pro_name, p.company_name AS pro_company,
             p.phone AS pro_phone, p.pro_code AS pro_code
      FROM gdpr_requests g
      LEFT JOIN professional_applications p ON p.id = g.pro_id
      ORDER BY CASE WHEN g.status = 'pending' THEN 0 ELSE 1 END, g.created_at DESC
      LIMIT 200
    `);

    const requests = result.rows.map((req) => {
      const typeLabel = GDPR_TYPE_LABELS[req.request_type] || req.request_type;
      const statusLabel = GDPR_STATUS_LABELS[req.status] || req.status;

      const proDisplay = req.pro_company || req.pro_name || "Inconnu";

      const daysSince = Math.floor(
        (Date.now() - new Date(req.created_at).getTime()) / (1000 * 60 * 60 * 24)
      );

      const urgency = req.status === "pending"
        ? (daysSince > 20 ? "🔴 URGENT (plus de 20 jours)" : daysSince > 10 ? "🟠 A traiter bientot" : "🟢 Recent")
        : "";

      return `
        <article class="card">
          <h2>
            <span class="badge badge-${req.status}">${escapeHtml(statusLabel)}</span>
            ${escapeHtml(typeLabel)}
          </h2>

          ${urgency ? `<p><strong>${urgency}</strong></p>` : ""}

          <p><span class="label">Professionnel :</span> <span class="value">${escapeHtml(proDisplay)}</span></p>
          ${req.pro_code ? `<p><span class="label">Code pro :</span> <code>${escapeHtml(req.pro_code)}</code></p>` : ""}
          ${req.pro_phone ? `<p><span class="label">Telephone :</span> <span class="value">${escapeHtml(req.pro_phone)}</span></p>` : ""}
          <p><span class="label">Message :</span> <span class="value">${escapeHtml(req.message || "Aucun message")}</span></p>
          <p class="muted">Demande le : ${new Date(req.created_at).toLocaleString("fr-FR")} (il y a ${daysSince} jour(s))</p>
          ${req.processed_at ? `<p class="muted">Traitee le : ${new Date(req.processed_at).toLocaleString("fr-FR")}</p>` : ""}

          ${req.status === "pending" ? `
            <div class="actions">
              ${req.request_type === "deletion" && req.pro_id ? `
                <form action="/admin/rgpd/${encodeURIComponent(req.id)}/supprimer-pro" method="POST" style="display:inline">
                  <input type="hidden" name="csrfToken" value="${escapeHtml(req.adminSession.csrf)}">
                  <button class="danger" type="submit" onclick="return confirm('Supprimer DEFINITIVEMENT ce professionnel et toutes ses donnees ? Action irreversible.');">🗑️ Supprimer le pro + marquer traitee</button>
                </form>
              ` : ""}

              <form action="/admin/rgpd/${encodeURIComponent(req.id)}/traiter" method="POST" style="display:inline">
                <input type="hidden" name="csrfToken" value="${escapeHtml(req.adminSession.csrf)}">
                <button class="success" type="submit">✅ Marquer comme traitee</button>
              </form>

              <form action="/admin/rgpd/${encodeURIComponent(req.id)}/rejeter" method="POST" style="display:inline">
                <input type="hidden" name="csrfToken" value="${escapeHtml(req.adminSession.csrf)}">
                <button class="secondary" type="submit">❌ Rejeter</button>
              </form>
            </div>
          ` : ""}
        </article>
      `;
    }).join("");

    const menuHtml = await adminMenu("/admin/rgpd", req.adminSession.csrf);

    res.setHeader("Cache-Control", "no-store");

    res.send(page("Demandes RGPD", `
      <section class="card">
        <h1>Demandes RGPD</h1>
        <p>Total : ${result.rows.length} demande(s)</p>
        <p class="help-text">
          Conformement a la loi beninoise, vous devez repondre a chaque demande
          dans un delai maximum d'1 mois.
        </p>
      </section>

      ${menuHtml}

      ${requests || `<section class="card"><p>Aucune demande RGPD pour le moment.</p></section>`}
    `, null));
  } catch (error) {
    console.error("Erreur RGPD :", error.message);
    res.status(500).send(page("Erreur", "<h2>Impossible de charger les demandes RGPD.</h2>", null));
  }
});

/* ADMIN : SUPPRIMER UN PRO + MARQUER LA DEMANDE TRAITEE */

app.post("/admin/rgpd/:id/supprimer-pro", requireAdmin, verifyCsrf, async (req, res) => {
  const requestId = Number(req.params.id);
  if (!Number.isSafeInteger(requestId) || requestId < 1) return res.redirect(303, "/admin/rgpd");

  try {
    const reqResult = await pool.query(`SELECT pro_id FROM gdpr_requests WHERE id = $1`, [requestId]);
    if (!reqResult.rows.length) return res.redirect(303, "/admin/rgpd");

    const proId = reqResult.rows[0].pro_id;

    if (proId) {
      const proResult = await pool.query(
        `SELECT photo_profil_url, photo_identite_url, photo_activite_url
         FROM professional_applications WHERE id = $1`,
        [proId]
      );

      if (proResult.rows.length) {
        const pro = proResult.rows[0];
        await deleteFromCloudinary(pro.photo_profil_url);
        await deleteFromCloudinary(pro.photo_identite_url);
        await deleteFromCloudinary(pro.photo_activite_url);
      }

      await pool.query(`DELETE FROM job_offers WHERE pro_id = $1`, [proId]);
      await pool.query(`DELETE FROM professional_applications WHERE id = $1`, [proId]);
    }

    await pool.query(
      `UPDATE gdpr_requests SET status = 'processed', processed_at = NOW() WHERE id = $1`,
      [requestId]
    );
  } catch (error) {
    console.error("Erreur suppression RGPD :", error.message);
  }

  res.redirect(303, "/admin/rgpd");
});

app.post("/admin/rgpd/:id/traiter", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/rgpd");

  try {
    await pool.query(
      `UPDATE gdpr_requests SET status = 'processed', processed_at = NOW() WHERE id = $1`,
      [id]
    );
  } catch (error) {
    console.error("Erreur traitement RGPD :", error.message);
  }
  res.redirect(303, "/admin/rgpd");
});

app.post("/admin/rgpd/:id/rejeter", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/rgpd");

  try {
    await pool.query(
      `UPDATE gdpr_requests SET status = 'rejected', processed_at = NOW() WHERE id = $1`,
      [id]
    );
  } catch (error) {
    console.error("Erreur rejet RGPD :", error.message);
  }
  res.redirect(303, "/admin/rgpd");
});

/* DECONNEXION */

app.post("/admin/logout", requireAdmin, verifyCsrf, (req, res) => {
  clearSessionCookie(res);
  res.setHeader("Cache-Control", "no-store");
  res.redirect(303, "/admin");
});

/* PAGES STATIQUES */

app.get("/a-propos", async (req, res) => {
  const proConnected = await getConnectedPro(req);

  res.send(page("A propos", `
    <section class="card">
      <h1>A propos de TrouveMoi</h1>
      <p><strong>TrouveMoi</strong> est la plateforme beninoise de mise en relation entre les clients et les professionnels qualifies.</p>

      <h2>Notre mission</h2>
      <p>Nous voulons simplifier la recherche de professionnels de confiance au Benin. Trop souvent, trouver un plombier, un electricien ou un couturier fiable prend du temps et passe par le bouche-a-oreille.</p>
      <p>TrouveMoi centralise les professionnels de votre ville, verifie leur identite et vous permet de les contacter en un clic.</p>

      <h2>Nos services</h2>
      <ul style="margin-left:20px;margin-bottom:16px">
        <li>Annuaire de professionnels verifies</li>
        <li>Recherche par ville, quartier et metier</li>
        <li>Contact direct par telephone ou WhatsApp</li>
        <li>Offres d'emploi publiees par des professionnels verifies</li>
      </ul>

      <h2>Notre engagement</h2>
      <p>Chaque professionnel inscrit sur TrouveMoi est verifie par notre equipe (photo d'identite et informations verifiees) avant publication.</p>
      <p>Seuls les professionnels verifies peuvent publier des offres d'emploi, afin de lutter contre les arnaques et de garantir la fiabilite de chaque annonce.</p>

      <p style="margin-top:24px">
        <a class="button" href="/contact">Nous contacter</a>
        <a class="button secondary" href="/">Voir les professionnels</a>
      </p>
    </section>
  `, proConnected));
});

app.get("/conditions", async (req, res) => {
  const proConnected = await getConnectedPro(req);

  res.send(page("Conditions d'utilisation", `
    <section class="card">
      <h1>Conditions d'utilisation</h1>
      <p class="muted">Derniere mise a jour : ${new Date().toLocaleDateString("fr-FR")}</p>

      <h2>1. Acceptation des conditions</h2>
      <p>En utilisant TrouveMoi, vous acceptez sans reserve les presentes conditions d'utilisation.</p>

      <h2>2. Nature du service</h2>
      <p>TrouveMoi est une plateforme de mise en relation. Nous ne fournissons pas directement de services professionnels.</p>

      <h2>3. Inscription des professionnels</h2>
      <p>Les professionnels doivent fournir des informations exactes et a jour. Toute fausse declaration entraine le rejet de la candidature.</p>

      <h2>4. Publication d'offres d'emploi</h2>
      <p>Seuls les professionnels verifies (ayant recu un code professionnel apres approbation de leur candidature) peuvent publier des offres d'emploi sur TrouveMoi. Toute offre est examinee par l'administration avant publication.</p>

      <h2>5. Responsabilites</h2>
      <p>TrouveMoi ne peut etre tenu responsable de la qualite des services fournis par les professionnels references.</p>

      <h2>6. Utilisation interdite</h2>
      <p>Il est interdit de :</p>
      <ul style="margin-left:20px;margin-bottom:16px">
        <li>Publier de fausses informations</li>
        <li>Usurper l'identite d'autrui</li>
        <li>Publier de fausses offres d'emploi</li>
        <li>Utiliser la plateforme a des fins illicites</li>
      </ul>

      <h2>7. Contact</h2>
      <p>Pour toute question : <a href="/contact">formulaire de contact</a></p>
    </section>
  `, proConnected));
});

app.get("/confidentialite", async (req, res) => {
  const proConnected = await getConnectedPro(req);

  res.send(page("Politique de confidentialite", `
    <section class="card">
      <h1>Politique de confidentialite</h1>
      <p class="muted">Derniere mise a jour : ${new Date().toLocaleDateString("fr-FR")}</p>

      <h2>1. Donnees collectees</h2>
      <p>Nous collectons :</p>
      <ul style="margin-left:20px;margin-bottom:16px">
        <li>Pros : nom, societe/etablissement (facultatif), telephone, ville, quartier, metier, description, photos, code professionnel</li>
        <li>Offres : entreprise, contacts, description du poste</li>
        <li>Contact : nom, email, telephone, message</li>
      </ul>

      <h2>2. Utilisation des donnees</h2>
      <p>Vos donnees sont utilisees pour :</p>
      <ul style="margin-left:20px;margin-bottom:16px">
        <li>Mettre en relation les clients et les professionnels</li>
        <li>Afficher les profils approuves</li>
        <li>Permettre aux pros verifies de publier des offres</li>
        <li>Vous contacter en cas de besoin</li>
      </ul>

      <h2>3. Protection des photos d'identite</h2>
      <p>Les photos d'identite sont <strong>strictement privees</strong>. Elles ne sont visibles que par l'administration.</p>

      <h2>4. Code professionnel</h2>
      <p>Le code professionnel est personnel. Il ne doit pas etre partage. Il permet de gerer vos offres d'emploi.</p>

      <h2>5. Partage des donnees</h2>
      <p>Nous ne vendons ni ne partageons vos donnees avec des tiers.</p>

      <h2>6. Vos droits</h2>
      <p>Conformement a la loi beninoise sur la protection des donnees personnelles, vous disposez des droits suivants :</p>
      <ul style="margin-left:20px;margin-bottom:16px">
        <li><strong>Droit d'acces</strong> : consulter toutes vos donnees</li>
        <li><strong>Droit de rectification</strong> : corriger vos donnees</li>
        <li><strong>Droit a l'effacement</strong> : demander la suppression de vos donnees</li>
        <li><strong>Droit d'opposition</strong> : refuser certains traitements (ex : visibilite du numero)</li>
        <li><strong>Droit a la portabilite</strong> : recuperer vos donnees dans un format lisible</li>
      </ul>
      <p>
        <strong>Comment exercer vos droits ?</strong><br>
        Les professionnels inscrits peuvent exercer ces droits directement depuis leur espace personnel
        (<a href="/mon-espace-pro">Mon espace pro</a>).
        Toute autre personne peut nous contacter via le <a href="/contact">formulaire de contact</a>.
      </p>
      <p>Nous nous engageons a repondre a toute demande dans un delai maximum d'<strong>un mois</strong>.</p>

      <h2>7. Cookies</h2>
      <p>Nous utilisons uniquement des cookies techniques necessaires au fonctionnement de l'administration.</p>

      <h2>8. Autorite de controle</h2>
      <p>Conformement a la loi beninoise, vous pouvez introduire une reclamation aupres de l'Autorite de Protection des Donnees Personnelles (APDP) du Benin.</p>
    </section>
  `, proConnected));
});

app.get("/contact", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const proId = String(req.query.pro || "").trim();
  let proInfo = null;

  if (proId && /^\d+$/.test(proId)) {
    try {
      const proResult = await pool.query(
        `SELECT full_name, company_name, profession FROM professional_applications
         WHERE id = $1 AND status = 'approved'`,
        [parseInt(proId, 10)]
      );
      if (proResult.rows.length) proInfo = proResult.rows[0];
    } catch (error) {
      console.error("Erreur recherche pro :", error.message);
    }
  }

  const proDisplay = proInfo ? getDisplayName(proInfo) : "";

  const defaultSubject = proInfo
    ? `Demande de contact pour ${proDisplay} (${proInfo.profession})`
    : "";

  const defaultMessage = proInfo
    ? `Bonjour, je souhaite contacter ${proDisplay} (${proInfo.profession}) via TrouveMoi. Merci de me mettre en relation.`
    : "";

  res.send(page("Contact", `
    <section class="card">
      <h1>Nous contacter</h1>

      ${proInfo ? `
        <div class="alert alert-info">
          📩 Vous souhaitez contacter <strong>${escapeHtml(proDisplay)}</strong>
          (${escapeHtml(proInfo.profession)}). Ce professionnel a choisi de ne pas
          afficher son numero publiquement. Remplissez ce formulaire, votre demande
          sera transmise par l'administration.
          <br><br>
          <strong>⚠️ Cela peut prendre plusieurs jours.</strong>
        </div>
      ` : ""}

      <p>Une question, une suggestion, un probleme ? Ecrivez-nous.</p>

      <form action="/contact" method="POST">
        <input type="hidden" name="pro_id" value="${escapeHtml(proId)}">

        <label for="name">Votre nom *</label>
        <input id="name" name="name" required maxlength="150">

        <label for="email">Votre e-mail</label>
        <input id="email" name="email" type="email" maxlength="254" placeholder="vous@exemple.com">

        <label for="phone">Votre telephone</label>
        <input id="phone" name="phone" type="tel" maxlength="30" placeholder="+229...">

        <label for="subject">Sujet *</label>
        <input id="subject" name="subject" required maxlength="200" value="${escapeHtml(defaultSubject)}">

        <label for="message">Votre message *</label>
        <textarea id="message" name="message" required maxlength="5000" rows="6">${escapeHtml(defaultMessage)}</textarea>

        <p class="help-text">Au moins un moyen de contact (email ou telephone) est requis.</p>

        <button type="submit">Envoyer le message</button>
      </form>
    </section>
  `, proConnected));
});

app.post("/contact", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const { name, email, phone, subject, message, pro_id } = req.body;

  const cleanName = typeof name === "string" ? name.trim().slice(0, 150) : "";
  const cleanEmail = typeof email === "string" ? email.trim().slice(0, 254) : "";
  const cleanPhone = typeof phone === "string" ? normalizePhone(phone).slice(0, 30) : "";
  const cleanSubject = typeof subject === "string" ? subject.trim().slice(0, 200) : "";
  const cleanMessage = typeof message === "string" ? message.trim().slice(0, 5000) : "";

  let proIdInt = null;

  if (typeof pro_id === "string" && /^\d+$/.test(pro_id)) {
    proIdInt = parseInt(pro_id, 10);
  }

  if (!cleanName || !cleanSubject || !cleanMessage || (!cleanEmail && !cleanPhone)) {
    return res.status(400).send(
      page("Informations manquantes", `
        <section class="card">
          <h2>Informations manquantes</h2>
          <p>Le nom, le sujet, le message et au moins un moyen de contact sont obligatoires.</p>
          <a href="/contact">Retour au formulaire</a>
        </section>
      `, proConnected)
    );
  }

  if (cleanEmail && !validEmail(cleanEmail)) {
    return res.status(400).send(
      page("E-mail invalide", `
        <section class="card">
          <h2>L'adresse e-mail est invalide.</h2>
          <a href="/contact">Retour au formulaire</a>
        </section>
      `, proConnected)
    );
  }

  if (cleanPhone && !validPhone(cleanPhone)) {
    return res.status(400).send(
      page("Telephone invalide", `
        <section class="card">
          <h2>Le numero de telephone est invalide.</h2>
          <a href="/contact">Retour au formulaire</a>
        </section>
      `, proConnected)
    );
  }

  try {
    await pool.query(`
      INSERT INTO contact_messages (name, email, phone, subject, message, is_read, pro_id)
      VALUES ($1, $2, $3, $4, $5, false, $6)
    `, [cleanName, cleanEmail || null, cleanPhone || null, cleanSubject, cleanMessage, proIdInt]);

    res.status(201).send(
      page("Message envoye", `
        <section class="card">
          <h1>Message envoye avec succes !</h1>
          <p>Merci pour votre message. Nous vous repondrons dans les plus brefs delais.</p>
          <a class="button" href="/">Retour a l'accueil</a>
        </section>
      `, proConnected)
    );
  } catch (error) {
    console.error("Erreur contact :", error.message);
    res.status(500).send(
      page("Erreur", `
        <section class="card">
          <h2>Impossible d'envoyer le message.</h2>
          <p>Veuillez reessayer plus tard.</p>
        </section>
      `, proConnected)
    );
  }
});

/* VERIFICATION DU SERVEUR */

app.get("/health", (req, res) => {
  res.json({ status: "ok", application: "TrouveMoi" });
});

app.get("/health/database", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "connected", application: "TrouveMoi" });
  } catch (error) {
    console.error("Verification de la base impossible :", error.message);
    res.status(500).json({ status: "error", database: "disconnected", application: "TrouveMoi" });
  }
});

/* DEMARRAGE */

async function startServer() {
  try {
    /* TABLE PROS */

    await pool.query(`
      CREATE TABLE IF NOT EXISTS professional_applications (
        id SERIAL PRIMARY KEY,
        full_name VARCHAR(150) NOT NULL,
        company_name VARCHAR(200),
        phone VARCHAR(30) NOT NULL,
        phone_public BOOLEAN NOT NULL DEFAULT true,
        city VARCHAR(100) NOT NULL,
        neighborhood VARCHAR(150),
        profession VARCHAR(150) NOT NULL,
        experience VARCHAR(100),
        service_description TEXT NOT NULL,
        service_area VARCHAR(300),
        availability VARCHAR(100),
        npi VARCHAR(100),
        photo_profil_url TEXT,
        photo_identite_url TEXT,
        photo_activite_url TEXT,
        contact_preference VARCHAR(20),
        whatsapp_number VARCHAR(30),
        contact_email VARCHAR(254),
        pro_code VARCHAR(10) UNIQUE,
        status VARCHAR(30) NOT NULL DEFAULT 'pending',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    /* MIGRATIONS PROS */

    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS company_name VARCHAR(200)`);
    await pool.query(`ALTER TABLE professional_applications ALTER COLUMN npi DROP NOT NULL`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS photo_profil_url TEXT`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS photo_identite_url TEXT`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS photo_activite_url TEXT`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS pro_code VARCHAR(10) UNIQUE`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS phone_public BOOLEAN NOT NULL DEFAULT true`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS contact_preference VARCHAR(20)`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS whatsapp_number VARCHAR(30)`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS contact_email VARCHAR(254)`);

    /* TABLE OFFRES */

    await pool.query(`
      CREATE TABLE IF NOT EXISTS job_offers (
        id SERIAL PRIMARY KEY,
        company_name VARCHAR(200) NOT NULL,
        job_title VARCHAR(200) NOT NULL,
        city VARCHAR(100) NOT NULL,
        contract_type VARCHAR(50) NOT NULL,
        salary VARCHAR(100),
        description TEXT NOT NULL,
        qualifications TEXT,
        contact_phone VARCHAR(30),
        contact_whatsapp VARCHAR(30),
        contact_email VARCHAR(254),
        deadline DATE,
        status VARCHAR(20) NOT NULL DEFAULT 'pending',
        pro_id INTEGER REFERENCES professional_applications(id) ON DELETE SET NULL,
        expires_at TIMESTAMP,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CHECK (
          contact_phone IS NOT NULL
          OR contact_whatsapp IS NOT NULL
          OR contact_email IS NOT NULL
        )
      )
    `);

    await pool.query(`ALTER TABLE job_offers ADD COLUMN IF NOT EXISTS pro_id INTEGER REFERENCES professional_applications(id) ON DELETE SET NULL`);
    await pool.query(`ALTER TABLE job_offers ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP`);
    await pool.query(`ALTER TABLE job_offers DROP CONSTRAINT IF EXISTS job_offers_status_check`);
    await pool.query(`ALTER TABLE job_offers ADD CONSTRAINT job_offers_status_check CHECK (status IN ('pending', 'approved', 'rejected', 'closed'))`);

    /* TABLE VILLES */

    await pool.query(`
      CREATE TABLE IF NOT EXISTS cities (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL UNIQUE,
        display_order INTEGER NOT NULL DEFAULT 0
      )
    `);

    /* TABLE QUARTIERS */

    await pool.query(`
      CREATE TABLE IF NOT EXISTS neighborhoods (
        id SERIAL PRIMARY KEY,
        city_id INTEGER NOT NULL REFERENCES cities(id) ON DELETE CASCADE,
        name VARCHAR(150) NOT NULL,
        UNIQUE (city_id, name)
      )
    `);

    /* TABLE METIERS */

    await pool.query(`
      CREATE TABLE IF NOT EXISTS professions (
        id SERIAL PRIMARY KEY,
        name VARCHAR(150) NOT NULL UNIQUE,
        category VARCHAR(100),
        display_order INTEGER NOT NULL DEFAULT 0
      )
    `);

    /* TABLE MESSAGES */

    await pool.query(`
      CREATE TABLE IF NOT EXISTS contact_messages (
        id SERIAL PRIMARY KEY,
        name VARCHAR(150) NOT NULL,
        email VARCHAR(254),
        phone VARCHAR(30),
        subject VARCHAR(200) NOT NULL,
        message TEXT NOT NULL,
        is_read BOOLEAN NOT NULL DEFAULT false,
        pro_id INTEGER REFERENCES professional_applications(id) ON DELETE SET NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`ALTER TABLE contact_messages ADD COLUMN IF NOT EXISTS pro_id INTEGER REFERENCES professional_applications(id) ON DELETE SET NULL`);

    /* TABLE RGPD */

    await pool.query(`
      CREATE TABLE IF NOT EXISTS gdpr_requests (
        id SERIAL PRIMARY KEY,
        pro_id INTEGER REFERENCES professional_applications(id) ON DELETE SET NULL,
        request_type VARCHAR(30) NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'pending',
        message TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        processed_at TIMESTAMP
      )
    `);

    /* INSERTION DES VILLES */

    const citiesData = [
      ["Cotonou", 1],
      ["Abomey-Calavi", 2],
      ["Porto-Novo", 3],
      ["Parakou", 4],
      ["Bohicon", 5],
      ["Natitingou", 6],
      ["Ouidah", 7]
    ];

    for (const [name, order] of citiesData) {
      await pool.query(
        `INSERT INTO cities (name, display_order) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING`,
        [name, order]
      );
    }

    /* INSERTION DES QUARTIERS */

    const neighborhoodsData = {
      "Cotonou": ["Akpakpa", "Cadjèhoun", "Fidjrossè", "Ganhi", "Godomey", "Gbégamey", "Haie Vive", "Jéricho", "Ladji", "Missèbo", "Saint-Michel", "Sainte-Rita", "Sèmè-Podji", "Tokpa", "Vèdoko", "Zogbo", "Zone des Ambassades", "Dantokpa", "Agla", "Aïdjèdo", "Sikècodji"],
      "Abomey-Calavi": ["Calavi centre", "Godomey", "Akassato", "Zinvié", "Togba", "Tankpè", "Hêvié", "Ouèdo", "Cocotomey", "Kpota"],
      "Porto-Novo": ["Djègan-Kpèvi", "Ouando", "Akonaboè", "Djassin", "Houinmè", "Sèmè", "Tokpota", "Zounvié", "Avakpa", "Atinkanmey"],
      "Parakou": ["Zongo", "Dépôt", "Guéma", "Kpébié", "Madina", "Tourou", "Albarika", "Baparapé", "Titirou"],
      "Bohicon": ["Bohicon centre", "Agbangnizoun", "Sèdjè", "Djidja", "Ouèssè", "Kpassè"],
      "Natitingou": ["Natitingou centre", "Kanté", "Perma", "Kouandé", "Tchoumi-Tchoumi", "Yokossi"],
      "Ouidah": ["Ouidah centre", "Pahou", "Gbéna", "Sè", "Kpomassè", "Avlékété", "Djègbadji"]
    };

    for (const [cityName, neighborhoods] of Object.entries(neighborhoodsData)) {
      const cityResult = await pool.query("SELECT id FROM cities WHERE name = $1", [cityName]);
      if (!cityResult.rows.length) continue;

      const cityId = cityResult.rows[0].id;

      for (const neighborhood of neighborhoods) {
        await pool.query(
          `INSERT INTO neighborhoods (city_id, name) VALUES ($1, $2) ON CONFLICT (city_id, name) DO NOTHING`,
          [cityId, neighborhood]
        );
      }
    }

    /* INSERTION DES METIERS */

    const professionsData = [
      ["Maçon", "Bâtiment"], ["Plombier", "Bâtiment"], ["Électricien", "Bâtiment"], ["Carreleur", "Bâtiment"], ["Peintre en bâtiment", "Bâtiment"], ["Menuisier bois", "Bâtiment"], ["Menuisier aluminium", "Bâtiment"], ["Soudeur", "Bâtiment"], ["Ferrailleur", "Bâtiment"], ["Charpentier", "Bâtiment"], ["Étanchéiste (toiture)", "Bâtiment"], ["Vitrier", "Bâtiment"],
      ["Femme de ménage", "Maison"], ["Repassage à domicile", "Maison"], ["Cuisinier", "Maison"], ["Cuisinière", "Maison"], ["Gardien", "Maison"], ["Vigile", "Maison"], ["Nounou", "Maison"], ["Garde d'enfants", "Maison"], ["Jardinier", "Maison"], ["Désinsectisation", "Maison"], ["Dératisation", "Maison"], ["Plombier-déboucheur", "Maison"],
      ["Coiffeur", "Beauté"], ["Coiffeuse", "Beauté"], ["Tresseuse", "Beauté"], ["Barbier", "Beauté"], ["Esthéticienne", "Beauté"], ["Maquilleuse", "Beauté"], ["Manucure", "Beauté"], ["Pédicure", "Beauté"], ["Masseur", "Beauté"], ["Masseuse", "Beauté"], ["Tatoueur", "Beauté"],
      ["Couturier", "Couture"], ["Couturière", "Couture"], ["Tailleur", "Couture"], ["Brodeur", "Couture"], ["Retoucheur", "Couture"], ["Styliste modéliste", "Couture"], ["Cordonnier", "Couture"],
      ["Mécanicien auto", "Automobile"], ["Mécanicien moto", "Automobile"], ["Électricien auto", "Automobile"], ["Carrossier", "Automobile"], ["Tôlier", "Automobile"], ["Vulcanisateur", "Automobile"], ["Chauffeur de taxi", "Transport"], ["Chauffeur de moto-taxi", "Transport"], ["Chauffeur personnel", "Transport"], ["Déménageur", "Transport"],
      ["Traiteur", "Restauration"], ["Pâtissier", "Restauration"], ["Boulanger", "Restauration"], ["Vendeur de nourriture", "Restauration"], ["Boucher", "Restauration"], ["Poissonnier", "Restauration"], ["Barista", "Restauration"],
      ["Développeur web", "Informatique"], ["Développeur mobile", "Informatique"], ["Informaticien", "Informatique"], ["Réparateur de téléphone", "Informatique"], ["Réparateur d'ordinateur", "Informatique"], ["Graphiste", "Informatique"], ["Community manager", "Informatique"], ["Photographe", "Informatique"], ["Vidéaste", "Informatique"], ["Ingénieur réseau", "Informatique"],
      ["Professeur de Maths", "Éducation"], ["Professeur de Français", "Éducation"], ["Professeur d'Anglais", "Éducation"], ["Enseignant primaire", "Éducation"], ["Formateur informatique", "Éducation"], ["Coach scolaire", "Éducation"],
      ["Infirmier à domicile", "Santé"], ["Infirmière à domicile", "Santé"], ["Sage-femme", "Santé"], ["Kinésithérapeute", "Santé"], ["Aide-soignant", "Santé"], ["Pharmacien", "Santé"], ["Opticien", "Santé"],
      ["Comptable", "Professionnel"], ["Fiscaliste", "Professionnel"], ["Juriste", "Professionnel"], ["Avocat", "Professionnel"], ["Notaire", "Professionnel"], ["Traducteur", "Professionnel"], ["Rédacteur de contenu", "Professionnel"], ["Secrétaire", "Professionnel"], ["Assistant administratif", "Professionnel"], ["Consultant", "Professionnel"],
      ["Wedding planner", "Événementiel"], ["Décorateur événementiel", "Événementiel"], ["DJ", "Événementiel"], ["Animateur", "Événementiel"], ["MC", "Événementiel"], ["Serveur événementiel", "Événementiel"], ["Sécurité événementielle", "Événementiel"], ["Sonorisation", "Événementiel"],
      ["Agent immobilier", "Immobilier"], ["Courtier", "Immobilier"], ["Serrurier", "Divers"], ["Climatisation", "Divers"], ["Froid", "Divers"], ["Réparation électroménager", "Divers"], ["Antenniste", "Divers"], ["Forgeron", "Divers"], ["Puisatier", "Divers"], ["Agriculteur", "Agriculture"], ["Maraîcher", "Agriculture"], ["Éleveur", "Agriculture"], ["Pêcheur", "Agriculture"], ["Apiculteur", "Agriculture"], ["Prothésiste dentaire", "Santé"]
    ];

    let orderCounter = 0;

    for (const [name, category] of professionsData) {
      orderCounter += 1;
      await pool.query(
        `INSERT INTO professions (name, category, display_order) VALUES ($1, $2, $3) ON CONFLICT (name) DO NOTHING`,
        [name, category, orderCounter]
      );
    }

    console.log(
      "Toutes les tables sont pretes (pros, societe, offres, villes, quartiers, metiers, messages, RGPD, preferences contact)."
    );

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`TrouveMoi demarre sur le port ${PORT}.`);
    });
  } catch (error) {
    console.error("Erreur au demarrage :", error);
    process.exit(1);
  }
}

startServer();
