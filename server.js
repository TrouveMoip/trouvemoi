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

const REVIEW_STATUSES = ["pending", "approved", "rejected"];

const REVIEW_STATUS_LABELS = {
  pending: "En attente",
  approved: "Approuve",
  rejected: "Rejete"
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
  if (!person) return "";
  if (person.company_name && person.company_name.trim()) {
    return person.company_name.trim();
  }
  return person.full_name || "";
}

function getCsrf(req) {
  if (req.adminSession && typeof req.adminSession.csrf === "string") {
    return req.adminSession.csrf;
  }
  return "";
}

function renderStars(rating) {
  const full = Math.floor(rating);
  const hasHalf = (rating - full) >= 0.5;
  let html = "";

  for (let i = 1; i <= 5; i++) {
    if (i <= full) {
      html += "★";
    } else if (i === full + 1 && hasHalf) {
      html += "⯨";
    } else {
      html += "☆";
    }
  }

  return html;
}

function renderLogo() {
  return `
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 50" width="180" height="45" style="display:inline-block;vertical-align:middle;max-width:100%">
      <circle cx="22" cy="22" r="15" fill="none" stroke="white" stroke-width="3.5"/>
      <line x1="33" y1="33" x2="43" y2="43" stroke="white" stroke-width="4" stroke-linecap="round"/>
      <circle cx="17" cy="19" r="3" fill="white"/>
      <path d="M 12 28 Q 12 23 17 23 Q 22 23 22 28 Z" fill="white"/>
      <circle cx="27" cy="19" r="3" fill="white" opacity="0.85"/>
      <path d="M 22 28 Q 22 23 27 23 Q 32 23 32 28 Z" fill="white" opacity="0.85"/>
      <text x="55" y="32" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif" font-size="22" font-weight="800" fill="white" letter-spacing="-0.5" class="logo-text">TrouveMoi</text>
    </svg>
  `;
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
      <meta name="theme-color" content="#1e40af">
      <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 50 50'%3E%3Crect width='50' height='50' rx='10' fill='%231e40af'/%3E%3Ccircle cx='22' cy='22' r='10' fill='none' stroke='white' stroke-width='3'/%3E%3Cline x1='29' y1='29' x2='37' y2='37' stroke='white' stroke-width='3.5' stroke-linecap='round'/%3E%3Ccircle cx='19' cy='20' r='2.5' fill='white'/%3E%3Ccircle cx='25' cy='20' r='2.5' fill='white' opacity='0.85'/%3E%3C/svg%3E">
      <title>${escapeHtml(title)} - TrouveMoi</title>

      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
          padding: 0; background: #f4f7fb; color: #222;
          line-height: 1.6; min-height: 100vh;
          display: flex; flex-direction: column;
        }

        header {
          background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
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
          display: inline-flex;
          align-items: center;
          text-decoration: none;
        }

        .logo svg {
          display: block;
          height: 42px;
          width: auto;
          max-width: 100%;
        }

        .tagline { font-size: 13px; opacity: 0.9; margin-top: 2px; }

        nav { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }

        nav a, nav button {
          color: white; text-decoration: none;
          padding: 8px 14px; border-radius: 6px;
          font-size: 14px; font-weight: 500;
          transition: background 0.2s;
        }

        nav a:hover, nav button:hover { background: rgba(255,255,255,0.15); }

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

        h1 {
          font-size: 28px; margin-bottom: 16px;
          color: #1e40af; line-height: 1.3;
          border-left: 5px solid #1e40af;
          padding-left: 14px;
        }

        h2 {
          font-size: 22px; margin-bottom: 14px;
          color: #1e3a8a; line-height: 1.3;
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

        .label { font-weight: 700; color: #1a1a1a; }
        .value { color: #333; }

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
          outline: none; border-color: #2563eb;
          box-shadow: 0 0 0 3px rgba(37,99,235,0.1);
        }

        textarea { resize: vertical; min-height: 100px; }

        input[type="file"] {
          padding: 10px; background: #f9fafb;
          border: 2px dashed #ccc; cursor: pointer;
        }

        input[type="file"]:hover { border-color: #2563eb; background: #eff6ff; }

        input[type="checkbox"], input[type="radio"] { width: auto; margin-right: 8px; }

        optgroup {
          font-weight: 800; color: #1e40af; font-style: normal;
          background: #eff6ff; padding: 6px 0; font-size: 15px;
        }

        optgroup option {
          font-weight: 400; color: #222; background: white; font-size: 15px;
        }

        button, .button {
          display: inline-block; border: none;
          background: #2563eb; color: white;
          padding: 12px 20px; border-radius: 8px;
          cursor: pointer; text-decoration: none;
          text-align: center; font-size: 15px; font-weight: 600;
          transition: background 0.2s, transform 0.1s;
          margin-right: 8px; margin-bottom: 8px;
          font-family: inherit;
        }

        button:hover, .button:hover { background: #1d4ed8; transform: translateY(-1px); }

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

        .photos-grid {
          display: flex; flex-wrap: wrap; gap: 12px; margin: 16px 0;
        }

        .photos-grid img {
          max-width: 280px; max-height: 280px;
          border-radius: 10px; border: 2px solid #e5e7eb;
          object-fit: cover;
        }

        .photo-profil { border: 3px solid #2563eb !important; }
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

        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 16px; margin-bottom: 24px;
        }

        .stat-card {
          background: white; padding: 24px;
          border-radius: 12px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.06);
          border-left: 4px solid #2563eb;
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
          font-size: 13px; color: #2563eb;
          text-decoration: none; font-weight: 600;
        }

        .stat-link:hover { text-decoration: underline; }

        .pro-code-box {
          background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
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

        .alert {
          padding: 16px 20px; border-radius: 8px;
          margin-bottom: 16px; border-left: 4px solid;
        }

        .alert-success { background: #d1fae5; border-color: #0a9d70; color: #065f46; }
        .alert-danger { background: #fee2e2; border-color: #b42318; color: #991b1b; }
        .alert-warning { background: #fffbeb; border-color: #f59e0b; color: #92400e; }
        .alert-info { background: #dbeafe; border-color: #3b82f6; color: #1e40af; }

        .pro-welcome {
          background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
          color: white; padding: 28px; border-radius: 12px;
          margin-bottom: 20px; box-shadow: 0 4px 20px rgba(30,64,175,0.3);
        }

        .pro-welcome h2 {
          color: white; border: none; padding: 0;
          margin-bottom: 8px; font-size: 24px;
        }

        .pro-welcome p {
          opacity: 0.95; margin-bottom: 16px; font-size: 15px;
        }

        .pro-welcome .actions { margin: 0; }

        .pro-welcome .button { background: white; color: #1e40af; }
        .pro-welcome .button:hover { background: #eff6ff; transform: translateY(-1px); }

        .pro-welcome .button.secondary {
          background: rgba(255,255,255,0.25); color: white;
        }
        .pro-welcome .button.secondary:hover { background: rgba(255,255,255,0.35); }

        .admin-alerts {
          background: #fff7ed; border: 1px solid #fdba74;
          border-left: 5px solid #ea580c;
          padding: 20px; border-radius: 10px; margin-bottom: 20px;
        }

        .admin-alerts h3 {
          color: #9a3412; border: none; padding: 0;
          margin-bottom: 12px; font-size: 17px;
        }

        .admin-alerts ul { list-style: none; margin: 0; }

        .admin-alerts li {
          padding: 8px 0; border-bottom: 1px solid #fed7aa; color: #7c2d12;
        }

        .admin-alerts li:last-child { border-bottom: none; }

        .admin-alerts a { color: #9a3412; font-weight: 700; text-decoration: none; }
        .admin-alerts a:hover { text-decoration: underline; }

        .pros-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
          gap: 20px; margin-top: 20px;
        }

        .pro-card {
          background: white; border-radius: 12px; overflow: hidden;
          box-shadow: 0 2px 8px rgba(0,0,0,0.08);
          transition: transform 0.2s, box-shadow 0.2s;
          display: flex; flex-direction: column;
        }

        .pro-card:hover {
          transform: translateY(-4px);
          box-shadow: 0 8px 24px rgba(0,0,0,0.12);
        }

        .pro-card-image {
          width: 100%; height: 180px;
          background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
          display: flex; align-items: center; justify-content: center;
          overflow: hidden;
        }

        .pro-card-image img { width: 100%; height: 100%; object-fit: cover; }

        .pro-card-image-placeholder { font-size: 60px; color: white; opacity: 0.5; }

        .pro-card-body {
          padding: 16px; flex: 1; display: flex; flex-direction: column;
        }

        .pro-card-profession {
          font-size: 13px; font-weight: 700; color: #1e40af;
          text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px;
        }

        .pro-card-name {
          font-size: 17px; font-weight: 700; color: #1a1a1a;
          margin-bottom: 8px; line-height: 1.3;
        }

        .pro-card-location {
          font-size: 14px; color: #667085; margin-bottom: 10px;
        }

        .pro-card-location::before { content: "📍 "; }

        .pro-card-rating {
          font-size: 15px; color: #f59e0b; font-weight: 600;
          margin-bottom: 12px; letter-spacing: 1px;
        }

        .pro-card-rating .reviews-count {
          color: #667085; font-weight: 400; font-size: 13px;
          letter-spacing: 0; margin-left: 6px;
        }

        .pro-card-rating .no-rating {
          color: #94a3b8; font-weight: 400; font-style: italic;
          font-size: 13px; letter-spacing: 0;
        }

        .pro-card-button {
          display: block; width: 100%; background: #2563eb;
          color: white; padding: 10px 16px; border-radius: 6px;
          text-align: center; text-decoration: none;
          font-weight: 600; font-size: 14px; margin-top: auto;
          transition: background 0.2s;
        }

        .pro-card-button:hover { background: #1d4ed8; }

        .pro-header {
          background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
          color: white; padding: 32px 24px;
          border-radius: 12px; margin-bottom: 20px;
        }

        .pro-header h1 {
          color: white; border: none; padding: 0;
          font-size: 30px; margin-bottom: 8px;
        }

        .pro-header .profession {
          font-size: 18px; opacity: 0.95;
          margin-bottom: 8px; font-weight: 600;
        }

        .pro-header .location { font-size: 15px; opacity: 0.9; }

        .pro-header .rating-large {
          font-size: 22px; color: #fef3c7;
          margin-top: 12px; font-weight: 700; letter-spacing: 2px;
        }

        .pro-header .rating-large .reviews-count {
          color: rgba(255,255,255,0.85); font-weight: 400;
          font-size: 15px; letter-spacing: 0; margin-left: 8px;
        }

        .review-item {
          background: #f9fafb; padding: 16px;
          border-radius: 10px; margin-bottom: 14px;
          border-left: 4px solid #f59e0b;
        }

        .review-header {
          display: flex; justify-content: space-between;
          align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 8px;
        }

        .review-author { font-weight: 700; color: #1a1a1a; }
        .review-stars { color: #f59e0b; font-size: 18px; letter-spacing: 2px; }
        .review-date { font-size: 13px; color: #94a3b8; }
        .review-comment { color: #333; margin-top: 8px; line-height: 1.6; }

        .rating-summary {
          display: flex; align-items: center; gap: 24px;
          padding: 24px; background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
          border-radius: 12px; margin-bottom: 20px; flex-wrap: wrap;
        }

        .rating-big-number {
          font-size: 52px; font-weight: 800;
          color: #92400e; line-height: 1;
        }

        .rating-details { flex: 1; min-width: 180px; }
        .rating-details .stars { font-size: 28px; color: #f59e0b; letter-spacing: 3px; }
        .rating-details .count { font-size: 14px; color: #78350f; margin-top: 4px; font-weight: 600; }

        .btn-review { background: #f59e0b; color: white; }
        .btn-review:hover { background: #d97706; }

        .star-rating-input {
          display: flex; flex-direction: row-reverse;
          justify-content: flex-end; gap: 6px;
          margin-bottom: 16px; width: auto;
        }

        .star-rating-input input { display: none; }

        .star-rating-input label {
          font-size: 44px; color: #d1d5db; cursor: pointer;
          transition: color 0.2s, transform 0.1s;
          margin: 0; padding: 0; line-height: 1; font-weight: normal;
        }

        .star-rating-input label:hover { transform: scale(1.1); }
        .star-rating-input input:checked ~ label { color: #f59e0b; }
        .star-rating-input label:hover,
        .star-rating-input label:hover ~ label { color: #f59e0b; }

        .checkbox-block {
          background: #f9fafb; padding: 16px;
          border-radius: 8px; margin: 12px 0;
          border: 1px solid #e5e7eb;
        }

        .checkbox-block label {
          display: flex; align-items: flex-start;
          margin: 0; font-weight: 500;
        }

        .checkbox-block input[type="checkbox"],
        .checkbox-block input[type="radio"] {
          margin-top: 5px;
        }

        footer {
          background: #1a1a1a; color: #ccc;
          padding: 32px 20px 20px; margin-top: 40px;
        }

        .footer-content {
          max-width: 1100px; margin: 0 auto;
          display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 24px;
        }

        .footer-col h4 {
          color: white; margin-bottom: 12px;
          font-size: 15px; text-transform: uppercase; letter-spacing: 0.5px;
        }

        .footer-col a {
          display: block; color: #aaa; text-decoration: none;
          padding: 4px 0; font-size: 14px;
        }

        .footer-col a:hover { color: #3b82f6; }

        .footer-bottom {
          max-width: 1100px; margin: 24px auto 0;
          padding-top: 20px; border-top: 1px solid #333;
          text-align: center; font-size: 13px; color: #888;
        }

        @media (max-width: 600px) {
          header { padding: 14px 16px; }
          .header-content { flex-direction: column; text-align: center; }
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
          .rating-big-number { font-size: 40px; }
          .rating-details .stars { font-size: 22px; }
          .star-rating-input label { font-size: 36px; }
          .logo svg { height: 32px; }
          .logo .logo-text { font-size: 18px; }
        }
      </style>
    </head>

    <body>
      <header>
        <div class="header-content">
          <div>
            <a href="/" class="logo" aria-label="TrouveMoi">
              ${renderLogo()}
            </a>
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
        p.id, p.full_name, p.company_name, p.phone, p.phone_public, p.city, p.neighborhood,
        p.profession, p.experience, p.service_description, p.service_area, p.availability,
        p.photo_activite_url,
        (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count,
        (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating
      FROM professional_applications p
      WHERE p.status = 'approved'
    `;

    const values = [];

    if (profession) {
      values.push(`%${profession}%`);
      query += ` AND p.profession ILIKE $${values.length}`;
    }

    if (city) {
      values.push(city);
      query += ` AND p.city = $${values.length}`;
    }

    if (neighborhood) {
      values.push(neighborhood);
      query += ` AND p.neighborhood = $${values.length}`;
    }

    query += " ORDER BY p.created_at DESC LIMIT 50";

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

    const prosCards = result.rows.map((person) => {
      const displayName = getDisplayName(person);
      const reviewsCount = Number(person.reviews_count || 0);
      const avgRating = Number(person.avg_rating || 0);

      const photoHtml = person.photo_activite_url
        ? `<img src="${escapeHtml(person.photo_activite_url)}" alt="${escapeHtml(person.profession)}">`
        : `<div class="pro-card-image-placeholder">👤</div>`;

      let ratingHtml = "";

      if (reviewsCount > 0) {
        ratingHtml = `
          <div class="pro-card-rating">
            ${renderStars(avgRating)}
            <span class="reviews-count">${avgRating.toFixed(1)} (${reviewsCount} avis)</span>
          </div>
        `;
      } else {
        ratingHtml = `
          <div class="pro-card-rating">
            <span class="no-rating">Pas encore d'avis</span>
          </div>
        `;
      }

      return `
        <article class="pro-card">
          <div class="pro-card-image">
            ${photoHtml}
          </div>

          <div class="pro-card-body">
            <div class="pro-card-profession">${escapeHtml(person.profession)}</div>
            <div class="pro-card-name">${escapeHtml(displayName)}</div>
            <div class="pro-card-location">${escapeHtml(person.city)}${person.neighborhood ? ` - ${escapeHtml(person.neighborhood)}` : ""}</div>

            ${ratingHtml}

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

    const alerteArnaque = `
      <div class="alert alert-warning">
        <strong>⚠️ ATTENTION :</strong> Ne payez jamais un professionnel avant de l'avoir rencontré en personne. Si quelqu'un vous demande de l'argent à l'avance, veuillez le signaler en cliquant sur le bouton <strong>"Contact"</strong> en haut de la page.
      </div>
    `;

    const prosSection = result.rows.length > 0
      ? `<div class="pros-grid">${prosCards}</div>`
      : `<section class="card"><p>Aucun professionnel approuve ne correspond a votre recherche.</p></section>`;

    const content = `
      ${welcomeBanner}
      ${alerteArnaque}

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

      ${prosSection}

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
      return res.status(404).send(page("Profil introuvable", `<section class="card"><h2>Profil introuvable</h2><p>Ce professionnel n'existe pas.</p><a class="button" href="/">Retour</a></section>`, proConnected));
    }

    const result = await pool.query(
      `SELECT
        p.id, p.full_name, p.company_name, p.phone, p.phone_public, p.city, p.neighborhood,
        p.profession, p.experience, p.service_description, p.service_area, p.availability,
        p.photo_activite_url,
        (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count,
        (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating
       FROM professional_applications p
       WHERE p.id = $1 AND p.status = 'approved'`,
      [id]
    );

    if (!result.rows.length) {
      return res.status(404).send(page("Profil introuvable", `<section class="card"><h2>Profil introuvable</h2><p>Ce professionnel n'existe pas.</p><a class="button" href="/">Retour</a></section>`, proConnected));
    }

    const person = result.rows[0];
    const displayName = getDisplayName(person);
    const phoneClean = normalizePhone(person.phone || "");
    const whatsappNumber = phoneClean.replace(/^\+/, "");
    const phonePublic = person.phone_public === true;

    const reviewsCount = Number(person.reviews_count || 0);
    const avgRating = Number(person.avg_rating || 0);

    const reviewsResult = await pool.query(
      `SELECT id, author_name, rating, comment, created_at FROM reviews WHERE pro_id = $1 AND status = 'approved' ORDER BY created_at DESC LIMIT 5`,
      [id]
    );

    const reviews = reviewsResult.rows;
    const shareText = encodeURIComponent("Decouvrez " + displayName + " (" + person.profession + ") sur TrouveMoi");
    const shareUrl = encodeURIComponent("https://trouvemoi-4mk0.onrender.com/pro/" + person.id);

    const sameCityResult = await pool.query(
      `SELECT id, full_name, company_name, profession, city, neighborhood, photo_activite_url FROM professional_applications WHERE status = 'approved' AND city = $1 AND id != $2 ORDER BY created_at DESC LIMIT 4`,
      [person.city, person.id]
    );

    const sameProfessionResult = await pool.query(
      `SELECT id, full_name, company_name, profession, city, neighborhood, photo_activite_url FROM professional_applications WHERE status = 'approved' AND profession = $1 AND id != $2 ORDER BY created_at DESC LIMIT 4`,
      [person.profession, person.id]
    );

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
        </div>
        <div class="contact-buttons">
          <a class="button" href="/contact?pro=${encodeURIComponent(person.id)}">📩 Contacter ce professionnel</a>
          <a class="button share" href="https://wa.me/?text=${shareText}%20-%20${shareUrl}" target="_blank" rel="noopener noreferrer">📤 Partager</a>
        </div>
      `;
    }

    let ratingHeader = "";
    if (reviewsCount > 0) {
      ratingHeader = `<div class="rating-large">${renderStars(avgRating)}<span class="reviews-count">${avgRating.toFixed(1)} / 5 (${reviewsCount} avis)</span></div>`;
    } else {
      ratingHeader = `<div class="rating-large" style="color:rgba(255,255,255,0.7);font-size:16px;letter-spacing:0">Pas encore d'avis</div>`;
    }

    let ratingSummary = "";
    if (reviewsCount > 0) {
      ratingSummary = `
        <div class="rating-summary">
          <div class="rating-big-number">${avgRating.toFixed(1)}</div>
          <div class="rating-details">
            <div class="stars">${renderStars(avgRating)}</div>
            <div class="count">Base sur ${reviewsCount} avis client${reviewsCount > 1 ? "s" : ""}</div>
          </div>
        </div>
      `;
    }

    const reviewsHtml = reviews.map((rev) => {
      const dateStr = new Date(rev.created_at).toLocaleDateString("fr-FR", { day: "numeric", month: "long", year: "numeric" });
      return `
        <div class="review-item">
          <div class="review-header">
            <div class="review-author">${escapeHtml(rev.author_name)}</div>
            <div class="review-stars">${renderStars(rev.rating)}</div>
          </div>
          <div class="review-date">${escapeHtml(dateStr)}</div>
          ${rev.comment ? `<div class="review-comment">${escapeHtml(rev.comment).replace(/\n/g, "<br>")}</div>` : ""}
        </div>
      `;
    }).join("");

    const reviewsSection = reviews.length > 0 ? `
      <section class="card">
        <h2>Avis des clients (${reviewsCount})</h2>
        ${ratingSummary}
        ${reviewsHtml}
        ${reviewsCount > 5 ? `<p class="muted">Seuls les 5 derniers avis sont affiches.</p>` : ""}
      </section>
    ` : "";

    const reviewButton = `
      <section class="card" style="text-align:center">
        <h3>Vous avez fait appel a ce professionnel ?</h3>
        <p class="help-text">Partagez votre experience en laissant un avis. Il sera verifie avant publication.</p>
        <a class="button btn-review" href="/pro/${encodeURIComponent(person.id)}/avis">⭐ Laisser un avis</a>
      </section>
    `;

    function buildMiniCards(rows) {
      return rows.map((p) => {
        const name = getDisplayName(p);
        const photo = p.photo_activite_url ? `<img src="${escapeHtml(p.photo_activite_url)}" alt="${escapeHtml(p.profession)}">` : `<div class="pro-card-image-placeholder">👤</div>`;
        return `
          <article class="pro-card">
            <div class="pro-card-image">${photo}</div>
            <div class="pro-card-body">
              <div class="pro-card-profession">${escapeHtml(p.profession)}</div>
              <div class="pro-card-name">${escapeHtml(name)}</div>
              <div class="pro-card-location">${escapeHtml(p.city)}</div>
              <a class="pro-card-button" href="/pro/${encodeURIComponent(p.id)}">Voir le profil →</a>
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
        ${ratingHeader}
      </div>

      <section class="card">
        ${person.photo_activite_url ? `<div class="photos-grid"><div class="photo-block"><img src="${escapeHtml(person.photo_activite_url)}" alt="Activite" class="photo-activite"><div class="photo-label">Activite</div></div></div>` : ""}
        ${person.experience ? `<p><span class="label">Experience :</span> <span class="value">${escapeHtml(person.experience)}</span></p>` : ""}
        <h2>Description des services</h2>
        <p>${escapeHtml(person.service_description).replace(/\n/g, "<br>")}</p>
        ${person.service_area ? `<p><span class="label">Zone d'intervention :</span> <span class="value">${escapeHtml(person.service_area)}</span></p>` : ""}
        ${person.availability ? `<p><span class="label">Disponibilite :</span> <span class="value">${escapeHtml(person.availability)}</span></p>` : ""}
        ${contactButtons}
        <p style="margin-top:24px"><a class="button secondary" href="/">← Retour a l'accueil</a></p>
      </section>

      ${reviewsSection}
      ${reviewButton}

      ${sameProfessionCards ? `<h2>Autres professionnels en ${escapeHtml(person.profession)}</h2><div class="pros-grid" style="margin-bottom:24px">${sameProfessionCards}</div>` : ""}
      ${sameCityCards ? `<h2>Autres professionnels a ${escapeHtml(person.city)}</h2><div class="pros-grid" style="margin-bottom:24px">${sameCityCards}</div>` : ""}
    `;

    res.send(page(displayName, content, proConnected));
  } catch (error) {
    console.error("Erreur page profil :", error.message);
    res.status(500).send(page("Erreur", "<h2>Une erreur technique est survenue.</h2>", null));
  }
});

/* FORMULAIRE AVIS */

app.get("/pro/:id/avis", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/");

    const result = await pool.query(`SELECT id, full_name, company_name, profession, city FROM professional_applications WHERE id = $1 AND status = 'approved'`, [id]);
    if (!result.rows.length) return res.redirect(303, "/");

    const person = result.rows[0];
    const displayName = getDisplayName(person);

    const content = `
      <section class="card">
        <h1>Laisser un avis</h1>
        <div class="alert alert-info">⭐ Vous allez laisser un avis sur <strong>${escapeHtml(displayName)}</strong> (${escapeHtml(person.profession)}).</div>
        <form action="/pro/${encodeURIComponent(person.id)}/avis" method="POST">
          <label for="author_name">Votre nom *</label>
          <input id="author_name" name="author_name" required maxlength="100" placeholder="Ex : Jean D.">
          <label>Votre note *</label>
          <div class="star-rating-input">
            <input type="radio" id="star5" name="rating" value="5" required><label for="star5" title="Excellent">★</label>
            <input type="radio" id="star4" name="rating" value="4"><label for="star4" title="Tres bien">★</label>
            <input type="radio" id="star3" name="rating" value="3"><label for="star3" title="Bien">★</label>
            <input type="radio" id="star2" name="rating" value="2"><label for="star2" title="Moyen">★</label>
            <input type="radio" id="star1" name="rating" value="1"><label for="star1" title="Mauvais">★</label>
          </div>
          <label for="comment">Votre commentaire (facultatif)</label>
          <textarea id="comment" name="comment" maxlength="1000" rows="5" placeholder="Decrivez votre experience..."></textarea>
          <button type="submit">Envoyer mon avis</button>
          <a class="button secondary" href="/pro/${encodeURIComponent(person.id)}">Annuler</a>
        </form>
      </section>
    `;
    res.send(page("Laisser un avis", content, proConnected));
  } catch (error) {
    res.redirect(303, "/");
  }
});

app.post("/pro/:id/avis", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/");

    const proResult = await pool.query(`SELECT id, full_name, company_name, profession FROM professional_applications WHERE id = $1 AND status = 'approved'`, [id]);
    if (!proResult.rows.length) return res.redirect(303, "/");

    const person = proResult.rows[0];
    const displayName = getDisplayName(person);
    const authorName = String(req.body.author_name || "").trim().slice(0, 100);
    const rating = parseInt(req.body.rating, 10);
    const comment = String(req.body.comment || "").trim().slice(0, 1000);

    if (!authorName || !rating || rating < 1 || rating > 5) {
      return res.status(400).send(page("Avis invalide", `<section class="card"><h2>Avis invalide</h2><p>Le nom et la note (1 a 5) sont obligatoires.</p><a class="button" href="/pro/${encodeURIComponent(person.id)}/avis">Retour</a></section>`, proConnected));
    }

    await pool.query(`INSERT INTO reviews (pro_id, author_name, rating, comment, status) VALUES ($1, $2, $3, $4, 'pending')`, [person.id, authorName, rating, comment || null]);
    res.send(page("Avis envoye", `<section class="card"><h1>Merci pour votre avis !</h1><p>Votre avis sur <strong>${escapeHtml(displayName)}</strong> a bien ete enregistre.</p><a class="button" href="/pro/${encodeURIComponent(person.id)}">Voir le profil</a></section>`, proConnected));
  } catch (error) {
    res.status(500).send(page("Erreur", "<h2>Impossible d'enregistrer votre avis.</h2>", null));
  }
});

/* PAGE EMPLOIS */

app.get("/emplois", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const keyword = String(req.query.keyword || "").trim().slice(0, 150);
    const city = String(req.query.city || "").trim().slice(0, 100);
    const contract = String(req.query.contract || "").trim().slice(0, 50);

    let query = `
      SELECT id, company_name, job_title, city, contract_type, salary, description, qualifications, contact_phone, contact_whatsapp, contact_email, deadline, created_at, expires_at
      FROM job_offers
      WHERE status = 'approved' AND (deadline IS NULL OR deadline >= CURRENT_DATE) AND (expires_at IS NULL OR expires_at > NOW())
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

    const contractOptions = JOB_CONTRACT_TYPES.map((type) => `<option value="${escapeHtml(type)}" ${contract === type ? "selected" : ""}>${escapeHtml(type)}</option>`).join("");

    const alerteEmploi = `
      <div class="alert alert-warning">
        <strong>⚠️ RAPPEL :</strong> Si un recruteur vous demande de l'argent avant l'entretien, veuillez signaler ce recruteur en nous envoyant directement un message en cliquant sur le bouton <strong>"Contact"</strong> de la page d'accueil.
      </div>
    `;

    res.send(page("Offres d'emploi", `
      ${alerteEmploi}
      <section class="card">
        <h1>Rechercher un emploi</h1>
        <form action="/emplois" method="GET">
          <label for="keyword">Metier, poste ou entreprise</label>
          <input id="keyword" name="keyword" value="${escapeHtml(keyword)}" placeholder="Ex. : commercial">
          <label for="city">Ville</label>
          <input id="city" name="city" value="${escapeHtml(city)}" placeholder="Ex. : Cotonou">
          <label for="contract">Type de contrat</label>
          <select id="contract" name="contract"><option value="">Tous les contrats</option>${contractOptions}</select>
          <button type="submit">Rechercher</button>
        </form>
        <a class="button" href="/publier-emploi">Publier une offre (pros uniquement)</a>
      </section>
      <h2>Offres disponibles (${result.rows.length})</h2>
      ${jobs || `<section class="card"><p>Aucune offre ne correspond a votre recherche.</p></section>`}
    `, proConnected));
  } catch (error) {
    res.status(500).send(page("Erreur", "<h2>Impossible de charger les offres d'emploi.</h2>", null));
  }
});

/* FORMULAIRE PROFESSIONNEL */

app.get("/devenir-professionnel", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const citiesResult = await pool.query("SELECT id, name FROM cities ORDER BY display_order ASC");
    const professionsResult = await pool.query("SELECT id, name, category FROM professions ORDER BY display_order ASC");

    const cityOptions = citiesResult.rows.map((c) => `<option value="${escapeHtml(c.name)}">${escapeHtml(c.name)}</option>`).join("");
    const professionsByCategory = {};

    for (const p of professionsResult.rows) {
      const cat = p.category || "Autres";
      if (!professionsByCategory[cat]) professionsByCategory[cat] = [];
      professionsByCategory[cat].push(p.name);
    }

    const professionOptions = Object.entries(professionsByCategory)
      .map(([category, names]) => {
        const options = names.map((name) => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join("");
        return `<optgroup label="${escapeHtml(category)}">${options}</optgroup>`;
      }).join("");

    const content = `
      <section class="card">
        <h1>Devenir professionnel sur TrouveMoi</h1>
        <p>Remplissez le formulaire pour soumettre votre candidature. Votre profil sera examine par notre equipe avant publication.</p>

        <form action="/candidatures" method="POST" enctype="multipart/form-data">
          <label for="full_name">Nom et prenoms *</label>
          <input id="full_name" name="full_name" required maxlength="150">

          <label for="company_name">Nom de la societe ou de l'etablissement (facultatif)</label>
          <input id="company_name" name="company_name" maxlength="200" placeholder="Ex. : Ets Dupont & Fils">

          <label for="phone">Telephone *</label>
          <input id="phone" name="phone" type="tel" required maxlength="30" placeholder="+229...">

          <div class="checkbox-block">
            <label>
              <input type="checkbox" name="phone_public" value="yes" checked>
              <span><strong>J'accepte que mon numero soit visible publiquement</strong></span>
            </label>
          </div>

          <h3>Comment souhaitez-vous recevoir votre code ? *</h3>
          <div class="checkbox-block">
            <label><input type="radio" name="contact_preference" value="whatsapp" required> <span><strong>📱 Par WhatsApp</strong></span></label>
            <div id="whatsapp-number-block" class="hidden" style="margin-top:12px;margin-left:30px">
              <label for="whatsapp_number">Numero WhatsApp (si different)</label>
              <input id="whatsapp_number" name="whatsapp_number" type="tel" maxlength="30">
            </div>
          </div>
          <div class="checkbox-block">
            <label><input type="radio" name="contact_preference" value="email" required> <span><strong>✉️ Par email</strong></span></label>
            <div id="email-block" class="hidden" style="margin-top:12px;margin-left:30px">
              <label for="contact_email">Adresse email *</label>
              <input id="contact_email" name="contact_email" type="email" maxlength="254">
            </div>
          </div>

          <label for="city">Ville *</label>
          <select id="city" name="city" required>
            <option value="">Choisissez votre ville</option>
            ${cityOptions}
          </select>

          <label for="neighborhood">Quartier</label>
          <select id="neighborhood" name="neighborhood"><option value="">Choisissez d'abord une ville</option></select>
          <div id="neighborhood-other-block" class="hidden">
            <label for="neighborhood_other">Precisez votre quartier</label>
            <input id="neighborhood_other" name="neighborhood_other" maxlength="150">
          </div>

          <label for="profession">Profession ou service propose *</label>
          <select id="profession" name="profession" required>
            <option value="">Choisissez un metier</option>
            ${professionOptions}
            <option value="__AUTRE__">Autre (precisez)</option>
          </select>
          <div id="profession-other-block" class="hidden">
            <label for="profession_other">Precisez votre metier *</label>
            <input id="profession_other" name="profession_other" maxlength="150">
          </div>

          <label for="experience">Experience</label>
          <select id="experience" name="experience">
            <option value="">Selectionnez</option>
            <option value="Debutant">Debutant</option>
            <option value="Moins de 2 ans">Moins de 2 ans</option>
            <option value="2 a 5 ans">2 a 5 ans</option>
            <option value="Plus de 5 ans">Plus de 5 ans</option>
          </select>

          <label for="service_description">Description des services *</label>
          <textarea id="service_description" name="service_description" rows="5" required maxlength="3000"></textarea>

          <label for="service_area">Zones d'intervention</label>
          <input id="service_area" name="service_area" maxlength="300">

          <label for="availability">Disponibilite</label>
          <select id="availability" name="availability">
            <option value="">Selectionnez</option>
            <option value="Disponible immediatement">Disponible immediatement</option>
            <option value="Sur rendez-vous">Sur rendez-vous</option>
            <option value="A temps partiel">A temps partiel</option>
          </select>

          <hr style="margin:24px 0;border:none;border-top:1px solid #e5e7eb">
          <h3>Photos</h3>
          <p class="help-text">Formats : JPG, PNG, WEBP. Max : 5 Mo.</p>

          <label for="photo_profil">Photo de profil * (privee)</label>
          <input id="photo_profil" name="photo_profil" type="file" required>

          <label for="photo_identite">Photo d'identite * (privee)</label>
          <input id="photo_identite" name="photo_identite" type="file" required>

          <label for="photo_activite">Photo d'activite (publique)</label>
          <input id="photo_activite" name="photo_activite" type="file">

          <div class="checkbox-block">
            <label><input type="checkbox" name="gdpr_consent" value="yes" required> J'accepte la Politique de confidentialite.</label>
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
          if (!city) { neighborhoodSelect.innerHTML = '<option value="">Choisissez une ville</option>'; return; }
          neighborhoodSelect.innerHTML = '<option value="">Chargement...</option>';
          try {
            const res = await fetch('/api/neighborhoods?city=' + encodeURIComponent(city));
            const data = await res.json();
            neighborhoodSelect.innerHTML = '<option value="">Choisissez un quartier</option>';
            for (const n of data.neighborhoods) {
              const opt = document.createElement('option'); opt.value = n; opt.textContent = n; neighborhoodSelect.appendChild(opt);
            }
            const otherOpt = document.createElement('option'); otherOpt.value = '__AUTRE__'; otherOpt.textContent = 'Autre'; neighborhoodSelect.appendChild(otherOpt);
            neighborhoodOtherBlock.classList.remove('hidden');
          } catch (e) { neighborhoodSelect.innerHTML = '<option value="">Erreur</option>'; }
        });

        neighborhoodSelect.addEventListener('change', function() { if (neighborhoodSelect.value === '__AUTRE__') neighborhoodOtherBlock.classList.remove('hidden'); });
        professionSelect.addEventListener('change', function() { if (professionSelect.value === '__AUTRE__') professionOtherBlock.classList.remove('hidden'); else professionOtherBlock.classList.add('hidden'); });
        whatsappRadio.addEventListener('change', function() { if (whatsappRadio.checked) { whatsappNumberBlock.classList.remove('hidden'); emailBlock.classList.add('hidden'); } });
        emailRadio.addEventListener('change', function() { if (emailRadio.checked) { emailBlock.classList.remove('hidden'); whatsappNumberBlock.classList.add('hidden'); } });
      </script>
    `;
    res.send(page("Devenir professionnel", content, proConnected));
  } catch (error) {
    res.status(500).send(page("Erreur", "<h2>Une erreur technique est survenue.</h2>", null));
  }
});

/* API QUARTIERS */

app.get("/api/neighborhoods", async (req, res) => {
  try {
    const city = String(req.query.city || "").trim();
    if (!city) return res.json({ neighborhoods: [] });
    const cityResult = await pool.query("SELECT id FROM cities WHERE name = $1", [city]);
    if (!cityResult.rows.length) return res.json({ neighborhoods: [] });
    const neighborhoodsResult = await pool.query(`SELECT name FROM neighborhoods WHERE city_id = $1 ORDER BY name ASC`, [cityResult.rows[0].id]);
    res.json({ neighborhoods: neighborhoodsResult.rows.map((n) => n.name) });
  } catch (error) {
    res.status(500).json({ neighborhoods: [] });
  }
});

/* ENREGISTREMENT CANDIDATURES */

app.post("/candidatures", upload.fields([
  { name: "photo_profil", maxCount: 1 },
  { name: "photo_identite", maxCount: 1 },
  { name: "photo_activite", maxCount: 1 }
]), async (req, res) => {
  const { full_name, company_name, phone, phone_public, city, neighborhood, neighborhood_other, profession, profession_other, experience, service_description, service_area, availability, gdpr_consent, contact_preference, whatsapp_number, contact_email } = req.body;

  if (gdpr_consent !== "yes") return res.status(400).send(page("Erreur", "<h2>Consentement RGPD obligatoire.</h2>", null));

  const files = req.files || {};
  const photoProfil = files.photo_profil?.[0];
  const photoIdentite = files.photo_identite?.[0];
  const photoActivite = files.photo_activite?.[0];

  let finalNeighborhood = (neighborhood === "__AUTRE__") ? neighborhood_other : neighborhood;
  let finalProfession = (profession === "__AUTRE__") ? profession_other : profession;
  const pref = contact_preference;
  const phoneIsPublic = phone_public === "yes";
  const finalCompanyName = company_name && company_name.trim() ? company_name.trim() : null;

  if (!full_name || !phone || !city || !finalProfession || !service_description || !photoProfil || !photoIdentite) {
    return res.status(400).send(page("Erreur", "<h2>Informations manquantes.</h2>", null));
  }

  try {
    const timestamp = Date.now();
    const profilResult = await uploadToCloudinary(photoProfil.buffer, "trouvemoi/profils", `profil_${timestamp}`);
    const identiteResult = await uploadToCloudinary(photoIdentite.buffer, "trouvemoi/identites", `identite_${timestamp}`);
    let photoActiviteUrl = null;
    if (photoActivite) {
      const actResult = await uploadToCloudinary(photoActivite.buffer, "trouvemoi/activites", `activite_${timestamp}`);
      photoActiviteUrl = actResult.secure_url;
    }

    const result = await pool.query(`
      INSERT INTO professional_applications (
        full_name, company_name, phone, phone_public, city, neighborhood, profession,
        experience, service_description, service_area, availability, npi,
        photo_profil_url, photo_identite_url, photo_activite_url,
        contact_preference, whatsapp_number, contact_email, pro_code, status
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,$12,$13,$14,$15,$16,$17,NULL,'pending')
      RETURNING id
    `, [full_name, finalCompanyName, phone, phoneIsPublic, city, finalNeighborhood, finalProfession, experience, service_description, service_area, availability, profilResult.secure_url, identiteResult.secure_url, photoActiviteUrl, pref, whatsapp_number, contact_email]);

    res.send(page("Candidature envoyee", `<section class="card"><h1>Succes !</h1><p>Votre candidature (Ref: ${result.rows[0].id}) est en attente.</p><a class="button" href="/">Retour</a></section>`, null));
  } catch (error) {
    res.status(500).send(page("Erreur", "<h2>Impossible d'enregistrer.</h2>", null));
  }
});

/* PUBLICATION EMPLOI */

app.get("/publier-emploi", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.send(page("Erreur", "<section class='card'><h2>Reserve aux pros verifies.</h2><a href='/mon-espace-pro'>Se connecter</a></section>", null));
  
  const contractOptions = JOB_CONTRACT_TYPES.map((type) => `<option value="${escapeHtml(type)}">${escapeHtml(type)}</option>`).join("");

  res.send(page("Publier une offre", `
    <section class="card">
      <h1>Publier une offre d'emploi</h1>
      <form action="/offres-emploi" method="POST">
        <label for="company_name">Nom de l'entreprise *</label>
        <input id="company_name" name="company_name" required value="${escapeHtml(getDisplayName(proConnected.pro))}">
        <label for="job_title">Intitule du poste *</label>
        <input id="job_title" name="job_title" required>
        <label for="city">Ville *</label>
        <input id="city" name="city" required value="${escapeHtml(proConnected.pro.city)}">
        <label for="contract_type">Type de contrat *</label>
        <select id="contract_type" name="contract_type" required><option value="">Choisir</option>${contractOptions}</select>
        <label for="description">Description *</label>
        <textarea id="description" name="description" required></textarea>
        <label for="contact_phone">Telephone</label>
        <input id="contact_phone" name="contact_phone" type="tel">
        <button type="submit">Soumettre</button>
      </form>
      <p><a href="/mon-espace-pro">Retour</a></p>
    </section>
  `, proConnected));
});

app.post("/offres-emploi", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/publier-emploi");
  const { company_name, job_title, city, contract_type, description, contact_phone } = req.body;
  try {
    await pool.query(`
      INSERT INTO job_offers (company_name, job_title, city, contract_type, description, contact_phone, status, pro_id, expires_at)
      VALUES ($1,$2,$3,$4,$5,$6,'pending',$7, NOW() + INTERVAL '${OFFER_DURATION_DAYS} days')
    `, [company_name, job_title, city, contract_type, description, contact_phone, proConnected.pro.id]);
    res.send(page("Succes", "<section class='card'><h1>Offre soumise !</h1><a href='/mon-espace-pro'>Retour</a></section>", proConnected));
  } catch (e) { res.status(500).send("Erreur"); }
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
          <input id="pro_code" name="pro_code" required maxlength="10" placeholder="TM12345" style="text-transform:uppercase">
          <button type="submit">Se connecter</button>
        </form>
      </section>
    `, null));
  }

  let offers = [];
  let gdprRequests = [];
  let myReviews = [];

  try {
    const offersResult = await pool.query(`SELECT id, company_name, job_title, city, contract_type, salary, description, qualifications, contact_phone, contact_whatsapp, contact_email, deadline, status, created_at, expires_at FROM job_offers WHERE pro_id = $1 ORDER BY created_at DESC`, [proConnected.pro.id]);
    offers = offersResult.rows;

    const gdprResult = await pool.query(`SELECT id, request_type, status, created_at, processed_at FROM gdpr_requests WHERE pro_id = $1 ORDER BY created_at DESC LIMIT 20`, [proConnected.pro.id]);
    gdprRequests = gdprResult.rows;

    const reviewsResult = await pool.query(`SELECT id, author_name, rating, comment, status, created_at FROM reviews WHERE pro_id = $1 ORDER BY created_at DESC LIMIT 10`, [proConnected.pro.id]);
    myReviews = reviewsResult.rows;
  } catch (error) {
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
        <p><span class="badge badge-${offer.status}">${escapeHtml(statusLabel)}</span> ${isPublic ? `<span class="badge badge-approved">En ligne</span>` : ""} ${expired ? `<span class="badge badge-rejected">Expiree</span>` : ""}</p>
        <p><span class="label">Entreprise :</span> <span class="value">${escapeHtml(offer.company_name)}</span></p>
        <p><span class="label">Ville :</span> <span class="value">${escapeHtml(offer.city)}</span></p>
        ${offer.expires_at ? `<p class="muted">Expire le : ${new Date(offer.expires_at).toLocaleDateString("fr-FR")}</p>` : ""}
        <div class="actions">
          ${offer.status === "approved" && !expired ? `<form action="/mon-espace-pro/offre/${offer.id}/close" method="POST" style="display:inline"><button class="warning" type="submit">🔒 Cloturer</button></form>` : ""}
          ${offer.status === "closed" ? `<form action="/mon-espace-pro/offre/${offer.id}/reopen" method="POST" style="display:inline"><button class="success" type="submit">🔓 Rouvrir</button></form>` : ""}
          <a class="button secondary" href="/mon-espace-pro/offre/${offer.id}/modifier">✏️ Modifier</a>
        </div>
      </article>
    `;
  }).join("");

  const gdprHtml = gdprRequests.map((req) => `
    <article class="card" style="padding:16px">
      <p><span class="badge badge-${req.status}">${escapeHtml(GDPR_STATUS_LABELS[req.status])}</span> <strong>${escapeHtml(GDPR_TYPE_LABELS[req.request_type])}</strong></p>
      <p class="muted">Demande le : ${new Date(req.created_at).toLocaleString("fr-FR")}</p>
    </article>
  `).join("");

  const myReviewsHtml = myReviews.map((rev) => `
    <div class="review-item">
      <div class="review-header"><div class="review-author">${escapeHtml(rev.author_name)}</div><div><span class="badge badge-${rev.status}">${escapeHtml(REVIEW_STATUS_LABELS[rev.status])}</span></div></div>
      <div class="review-stars">${renderStars(rev.rating)}</div>
      ${rev.comment ? `<div class="review-comment">${escapeHtml(rev.comment)}</div>` : ""}
    </div>
  `).join("");

  const phoneStatus = proConnected.pro.phone_public ? `<span class="badge badge-approved">Public</span> Votre numero est visible.` : `<span class="badge badge-closed">Prive</span> Votre numero est cache.`;
  let contactInfoBlock = "";
  if (proConnected.pro.contact_preference === "whatsapp" && proConnected.pro.whatsapp_number) contactInfoBlock = `<p><span class="label">Reception code :</span> WhatsApp (${escapeHtml(proConnected.pro.whatsapp_number)})</p>`;
  else if (proConnected.pro.contact_preference === "email" && proConnected.pro.contact_email) contactInfoBlock = `<p><span class="label">Reception code :</span> Email (${escapeHtml(proConnected.pro.contact_email)})</p>`;
  
  const companyBlock = proConnected.pro.company_name ? `<p><span class="label">Societe :</span> ${escapeHtml(proConnected.pro.company_name)}</p>` : "";
  const displayName = getDisplayName(proConnected.pro);

  res.send(page("Mon espace pro", `
    <section class="card">
      <h1>Bonjour ${escapeHtml(displayName)} 👋</h1>
      <div class="pro-code-box">
        <div class="pro-code-label">Votre code professionnel</div>
        <div class="pro-code-value">${escapeHtml(proConnected.code)}</div>
      </div>
      <div class="actions"><a class="button" href="/publier-emploi">📢 Publier une offre</a><a class="button secondary" href="/">🌐 Voir le site</a></div>
      <form action="/mon-espace-pro/logout" method="POST" style="display:inline"><button class="danger" type="submit">Deconnexion</button></form>
    </section>

    <section class="card">
      <h2>Mes informations</h2>
      ${companyBlock}
      <p><span class="label">Nom :</span> ${escapeHtml(proConnected.pro.full_name)}</p>
      <p><span class="label">Profession :</span> ${escapeHtml(proConnected.pro.profession)}</p>
      <p><span class="label">Ville :</span> ${escapeHtml(proConnected.pro.city)}</p>
      <p><span class="label">Telephone :</span> ${escapeHtml(proConnected.pro.phone)}</p>
      <p><span class="label">Visibilite :</span> ${phoneStatus}</p>
      ${contactInfoBlock}
      <div class="actions"><a class="button secondary" href="/mon-espace-pro/modifier-telephone">Modifier la visibilite</a></div>
    </section>

    <section class="card"><h2>Mes avis recus (${myReviews.length})</h2>${myReviewsHtml || `<p class="muted">Aucun avis.</p>`}</section>
    <section class="card"><h2>Mes offres d'emploi (${offers.length})</h2></section>
    ${offersHtml || `<section class="card"><p class="muted">Aucune offre.</p><a class="button" href="/publier-emploi">Publier</a></section>`}

    <section class="card">
      <h2>Mes droits (RGPD)</h2>
      <div class="actions">
        <a class="button" href="/mon-espace-pro/mes-donnees">📥 Telecharger mes donnees</a>
        <form action="/mon-espace-pro/demande-suppression" method="POST" style="display:inline"><button class="danger" type="submit">🗑️ Demander suppression</button></form>
      </div>
      ${gdprHtml ? `<h3 style="margin-top:24px">Historique</h3>${gdprHtml}` : ""}
    </section>
  `, proConnected));
});

app.post("/mon-espace-pro/login", async (req, res) => {
  const code = String(req.body.pro_code || "").trim().toUpperCase();
  if (!/^TM\d{5}$/.test(code)) return res.status(400).send(page("Erreur", "<h2>Code invalide.</h2>", null));
  try {
    const result = await pool.query(`SELECT id FROM professional_applications WHERE pro_code = $1 AND status = 'approved'`, [code]);
    if (!result.rows.length) return res.status(401).send(page("Erreur", "<h2>Code incorrect.</h2>", null));
    setProCookie(res, code);
    res.redirect(303, "/mon-espace-pro");
  } catch (error) { res.redirect(303, "/mon-espace-pro"); }
});

app.post("/mon-espace-pro/logout", (req, res) => { clearProCookie(res); res.redirect(303, "/mon-espace-pro"); });

app.get("/mon-espace-pro/modifier-telephone", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  res.send(page("Modifier", `<section class="card"><h1>Visibilite</h1><form action="/mon-espace-pro/modifier-telephone" method="POST"><div class="checkbox-block"><label><input type="checkbox" name="phone_public" value="yes" ${proConnected.pro.phone_public ? "checked" : ""}> Rendre mon numero public</label></div><button type="submit">Enregistrer</button></form></section>`, proConnected));
});

app.post("/mon-espace-pro/modifier-telephone", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  const phonePublic = req.body.phone_public === "yes";
  await pool.query(`UPDATE professional_applications SET phone_public = $1 WHERE id = $2`, [phonePublic, proConnected.pro.id]);
  res.redirect(303, "/mon-espace-pro");
});

app.get("/mon-espace-pro/mes-donnees", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  const offersResult = await pool.query(`SELECT * FROM job_offers WHERE pro_id = $1`, [proConnected.pro.id]);
  const gdprResult = await pool.query(`SELECT * FROM gdpr_requests WHERE pro_id = $1`, [proConnected.pro.id]);
  const reviewsResult = await pool.query(`SELECT * FROM reviews WHERE pro_id = $1`, [proConnected.pro.id]);
  
  const exportData = { utilisateur: proConnected.pro, offres: offersResult.rows, demandes: gdprResult.rows, avis: reviewsResult.rows };
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="trouvemoi-${proConnected.code}.json"`);
  res.send(JSON.stringify(exportData, null, 2));
});

app.post("/mon-espace-pro/demande-suppression", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  await pool.query(`INSERT INTO gdpr_requests (pro_id, request_type, status, message) VALUES ($1, 'deletion', 'pending', $2)`, [proConnected.pro.id, "Demande espace pro"]);
  res.send(page("Demande envoyee", "<section class='card'><h1>Demande envoyee</h1><p>L'admin va traiter votre demande.</p><a href='/mon-espace-pro'>Retour</a></section>", proConnected));
});

app.post("/mon-espace-pro/offre/:id/close", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (proConnected) await pool.query(`UPDATE job_offers SET status = 'closed' WHERE id = $1 AND pro_id = $2`, [Number(req.params.id), proConnected.pro.id]);
  res.redirect(303, "/mon-espace-pro");
});

app.post("/mon-espace-pro/offre/:id/reopen", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (proConnected) await pool.query(`UPDATE job_offers SET status = 'approved', expires_at = NOW() + INTERVAL '${OFFER_DURATION_DAYS} days' WHERE id = $1 AND pro_id = $2`, [Number(req.params.id), proConnected.pro.id]);
  res.redirect(303, "/mon-espace-pro");
});

app.post("/mon-espace-pro/offre/:id/renew", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (proConnected) await pool.query(`UPDATE job_offers SET expires_at = GREATEST(COALESCE(expires_at, NOW()), NOW()) + INTERVAL '${OFFER_DURATION_DAYS} days' WHERE id = $1 AND pro_id = $2`, [Number(req.params.id), proConnected.pro.id]);
  res.redirect(303, "/mon-espace-pro");
});

/* CONNEXION ADMINISTRATEUR */

const loginAttempts = new Map();

app.get("/admin", (req, res) => {
  const session = verifySessionToken(readCookie(req, SESSION_COOKIE));
  if (session) return res.redirect(303, "/admin/dashboard");

  res.setHeader("Cache-Control", "no-store");
  res.send(page("Admin", `<section class="card"><h1>Administration</h1><form action="/admin/login" method="POST"><label>Mot de passe</label><input type="password" name="password" required><button>Se connecter</button></form></section>`, null));
});

app.post("/admin/login", (req, res) => {
  const now = Date.now();
  const address = req.ip || "unknown";
  const current = loginAttempts.get(address);

  if (current && current.count >= 5) return res.status(429).send("Trop de tentatives.");

  if (!safeEqual(req.body.password || "", process.env.ADMIN_PASSWORD || "")) {
    if (current) current.count += 1; else loginAttempts.set(address, { count: 1, startedAt: now });
    return res.status(401).send(page("Refuse", "<h2>Mot de passe incorrect.</h2>", null));
  }

  loginAttempts.delete(address);
  const session = { expiresAt: Date.now() + SESSION_DURATION, csrf: crypto.randomBytes(32).toString("hex") };
  setSessionCookie(res, createSessionToken(session));
  res.redirect(303, "/admin/dashboard");
});

async function adminMenu(current, csrf) {
  let gdprCount = 0, prosPendingCount = 0, reviewsPendingCount = 0;
  try {
    gdprCount = Number((await pool.query("SELECT COUNT(*) FROM gdpr_requests WHERE status = 'pending'")).rows[0].count);
    prosPendingCount = Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status = 'pending'")).rows[0].count);
    reviewsPendingCount = Number((await pool.query("SELECT COUNT(*) FROM reviews WHERE status = 'pending'")).rows[0].count);
  } catch (e) {}

  const links = [
    { href: "/admin/dashboard", label: "📊 Tableau de bord", badge: 0 },
    { href: "/admin/candidatures", label: "📋 Candidatures", badge: prosPendingCount },
    { href: "/admin/avis", label: "⭐ Avis", badge: reviewsPendingCount },
    { href: "/admin/emplois", label: "💼 Offres", badge: 0 },
    { href: "/admin/rgpd", label: "🔐 RGPD", badge: gdprCount }
  ];

  return `
    <section class="card">
      <div class="actions">
        ${links.map(l => `<a class="button ${current === l.href ? "" : "secondary"}" href="${l.href}">${l.label}${l.badge > 0 ? ` <span class="badge badge-new">${l.badge}</span>` : ""}</a>`).join("")}
      </div>
      <form action="/admin/logout" method="POST"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><button class="danger">Deconnexion</button></form>
    </section>
  `;
}

app.get("/admin/dashboard", requireAdmin, async (req, res) => {
  const stats = {
    pros: Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status = 'approved'")).rows[0].count),
    prosPending: Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status = 'pending'")).rows[0].count),
    jobs: Number((await pool.query("SELECT COUNT(*) FROM job_offers WHERE status = 'approved'")).rows[0].count),
    reviews: Number((await pool.query("SELECT COUNT(*) FROM reviews WHERE status = 'pending'")).rows[0].count),
    gdpr: Number((await pool.query("SELECT COUNT(*) FROM gdpr_requests WHERE status = 'pending'")).rows[0].count)
  };
  const menu = await adminMenu("/admin/dashboard", getCsrf(req));

  res.send(page("Dashboard", `
    <section class="card"><h1>Bienvenue Admin</h1></section>
    ${menu}
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-number">${stats.pros}</div><div class="stat-label">Pros approuves</div></div>
      <div class="stat-card warning"><div class="stat-number">${stats.prosPending}</div><div class="stat-label">Candidatures en attente</div></div>
      <div class="stat-card danger"><div class="stat-number">${stats.reviews}</div><div class="stat-label">Avis a moderer</div></div>
    </div>
  `, null));
});

/* ADMIN CANDIDATURES */

app.get("/admin/candidatures", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  const result = await pool.query(`
    SELECT p.*, 
    (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count 
    FROM professional_applications p ORDER BY status = 'pending' DESC, created_at DESC
  `);

  const applications = result.rows.map(c => {
    const statusOptions = ALLOWED_STATUSES.map(s => `<option value="${s}" ${c.status === s ? "selected" : ""}>${STATUS_LABELS[s]}</option>`).join("");
    const photos = `
      <div class="photos-grid">
        ${c.photo_profil_url ? `<div class="photo-block"><img src="${escapeHtml(c.photo_profil_url)}" class="photo-profil"><div class="photo-label">Profil</div></div>` : ""}
        ${c.photo_identite_url ? `<div class="photo-block"><img src="${escapeHtml(c.photo_identite_url)}" class="photo-identite"><div class="photo-label">Identite</div></div>` : ""}
        ${c.photo_activite_url ? `<div class="photo-block"><img src="${escapeHtml(c.photo_activite_url)}" class="photo-activite"><div class="photo-label">Activite</div></div>` : ""}
      </div>`;
    let codeBlock = "";
    if (c.pro_code) {
      codeBlock = `<div class="pro-code-box"><div class="pro-code-value">${escapeHtml(c.pro_code)}</div></div>`;
    }

    return `
      <article class="card">
        <h2>${escapeHtml(c.full_name)}</h2>
        ${photos}
        <p><span class="label">Ville :</span> ${escapeHtml(c.city)}</p>
        <p><span class="label">Profession :</span> ${escapeHtml(c.profession)}</p>
        <p><span class="label">Statut :</span> ${STATUS_LABELS[c.status]}</p>
        ${codeBlock}
        <form action="/admin/candidatures/${c.id}/status" method="POST">
          <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
          <select name="status">${statusOptions}</select>
          <button>Enregistrer</button>
        </form>
        <form action="/admin/candidatures/${c.id}/supprimer" method="POST" style="margin-top:12px">
          <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
          <button class="danger" onclick="return confirm('Supprimer ?')">🗑️ Supprimer</button>
        </form>
      </article>
    `;
  }).join("");

  const menu = await adminMenu("/admin/candidatures", csrf);
  res.send(page("Candidatures", `<section class="card"><h1>Candidatures</h1></section>${menu}${applications}`, null));
});

app.post("/admin/candidatures/:id/status", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id), status = req.body.status;
  if (!ALLOWED_STATUSES.includes(status)) return res.redirect(303, "/admin/candidatures");
  const existing = await pool.query("SELECT pro_code FROM professional_applications WHERE id = $1", [id]);
  if (status === "approved" && !existing.rows[0].pro_code) {
    const newCode = await generateUniqueProCode();
    await pool.query(`UPDATE professional_applications SET status = $1, pro_code = $2 WHERE id = $3`, [status, newCode, id]);
  } else {
    await pool.query(`UPDATE professional_applications SET status = $1 WHERE id = $2`, [status, id]);
  }
  res.redirect(303, "/admin/candidatures");
});

app.post("/admin/candidatures/:id/supprimer", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  const proResult = await pool.query(`SELECT photo_profil_url, photo_identite_url, photo_activite_url FROM professional_applications WHERE id = $1`, [id]);
  if (proResult.rows.length) {
    const p = proResult.rows[0];
    await deleteFromCloudinary(p.photo_profil_url); await deleteFromCloudinary(p.photo_identite_url); await deleteFromCloudinary(p.photo_activite_url);
  }
  await pool.query(`DELETE FROM reviews WHERE pro_id = $1`, [id]);
  await pool.query(`DELETE FROM gdpr_requests WHERE pro_id = $1`, [id]);
  await pool.query(`DELETE FROM job_offers WHERE pro_id = $1`, [id]);
  await pool.query(`DELETE FROM professional_applications WHERE id = $1`, [id]);
  res.redirect(303, "/admin/candidatures");
});

/* ADMIN AVIS */

app.get("/admin/avis", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  const result = await pool.query(`SELECT r.*, p.full_name AS pro_name FROM reviews r LEFT JOIN professional_applications p ON p.id = r.pro_id ORDER BY status = 'pending' DESC`);
  const reviews = result.rows.map(r => `
    <article class="card">
      <h2>Avis de ${escapeHtml(r.author_name)} sur ${escapeHtml(r.pro_name || "Inconnu")}</h2>
      <div class="review-stars">${renderStars(r.rating)}</div>
      <p>${escapeHtml(r.comment || "Aucun commentaire")}</p>
      <div class="actions">
        <form action="/admin/avis/${r.id}/statut" method="POST" style="display:inline">
          <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><input type="hidden" name="status" value="approved"><button class="success">Approuver</button>
        </form>
        <form action="/admin/avis/${r.id}/statut" method="POST" style="display:inline">
          <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><input type="hidden" name="status" value="rejected"><button class="danger">Rejeter</button>
        </form>
      </div>
    </article>
  `).join("");
  const menu = await adminMenu("/admin/avis", csrf);
  res.send(page("Avis", `<section class="card"><h1>Moderation des avis</h1></section>${menu}${reviews}`, null));
});

app.post("/admin/avis/:id/statut", requireAdmin, verifyCsrf, async (req, res) => {
  if (REVIEW_STATUSES.includes(req.body.status)) {
    await pool.query(`UPDATE reviews SET status = $1 WHERE id = $2`, [req.body.status, Number(req.params.id)]);
  }
  res.redirect(303, "/admin/avis");
});

/* ADMIN EMPLOIS */

app.get("/admin/emplois", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  const result = await pool.query(`SELECT j.*, p.full_name AS pro_name FROM job_offers j LEFT JOIN professional_applications p ON p.id = j.pro_id ORDER BY status = 'pending' DESC`);
  const jobs = result.rows.map(j => `
    <article class="card">
      <h2>${escapeHtml(j.job_title)}</h2>
      <p>Posté par : ${escapeHtml(j.pro_name || "Inconnu")}</p>
      <p>${escapeHtml(j.description)}</p>
      <form action="/admin/emplois/${j.id}/status" method="POST">
        <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
        <select name="status">${JOB_STATUSES.map(s => `<option value="${s}" ${j.status === s ? "selected" : ""}>${JOB_STATUS_LABELS[s]}</option>`).join("")}</select>
        <button>Modifier</button>
      </form>
    </article>
  `).join("");
  const menu = await adminMenu("/admin/emplois", csrf);
  res.send(page("Emplois", `<section class="card"><h1>Offres d'emploi</h1></section>${menu}${jobs}`, null));
});

app.post("/admin/emplois/:id/status", requireAdmin, verifyCsrf, async (req, res) => {
  if (JOB_STATUSES.includes(req.body.status)) {
    await pool.query(`UPDATE job_offers SET status = $1 WHERE id = $2`, [req.body.status, Number(req.params.id)]);
  }
  res.redirect(303, "/admin/emplois");
});

/* ADMIN RGPD */

app.get("/admin/rgpd", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  const result = await pool.query(`SELECT g.*, p.full_name AS pro_name FROM gdpr_requests g LEFT JOIN professional_applications p ON p.id = g.pro_id ORDER BY status = 'pending' DESC`);
  const reqs = result.rows.map(r => `
    <article class="card">
      <h2>${GDPR_TYPE_LABELS[r.request_type]} - ${escapeHtml(r.pro_name || "Inconnu")}</h2>
      <p>${escapeHtml(r.message)}</p>
      ${r.status === "pending" ? `
        <form action="/admin/rgpd/${r.id}/traiter" method="POST">
          <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
          <button class="success">Marquer traitee</button>
        </form>
      ` : `<p class="badge badge-${r.status}">${GDPR_STATUS_LABELS[r.status]}</p>`}
    </article>
  `).join("");
  const menu = await adminMenu("/admin/rgpd", csrf);
  res.send(page("RGPD", `<section class="card"><h1>Demandes RGPD</h1></section>${menu}${reqs}`, null));
});

app.post("/admin/rgpd/:id/traiter", requireAdmin, verifyCsrf, async (req, res) => {
  await pool.query(`UPDATE gdpr_requests SET status = 'processed' WHERE id = $1`, [Number(req.params.id)]);
  res.redirect(303, "/admin/rgpd");
});

app.post("/admin/logout", requireAdmin, verifyCsrf, (req, res) => {
  clearSessionCookie(res);
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
      <p>Simplifier la recherche de professionnels de confiance au Benin. TrouveMoi centralise les pros de votre ville et vous permet de les contacter en un clic.</p>
      <h2>Nos services</h2>
      <ul style="margin-left:20px;margin-bottom:16px">
        <li>Annuaire de professionnels verifies</li>
        <li>Recherche par ville, quartier et metier</li>
        <li>Contact direct par telephone ou WhatsApp</li>
        <li>Offres d'emploi</li>
        <li>Avis clients moderes</li>
      </ul>
      <p style="margin-top:24px"><a class="button" href="/contact">Nous contacter</a> <a class="button secondary" href="/">Voir les professionnels</a></p>
    </section>
  `, proConnected));
});

app.get("/conditions", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  res.send(page("Conditions", `
    <section class="card">
      <h1>Conditions d'utilisation</h1>
      <p class="muted">Derniere mise a jour : ${new Date().toLocaleDateString("fr-FR")}</p>
      <h2>1. Acceptation</h2><p>En utilisant TrouveMoi, vous acceptez ces conditions.</p>
      <h2>2. Nature du service</h2><p>TrouveMoi est une plateforme de mise en relation. Nous ne fournissons pas directement de services professionnels.</p>
      <h2>3. Inscription des professionnels</h2><p>Les pros doivent fournir des informations exactes. Toute fausse declaration entraine le rejet.</p>
      <h2>4. Publication d'offres</h2><p>Seuls les pros verifies peuvent publier des offres. Toute offre est examinee avant publication.</p>
      <h2>5. Avis clients</h2><p>Les avis sont moderes. Tout avis injurieux sera supprime.</p>
      <h2>6. Responsabilites</h2><p>TrouveMoi ne peut etre tenu responsable de la qualite des services fournis par les pros.</p>
    </section>
  `, proConnected));
});

app.get("/confidentialite", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  res.send(page("Confidentialite", `
    <section class="card">
      <h1>Politique de confidentialite</h1>
      <p class="muted">Derniere mise a jour : ${new Date().toLocaleDateString("fr-FR")}</p>
      <h2>1. Donnees collectees</h2><p>Nom, telephone, ville, metier, photos, avis, messages.</p>
      <h2>2. Utilisation</h2><p>Mise en relation, affichage des profils, gestion des offres et avis.</p>
      <h2>3. Protection</h2><p>Les photos d'identite sont strictement privees.</p>
      <h2>4. Vos droits</h2><p>Vous disposez des droits d'acces, rectification, suppression et opposition. Contactez-nous via le <a href="/contact">formulaire de contact</a>.</p>
    </section>
  `, proConnected));
});

app.get("/contact", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  res.send(page("Contact", `
    <section class="card">
      <h1>Nous contacter</h1>
      <p>Une question, une suggestion, un probleme ? Ecrivez-nous.</p>
      <form action="/contact" method="POST">
        <label>Votre nom *</label><input name="name" required>
        <label>Votre email</label><input type="email" name="email">
        <label>Votre telephone</label><input type="tel" name="phone">
        <label>Sujet *</label><input name="subject" required>
        <label>Message *</label><textarea name="message" required rows="6"></textarea>
        <button type="submit">Envoyer</button>
      </form>
    </section>
  `, proConnected));
});

app.post("/contact", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const { name, email, phone, subject, message } = req.body;
  if (!name || !subject || !message || (!email && !phone)) {
    return res.status(400).send(page("Erreur", "<section class='card'><h2>Informations manquantes.</h2></section>", proConnected));
  }
  try {
    await pool.query(`INSERT INTO contact_messages (name, email, phone, subject, message) VALUES ($1, $2, $3, $4, $5)`, [name, email, phone, subject, message]);
    res.send(page("Succes", "<section class='card'><h1>Message envoye !</h1><a href='/'>Retour</a></section>", proConnected));
  } catch (e) {
    res.status(500).send(page("Erreur", "<h2>Erreur d'envoi.</h2>", proConnected));
  }
});

app.get("/health", (req, res) => res.json({ status: "ok" }));
app.get("/health/database", async (req, res) => {
  try { await pool.query("SELECT 1"); res.json({ status: "ok", database: "connected" }); }
  catch (e) { res.status(500).json({ status: "error" }); }
});

/* DEMARRAGE */

async function startServer() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS professional_applications (
        id SERIAL PRIMARY KEY, full_name VARCHAR(150) NOT NULL, company_name VARCHAR(200),
        phone VARCHAR(30) NOT NULL, phone_public BOOLEAN NOT NULL DEFAULT true,
        city VARCHAR(100) NOT NULL, neighborhood VARCHAR(150), profession VARCHAR(150) NOT NULL,
        experience VARCHAR(100), service_description TEXT NOT NULL, service_area VARCHAR(300),
        availability VARCHAR(100), npi VARCHAR(100), photo_profil_url TEXT, photo_identite_url TEXT,
        photo_activite_url TEXT, contact_preference VARCHAR(20), whatsapp_number VARCHAR(30),
        contact_email VARCHAR(254), pro_code VARCHAR(10) UNIQUE, status VARCHAR(30) NOT NULL DEFAULT 'pending',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`ALTER TABLE professional_applications ALTER COLUMN npi DROP NOT NULL`);
    await pool.query(`CREATE TABLE IF NOT EXISTS job_offers (
      id SERIAL PRIMARY KEY, company_name VARCHAR(200) NOT NULL, job_title VARCHAR(200) NOT NULL,
      city VARCHAR(100) NOT NULL, contract_type VARCHAR(50) NOT NULL, salary VARCHAR(100),
      description TEXT NOT NULL, qualifications TEXT, contact_phone VARCHAR(30),
      contact_whatsapp VARCHAR(30), contact_email VARCHAR(254), deadline DATE,
      status VARCHAR(20) NOT NULL DEFAULT 'pending', pro_id INTEGER REFERENCES professional_applications(id) ON DELETE SET NULL,
      expires_at TIMESTAMP, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS cities (id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL UNIQUE, display_order INTEGER NOT NULL DEFAULT 0)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS neighborhoods (id SERIAL PRIMARY KEY, city_id INTEGER NOT NULL REFERENCES cities(id) ON DELETE CASCADE, name VARCHAR(150) NOT NULL, UNIQUE (city_id, name))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS professions (id SERIAL PRIMARY KEY, name VARCHAR(150) NOT NULL UNIQUE, category VARCHAR(100), display_order INTEGER NOT NULL DEFAULT 0)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS contact_messages (id SERIAL PRIMARY KEY, name VARCHAR(150) NOT NULL, email VARCHAR(254), phone VARCHAR(30), subject VARCHAR(200) NOT NULL, message TEXT NOT NULL, is_read BOOLEAN NOT NULL DEFAULT false, pro_id INTEGER REFERENCES professional_applications(id) ON DELETE SET NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS gdpr_requests (id SERIAL PRIMARY KEY, pro_id INTEGER REFERENCES professional_applications(id) ON DELETE SET NULL, request_type VARCHAR(30) NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'pending', message TEXT, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, processed_at TIMESTAMP)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS reviews (id SERIAL PRIMARY KEY, pro_id INTEGER NOT NULL REFERENCES professional_applications(id) ON DELETE CASCADE, author_name VARCHAR(100) NOT NULL, rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5), comment TEXT, status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')), created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, processed_at TIMESTAMP)`);

    const citiesData = [["Cotonou", 1], ["Abomey-Calavi", 2], ["Porto-Novo", 3], ["Parakou", 4], ["Bohicon", 5], ["Natitingou", 6], ["Ouidah", 7]];
    for (const [name, order] of citiesData) {
      await pool.query(`INSERT INTO cities (name, display_order) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING`, [name, order]);
    }

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
      const cityRes = await pool.query("SELECT id FROM cities WHERE name = $1", [cityName]);
      if (cityRes.rows.length) {
        for (const n of neighborhoods) {
          await pool.query(`INSERT INTO neighborhoods (city_id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [cityRes.rows[0].id, n]);
        }
      }
    }

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
      await pool.query(`INSERT INTO professions (name, category, display_order) VALUES ($1, $2, $3) ON CONFLICT (name) DO NOTHING`, [name, category, orderCounter]);
    }

    console.log("Toutes les tables sont pretes.");
    app.listen(PORT, "0.0.0.0", () => { console.log(`TrouveMoi demarre sur le port ${PORT}.`); });
  } catch (error) {
    console.error("Erreur au demarrage :", error);
    process.exit(1);
  }
}

startServer();
