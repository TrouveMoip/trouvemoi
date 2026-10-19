const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) { console.error("Erreur : DATABASE_URL manquante."); process.exit(1); }
if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) { console.error("Erreur : Variables Cloudinary manquantes."); process.exit(1); }

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 4 },
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg", "image/jpg", "image/png", "image/webp"];
    if (!allowed.includes(file.mimetype)) return cb(new Error("Format non autorise."));
    cb(null, true);
  }
});

function uploadToCloudinary(buffer, folder, publicId) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: folder, public_id: publicId, resource_type: "image", transformation: [{ width: 800, height: 800, crop: "limit" }, { quality: "auto" }, { fetch_format: "auto" }] },
      (error, result) => { if (error) return reject(error); resolve(result); }
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
  } catch (error) { console.error("Erreur suppression Cloudinary :", error.message); }
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false }
});

pool.on("error", (error) => console.error("Erreur DB :", error.message));

app.use(express.urlencoded({ extended: true, limit: "20kb" }));
app.use(express.json({ limit: "20kb" }));
app.disable("x-powered-by");
app.set("trust proxy", 1); // ✅ Correctif : IP réelle derrière proxy (Render/Heroku)

const SESSION_COOKIE = "tm_admin_session";
const SESSION_DURATION = 4 * 60 * 60 * 1000;
const PRO_COOKIE = "tm_pro_session";

const ALLOWED_STATUSES = ["pending", "under_review", "approved", "rejected", "corrections_requested"];
const STATUS_LABELS = { pending: "En attente", under_review: "En cours", approved: "Approuvee", rejected: "Refusee", corrections_requested: "Corrections demandees" };
const JOB_STATUSES = ["pending", "approved", "rejected", "closed"];
const JOB_STATUS_LABELS = { pending: "En attente", approved: "Approuvee", rejected: "Refusee", closed: "Cloturee" };
const REVIEW_STATUSES = ["pending", "approved", "rejected"];
const REVIEW_STATUS_LABELS = { pending: "En attente", approved: "Approuve", rejected: "Rejete" };
const GDPR_REQUEST_TYPES = ["access", "deletion", "rectification", "opposition"];
const GDPR_TYPE_LABELS = { access: "Acces", deletion: "Suppression", rectification: "Rectification", opposition: "Opposition" };
const GDPR_STATUSES = ["pending", "processed", "rejected"];
const GDPR_STATUS_LABELS = { pending: "En attente", processed: "Traitee", rejected: "Refusee" };
const JOB_CONTRACT_TYPES = ["CDI", "CDD", "Stage", "Interim", "Freelance", "Apprentissage", "Autre"];
const OFFER_DURATION_DAYS = 15;
const CONTACT_PREFERENCES = ["whatsapp", "email"];

// ✅ Correctif : Maps anti-bruteforce
const loginAttempts = new Map();
const resetAttempts = new Map();
const trackingAttempts = new Map();

function escapeHtml(value) { return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function safeEqual(a, b) { const b1 = Buffer.from(String(a)), b2 = Buffer.from(String(b)); return b1.length === b2.length && crypto.timingSafeEqual(b1, b2); }

function createSessionToken(payload) {
  const secret = process.env.ADMIN_SESSION_SECRET;
  if (!secret || secret.length < 32) throw new Error("Secret trop court.");
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${encoded}.${crypto.createHmac("sha256", secret).update(encoded).digest("base64url")}`;
}

function verifySessionToken(token) {
  try {
    if (!token || !process.env.ADMIN_SESSION_SECRET) return null;
    const [encoded, signature] = token.split(".");
    if (!encoded || !signature) return null;
    const expected = crypto.createHmac("sha256", process.env.ADMIN_SESSION_SECRET).update(encoded).digest("base64url");
    if (!safeEqual(signature, expected)) return null;
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    return (payload.expiresAt > Date.now() && typeof payload.csrf === "string") ? payload : null;
  } catch { return null; }
}

function readCookie(req, name) {
  for (const item of (req.headers.cookie || "").split(";")) {
    const [key, ...val] = item.trim().split("=");
    if (key === name) return val.join("=");
  }
  return null;
}

function setSessionCookie(res, token) { res.setHeader("Set-Cookie", `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_DURATION / 1000}`); }
function clearSessionCookie(res) { res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`); }
function setProCookie(res, code) { res.setHeader("Set-Cookie", `${PRO_COOKIE}=${code}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_DURATION / 1000}`); }
function clearProCookie(res) { res.setHeader("Set-Cookie", `${PRO_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`); }

function requireAdmin(req, res, next) {
  const session = verifySessionToken(readCookie(req, SESSION_COOKIE));
  if (!session) { clearSessionCookie(res); return res.redirect(303, "/admin"); }
  req.adminSession = session; next();
}

// ✅ Correctif : CSRF robuste (n'accepte plus "" == "")
function verifyCsrf(req, res, next) {
  const csrf = req.adminSession?.csrf;
  if (!csrf || !req.body.csrfToken || !safeEqual(req.body.csrfToken, csrf)) {
    return res.status(403).send(page("Refuse", "<h1>Erreur CSRF</h1>", null));
  }
  next();
}

// ✅ Correctif : randomInt crypto au lieu de Math.random
function generateProCode() { return `TM${crypto.randomInt(10000, 100000)}`; }
async function generateUniqueProCode() {
  let code, exists = true, attempts = 0;
  while (exists && attempts < 20) {
    code = generateProCode();
    exists = (await pool.query("SELECT id FROM professional_applications WHERE pro_code = $1", [code])).rows.length > 0;
    attempts++;
  }
  return code;
}

async function getConnectedPro(req) {
  const code = readCookie(req, PRO_COOKIE);
  if (!code) return null;
  const result = await pool.query(`SELECT * FROM professional_applications WHERE pro_code = $1 AND status = 'approved'`, [code]);
  return result.rows.length ? { pro: result.rows[0], code } : null;
}

function getDisplayName(person) { return (person?.company_name?.trim() || person?.full_name || ""); }
function getCsrf(req) { return req.adminSession?.csrf || ""; }

function renderStars(rating) {
  let html = "";
  const full = Math.floor(rating), half = (rating - full) >= 0.5;
  for (let i = 1; i <= 5; i++) html += (i <= full) ? "★" : (i === full + 1 && half) ? "⯨" : "☆";
  return html;
}

// ✅ AJOUT : Badge Vérifié KYC
function renderKycBadge(size) {
  const cls = size === "lg" ? "badge-verified badge-verified-lg" : "badge-verified";
  return `<span class="${cls}" title="Identite verifiee manuellement par TrouveMoi">Verifie KYC</span>`;
}

function renderLogo() {
  return `
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 50" width="180" height="45" style="display:inline-block;vertical-align:middle;max-width:100%">
      <circle cx="22" cy="22" r="15" fill="none" stroke="white" stroke-width="3.5"/>
      <line x1="33" y1="33" x2="43" y2="43" stroke="white" stroke-width="4" stroke-linecap="round"/>
      <circle cx="17" cy="19" r="3" fill="white"/><path d="M 12 28 Q 12 23 17 23 Q 22 23 22 28 Z" fill="white"/>
      <circle cx="27" cy="19" r="3" fill="white" opacity="0.85"/><path d="M 22 28 Q 22 23 27 23 Q 32 23 32 28 Z" fill="white" opacity="0.85"/>
      <text x="55" y="32" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif" font-size="22" font-weight="800" fill="white" letter-spacing="-0.5" class="logo-text">TrouveMoi</text>
    </svg>`;
}

function buildMenu(proConnected) {
  if (proConnected) {
    return `<nav><a href="/">Professionnels</a><a href="/emplois">Emploi</a><a href="/mon-espace-pro">Mon espace pro</a><a href="/publier-emploi">📢 Publier une offre</a><form action="/mon-espace-pro/logout" method="POST" style="display:inline"><button type="submit" style="background:transparent;border:none;color:white;padding:8px 14px;border-radius:6px;font-size:14px;font-weight:500;cursor:pointer;font-family:inherit">Deconnexion</button></form></nav>`;
  }
  return `<nav><a href="/">Professionnels</a><a href="/emplois">Emploi</a><a href="/devenir-professionnel">Devenir pro</a><a href="/mon-espace-pro">Espace pro</a><a href="/contact">Contact</a></nav>`;
}

function page(title, content, proConnected) {
  return `
    <!DOCTYPE html>
    <html lang="fr">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="description" content="TrouveMoi - Mise en relation au Benin.">
      <meta name="theme-color" content="#1e40af">
      <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 50 50'%3E%3Crect width='50' height='50' rx='10' fill='%231e40af'/%3E%3Ccircle cx='22' cy='22' r='10' fill='none' stroke='white' stroke-width='3'/%3E%3Cline x1='29' y1='29' x2='37' y2='37' stroke='white' stroke-width='3.5' stroke-linecap='round'/%3E%3C/svg%3E">
      <title>${escapeHtml(title)} - TrouveMoi</title>

      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; padding: 0; background: #f4f7fb; color: #222; line-height: 1.6; min-height: 100vh; display: flex; flex-direction: column; }

        header { background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%); color: white; padding: 18px 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); position: sticky; top: 0; z-index: 100; }
        .header-content { max-width: 1100px; margin: 0 auto; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; }
        .logo { display: inline-flex; align-items: center; text-decoration: none; }
        .logo svg { display: block; height: 42px; width: auto; max-width: 100%; }
        .tagline { font-size: 13px; opacity: 0.9; margin-top: 2px; }

        nav { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
        nav a, nav button { color: white; text-decoration: none; padding: 8px 14px; border-radius: 6px; font-size: 14px; font-weight: 500; transition: background 0.2s; }
        nav a:hover, nav button:hover { background: rgba(255,255,255,0.15); }

        main { max-width: 1100px; width: 100%; margin: 0 auto; padding: 24px 20px; flex: 1; }
        .card { background: white; padding: 24px; margin-bottom: 20px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); transition: box-shadow 0.2s; }
        .card:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.08); }

        h1 { font-size: 28px; margin-bottom: 16px; color: #1e40af; line-height: 1.3; border-left: 5px solid #1e40af; padding-left: 14px; }
        h2 { font-size: 22px; margin-bottom: 14px; color: #1e3a8a; line-height: 1.3; border-left: 4px solid #3b82f6; padding-left: 12px; }
        h3 { font-size: 18px; margin-bottom: 10px; color: #475467; line-height: 1.3; border-left: 3px solid #94a3b8; padding-left: 10px; }
        p { margin-bottom: 12px; }

        .label { font-weight: 700; color: #1a1a1a; }
        .value { color: #333; }

        label { display: block; margin-top: 8px; margin-bottom: 4px; font-weight: 600; font-size: 14px; color: #333; }
        input, textarea, select { width: 100%; padding: 12px 14px; margin-bottom: 14px; border: 1px solid #ddd; border-radius: 8px; font-size: 15px; font-family: inherit; background: white; transition: border-color 0.2s, box-shadow 0.2s; }
        input:focus, textarea:focus, select:focus { outline: none; border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37,99,235,0.1); }
        textarea { resize: vertical; min-height: 100px; }
        input[type="file"] { padding: 10px; background: #f9fafb; border: 2px dashed #ccc; cursor: pointer; }
        input[type="file"]:hover { border-color: #2563eb; background: #eff6ff; }
        input[type="checkbox"], input[type="radio"] { width: auto; margin-right: 8px; }
        
        optgroup { font-weight: 800; color: #1e40af; font-style: normal; background: #eff6ff; padding: 6px 0; font-size: 15px; }
        optgroup option { font-weight: 400; color: #222; background: white; font-size: 15px; }

        button, .button { display: inline-block; border: none; background: #2563eb; color: white; padding: 12px 20px; border-radius: 8px; cursor: pointer; text-decoration: none; text-align: center; font-size: 15px; font-weight: 600; transition: background 0.2s, transform 0.1s; margin-right: 8px; margin-bottom: 8px; font-family: inherit; }
        button:hover, .button:hover { background: #1d4ed8; transform: translateY(-1px); }

        .danger { background: #b42318; } .danger:hover { background: #9a1d13; }
        .secondary { background: #475467; } .secondary:hover { background: #344054; }
        .warning { background: #f59e0b; } .warning:hover { background: #d97706; }
        .success { background: #0a9d70; } .success:hover { background: #087f5b; }
        .info { background: #3b82f6; } .info:hover { background: #1e40af; }
        .muted { color: #667085; font-size: 14px; }

        .contact-buttons { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 16px; }
        .contact-buttons .button { flex: 1 1 140px; margin: 0; }
        .whatsapp { background: #25d366; } .whatsapp:hover { background: #1da851; }
        .email { background: #475467; } .email:hover { background: #344054; }
        .share { background: #4267b2; } .share:hover { background: #365899; }

        .photos-grid { display: flex; flex-wrap: wrap; gap: 12px; margin: 16px 0; }
        .photos-grid img { max-width: 280px; max-height: 280px; border-radius: 10px; border: 2px solid #e5e7eb; object-fit: cover; }
        .photo-profil { border: 3px solid #2563eb !important; }
        .photo-identite { border: 3px solid #b42318 !important; }
        .photo-activite { border: 3px solid #475467 !important; }
        .photo-kyc { border: 3px solid #f59e0b !important; }
        .photo-label { font-size: 12px; color: #667085; text-align: center; margin-top: 4px; font-weight: 600; }
        .photo-block { display: flex; flex-direction: column; align-items: center; }

        .help-text { font-size: 13px; color: #667085; margin-bottom: 12px; font-style: italic; }
        .hidden { display: none !important; }
        .actions { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }

        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .stat-card { background: white; padding: 24px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); border-left: 4px solid #2563eb; transition: transform 0.2s, box-shadow 0.2s; }
        .stat-card:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(0,0,0,0.1); }
        .stat-card.warning { border-left-color: #f59e0b; } .stat-card.danger { border-left-color: #b42318; } .stat-card.info { border-left-color: #3b82f6; }
        .stat-icon { font-size: 32px; margin-bottom: 8px; }
        .stat-number { font-size: 36px; font-weight: 800; color: #1a1a1a; line-height: 1; margin-bottom: 6px; }
        .stat-label { font-size: 14px; color: #667085; font-weight: 500; }
        .stat-link { display: inline-block; margin-top: 10px; font-size: 13px; color: #2563eb; text-decoration: none; font-weight: 600; }

        .pro-code-box { background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%); color: white; padding: 24px; border-radius: 12px; text-align: center; margin: 16px 0; }
        .pro-code-value { font-size: 42px; font-weight: 800; letter-spacing: 4px; margin: 12px 0; font-family: "Courier New", monospace; }
        .pro-code-label { font-size: 14px; opacity: 0.9; text-transform: uppercase; letter-spacing: 1px; }

        .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
        .badge-pending { background: #fef3c7; color: #92400e; }
        .badge-approved { background: #d1fae5; color: #065f46; }
        .badge-rejected { background: #fee2e2; color: #991b1b; }
        .badge-closed { background: #e5e7eb; color: #374151; }
        .badge-processed { background: #d1fae5; color: #065f46; }
        .badge-new { background: #b42318; color: white; margin-left: 6px; padding: 2px 8px; font-size: 11px; }

        /* ✅ AJOUT : Badge Vérifié KYC */
        .badge-verified {
          display: inline-flex;
          align-items: center;
          gap: 4px;
          background: linear-gradient(135deg, #0a9d70 0%, #087f5b 100%);
          color: white;
          padding: 4px 10px;
          border-radius: 20px;
          font-size: 11px;
          font-weight: 700;
          letter-spacing: 0.5px;
          text-transform: uppercase;
          box-shadow: 0 2px 6px rgba(10,157,112,0.3);
        }
        .badge-verified::before {
          content: "✓";
          font-size: 13px;
          font-weight: 900;
        }
        .badge-verified-lg {
          font-size: 13px;
          padding: 6px 14px;
        }

        .alert { padding: 16px 20px; border-radius: 8px; margin-bottom: 16px; border-left: 4px solid; }
        .alert-success { background: #d1fae5; border-color: #0a9d70; color: #065f46; }
        .alert-danger { background: #fee2e2; border-color: #b42318; color: #991b1b; }
        .alert-warning { background: #fffbeb; border-color: #f59e0b; color: #92400e; }
        .alert-info { background: #dbeafe; border-color: #3b82f6; color: #1e40af; }

        .pro-welcome { background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%); color: white; padding: 28px; border-radius: 12px; margin-bottom: 20px; box-shadow: 0 4px 20px rgba(30,64,175,0.3); }
        .pro-welcome h2 { color: white; border: none; padding: 0; margin-bottom: 8px; font-size: 24px; }
        .pro-welcome p { opacity: 0.95; margin-bottom: 16px; font-size: 15px; }
        .pro-welcome .actions { margin: 0; }
        .pro-welcome .button { background: white; color: #1e40af; }
        .pro-welcome .button:hover { background: #eff6ff; transform: translateY(-1px); }
        .pro-welcome .button.secondary { background: rgba(255,255,255,0.25); color: white; }

        .admin-alerts { background: #fff7ed; border: 1px solid #fdba74; border-left: 5px solid #ea580c; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .admin-alerts h3 { color: #9a3412; border: none; padding: 0; margin-bottom: 12px; font-size: 17px; }
        .admin-alerts ul { list-style: none; margin: 0; }
        .admin-alerts li { padding: 8px 0; border-bottom: 1px solid #fed7aa; color: #7c2d12; }
        .admin-alerts a { color: #9a3412; font-weight: 700; text-decoration: none; }

        .pros-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 20px; margin-top: 20px; }
        .pro-card { background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.08); transition: transform 0.2s, box-shadow 0.2s; display: flex; flex-direction: column; }
        .pro-card:hover { transform: translateY(-4px); box-shadow: 0 8px 24px rgba(0,0,0,0.12); }
        .pro-card-image { width: 100%; height: 180px; background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%); display: flex; align-items: center; justify-content: center; overflow: hidden; }
        .pro-card-image img { width: 100%; height: 100%; object-fit: cover; }
        .pro-card-image-placeholder { font-size: 60px; color: white; opacity: 0.5; }
        .pro-card-body { padding: 16px; flex: 1; display: flex; flex-direction: column; }
        .pro-card-profession { font-size: 13px; font-weight: 700; color: #1e40af; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
        .pro-card-name { font-size: 17px; font-weight: 700; color: #1a1a1a; margin-bottom: 8px; line-height: 1.3; }
        .pro-card-location { font-size: 14px; color: #667085; margin-bottom: 10px; }
        .pro-card-location::before { content: "📍 "; }
        .pro-card-rating { font-size: 15px; color: #f59e0b; font-weight: 600; margin-bottom: 12px; letter-spacing: 1px; }
        .pro-card-rating .reviews-count { color: #667085; font-weight: 400; font-size: 13px; letter-spacing: 0; margin-left: 6px; }
        .pro-card-rating .no-rating { color: #94a3b8; font-weight: 400; font-style: italic; font-size: 13px; letter-spacing: 0; }
        .pro-card-button { display: block; width: 100%; background: #2563eb; color: white; padding: 10px 16px; border-radius: 6px; text-align: center; text-decoration: none; font-weight: 600; font-size: 14px; margin-top: auto; transition: background 0.2s; }
        .pro-card-button:hover { background: #1d4ed8; }

        .pro-header { background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%); color: white; padding: 32px 24px; border-radius: 12px; margin-bottom: 20px; }
        .pro-header h1 { color: white; border: none; padding: 0; font-size: 30px; margin-bottom: 8px; }
        .pro-header .profession { font-size: 18px; opacity: 0.95; margin-bottom: 8px; font-weight: 600; }
        .pro-header .location { font-size: 15px; opacity: 0.9; }
        .pro-header .rating-large { font-size: 22px; color: #fef3c7; margin-top: 12px; font-weight: 700; letter-spacing: 2px; }
        .pro-header .rating-large .reviews-count { color: rgba(255,255,255,0.85); font-weight: 400; font-size: 15px; letter-spacing: 0; margin-left: 8px; }

        .review-item { background: #f9fafb; padding: 16px; border-radius: 10px; margin-bottom: 14px; border-left: 4px solid #f59e0b; }
        .review-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 8px; }
        .review-author { font-weight: 700; color: #1a1a1a; }
        .review-stars { color: #f59e0b; font-size: 18px; letter-spacing: 2px; }
        .review-date { font-size: 13px; color: #94a3b8; }
        .review-comment { color: #333; margin-top: 8px; line-height: 1.6; }

        .rating-summary { display: flex; align-items: center; gap: 24px; padding: 24px; background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%); border-radius: 12px; margin-bottom: 20px; flex-wrap: wrap; }
        .rating-big-number { font-size: 52px; font-weight: 800; color: #92400e; line-height: 1; }
        .rating-details { flex: 1; min-width: 180px; }
        .rating-details .stars { font-size: 28px; color: #f59e0b; letter-spacing: 3px; }
        .rating-details .count { font-size: 14px; color: #78350f; margin-top: 4px; font-weight: 600; }

        .btn-review { background: #f59e0b; color: white; }
        .btn-review:hover { background: #d97706; }

        .star-rating-input { display: flex; flex-direction: row-reverse; justify-content: flex-end; gap: 6px; margin-bottom: 16px; width: auto; }
        .star-rating-input input { display: none; }
        .star-rating-input label { font-size: 44px; color: #d1d5db; cursor: pointer; transition: color 0.2s, transform 0.1s; margin: 0; padding: 0; line-height: 1; font-weight: normal; }
        .star-rating-input label:hover { transform: scale(1.1); }
        .star-rating-input input:checked ~ label { color: #f59e0b; }
        .star-rating-input label:hover, .star-rating-input label:hover ~ label { color: #f59e0b; }

        .checkbox-block { background: #f9fafb; padding: 16px; border-radius: 8px; margin: 12px 0; border: 1px solid #e5e7eb; }
        .checkbox-block label { display: flex; align-items: flex-start; margin: 0; font-weight: 500; }

        footer { background: #1a1a1a; color: #ccc; padding: 32px 20px 20px; margin-top: 40px; }
        .footer-content { max-width: 1100px; margin: 0 auto; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 24px; }
        .footer-col h4 { color: white; margin-bottom: 12px; font-size: 15px; text-transform: uppercase; letter-spacing: 0.5px; }
        .footer-col a { display: block; color: #aaa; text-decoration: none; padding: 4px 0; font-size: 14px; }
        .footer-col a:hover { color: #3b82f6; }
        .footer-bottom { max-width: 1100px; margin: 24px auto 0; padding-top: 20px; border-top: 1px solid #333; text-align: center; font-size: 13px; color: #888; }

        @media (max-width: 600px) {
          header { padding: 14px 16px; }
          .header-content { flex-direction: column; text-align: center; }
          nav { justify-content: center; }
          main { padding: 16px 12px; }
          .card { padding: 16px; }
          h1 { font-size: 22px; } h2 { font-size: 18px; } h3 { font-size: 16px; }
          .photos-grid img { max-width: 100%; }
          .contact-buttons .button { flex: 1 1 100%; }
          .stat-number { font-size: 28px; }
          .pros-grid { grid-template-columns: 1fr; }
          .rating-big-number { font-size: 40px; }
          .logo svg { height: 32px; }
          .logo .logo-text { font-size: 18px; }
        }
      </style>
    </head>

    <body>
      <header>
        <div class="header-content">
          <div>
            <a href="/" class="logo" aria-label="TrouveMoi">${renderLogo()}</a>
            <div class="tagline">Trouvez le bon professionnel au Benin</div>
          </div>
          ${buildMenu(proConnected)}
        </div>
      </header>
      <main>${content}</main>
      <footer>
        <div class="footer-content">
          <div class="footer-col"><h4>TrouveMoi</h4><p style="color:#aaa;font-size:14px">La plateforme beninoise de mise en relation.</p></div>
          <div class="footer-col"><h4>Navigation</h4><a href="/">Professionnels</a><a href="/emplois">Offres d'emploi</a><a href="/devenir-professionnel">Devenir professionnel</a><a href="/mon-espace-pro">Espace pro</a></div>
          <div class="footer-col"><h4>Informations</h4><a href="/a-propos">A propos</a><a href="/contact">Contact</a><a href="/conditions">Conditions</a><a href="/confidentialite">Confidentialite</a></div>
          <div class="footer-col"><h4>Contact</h4><a href="/contact">Nous ecrire</a><a href="mailto:contact@trouvemoi.bj">contact@trouvemoi.bj</a></div>
        </div>
        <div class="footer-bottom">&copy; ${new Date().getFullYear()} TrouveMoi. Tous droits reserves.</div>
      </footer>
    </body>
    </html>
  `;
}

function jobContactButtons(job) {
  const b = [];
  if (job.contact_phone) b.push(`<a class="button" href="tel:${escapeHtml(job.contact_phone)}">📞 Appeler</a>`);
  if (job.contact_whatsapp) {
    const wa = job.contact_whatsapp.replace(/^\+/, "");
    b.push(`<a class="button whatsapp" href="https://wa.me/${escapeHtml(wa)}?text=${encodeURIComponent("Bonjour, je vous contacte suite à votre offre d'emploi sur TrouveMoi.")}" target="_blank">💬 WhatsApp</a>`);
  }
  return b.length ? `<div class="contact-buttons">${b.join("")}</div>` : "";
}

/* PAGE D'ACCUEIL */

app.get("/", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const profession = String(req.query.profession || "").trim().slice(0, 150);
    const city = String(req.query.city || "").trim().slice(0, 100);
    const neighborhood = String(req.query.neighborhood || "").trim().slice(0, 150);

    const citiesResult = await pool.query("SELECT id, name FROM cities ORDER BY display_order ASC");
    const professionsResult = await pool.query("SELECT id, name, category FROM professions ORDER BY display_order ASC");

    let query = `
      SELECT p.id, p.full_name, p.company_name, p.phone, p.phone_public, p.city, p.neighborhood,
        p.profession, p.experience, p.service_description, p.service_area, p.availability, p.photo_activite_url,
        (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count,
        (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating
      FROM professional_applications p WHERE p.status = 'approved'
    `;

    const values = [];
    if (profession) { values.push(`%${profession}%`); query += ` AND p.profession ILIKE $${values.length}`; }
    if (city) { values.push(city); query += ` AND p.city = $${values.length}`; }
    if (neighborhood) { values.push(neighborhood); query += ` AND p.neighborhood = $${values.length}`; }
    query += " ORDER BY p.created_at DESC LIMIT 50";

    const result = await pool.query(query, values);

    const cityOptions = citiesResult.rows.map((c) => `<option value="${escapeHtml(c.name)}" ${city === c.name ? "selected" : ""}>${escapeHtml(c.name)}</option>`).join("");
    let neighborhoodOptions = "";

    if (city) {
      const cityResult = await pool.query("SELECT id FROM cities WHERE name = $1", [city]);
      if (cityResult.rows.length) {
        const nResult = await pool.query(`SELECT name FROM neighborhoods WHERE city_id = $1 ORDER BY name ASC`, [cityResult.rows[0].id]);
        neighborhoodOptions = nResult.rows.map((n) => `<option value="${escapeHtml(n.name)}" ${neighborhood === n.name ? "selected" : ""}>${escapeHtml(n.name)}</option>`).join("");
      }
    }

    const professionsByCategory = {};
    for (const p of professionsResult.rows) {
      const cat = p.category || "Autres";
      if (!professionsByCategory[cat]) professionsByCategory[cat] = [];
      professionsByCategory[cat].push(p.name);
    }

    const professionOptions = Object.entries(professionsByCategory).map(([category, names]) => {
      const options = names.map((name) => `<option value="${escapeHtml(name)}" ${profession === name ? "selected" : ""}>${escapeHtml(name)}</option>`).join("");
      return `<optgroup label="${escapeHtml(category)}">${options}</optgroup>`;
    }).join("");

    const prosCards = result.rows.map((person) => {
      const displayName = getDisplayName(person);
      const reviewsCount = Number(person.reviews_count || 0);
      const avgRating = Number(person.avg_rating || 0);
      const photoHtml = person.photo_activite_url ? `<img src="${escapeHtml(person.photo_activite_url)}" alt="${escapeHtml(person.profession)}">` : `<div class="pro-card-image-placeholder">👤</div>`;
      
      let ratingHtml = reviewsCount > 0 
        ? `<div class="pro-card-rating">${renderStars(avgRating)}<span class="reviews-count">${avgRating.toFixed(1)} (${reviewsCount} avis)</span></div>`
        : `<div class="pro-card-rating"><span class="no-rating">Pas encore d'avis</span></div>`;

      // ✅ AJOUT : Badge KYC affiché sur la carte
      return `
        <article class="pro-card">
          <div class="pro-card-image">${photoHtml}</div>
          <div class="pro-card-body">
            <div class="pro-card-profession">${escapeHtml(person.profession)}</div>
            <div class="pro-card-name">${escapeHtml(displayName)}</div>
            <div class="pro-card-location">${escapeHtml(person.city)}${person.neighborhood ? ` - ${escapeHtml(person.neighborhood)}` : ""}</div>
            <div style="margin-bottom:8px">${renderKycBadge()}</div>
            ${ratingHtml}
            <a class="pro-card-button" href="/pro/${encodeURIComponent(person.id)}">Voir le profil →</a>
          </div>
        </article>
      `;
    }).join("");

    const welcomeBanner = proConnected ? `
      <div class="pro-welcome">
        <h2>🎉 Bonjour ${escapeHtml(getDisplayName(proConnected.pro))} !</h2>
        <p>Votre candidature est approuvee. Vous pouvez gerer vos offres.</p>
        <div class="actions"><a class="button" href="/mon-espace-pro">🏠 Mon espace pro</a><a class="button secondary" href="/mon-espace-pro">👁️ Voir mon code</a></div>
      </div>
    ` : "";

    const alerteArnaque = `
      <div class="alert alert-warning">
        <strong>⚠️ ATTENTION :</strong> Ne payez jamais un professionnel avant de l'avoir rencontré en personne. Si quelqu'un vous demande de l'argent à l'avance, veuillez le signaler en cliquant sur le bouton <strong>"Contact"</strong> en haut de la page.
      </div>
    `;

    const prosSection = result.rows.length > 0 ? `<div class="pros-grid">${prosCards}</div>` : `<section class="card"><p>Aucun professionnel approuve ne correspond a votre recherche.</p></section>`;

    const content = `
      ${welcomeBanner}
      ${alerteArnaque}
      <section class="card">
        <h1>Rechercher un professionnel</h1>
        <form action="/" method="GET">
          <label for="profession">Metier</label>
          <select id="profession" name="profession"><option value="">Tous</option>${professionOptions}</select>
          <label for="city">Ville</label>
          <select id="city" name="city"><option value="">Toutes</option>${cityOptions}</select>
          ${city && neighborhoodOptions ? `<label for="neighborhood">Quartier</label><select id="neighborhood" name="neighborhood"><option value="">Tous</option>${neighborhoodOptions}</select>` : ""}
          <button type="submit">Rechercher</button>
        </form>
        <a class="button" href="/devenir-professionnel">Devenir professionnel</a>
        <a class="button secondary" href="/emplois">Consulter les offres d'emploi</a>
      </section>
      <h2>Professionnels disponibles (${result.rows.length})</h2>
      ${prosSection}
    `;
    res.send(page("Accueil", content, proConnected));
  } catch (error) {
    res.status(500).send(page("Erreur", "<h2>Une erreur technique est survenue.</h2>", null));
  }
});

/* PAGE PROFIL DETAILLE */

app.get("/pro/:id", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/");

    const result = await pool.query(`
      SELECT p.*, 
        (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count,
        (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating
      FROM professional_applications p WHERE p.id = $1 AND p.status = 'approved'`, [id]);

    if (!result.rows.length) return res.redirect(303, "/");
    const person = result.rows[0];
    const displayName = getDisplayName(person);
    const phoneClean = (person.phone || "").replace(/[()\s.-]/g, "");
    const whatsappNumber = phoneClean.replace(/^\+/, "");
    const reviewsCount = Number(person.reviews_count || 0);
    const avgRating = Number(person.avg_rating || 0);

    const reviewsResult = await pool.query(`SELECT id, author_name, rating, comment, created_at FROM reviews WHERE pro_id = $1 AND status = 'approved' ORDER BY created_at DESC LIMIT 5`, [id]);
    const reviews = reviewsResult.rows;
    const shareText = encodeURIComponent("Decouvrez " + displayName + " (" + person.profession + ") sur TrouveMoi");
    const shareUrl = encodeURIComponent("https://trouvemoi-4mk0.onrender.com/pro/" + person.id);

    let contactButtons = "";
    if (person.phone_public && phoneClean) {
      contactButtons = `
        <div class="contact-buttons">
          <a class="button" href="tel:${escapeHtml(phoneClean)}">📞 Appeler</a>
          <a class="button whatsapp" href="https://wa.me/${escapeHtml(whatsappNumber)}?text=${encodeURIComponent("Bonjour, je vous contacte via TrouveMoi pour votre service de " + person.profession + ".")}" target="_blank">💬 WhatsApp</a>
          <a class="button share" href="https://wa.me/?text=${shareText}%20-%20${shareUrl}" target="_blank">📤 Partager</a>
        </div>`;
    } else {
      contactButtons = `
        <div class="alert alert-info">📩 Ce professionnel a choisi de ne pas afficher son numero publiquement.</div>
        <div class="contact-buttons">
          <a class="button" href="/contact?pro=${person.id}">📩 Contacter via le site</a>
          <a class="button share" href="https://wa.me/?text=${shareText}%20-%20${shareUrl}" target="_blank">📤 Partager</a>
        </div>`;
    }

    let ratingHeader = reviewsCount > 0 
      ? `<div class="rating-large">${renderStars(avgRating)}<span class="reviews-count">${avgRating.toFixed(1)} / 5 (${reviewsCount} avis)</span></div>`
      : `<div class="rating-large" style="color:rgba(255,255,255,0.7);font-size:16px;letter-spacing:0">Pas encore d'avis</div>`;

    let ratingSummary = reviewsCount > 0 
      ? `<div class="rating-summary"><div class="rating-big-number">${avgRating.toFixed(1)}</div><div class="rating-details"><div class="stars">${renderStars(avgRating)}</div><div class="count">Base sur ${reviewsCount} avis</div></div></div>` 
      : "";

    const reviewsHtml = reviews.map((rev) => {
      const dateStr = new Date(rev.created_at).toLocaleDateString("fr-FR");
      return `<div class="review-item"><div class="review-header"><div class="review-author">${escapeHtml(rev.author_name)}</div><div class="review-stars">${renderStars(rev.rating)}</div></div><div class="review-date">${escapeHtml(dateStr)}</div>${rev.comment ? `<div class="review-comment">${escapeHtml(rev.comment).replace(/\n/g, "<br>")}</div>` : ""}</div>`;
    }).join("");

    const reviewsSection = reviews.length > 0 ? `<section class="card"><h2>Avis des clients (${reviewsCount})</h2>${ratingSummary}${reviewsHtml}</section>` : "";
    const reviewButton = `<section class="card" style="text-align:center"><h3>Vous avez fait appel a ce professionnel ?</h3><a class="button btn-review" href="/pro/${person.id}/avis">⭐ Laisser un avis</a></section>`;

    // ✅ AJOUT : Badge KYC dans l'en-tête du profil
    const content = `
      <div class="pro-header">
        <h1>${escapeHtml(displayName)}</h1>
        <div class="profession">${escapeHtml(person.profession)}</div>
        <div class="location">📍 ${escapeHtml(person.city)}${person.neighborhood ? ` - ${escapeHtml(person.neighborhood)}` : ""}</div>
        <div style="margin-top:10px">${renderKycBadge("lg")}</div>
        ${ratingHeader}
      </div>
      <section class="card">
        ${person.photo_activite_url ? `<div class="photos-grid"><div class="photo-block"><img src="${escapeHtml(person.photo_activite_url)}" class="photo-activite"></div></div>` : ""}
        <h2>Description des services</h2>
        <p>${escapeHtml(person.service_description).replace(/\n/g, "<br>")}</p>
        ${person.service_area ? `<p><span class="label">Zone d'intervention :</span> ${escapeHtml(person.service_area)}</p>` : ""}
        ${person.availability ? `<p><span class="label">Disponibilite :</span> ${escapeHtml(person.availability)}</p>` : ""}
        ${contactButtons}
        <p style="margin-top:24px"><a class="button secondary" href="/">← Retour</a></p>
      </section>
      ${reviewsSection} ${reviewButton}
    `;
    res.send(page(displayName, content, proConnected));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

/* FORMULAIRE AVIS */

app.get("/pro/:id/avis", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const id = Number(req.params.id);
    const result = await pool.query(`SELECT id, full_name, company_name, profession FROM professional_applications WHERE id = $1 AND status = 'approved'`, [id]);
    if (!result.rows.length) return res.redirect(303, "/");
    const person = result.rows[0];
    const displayName = getDisplayName(person);

    res.send(page("Avis", `
      <section class="card">
        <h1>Laisser un avis</h1>
        <div class="alert alert-info">⭐ Vous laissez un avis sur <strong>${escapeHtml(displayName)}</strong>.</div>
        <form action="/pro/${person.id}/avis" method="POST">
          <label>Votre nom *</label><input name="author_name" required maxlength="100">
          <label>Note *</label>
          <div class="star-rating-input">
            <input type="radio" id="s5" name="rating" value="5" required><label for="s5">★</label>
            <input type="radio" id="s4" name="rating" value="4"><label for="s4">★</label>
            <input type="radio" id="s3" name="rating" value="3"><label for="s3">★</label>
            <input type="radio" id="s2" name="rating" value="2"><label for="s2">★</label>
            <input type="radio" id="s1" name="rating" value="1"><label for="s1">★</label>
          </div>
          <label>Commentaire</label><textarea name="comment" rows="4" maxlength="3000"></textarea>
          <button type="submit">Envoyer</button>
          <a class="button secondary" href="/pro/${person.id}">Annuler</a>
        </form>
      </section>
    `, proConnected));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

// ✅ Correctif : validation rating + vérification pro approuvé
app.post("/pro/:id/avis", async (req, res) => {
  try {
    const proId = Number(req.params.id);
    if (!Number.isSafeInteger(proId) || proId < 1) return res.redirect(303, "/");
    const check = await pool.query(`SELECT id FROM professional_applications WHERE id = $1 AND status = 'approved'`, [proId]);
    if (!check.rows.length) return res.redirect(303, "/");
    const ratingNum = Number(req.body.rating);
    if (!Number.isInteger(ratingNum) || ratingNum < 1 || ratingNum > 5) {
      return res.status(400).send(page("Erreur", "<h2>Note invalide (1 a 5).</h2>", null));
    }
    const author = String(req.body.author_name || "").trim().slice(0, 100);
    if (!author) return res.status(400).send(page("Erreur", "<h2>Nom requis.</h2>", null));
    const comment = String(req.body.comment || "").slice(0, 3000);
    await pool.query(`INSERT INTO reviews (pro_id, author_name, rating, comment, status) VALUES ($1, $2, $3, $4, 'pending')`, [proId, author, ratingNum, comment]);
    res.send(page("Succes", "<section class='card'><h1>Merci !</h1><p>Votre avis sera examine.</p><a href='/'>Retour</a></section>", null));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

/* PAGE EMPLOIS */

app.get("/emplois", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const keyword = String(req.query.keyword || "").trim();
  const city = String(req.query.city || "").trim();

  let query = `SELECT * FROM job_offers WHERE status = 'approved' AND (expires_at IS NULL OR expires_at > NOW())`;
  const values = [];
  if (keyword) { values.push(`%${keyword}%`); query += ` AND (job_title ILIKE $${values.length} OR company_name ILIKE $${values.length})`; }
  if (city) { values.push(`%${city}%`); query += ` AND city ILIKE $${values.length}`; }
  query += " ORDER BY created_at DESC LIMIT 100";

  const result = await pool.query(query, values);

  const jobs = result.rows.map((job) => `
    <article class="card">
      <h2>${escapeHtml(job.job_title)}</h2>
      <p><span class="label">Entreprise :</span> ${escapeHtml(job.company_name)}</p>
      <p><span class="label">Ville :</span> ${escapeHtml(job.city)}</p>
      <p><span class="label">Contrat :</span> ${escapeHtml(job.contract_type)}</p>
      <p>${escapeHtml(job.description).replace(/\n/g, "<br>")}</p>
      ${jobContactButtons(job)}
    </article>
  `).join("");

  const alerteEmploi = `
    <div class="alert alert-warning">
      <strong>⚠️ RAPPEL :</strong> Si un recruteur vous demande de l'argent avant l'entretien, veuillez signaler ce recruteur en nous envoyant directement un message en cliquant sur le bouton <strong>"Contact"</strong> de la page d'accueil.
    </div>
  `;

  res.send(page("Emploi", `
    ${alerteEmploi}
    <section class="card">
      <h1>Rechercher un emploi</h1>
      <form action="/emplois" method="GET">
        <label>Mot clé</label><input name="keyword" value="${escapeHtml(keyword)}">
        <label>Ville</label><input name="city" value="${escapeHtml(city)}">
        <button>Rechercher</button>
      </form>
      <a class="button" href="/publier-emploi">Publier une offre</a>
    </section>
    <h2>Offres disponibles (${result.rows.length})</h2>
    ${jobs || `<section class="card"><p>Aucune offre.</p></section>`}
  `, proConnected));
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

    const professionOptions = Object.entries(professionsByCategory).map(([category, names]) => {
      const options = names.map((name) => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join("");
      return `<optgroup label="${escapeHtml(category)}">${options}</optgroup>`;
    }).join("");

    const content = `
      <section class="card">
        <h1>Devenir professionnel sur TrouveMoi</h1>
        <p>Remplissez le formulaire. Votre profil sera examine avant publication.</p>

        <form action="/candidatures" method="POST" enctype="multipart/form-data">
          <label for="full_name">Nom et prenoms *</label>
          <input id="full_name" name="full_name" required maxlength="150">

          <label for="company_name">Nom de la societe (facultatif)</label>
          <input id="company_name" name="company_name" maxlength="200">

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
              <label for="whatsapp_number">Numero WhatsApp</label>
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
          
          <h3>Photos obligatoires (KYC)</h3>
          <p class="help-text">Formats : JPG, PNG, WEBP. Max : 5 Mo.</p>

          <label for="photo_profil">1. Photo de profil * (privee)</label>
          <input id="photo_profil" name="photo_profil" type="file" accept="image/*" required>

          <label for="photo_identite">2. Photo de votre piece d'identite (recto) * (privee)</label>
          <input id="photo_identite" name="photo_identite" type="file" accept="image/*" required>

          <label for="photo_kyc">3. Photo de verification (Vous + Piece d'identite) * (privee)</label>
          <div style="background:#eff6ff; padding:15px; border-radius:8px; margin-bottom:15px; border:1px dashed #3b82f6; text-align:center;">
            <p style="font-size:13px; margin-bottom:10px; color:#1e40af;"><strong>Exemple de photo :</strong> Prenez une photo de vous, de face, en tenant votre pièce à côté de votre visage. Sans lunettes ni chapeau.</p>
            <img src="https://res.cloudinary.com/gxm35ndf/image/upload/v1792403314/kyc.jpg" alt="Exemple KYC" style="max-width:180px; border-radius:8px; border:2px solid #3b82f6;">
          </div>
          <input id="photo_kyc" name="photo_kyc" type="file" accept="image/*" required>

          <label for="photo_activite">4. Photo d'activite (publique, optionnelle)</label>
          <input id="photo_activite" name="photo_activite" type="file" accept="image/*">

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
        whatsappRadio.addEventListener('change', function() { if (whatsappRadio.checked) { document.getElementById('whatsapp-number-block').classList.remove('hidden'); document.getElementById('email-block').classList.add('hidden'); } });
        emailRadio.addEventListener('change', function() { if (emailRadio.checked) { document.getElementById('email-block').classList.remove('hidden'); document.getElementById('whatsapp-number-block').classList.add('hidden'); } });
      </script>
    `;
    res.send(page("Devenir professionnel", content, proConnected));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
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
  } catch (error) { res.status(500).json({ neighborhoods: [] }); }
});

/* ENREGISTREMENT CANDIDATURES (AVEC KYC + ANTI-DOUBLON) */
app.post("/candidatures", upload.fields([
  { name: "photo_profil", maxCount: 1 },
  { name: "photo_identite", maxCount: 1 },
  { name: "photo_kyc", maxCount: 1 },
  { name: "photo_activite", maxCount: 1 }
]), async (req, res) => {
  const { full_name, company_name, phone, phone_public, city, neighborhood, neighborhood_other, profession, profession_other, experience, service_description, service_area, availability, gdpr_consent, contact_preference, whatsapp_number, contact_email } = req.body;

  if (gdpr_consent !== "yes") return res.status(400).send(page("Erreur", "<h2>Consentement RGPD obligatoire.</h2>", null));

  // ✅ DÉTECTION DE DOUBLON SÉCURISÉE (Nom + Société + Téléphone)
  const safeName = String(full_name || "").trim().toLowerCase();
  const safeCompany = String(company_name || "").trim().toLowerCase();
  const safePhone = String(phone || "").replace(/[()\s.-]/g, "");

  try {
    const duplicateCheck = await pool.query(
      `SELECT id FROM professional_applications 
       WHERE LOWER(TRIM(full_name)) = $1 
       AND LOWER(TRIM(COALESCE(company_name, ''))) = $2 
       AND REGEXP_REPLACE(phone, '[()\\s.-]', '', 'g') = $3
       AND status IN ('pending', 'under_review', 'approved', 'corrections_requested')`,
      [safeName, safeCompany, safePhone]
    );

    if (duplicateCheck.rows.length > 0) {
      return res.status(409).send(page("Inscription impossible", `
        <section class="card">
          <h1 style="color:#b42318; border-left-color:#b42318">⚠️ Inscription impossible</h1>
          <p><strong>Impossible de s'enregistrer deux fois.</strong></p>
          <p>Si vous ne vous êtes jamais enregistré sur cette plateforme, veuillez nous contacter directement pour plus d'assistance.</p>
          <div class="actions" style="margin-top:20px">
            <a class="button" href="/contact">📩 Nous contacter</a>
            <a class="button secondary" href="/">Retour à l'accueil</a>
          </div>
        </section>
      `, null));
    }
  } catch (dbError) {
    console.error("Erreur vérification doublon :", dbError.message);
    // En cas d'erreur DB, on laisse passer pour ne pas bloquer les inscriptions légitimes
  }

  // ✅ Correctif : validation contact_preference
  if (!CONTACT_PREFERENCES.includes(contact_preference)) {
    return res.status(400).send(page("Erreur", "<h2>Preference de contact invalide.</h2>", null));
  }

  const files = req.files || {};
  const photoProfil = files.photo_profil?.[0];
  const photoIdentite = files.photo_identite?.[0];
  const photoKyc = files.photo_kyc?.[0];
  const photoActivite = files.photo_activite?.[0];

  if (!full_name || !phone || !city || !profession || !service_description || !photoProfil || !photoIdentite || !photoKyc) {
    return res.status(400).send(page("Erreur", "<h2>Informations ou photos manquantes (KYC obligatoire).</h2>", null));
  }

  let finalNeighborhood = (neighborhood === "__AUTRE__") ? neighborhood_other : neighborhood;
  let finalProfession = (profession === "__AUTRE__") ? profession_other : profession;
  const pref = contact_preference;
  const phoneIsPublic = phone_public === "yes";
  const finalCompanyName = company_name && company_name.trim() ? company_name.trim() : null;

  try {
    const timestamp = Date.now();
    const profilResult = await uploadToCloudinary(photoProfil.buffer, "trouvemoi/profils", `profil_${timestamp}`);
    const identiteResult = await uploadToCloudinary(photoIdentite.buffer, "trouvemoi/identites", `identite_${timestamp}`);
    const kycResult = await uploadToCloudinary(photoKyc.buffer, "trouvemoi/kyc", `kyc_${timestamp}`);
    let photoActiviteUrl = null;
    if (photoActivite) {
      const actResult = await uploadToCloudinary(photoActivite.buffer, "trouvemoi/activites", `activite_${timestamp}`);
      photoActiviteUrl = actResult.secure_url;
    }

    // ✅ Correctif : tracking_code avec crypto.randomInt
    const trackingCode = `SUIVI-${crypto.randomInt(1000, 10000)}`;

    const result = await pool.query(`
      INSERT INTO professional_applications (
        full_name, company_name, phone, phone_public, city, neighborhood, profession,
        experience, service_description, service_area, availability, npi,
        photo_profil_url, photo_identite_url, photo_kyc_url, photo_activite_url,
        contact_preference, whatsapp_number, contact_email, pro_code, tracking_code, status
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,$12,$13,$14,$15,$16,$17,$18,NULL,$19,'pending')
      RETURNING id
    `, [full_name, finalCompanyName, phone, phoneIsPublic, city, finalNeighborhood, finalProfession, experience, service_description, service_area, availability, profilResult.secure_url, identiteResult.secure_url, kycResult.secure_url, photoActiviteUrl, pref, whatsapp_number, contact_email, trackingCode]);

    res.send(page("Candidature envoyee", `
      <section class="card">
        <h1>Succès !</h1>
        <p>Votre candidature est en attente d'examen.</p>
        <div class="alert alert-info">
          <strong>Votre code de suivi est : <span style="font-size:20px">${escapeHtml(trackingCode)}</span></strong><br>
          <p style="margin-top:10px">Notez ce code précieusement. Il vous permettra de suivre l'état de votre dossier et de voir les corrections demandées par l'administration.</p>
          <a class="button" href="/suivi-dossier">Suivre mon dossier</a>
        </div>
        <a class="button secondary" href="/">Retour a l'accueil</a>
      </section>
    `, null));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Impossible d'enregistrer.</h2>", null)); }
});

/* SUIVI DE DOSSIER (POUR LES CORRECTIONS) */

app.get("/suivi-dossier", (req, res) => {
  res.send(page("Suivi de dossier", `
    <section class="card">
      <h1>Suivre mon dossier</h1>
      <p>Entrez le code de suivi reçu lors de votre inscription.</p>
      <form action="/suivi-dossier" method="POST">
        <label>Code de suivi (ex: SUIVI-1234) *</label>
        <input name="tracking_code" required placeholder="SUIVI-XXXX" maxlength="20" style="text-transform:uppercase">
        <button type="submit">Voir mon dossier</button>
      </form>
    </section>
  `, null));
});

app.post("/suivi-dossier", async (req, res) => {
  // ✅ Anti-bruteforce du code de suivi
  const ip = req.ip || "unknown";
  const now = Date.now();
  const attempts = trackingAttempts.get(ip) || { count: 0, startedAt: now };
  if (now - attempts.startedAt > 15 * 60 * 1000) { attempts.count = 0; attempts.startedAt = now; }
  if (attempts.count >= 10) {
    return res.status(429).send(page("Trop de tentatives", 
      "<section class='card'><h1>⏳ Trop de tentatives</h1><p>Veuillez patienter 15 minutes avant de réessayer.</p></section>", 
      null));
  }
  attempts.count++;
  trackingAttempts.set(ip, attempts);

  try {
    const code = String(req.body.tracking_code || "").trim().toUpperCase();
    if (!code) return res.redirect(303, "/suivi-dossier");
    
    const result = await pool.query(`SELECT * FROM professional_applications WHERE tracking_code = $1`, [code]);
    
    if (!result.rows.length) {
      return res.send(page("Erreur", `<section class="card"><h2>Code introuvable.</h2><a href="/suivi-dossier">Réessayer</a></section>`, null));
    }
    const pro = result.rows[0];

    let statusHtml = "";
    if (pro.status === 'pending') statusHtml = `<div class="alert alert-info">⏳ Votre dossier est en cours d'examen.</div>`;
    else if (pro.status === 'approved') {
      statusHtml = `
        <div class="alert alert-success">
          ✅ Votre dossier a été approuvé !<br><br>
          <strong>Votre code professionnel est : <span style="font-size:20px">${escapeHtml(pro.pro_code)}</span></strong><br><br>
          Vous pouvez vous connecter sur votre espace pro avec ce code.
          <div style="margin-top:15px"><a class="button success" href="/mon-espace-pro">Se connecter à mon espace pro</a></div>
        </div>
      `;
    }
    else if (pro.status === 'rejected') statusHtml = `<div class="alert alert-danger">❌ Votre dossier a été refusé. Motif : ${escapeHtml(pro.rejection_reason || "Non spécifié")}</div>`;
    else if (pro.status === 'corrections_requested') {
      statusHtml = `
        <div class="alert alert-warning">
          <h3 style="margin-top:0">⚠️ Corrections demandées</h3>
          <p><strong>Motif :</strong> ${escapeHtml(pro.rejection_reason)}</p>
          <p>Veuillez corriger votre dossier et le renvoyer.</p>
          <button onclick="document.getElementById('form-correct').classList.remove('hidden')">Corriger mon dossier</button>
        </div>
        <div id="form-correct" class="hidden" style="margin-top:20px">
          <form action="/candidatures/${pro.id}/corriger" method="POST" enctype="multipart/form-data">
            <input type="hidden" name="tracking_code" value="${escapeHtml(pro.tracking_code)}">
            <label>Nouvelle photo d'identité (optionnel)</label>
            <input type="file" name="photo_identite" accept="image/*">
            <label>Nouvelle photo KYC (optionnel)</label>
            <input type="file" name="photo_kyc" accept="image/*">
            <button type="submit" class="success">Renvoyer pour validation</button>
          </form>
        </div>
      `;
    }

    res.send(page("Mon dossier", `
      <section class="card">
        <h1>Dossier de ${escapeHtml(pro.full_name)}</h1>
        ${statusHtml}
        <p style="margin-top:20px"><a href="/suivi-dossier">Retour</a></p>
      </section>
    `, null));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

// ✅ Correctif : vérification du tracking_code pour éviter l'usurpation
app.post("/candidatures/:id/corriger", upload.fields([{ name: "photo_identite", maxCount: 1 }, { name: "photo_kyc", maxCount: 1 }]), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).send(page("Erreur", "<h2>ID invalide.</h2>", null));
  
  const files = req.files || {};
  const trackingCode = String(req.body.tracking_code || "").trim().toUpperCase();
  
  try {
    // Vérifier que le tracking_code correspond bien au dossier
    const check = await pool.query("SELECT tracking_code FROM professional_applications WHERE id = $1", [id]);
    if (!check.rows.length || check.rows[0].tracking_code !== trackingCode) {
      return res.status(403).send(page("Erreur", "<h2>Acces refuse.</h2>", null));
    }

    if (files.photo_identite?.[0]) {
      const res1 = await uploadToCloudinary(files.photo_identite[0].buffer, "trouvemoi/identites", `id_corr_${Date.now()}`);
      await pool.query(`UPDATE professional_applications SET photo_identite_url = $1 WHERE id = $2`, [res1.secure_url, id]);
    }
    if (files.photo_kyc?.[0]) {
      const res2 = await uploadToCloudinary(files.photo_kyc[0].buffer, "trouvemoi/kyc", `kyc_corr_${Date.now()}`);
      await pool.query(`UPDATE professional_applications SET photo_kyc_url = $1 WHERE id = $2`, [res2.secure_url, id]);
    }
    await pool.query(`UPDATE professional_applications SET status = 'pending', rejection_reason = NULL WHERE id = $1`, [id]);
    res.send(page("Succes", "<section class='card'><h1>Dossier mis à jour !</h1><p>Il est de nouveau en attente d'examen.</p><a href='/'>Accueil</a></section>", null));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

/* ESPACE PRO */

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
        <p style="margin-top:20px"><a href="/suivi-dossier">Mon dossier est en attente ? Suivre mon dossier</a></p>
        <p style="margin-top:10px"><a href="/mon-espace-pro/reinitialiser" style="color:#b42318">🔐 Mon code a fuité / Je l'ai perdu</a></p>
      </section>
    `, null));
  }

  let offers = [], gdprRequests = [], myReviews = [];

  try {
    offers = (await pool.query(`SELECT * FROM job_offers WHERE pro_id = $1 ORDER BY created_at DESC`, [proConnected.pro.id])).rows;
    gdprRequests = (await pool.query(`SELECT * FROM gdpr_requests WHERE pro_id = $1 ORDER BY created_at DESC LIMIT 20`, [proConnected.pro.id])).rows;
    myReviews = (await pool.query(`SELECT * FROM reviews WHERE pro_id = $1 ORDER BY created_at DESC LIMIT 10`, [proConnected.pro.id])).rows;
  } catch (error) { return res.status(500).send(page("Erreur", "<h2>Erreur technique.</h2>", proConnected)); }

  const now = new Date();

  const offersHtml = offers.map((offer) => {
    const expired = offer.expires_at && new Date(offer.expires_at) < now;
    const statusLabel = JOB_STATUS_LABELS[offer.status] || offer.status;
    const isPublic = offer.status === "approved" && !expired;

    return `
      <article class="card">
        <h2>${escapeHtml(offer.job_title)}</h2>
        <p><span class="badge badge-${offer.status}">${escapeHtml(statusLabel)}</span> ${isPublic ? `<span class="badge badge-approved">En ligne</span>` : ""} ${expired ? `<span class="badge badge-rejected">Expiree</span>` : ""}</p>
        <p><span class="label">Entreprise :</span> ${escapeHtml(offer.company_name)}</p>
        <p><span class="label">Ville :</span> ${escapeHtml(offer.city)}</p>
        ${offer.expires_at ? `<p class="muted">Expire le : ${new Date(offer.expires_at).toLocaleDateString("fr-FR")}</p>` : ""}
        <div class="actions">
          ${offer.status === "approved" && !expired ? `<form action="/mon-espace-pro/offre/${offer.id}/close" method="POST" style="display:inline"><button class="warning" type="submit">🔒 Cloturer</button></form>` : ""}
          ${offer.status === "closed" ? `<form action="/mon-espace-pro/offre/${offer.id}/reopen" method="POST" style="display:inline"><button class="success" type="submit">🔓 Rouvrir</button></form>` : ""}
          ${offer.status === "approved" && !expired ? `<form action="/mon-espace-pro/offre/${offer.id}/renew" method="POST" style="display:inline"><button class="secondary" type="submit">🔄 Prolonger ${OFFER_DURATION_DAYS}j</button></form>` : ""}
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

/* CONNEXION ESPACE PRO */
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

/* ✅ NOUVEAU : Auto-réinitialisation du code pro par le propriétaire du dossier */
app.get("/mon-espace-pro/reinitialiser", (req, res) => {
  res.send(page("Réinitialiser mon code", `
    <section class="card">
      <h1>🔐 Réinitialiser mon code professionnel</h1>
      <p>Pour des raisons de sécurité, entrez votre <strong>code de suivi</strong> (SUIVI-XXXX) reçu lors de votre inscription. Un nouveau code professionnel vous sera attribué immédiatement.</p>
      <form action="/mon-espace-pro/reinitialiser" method="POST">
        <label>Code de suivi *</label>
        <input name="tracking_code" required maxlength="20" style="text-transform:uppercase" placeholder="SUIVI-XXXX">
        <button type="submit" class="warning">🔄 Générer un nouveau code</button>
      </form>
      <div class="alert alert-warning" style="margin-top:16px">
        ⚠️ Votre ancien code sera immédiatement désactivé et ne pourra plus être utilisé.
      </div>
      <p style="margin-top:16px"><a href="/mon-espace-pro">← Retour à la connexion</a></p>
    </section>
  `, null));
});

app.post("/mon-espace-pro/reinitialiser", async (req, res) => {
  // ✅ Anti-bruteforce
  const ip = req.ip || "unknown";
  const now = Date.now();
  const attempts = resetAttempts.get(ip) || { count: 0, startedAt: now };
  if (now - attempts.startedAt > 15 * 60 * 1000) { attempts.count = 0; attempts.startedAt = now; }
  if (attempts.count >= 5) {
    return res.status(429).send(page("Trop de tentatives", 
      "<section class='card'><h1>⏳ Trop de tentatives</h1><p>Veuillez patienter 15 minutes avant de réessayer.</p></section>", 
      null));
  }
  attempts.count++;
  resetAttempts.set(ip, attempts);

  const code = String(req.body.tracking_code || "").trim().toUpperCase();
  if (!code) return res.redirect(303, "/mon-espace-pro/reinitialiser");
  
  try {
    const result = await pool.query(
      `SELECT id, full_name FROM professional_applications WHERE tracking_code = $1 AND status = 'approved'`,
      [code]
    );
    if (!result.rows.length) {
      return res.status(404).send(page("Erreur", 
        "<section class='card'><h2>Code de suivi introuvable ou dossier non approuvé.</h2><a href='/mon-espace-pro/reinitialiser'>Réessayer</a></section>", 
        null));
    }
    
    const newCode = await generateUniqueProCode();
    await pool.query(
      `UPDATE professional_applications SET pro_code = $1, pro_code_updated_at = NOW() WHERE id = $2`,
      [newCode, result.rows[0].id]
    );
    
    res.send(page("Nouveau code généré", `
      <section class="card">
        <h1>✅ Nouveau code généré</h1>
        <p>Votre ancien code est désormais <strong>invalide</strong>.</p>
        <div class="pro-code-box">
          <div class="pro-code-label">Votre nouveau code professionnel</div>
          <div class="pro-code-value">${escapeHtml(newCode)}</div>
        </div>
        <div class="alert alert-warning">
          <strong>⚠️ Notez ce code immédiatement.</strong> Il ne sera plus affiché.
        </div>
        <div class="actions" style="margin-top:20px">
          <a class="button" href="/mon-espace-pro">Se connecter maintenant</a>
        </div>
      </section>
    `, null));
  } catch (e) {
    console.error("Erreur réinitialisation :", e.message);
    res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null));
  }
});

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

// ✅ Correctif : inclure les messages de contact dans l'export RGPD
app.get("/mon-espace-pro/mes-donnees", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  
  try {
    const offersResult = await pool.query(`SELECT * FROM job_offers WHERE pro_id = $1`, [proConnected.pro.id]);
    const gdprResult = await pool.query(`SELECT * FROM gdpr_requests WHERE pro_id = $1`, [proConnected.pro.id]);
    const reviewsResult = await pool.query(`SELECT * FROM reviews WHERE pro_id = $1`, [proConnected.pro.id]);
    const messagesResult = await pool.query(`SELECT id, name, email, phone, subject, message, created_at FROM contact_messages WHERE pro_id = $1`, [proConnected.pro.id]);
    
    const exportData = { 
      utilisateur: proConnected.pro, 
      offres: offersResult.rows, 
      demandes: gdprResult.rows, 
      avis: reviewsResult.rows,
      messages_recus: messagesResult.rows
    };
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Content-Disposition", `attachment; filename="trouvemoi-${proConnected.code}.json"`);
    res.send(JSON.stringify(exportData, null, 2));
  } catch (e) { res.status(500).send("Erreur lors de l'export."); }
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

/* PUBLICATION EMPLOI */
app.get("/publier-emploi", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  const contractOptions = JOB_CONTRACT_TYPES.map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join("");
  res.send(page("Publier", `<section class="card"><h1>Nouvelle offre</h1><form action="/offres-emploi" method="POST"><label>Entreprise *</label><input name="company_name" required maxlength="200" value="${escapeHtml(getDisplayName(proConnected.pro))}"><label>Poste *</label><input name="job_title" required maxlength="200"><label>Ville *</label><input name="city" required maxlength="100" value="${escapeHtml(proConnected.pro.city)}"><label>Contrat *</label><select name="contract_type" required><option value="">Choisir</option>${contractOptions}</select><label>Description *</label><textarea name="description" required maxlength="5000"></textarea><button>Soumettre</button></form><p><a href="/mon-espace-pro">Retour</a></p></section>`, proConnected));
});

// ✅ Correctif : validation contract_type
app.post("/offres-emploi", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  
  if (!JOB_CONTRACT_TYPES.includes(req.body.contract_type)) {
    return res.status(400).send(page("Erreur", "<h2>Type de contrat invalide.</h2>", proConnected));
  }
  
  try {
    await pool.query(`INSERT INTO job_offers (company_name, job_title, city, contract_type, description, status, pro_id, expires_at) VALUES ($1,$2,$3,$4,$5,'pending',$6, NOW() + INTERVAL '15 days')`, [req.body.company_name, req.body.job_title, req.body.city, req.body.contract_type, req.body.description, proConnected.pro.id]);
    res.send(page("Succes", "<section class='card'><h1>Offre soumise !</h1><p>En attente de validation.</p><a href='/mon-espace-pro'>Retour</a></section>", proConnected));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", proConnected)); }
});

/* ADMINISTRATION */

app.get("/admin", (req, res) => {
  const session = verifySessionToken(readCookie(req, SESSION_COOKIE));
  if (session) return res.redirect(303, "/admin/dashboard");
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
  let gdprCount = 0, prosPendingCount = 0, reviewsPendingCount = 0, msgsCount = 0;
  try {
    gdprCount = Number((await pool.query("SELECT COUNT(*) FROM gdpr_requests WHERE status = 'pending'")).rows[0].count);
    prosPendingCount = Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status = 'pending'")).rows[0].count);
    reviewsPendingCount = Number((await pool.query("SELECT COUNT(*) FROM reviews WHERE status = 'pending'")).rows[0].count);
    msgsCount = Number((await pool.query("SELECT COUNT(*) FROM contact_messages WHERE is_read = false")).rows[0].count);
  } catch (e) {}

  const links = [
    { href: "/admin/dashboard", label: "📊 Tableau de bord", badge: 0 },
    { href: "/admin/candidatures", label: "📋 Candidatures", badge: prosPendingCount },
    { href: "/admin/avis", label: "⭐ Avis", badge: reviewsPendingCount },
    { href: "/admin/emplois", label: "💼 Offres", badge: 0 },
    { href: "/admin/messages", label: "📩 Messages", badge: msgsCount },
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
    reviews: Number((await pool.query("SELECT COUNT(*) FROM reviews WHERE status = 'pending'")).rows[0].count),
    messages: Number((await pool.query("SELECT COUNT(*) FROM contact_messages WHERE is_read = false")).rows[0].count)
  };
  const menu = await adminMenu("/admin/dashboard", getCsrf(req));

  res.send(page("Dashboard", `
    <section class="card"><h1>Bienvenue Admin</h1></section>
    ${menu}
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-number">${stats.pros}</div><div class="stat-label">Pros approuves</div></div>
      <div class="stat-card warning"><div class="stat-number">${stats.prosPending}</div><div class="stat-label">Candidatures en attente</div></div>
      <div class="stat-card danger"><div class="stat-number">${stats.reviews}</div><div class="stat-label">Avis a moderer</div></div>
      <div class="stat-card info"><div class="stat-number">${stats.messages}</div><div class="stat-label">Messages non lus</div></div>
    </div>
  `, null));
});

/* ADMIN CANDIDATURES (AVEC BOUTON WHATSAPP + REGENERATION) */

app.get("/admin/candidatures", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  const result = await pool.query(`SELECT p.* FROM professional_applications p ORDER BY CASE WHEN p.status = 'pending' THEN 0 ELSE 1 END, p.created_at DESC`);

  const applications = result.rows.map(c => {
    const statusOptions = ALLOWED_STATUSES.map(s => `<option value="${s}" ${c.status === s ? "selected" : ""}>${STATUS_LABELS[s]}</option>`).join("");
    const photos = `
      <div class="photos-grid">
        ${c.photo_profil_url ? `<div class="photo-block"><img src="${escapeHtml(c.photo_profil_url)}" class="photo-profil"><div class="photo-label">Profil</div></div>` : ""}
        ${c.photo_identite_url ? `<div class="photo-block"><img src="${escapeHtml(c.photo_identite_url)}" class="photo-identite"><div class="photo-label">Identite</div></div>` : ""}
        ${c.photo_kyc_url ? `<div class="photo-block"><img src="${escapeHtml(c.photo_kyc_url)}" class="photo-kyc"><div class="photo-label" style="color:#f59e0b">KYC (Verification)</div></div>` : ""}
        ${c.photo_activite_url ? `<div class="photo-block"><img src="${escapeHtml(c.photo_activite_url)}" class="photo-activite"><div class="photo-label">Activite</div></div>` : ""}
      </div>`;
    
    let codeBlock = "";
    if (c.pro_code) {
      const waNumber = c.whatsapp_number || c.phone;
      const cleanNumber = waNumber.replace(/[()\s.-]/g, "").replace(/^\+/, "");
      const waMessage = encodeURIComponent(`Bonjour ${c.full_name}, votre candidature sur TrouveMoi a ete approuvee ✅\n\nVotre code professionnel est : ${c.pro_code}\n\nConservez-le precieusement pour vous connecter a votre espace pro : https://trouvemoi-4mk0.onrender.com/mon-espace-pro`);
      
      codeBlock = `
        <div class="pro-code-box" style="margin:16px 0">
          <div class="pro-code-label">Code professionnel</div>
          <div class="pro-code-value">${escapeHtml(c.pro_code)}</div>
        </div>
        <div class="card" style="background:#f0fdf9;border:1px solid #0a9d70">
          <h3 style="margin-top:0">📤 Envoyer le code au professionnel</h3>
          <a class="button whatsapp" href="https://wa.me/${escapeHtml(cleanNumber)}?text=${waMessage}" target="_blank">📱 Envoyer par WhatsApp</a>
        </div>
        <div class="card" style="background:#fff7ed;border:1px solid #fdba74;margin-top:12px">
          <h3 style="margin-top:0;color:#9a3412">🔄 Régénérer le code</h3>
          <p class="muted" style="font-size:13px;margin-bottom:10px">Utile si le professionnel a perdu son code ou s'il a fuité. L'ancien code sera immédiatement désactivé.</p>
          <form action="/admin/candidatures/${c.id}/regenerer-code" method="POST" onsubmit="return confirm('Régénérer le code ? L ancien sera invalidé immédiatement.')">
            <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
            <button class="warning" type="submit">🔄 Générer un nouveau code</button>
          </form>
        </div>
      `;
    }

    return `
      <article class="card">
        <h2>${escapeHtml(c.full_name)} <span class="badge badge-${c.status}">${STATUS_LABELS[c.status]}</span>${c.status === 'approved' ? ` ${renderKycBadge()}` : ""}</h2>
        ${photos}
        <p><span class="label">Ville :</span> ${escapeHtml(c.city)}</p>
        <p><span class="label">Profession :</span> ${escapeHtml(c.profession)}</p>
        ${c.rejection_reason ? `<p><span class="label" style="color:red">Motif :</span> ${escapeHtml(c.rejection_reason)}</p>` : ""}
        
        ${codeBlock}
        
        <form action="/admin/candidatures/${c.id}/status" method="POST" style="background:#f9fafb; padding:15px; border-radius:8px;">
          <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
          <label for="status-${c.id}">Changer le statut</label>
          <select id="status-${c.id}" name="status">${statusOptions}</select>
          <label for="reason-${c.id}">Motif (si refus ou corrections)</label>
          <input id="reason-${c.id}" name="rejection_reason" maxlength="1000" value="${escapeHtml(c.rejection_reason || "")}" placeholder="Ex: Photo floue, veuillez recommencer">
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
  const id = Number(req.params.id), status = req.body.status, reason = req.body.rejection_reason || null;
  if (!ALLOWED_STATUSES.includes(status)) return res.redirect(303, "/admin/candidatures");
  
  const existing = await pool.query("SELECT pro_code FROM professional_applications WHERE id = $1", [id]);
  if (!existing.rows.length) return res.redirect(303, "/admin/candidatures");
  
  if (status === "approved" && !existing.rows[0].pro_code) {
    const newCode = await generateUniqueProCode();
    await pool.query(`UPDATE professional_applications SET status = $1, pro_code = $2, rejection_reason = $3 WHERE id = $4`, [status, newCode, reason, id]);
  } else {
    await pool.query(`UPDATE professional_applications SET status = $1, rejection_reason = $2 WHERE id = $3`, [status, reason, id]);
  }
  res.redirect(303, "/admin/candidatures");
});

// ✅ NOUVEAU : Régénération du code pro par l'admin
app.post("/admin/candidatures/:id/regenerer-code", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/candidatures");
  
  try {
    const check = await pool.query("SELECT id, status FROM professional_applications WHERE id = $1", [id]);
    if (!check.rows.length || check.rows[0].status !== "approved") {
      return res.redirect(303, "/admin/candidatures");
    }
    const newCode = await generateUniqueProCode();
    await pool.query(
      `UPDATE professional_applications SET pro_code = $1, pro_code_updated_at = NOW() WHERE id = $2`,
      [newCode, id]
    );
    res.redirect(303, "/admin/candidatures");
  } catch (e) {
    console.error("Erreur régénération code :", e.message);
    res.redirect(303, "/admin/candidatures");
  }
});

app.post("/admin/candidatures/:id/supprimer", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  const proResult = await pool.query(`SELECT photo_profil_url, photo_identite_url, photo_kyc_url, photo_activite_url FROM professional_applications WHERE id = $1`, [id]);
  
  if (proResult.rows.length) {
    const p = proResult.rows[0];
    // ✅ Correctif : Promise.allSettled pour ne pas bloquer si une suppression échoue
    await Promise.allSettled([p.photo_profil_url, p.photo_identite_url, p.photo_kyc_url, p.photo_activite_url].map(url => deleteFromCloudinary(url)));
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
  const result = await pool.query(`SELECT r.*, p.full_name AS pro_name FROM reviews r LEFT JOIN professional_applications p ON p.id = r.pro_id ORDER BY CASE WHEN r.status = 'pending' THEN 0 ELSE 1 END, r.created_at DESC`);
  const reviews = result.rows.map(r => `
    <article class="card">
      <h2>Avis de ${escapeHtml(r.author_name)} sur ${escapeHtml(r.pro_name || "Inconnu")} <span class="badge badge-${r.status}">${REVIEW_STATUS_LABELS[r.status]}</span></h2>
      <div class="review-stars">${renderStars(r.rating)}</div>
      <p>${escapeHtml(r.comment || "Aucun commentaire")}</p>
      <div class="actions">
        <form action="/admin/avis/${r.id}/statut" method="POST" style="display:inline"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><input type="hidden" name="status" value="approved"><button class="success">Approuver</button></form>
        <form action="/admin/avis/${r.id}/statut" method="POST" style="display:inline"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><input type="hidden" name="status" value="rejected"><button class="danger">Rejeter</button></form>
      </div>
    </article>
  `).join("");
  const menu = await adminMenu("/admin/avis", csrf);
  res.send(page("Avis", `<section class="card"><h1>Moderation des avis</h1></section>${menu}${reviews || '<section class="card"><p class="muted">Aucun avis.</p></section>'}`, null));
});

// ✅ Correctif : processed_at renseigné
app.post("/admin/avis/:id/statut", requireAdmin, verifyCsrf, async (req, res) => {
  if (REVIEW_STATUSES.includes(req.body.status)) {
    await pool.query(`UPDATE reviews SET status = $1, processed_at = NOW() WHERE id = $2`, [req.body.status, Number(req.params.id)]);
  }
  res.redirect(303, "/admin/avis");
});

/* ADMIN EMPLOIS */
app.get("/admin/emplois", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  const result = await pool.query(`SELECT j.*, p.full_name AS pro_name FROM job_offers j LEFT JOIN professional_applications p ON p.id = j.pro_id ORDER BY CASE WHEN j.status = 'pending' THEN 0 ELSE 1 END, j.created_at DESC`);
  const jobs = result.rows.map(j => `
    <article class="card">
      <h2>${escapeHtml(j.job_title)} <span class="badge badge-${j.status}">${JOB_STATUS_LABELS[j.status]}</span></h2>
      <p>Posté par : ${escapeHtml(j.pro_name || "Inconnu")}</p>
      <p><strong>Ville :</strong> ${escapeHtml(j.city)} | <strong>Contrat :</strong> ${escapeHtml(j.contract_type)}</p>
      <p>${escapeHtml(j.description)}</p>
      <form action="/admin/emplois/${j.id}/status" method="POST"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><select name="status">${JOB_STATUSES.map(s => `<option value="${s}" ${j.status === s ? "selected" : ""}>${JOB_STATUS_LABELS[s]}</option>`).join("")}</select><button>Modifier</button></form>
    </article>
  `).join("");
  const menu = await adminMenu("/admin/emplois", csrf);
  res.send(page("Emplois", `<section class="card"><h1>Offres d'emploi</h1></section>${menu}${jobs || '<section class="card"><p class="muted">Aucune offre.</p></section>'}`, null));
});

app.post("/admin/emplois/:id/status", requireAdmin, verifyCsrf, async (req, res) => {
  if (JOB_STATUSES.includes(req.body.status)) await pool.query(`UPDATE job_offers SET status = $1 WHERE id = $2`, [req.body.status, Number(req.params.id)]);
  res.redirect(303, "/admin/emplois");
});

/* ADMIN MESSAGES */
app.get("/admin/messages", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  const result = await pool.query(`SELECT * FROM contact_messages ORDER BY is_read ASC, created_at DESC`);
  const messages = result.rows.map(m => `
    <article class="card" style="${m.is_read ? 'opacity:0.6' : ''}">
      <h2>${escapeHtml(m.subject)}</h2>
      <p><strong>De :</strong> ${escapeHtml(m.name)} (${escapeHtml(m.email || m.phone || '')})</p>
      ${m.pro_id ? `<p class="muted">Concernant le pro ID : ${m.pro_id}</p>` : ""}
      <p>${escapeHtml(m.message)}</p>
      <p class="muted">Recu le : ${new Date(m.created_at).toLocaleString("fr-FR")}</p>
      ${!m.is_read ? `<form action="/admin/messages/${m.id}/read" method="POST"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><button class="secondary">Marquer lu</button></form>` : ""}
    </article>
  `).join("");
  const menu = await adminMenu("/admin/messages", csrf);
  res.send(page("Messages", `<section class="card"><h1>Messages</h1></section>${menu}${messages || '<section class="card"><p class="muted">Aucun message.</p></section>'}`, null));
});

app.post("/admin/messages/:id/read", requireAdmin, verifyCsrf, async (req, res) => {
  await pool.query(`UPDATE contact_messages SET is_read = true WHERE id = $1`, [Number(req.params.id)]);
  res.redirect(303, "/admin/messages");
});

/* ADMIN RGPD */
app.get("/admin/rgpd", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  const result = await pool.query(`SELECT g.*, p.full_name AS pro_name FROM gdpr_requests g LEFT JOIN professional_applications p ON p.id = g.pro_id ORDER BY CASE WHEN g.status = 'pending' THEN 0 ELSE 1 END, g.created_at DESC`);
  const reqs = result.rows.map(r => `
    <article class="card">
      <h2>${GDPR_TYPE_LABELS[r.request_type]} - ${escapeHtml(r.pro_name || "Inconnu")} <span class="badge badge-${r.status}">${GDPR_STATUS_LABELS[r.status]}</span></h2>
      <p>${escapeHtml(r.message)}</p>
      <p class="muted">Demande le : ${new Date(r.created_at).toLocaleString("fr-FR")}</p>
      ${r.status === "pending" ? `<form action="/admin/rgpd/${r.id}/traiter" method="POST"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><button class="success">Marquer comme traitee</button></form>` : ""}
    </article>
  `).join("");
  const menu = await adminMenu("/admin/rgpd", csrf);
  res.send(page("RGPD", `<section class="card"><h1>RGPD</h1></section>${menu}${reqs || '<section class="card"><p class="muted">Aucune demande.</p></section>'}`, null));
});

// ✅ Correctif : processed_at renseigné
app.post("/admin/rgpd/:id/traiter", requireAdmin, verifyCsrf, async (req, res) => {
  await pool.query(`UPDATE gdpr_requests SET status = 'processed', processed_at = NOW() WHERE id = $1`, [Number(req.params.id)]);
  res.redirect(303, "/admin/rgpd");
});

app.post("/admin/logout", requireAdmin, verifyCsrf, (req, res) => { clearSessionCookie(res); res.redirect(303, "/admin"); });

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
      <h2>3. Protection</h2><p>Les photos d'identite et les photos de verification KYC sont strictement privees et accessibles uniquement aux administrateurs pour validation.</p>
      <h2>4. Vos droits</h2><p>Vous disposez des droits d'acces, rectification, suppression et opposition. Contactez-nous via le <a href="/contact">formulaire de contact</a>.</p>
    </section>
  `, proConnected));
});

app.get("/contact", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const proId = String(req.query.pro || "").trim();
  
  res.send(page("Contact", `
    <section class="card">
      <h1>Nous contacter</h1>
      <p>Une question, une suggestion, un probleme ? Ecrivez-nous.</p>
      <form action="/contact" method="POST">
        <input type="hidden" name="pro_id" value="${escapeHtml(proId)}">
        <label>Votre nom *</label><input name="name" required maxlength="150">
        <label>Votre email</label><input type="email" name="email" maxlength="254">
        <label>Votre telephone</label><input type="tel" name="phone" maxlength="30">
        <label>Sujet *</label><input name="subject" required maxlength="200">
        <label>Message *</label><textarea name="message" required rows="6" maxlength="5000"></textarea>
        <button type="submit">Envoyer</button>
      </form>
    </section>
  `, proConnected));
});

// ✅ Correctif : validation pro_id + troncature des champs
app.post("/contact", async (req, res) => {
  const { name, email, phone, subject, message, pro_id } = req.body;
  if (!name || !subject || !message || (!email && !phone)) {
    return res.status(400).send(page("Erreur", "<section class='card'><h2>Informations manquantes.</h2><a href='/contact'>Retour</a></section>", null));
  }
  try {
    let proIdInt = null;
    if (/^\d+$/.test(String(pro_id || ""))) {
      const candidate = parseInt(pro_id, 10);
      if (Number.isSafeInteger(candidate) && candidate > 0) {
        const exists = await pool.query("SELECT 1 FROM professional_applications WHERE id = $1 AND status = 'approved'", [candidate]);
        if (exists.rows.length) proIdInt = candidate;
      }
    }
    await pool.query(
      `INSERT INTO contact_messages (name, email, phone, subject, message, pro_id) VALUES ($1, $2, $3, $4, $5, $6)`,
      [String(name).slice(0, 150), email ? String(email).slice(0, 254) : null, phone ? String(phone).slice(0, 30) : null, String(subject).slice(0, 200), String(message).slice(0, 5000), proIdInt]
    );
    res.send(page("Succes", "<section class='card'><h1>Message envoye !</h1><p>Nous vous repondrons dans les plus brefs delais.</p><a class='button' href='/'>Retour a l'accueil</a></section>", null));
  } catch (e) {
    console.error("Erreur /contact :", e.message);
    res.status(500).send(page("Erreur", "<h2>Erreur d'envoi.</h2>", null));
  }
});

/* HEALTH CHECKS */
app.get("/health", (req, res) => res.json({ status: "ok", application: "TrouveMoi", time: new Date().toISOString() }));
app.get("/health/database", async (req, res) => {
  try { await pool.query("SELECT 1"); res.json({ status: "ok", database: "connected" }); }
  catch (e) { res.status(500).json({ status: "error", message: "database unreachable" }); }
});

/* ROBOTS + SITEMAP (SEO) */
app.get("/robots.txt", (req, res) => {
  res.type("text/plain").send(`User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /mon-espace-pro\nDisallow: /suivi-dossier\nSitemap: ${req.protocol}://${req.get("host")}/sitemap.xml`);
});

app.get("/sitemap.xml", async (req, res) => {
  try {
    const base = `${req.protocol}://${req.get("host")}`;
    const pros = await pool.query(`SELECT id FROM professional_applications WHERE status = 'approved' LIMIT 1000`);
    const urls = [
      `${base}/`, `${base}/emplois`, `${base}/devenir-professionnel`, `${base}/a-propos`, `${base}/contact`, `${base}/conditions`, `${base}/confidentialite`,
      ...pros.rows.map(p => `${base}/pro/${p.id}`)
    ];
    const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.map(u => `  <url><loc>${u}</loc></url>`).join("\n")}\n</urlset>`;
    res.type("application/xml").send(xml);
  } catch (e) { res.status(500).send("error"); }
});

/* 404 - PAGE INTROUVABLE */
app.use((req, res) => {
  res.status(404).send(page("Introuvable", "<section class='card'><h1>404 - Page introuvable</h1><p>La page demandee n'existe pas.</p><a class='button' href='/'>Retour a l'accueil</a></section>", null));
});

/* GESTION GLOBALE DES ERREURS (Multer, etc.) */
app.use((err, req, res, next) => {
  console.error("Erreur non geree :", err.message);
  if (err.code === "LIMIT_FILE_SIZE") return res.status(413).send(page("Erreur", "<h2>Fichier trop volumineux (max 5 Mo).</h2>", null));
  if (err.message && err.message.includes("Format non autorise")) return res.status(400).send(page("Erreur", "<h2>Format d'image non autorise.</h2>", null));
  res.status(500).send(page("Erreur", "<section class='card'><h1>Une erreur est survenue</h1><p>Veuillez reessayer plus tard.</p><a class='button' href='/'>Accueil</a></section>", null));
});

/* DEMARRAGE */

async function startServer() {
  try {
    /* TABLE PROS */
    await pool.query(`
      CREATE TABLE IF NOT EXISTS professional_applications (
        id SERIAL PRIMARY KEY, full_name VARCHAR(150) NOT NULL, company_name VARCHAR(200),
        phone VARCHAR(30) NOT NULL, phone_public BOOLEAN NOT NULL DEFAULT true,
        city VARCHAR(100) NOT NULL, neighborhood VARCHAR(150), profession VARCHAR(150) NOT NULL,
        experience VARCHAR(100), service_description TEXT NOT NULL, service_area VARCHAR(300),
        availability VARCHAR(100), npi VARCHAR(100), photo_profil_url TEXT, photo_identite_url TEXT,
        photo_kyc_url TEXT, photo_activite_url TEXT, contact_preference VARCHAR(20), 
        whatsapp_number VARCHAR(30), contact_email VARCHAR(254), pro_code VARCHAR(10) UNIQUE, 
        tracking_code VARCHAR(20) UNIQUE, rejection_reason TEXT,
        status VARCHAR(30) NOT NULL DEFAULT 'pending', created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    /* MIGRATIONS POUR BASES EXISTANTES */
    const migrations = [
      `ALTER TABLE professional_applications ALTER COLUMN npi DROP NOT NULL`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS company_name VARCHAR(200)`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS phone_public BOOLEAN NOT NULL DEFAULT true`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS photo_kyc_url TEXT`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS contact_preference VARCHAR(20)`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS whatsapp_number VARCHAR(30)`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS contact_email VARCHAR(254)`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS tracking_code VARCHAR(20)`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS rejection_reason TEXT`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS pro_code_updated_at TIMESTAMP`
    ];
    for (const q of migrations) {
      try { await pool.query(q); } catch (e) { console.warn("Migration ignoree :", e.message); }
    }

    /* TABLE OFFRES */
    await pool.query(`CREATE TABLE IF NOT EXISTS job_offers (
      id SERIAL PRIMARY KEY, company_name VARCHAR(200) NOT NULL, job_title VARCHAR(200) NOT NULL,
      city VARCHAR(100) NOT NULL, contract_type VARCHAR(50) NOT NULL, description TEXT NOT NULL, 
      status VARCHAR(20) NOT NULL DEFAULT 'pending', pro_id INTEGER REFERENCES professional_applications(id) ON DELETE SET NULL, 
      expires_at TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    /* TABLE VILLES */
    await pool.query(`CREATE TABLE IF NOT EXISTS cities (id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL UNIQUE, display_order INTEGER NOT NULL DEFAULT 0)`);

    /* TABLE QUARTIERS */
    await pool.query(`CREATE TABLE IF NOT EXISTS neighborhoods (id SERIAL PRIMARY KEY, city_id INTEGER NOT NULL REFERENCES cities(id) ON DELETE CASCADE, name VARCHAR(150) NOT NULL, UNIQUE (city_id, name))`);

    /* TABLE METIERS */
    await pool.query(`CREATE TABLE IF NOT EXISTS professions (id SERIAL PRIMARY KEY, name VARCHAR(150) NOT NULL UNIQUE, category VARCHAR(100), display_order INTEGER NOT NULL DEFAULT 0)`);

    /* TABLE MESSAGES */
    await pool.query(`CREATE TABLE IF NOT EXISTS contact_messages (id SERIAL PRIMARY KEY, name VARCHAR(150) NOT NULL, email VARCHAR(254), phone VARCHAR(30), subject VARCHAR(200) NOT NULL, message TEXT NOT NULL, is_read BOOLEAN NOT NULL DEFAULT false, pro_id INTEGER REFERENCES professional_applications(id) ON DELETE SET NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);

    /* TABLE RGPD */
    await pool.query(`CREATE TABLE IF NOT EXISTS gdpr_requests (id SERIAL PRIMARY KEY, pro_id INTEGER REFERENCES professional_applications(id) ON DELETE SET NULL, request_type VARCHAR(30) NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'pending', message TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, processed_at TIMESTAMP)`);

    /* TABLE AVIS */
    await pool.query(`CREATE TABLE IF NOT EXISTS reviews (id SERIAL PRIMARY KEY, pro_id INTEGER NOT NULL REFERENCES professional_applications(id) ON DELETE CASCADE, author_name VARCHAR(100) NOT NULL, rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5), comment TEXT, status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, processed_at TIMESTAMP)`);

    /* INDEX (perf) */
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_reviews_pro_id ON reviews(pro_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_reviews_status ON reviews(status)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_pros_status ON professional_applications(status)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_pros_city_profession ON professional_applications(city, profession)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_jobs_status ON job_offers(status)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_read ON contact_messages(is_read)`);

    /* DONNEES DE BASE (Villes) */
    const checkCities = await pool.query("SELECT COUNT(*) FROM cities");
    if (Number(checkCities.rows[0].count) === 0) {
      const citiesData = [["Cotonou", 1], ["Abomey-Calavi", 2], ["Porto-Novo", 3], ["Parakou", 4], ["Bohicon", 5], ["Natitingou", 6], ["Ouidah", 7]];
      for (const [name, order] of citiesData) {
        await pool.query(`INSERT INTO cities (name, display_order) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [name, order]);
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
    }

    /* DONNEES DE BASE (Metiers) */
    const checkProfs = await pool.query("SELECT COUNT(*) FROM professions");
    if (Number(checkProfs.rows[0].count) === 0) {
      const profs = [
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
      for (const [name, category] of profs) {
        orderCounter += 1;
        await pool.query(`INSERT INTO professions (name, category, display_order) VALUES ($1, $2, $3) ON CONFLICT (name) DO NOTHING`, [name, category, orderCounter]);
      }
    }

    console.log("Toutes les tables sont pretes (KYC, suivi et anti-doublon inclus).");

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`TrouveMoi demarre sur le port ${PORT}.`);
    });
  } catch (error) {
    console.error("Erreur au demarrage :", error);
    process.exit(1);
  }
}

startServer();

