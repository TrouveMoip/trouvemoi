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
app.set("trust proxy", 1);

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

// ✅ Maps anti-bruteforce et anti-spam
const loginAttempts = new Map();
const resetAttempts = new Map();
const trackingAttempts = new Map();
const contactAttempts = new Map();
const reviewAttempts = new Map();

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

function verifyCsrf(req, res, next) {
  const csrf = req.adminSession?.csrf;
  if (!csrf || !req.body.csrfToken || !safeEqual(req.body.csrfToken, csrf)) {
    return res.status(403).send(page("Refuse", "<h1>Erreur CSRF</h1>", null));
  }
  next();
}

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

function renderKycBadge(size) {
  const cls = size === "lg" ? "badge-verified badge-verified-lg" : "badge-verified";
  return `<span class="${cls}" title="Identite verifiee manuellement par TrouveMoi">Verifie KYC</span>`;
}

// ✅ NOUVEAU LOGO (Épingle + Loupe + Personnes)
function renderLogo() {
  return `
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 220 50" width="200" height="45" style="display:inline-block;vertical-align:middle;max-width:100%">
      <path d="M 25 5 C 14 5 5 14 5 25 C 5 40 25 48 25 48 C 25 48 45 40 45 25 C 45 14 36 5 25 5 Z" fill="none" stroke="white" stroke-width="3.5"/>
      <line x1="32" y1="32" x2="42" y2="42" stroke="white" stroke-width="4.5" stroke-linecap="round"/>
      <circle cx="18" cy="20" r="4" fill="white"/>
      <path d="M 10 32 Q 10 26 18 26 Q 26 26 26 32 Z" fill="white"/>
      <circle cx="30" cy="20" r="4" fill="white" opacity="0.85"/>
      <path d="M 22 32 Q 22 26 30 26 Q 38 26 38 32 Z" fill="white" opacity="0.85"/>
      <text x="55" y="33" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif" font-size="24" font-weight="900" fill="white" letter-spacing="-0.5" class="logo-text">TrouveMoi</text>
    </svg>`;
}

function buildMenu(proConnected) {
  if (proConnected) {
    return `<nav><a href="/">Professionnels</a><a href="/emplois">Emploi</a><a href="/mon-espace-pro">Mon espace pro</a><a href="/publier-emploi">📢 Publier une offre</a><form action="/mon-espace-pro/logout" method="POST" style="display:inline"><button type="submit" style="background:transparent;border:none;color:white;padding:8px 14px;border-radius:20px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit">Deconnexion</button></form></nav>`;
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

      <!-- ✅ GOOGLE ANALYTICS (GA4) -->
      <script async src="https://www.googletagmanager.com/gtag/js?id=G-6YQ5R6M4ET"></script>
      <script>
        window.dataLayer = window.dataLayer || [];
        function gtag(){dataLayer.push(arguments);}
        gtag('js', new Date());
        gtag('config', 'G-6YQ5R6M4ET');
      </script>

      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; padding: 0; background: #f8f9fa; color: #1a202c; line-height: 1.6; min-height: 100vh; display: flex; flex-direction: column; }
        
        /* ✅ LE MENU BLEU EST DE RETOUR */
        header { background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%); color: white; padding: 16px 20px; box-shadow: 0 4px 20px rgba(30,64,175,0.15); position: sticky; top: 0; z-index: 100; }
        .header-content { max-width: 1100px; margin: 0 auto; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; }
        .logo { display: inline-flex; align-items: center; text-decoration: none; }
        .logo svg { display: block; height: 42px; width: auto; max-width: 100%; }
        .tagline { font-size: 13px; color: rgba(255,255,255,0.85); margin-top: 2px; }
        
        nav { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
        nav a, nav button { color: white; text-decoration: none; padding: 8px 14px; border-radius: 20px; font-size: 14px; font-weight: 600; transition: background 0.2s; }
        nav a:hover, nav button:hover { background: rgba(255,255,255,0.2); color: white; }
        
        main { max-width: 1100px; width: 100%; margin: 0 auto; padding: 24px 20px; flex: 1; }
        .card { background: white; padding: 24px; margin-bottom: 20px; border-radius: 20px; box-shadow: 0 4px 16px rgba(0,0,0,0.04); transition: transform 0.2s, box-shadow 0.2s; }
        .card:hover { box-shadow: 0 8px 24px rgba(0,0,0,0.08); }
        
        /* ✅ TITRES EN BLEU */
        h1 { font-size: 28px; margin-bottom: 16px; color: #1e40af; line-height: 1.2; font-weight: 800; border: none; padding: 0; }
        h2 { font-size: 22px; margin-bottom: 14px; color: #1e3a8a; line-height: 1.3; font-weight: 700; border: none; padding: 0; }
        h3 { font-size: 18px; margin-bottom: 10px; color: #1a202c; line-height: 1.3; font-weight: 600; border: none; padding: 0; }
        p { margin-bottom: 12px; color: #4a5568; }
        
        .label { font-weight: 700; color: #1a202c; }
        .value { color: #4a5568; }
        
        label { display: block; margin-top: 8px; margin-bottom: 6px; font-weight: 600; font-size: 14px; color: #1a202c; }
        
        /* ✅ CHAMPS CLAIRS AVEC BORDURE POUR BIEN LES VOIR */
        input, textarea, select { width: 100%; padding: 16px 20px; margin-bottom: 14px; border: 1px solid #cbd5e0; border-radius: 50px; font-size: 15px; font-family: inherit; background: white; transition: border-color 0.2s, box-shadow 0.2s; }
        input:focus, textarea:focus, select:focus { outline: none; border-color: #2563eb; box-shadow: 0 0 0 4px rgba(37,99,235,0.1); }
        textarea { resize: vertical; min-height: 100px; border-radius: 20px; }
        input[type="file"] { padding: 10px; background: #f8f9fa; border: 2px dashed #cbd5e0; cursor: pointer; border-radius: 20px; }
        input[type="file"]:hover { border-color: #2563eb; background: #eff6ff; }
        input[type="checkbox"], input[type="radio"] { width: auto; margin-right: 8px; }
        
        optgroup { font-weight: 800; color: #1e40af; font-style: normal; background: #eff6ff; padding: 6px 0; font-size: 15px; }
        optgroup option { font-weight: 400; color: #222; background: white; font-size: 15px; }

        /* ✅ BOUTONS ARRONDIS */
        button, .button { display: inline-block; border: none; background: #2563eb; color: white; padding: 14px 24px; border-radius: 50px; cursor: pointer; text-decoration: none; text-align: center; font-size: 15px; font-weight: 600; transition: background 0.2s, transform 0.1s; margin-right: 8px; margin-bottom: 8px; font-family: inherit; border: 1px solid transparent; }
        button:hover, .button:hover { background: #1d4ed8; transform: translateY(-2px); box-shadow: 0 4px 12px rgba(37,99,235,0.2); }
        
        .danger { background: #e53e3e; } .danger:hover { background: #c53030; box-shadow: 0 4px 12px rgba(229,62,62,0.2); }
        .secondary { background: white; color: #4a5568; border: 1px solid #cbd5e0; } .secondary:hover { background: #edf2f7; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
        .warning { background: #ed8936; } .warning:hover { background: #dd6b20; box-shadow: 0 4px 12px rgba(237,137,54,0.2); }
        .success { background: #38a169; } .success:hover { background: #2f855a; box-shadow: 0 4px 12px rgba(56,161,105,0.2); }
        .info { background: #3182ce; } .info:hover { background: #2b6cb0; }
        .muted { color: #718096; font-size: 14px; }

        .contact-buttons { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 16px; }
        .contact-buttons .button { flex: 1 1 140px; margin: 0; }
        .whatsapp { background: #25d366; } .whatsapp:hover { background: #1da851; box-shadow: 0 4px 12px rgba(37,211,102,0.2); }
        .facebook { background: #1877F2; } .facebook:hover { background: #166FE5; }
        .email { background: #475467; } .email:hover { background: #344054; }
        .share { background: #4267b2; } .share:hover { background: #365899; }

        .photos-grid { display: flex; flex-wrap: wrap; gap: 12px; margin: 16px 0; }
        .photos-grid img { max-width: 280px; max-height: 280px; border-radius: 20px; border: 2px solid #e2e8f0; object-fit: cover; }
        .photo-profil { border: 3px solid #2563eb !important; }
        .photo-identite { border: 3px solid #e53e3e !important; }
        .photo-activite { border: 3px solid #4a5568 !important; }
        .photo-kyc { border: 3px solid #ed8936 !important; }
        .photo-label { font-size: 12px; color: #718096; text-align: center; margin-top: 4px; font-weight: 600; }
        .photo-block { display: flex; flex-direction: column; align-items: center; }

        .help-text { font-size: 13px; color: #718096; margin-bottom: 12px; font-style: italic; }
        .hidden { display: none !important; }
        .actions { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }

        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .stat-card { background: white; padding: 24px; border-radius: 20px; box-shadow: 0 4px 16px rgba(0,0,0,0.04); border-left: 6px solid #2563eb; transition: transform 0.2s, box-shadow 0.2s; }
        .stat-card:hover { transform: translateY(-4px); box-shadow: 0 8px 24px rgba(0,0,0,0.08); }
        .stat-card.warning { border-left-color: #ed8936; } .stat-card.danger { border-left-color: #e53e3e; } .stat-card.info { border-left-color: #3182ce; } .stat-card.success { border-left-color: #38a169; }
        .stat-number { font-size: 36px; font-weight: 800; color: #1a202c; line-height: 1; margin-bottom: 6px; }
        .stat-label { font-size: 14px; color: #718096; font-weight: 600; }

        .pro-code-box { background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%); color: white; padding: 24px; border-radius: 20px; text-align: center; margin: 16px 0; box-shadow: 0 10px 30px rgba(30,64,175,0.2); }
        .pro-code-value { font-size: 42px; font-weight: 800; letter-spacing: 4px; margin: 12px 0; font-family: "Courier New", monospace; }
        .pro-code-label { font-size: 14px; opacity: 0.9; text-transform: uppercase; letter-spacing: 1px; }

        .badge { display: inline-block; padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
        .badge-pending { background: #fefcbf; color: #b7791f; }
        .badge-approved { background: #c6f6d5; color: #22543d; }
        .badge-rejected { background: #fed7d7; color: #822727; }
        .badge-closed { background: #e2e8f0; color: #4a5568; }
        .badge-processed { background: #c6f6d5; color: #22543d; }
        .badge-new { background: #e53e3e; color: white; margin-left: 6px; padding: 2px 8px; font-size: 11px; }
        
        .badge-verified { display: inline-flex; align-items: center; gap: 4px; background: #38a169; color: white; padding: 6px 14px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; box-shadow: 0 2px 6px rgba(56,161,105,0.3); }
        .badge-verified::before { content: "✓"; font-size: 13px; font-weight: 900; }
        .badge-verified-lg { font-size: 13px; padding: 8px 18px; }

        .alert { padding: 16px 20px; border-radius: 16px; margin-bottom: 16px; border: none; font-weight: 500; }
        .alert-success { background: #c6f6d5; color: #22543d; }
        .alert-danger { background: #fed7d7; color: #822727; }
        .alert-warning { background: #fefcbf; color: #b7791f; }
        .alert-info { background: #bee3f8; color: #2a4365; }

        .pro-welcome { background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%); color: white; padding: 28px; border-radius: 20px; margin-bottom: 20px; box-shadow: 0 10px 30px rgba(30,64,175,0.2); }
        .pro-welcome h2 { color: white; margin-bottom: 8px; font-size: 24px; }
        .pro-welcome p { color: rgba(255,255,255,0.9); margin-bottom: 16px; font-size: 15px; }
        .pro-welcome .actions { margin: 0; }
        .pro-welcome .button { background: white; color: #1e40af; }
        .pro-welcome .button:hover { background: #eff6ff; transform: translateY(-2px); box-shadow: 0 4px 12px rgba(255,255,255,0.3); }
        .pro-welcome .button.secondary { background: rgba(255,255,255,0.2); color: white; border: none; }

        .pros-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 20px; margin-top: 20px; }
        .pro-card { background: white; border-radius: 20px; overflow: hidden; box-shadow: 0 4px 16px rgba(0,0,0,0.04); transition: transform 0.2s, box-shadow 0.2s; display: flex; flex-direction: column; }
        .pro-card:hover { transform: translateY(-4px); box-shadow: 0 8px 24px rgba(0,0,0,0.1); }
        .pro-card-image { width: 100%; height: 180px; background: #edf2f7; display: flex; align-items: center; justify-content: center; overflow: hidden; }
        .pro-card-image img { width: 100%; height: 100%; object-fit: cover; }
        .pro-card-image-placeholder { font-size: 60px; color: #cbd5e0; }
        .pro-card-body { padding: 20px; flex: 1; display: flex; flex-direction: column; }
        .pro-card-profession { font-size: 13px; font-weight: 800; color: #2563eb; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
        .pro-card-name { font-size: 18px; font-weight: 800; color: #1a202c; margin-bottom: 8px; line-height: 1.3; }
        .pro-card-location { font-size: 14px; color: #718096; margin-bottom: 12px; }
        .pro-card-location::before { content: "📍 "; }
        .pro-card-rating { font-size: 15px; color: #ed8936; font-weight: 600; margin-bottom: 12px; letter-spacing: 1px; }
        .pro-card-rating .reviews-count { color: #718096; font-weight: 400; font-size: 13px; letter-spacing: 0; margin-left: 6px; }
        .pro-card-rating .no-rating { color: #a0aec0; font-weight: 400; font-style: italic; font-size: 13px; letter-spacing: 0; }
        .pro-card-button { display: block; width: 100%; background: #edf2f7; color: #2b6cb0; padding: 12px 16px; border-radius: 50px; text-align: center; text-decoration: none; font-weight: 700; font-size: 14px; margin-top: auto; transition: background 0.2s; }
        .pro-card-button:hover { background: #bee3f8; }

        .pro-header { background: white; color: #1a202c; padding: 32px 24px; border-radius: 20px; margin-bottom: 20px; box-shadow: 0 4px 16px rgba(0,0,0,0.04); text-align: center; }
        .pro-header h1 { color: #1a202c; font-size: 30px; margin-bottom: 8px; }
        .pro-header .profession { font-size: 18px; color: #2563eb; margin-bottom: 8px; font-weight: 700; }
        .pro-header .location { font-size: 15px; color: #718096; }
        .pro-header .rating-large { font-size: 22px; color: #ed8936; margin-top: 12px; font-weight: 700; letter-spacing: 2px; }
        .pro-header .rating-large .reviews-count { color: #718096; font-weight: 400; font-size: 15px; letter-spacing: 0; margin-left: 8px; }

        .review-item { background: #f8f9fa; padding: 20px; border-radius: 16px; margin-bottom: 16px; border: 1px solid #edf2f7; }
        .review-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 8px; }
        .review-author { font-weight: 800; color: #1a202c; }
        .review-stars { color: #ed8936; font-size: 18px; letter-spacing: 2px; }
        .review-date { font-size: 13px; color: #a0aec0; }
        .review-comment { color: #4a5568; margin-top: 8px; line-height: 1.6; }

        .rating-summary { display: flex; align-items: center; gap: 24px; padding: 24px; background: #fefcbf; border-radius: 20px; margin-bottom: 24px; flex-wrap: wrap; }
        .rating-big-number { font-size: 52px; font-weight: 800; color: #b7791f; line-height: 1; }
        .rating-details { flex: 1; min-width: 180px; }
        .rating-details .stars { font-size: 28px; color: #ed8936; letter-spacing: 3px; }
        .rating-details .count { font-size: 14px; color: #744210; margin-top: 4px; font-weight: 600; }

        .btn-review { background: #ed8936; color: white; }
        .btn-review:hover { background: #dd6b20; box-shadow: 0 4px 12px rgba(237,137,54,0.2); }

        .star-rating-input { display: flex; flex-direction: row-reverse; justify-content: flex-end; gap: 6px; margin-bottom: 16px; width: auto; }
        .star-rating-input input { display: none; }
        .star-rating-input label { font-size: 44px; color: #cbd5e0; cursor: pointer; transition: color 0.2s, transform 0.1s; margin: 0; padding: 0; line-height: 1; font-weight: normal; }
        .star-rating-input label:hover { transform: scale(1.1); }
        .star-rating-input input:checked ~ label { color: #ed8936; }
        .star-rating-input label:hover, .star-rating-input label:hover ~ label { color: #ed8936; }

        .checkbox-block { background: #f8f9fa; padding: 16px; border-radius: 16px; margin: 12px 0; border: 1px solid #edf2f7; }
        .checkbox-block label { display: flex; align-items: flex-start; margin: 0; font-weight: 500; color: #4a5568; }

        footer { background: white; color: #718096; padding: 40px 20px 20px; margin-top: 40px; border-top: 1px solid #edf2f7; }
        .footer-content { max-width: 1100px; margin: 0 auto; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 32px; }
        .footer-col h4 { color: #1a202c; margin-bottom: 16px; font-size: 15px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 800; }
        .footer-col a { display: block; color: #718096; text-decoration: none; padding: 6px 0; font-size: 14px; transition: color 0.2s; }
        .footer-col a:hover { color: #2563eb; }
        .footer-bottom { max-width: 1100px; margin: 32px auto 0; padding-top: 24px; border-top: 1px solid #edf2f7; text-align: center; font-size: 13px; color: #a0aec0; }

        @media (max-width: 600px) {
          header { padding: 14px 16px; }
          .header-content { flex-direction: column; text-align: center; }
          nav { justify-content: center; margin-top: 10px; }
          main { padding: 16px 12px; }
          .card { padding: 20px 16px; }
          h1 { font-size: 24px; } h2 { font-size: 20px; } h3 { font-size: 16px; }
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
          <div class="footer-col"><h4>TrouveMoi</h4><p style="color:#718096;font-size:14px">La plateforme beninoise de mise en relation.</p></div>
          
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
            <a href="/conditions">Conditions</a>
            <a href="/confidentialite">Confidentialite</a>
          </div>
          
          <div class="footer-col">
            <h4>Suivez-nous</h4>
            <a href="https://www.facebook.com/TrouveMoi.bj" target="_blank" style="display:flex; align-items:center; gap:8px;">
              <span style="font-size:18px;">🔵</span> Page Facebook
            </a>
          </div>

          <div class="footer-col">
            <h4>Contact</h4>
            <a href="/contact">Nous ecrire</a>
            <a href="mailto:contact@trouvemoi.bj">contact@trouvemoi.bj</a>
          </div>
        </div>
        <div class="footer-bottom">&copy; ${new Date().getFullYear()} TrouveMoi. Tous droits reserves.</div>
      </footer>

      <!-- ✅ AJOUT : Modale de Zoom pour l'Admin -->
      <div id="image-modal" style="display:none; position:fixed; z-index:9999; padding-top:50px; left:0; top:0; width:100%; height:100%; overflow:auto; background-color:rgba(0,0,0,0.9); cursor:zoom-out;" onclick="this.style.display='none'">
        <span style="position:absolute; top:15px; right:35px; color:#fff; font-size:40px; font-weight:bold; cursor:pointer;" onclick="document.getElementById('image-modal').style.display='none'">&times;</span>
        <img id="modal-img" style="margin: auto; display: block; max-width: 90%; max-height: 90vh; border-radius: 20px; box-shadow: 0 0 20px rgba(255,255,255,0.2);">
      </div>

      <script>
        function zoomImage(src) {
          document.getElementById('image-modal').style.display = 'block';
          document.getElementById('modal-img').src = src;
        }
      </script>
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

// ✅ Générateur de boutons de pagination
function renderPagination(currentPage, totalPages, baseUrl, queryParams = {}) {
  if (totalPages <= 1) return "";
  
  const buildUrl = (pageNum) => {
    const params = new URLSearchParams(queryParams);
    params.set("page", pageNum);
    return `${baseUrl}?${params.toString()}`;
  };

  let html = `<div style="display:flex; justify-content:center; align-items:center; gap:15px; margin: 30px 0; flex-wrap: wrap;">`;
  
  if (currentPage > 1) {
    html += `<a href="${buildUrl(currentPage - 1)}" class="button secondary" style="margin:0">← Précédent</a>`;
  } else {
    html += `<span class="button secondary" style="margin:0; opacity:0.5; cursor:not-allowed;">← Précédent</span>`;
  }

  html += `<span style="font-weight:bold; color:#4a5568;">Page ${currentPage} sur ${totalPages}</span>`;

  if (currentPage < totalPages) {
    html += `<a href="${buildUrl(currentPage + 1)}" class="button secondary" style="margin:0">Suivant →</a>`;
  } else {
    html += `<span class="button secondary" style="margin:0; opacity:0.5; cursor:not-allowed;">Suivant →</span>`;
  }

  html += `</div>`;
  return html;
}
/* PAGE D'ACCUEIL (Design C'CHAP avec Image de fond) */

app.get("/", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const profession = String(req.query.profession || "").trim().slice(0, 150);
    const city = String(req.query.city || "").trim().slice(0, 100);
    const neighborhood = String(req.query.neighborhood || "").trim().slice(0, 150);
    
    const currentPage = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 12;
    const offset = (currentPage - 1) * limit;

    const citiesResult = await pool.query("SELECT id, name FROM cities ORDER BY display_order ASC");
    const professionsResult = await pool.query("SELECT id, name, category FROM professions ORDER BY display_order ASC");
    const allNeighborhoodsResult = await pool.query(`SELECT name FROM neighborhoods ORDER BY name ASC`);

    let whereClause = ` WHERE p.status = 'approved'`;
    const values = [];
    
    if (profession) { values.push(`%${profession}%`); whereClause += ` AND p.profession ILIKE $${values.length}`; }
    if (city) { values.push(`%${city}%`); whereClause += ` AND p.city ILIKE $${values.length}`; }
    if (neighborhood) { values.push(`%${neighborhood}%`); whereClause += ` AND p.neighborhood ILIKE $${values.length}`; }

    const countResult = await pool.query(`SELECT COUNT(*) FROM professional_applications p ${whereClause}`, values);
    const totalPros = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalPros / limit);

    const queryValues = [...values, limit, offset];
    const query = `
      SELECT p.id, p.full_name, p.company_name, p.phone, p.phone_public, p.city, p.neighborhood,
        p.profession, p.experience, p.service_description, p.service_area, p.availability, p.photo_activite_url,
        (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count,
        (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating
      FROM professional_applications p 
      ${whereClause}
      ORDER BY p.created_at DESC 
      LIMIT $${queryValues.length - 1} OFFSET $${queryValues.length}
    `;
    const result = await pool.query(query, queryValues);

    // Préparation des Datalists
    const cityOptions = citiesResult.rows.map((c) => `<option value="${escapeHtml(c.name)}">`).join("");
    const neighborhoodOptions = allNeighborhoodsResult.rows.map((n) => `<option value="${escapeHtml(n.name)}">`).join("");
    
    const professionsByCategory = {};
    for (const p of professionsResult.rows) {
      const cat = p.category || "Autres";
      if (!professionsByCategory[cat]) professionsByCategory[cat] = [];
      professionsByCategory[cat].push(p.name);
    }
    const professionOptions = Object.values(professionsByCategory).flat().map((name) => `<option value="${escapeHtml(name)}">`).join("");

    const prosCards = result.rows.map((person) => {
      const displayName = getDisplayName(person);
      const reviewsCount = Number(person.reviews_count || 0);
      const avgRating = Number(person.avg_rating || 0);
      const photoHtml = person.photo_activite_url ? `<img src="${escapeHtml(person.photo_activite_url)}" alt="${escapeHtml(person.profession)}">` : `<div class="pro-card-image-placeholder">👤</div>`;
      
      let ratingHtml = reviewsCount > 0 
        ? `<div class="pro-card-rating">${renderStars(avgRating)}<span class="reviews-count">${avgRating.toFixed(1)} (${reviewsCount} avis)</span></div>`
        : `<div class="pro-card-rating"><span class="no-rating">Pas encore d'avis</span></div>`;

      return `
        <article class="pro-card">
          <div class="pro-card-image">${photoHtml}</div>
          <div class="pro-card-body">
            <div class="pro-card-profession">${escapeHtml(person.profession)}</div>
            <div class="pro-card-name">${escapeHtml(displayName)}</div>
            <div class="pro-card-location">${escapeHtml(person.city)}${person.neighborhood ? ` - ${escapeHtml(person.neighborhood)}` : ""}</div>
            <div style="margin-bottom:12px">${renderKycBadge()}</div>
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

    const prosSection = result.rows.length > 0 ? `<div class="pros-grid">${prosCards}</div>` : `<section class="card"><p style="text-align:center;">Aucun professionnel ne correspond à votre recherche.</p></section>`;
    const paginationHtml = renderPagination(currentPage, totalPages, "/", { profession, city, neighborhood });

    // ✅ L'INTERFACE D'ACCUEIL AVEC IMAGE DE FOND
    const content = `
      ${welcomeBanner}
      
      <div style="position: relative; text-align: center; padding: 80px 20px; margin-bottom: 40px; border-radius: 30px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.1);">
        
        <!-- L'IMAGE DE FOND -->
        <div style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; background-image: url('https://images.unsplash.com/photo-1504917595217-d4bf401fa381?q=80&w=2070&auto=format&fit=crop'); background-size: cover; background-position: center; z-index: 1;"></div>
        
        <!-- LE VOILE BLEU (pour la lisibilité) -->
        <div style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; background: linear-gradient(135deg, rgba(30,64,175,0.85) 0%, rgba(37,99,235,0.75) 100%); z-index: 2;"></div>

        <!-- LE CONTENU -->
        <div style="position: relative; z-index: 3; max-width: 800px; margin: 0 auto;">
          <h1 style="font-size: 38px; font-weight: 800; color: white; margin-bottom: 15px; line-height: 1.2; text-shadow: 0 2px 4px rgba(0,0,0,0.3);">
            Trouve ce dont tu as besoin,<br><span style="color: #fbbf24;">près de toi.</span>
          </h1>
          <p style="font-size: 18px; color: rgba(255,255,255,0.95); margin-bottom: 35px; text-shadow: 0 1px 3px rgba(0,0,0,0.3);">Des professionnels vérifiés au Bénin, en 1 clic.</p>

          <form action="/" method="GET" style="background: white; padding: 10px; border-radius: 60px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); display: flex; flex-wrap: wrap; gap: 10px; align-items: center;">
            
            <input id="profession" name="profession" list="list-professions" value="${escapeHtml(profession)}" placeholder="Ex. Plombier, Coiffeuse..." style="flex: 2 1 200px; border: none; background: transparent; margin: 0; padding: 15px 20px; box-shadow: none; font-size: 16px; border-radius: 50px;">
            <datalist id="list-professions">${professionOptions}</datalist>

            <input id="city" name="city" list="list-cities" value="${escapeHtml(city)}" placeholder="Ville (ex: Cotonou)" style="flex: 1 1 150px; border: none; border-left: 1px solid #e2e8f0; background: transparent; margin: 0; padding: 15px 20px; box-shadow: none; font-size: 16px; border-radius: 50px;">
            <datalist id="list-cities">${cityOptions}</datalist>
            
            <input type="hidden" name="neighborhood" value="${escapeHtml(neighborhood)}">

            <button type="submit" style="border-radius: 50px; padding: 16px 36px; margin: 0; background: #ff8c00; flex: 0 0 auto; font-size: 16px; font-weight: 700; box-shadow: 0 4px 12px rgba(255,140,0,0.4); color: white;">Rechercher</button>
          </form>
          <p style="font-size: 14px; color: rgba(255,255,255,0.8); margin-top: 15px;">Ex. coiffeuse, restaurant, plombier...</p>
        </div>
      </div>

      <div style="display: flex; justify-content: center; gap: 15px; flex-wrap: wrap; margin-bottom: 40px;">
        <a class="button" href="/devenir-professionnel" style="background: white; color: #1e40af; border: 2px solid #1e40af; padding: 14px 30px;">Devenir professionnel</a>
        <a class="button" href="/emplois" style="background: #f8f9fa; color: #4a5568; border: 2px solid #cbd5e0; padding: 14px 30px;">Consulter les offres d'emploi</a>
      </div>

      <div class="alert alert-warning" style="max-width: 800px; margin: 0 auto 40px auto; text-align: center;">
        <strong>⚠️ ATTENTION :</strong> Ne payez jamais un professionnel avant de l'avoir rencontré en personne.
      </div>

      <h2 style="text-align: center; margin-bottom: 20px;">Professionnels disponibles (${totalPros})</h2>
      ${prosSection}
      ${paginationHtml}
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
    
    const baseUrl = `${req.protocol}://${req.get("host")}`;
    const shareText = encodeURIComponent("Decouvrez " + displayName + " (" + person.profession + ") sur TrouveMoi");
    const shareUrl = encodeURIComponent(`${baseUrl}/pro/${person.id}`);

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
      : `<div class="rating-large" style="color:#a0aec0;font-size:16px;letter-spacing:0">Pas encore d'avis</div>`;

    let ratingSummary = reviewsCount > 0 
      ? `<div class="rating-summary"><div class="rating-big-number">${avgRating.toFixed(1)}</div><div class="rating-details"><div class="stars">${renderStars(avgRating)}</div><div class="count">Base sur ${reviewsCount} avis</div></div></div>` 
      : "";

    const reviewsHtml = reviews.map((rev) => {
      const dateStr = new Date(rev.created_at).toLocaleDateString("fr-FR");
      return `<div class="review-item"><div class="review-header"><div class="review-author">${escapeHtml(rev.author_name)}</div><div class="review-stars">${renderStars(rev.rating)}</div></div><div class="review-date">${escapeHtml(dateStr)}</div>${rev.comment ? `<div class="review-comment">${escapeHtml(rev.comment).replace(/\n/g, "<br>")}</div>` : ""}</div>`;
    }).join("");

    const reviewsSection = reviews.length > 0 ? `<section class="card"><h2>Avis des clients (${reviewsCount})</h2>${ratingSummary}${reviewsHtml}</section>` : "";
    const reviewButton = `<section class="card" style="text-align:center"><h3>Vous avez fait appel a ce professionnel ?</h3><a class="button btn-review" href="/pro/${person.id}/avis">⭐ Laisser un avis</a></section>`;

    const content = `
      <div class="pro-header">
        <h1>${escapeHtml(displayName)}</h1>
        <div class="profession">${escapeHtml(person.profession)}</div>
        <div class="location">📍 ${escapeHtml(person.city)}${person.neighborhood ? ` - ${escapeHtml(person.neighborhood)}` : ""}</div>
        <div style="margin-top:16px">${renderKycBadge("lg")}</div>
        ${ratingHeader}
      </div>
      <section class="card">
        ${person.photo_activite_url ? `<div class="photos-grid" style="justify-content:center;"><div class="photo-block"><img src="${escapeHtml(person.photo_activite_url)}" class="photo-activite"></div></div>` : ""}
        <h2>Description des services</h2>
        <p>${escapeHtml(person.service_description).replace(/\n/g, "<br>")}</p>
        ${person.service_area ? `<p><span class="label">Zone d'intervention :</span> ${escapeHtml(person.service_area)}</p>` : ""}
        ${person.availability ? `<p><span class="label">Disponibilite :</span> ${escapeHtml(person.availability)}</p>` : ""}
        ${contactButtons}
        <p style="margin-top:32px; text-align:center;"><a class="button secondary" href="/">← Retour à l'accueil</a></p>
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
      <section class="card" style="max-width: 600px; margin: 0 auto;">
        <h1 style="text-align:center;">Laisser un avis</h1>
        <div class="alert alert-info" style="text-align:center;">⭐ Vous laissez un avis sur <strong>${escapeHtml(displayName)}</strong>.</div>
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
          <div style="text-align:center; margin-top:20px;">
            <button type="submit">Envoyer</button>
            <a class="button secondary" href="/pro/${person.id}">Annuler</a>
          </div>
        </form>
      </section>
    `, proConnected));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

// ✅ Rate Limiting et validation sur les avis
app.post("/pro/:id/avis", async (req, res) => {
  const ip = req.ip || "unknown";
  const now = Date.now();
  const attempts = reviewAttempts.get(ip) || { count: 0, startedAt: now };
  if (now - attempts.startedAt > 60 * 60 * 1000) { attempts.count = 0; attempts.startedAt = now; }
  if (attempts.count >= 5) {
    return res.status(429).send(page("Trop de tentatives", "<section class='card'><h1>⏳ Trop de tentatives</h1><p>Vous avez envoyé trop d'avis récemment. Veuillez patienter 1 heure avant de réessayer.</p><a class='button' href='/'>Accueil</a></section>", null));
  }
  attempts.count++;
  reviewAttempts.set(ip, attempts);

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
    res.send(page("Succes", "<section class='card' style='text-align:center;'><h1>Merci !</h1><p>Votre avis sera examine.</p><a class='button' href='/'>Retour</a></section>", null));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

/* PAGE EMPLOIS */

app.get("/emplois", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const keyword = String(req.query.keyword || "").trim();
  const city = String(req.query.city || "").trim();
  
  const currentPage = Math.max(1, parseInt(req.query.page) || 1);
  const limit = 10;
  const offset = (currentPage - 1) * limit;

  let whereClause = ` WHERE status = 'approved' AND (expires_at IS NULL OR expires_at > NOW())`;
  const values = [];
  if (keyword) { values.push(`%${keyword}%`); whereClause += ` AND (job_title ILIKE $${values.length} OR company_name ILIKE $${values.length})`; }
  if (city) { values.push(`%${city}%`); whereClause += ` AND city ILIKE $${values.length}`; }

  const countResult = await pool.query(`SELECT COUNT(*) FROM job_offers ${whereClause}`, values);
  const totalJobs = parseInt(countResult.rows[0].count);
  const totalPages = Math.ceil(totalJobs / limit);

  const queryValues = [...values, limit, offset];
  const query = `SELECT * FROM job_offers ${whereClause} ORDER BY created_at DESC LIMIT $${queryValues.length - 1} OFFSET $${queryValues.length}`;
  const result = await pool.query(query, queryValues);

  const jobs = result.rows.map((job) => `
    <article class="card">
      <h2 style="color:#2563eb;">${escapeHtml(job.job_title)}</h2>
      <p><span class="label">Entreprise :</span> ${escapeHtml(job.company_name)}</p>
      <p><span class="label">Ville :</span> ${escapeHtml(job.city)}</p>
      <p><span class="label">Contrat :</span> <span class="badge badge-processed">${escapeHtml(job.contract_type)}</span></p>
      <p style="margin-top:16px;">${escapeHtml(job.description).replace(/\n/g, "<br>")}</p>
      ${jobContactButtons(job)}
    </article>
  `).join("");

  const alerteEmploi = `
    <div class="alert alert-warning" style="max-width: 800px; margin: 0 auto 30px auto; text-align:center;">
      <strong>⚠️ RAPPEL :</strong> Si un recruteur vous demande de l'argent avant l'entretien, veuillez signaler ce recruteur en nous envoyant un message via la page <strong>Contact</strong>.
    </div>
  `;
  
  const paginationHtml = renderPagination(currentPage, totalPages, "/emplois", { keyword, city });

  res.send(page("Emploi", `
    <h1 style="text-align: center; margin-bottom: 30px;">Offres d'emploi</h1>
    ${alerteEmploi}
    <section class="card" style="max-width: 800px; margin: 0 auto 30px auto;">
      <form action="/emplois" method="GET" style="display:flex; gap:10px; flex-wrap:wrap;">
        <input name="keyword" value="${escapeHtml(keyword)}" placeholder="Mot clé (ex: Développeur)" style="flex:1 1 200px; margin:0;">
        <input name="city" value="${escapeHtml(city)}" placeholder="Ville (ex: Cotonou)" style="flex:1 1 200px; margin:0;">
        <button style="margin:0; padding:14px 30px;">Rechercher</button>
      </form>
      <div style="text-align: center; margin-top: 20px;">
        <a class="button" href="/publier-emploi" style="background: #38a169;">Publier une offre</a>
      </div>
    </section>
    <h2 style="text-align: center; margin-bottom: 20px;">Résultats (${totalJobs})</h2>
    ${jobs || `<section class="card"><p style="text-align:center;">Aucune offre disponible pour le moment.</p></section>`}
    ${paginationHtml}
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
      <section class="card" style="max-width: 800px; margin: 0 auto;">
        <h1 style="text-align: center; margin-bottom: 24px;">Devenir professionnel</h1>
        <p style="text-align: center; color: #718096; margin-bottom: 32px;">Remplissez le formulaire. Votre profil sera vérifié avant publication.</p>

        <form action="/candidatures" method="POST" enctype="multipart/form-data">
          
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div>
              <label for="full_name">Nom et prenoms *</label>
              <input id="full_name" name="full_name" required maxlength="150" placeholder="Ex: Jean Dupont">
            </div>
            <div>
              <label for="company_name">Nom de la societe (facultatif)</label>
              <input id="company_name" name="company_name" maxlength="200" placeholder="Ex: Dupont BTP">
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div>
              <label for="phone">Telephone *</label>
              <input id="phone" name="phone" type="tel" required maxlength="30" placeholder="+229 01 97 00 00 00">
            </div>
            <div>
              <label for="npi">Numéro Personnel d'Identification (NPI) *</label>
              <input id="npi" name="npi" required maxlength="15" placeholder="Ex: 1234567890">
            </div>
          </div>
          <p class="help-text" style="margin-top: -10px; margin-bottom: 20px; color: #e53e3e;">Le NPI est obligatoire pour vérifier votre identité et garantir la sécurité de la plateforme (évite les doublons).</p>

          <div class="checkbox-block">
            <label>
              <input type="checkbox" name="phone_public" value="yes" checked>
              <span><strong>J'accepte que mon numero soit visible publiquement sur mon profil</strong></span>
            </label>
          </div>

          <h3 style="margin-top: 30px;">Comment souhaitez-vous recevoir votre code ? *</h3>
          <div class="checkbox-block">
            <label><input type="radio" name="contact_preference" value="whatsapp" required> <span><strong>📱 Par WhatsApp</strong></span></label>
            <div id="whatsapp-number-block" class="hidden" style="margin-top:12px;margin-left:30px">
              <label for="whatsapp_number">Numero WhatsApp (Format : +229 01...)</label>
              <input id="whatsapp_number" name="whatsapp_number" type="tel" maxlength="30" placeholder="+229 01 97 00 00 00">
            </div>
          </div>
          <div class="checkbox-block">
            <label><input type="radio" name="contact_preference" value="email" required> <span><strong>✉️ Par email</strong></span></label>
            <div id="email-block" class="hidden" style="margin-top:12px;margin-left:30px">
              <label for="contact_email">Adresse email *</label>
              <input id="contact_email" name="contact_email" type="email" maxlength="254" placeholder="Ex: contact@email.com">
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">
            <div>
              <label for="city">Ville *</label>
              <select id="city" name="city" required>
                <option value="">Choisissez votre ville</option>
                ${cityOptions}
              </select>
            </div>
            <div>
              <label for="neighborhood">Quartier</label>
              <select id="neighborhood" name="neighborhood"><option value="">Choisissez d'abord une ville</option></select>
              <div id="neighborhood-other-block" class="hidden" style="margin-top:10px;">
                <input id="neighborhood_other" name="neighborhood_other" maxlength="150" placeholder="Precisez votre quartier">
              </div>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div>
              <label for="profession">Profession *</label>
              <select id="profession" name="profession" required>
                <option value="">Choisissez un metier</option>
                ${professionOptions}
                <option value="__AUTRE__">Autre (precisez)</option>
              </select>
              <div id="profession-other-block" class="hidden" style="margin-top:10px;">
                <input id="profession_other" name="profession_other" maxlength="150" placeholder="Precisez votre metier">
              </div>
            </div>
            <div>
              <label for="experience">Experience</label>
              <select id="experience" name="experience">
                <option value="">Selectionnez</option>
                <option value="Debutant">Debutant</option>
                <option value="Moins de 2 ans">Moins de 2 ans</option>
                <option value="2 a 5 ans">2 a 5 ans</option>
                <option value="Plus de 5 ans">Plus de 5 ans</option>
              </select>
            </div>
          </div>

          <label for="service_description">Description de vos services *</label>
          <textarea id="service_description" name="service_description" rows="4" required maxlength="3000" placeholder="Decrivez ce que vous faites, vos specialites..."></textarea>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div>
              <label for="service_area">Zones d'intervention</label>
              <input id="service_area" name="service_area" maxlength="300" placeholder="Ex: Cotonou et environs">
            </div>
            <div>
              <label for="availability">Disponibilite</label>
              <select id="availability" name="availability">
                <option value="">Selectionnez</option>
                <option value="Disponible immediatement">Disponible immediatement</option>
                <option value="Sur rendez-vous">Sur rendez-vous</option>
                <option value="A temps partiel">A temps partiel</option>
              </select>
            </div>
          </div>

          <hr style="margin:32px 0;border:none;border-top:1px solid #e2e8f0">
          
          <h3>Photos obligatoires (KYC)</h3>
          <p class="help-text">Formats : JPG, PNG, WEBP. Max : 5 Mo par photo.</p>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div>
              <label for="photo_profil">1. Photo de profil *</label>
              <input id="photo_profil" name="photo_profil" type="file" accept="image/*" required>
            </div>
            <div>
              <label for="photo_identite">2. Piece d'identite (recto) *</label>
              <input id="photo_identite" name="photo_identite" type="file" accept="image/*" required>
            </div>
          </div>

          <label for="photo_kyc" style="margin-top:16px;">3. Photo de verification (Vous tenant votre piece d'identite) *</label>
          <div style="background:#f8f9fa; padding:15px; border-radius:16px; margin-bottom:15px; border:1px dashed #cbd5e0; text-align:center;">
            <p style="font-size:13px; margin-bottom:10px; color:#4a5568;"><strong>Exemple :</strong> Prenez une photo de vous, de face, en tenant votre pièce à côté de votre visage. Sans lunettes ni chapeau.</p>
            <img src="https://res.cloudinary.com/gxm35ndf/image/upload/v1792403314/kyc.jpg" alt="Exemple KYC" style="max-width:160px; border-radius:12px; border:2px solid #e2e8f0;">
          </div>
          <input id="photo_kyc" name="photo_kyc" type="file" accept="image/*" required>

          <label for="photo_activite" style="margin-top:16px;">4. Photo d'activite (publique, optionnelle)</label>
          <input id="photo_activite" name="photo_activite" type="file" accept="image/*">

          <div class="checkbox-block" style="margin-top:24px;">
            <label><input type="checkbox" name="gdpr_consent" value="yes" required> <span>J'accepte la <a href="/confidentialite" target="_blank" style="color:#2563eb;">Politique de confidentialite</a>.</span></label>
          </div>

          <div style="text-align: center; margin-top: 30px;">
            <button type="submit" style="padding: 16px 40px; font-size: 16px;">Envoyer ma candidature</button>
          </div>
        </form>
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

/* ENREGISTREMENT CANDIDATURES (AVEC KYC + NPI + VERIF NUMERO 01) */
app.post("/candidatures", upload.fields([
  { name: "photo_profil", maxCount: 1 },
  { name: "photo_identite", maxCount: 1 },
  { name: "photo_kyc", maxCount: 1 },
  { name: "photo_activite", maxCount: 1 }
]), async (req, res) => {
  const { full_name, company_name, phone, npi, phone_public, city, neighborhood, neighborhood_other, profession, profession_other, experience, service_description, service_area, availability, gdpr_consent, contact_preference, whatsapp_number, contact_email } = req.body;

  if (gdpr_consent !== "yes") return res.status(400).send(page("Erreur", "<h2>Consentement RGPD obligatoire.</h2>", null));

  // ✅ VÉRIFICATION STRICTE DU NUMÉRO BÉNINOIS (10 chiffres avec 01 OBLIGATOIRE)
  const cleanPhone = String(phone || "").replace(/[\s().-]/g, "");
  const beninPhoneRegex = /^(?:\+?229|00229)?01[45679]\d{7}$/;

  if (!beninPhoneRegex.test(cleanPhone)) {
    return res.status(400).send(page("Erreur", `
      <section class="card" style="max-width: 600px; margin: 40px auto; text-align: center;">
        <h1 style="color:#e53e3e; justify-content: center;">⚠️ Numéro invalide</h1>
        <p>Pour être sur TrouveMoi, vous devez obligatoirement utiliser un numéro de téléphone béninois au <strong>nouveau format (10 chiffres)</strong>.</p>
        <p>Exemple de format attendu : <strong>+229 01 XX XX XX XX</strong> ou <strong>01 XX XX XX XX</strong>.</p>
        <div class="actions" style="justify-content: center; margin-top:20px;">
          <a class="button" href="/devenir-professionnel">Réessayer</a>
          <a class="button secondary" href="/contact">Contacter le support</a>
        </div>
      </section>
    `, null));
  }

  if (whatsapp_number) {
    const cleanWa = String(whatsapp_number).replace(/[\s().-]/g, "");
    if (!beninPhoneRegex.test(cleanWa)) {
      return res.status(400).send(page("Erreur", `
        <section class="card" style="max-width: 600px; margin: 40px auto; text-align: center;">
          <h1 style="color:#e53e3e; justify-content: center;">⚠️ Numéro WhatsApp invalide</h1>
          <p>Le numéro WhatsApp doit aussi être au nouveau format béninois (01 + 8 chiffres).</p>
          <a class="button" href="/devenir-professionnel" style="margin-top:20px;">Réessayer</a>
        </section>
      `, null));
    }
  }

  // ✅ VÉRIFICATION DU NPI
  const safeNpi = String(npi || "").trim();
  if (safeNpi.length < 8) {
    return res.status(400).send(page("Erreur", "<h2>Le NPI est obligatoire et doit être valide (au moins 8 caractères).</h2>", null));
  }

  // ✅ DÉTECTION DE DOUBLON SÉCURISÉE (Par Téléphone OU par NPI)
  const safeName = String(full_name || "").trim().toLowerCase();
  const safeCompany = String(company_name || "").trim().toLowerCase();
  const safePhone = String(phone || "").replace(/[()\s.-]/g, "");

  try {
    const duplicateCheck = await pool.query(
      `SELECT id FROM professional_applications 
       WHERE (
         REGEXP_REPLACE(phone, '[()\\s.-]', '', 'g') = $1 
         OR npi = $2
       )
       AND status IN ('pending', 'under_review', 'approved', 'corrections_requested')`,
      [safePhone, safeNpi]
    );

    if (duplicateCheck.rows.length > 0) {
      return res.status(409).send(page("Inscription impossible", `
        <section class="card" style="max-width: 600px; margin: 40px auto; text-align: center;">
          <h1 style="color:#e53e3e; justify-content: center;">⚠️ Inscription impossible</h1>
          <p><strong>Un dossier existe déjà avec ce numéro de téléphone ou ce NPI.</strong></p>
          <p>Si vous ne vous êtes jamais enregistré sur cette plateforme, veuillez nous contacter directement pour plus d'assistance.</p>
          <div class="actions" style="justify-content: center; margin-top:20px;">
            <a class="button" href="/contact">📩 Nous contacter</a>
            <a class="button secondary" href="/">Retour à l'accueil</a>
          </div>
        </section>
      `, null));
    }
  } catch (dbError) {
    console.error("Erreur vérification doublon :", dbError.message);
  }

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

    const trackingCode = `SUIVI-${crypto.randomInt(1000, 10000)}`;

    // ✅ INSERTION AVEC LE NPI ($12)
    const result = await pool.query(`
      INSERT INTO professional_applications (
        full_name, company_name, phone, phone_public, city, neighborhood, profession,
        experience, service_description, service_area, availability, npi,
        photo_profil_url, photo_identite_url, photo_kyc_url, photo_activite_url,
        contact_preference, whatsapp_number, contact_email, pro_code, tracking_code, status
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,NULL,$20,'pending')
      RETURNING id
    `, [full_name, finalCompanyName, phone, phoneIsPublic, city, finalNeighborhood, finalProfession, experience, service_description, service_area, availability, safeNpi, profilResult.secure_url, identiteResult.secure_url, kycResult.secure_url, photoActiviteUrl, pref, whatsapp_number, contact_email, trackingCode]);

    res.send(page("Candidature envoyee", `
      <section class="card" style="max-width: 600px; margin: 40px auto; text-align: center;">
        <h1 style="color:#38a169; justify-content: center;">Succès !</h1>
        <p>Votre candidature est en attente d'examen.</p>
        <div class="alert alert-info" style="margin-top:20px;">
          <strong>Votre code de suivi est : <span style="font-size:24px; font-family:monospace; font-weight:bold;">${escapeHtml(trackingCode)}</span></strong>
          <p style="margin-top:10px">Notez ce code précieusement. Il vous permettra de suivre l'état de votre dossier.</p>
          <a class="button" href="/suivi-dossier" style="margin-top:10px;">Suivre mon dossier</a>
        </div>
        <a class="button secondary" href="/" style="margin-top:20px;">Retour a l'accueil</a>
      </section>
    `, null));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Impossible d'enregistrer.</h2>", null)); }
});
/* SUIVI DE DOSSIER (POUR LES CORRECTIONS) */

app.get("/suivi-dossier", (req, res) => {
  res.send(page("Suivi de dossier", `
    <section class="card" style="max-width: 500px; margin: 40px auto;">
      <h1 style="text-align: center; margin-bottom: 24px;">Suivre mon dossier</h1>
      <p style="text-align: center; color: #718096; margin-bottom: 24px;">Entrez le code de suivi reçu lors de votre inscription.</p>
      <form action="/suivi-dossier" method="POST">
        <label>Code de suivi (ex: SUIVI-1234) *</label>
        <input name="tracking_code" required placeholder="SUIVI-XXXX" maxlength="20" style="text-transform:uppercase; text-align:center; font-size:20px; font-weight:bold;">
        <button type="submit" style="width: 100%; margin-top:10px;">Voir mon dossier</button>
      </form>
    </section>
  `, null));
});

app.post("/suivi-dossier", async (req, res) => {
  const ip = req.ip || "unknown";
  const now = Date.now();
  const attempts = trackingAttempts.get(ip) || { count: 0, startedAt: now };
  if (now - attempts.startedAt > 15 * 60 * 1000) { attempts.count = 0; attempts.startedAt = now; }
  if (attempts.count >= 10) {
    return res.status(429).send(page("Trop de tentatives", 
      "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>⏳ Trop de tentatives</h1><p>Veuillez patienter 15 minutes avant de réessayer.</p></section>", 
      null));
  }
  attempts.count++;
  trackingAttempts.set(ip, attempts);

  try {
    const code = String(req.body.tracking_code || "").trim().toUpperCase();
    if (!code) return res.redirect(303, "/suivi-dossier");
    
    const result = await pool.query(`SELECT * FROM professional_applications WHERE tracking_code = $1`, [code]);
    
    if (!result.rows.length) {
      return res.send(page("Erreur", `<section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;"><h2>Code introuvable.</h2><a href="/suivi-dossier" class="button">Réessayer</a></section>`, null));
    }
    const pro = result.rows[0];

    let statusHtml = "";
    if (pro.status === 'pending') statusHtml = `<div class="alert alert-info" style="text-align:center;">⏳ Votre dossier est en cours d'examen.</div>`;
    else if (pro.status === 'approved') {
      statusHtml = `
        <div class="alert alert-success" style="text-align:center;">
          ✅ Votre dossier a été approuvé !<br><br>
          <strong>Votre code professionnel est : <span style="font-size:24px; font-family:monospace;">${escapeHtml(pro.pro_code)}</span></strong><br><br>
          Vous pouvez vous connecter sur votre espace pro avec ce code.
          <div style="margin-top:20px;"><a class="button success" href="/mon-espace-pro">Se connecter à mon espace pro</a></div>
        </div>
      `;
    }
    else if (pro.status === 'rejected') statusHtml = `<div class="alert alert-danger" style="text-align:center;">❌ Votre dossier a été refusé. Motif : ${escapeHtml(pro.rejection_reason || "Non spécifié")}</div>`;
    else if (pro.status === 'corrections_requested') {
      statusHtml = `
        <div class="alert alert-warning">
          <h3 style="margin-top:0">⚠️ Corrections demandées</h3>
          <p><strong>Motif :</strong> ${escapeHtml(pro.rejection_reason)}</p>
          <p>Veuillez corriger votre dossier et le renvoyer.</p>
          <button onclick="document.getElementById('form-correct').classList.remove('hidden')" style="margin-top:10px; background: #ed8936;">Corriger mon dossier</button>
        </div>
        <div id="form-correct" class="hidden" style="margin-top:20px">
          <form action="/candidatures/${pro.id}/corriger" method="POST" enctype="multipart/form-data" style="background:#f8f9fa; padding:20px; border-radius:20px;">
            <input type="hidden" name="tracking_code" value="${escapeHtml(pro.tracking_code)}">
            
            <div class="alert alert-info" style="padding:12px; font-size:14px; margin-bottom:20px;">
              <strong>Instruction :</strong> Veuillez renvoyer uniquement la ou les photos qui posent problème selon le motif ci-dessus. Si une photo était déjà valide, vous n'avez pas besoin de la renvoyer.
            </div>

            <label>Nouvelle photo d'identité (si concernée)</label>
            <input type="file" name="photo_identite" accept="image/*">
            
            <label>Nouvelle photo de vérification KYC (si concernée)</label>
            <input type="file" name="photo_kyc" accept="image/*">
            
            <button type="submit" class="success" style="width:100%; margin-top:10px;">Renvoyer pour validation</button>
          </form>
        </div>
      `;
    }

    res.send(page("Mon dossier", `
      <section class="card" style="max-width: 600px; margin: 40px auto;">
        <h1 style="text-align:center;">Dossier de ${escapeHtml(pro.full_name)}</h1>
        ${statusHtml}
        <p style="text-align:center; margin-top:30px;"><a href="/suivi-dossier" style="color:#718096; text-decoration:underline;">← Retour</a></p>
      </section>
    `, null));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

// ✅ Vérification du tracking_code pour éviter l'usurpation
app.post("/candidatures/:id/corriger", upload.fields([{ name: "photo_identite", maxCount: 1 }, { name: "photo_kyc", maxCount: 1 }]), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).send(page("Erreur", "<h2>ID invalide.</h2>", null));
  
  const files = req.files || {};
  const trackingCode = String(req.body.tracking_code || "").trim().toUpperCase();
  
  try {
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
    res.send(page("Succes", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>Dossier mis à jour !</h1><p>Il est de nouveau en attente d'examen.</p><a href='/' class='button'>Accueil</a></section>", null));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

/* ESPACE PRO */

app.get("/mon-espace-pro", async (req, res) => {
  const proConnected = await getConnectedPro(req);

  if (!proConnected) {
    return res.send(page("Espace pro", `
      <section class="card" style="max-width: 500px; margin: 40px auto;">
        <h1 style="text-align: center;">Espace professionnel</h1>
        <p style="text-align: center; color:#718096; margin-bottom:24px;">Connectez-vous avec votre code professionnel.</p>
        <form action="/mon-espace-pro/login" method="POST">
          <label for="pro_code">Code professionnel</label>
          <input id="pro_code" name="pro_code" required maxlength="10" placeholder="TM12345" style="text-transform:uppercase; text-align:center; font-size:20px; font-weight:bold;">
          <button type="submit" style="width: 100%;">Se connecter</button>
        </form>
        <div style="text-align:center; margin-top:20px; font-size:14px;">
          <p style="margin-bottom:8px;"><a href="/suivi-dossier" style="color:#2563eb;">Mon dossier est en attente ? Suivre mon dossier</a></p>
          <p><a href="/mon-espace-pro/reinitialiser" style="color:#e53e3e;">🔐 Mon code a fuité / Je l'ai perdu</a></p>
        </div>
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
      <article class="card" style="box-shadow:none; border:1px solid #edf2f7; margin-bottom:16px;">
        <h2 style="font-size:18px;">${escapeHtml(offer.job_title)}</h2>
        <p style="margin-bottom:12px;">
          <span class="badge badge-${offer.status}">${escapeHtml(statusLabel)}</span> 
          ${isPublic ? `<span class="badge badge-approved">En ligne</span>` : ""} 
          ${expired ? `<span class="badge badge-rejected">Expiree</span>` : ""}
        </p>
        <p class="muted" style="font-size:14px; margin-bottom:4px;"><strong>Entreprise :</strong> ${escapeHtml(offer.company_name)}</p>
        <p class="muted" style="font-size:14px; margin-bottom:4px;"><strong>Ville :</strong> ${escapeHtml(offer.city)}</p>
        ${offer.expires_at ? `<p class="muted" style="font-size:13px;">Expire le : ${new Date(offer.expires_at).toLocaleDateString("fr-FR")}</p>` : ""}
        
        <div class="actions" style="margin-top:16px;">
          ${offer.status === "approved" && !expired ? `<form action="/mon-espace-pro/offre/${offer.id}/close" method="POST" style="display:inline"><button class="warning" type="submit" style="padding:8px 16px; font-size:13px;">🔒 Cloturer</button></form>` : ""}
          ${offer.status === "closed" ? `<form action="/mon-espace-pro/offre/${offer.id}/reopen" method="POST" style="display:inline"><button class="success" type="submit" style="padding:8px 16px; font-size:13px;">🔓 Rouvrir</button></form>` : ""}
          ${offer.status === "approved" && !expired ? `<form action="/mon-espace-pro/offre/${offer.id}/renew" method="POST" style="display:inline"><button class="secondary" type="submit" style="padding:8px 16px; font-size:13px;">🔄 Prolonger ${OFFER_DURATION_DAYS}j</button></form>` : ""}
        </div>
      </article>
    `;
  }).join("");

  const gdprHtml = gdprRequests.map((req) => `
    <article class="card" style="padding:16px; box-shadow:none; border:1px solid #edf2f7; margin-bottom:10px;">
      <p style="margin:0;"><span class="badge badge-${req.status}">${escapeHtml(GDPR_STATUS_LABELS[req.status])}</span> <strong>${escapeHtml(GDPR_TYPE_LABELS[req.request_type])}</strong></p>
      <p class="muted" style="font-size:12px; margin-top:4px;">Demande le : ${new Date(req.created_at).toLocaleString("fr-FR")}</p>
    </article>
  `).join("");

  const myReviewsHtml = myReviews.map((rev) => `
    <div class="review-item">
      <div class="review-header">
        <div class="review-author">${escapeHtml(rev.author_name)}</div>
        <div><span class="badge badge-${rev.status}">${escapeHtml(REVIEW_STATUS_LABELS[rev.status])}</span></div>
      </div>
      <div class="review-stars">${renderStars(rev.rating)}</div>
      ${rev.comment ? `<div class="review-comment">${escapeHtml(rev.comment)}</div>` : ""}
    </div>
  `).join("");

  const phoneStatus = proConnected.pro.phone_public ? `<span class="badge badge-approved">Public</span>` : `<span class="badge badge-closed">Privé</span>`;
  
  let contactInfoBlock = "";
  if (proConnected.pro.contact_preference === "whatsapp" && proConnected.pro.whatsapp_number) contactInfoBlock = `<p style="margin-bottom:4px;"><span class="label">Reception code :</span> WhatsApp (${escapeHtml(proConnected.pro.whatsapp_number)})</p>`;
  else if (proConnected.pro.contact_preference === "email" && proConnected.pro.contact_email) contactInfoBlock = `<p style="margin-bottom:4px;"><span class="label">Reception code :</span> Email (${escapeHtml(proConnected.pro.contact_email)})</p>`;
  
  const companyBlock = proConnected.pro.company_name ? `<p style="margin-bottom:4px;"><span class="label">Societe :</span> ${escapeHtml(proConnected.pro.company_name)}</p>` : "";
  const displayName = getDisplayName(proConnected.pro);

  res.send(page("Mon espace pro", `
    <div class="pro-welcome" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:20px;">
      <div>
        <h2 style="margin:0;">Bonjour ${escapeHtml(displayName)} 👋</h2>
        <p style="margin:0; margin-top:4px; color:rgba(255,255,255,0.8);">Bienvenue sur votre espace professionnel.</p>
      </div>
      <div class="pro-code-box" style="margin:0; padding:12px 24px; box-shadow:none; background:rgba(255,255,255,0.15); border-radius:16px;">
        <div class="pro-code-label" style="font-size:11px;">Votre code pro</div>
        <div class="pro-code-value" style="font-size:28px; margin:4px 0; letter-spacing:2px;">${escapeHtml(proConnected.code)}</div>
      </div>
    </div>

    <div style="display:flex; gap:10px; margin-bottom:24px; flex-wrap:wrap;">
      <a class="button" href="/publier-emploi">📢 Publier une offre</a>
      <a class="button secondary" href="/">🌐 Voir le site</a>
      <form action="/mon-espace-pro/logout" method="POST" style="display:inline; margin-left:auto;"><button class="danger" type="submit">Deconnexion</button></form>
    </div>

    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap:20px;">
      <section class="card">
        <h2>Mes informations</h2>
        ${companyBlock}
        <p style="margin-bottom:4px;"><span class="label">Nom :</span> ${escapeHtml(proConnected.pro.full_name)}</p>
        <p style="margin-bottom:4px;"><span class="label">Profession :</span> ${escapeHtml(proConnected.pro.profession)}</p>
        <p style="margin-bottom:4px;"><span class="label">Ville :</span> ${escapeHtml(proConnected.pro.city)}</p>
        <p style="margin-bottom:4px;"><span class="label">Telephone :</span> ${escapeHtml(proConnected.pro.phone)}</p>
        <p style="margin-bottom:4px;"><span class="label">Visibilite :</span> ${phoneStatus}</p>
        ${contactInfoBlock}
        <div class="actions" style="margin-top:16px;"><a class="button secondary" href="/mon-espace-pro/modifier-telephone" style="font-size:13px; padding:10px 16px;">Modifier la visibilité</a></div>
      </section>

      <section class="card">
        <h2>Mes avis recus (${myReviews.length})</h2>
        ${myReviewsHtml || `<p class="muted">Aucun avis pour le moment.</p>`}
      </section>
    </div>

    <section class="card" style="margin-top:20px;">
      <h2>Mes offres d'emploi (${offers.length})</h2>
      ${offersHtml || `<p class="muted">Aucune offre publiée.</p><a class="button" href="/publier-emploi" style="margin-top:10px;">Publier ma première offre</a>`}
    </section>

    <section class="card" style="margin-top:20px; background:#f8f9fa; border:1px solid #edf2f7;">
      <h2>Mes droits (RGPD)</h2>
      <div class="actions" style="margin-top:16px;">
        <a class="button secondary" href="/mon-espace-pro/mes-donnees" style="font-size:13px;">📥 Telecharger mes donnees</a>
        <form action="/mon-espace-pro/demande-suppression" method="POST" style="display:inline;"><button class="danger" type="submit" style="font-size:13px;">🗑️ Demander suppression</button></form>
      </div>
      ${gdprHtml ? `<h3 style="margin-top:24px; font-size:16px;">Historique des demandes</h3>${gdprHtml}` : ""}
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

/* ✅ Auto-réinitialisation du code pro par le propriétaire du dossier */
app.get("/mon-espace-pro/reinitialiser", (req, res) => {
  res.send(page("Réinitialiser mon code", `
    <section class="card" style="max-width: 500px; margin: 40px auto;">
      <h1 style="text-align:center;">🔐 Réinitialiser mon code</h1>
      <p style="text-align: center; color:#718096; margin-bottom:24px;">Entrez votre <strong>code de suivi</strong> (SUIVI-XXXX) reçu à l'inscription. Un nouveau code professionnel vous sera attribué immédiatement.</p>
      <form action="/mon-espace-pro/reinitialiser" method="POST">
        <label>Code de suivi *</label>
        <input name="tracking_code" required maxlength="20" style="text-transform:uppercase; text-align:center; font-size:20px;" placeholder="SUIVI-XXXX">
        <button type="submit" class="warning" style="width:100%; margin-top:10px;">🔄 Générer un nouveau code</button>
      </form>
      <div class="alert alert-warning" style="margin-top:20px; text-align:center; font-size:14px;">
        ⚠️ Votre ancien code sera immédiatement désactivé.
      </div>
      <p style="text-align:center; margin-top:20px;"><a href="/mon-espace-pro" style="color:#718096;">← Retour à la connexion</a></p>
    </section>
  `, null));
});

app.post("/mon-espace-pro/reinitialiser", async (req, res) => {
  const ip = req.ip || "unknown";
  const now = Date.now();
  const attempts = resetAttempts.get(ip) || { count: 0, startedAt: now };
  if (now - attempts.startedAt > 15 * 60 * 1000) { attempts.count = 0; attempts.startedAt = now; }
  if (attempts.count >= 5) {
    return res.status(429).send(page("Trop de tentatives", 
      "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>⏳ Trop de tentatives</h1><p>Veuillez patienter 15 minutes avant de réessayer.</p></section>", 
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
        "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h2>Code de suivi introuvable ou dossier non approuvé.</h2><a href='/mon-espace-pro/reinitialiser' class='button'>Réessayer</a></section>", 
        null));
    }
    
    const newCode = await generateUniqueProCode();
    await pool.query(
      `UPDATE professional_applications SET pro_code = $1, pro_code_updated_at = NOW() WHERE id = $2`,
      [newCode, result.rows[0].id]
    );
    
    res.send(page("Nouveau code généré", `
      <section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;">
        <h1 style="color:#38a169;">✅ Nouveau code généré</h1>
        <p>Votre ancien code est désormais <strong>invalide</strong>.</p>
        <div class="pro-code-box" style="margin:24px 0;">
          <div class="pro-code-label">Votre nouveau code pro</div>
          <div class="pro-code-value">${escapeHtml(newCode)}</div>
        </div>
        <div class="alert alert-warning">
          <strong>⚠️ Notez ce code immédiatement.</strong> Il ne sera plus affiché.
        </div>
        <a class="button" href="/mon-espace-pro" style="margin-top:20px;">Se connecter maintenant</a>
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
  res.send(page("Modifier", `
    <section class="card" style="max-width: 500px; margin: 40px auto;">
      <h1 style="text-align:center;">Visibilité</h1>
      <form action="/mon-espace-pro/modifier-telephone" method="POST">
        <div class="checkbox-block">
          <label><input type="checkbox" name="phone_public" value="yes" ${proConnected.pro.phone_public ? "checked" : ""}> <span style="font-weight:600;">Rendre mon numéro public sur mon profil</span></label>
        </div>
        <button type="submit" style="width:100%; margin-top:20px;">Enregistrer</button>
      </form>
    </section>
  `, proConnected));
});

app.post("/mon-espace-pro/modifier-telephone", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  const phonePublic = req.body.phone_public === "yes";
  await pool.query(`UPDATE professional_applications SET phone_public = $1 WHERE id = $2`, [phonePublic, proConnected.pro.id]);
  res.redirect(303, "/mon-espace-pro");
});

// ✅ Inclure les messages de contact dans l'export RGPD
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
  res.send(page("Demande envoyee", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>Demande envoyee</h1><p>L'admin va traiter votre demande dans les plus brefs délais.</p><a href='/mon-espace-pro' class='button'>Retour</a></section>", proConnected));
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
  
  res.send(page("Publier", `
    <section class="card" style="max-width: 700px; margin: 0 auto;">
      <h1 style="text-align:center;">Nouvelle offre d'emploi</h1>
      <form action="/offres-emploi" method="POST">
        <label>Nom de l'entreprise *</label>
        <input name="company_name" required maxlength="200" value="${escapeHtml(getDisplayName(proConnected.pro))}">
        
        <label>Intitulé du poste *</label>
        <input name="job_title" required maxlength="200" placeholder="Ex: Développeur Web, Maçon...">
        
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px;">
          <div>
            <label>Ville *</label>
            <input name="city" required maxlength="100" value="${escapeHtml(proConnected.pro.city)}">
          </div>
          <div>
            <label>Type de contrat *</label>
            <select name="contract_type" required><option value="">Choisir</option>${contractOptions}</select>
          </div>
        </div>
        
        <label>Description du poste *</label>
        <textarea name="description" required maxlength="5000" rows="6" placeholder="Décrivez les missions, les compétences requises..."></textarea>
        
        <div style="text-align:center; margin-top:20px;">
          <button type="submit" style="padding:14px 40px;">Soumettre l'offre</button>
          <a href="/mon-espace-pro" class="button secondary" style="padding:14px 30px;">Annuler</a>
        </div>
      </form>
    </section>
  `, proConnected));
});

// ✅ Validation contract_type
app.post("/offres-emploi", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  
  if (!JOB_CONTRACT_TYPES.includes(req.body.contract_type)) {
    return res.status(400).send(page("Erreur", "<h2>Type de contrat invalide.</h2>", proConnected));
  }
  
  try {
    await pool.query(`INSERT INTO job_offers (company_name, job_title, city, contract_type, description, status, pro_id, expires_at) VALUES ($1,$2,$3,$4,$5,'pending',$6, NOW() + INTERVAL '15 days')`, [req.body.company_name, req.body.job_title, req.body.city, req.body.contract_type, req.body.description, proConnected.pro.id]);
    res.send(page("Succes", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>Offre soumise !</h1><p>Votre offre est en attente de validation par l'administration.</p><a href='/mon-espace-pro' class='button'>Retour à mon espace</a></section>", proConnected));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", proConnected)); }
});

/* ADMINISTRATION */

app.get("/admin", (req, res) => {
  const session = verifySessionToken(readCookie(req, SESSION_COOKIE));
  if (session) return res.redirect(303, "/admin/dashboard");
  res.send(page("Admin", `
    <section class="card" style="max-width: 400px; margin: 60px auto;">
      <h1 style="text-align:center;">Administration</h1>
      <form action="/admin/login" method="POST">
        <label>Mot de passe</label>
        <input type="password" name="password" required style="text-align:center; font-size:20px;">
        <button style="width:100%; margin-top:10px;">Se connecter</button>
      </form>
    </section>
  `, null));
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
    <section class="card" style="background:#f8f9fa; border:1px solid #edf2f7;">
      <div class="actions" style="justify-content:center; gap:10px;">
        ${links.map(l => `<a class="button ${current === l.href ? "" : "secondary"}" href="${l.href}" style="padding:10px 18px; font-size:14px;">${l.label}${l.badge > 0 ? ` <span class="badge badge-new">${l.badge}</span>` : ""}</a>`).join("")}
      </div>
      <div style="text-align:center; margin-top:20px;">
        <form action="/admin/logout" method="POST"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><button class="danger" style="padding:8px 24px; font-size:14px;">Déconnexion</button></form>
      </div>
    </section>
  `;
}

/* DASHBOARD AVEC INSCRIPTIONS DU JOUR */
app.get("/admin/dashboard", requireAdmin, async (req, res) => {
  const stats = {
    pros: Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status = 'approved'")).rows[0].count),
    prosPending: Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status = 'pending'")).rows[0].count),
    reviews: Number((await pool.query("SELECT COUNT(*) FROM reviews WHERE status = 'pending'")).rows[0].count),
    messages: Number((await pool.query("SELECT COUNT(*) FROM contact_messages WHERE is_read = false")).rows[0].count),
    prosToday: Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE DATE(created_at) = CURRENT_DATE")).rows[0].count)
  };

  const todayResult = await pool.query(`
    SELECT id, full_name, profession, city, status, created_at 
    FROM professional_applications 
    WHERE DATE(created_at) = CURRENT_DATE 
    ORDER BY created_at DESC
  `);

  const todayList = todayResult.rows.map(p => `
    <tr>
      <td style="padding:12px 8px; border-bottom:1px solid #edf2f7;"><a href="/admin/candidatures" style="color:#2563eb; font-weight:600;">${escapeHtml(p.full_name)}</a></td>
      <td style="padding:12px 8px; border-bottom:1px solid #edf2f7;">${escapeHtml(p.profession)}</td>
      <td style="padding:12px 8px; border-bottom:1px solid #edf2f7;">${escapeHtml(p.city)}</td>
      <td style="padding:12px 8px; border-bottom:1px solid #edf2f7;"><span class="badge badge-${p.status}">${STATUS_LABELS[p.status]}</span></td>
      <td style="padding:12px 8px; border-bottom:1px solid #edf2f7;">${new Date(p.created_at).toLocaleTimeString("fr-FR", {hour: '2-digit', minute:'2-digit'})}</td>
    </tr>
  `).join("");

  const todayHtml = todayResult.rows.length > 0 ? `
    <section class="card" style="margin-top:30px;">
      <h2>📅 Inscriptions du jour (${stats.prosToday})</h2>
      <div style="overflow-x:auto;">
        <table style="width:100%; border-collapse:collapse; text-align:left; font-size:14px;">
          <thead>
            <tr style="background:#f8f9fa; border-bottom:2px solid #e2e8f0;">
              <th style="padding:12px 8px;">Nom</th>
              <th style="padding:12px 8px;">Métier</th>
              <th style="padding:12px 8px;">Ville</th>
              <th style="padding:12px 8px;">Statut</th>
              <th style="padding:12px 8px;">Heure</th>
            </tr>
          </thead>
          <tbody>${todayList}</tbody>
        </table>
      </div>
    </section>
  ` : `<section class="card" style="margin-top:30px; text-align:center;"><p class="muted">Aucune nouvelle inscription aujourd'hui.</p></section>`;

  const menu = await adminMenu("/admin/dashboard", getCsrf(req));

  res.send(page("Dashboard", `
    <h1 style="text-align:center; margin-bottom:30px;">Tableau de bord</h1>
    ${menu}
    
    <div class="stats-grid" style="margin-top:30px;">
      <div class="stat-card"><div class="stat-number">${stats.pros}</div><div class="stat-label">Pros approuvés</div></div>
      <div class="stat-card warning"><div class="stat-number">${stats.prosPending}</div><div class="stat-label">Candidatures en attente</div></div>
      <div class="stat-card danger"><div class="stat-number">${stats.reviews}</div><div class="stat-label">Avis à modérer</div></div>
      <div class="stat-card info"><div class="stat-number">${stats.messages}</div><div class="stat-label">Messages non lus</div></div>
      <div class="stat-card success">
        <div class="stat-number" style="color: #38a169;">${stats.prosToday}</div>
        <div class="stat-label">Nouveaux aujourd'hui</div>
      </div>
    </div>

    ${todayHtml}
  `, null));
});

/* ADMIN CANDIDATURES (AVEC LOUPE ET NPI) */

app.get("/admin/candidatures", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  const result = await pool.query(`SELECT p.* FROM professional_applications p ORDER BY CASE WHEN p.status = 'pending' THEN 0 ELSE 1 END, p.created_at DESC`);

  const applications = result.rows.map(c => {
    const statusOptions = ALLOWED_STATUSES.map(s => `<option value="${s}" ${c.status === s ? "selected" : ""}>${STATUS_LABELS[s]}</option>`).join("");
    
    // ✅ LA LOUPE EST ACTIVÉE ICI (onclick="zoomImage(this.src)")
    const photos = `
      <div class="photos-grid">
        ${c.photo_profil_url ? `<div class="photo-block"><img src="${escapeHtml(c.photo_profil_url)}" class="photo-profil" style="cursor:zoom-in" onclick="zoomImage(this.src)"><div class="photo-label">Profil</div></div>` : ""}
        ${c.photo_identite_url ? `<div class="photo-block"><img src="${escapeHtml(c.photo_identite_url)}" class="photo-identite" style="cursor:zoom-in" onclick="zoomImage(this.src)"><div class="photo-label">Identité</div></div>` : ""}
        ${c.photo_kyc_url ? `<div class="photo-block"><img src="${escapeHtml(c.photo_kyc_url)}" class="photo-kyc" style="cursor:zoom-in" onclick="zoomImage(this.src)"><div class="photo-label" style="color:#dd6b20">KYC (Vérification)</div></div>` : ""}
        ${c.photo_activite_url ? `<div class="photo-block"><img src="${escapeHtml(c.photo_activite_url)}" class="photo-activite" style="cursor:zoom-in" onclick="zoomImage(this.src)"><div class="photo-label">Activité</div></div>` : ""}
      </div>`;
    
    let codeBlock = "";
    if (c.pro_code) {
      const waNumber = c.whatsapp_number || c.phone;
      const cleanNumber = waNumber.replace(/[()\s.-]/g, "").replace(/^\+/, "");
      
      const baseUrl = `${req.protocol}://${req.get("host")}`;
      const waMessage = encodeURIComponent(`Bonjour ${c.full_name}, votre candidature sur TrouveMoi a ete approuvee ✅\n\nVotre code professionnel est : ${c.pro_code}\n\nConservez-le precieusement pour vous connecter a votre espace pro : ${baseUrl}/mon-espace-pro`);
      
      codeBlock = `
        <div class="pro-code-box" style="margin:24px 0; padding:16px;">
          <div class="pro-code-label">Code professionnel généré</div>
          <div class="pro-code-value" style="font-size:32px; margin:8px 0;">${escapeHtml(c.pro_code)}</div>
        </div>
        <div class="card" style="background:#f0fff4; border:1px solid #38a169; box-shadow:none; padding:16px;">
          <h3 style="margin-top:0; font-size:16px;">📤 Envoyer le code au professionnel</h3>
          <a class="button whatsapp" href="https://wa.me/${escapeHtml(cleanNumber)}?text=${waMessage}" target="_blank" style="margin-top:10px;">📱 Envoyer par WhatsApp</a>
        </div>
        <div class="card" style="background:#fffaf0; border:1px solid #ed8936; margin-top:12px; box-shadow:none; padding:16px;">
          <h3 style="margin-top:0; color:#c05621; font-size:16px;">🔄 Régénérer le code</h3>
          <p class="muted" style="font-size:13px; margin-bottom:10px;">Utile si le professionnel a perdu son code ou s'il a fuité. L'ancien code sera immédiatement désactivé.</p>
          <form action="/admin/candidatures/${c.id}/regenerer-code" method="POST" onsubmit="return confirm('Régénérer le code ? L ancien sera invalidé immédiatement.')">
            <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
            <button class="warning" type="submit" style="font-size:13px; padding:10px 16px;">🔄 Générer un nouveau code</button>
          </form>
        </div>
      `;
    }

    return `
      <article class="card" style="margin-bottom:30px;">
        <h2>${escapeHtml(c.full_name)} <span class="badge badge-${c.status}">${STATUS_LABELS[c.status]}</span>${c.status === 'approved' ? ` ${renderKycBadge()}` : ""}</h2>
        
        ${photos}
        
        <div style="background:#f8f9fa; padding:16px; border-radius:16px; margin:16px 0; border:1px solid #edf2f7;">
          <p style="margin-bottom:4px;"><span class="label">NPI :</span> <strong style="color:#2563eb; font-size:16px;">${escapeHtml(c.npi || "Non renseigné")}</strong></p>
          <p style="margin-bottom:4px;"><span class="label">Téléphone :</span> ${escapeHtml(c.phone)}</p>
          <p style="margin-bottom:4px;"><span class="label">Ville :</span> ${escapeHtml(c.city)} ${c.neighborhood ? `(${escapeHtml(c.neighborhood)})` : ""}</p>
          <p style="margin-bottom:4px;"><span class="label">Profession :</span> ${escapeHtml(c.profession)}</p>
          <p style="margin-bottom:4px;"><span class="label">Email :</span> ${escapeHtml(c.contact_email || "Non renseigné")}</p>
          <p><span class="label">Description :</span> ${escapeHtml(c.service_description)}</p>
        </div>

        ${c.rejection_reason ? `<div class="alert alert-danger"><strong>Motif :</strong> ${escapeHtml(c.rejection_reason)}</div>` : ""}
        
        ${codeBlock}
        
        <form action="/admin/candidatures/${c.id}/status" method="POST" style="background:#f8f9fa; padding:20px; border-radius:20px; margin-top:20px;">
          <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
          <h3 style="margin-top:0; font-size:16px;">Changer le statut</h3>
          <div style="display:grid; grid-template-columns:1fr 2fr; gap:16px; align-items:end;">
            <div>
              <label for="status-${c.id}">Statut</label>
              <select id="status-${c.id}" name="status">${statusOptions}</select>
            </div>
            <div>
              <label for="reason-${c.id}">Motif (si refus ou corrections)</label>
              <input id="reason-${c.id}" name="rejection_reason" maxlength="1000" value="${escapeHtml(c.rejection_reason || "")}" placeholder="Ex: Photo floue, veuillez recommencer">
            </div>
          </div>
          <div style="text-align:right; margin-top:10px;">
            <button type="submit">Enregistrer les modifications</button>
          </div>
        </form>
        
        <div style="text-align:right; margin-top:12px;">
          <form action="/admin/candidatures/${c.id}/supprimer" method="POST">
            <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
            <button class="danger" onclick="return confirm('Supprimer ce dossier définitivement ?')" style="font-size:13px; padding:8px 16px; background:transparent; color:#e53e3e; border:1px solid #e53e3e;">🗑️ Supprimer le dossier</button>
          </form>
        </div>
      </article>
    `;
  }).join("");

  const menu = await adminMenu("/admin/candidatures", csrf);
  res.send(page("Candidatures", `<h1 style="text-align:center; margin-bottom:30px;">Gestion des candidatures</h1>${menu}${applications}`, null));
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

app.post("/admin/candidatures/:id/regenerer-code", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/candidatures");
  try {
    const check = await pool.query("SELECT id, status FROM professional_applications WHERE id = $1", [id]);
    if (!check.rows.length || check.rows[0].status !== "approved") return res.redirect(303, "/admin/candidatures");
    
    const newCode = await generateUniqueProCode();
    await pool.query(`UPDATE professional_applications SET pro_code = $1, pro_code_updated_at = NOW() WHERE id = $2`, [newCode, id]);
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
    <article class="card" style="margin-bottom:20px;">
      <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:10px;">
        <div>
          <h2 style="margin-bottom:4px; font-size:18px;">Avis de ${escapeHtml(r.author_name)}</h2>
          <p class="muted" style="font-size:14px;">Concernant : <strong>${escapeHtml(r.pro_name || "Inconnu")}</strong></p>
        </div>
        <span class="badge badge-${r.status}">${REVIEW_STATUS_LABELS[r.status]}</span>
      </div>
      
      <div class="review-stars" style="margin:10px 0; font-size:24px;">${renderStars(r.rating)}</div>
      <p style="background:#f8f9fa; padding:16px; border-radius:12px; font-style:italic;">"${escapeHtml(r.comment || "Aucun commentaire")}"</p>
      
      <div class="actions" style="margin-top:16px;">
        <form action="/admin/avis/${r.id}/statut" method="POST" style="display:inline"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><input type="hidden" name="status" value="approved"><button class="success" style="padding:8px 24px; font-size:14px;">Approuver</button></form>
        <form action="/admin/avis/${r.id}/statut" method="POST" style="display:inline"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><input type="hidden" name="status" value="rejected"><button class="danger" style="padding:8px 24px; font-size:14px;">Rejeter</button></form>
      </div>
    </article>
  `).join("");
  
  const menu = await adminMenu("/admin/avis", csrf);
  res.send(page("Avis", `<h1 style="text-align:center; margin-bottom:30px;">Modération des avis</h1>${menu}${reviews || '<section class="card"><p class="muted" style="text-align:center;">Aucun avis pour le moment.</p></section>'}`, null));
});

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
    <article class="card" style="margin-bottom:20px;">
      <h2 style="font-size:18px;">${escapeHtml(j.job_title)} <span class="badge badge-${j.status}">${JOB_STATUS_LABELS[j.status]}</span></h2>
      <p class="muted" style="font-size:14px;">Posté par : <strong>${escapeHtml(j.pro_name || "Inconnu")}</strong></p>
      
      <div style="background:#f8f9fa; padding:16px; border-radius:12px; margin:16px 0;">
        <p style="margin-bottom:4px;"><strong>Ville :</strong> ${escapeHtml(j.city)} | <strong>Contrat :</strong> ${escapeHtml(j.contract_type)}</p>
        <p>${escapeHtml(j.description)}</p>
      </div>
      
      <form action="/admin/emplois/${j.id}/status" method="POST" style="display:flex; align-items:center; gap:10px;">
        <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
        <select name="status" style="margin:0; width:auto; padding:8px 16px;">${JOB_STATUSES.map(s => `<option value="${s}" ${j.status === s ? "selected" : ""}>${JOB_STATUS_LABELS[s]}</option>`).join("")}</select>
        <button style="margin:0; padding:10px 20px; font-size:14px;">Mettre à jour</button>
      </form>
    </article>
  `).join("");
  
  const menu = await adminMenu("/admin/emplois", csrf);
  res.send(page("Emplois", `<h1 style="text-align:center; margin-bottom:30px;">Offres d'emploi</h1>${menu}${jobs || '<section class="card"><p class="muted" style="text-align:center;">Aucune offre pour le moment.</p></section>'}`, null));
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
    <article class="card" style="margin-bottom:20px; ${m.is_read ? 'opacity:0.6' : 'border-left:4px solid #3182ce;'}">
      <h2 style="font-size:18px;">${escapeHtml(m.subject)}</h2>
      <p class="muted" style="font-size:14px;"><strong>De :</strong> ${escapeHtml(m.name)} (${escapeHtml(m.email || m.phone || '')})</p>
      ${m.pro_id ? `<p class="muted" style="font-size:12px;">Concernant le pro ID : ${m.pro_id}</p>` : ""}
      
      <p style="background:#f8f9fa; padding:16px; border-radius:12px; margin:16px 0;">${escapeHtml(m.message)}</p>
      <p class="muted" style="font-size:12px;">Reçu le : ${new Date(m.created_at).toLocaleString("fr-FR")}</p>
      
      ${!m.is_read ? `<form action="/admin/messages/${m.id}/read" method="POST" style="margin-top:10px;"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><button class="secondary" style="padding:8px 16px; font-size:14px;">Marquer comme lu</button></form>` : ""}
    </article>
  `).join("");
  
  const menu = await adminMenu("/admin/messages", csrf);
  res.send(page("Messages", `<h1 style="text-align:center; margin-bottom:30px;">Messages de contact</h1>${menu}${messages || '<section class="card"><p class="muted" style="text-align:center;">Aucun message.</p></section>'}`, null));
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
    <article class="card" style="margin-bottom:20px;">
      <h2 style="font-size:18px;">${GDPR_TYPE_LABELS[r.request_type]} - ${escapeHtml(r.pro_name || "Inconnu")}</h2>
      <p style="margin-top:8px;"><span class="badge badge-${r.status}">${GDPR_STATUS_LABELS[r.status]}</span></p>
      
      <p style="background:#f8f9fa; padding:16px; border-radius:12px; margin:16px 0;">${escapeHtml(r.message)}</p>
      <p class="muted" style="font-size:12px;">Demande le : ${new Date(r.created_at).toLocaleString("fr-FR")}</p>
      
      ${r.status === "pending" ? `<form action="/admin/rgpd/${r.id}/traiter" method="POST" style="margin-top:10px;"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><button class="success" style="padding:8px 16px; font-size:14px;">Marquer comme traitée</button></form>` : ""}
    </article>
  `).join("");
  
  const menu = await adminMenu("/admin/rgpd", csrf);
  res.send(page("RGPD", `<h1 style="text-align:center; margin-bottom:30px;">Demandes RGPD</h1>${menu}${reqs || '<section class="card"><p class="muted" style="text-align:center;">Aucune demande.</p></section>'}`, null));
});

app.post("/admin/rgpd/:id/traiter", requireAdmin, verifyCsrf, async (req, res) => {
  await pool.query(`UPDATE gdpr_requests SET status = 'processed', processed_at = NOW() WHERE id = $1`, [Number(req.params.id)]);
  res.redirect(303, "/admin/rgpd");
});

app.post("/admin/logout", requireAdmin, verifyCsrf, (req, res) => { clearSessionCookie(res); res.redirect(303, "/admin"); });

/* PAGES STATIQUES */

app.get("/a-propos", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  res.send(page("A propos", `
    <section class="card" style="max-width: 800px; margin: 0 auto;">
      <h1 style="text-align:center;">A propos de TrouveMoi</h1>
      <p style="font-size: 16px; margin-top: 20px;"><strong>TrouveMoi</strong> est la plateforme beninoise de mise en relation entre les clients et les professionnels qualifies.</p>
      <h2 style="margin-top: 30px;">Notre mission</h2>
      <p>Simplifier la recherche de professionnels de confiance au Benin. TrouveMoi centralise les pros de votre ville et vous permet de les contacter en un clic, en toute sécurité grâce à la vérification KYC.</p>
      <h2 style="margin-top: 30px;">Nos services</h2>
      <ul style="margin-left:20px;margin-bottom:24px; font-size:15px; line-height:2;">
        <li>Annuaire de professionnels vérifiés</li>
        <li>Recherche intuitive par ville, quartier et métier</li>
        <li>Contact direct par téléphone ou WhatsApp</li>
        <li>Publication et consultation d'offres d'emploi</li>
        <li>Système d'avis clients modérés</li>
      </ul>
      <div style="text-align:center; margin-top:30px;">
        <a class="button" href="/contact">Nous contacter</a> 
        <a class="button secondary" href="/">Voir les professionnels</a>
      </div>
    </section>
  `, proConnected));
});

app.get("/conditions", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  res.send(page("Conditions", `
    <section class="card" style="max-width: 800px; margin: 0 auto;">
      <h1 style="text-align:center;">Conditions d'utilisation</h1>
      <p class="muted" style="text-align:center; margin-bottom:30px;">Dernière mise à jour : ${new Date().toLocaleDateString("fr-FR")}</p>
      
      <h2>1. Acceptation</h2><p>En utilisant TrouveMoi, vous acceptez ces conditions.</p>
      <h2>2. Nature du service</h2><p>TrouveMoi est une plateforme de mise en relation. Nous ne fournissons pas directement de services professionnels et ne pouvons être tenus responsables de la qualité des prestations.</p>
      <h2>3. Inscription des professionnels</h2><p>Les pros doivent fournir des informations exactes (dont leur NPI). Toute fausse déclaration entraîne le rejet définitif du dossier.</p>
      <h2>4. Publication d'offres</h2><p>Seuls les pros vérifiés peuvent publier des offres. Toute offre est examinée manuellement avant publication.</p>
      <h2>5. Avis clients</h2><p>Les avis sont modérés. Tout avis injurieux, diffamatoire ou spam sera supprimé sans préavis.</p>
    </section>
  `, proConnected));
});

app.get("/confidentialite", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  res.send(page("Confidentialite", `
    <section class="card" style="max-width: 800px; margin: 0 auto;">
      <h1 style="text-align:center;">Politique de confidentialité</h1>
      <p class="muted" style="text-align:center; margin-bottom:30px;">Dernière mise à jour : ${new Date().toLocaleDateString("fr-FR")}</p>
      
      <h2>1. Données collectées</h2><p>Nom, téléphone, NPI, ville, métier, photos (profil et KYC), avis, messages.</p>
      <h2>2. Utilisation</h2><p>Mise en relation, affichage des profils, vérification d'identité, gestion des offres et avis.</p>
      <h2>3. Protection</h2><p>Les photos d'identité et de vérification KYC sont strictement privées. Seuls les administrateurs y ont accès pour validation.</p>
      <h2>4. Vos droits</h2><p>Vous disposez des droits d'accès, rectification, suppression et opposition. Contactez-nous via le <a href="/contact" style="color:#2563eb;">formulaire de contact</a> ou depuis votre espace pro.</p>
    </section>
  `, proConnected));
});

app.get("/contact", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const proId = String(req.query.pro || "").trim();
  
  res.send(page("Contact", `
    <section class="card" style="max-width: 600px; margin: 0 auto;">
      <h1 style="text-align:center;">Nous contacter</h1>
      <p style="text-align:center; color:#718096; margin-bottom:30px;">Une question, une suggestion, un problème ? Écrivez-nous.</p>
      
      <form action="/contact" method="POST">
        <input type="hidden" name="pro_id" value="${escapeHtml(proId)}">
        
        <label>Votre nom *</label>
        <input name="name" required maxlength="150">
        
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px;">
          <div>
            <label>Votre email</label>
            <input type="email" name="email" maxlength="254">
          </div>
          <div>
            <label>Votre téléphone</label>
            <input type="tel" name="phone" maxlength="30">
          </div>
        </div>
        
        <label>Sujet *</label>
        <input name="subject" required maxlength="200">
        
        <label>Message *</label>
        <textarea name="message" required rows="5" maxlength="5000"></textarea>
        
        <div style="text-align:center; margin-top:20px;">
          <button type="submit" style="padding:14px 40px;">Envoyer le message</button>
        </div>
      </form>
    </section>
  `, proConnected));
});

// ✅ Validation pro_id + troncature des champs + RATE LIMITING
app.post("/contact", async (req, res) => {
  // ✅ RATE LIMITING : 3 messages max / heure / IP
  const ip = req.ip || "unknown";
  const now = Date.now();
  const attempts = contactAttempts.get(ip) || { count: 0, startedAt: now };
  if (now - attempts.startedAt > 60 * 60 * 1000) { attempts.count = 0; attempts.startedAt = now; }
  if (attempts.count >= 3) {
    return res.status(429).send(page("Trop de tentatives", 
      "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>⏳ Trop de messages</h1><p>Vous avez envoyé trop de messages récemment. Veuillez patienter 1 heure.</p><a class='button' href='/'>Accueil</a></section>", 
      null));
  }
  attempts.count++;
  contactAttempts.set(ip, attempts);

  const { name, email, phone, subject, message, pro_id } = req.body;
  if (!name || !subject || !message || (!email && !phone)) {
    return res.status(400).send(page("Erreur", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h2>Informations manquantes.</h2><a href='/contact' class='button'>Retour</a></section>", null));
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
    res.send(page("Succes", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>Message envoyé !</h1><p>Nous vous répondrons dans les plus brefs délais.</p><a class='button' href='/'>Retour à l'accueil</a></section>", null));
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
  res.status(404).send(page("Introuvable", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>404</h1><p>La page demandée n'existe pas.</p><a class='button' href='/'>Retour à l'accueil</a></section>", null));
});

/* GESTION GLOBALE DES ERREURS */
app.use((err, req, res, next) => {
  console.error("Erreur non geree :", err.message);
  if (err.code === "LIMIT_FILE_SIZE") return res.status(413).send(page("Erreur", "<h2>Fichier trop volumineux (max 5 Mo).</h2>", null));
  if (err.message && err.message.includes("Format non autorise")) return res.status(400).send(page("Erreur", "<h2>Format d'image non autorise.</h2>", null));
  res.status(500).send(page("Erreur", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>Une erreur est survenue</h1><p>Veuillez réessayer plus tard.</p><a class='button' href='/'>Accueil</a></section>", null));
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
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS pro_code_updated_at TIMESTAMP`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS npi VARCHAR(100)`
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
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_pros_npi ON professional_applications(npi)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_jobs_status ON job_offers(status)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_read ON contact_messages(is_read)`);

    /* ==========================================
       DONNEES DE BASE : LES VILLES DU BENIN
       ========================================== */
    const citiesData = [
      ["Cotonou", 1], ["Abomey-Calavi", 2], ["Porto-Novo", 3], ["Parakou", 4], 
      ["Bohicon", 5], ["Natitingou", 6], ["Ouidah", 7], ["Abomey", 8], 
      ["Lokossa", 9], ["Djougou", 10], ["Kandi", 11], ["Malanville", 12], 
      ["Savalou", 13], ["Dassa-Zoumè", 14], ["Savè", 15], ["Nikki", 16], 
      ["Tchaourou", 17], ["Allada", 18], ["Comè", 19], ["Banikoara", 20], 
      ["Sakété", 21], ["Pobè", 22], ["Adjohoun", 23], ["Akpro-Missérété", 24], 
      ["Avrankou", 25], ["Sèmè-Podji", 26], ["Aplahoué", 27], ["Dogbo", 28], 
      ["Grand-Popo", 29], ["Zagnanado", 30], ["Agbangnizoun", 31], ["Ouaké", 32], 
      ["Bassila", 33], ["Boukoumbé", 34], ["Tanguiéta", 35], ["Copargo", 36], 
      ["Glazoué", 37], ["Bantè", 38], ["Ouèssè", 39], ["Kalalé", 40]
    ];
    
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
      "Ouidah": ["Ouidah centre", "Pahou", "Gbéna", "Sè", "Kpomassè", "Avlékété", "Djègbadji"],
      "Abomey": ["Houndjro", "Adandokpodji", "Djègbé", "Gbècon-Hounli", "Vidolé"],
      "Lokossa": ["Lokossa centre", "Agamè", "Ouèdèmè", "Koussoukovi"],
      "Djougou": ["Djougou centre", "Kilir", "Zongo", "Sèkèré"],
      "Kandi": ["Kandi centre", "Sonsoro", "Kassakou"],
      "Malanville": ["Malanville centre", "Garou-Tédji", "Monsoy"],
      "Savalou": ["Savalou centre", "Attakè", "Gbakè"],
      "Dassa-Zoumè": ["Dassa centre", "Kpingni", "Tré"],
      "Savè": ["Savè centre", "Boni", "Kaboua"],
      "Nikki": ["Nikki centre", "Sérékali", "Tasso"],
      "Tchaourou": ["Tchaourou centre", "Bétérou", "Ali"],
      "Allada": ["Allada centre", "Ganvié", "Attogon"],
      "Comè": ["Comè centre", "Agoué", "Oumako"],
      "Banikoara": ["Banikoara centre", "Sommpérékou", "Founougo"],
      "Sakété": ["Sakété centre", "Ijebu", "Kétou"],
      "Pobè": ["Pobè centre", "Issaba", "Adja-Ouèrè"],
      "Sèmè-Podji": ["Sèmè centre", "Ekpè", "Tohoun"],
      "Dogbo": ["Dogbo centre", "Tota", "Dévé"],
      "Grand-Popo": ["Grand-Popo centre", "Avlo", "Agoué"],
      "Bassila": ["Bassila centre", "Manigri", "Alédjo"],
      "Tanguiéta": ["Tanguiéta centre", "Taneka", "Kouaténa"]
    };

    for (const [cityName, neighborhoods] of Object.entries(neighborhoodsData)) {
      const cityRes = await pool.query("SELECT id FROM cities WHERE name = $1", [cityName]);
      if (cityRes.rows.length) {
        for (const n of neighborhoods) {
          await pool.query(`INSERT INTO neighborhoods (city_id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [cityRes.rows[0].id, n]);
        }
      }
    }

    /* ==========================================
       DONNEES DE BASE : LES METIERS (MISE A JOUR)
       ========================================== */
    const profs = [
      // Bâtiment et Construction
      ["Maçon", "Bâtiment"], ["Plombier", "Bâtiment"], ["Électricien", "Bâtiment"], ["Carreleur", "Bâtiment"], ["Peintre en bâtiment", "Bâtiment"], ["Menuisier bois", "Bâtiment"], ["Menuisier aluminium", "Bâtiment"], ["Soudeur", "Bâtiment"], ["Ferrailleur", "Bâtiment"], ["Charpentier", "Bâtiment"], ["Étanchéiste (toiture)", "Bâtiment"], ["Vitrier", "Bâtiment"],
      ["Installateur de panneaux solaires", "Énergie"], ["Technicien de groupe électrogène", "Énergie"], ["Domoticien", "Bâtiment"], ["Architecte", "Bâtiment"], ["Dessinateur bâtiment", "Bâtiment"], ["Géomètre", "Bâtiment"], ["Ingénieur BTP", "Bâtiment"], ["Conducteur de travaux", "Bâtiment"],
      
      // Maison et Services
      ["Femme de ménage", "Maison"], ["Repassage à domicile", "Maison"], ["Cuisinier", "Maison"], ["Cuisinière", "Maison"], ["Gardien", "Maison"], ["Vigile", "Maison"], ["Nounou", "Maison"], ["Garde d'enfants", "Maison"], ["Jardinier", "Maison"], ["Désinsectisation", "Maison"], ["Dératisation", "Maison"], ["Plombier-déboucheur", "Maison"],
      ["Garde-malade", "Santé"], ["Auxiliaire de vie", "Santé"], ["Aide aux devoirs", "Éducation"], ["Fleuriste", "Événementiel"], ["Art floral", "Événementiel"], ["Paysagiste", "Maison"], ["Majordome", "Maison"], ["Chef de maison", "Maison"], ["Réparateur de télévision", "Divers"], ["Réparateur d'électroménager", "Divers"], ["Serrurier", "Bâtiment"], ["Blindage de portes", "Bâtiment"],
      
      // Beauté et Bien-être
      ["Coiffeur", "Beauté"], ["Coiffeuse", "Beauté"], ["Tresseuse", "Beauté"], ["Barbier", "Beauté"], ["Esthéticienne", "Beauté"], ["Maquilleuse", "Beauté"], ["Manucure", "Beauté"], ["Pédicure", "Beauté"], ["Masseur", "Beauté"], ["Masseuse", "Beauté"], ["Tatoueur", "Beauté"],
      ["Prothésiste ongulaire", "Beauté"], ["Nail Art", "Beauté"], ["Lash maker (Extensions de cils)", "Beauté"], ["Maquilleur professionnel", "Beauté"],
      
      // Santé et Bien-être
      ["Infirmier à domicile", "Santé"], ["Infirmière à domicile", "Santé"], ["Sage-femme", "Santé"], ["Kinésithérapeute", "Santé"], ["Aide-soignant", "Santé"], ["Pharmacien", "Santé"], ["Opticien", "Santé"],
      ["Psychologue", "Santé"], ["Thérapeute de couple", "Santé"], ["Nutritionniste", "Santé"], ["Diététicien", "Santé"], ["Coach sportif", "Santé"], ["Personal Trainer", "Santé"], ["Vétérinaire", "Santé"], ["Toiletteur pour animaux", "Santé"], ["Ostéopathe", "Santé"], ["Naturopathe", "Santé"],
      
      // Couture et Textile
      ["Couturier", "Couture"], ["Couturière", "Couture"], ["Tailleur", "Couture"], ["Brodeur", "Couture"], ["Retoucheur", "Couture"], ["Styliste modéliste", "Couture"], ["Cordonnier", "Couture"],
      
      // Automobile et Transport
      ["Mécanicien auto", "Automobile"], ["Mécanicien moto", "Automobile"], ["Électricien auto", "Automobile"], ["Carrossier", "Automobile"], ["Tôlier", "Automobile"], ["Vulcanisateur", "Automobile"], ["Chauffeur de taxi", "Transport"], ["Chauffeur de moto-taxi", "Transport"], ["Chauffeur personnel", "Transport"], ["Déménageur", "Transport"],
      ["Livreur", "Transport"], ["Coursier", "Transport"], ["Chauffeur de poids lourd", "Transport"], ["Camionneur", "Transport"], ["Transitaire", "Transport"], ["Déclarant en douane", "Transport"],
      
      // Restauration et Événementiel
      ["Traiteur", "Restauration"], ["Pâtissier", "Restauration"], ["Boulanger", "Restauration"], ["Vendeur de nourriture", "Restauration"], ["Boucher", "Restauration"], ["Poissonnier", "Restauration"], ["Barista", "Restauration"],
      ["Chef à domicile", "Restauration"], ["Barman", "Événementiel"], ["Mixologue", "Événementiel"], ["Wedding Cake Designer", "Restauration"], ["Hôte(sse) d'accueil", "Événementiel"], ["Protocole", "Événementiel"], ["Guide touristique", "Tourisme"],
      
      // Numérique, Médias et Informatique
      ["Développeur web", "Informatique"], ["Développeur mobile", "Informatique"], ["Informaticien", "Informatique"], ["Réparateur de téléphone", "Informatique"], ["Réparateur d'ordinateur", "Informatique"], ["Graphiste", "Informatique"], ["Community manager", "Informatique"], ["Photographe", "Informatique"], ["Vidéaste", "Informatique"], ["Ingénieur réseau", "Informatique"],
      ["Monteur vidéo", "Informatique"], ["Motion Designer", "Informatique"], ["Pilote de drone", "Informatique"], ["Expert en cybersécurité", "Informatique"], ["Webmaster", "Informatique"], ["Gestionnaire de site web", "Informatique"], ["Data Analyst", "Informatique"], ["Testeur de jeux vidéo", "Informatique"], ["E-sport manager", "Informatique"], ["Créateur de contenu", "Informatique"], ["Influenceur", "Médias"],
      
      // Éducation
      ["Professeur de Maths", "Éducation"], ["Professeur de Français", "Éducation"], ["Professeur d'Anglais", "Éducation"], ["Enseignant primaire", "Éducation"], ["Formateur informatique", "Éducation"], ["Coach scolaire", "Éducation"],
      
      // Professionnel, Administration et Commerce
      ["Comptable", "Professionnel"], ["Fiscaliste", "Professionnel"], ["Juriste", "Professionnel"], ["Avocat", "Professionnel"], ["Notaire", "Professionnel"], ["Traducteur", "Professionnel"], ["Rédacteur de contenu", "Professionnel"], ["Secrétaire", "Professionnel"], ["Assistant administratif", "Professionnel"], ["Consultant", "Professionnel"],
      ["Magasinier", "Commerce"], ["Gestionnaire de stock", "Commerce"], ["Démarcheur", "Professionnel"],
      
      // Immobilier, Agriculture et Divers
      ["Agent immobilier", "Immobilier"], ["Courtier", "Immobilier"], ["Agriculteur", "Agriculture"], ["Maraîcher", "Agriculture"], ["Éleveur", "Agriculture"], ["Pêcheur", "Agriculture"], ["Apiculteur", "Agriculture"], ["Prothésiste dentaire", "Santé"],
      ["Climatisation", "Divers"], ["Froid", "Divers"], ["Antenniste", "Divers"], ["Forgeron", "Divers"], ["Puisatier", "Divers"]
    ];

    let orderCounter = 0;
    for (const [name, category] of profs) {
      orderCounter += 1;
      await pool.query(`INSERT INTO professions (name, category, display_order) VALUES ($1, $2, $3) ON CONFLICT (name) DO NOTHING`, [name, category, orderCounter]);
    }

    console.log("Toutes les tables sont pretes. Design et NPI inclus !");

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`TrouveMoi demarre sur le port ${PORT}.`);
    });
  } catch (error) {
    console.error("Erreur au demarrage :", error);
    process.exit(1);
  }
}

startServer();

