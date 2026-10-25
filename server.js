const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const compression = require("compression");

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

const KKIAPAY_PUBLIC_KEY = process.env.KKIAPAY_PUBLIC_KEY;
const KKIAPAY_PRIVATE_KEY = process.env.KKIAPAY_PRIVATE_KEY;
const KKIAPAY_SANDBOX = process.env.KKIAPAY_SANDBOX === "true";
const APP_URL = process.env.APP_URL || "https://trouvemoi.bj";

const BYPASS_PAYMENT = process.env.BYPASS_PAYMENT === "true"; 
const PAYMENT_AMOUNT = 1500; // ✅ MODIFIÉ : 1500 FCFA

const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 5 },
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
app.use(compression()); 
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
const GDPR_TYPE_LABELS = { access: "Acces", deletion: "Suppression", rectification: "Rectification", opposition: "Opposition" };
const GDPR_STATUS_LABELS = { pending: "En attente", processed: "Traitee", rejected: "Refusee" };
const JOB_CONTRACT_TYPES = ["CDI", "CDD", "Stage", "Interim", "Freelance", "Apprentissage", "Autre"];
const OFFER_DURATION_DAYS = 15;
const CONTACT_PREFERENCES = ["whatsapp", "email"];

const loginAttempts = new Map();
const resetAttempts = new Map();
const trackingAttempts = new Map();
const contactAttempts = new Map();
const reviewAttempts = new Map();

function escapeHtml(value) { return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function safeEqual(a, b) { const b1 = Buffer.from(String(a)), b2 = Buffer.from(String(b)); return b1.length === b2.length && crypto.timingSafeEqual(b1, b2); }

async function verifyRecaptcha(token) {
  if (!RECAPTCHA_SECRET_KEY) return true; 
  if (!token) return false;
  try {
    const res = await fetch("https://www.google.com/recaptcha/api/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `secret=${RECAPTCHA_SECRET_KEY}&response=${token}`
    });
    const data = await res.json();
    return data.success && data.score >= 0.5;
  } catch (e) { return false; }
}

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

function getOrCreateVisitorId(req, res) {
  let vid = readCookie(req, "tm_visitor_id");
  if (!vid || vid.length < 20) {
    vid = crypto.randomBytes(16).toString("hex");
    const currentCookies = res.getHeader("Set-Cookie") || [];
    const newCookie = `tm_visitor_id=${vid}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${365 * 24 * 60 * 60}`;
    res.setHeader("Set-Cookie", Array.isArray(currentCookies) ? [...currentCookies, newCookie] : [currentCookies, newCookie].filter(Boolean));
  }
  return vid;
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

function generateReferralCode() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 7; i++) { result += chars.charAt(Math.floor(Math.random() * chars.length)); }
  return result;
}

async function generateUniqueReferralCode() {
  let code, exists = true, attempts = 0;
  while (exists && attempts < 20) {
    code = generateReferralCode();
    const result = await pool.query("SELECT id FROM professional_applications WHERE referral_code = $1", [code]);
    exists = result.rows.length > 0;
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

async function logAdminAction(action, targetType, targetId, details) {
  try {
    await pool.query(`INSERT INTO admin_logs (action, target_type, target_id, details) VALUES ($1, $2, $3, $4)`, [action, targetType, targetId, details]);
  } catch (e) { console.error("Erreur log admin :", e.message); }
}

async function verifyKkiapayTransaction(transactionId) {
  try {
    const res = await fetch(`https://api.kkiapay.me/api/v1/transactions/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": KKIAPAY_PUBLIC_KEY, "x-private-key": KKIAPAY_PRIVATE_KEY },
      body: JSON.stringify({ transactionId })
    });
    if (!res.ok) return { success: false, reason: `HTTP ${res.status}` };
    const data = await res.json();
    return { success: data.status === "SUCCESS" && Number(data.amount) >= PAYMENT_AMOUNT, amount: Number(data.amount || 0), method: data.method || null };
  } catch (e) { return { success: false, reason: "network" }; }
}

function renderStars(rating) {
  let html = "";
  const full = Math.floor(rating), half = (rating - full) >= 0.5;
  for (let i = 1; i <= 5; i++) html += (i <= full) ? "★" : (i === full + 1 && half) ? "⯨" : "☆";
  return html;
}

function renderKycBadge(size) {
  const cls = size === "lg" ? "kyc-tick kyc-tick-lg" : "kyc-tick";
  return `<span class="${cls}" title="Identité vérifiée par KYC">✓</span>`;
}

function renderLogo() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 280 55" width="240" height="50" style="display:inline-block;vertical-align:middle;max-width:100%" aria-label="TrouveMoi"><rect x="2" y="5" width="48" height="45" rx="12" fill="white"/><text x="26" y="38" text-anchor="middle" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif" font-size="28" font-weight="900" fill="#1e40af" letter-spacing="-1.5">TM</text><text x="62" y="39" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif" font-size="30" font-weight="900" fill="white" letter-spacing="-0.8">TrouveMoi</text></svg>`;
}

function buildMenu(proConnected) {
  if (proConnected) {
    return `<nav><a href="/">Professionnels</a><a href="/mes-favoris">❤️ Favoris</a><a href="/emplois">Emploi</a><a href="/mon-espace-pro">Mon espace pro</a><a href="/publier-emploi">📢 Publier une offre</a><form action="/mon-espace-pro/logout" method="POST" style="display:inline"><button type="submit" style="background:transparent;border:none;color:white;padding:8px 14px;border-radius:20px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit">Deconnexion</button></form></nav>`;
  }
  return `<nav><a href="/">Professionnels</a><a href="/mes-favoris">❤️ Favoris</a><a href="/emplois">Emploi</a><a href="/devenir-professionnel">Devenir pro</a><a href="/mon-espace-pro">Espace pro</a><a href="/contact">Contact</a></nav>`;
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
      <link rel="manifest" href="/manifest.json">
      <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 50 50'%3E%3Crect width='50' height='50' rx='10' fill='%231e40af'/%3E%3Ctext x='25' y='35' text-anchor='middle' font-family='Arial' font-size='22' font-weight='900' fill='white'%3ETM%3C/text%3E%3C/svg%3E">
      <title>${escapeHtml(title)} - TrouveMoi</title>
      
      <script src="https://www.google.com/recaptcha/api.js?render=6LelG_0tAAAAAGyx3z4xqCkxZ6rga6sF0RQ_RUtC"></script>
      
      <script async src="https://www.googletagmanager.com/gtag/js?id=G-6YQ5R6M4ET"></script>
      <script>window.dataLayer = window.dataLayer || []; function gtag(){dataLayer.push(arguments);} gtag('js', new Date()); gtag('config', 'G-6YQ5R6M4ET');</script>
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; padding: 0; background: #f4f7f6; color: #1a202c; line-height: 1.6; min-height: 100vh; display: flex; flex-direction: column; }
        header { background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; padding: 16px 20px; box-shadow: 0 4px 20px rgba(30,64,175,0.15); position: sticky; top: 0; z-index: 100; }
        .header-content { max-width: 1200px; margin: 0 auto; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; }
        .logo { display: inline-flex; align-items: center; text-decoration: none; }
        .logo svg { display: block; height: 45px; width: auto; max-width: 100%; }
        .tagline { font-size: 13px; color: rgba(255,255,255,0.85); margin-top: 2px; }
        nav { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
        nav a, nav button { color: white; text-decoration: none; padding: 8px 14px; border-radius: 20px; font-size: 14px; font-weight: 600; transition: background 0.2s; }
        nav a:hover, nav button:hover { background: rgba(255,255,255,0.2); color: white; }
        
        main { max-width: 1200px; width: 100%; margin: 0 auto; padding: 24px 20px; flex: 1; }
        .card { background: white; padding: 24px; margin-bottom: 20px; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.04); transition: transform 0.2s, box-shadow 0.2s; border: 1px solid #eef2f5; }
        .card:hover { box-shadow: 0 8px 30px rgba(0,0,0,0.08); }
        
        h1 { font-size: 28px; margin-bottom: 16px; color: #1e3a8a; line-height: 1.2; font-weight: 800; }
        h2 { font-size: 22px; margin-bottom: 14px; color: #1e40af; line-height: 1.3; font-weight: 700; }
        h3 { font-size: 18px; margin-bottom: 10px; color: #1a202c; line-height: 1.3; font-weight: 600; }
        p { margin-bottom: 12px; color: #4a5568; }
        .label { font-weight: 700; color: #1a202c; }
        
        label { display: block; margin-top: 8px; margin-bottom: 6px; font-weight: 600; font-size: 14px; color: #1a202c; }
        input, textarea, select { width: 100%; padding: 14px 18px; margin-bottom: 14px; border: 1px solid #cbd5e0; border-radius: 12px; font-size: 15px; font-family: inherit; background: #fdfdfd; transition: border-color 0.2s, box-shadow 0.2s; }
        input:focus, textarea:focus, select:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 4px rgba(59,130,246,0.1); background: white; }
        textarea { resize: vertical; min-height: 100px; }
        input[type="file"] { padding: 10px; background: #f8fafc; border: 2px dashed #cbd5e0; cursor: pointer; transition: all 0.2s; }
        input[type="checkbox"], input[type="radio"] { width: auto; margin-right: 8px; }
        optgroup { font-weight: 800; color: #1e40af; font-style: normal; background: #eff6ff; padding: 6px 0; font-size: 15px; }
        optgroup option { font-weight: 400; color: #222; background: white; font-size: 15px; }
        
        button, .button { display: inline-flex; align-items: center; justify-content: center; border: none; background: #2563eb; color: white; padding: 12px 24px; border-radius: 12px; cursor: pointer; text-decoration: none; text-align: center; font-size: 15px; font-weight: 600; transition: all 0.2s; margin-right: 8px; margin-bottom: 8px; font-family: inherit; }
        button:hover, .button:hover { background: #1d4ed8; transform: translateY(-2px); box-shadow: 0 4px 12px rgba(37,99,235,0.25); }
        .danger { background: #ef4444; } .danger:hover { background: #dc2626; }
        .secondary { background: white; color: #4b5563; border: 1px solid #d1d5db; } .secondary:hover { background: #f3f4f6; color: #111827; }
        .warning { background: #f59e0b; } .warning:hover { background: #d97706; }
        .success { background: #10b981; } .success:hover { background: #059669; }
        .whatsapp { background: #25d366; } .whatsapp:hover { background: #1da851; }
        
        .badge { display: inline-block; padding: 6px 12px; border-radius: 30px; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
        .badge-pending { background: #fef3c7; color: #92400e; } .badge-approved { background: #d1fae5; color: #065f46; } .badge-rejected { background: #fee2e2; color: #991b1b; } .badge-closed { background: #e5e7eb; color: #374151; }
        .badge-processed { background: #dbeafe; color: #1e40af; text-transform: none; letter-spacing: 0; }
        .badge-new { display: inline-block; background: #ef4444; color: white; font-size: 10px; font-weight: 800; padding: 2px 8px; border-radius: 10px; margin-left: 6px; text-transform: none; letter-spacing: 0; }
        
        .kyc-tick { display: inline-flex; align-items: center; justify-content: center; width: 18px; height: 18px; background: #1d9bf0; color: white; border-radius: 50%; font-size: 11px; font-weight: bold; margin-left: 6px; vertical-align: middle; box-shadow: 0 1px 3px rgba(0,0,0,0.2); }
        .kyc-tick-lg { width: 24px; height: 24px; font-size: 14px; margin-left: 8px; }

        .badge-local { background: #dbeafe; color: #1e40af; font-size: 11px; padding: 4px 10px; border-radius: 20px; font-weight: 700; display: inline-flex; align-items: center; gap: 4px; }
        .badge-ambulant { background: #fef3c7; color: #92400e; font-size: 11px; padding: 4px 10px; border-radius: 20px; font-weight: 700; display: inline-flex; align-items: center; gap: 4px; }

        .top-pro-badge { background: linear-gradient(135deg, #f59e0b, #eab308); color: white; font-weight: 800; font-size: 11px; padding: 4px 10px; border-radius: 20px; display: inline-flex; align-items: center; gap: 4px; box-shadow: 0 2px 6px rgba(245,158,11,0.3); margin-top: 4px; }
        .favorite-btn { position: absolute; top: 16px; right: 16px; background: white; border: 1px solid #e5e7eb; border-radius: 50%; width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.2s; z-index: 10; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .favorite-btn:hover { transform: scale(1.1); }
        .favorite-btn.active { background: #fee2e2; border-color: #fecaca; }

        .alert { padding: 16px; border-radius: 12px; margin-bottom: 16px; font-weight: 500; border: 1px solid transparent; }
        .alert-success { background: #ecfdf5; color: #065f46; border-color: #a7f3d0; }
        .alert-danger { background: #fef2f2; color: #991b1b; border-color: #fecaca; }
        .alert-warning { background: #fffbeb; color: #92400e; border-color: #fde68a; }
        .alert-info { background: #eff6ff; color: #1e40af; border-color: #bfdbfe; }

        .hidden { display: none !important; }
        .muted { color: #6b7280; font-style: italic; }
        .prof-group { font-weight: 800; color: #1e40af; }

        .star-rating-input { display: inline-flex; flex-direction: row-reverse; justify-content: flex-end; gap: 4px; margin-bottom: 14px; }
        .star-rating-input input[type="radio"] { display: none; }
        .star-rating-input label { font-size: 32px; color: #d1d5db; cursor: pointer; margin: 0; padding: 0 4px; transition: color 0.15s, transform 0.15s; }
        .star-rating-input label:hover,
        .star-rating-input label:hover ~ label,
        .star-rating-input input[type="radio"]:checked ~ label { color: #f59e0b; }
        .star-rating-input label:hover { transform: scale(1.1); }

        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; }
        .stat-card { background: white; border-radius: 12px; padding: 24px 16px; text-align: center; border-left: 4px solid #3b82f6; box-shadow: 0 2px 10px rgba(0,0,0,0.04); }
        .stat-card.warning { border-left-color: #f59e0b; }
        .stat-card.danger { border-left-color: #ef4444; }
        .stat-card.info { border-left-color: #06b6d4; }
        .stat-card.success { border-left-color: #10b981; }
        .stat-number { font-size: 32px; font-weight: 800; color: #1e40af; line-height: 1; }
        .stat-label { font-size: 12px; color: #6b7280; text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px; margin-top: 8px; }

        .pro-code-box { background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; padding: 20px; border-radius: 12px; text-align: center; }
        .pro-code-value { font-family: "Courier New", monospace; font-weight: 800; letter-spacing: 3px; }

        /* ✅ DESIGN COMPACT DES CARTES */
        .pros-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 16px; margin-top: 24px; }
        .pro-card { background: white; border-radius: 12px; padding: 16px; border: 1px solid #e5e7eb; box-shadow: 0 2px 8px rgba(0,0,0,0.04); display: flex; flex-direction: column; transition: transform 0.2s, box-shadow 0.2s; position: relative; overflow: hidden; }
        .pro-card:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(0,0,0,0.08); }
        .pro-card-top { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px; gap: 8px; }
        .pro-name { font-size: 16px; font-weight: 800; color: #111827; line-height: 1.2; margin-bottom: 2px; }
        .pro-meta { font-size: 12px; color: #6b7280; font-weight: 500; display: flex; align-items: center; gap: 4px; }
        .pro-desc { font-size: 13px; color: #4b5563; margin: 8px 0; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; flex-grow: 1; }
        
        .pro-actions { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin-top: 12px; }
        .pro-actions a { padding: 8px; font-size: 12px; border-radius: 6px; margin: 0; text-align: center; font-weight: 600; }
        .pro-profile-link { grid-column: span 2; background: #f3f4f6; color: #374151; font-weight: 700; }
        .pro-profile-link:hover { background: #e5e7eb; }

        .gallery-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; margin-top: 16px; }
        .gallery-grid img { width: 100%; height: 140px; object-fit: cover; border-radius: 12px; cursor: pointer; transition: transform 0.2s; border: 1px solid #e5e7eb; }
        .gallery-grid img:hover { transform: scale(1.03); }

        .admin-details { background: white; border-radius: 12px; margin-bottom: 12px; border: 1px solid #e5e7eb; overflow: hidden; }
        .admin-summary { display: flex; align-items: center; padding: 16px; cursor: pointer; list-style: none; user-select: none; background: #fafafa; }
        .admin-summary::-webkit-details-marker { display: none; }
        .admin-summary:hover { background: #f3f4f6; }
        .admin-summary-info { flex: 1; display: flex; justify-content: space-between; align-items: center; gap: 15px; }
        .admin-content { padding: 20px; border-top: 1px solid #e5e7eb; }

        footer { background: #111827; color: #9ca3af; padding: 40px 20px 20px; margin-top: 60px; }
        .footer-content { max-width: 1200px; margin: 0 auto; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 32px; }
        .footer-col h4 { color: white; margin-bottom: 16px; font-size: 15px; text-transform: uppercase; font-weight: 800; }
        .footer-col a { display: block; color: #9ca3af; text-decoration: none; padding: 6px 0; font-size: 14px; transition: color 0.2s; }
        .footer-col a:hover { color: white; }
        
        /* ✅ BOUTON FACEBOOK */
        .facebook-btn { display: inline-flex; align-items: center; justify-content: center; background: #1877F2; color: white; padding: 10px 20px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 14px; margin-top: 10px; transition: background 0.2s; }
        .facebook-btn:hover { background: #166fe5; }
        
        .footer-bottom { max-width: 1200px; margin: 32px auto 0; padding-top: 24px; border-top: 1px solid #374151; text-align: center; font-size: 13px; color: #6b7280; }

        @media (max-width: 600px) {
          header { padding: 14px 16px; }
          .header-content { flex-direction: column; text-align: center; }
          nav { justify-content: center; margin-top: 10px; }
          main { padding: 16px 12px; }
          .card { padding: 20px 16px; }
          .pros-grid { grid-template-columns: 1fr; }
          .stats-grid { grid-template-columns: 1fr 1fr; }
        }
      </style>
    </head>
    <body>
      <header>
        <div class="header-content">
          <div>
            <a href="/" class="logo" aria-label="TrouveMoi">${renderLogo()}</a>
            <div class="tagline">Site web de mise en relation client et professionnel</div>
          </div>
          ${buildMenu(proConnected)}
        </div>
      </header>
      <main>${content}</main>
      <footer>
        <div class="footer-content">
          <div class="footer-col">
            <h4>TrouveMoi</h4>
            <p style="color:#9ca3af;font-size:14px; margin-bottom: 10px;">La plateforme beninoise de mise en relation.</p>
            <a href="https://www.facebook.com/profile.php?id=61576706573118" target="_blank" class="facebook-btn">
              <svg width="18" height="18" fill="currentColor" viewBox="0 0 24 24" style="margin-right: 8px;"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.469h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.469h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/></svg>
              Suivez-nous sur Facebook
            </a>
          </div>
          <div class="footer-col"><h4>Navigation</h4><a href="/">Professionnels</a><a href="/mes-favoris">Mes favoris</a><a href="/emplois">Offres d'emploi</a><a href="/devenir-professionnel">Devenir professionnel</a><a href="/mon-espace-pro">Espace pro</a></div>
          <div class="footer-col"><h4>Informations</h4><a href="/a-propos">A propos</a><a href="/contact">Contact</a><a href="/blog">Blog</a><a href="/partenariats">Partenariats</a><a href="/conditions">Conditions</a><a href="/mentions-legales">Mentions légales</a><a href="/confidentialite">Confidentialite</a></div>
          <div class="footer-col"><h4>Contact</h4><a href="mailto:contact@trouvemoi.bj">contact@trouvemoi.bj</a></div>
        </div>
        <div class="footer-bottom">&copy; ${new Date().getFullYear()} TrouveMoi. Tous droits reserves.</div>
      </footer>
      <div id="image-modal" style="display:none; position:fixed; z-index:9999; padding-top:50px; left:0; top:0; width:100%; height:100%; overflow:auto; background-color:rgba(0,0,0,0.9); cursor:zoom-out;" onclick="this.style.display='none'"><span style="position:absolute; top:15px; right:35px; color:#fff; font-size:40px; font-weight:bold; cursor:pointer;" onclick="document.getElementById('image-modal').style.display='none'">&times;</span><img id="modal-img" style="margin: auto; display: block; max-width: 90%; max-height: 90vh; border-radius: 12px;"></div>
      
      <script>
        function zoomImage(src) { document.getElementById('image-modal').style.display = 'block'; document.getElementById('modal-img').src = src; }
        
        if ('serviceWorker' in navigator) {
          navigator.serviceWorker.register('/sw.js').catch(err => console.log('Erreur SW:', err));
        }

        async function toggleFav(e, id) {
          e.preventDefault();
          const btn = e.currentTarget;
          const res = await fetch('/api/favorite/' + id, { method: 'POST' });
          const data = await res.json();
          if (data.ok) {
            if (data.isFav) {
              btn.classList.add('active');
              btn.querySelector('svg').setAttribute('fill', '#ef4444');
              btn.querySelector('svg').setAttribute('stroke', '#ef4444');
            } else {
              btn.classList.remove('active');
              btn.querySelector('svg').setAttribute('fill', 'none');
              btn.querySelector('svg').setAttribute('stroke', '#6b7280');
            }
          }
        }

        async function getRecaptchaToken() {
          if (typeof grecaptcha === 'undefined') return "";
          return await grecaptcha.execute('6LelG_0tAAAAAGyx3z4xqCkxZ6rga6sF0RQ_RUtC', {action: 'submit'});
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
    let wa = job.contact_whatsapp.replace(/^\+/, "");
    if (!wa.startsWith("229")) wa = "229" + wa;
    b.push(`<a class="button whatsapp" href="https://wa.me/${escapeHtml(wa)}?text=${encodeURIComponent("Bonjour via TrouveMoi.")}" target="_blank">💬 WhatsApp</a>`);
  }
  return b.length ? `<div class="contact-buttons" style="display:flex; gap:10px;">${b.join("")}</div>` : "";
}

function renderPagination(currentPage, totalPages, baseUrl, queryParams = {}) {
  if (totalPages <= 1) return "";
  const buildUrl = (pageNum) => {
    const params = new URLSearchParams(queryParams);
    params.set("page", pageNum);
    return `${baseUrl}?${params.toString()}`;
  };
  let html = `<div style="display:flex; justify-content:center; align-items:center; gap:15px; margin: 30px 0; flex-wrap: wrap;">`;
  if (currentPage > 1) html += `<a href="${buildUrl(currentPage - 1)}" class="button secondary" style="margin:0">← Précédent</a>`;
  else html += `<span class="button secondary" style="margin:0; opacity:0.5; cursor:not-allowed;">← Précédent</span>`;
  html += `<span style="font-weight:bold; color:#4a5568;">Page ${currentPage} sur ${totalPages}</span>`;
  if (currentPage < totalPages) html += `<a href="${buildUrl(currentPage + 1)}" class="button secondary" style="margin:0">Suivant →</a>`;
  else html += `<span class="button secondary" style="margin:0; opacity:0.5; cursor:not-allowed;">Suivant →</span>`;
  html += `</div>`;
  return html;
}
app.get("/", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const visitorId = getOrCreateVisitorId(req, res);
    const refCode = req.query.ref;
    if (refCode) {
      res.setHeader("Set-Cookie", `tm_ref=${refCode}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${30 * 24 * 60 * 60}`);
    }

    const currentPage = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 12; const offset = (currentPage - 1) * limit;

    const totalAllProsResult = await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status = 'approved'");
    const totalAllPros = parseInt(totalAllProsResult.rows[0].count);

    const countResult = await pool.query(`SELECT COUNT(*) FROM professional_applications WHERE status = 'approved'`);
    const totalPros = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalPros / limit);

    const query = `SELECT p.id, p.full_name, p.company_name, p.phone, p.phone_public, p.city, p.neighborhood, p.profession, p.experience, p.service_description, p.service_area, p.availability, p.photo_activite_url, p.type_lieu, p.latitude, p.longitude, p.est_ouvert, 
      (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count, 
      (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating,
      EXISTS(SELECT 1 FROM client_favorites cf WHERE cf.pro_id = p.id AND cf.visitor_id = $3) AS is_favorite
      FROM professional_applications p WHERE p.status = 'approved' ORDER BY p.created_at DESC LIMIT $1 OFFSET $2`;
    const result = await pool.query(query, [limit, offset, visitorId]);

    const categoriesResult = await pool.query(`
      SELECT pr.category, COUNT(*) as count
      FROM professional_applications p
      JOIN professions pr ON p.profession = pr.name
      WHERE p.status = 'approved' AND pr.category IS NOT NULL
      GROUP BY pr.category
      ORDER BY count DESC
      LIMIT 8
    `);
    const categoriesHtml = categoriesResult.rows.map(c => `
      <a href="/recherche?category=${encodeURIComponent(c.category)}" class="button secondary" style="padding: 10px 20px; border-radius: 30px; margin: 5px; font-size: 14px; text-decoration: none; display: inline-flex; align-items: center; gap: 6px; background: white; border: 1px solid #e5e7eb; color: #374151;">
        ${escapeHtml(c.category)} <span style="background: #f3f4f6; padding: 2px 8px; border-radius: 10px; font-size: 11px; color: #6b7280;">${c.count}</span>
      </a>
    `).join("");

    const lastReviewsResult = await pool.query(`
      SELECT r.author_name, r.rating, r.comment, p.full_name, p.company_name, p.id as pro_id
      FROM reviews r
      JOIN professional_applications p ON p.id = r.pro_id
      WHERE r.status = 'approved' AND p.status = 'approved'
      ORDER BY r.created_at DESC LIMIT 3
    `);
    const lastReviewsHtml = lastReviewsResult.rows.map(rev => `
      <div class="card" style="padding: 20px; background: #fffbeb; border: 1px solid #fde68a; margin-bottom: 12px;">
        <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
          <div style="font-weight: 700; color: #111827;">${escapeHtml(rev.author_name)}</div>
          <div style="color: #f59e0b; font-size: 14px;">${renderStars(rev.rating)}</div>
        </div>
        <p style="font-size: 14px; color: #4b5563; font-style: italic;">"${escapeHtml(rev.comment || "Aucun commentaire")}"</p>
        <div style="font-size: 12px; color: #92400e; margin-top: 8px; text-align: right;">— à propos de <a href="/pro/${rev.pro_id}" style="color: #b45309; font-weight: bold;">${escapeHtml(rev.company_name || rev.full_name)}</a></div>
      </div>
    `).join("");

    const palettes = ["#d97706", "#dc2626", "#7c3aed", "#0891b2", "#db2777", "#2563eb", "#059669", "#ca8a04"];
    
    const prosCards = result.rows.map((person) => {
      const displayName = getDisplayName(person);
      const reviewsCount = Number(person.reviews_count || 0);
      const avgRating = Number(person.avg_rating || 0);
      const isTopPro = avgRating >= 4.5 && reviewsCount >= 10;
      
      let hash = 0; const key = String(person.profession);
      for (let i = 0; i < key.length; i++) { hash = ((hash << 5) - hash) + key.charCodeAt(i); hash = hash & hash; }
      const borderColor = palettes[Math.abs(hash) % palettes.length];
      
      let ratingHtml = reviewsCount > 0 
        ? `<div style="font-size: 13px; color: #ed8936; font-weight: 600;">${renderStars(avgRating)} <span style="color: #718096; font-weight: 400; font-size: 11px;">(${reviewsCount})</span></div>`
        : `<div style="font-size: 11px; color: #a0aec0; font-style: italic;">Pas encore d'avis</div>`;

      const typeBadge = person.type_lieu === 'fixe' 
        ? `<span class="badge-local">🏠 Local</span>` 
        : `<span class="badge-ambulant">🚗 Ambulant</span>`;

      let rawPhone = (person.phone || "").replace(/\D/g, "");
      if (rawPhone.startsWith("00229")) rawPhone = rawPhone.substring(5);
      if (rawPhone.startsWith("229")) rawPhone = rawPhone.substring(3);
      const cleanPhone = rawPhone;
      const waNumber = /^\d{8,10}$/.test(rawPhone) ? "229" + rawPhone : null;

      let actionButtons = "";
      if (person.phone_public && cleanPhone) {
        actionButtons = `
          <a href="tel:${escapeHtml(cleanPhone)}" class="button" style="background:#e0e7ff; color:#1e3a8a;">📞 Appeler</a>
          ${waNumber ? `<a href="https://wa.me/${waNumber}?text=${encodeURIComponent("Bonjour, je vous contacte via TrouveMoi. Je souhaiterais avoir des informations sur vos services. Merci.")}" target="_blank" class="button whatsapp">💬 WhatsApp</a>` : ""}
        `;
      } else {
        actionButtons = `
          <a href="/contact?pro=${person.id}" class="button" style="background:#e0e7ff; color:#1e3a8a; grid-column: span 2;">📩 Contacter</a>
        `;
      }

      return `
        <article class="pro-card" style="border-left: 4px solid ${borderColor};">
          <div class="favorite-btn ${person.is_favorite ? 'active' : ''}" onclick="toggleFav(event, ${person.id})" title="Ajouter aux favoris" style="top: 12px; right: 12px; width: 30px; height: 30px;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="${person.is_favorite ? '#ef4444' : 'none'}" stroke="${person.is_favorite ? '#ef4444' : '#6b7280'}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"></path></svg>
          </div>
          <div class="pro-card-top">
            <div>
              <div class="pro-name">${escapeHtml(displayName)} ${renderKycBadge()}</div>
              <div class="pro-meta" style="color: ${borderColor}; font-weight: 700; font-size: 11px; text-transform: uppercase;">${escapeHtml(person.profession)}</div>
              <div class="pro-meta">📍 ${escapeHtml(person.city)} ${person.neighborhood ? `- ${escapeHtml(person.neighborhood)}` : ""}</div>
            </div>
            <div style="text-align: right; display: flex; flex-direction: column; gap: 4px; align-items: flex-end; margin-right: 20px;">
              ${isTopPro ? `<span class="top-pro-badge" style="font-size: 9px; padding: 2px 6px;">⭐ Top</span>` : ""}
              ${typeBadge}
            </div>
          </div>
          
          <div class="pro-desc" style="font-size: 12px;">${escapeHtml(person.service_description || "")}</div>
          
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; margin-top: 4px;">
            ${ratingHtml}
            <span id="dist-${person.id}" style="font-size: 11px; font-weight: 700; color: #2563eb;"></span>
          </div>

          <div class="pro-actions" style="gap: 4px;">
            ${actionButtons}
            <a href="/pro/${encodeURIComponent(person.id)}" class="button pro-profile-link" style="padding: 6px; font-size: 11px;">Voir le profil →</a>
          </div>
        </article>
      `;
    }).join("");

    const welcomeBanner = proConnected ? `<div class="alert alert-info" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;"><div><strong>🎉 Bonjour ${escapeHtml(getDisplayName(proConnected.pro))} !</strong><br>Votre profil est en ligne.</div><a class="button success" href="/mon-espace-pro" style="margin:0;">Mon espace pro</a></div>` : "";
    
    const prosDataJS = JSON.stringify(result.rows.map(p => ({ id: p.id, lat: p.latitude, lon: p.longitude })).filter(p => p.lat && p.lon));

    const content = `
      ${welcomeBanner}
      <div style="position: relative; text-align: center; padding: 60px 20px; margin-bottom: 40px; border-radius: 24px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.15); background-image: url('https://res.cloudinary.com/gxm35ndf/image/upload/v1792582418/pros.jpg'); background-size: cover; background-position: center;">
        <div style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; background: linear-gradient(135deg, rgba(30,58,138,0.9) 0%, rgba(59,130,246,0.8) 100%); z-index: 1;"></div>
        <div style="position: relative; z-index: 2; max-width: 800px; margin: 0 auto;">
          <div style="width: 90px; height: 90px; border-radius: 50%; background: rgba(255,255,255,0.1); border: 3px solid #fbbf24; display: inline-flex; align-items: center; justify-content: center; font-size: 36px; font-weight: 900; color: white; margin-bottom: 20px;">${totalAllPros}</div>
          <div style="color: white; font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 20px;">Pros inscrits</div>
          
          <h1 style="font-size: 32px; font-weight: 800; color: white; margin-bottom: 12px; line-height: 1.2;">Trouvez le professionnel<br><span style="color: #fbbf24;">qu'il vous faut près de chez vous.</span></h1>
          <p style="font-size: 16px; color: rgba(255,255,255,0.9); margin-bottom: 30px;">Des professionnels vérifiés au Bénin, en 1 clic.</p>
          
          <a href="/recherche" class="button" style="background: #f59e0b; color: white; font-size: 18px; padding: 16px 40px; font-weight: 800; border-radius: 50px; box-shadow: 0 4px 15px rgba(245,158,11,0.4);">🔍 Rechercher un pro</a>
        </div>
      </div>

      ${categoriesResult.rows.length > 0 ? `
      <div style="text-align: center; margin-bottom: 40px;">
        <h3 style="font-size: 18px; margin-bottom: 16px; color: #374151;">Explorer par catégorie</h3>
        <div style="display: flex; flex-wrap: wrap; justify-content: center;">
          ${categoriesHtml}
        </div>
      </div>
      ` : ""}

      <div style="display: flex; justify-content: center; gap: 20px; flex-wrap: wrap; margin-bottom: 40px;">
        <a class="button" href="/devenir-professionnel" style="background: #2563eb; color: white; padding: 16px 24px; font-weight: 700; border-radius: 12px; flex: 1 1 250px;">👤 Devenir professionnel</a>
        <a class="button" href="/emplois" style="background: #10b981; color: white; padding: 16px 24px; font-weight: 700; border-radius: 12px; flex: 1 1 250px;">💼 Offres d'emploi</a>
      </div>

      <div class="alert alert-warning" style="text-align: center;"><strong>⚠️ ATTENTION :</strong> Ne payez jamais un professionnel avant de l'avoir rencontré en personne.</div>

      <h2 style="text-align: center; margin: 40px 0 20px 0;">Derniers professionnels inscrits</h2>
      <div class="pros-grid">
        ${prosCards || `<div class="card"><p style="text-align:center;">Aucun professionnel pour le moment.</p></div>`}
      </div>
      ${renderPagination(currentPage, totalPages, "/")}

      ${lastReviewsResult.rows.length > 0 ? `
      <div style="max-width: 800px; margin: 60px auto 20px auto;">
        <h2 style="text-align: center; margin-bottom: 20px;">Ce que disent les clients</h2>
        ${lastReviewsHtml}
      </div>
      ` : ""}

      <script>
        const prosGeo = ${prosDataJS};
        if (prosGeo.length > 0 && navigator.geolocation) {
          navigator.geolocation.getCurrentPosition((pos) => {
            const cLat = pos.coords.latitude, cLon = pos.coords.longitude;
            prosGeo.forEach(p => {
              const R = 6371;
              const dLat = (p.lat - cLat) * Math.PI / 180;
              const dLon = (p.lon - cLon) * Math.PI / 180;
              const a = Math.sin(dLat/2) * Math.sin(dLat/2) + Math.cos(cLat * Math.PI / 180) * Math.cos(p.lat * Math.PI / 180) * Math.sin(dLon/2) * Math.sin(dLon/2);
              const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
              const distance = (R * c).toFixed(1);
              const el = document.getElementById('dist-' + p.id);
              if (el) el.innerHTML = '📍 ' + distance + ' km';
            });
          });
        }
      </script>
    `;
    res.send(page("Accueil", content, proConnected));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Une erreur technique est survenue.</h2>", null)); }
});

app.get("/recherche", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const visitorId = getOrCreateVisitorId(req, res);
    const profession = String(req.query.profession || "").trim().slice(0, 150);
    const city = String(req.query.city || "").trim().slice(0, 100);
    const category = String(req.query.category || "").trim().slice(0, 100);
    const sort = String(req.query.sort || "pertinence").trim();
    
    const isSearching = profession !== "" || city !== "" || category !== "";
    
    const currentPage = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 12; const offset = (currentPage - 1) * limit;

    const citiesResult = await pool.query("SELECT id, name FROM cities ORDER BY display_order ASC");
    const professionsResult = await pool.query("SELECT id, name, category FROM professions ORDER BY display_order ASC");

    const professionsByCategory = {};
    for (const p of professionsResult.rows) { const cat = p.category || "Autres"; if (!professionsByCategory[cat]) professionsByCategory[cat] = []; professionsByCategory[cat].push(p.name); }

    let result = { rows: [] }; let totalPros = 0; let totalPages = 0;
    let prosSection = ""; let paginationHtml = ""; let prosDataJS = "[]";

    if (isSearching) {
      let whereClause = ` WHERE p.status = 'approved'`; const values = [];
      if (profession) { values.push(`%${profession}%`); whereClause += ` AND p.profession ILIKE $${values.length}`; }
      if (city) { values.push(`%${city}%`); whereClause += ` AND p.city ILIKE $${values.length}`; }
      if (category) { values.push(category); whereClause += ` AND p.profession IN (SELECT name FROM professions WHERE category = $${values.length})`; }

      const countResult = await pool.query(`SELECT COUNT(*) FROM professional_applications p ${whereClause}`, values);
      totalPros = parseInt(countResult.rows[0].count);
      totalPages = Math.ceil(totalPros / limit);

      let orderBy = "p.created_at DESC"; 
      if (sort === "rating") {
        orderBy = "avg_rating DESC, reviews_count DESC, p.created_at DESC";
      }

      const queryValues = [...values, visitorId, limit, offset];
      const query = `
        SELECT p.id, p.full_name, p.company_name, p.phone, p.phone_public, p.city, p.neighborhood, p.profession, p.service_description, p.type_lieu, p.latitude, p.longitude, 
        (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count, 
        (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating,
        EXISTS(SELECT 1 FROM client_favorites cf WHERE cf.pro_id = p.id AND cf.visitor_id = $${queryValues.length - 2}) AS is_favorite
        FROM professional_applications p ${whereClause} 
        ORDER BY ${orderBy} 
        LIMIT $${queryValues.length - 1} OFFSET $${queryValues.length}`;
      result = await pool.query(query, queryValues);

      const palettes = ["#d97706", "#dc2626", "#7c3aed", "#0891b2", "#db2777", "#2563eb", "#059669", "#ca8a04"];
      const prosCards = result.rows.map((person) => {
        const displayName = getDisplayName(person);
        const reviewsCount = Number(person.reviews_count || 0);
        const avgRating = Number(person.avg_rating || 0);
        const isTopPro = avgRating >= 4.5 && reviewsCount >= 10;
        
        let hash = 0; const key = String(person.profession);
        for (let i = 0; i < key.length; i++) { hash = ((hash << 5) - hash) + key.charCodeAt(i); hash = hash & hash; }
        const borderColor = palettes[Math.abs(hash) % palettes.length];
        
        let ratingHtml = reviewsCount > 0 
          ? `<div style="font-size: 13px; color: #ed8936; font-weight: 600;">${renderStars(avgRating)} <span style="color: #718096; font-weight: 400; font-size: 11px;">(${reviewsCount})</span></div>`
          : `<div style="font-size: 11px; color: #a0aec0; font-style: italic;">Pas encore d'avis</div>`;

        const typeBadge = person.type_lieu === 'fixe' ? `<span class="badge-local">🏠 Local</span>` : `<span class="badge-ambulant">🚗 Ambulant</span>`;
        
        let rawPhone = (person.phone || "").replace(/\D/g, "");
        if (rawPhone.startsWith("00229")) rawPhone = rawPhone.substring(5);
        if (rawPhone.startsWith("229")) rawPhone = rawPhone.substring(3);
        const cleanPhone = rawPhone;
        const waNumber = /^\d{8,10}$/.test(rawPhone) ? "229" + rawPhone : null;

        let actionButtons = "";
        if (person.phone_public && cleanPhone) {
          actionButtons = `
            <a href="tel:${escapeHtml(cleanPhone)}" class="button" style="background:#e0e7ff; color:#1e3a8a;">📞 Appeler</a>
            ${waNumber ? `<a href="https://wa.me/${waNumber}?text=${encodeURIComponent("Bonjour, je vous contacte via TrouveMoi. Je souhaiterais avoir des informations sur vos services. Merci.")}" target="_blank" class="button whatsapp">💬 WhatsApp</a>` : ""}
          `;
        } else {
          actionButtons = `<a href="/contact?pro=${person.id}" class="button" style="background:#e0e7ff; color:#1e3a8a; grid-column: span 2;">📩 Contacter</a>`;
        }

        return `
          <article class="pro-card" style="border-left: 4px solid ${borderColor};">
            <div class="favorite-btn ${person.is_favorite ? 'active' : ''}" onclick="toggleFav(event, ${person.id})" title="Ajouter aux favoris" style="top: 12px; right: 12px; width: 30px; height: 30px;">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="${person.is_favorite ? '#ef4444' : 'none'}" stroke="${person.is_favorite ? '#ef4444' : '#6b7280'}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"></path></svg>
            </div>
            <div class="pro-card-top">
              <div>
                <div class="pro-name">${escapeHtml(displayName)} ${renderKycBadge()}</div>
                <div class="pro-meta" style="color: ${borderColor}; font-weight: 700; font-size: 11px; text-transform: uppercase;">${escapeHtml(person.profession)}</div>
                <div class="pro-meta">📍 ${escapeHtml(person.city)} ${person.neighborhood ? `- ${escapeHtml(person.neighborhood)}` : ""}</div>
              </div>
              <div style="text-align: right; display: flex; flex-direction: column; gap: 4px; align-items: flex-end; margin-right: 20px;">
                ${isTopPro ? `<span class="top-pro-badge" style="font-size: 9px; padding: 2px 6px;">⭐ Top</span>` : ""}
                ${typeBadge}
              </div>
            </div>
            <div class="pro-desc" style="font-size: 12px;">${escapeHtml(person.service_description || "")}</div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; margin-top: 4px;">
              ${ratingHtml}
              <span id="dist-${person.id}" style="font-size: 11px; font-weight: 700; color: #2563eb;"></span>
            </div>
            <div class="pro-actions" style="gap: 4px;">
              ${actionButtons}
              <a href="/pro/${encodeURIComponent(person.id)}" class="button pro-profile-link" style="padding: 6px; font-size: 11px;">Voir le profil →</a>
            </div>
          </article>
        `;
      }).join("");

      prosSection = `<div class="pros-grid" id="pros-grid">${prosCards}</div>`;
      paginationHtml = renderPagination(currentPage, totalPages, "/recherche", { profession, city, category, sort });
      prosDataJS = JSON.stringify(result.rows.map(p => ({ id: p.id, lat: p.latitude, lon: p.longitude })).filter(p => p.lat && p.lon));
    }

    const content = `
      <div style="text-align: center; margin-bottom: 30px;">
        <h1 style="margin-bottom: 8px;">Rechercher un professionnel</h1>
        <a href="/" style="color: #6b7280; font-size: 14px; text-decoration: none;">← Retour à l'accueil</a>
      </div>
      
      <section class="card" style="max-width: 900px; margin: 0 auto 30px auto; background: #f8fafc;">
        <form action="/recherche" method="GET" style="display: flex; flex-wrap: wrap; gap: 12px;">
          <input id="profession" name="profession" list="professions-list" value="${escapeHtml(profession)}" placeholder="Métiers (ex: Maçon...)" autocomplete="off" style="flex: 1 1 200px; border: 1px solid #cbd5e0; margin: 0; padding: 16px; font-size: 16px; border-radius: 12px; font-weight: 500;">
          <datalist id="professions-list">${Object.entries(professionsByCategory).map(([cat, names]) => names.map(n => `<option value="${escapeHtml(n)}">${escapeHtml(cat)}</option>`).join("")).join("")}</datalist>
          
          <input id="city" name="city" list="cities-list" value="${escapeHtml(city)}" placeholder="Villes (ex: Cotonou...)" autocomplete="off" style="flex: 1 1 200px; border: 1px solid #cbd5e0; margin: 0; padding: 16px; font-size: 16px; border-radius: 12px; font-weight: 500;">
          <datalist id="cities-list">${citiesResult.rows.map(c => `<option value="${escapeHtml(c.name)}">`).join("")}</datalist>

          <select name="sort" style="flex: 0 0 150px; border: 1px solid #cbd5e0; margin: 0; padding: 16px; font-size: 14px; border-radius: 12px; background: white;">
            <option value="pertinence" ${sort === 'pertinence' ? 'selected' : ''}>Plus récents</option>
            <option value="rating" ${sort === 'rating' ? 'selected' : ''}>Mieux notés</option>
            <option value="distance" ${sort === 'distance' ? 'selected' : ''}>Plus proches</option>
          </select>

          <button type="submit" style="flex: 0 0 120px; border-radius: 12px; padding: 16px; margin: 0; background: #f59e0b; font-size: 16px; font-weight: 800; color: white; box-shadow: 0 4px 12px rgba(245,158,11,0.3);">🔍 Filtrer</button>
          
          ${category ? `<input type="hidden" name="category" value="${escapeHtml(category)}"><div style="width: 100%; font-size: 14px; color: #1e40af; margin-top: 8px;">Filtre actif : Catégorie <strong>${escapeHtml(category)}</strong> <a href="/recherche" style="color: #ef4444; margin-left: 10px;">(Effacer)</a></div>` : ""}
        </form>
      </section>
      
      ${isSearching ? `
        <h2 style="text-align: center; margin-bottom: 20px;">Résultats (${totalPros})</h2>
        ${prosSection} ${paginationHtml}
      ` : `
        <div style="text-align: center; padding: 60px 20px; background: white; border-radius: 20px; border: 1px dashed #cbd5e0;">
          <p style="font-size: 18px; color: #718096; margin: 0;">👆 Entrez un métier, une ville ou choisissez une catégorie.</p>
        </div>
      `}

      <script>
        const prosGeo = ${prosDataJS};
        const sortMode = "${sort}";
        
        if (prosGeo.length > 0 && navigator.geolocation) {
          navigator.geolocation.getCurrentPosition((pos) => {
            const cLat = pos.coords.latitude, cLon = pos.coords.longitude;
            prosGeo.forEach(p => {
              const R = 6371;
              const dLat = (p.lat - cLat) * Math.PI / 180;
              const dLon = (p.lon - cLon) * Math.PI / 180;
              const a = Math.sin(dLat/2) * Math.sin(dLat/2) + Math.cos(cLat * Math.PI / 180) * Math.cos(p.lat * Math.PI / 180) * Math.sin(dLon/2) * Math.sin(dLon/2);
              const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
              p.distance = (R * c);
              
              const el = document.getElementById('dist-' + p.id);
              if (el) el.innerHTML = '📍 ' + p.distance.toFixed(1) + ' km';
            });

            if (sortMode === "distance") {
              const grid = document.getElementById('pros-grid');
              if (grid) {
                const cards = Array.from(grid.children);
                cards.sort((a, b) => {
                  const idA = a.querySelector('[id^="dist-"]').id.replace('dist-', '');
                  const idB = b.querySelector('[id^="dist-"]').id.replace('dist-', '');
                  const distA = prosGeo.find(p => p.id == idA)?.distance || 99999;
                  const distB = prosGeo.find(p => p.id == idB)?.distance || 99999;
                  return distA - distB;
                });
                cards.forEach(card => grid.appendChild(card));
              }
            }
          });
        }
      </script>
    `;
    res.send(page("Recherche", content, proConnected));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Une erreur technique est survenue.</h2>", null)); }
});

app.post("/api/track/:id/:type", async (req, res) => {
  try {
    const id = Number(req.params.id);
    const type = req.params.type;
    if (!Number.isSafeInteger(id) || id < 1) return res.json({ ok: false });
    let col = "";
    if (type === "view") col = "views";
    else if (type === "phone") col = "phone_clicks";
    else if (type === "wa") col = "wa_clicks";
    else return res.json({ ok: false });

    await pool.query(`INSERT INTO pro_stats (pro_id, date, ${col}) VALUES ($1, CURRENT_DATE, 1) ON CONFLICT (pro_id, date) DO UPDATE SET ${col} = pro_stats.${col} + 1`, [id]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false }); }
});

app.post("/api/favorite/:id", async (req, res) => {
  try {
    const visitorId = getOrCreateVisitorId(req, res);
    const proId = Number(req.params.id);
    if (!Number.isSafeInteger(proId) || proId < 1) return res.json({ ok: false });

    const check = await pool.query("SELECT 1 FROM client_favorites WHERE visitor_id = $1 AND pro_id = $2", [visitorId, proId]);
    if (check.rows.length) {
      await pool.query("DELETE FROM client_favorites WHERE visitor_id = $1 AND pro_id = $2", [visitorId, proId]);
      res.json({ ok: true, isFav: false });
    } else {
      await pool.query("INSERT INTO client_favorites (visitor_id, pro_id) VALUES ($1, $2)", [visitorId, proId]);
      res.json({ ok: true, isFav: true });
    }
  } catch (e) { res.json({ ok: false }); }
});

app.get("/mes-favoris", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const visitorId = getOrCreateVisitorId(req, res);
  
  const result = await pool.query(`
    SELECT p.*, 
    (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count, 
    (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating 
    FROM professional_applications p 
    JOIN client_favorites cf ON p.id = cf.pro_id 
    WHERE cf.visitor_id = $1 AND p.status = 'approved'
    ORDER BY cf.created_at DESC
  `, [visitorId]);

  const cards = result.rows.map(person => {
    const displayName = getDisplayName(person);
    return `
      <article class="pro-card" style="border-left: 4px solid #ef4444;">
        <div class="favorite-btn active" onclick="toggleFav(event, ${person.id}).then(() => location.reload())" style="top: 12px; right: 12px; width: 30px; height: 30px;">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="#ef4444" stroke="#ef4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"></path></svg>
        </div>
        <div class="pro-card-top">
          <div>
            <div class="pro-name">${escapeHtml(displayName)} ${renderKycBadge()}</div>
            <div class="pro-meta">${escapeHtml(person.profession)}</div>
            <div class="pro-meta">📍 ${escapeHtml(person.city)}</div>
          </div>
        </div>
        <div class="pro-actions" style="margin-top: 12px; gap: 4px;">
          <a href="/pro/${person.id}" class="button pro-profile-link" style="padding: 6px; font-size: 11px;">Voir le profil →</a>
        </div>
      </article>
    `;
  }).join("");

  res.send(page("Mes Favoris", `
    <div style="text-align: center; margin-bottom: 30px;">
      <h1>❤️ Mes Favoris</h1>
      <a href="/" style="color: #6b7280; font-size: 14px;">← Retour à l'accueil</a>
    </div>
    <div class="pros-grid">
      ${cards || `<div class="card"><p style="text-align:center;">Vous n'avez pas encore de favoris. Cliquez sur le cœur d'un professionnel pour le sauvegarder ici.</p></div>`}
    </div>
  `, proConnected));
});

app.get("/pro/:id", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/");

    pool.query(`INSERT INTO pro_stats (pro_id, date, views) VALUES ($1, CURRENT_DATE, 1) ON CONFLICT (pro_id, date) DO UPDATE SET views = pro_stats.views + 1`, [id]).catch(() => {});

    const result = await pool.query(`
      SELECT p.*, (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count, (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating FROM professional_applications p WHERE p.id = $1 AND p.status = 'approved'`, [id]);
    if (!result.rows.length) return res.redirect(303, "/");
    const person = result.rows[0];

    const similarResult = await pool.query(`
      SELECT p.id, p.full_name, p.company_name, p.city, p.profession, (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') as avg_rating
      FROM professional_applications p
      WHERE p.status = 'approved' AND p.id != $1 AND (p.city = $2 OR p.profession = $3)
      ORDER BY RANDOM() LIMIT 3
    `, [id, person.city, person.profession]);
    const similarHtml = similarResult.rows.map(sim => `
      <a href="/pro/${sim.id}" class="card" style="display:block; padding:16px; text-decoration:none; margin-bottom:10px; border-left:4px solid #2563eb;">
        <div style="font-weight:700; color:#111827;">${escapeHtml(sim.company_name || sim.full_name)}</div>
        <div style="font-size:13px; color:#6b7280; margin-top:4px;">${escapeHtml(sim.profession)} à ${escapeHtml(sim.city)} • ${Number(sim.avg_rating).toFixed(1)} ⭐</div>
      </a>
    `).join("");

    const displayName = getDisplayName(person);
    
    let rawPhone = (person.phone || "").replace(/\D/g, "");
    if (rawPhone.startsWith("00229")) rawPhone = rawPhone.substring(5);
    if (rawPhone.startsWith("229")) rawPhone = rawPhone.substring(3);
    const phoneClean = rawPhone;
    const whatsappNumber = /^\d{8,10}$/.test(rawPhone) ? "229" + rawPhone : null;

    const reviewsCount = Number(person.reviews_count || 0);
    const avgRating = Number(person.avg_rating || 0);
    const isTopPro = avgRating >= 4.5 && reviewsCount >= 10;

    const reviewsResult = await pool.query(`SELECT id, author_name, rating, comment, pro_response, created_at FROM reviews WHERE pro_id = $1 AND status = 'approved' ORDER BY created_at DESC LIMIT 5`, [id]);
    const reviews = reviewsResult.rows;

    const baseUrl = `${req.protocol}://${req.get("host")}`;
    const shareText = encodeURIComponent("Decouvrez " + displayName + " (" + person.profession + ") sur TrouveMoi");
    const shareUrl = encodeURIComponent(`${baseUrl}/pro/${person.id}`);

    let contactButtons = "";
    if (person.phone_public && phoneClean) {
      contactButtons = `<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 16px;">
        <a class="button" href="tel:${escapeHtml(phoneClean)}" onclick="fetch('/api/track/${person.id}/phone', {method:'POST', keepalive:true})" style="margin: 0; background: #e0e7ff; color: #1e3a8a; font-size: 16px;">📞 Appeler</a>
        ${whatsappNumber ? `<a class="button whatsapp" href="https://wa.me/${escapeHtml(whatsappNumber)}?text=${encodeURIComponent("Bonjour, je vous contacte via TrouveMoi. Je souhaiterais avoir des informations sur vos services. Merci.")}" onclick="fetch('/api/track/${person.id}/wa', {method:'POST', keepalive:true})" target="_blank" style="margin: 0; font-size: 16px;">💬 WhatsApp</a>` : `<a class="button secondary" href="/contact?pro=${person.id}" style="margin: 0; font-size: 16px;">📩 Contacter</a>`}
      </div>
      <div style="margin-top: 12px;"><a class="button secondary" href="https://wa.me/?text=${shareText}%20-%20${shareUrl}" target="_blank" style="margin: 0; width: 100%; font-size: 14px;">📤 Partager ce profil</a></div>`;
    } else {
      contactButtons = `<div class="alert alert-info" style="font-size: 14px;">📩 Ce professionnel a choisi de ne pas afficher son numéro.</div><div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 16px;"><a class="button" href="/contact?pro=${person.id}" style="margin: 0; background: #e0e7ff; color: #1e3a8a; font-size: 16px;">📩 Contacter</a><a class="button secondary" href="https://wa.me/?text=${shareText}%20-%20${shareUrl}" target="_blank" style="margin: 0; font-size: 16px;">📤 Partager</a></div>`;
    }

    let ratingSummary = reviewsCount > 0 ? `<div style="display: flex; align-items: center; gap: 16px; padding: 16px; background: #fffbeb; border-radius: 12px; margin-bottom: 20px; border: 1px solid #fde68a;"><div style="font-size: 36px; font-weight: 800; color: #b45309;">${avgRating.toFixed(1)}</div><div><div style="font-size: 20px; color: #f59e0b;">${renderStars(avgRating)}</div><div style="font-size: 13px; color: #92400e;">Sur ${reviewsCount} avis clients</div></div></div>` : "";
    
    const reviewsHtml = reviews.map((rev) => `
      <div style="background: white; border: 1px solid #e5e7eb; padding: 16px; border-radius: 12px; margin-bottom: 12px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <div style="font-weight: 700; color: #111827;">${escapeHtml(rev.author_name)}</div>
          <div style="color: #f59e0b; font-size: 14px;">${renderStars(rev.rating)}</div>
        </div>
        <div style="font-size: 12px; color: #9ca3af; margin-bottom: 8px;">${new Date(rev.created_at).toLocaleDateString("fr-FR")}</div>
        ${rev.comment ? `<div style="color: #374151; font-size: 14px; line-height: 1.5;">${escapeHtml(rev.comment).replace(/\n/g, "<br>")}</div>` : ""}
        
        ${rev.pro_response ? `
        <div style="margin-top: 12px; padding: 12px; background: #f0fdf4; border-left: 3px solid #10b981; border-radius: 4px; font-size: 13px; color: #065f46;">
          <strong>Réponse du professionnel :</strong><br>${escapeHtml(rev.pro_response).replace(/\n/g, "<br>")}
        </div>` : ""}
      </div>
    `).join("");

    const photosGalerie = [person.photo_galerie_1, person.photo_galerie_2, person.photo_galerie_3].filter(url => url !== null && url !== "");
    let galerieHtml = "";
    if (photosGalerie.length > 0) {
      galerieHtml = `<div class="card" style="padding: 24px;"><h2 style="font-size: 18px; margin-bottom: 16px;">📸 Galerie Photos</h2><div class="gallery-grid">${photosGalerie.map(url => `<img src="${escapeHtml(url)}" onclick="zoomImage(this.src)">`).join("")}</div></div>`;
    }

    const openStatusBadge = (person.type_lieu === 'fixe' && person.est_ouvert) ? `
      <div style="margin-bottom: 16px;">
        <span class="badge" style="background:#d1fae5; color:#065f46; font-size: 14px; padding: 8px 16px; box-shadow: 0 2px 6px rgba(0,0,0,0.1);">
          🟢 Ouvert actuellement
        </span>
      </div>
    ` : "";

    const isOnLeave = person.unavailable_until && new Date(person.unavailable_until) > new Date();
    const leaveBadge = isOnLeave ? `<div class="alert alert-warning" style="margin-bottom:16px; text-align:center; font-size:14px;">🌴 Ce professionnel est actuellement indisponible jusqu'au ${new Date(person.unavailable_until).toLocaleDateString("fr-FR")}.</div>` : "";

    let horairesHtml = "";
    if (person.horaires_json) {
      const h = JSON.parse(person.horaires_json);
      const jours = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"];
      let rows = "";
      jours.forEach(j => {
        if (h[j]) rows += `<div style="display:flex; justify-content:space-between; font-size:13px; border-bottom:1px solid #e5e7eb; padding:4px 0;"><span style="text-transform:capitalize;">${j}</span><span style="font-weight:600;">${h[j].o} - ${h[j].f}</span></div>`;
        else rows += `<div style="display:flex; justify-content:space-between; font-size:13px; border-bottom:1px solid #e5e7eb; padding:4px 0;"><span style="text-transform:capitalize;">${j}</span><span style="color:#ef4444; font-weight:600;">Fermé</span></div>`;
      });
      horairesHtml = `<div style="margin-top:12px; background:white; padding:12px; border-radius:8px;">${rows}</div>`;
    } else if (person.heure_ouverture || person.heure_fermeture) {
      horairesHtml = `<p style="font-size: 14px; margin-bottom: 16px; color: #1e40af; font-weight: 600;">🕒 Horaires : ${person.heure_ouverture || '?'} - ${person.heure_fermeture || '?'}</p>`;
    }

    const content = `
      <div style="max-width: 800px; margin: 0 auto;">
        ${leaveBadge}
        <div class="card" style="text-align: center; padding: 32px 24px; position:relative;">
          <div class="favorite-btn" onclick="toggleFav(event, ${person.id})" style="top:16px; right:16px;">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#6b7280" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"></path></svg>
          </div>
          ${isTopPro ? `<div style="margin-bottom:12px;"><span class="top-pro-badge" style="font-size:14px; padding:8px 16px;">⭐ Top Pro</span></div>` : ""}
          ${openStatusBadge}
          <h1 style="color: #111827; font-size: 28px; margin-bottom: 6px;">${escapeHtml(displayName)} ${renderKycBadge("lg")}</h1>
          <div style="color: #2563eb; font-size: 16px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">${escapeHtml(person.profession)}</div>
          <div style="color: #6b7280; font-size: 15px; margin-top: 8px;">📍 ${escapeHtml(person.city)}${person.neighborhood ? ` - ${escapeHtml(person.neighborhood)}` : ""}</div>
          <div style="font-size: 22px; color: #f59e0b; margin-top: 12px; font-weight: 700;">${reviewsCount > 0 ? `${renderStars(avgRating)} <span style="font-size: 15px; color: #6b7280; font-weight: 400;">(${reviewsCount} avis)</span>` : `<span style="font-size: 15px; color: #9ca3af; font-weight: 400;">Pas encore d'avis</span>`}</div>
        </div>
        
        <div class="card">
          <h2 style="font-size: 18px; border-bottom: 2px solid #f3f4f6; padding-bottom: 12px; margin-bottom: 16px;">À propos</h2>
          <p style="font-size: 15px; line-height: 1.7; color: #374151; white-space: pre-line;">${escapeHtml(person.service_description)}</p>
          
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 24px; background: #f9fafb; padding: 16px; border-radius: 12px; border: 1px solid #e5e7eb;">
            <div><div style="font-size: 12px; color: #6b7280; text-transform: uppercase; font-weight: 700; margin-bottom: 4px;">Zone d'intervention</div><div style="font-size: 14px; font-weight: 600; color: #111827;">${person.service_area ? escapeHtml(person.service_area) : "Non spécifiée"}</div></div>
            <div><div style="font-size: 12px; color: #6b7280; text-transform: uppercase; font-weight: 700; margin-bottom: 4px;">Disponibilité</div><div style="font-size: 14px; font-weight: 600; color: #111827;">${person.availability ? escapeHtml(person.availability) : "Non spécifiée"}</div></div>
          </div>

          ${person.type_lieu === 'fixe' ? `
          <div style="margin-top: 24px; background: #eff6ff; padding: 20px; border-radius: 12px; border: 1px solid #bfdbfe;">
            <h3 style="font-size: 16px; margin-bottom: 8px; color: #1e3a8a;">📍 Localisation</h3>
            <p style="font-size: 14px; margin-bottom: 8px; color: #1e40af; font-weight: 500;">${person.adresse_exacte ? escapeHtml(person.adresse_exacte) : "Adresse non spécifiée"}</p>
            ${horairesHtml}
            ${person.latitude && person.longitude ? `
              <a href="https://www.google.com/maps/search/?api=1&query=${person.latitude},${person.longitude}" target="_blank" class="button" style="background: #2563eb; width: 100%; border-radius: 8px; margin-top:12px;">🗺️ Voir l'itinéraire sur Google Maps</a>
            ` : ""}
          </div> 
          ` : ""}

          <div style="margin-top: 24px;">${contactButtons}</div>
        </div>

        ${galerieHtml}

        <div class="card" style="background: #f9fafb;">
          <h2 style="font-size: 18px; margin-bottom: 16px;">Avis des clients (${reviewsCount})</h2>
          ${ratingSummary}${reviewsHtml || `<p style="color: #6b7280; font-style: italic; font-size: 14px;">Aucun avis pour le moment.</p>`}
          <div style="text-align: center; margin-top: 24px;"><a class="button warning" href="/pro/${person.id}/avis" style="width: 100%; font-size: 15px; margin: 0;">⭐ Laisser un avis</a></div>
        </div>

        ${similarHtml ? `
        <div style="margin-top: 24px;">
          <h2 style="font-size: 18px; margin-bottom: 16px;">Vous aimerez aussi...</h2>
          ${similarHtml}
        </div>
        ` : ""}

        <div style="text-align: center; margin-top: 24px; margin-bottom: 40px;">
          <a href="/recherche" style="color: #6b7280; font-size: 14px; text-decoration: underline; display: block; margin-bottom: 16px;">← Retour à la recherche</a>
          <a href="/contact?report=${person.id}" style="color: #ef4444; font-size: 13px; text-decoration: none; border: 1px solid #fecaca; padding: 6px 12px; border-radius: 20px; background: #fef2f2;">⚠️ Signaler ce professionnel</a>
        </div>
      </div>
    `;
    res.send(page(displayName, content, proConnected));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.get("/pro/:id/avis", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const id = Number(req.params.id);
    const result = await pool.query(`SELECT id, full_name, company_name, profession FROM professional_applications WHERE id = $1 AND status = 'approved'`, [id]);
    if (!result.rows.length) return res.redirect(303, "/");
    const person = result.rows[0];
    const displayName = getDisplayName(person);
    res.send(page("Avis", `<section class="card" style="max-width: 600px; margin: 0 auto;"><h1 style="text-align:center;">Laisser un avis</h1><div class="alert alert-info" style="text-align:center;">⭐ Avis sur <strong>${escapeHtml(displayName)}</strong>.</div><form action="/pro/${person.id}/avis" method="POST"><label>Votre nom *</label><input name="author_name" required maxlength="100"><label>Note *</label><div class="star-rating-input"><input type="radio" id="s5" name="rating" value="5" required><label for="s5">★</label><input type="radio" id="s4" name="rating" value="4"><label for="s4">★</label><input type="radio" id="s3" name="rating" value="3"><label for="s3">★</label><input type="radio" id="s2" name="rating" value="2"><label for="s2">★</label><input type="radio" id="s1" name="rating" value="1"><label for="s1">★</label></div><label>Commentaire</label><textarea name="comment" rows="4" maxlength="3000"></textarea><div style="text-align:center; margin-top:20px;"><button type="submit">Envoyer</button><a class="button secondary" href="/pro/${person.id}">Annuler</a></div></form></section>`, proConnected));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.post("/pro/:id/avis", async (req, res) => {
  const ip = req.ip || "unknown"; const now = Date.now();
  const attempts = reviewAttempts.get(ip) || { count: 0, startedAt: now };
  if (now - attempts.startedAt > 60 * 60 * 1000) { attempts.count = 0; attempts.startedAt = now; }
  if (attempts.count >= 5) return res.status(429).send(page("Trop de tentatives", "<section class='card'><h1>⏳ Trop de tentatives</h1><p>Patientez 1 heure.</p><a class='button' href='/'>Accueil</a></section>", null));
  attempts.count++; reviewAttempts.set(ip, attempts);

  try {
    const proId = Number(req.params.id);
    if (!Number.isSafeInteger(proId) || proId < 1) return res.redirect(303, "/");
    const check = await pool.query(`SELECT id FROM professional_applications WHERE id = $1 AND status = 'approved'`, [proId]);
    if (!check.rows.length) return res.redirect(303, "/");
    const ratingNum = Number(req.body.rating);
    if (!Number.isInteger(ratingNum) || ratingNum < 1 || ratingNum > 5) return res.status(400).send(page("Erreur", "<h2>Note invalide (1 a 5).</h2>", null));
    const author = String(req.body.author_name || "").trim().slice(0, 100);
    if (!author) return res.status(400).send(page("Erreur", "<h2>Nom requis.</h2>", null));
    const comment = String(req.body.comment || "").slice(0, 3000);
    await pool.query(`INSERT INTO reviews (pro_id, author_name, rating, comment, status) VALUES ($1, $2, $3, $4, 'pending')`, [proId, author, ratingNum, comment]);
    res.send(page("Succes", "<section class='card' style='text-align:center;'><h1>Merci !</h1><p>Votre avis sera examine.</p><a class='button' href='/'>Retour</a></section>", null));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.get("/emplois", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const keyword = String(req.query.keyword || "").trim(); const city = String(req.query.city || "").trim();
    const currentPage = Math.max(1, parseInt(req.query.page) || 1); const limit = 10; const offset = (currentPage - 1) * limit;

    let whereClause = ` WHERE status = 'approved' AND (expires_at IS NULL OR expires_at > NOW())`; const values = [];
    if (keyword) { values.push(`%${keyword}%`); whereClause += ` AND (job_title ILIKE $${values.length} OR company_name ILIKE $${values.length})`; }
    if (city) { values.push(`%${city}%`); whereClause += ` AND city ILIKE $${values.length}`; }

    const countResult = await pool.query(`SELECT COUNT(*) FROM job_offers ${whereClause}`, values);
    const totalJobs = parseInt(countResult.rows[0].count); const totalPages = Math.ceil(totalJobs / limit);

    const queryValues = [...values, limit, offset];
    const query = `SELECT * FROM job_offers ${whereClause} ORDER BY created_at DESC LIMIT $${queryValues.length - 1} OFFSET $${queryValues.length}`;
    const result = await pool.query(query, queryValues);

    const jobs = result.rows.map((job) => `<article class="card"><h2 style="color:#2563eb;">${escapeHtml(job.job_title)}</h2><p><span class="label">Entreprise :</span> ${escapeHtml(job.company_name)}</p><p><span class="label">Ville :</span> ${escapeHtml(job.city)}</p><p><span class="label">Contrat :</span> <span class="badge badge-processed">${escapeHtml(job.contract_type)}</span></p><p style="margin-top:16px;">${escapeHtml(job.description).replace(/\n/g, "<br>")}</p>${jobContactButtons(job)}</article>`).join("");
    const paginationHtml = renderPagination(currentPage, totalPages, "/emplois", { keyword, city });

    res.send(page("Emploi", `<h1 style="text-align: center; margin-bottom: 30px;">Offres d'emploi</h1><section class="card" style="max-width: 800px; margin: 0 auto 30px auto;"><form action="/emplois" method="GET" style="display:flex; gap:10px; flex-wrap:wrap;"><input name="keyword" value="${escapeHtml(keyword)}" placeholder="Mot clé" style="flex:1 1 200px; margin:0;"><input name="city" value="${escapeHtml(city)}" placeholder="Ville" style="flex:1 1 200px; margin:0;"><button style="margin:0; padding:14px 30px;">Rechercher</button></form></section><h2 style="text-align: center; margin-bottom: 20px;">Résultats (${totalJobs})</h2>${jobs || `<section class="card"><p style="text-align:center;">Aucune offre.</p></section>`}${paginationHtml}`, proConnected));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Une erreur est survenue.</h2>", null)); }
});
app.get("/devenir-professionnel", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const citiesResult = await pool.query("SELECT id, name FROM cities ORDER BY display_order ASC");
    const professionsResult = await pool.query("SELECT id, name, category FROM professions ORDER BY display_order ASC");

    const cityOptions = citiesResult.rows.map((c) => `<option value="${escapeHtml(c.name)}">${escapeHtml(c.name)}</option>`).join("");
    const professionsByCategory = {};
    for (const p of professionsResult.rows) { const cat = p.category || "Autres"; if (!professionsByCategory[cat]) professionsByCategory[cat] = []; professionsByCategory[cat].push(p.name); }
    const professionOptions = Object.entries(professionsByCategory).map(([category, names]) => `<optgroup label="${escapeHtml(category)}" class="prof-group">${names.map(name => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join("")}</optgroup>`).join("");

    const jours = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"];
    let horairesHtml = "";
    jours.forEach(j => {
      horairesHtml += `<div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
        <div style="width:100px; font-weight:600; text-transform:capitalize; font-size:14px;">${j}</div>
        <input type="time" name="h_${j}_o" style="margin:0; width:110px; padding:8px;">
        <span>à</span>
        <input type="time" name="h_${j}_f" style="margin:0; width:110px; padding:8px;">
        <label style="margin:0; display:flex; align-items:center; gap:4px; font-size:12px;"><input type="checkbox" name="h_${j}_ferme" value="yes" style="margin:0;"> Fermé</label>
      </div>`;
    });

   const allProfNames = professionsResult.rows.map(p => p.name);
const refFromUrl = String(req.query.ref || "").trim().toLowerCase();
const refCookie = refFromUrl || readCookie(req, "tm_ref") || "";
const warningHtml = refCookie ? `<div class="alert alert-warning" style="margin-bottom: 20px; border-left: 4px solid #f59e0b;"><strong>⚠️ AVERTISSEMENT IMPORTANT :</strong><br><br>Vous accédez à ce formulaire via un lien de parrainage.<br><br><strong>Si vous n'êtes pas un professionnel qualifié ou si votre métier n'est pas inscrit sur la plateforme TrouveMoi, veuillez ne pas continuer cette inscription.</strong><br><br>L'inscription n'est validée qu'après vérification de votre dossier (KYC). En cas de refus (faux profil, métier non inscrit sur la plateforme), les frais d'inscription ne seront pas remboursés.</div>` : "";

    const content = `
      <section class="card" style="max-width: 800px; margin: 0 auto;">
        <h1 style="text-align: center; margin-bottom: 24px;">Devenir professionnel</h1>
        ${warningHtml}
        ${BYPASS_PAYMENT ? "" : `<div class="alert alert-warning"><h3 style="color: #92400e; margin-bottom: 8px;">💳 Frais d'inscription : ${PAYMENT_AMOUNT} FCFA</h3><p style="margin: 0; font-size: 14px;">Un paiement unique de <strong>${PAYMENT_AMOUNT} FCFA</strong> est requis.</p></div>`}
        
        <form id="form-inscription" action="/candidatures" method="POST" enctype="multipart/form-data" style="background: #f8fafc; padding: 24px; border-radius: 16px; border: 1px solid #e2e8f0;">
          <input type="hidden" name="recaptcha_token" id="recaptcha_token" value="">
          
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div><label>Nom complet *</label><input name="full_name" required maxlength="150" placeholder="Jean Dupont"></div>
            <div><label>Societe (facultatif)</label><input name="company_name" maxlength="200" placeholder="Dupont BTP"></div>
          </div>
          
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div><label>Telephone *</label><input name="phone" type="tel" required maxlength="30" placeholder="0194010345" pattern="01[0-9]{8}" title="10 chiffres commençant par 01"></div>
            <div><label>NPI *</label><input name="npi" required maxlength="15" placeholder="1234567890"></div>
          </div>
          
          <div class="checkbox-block" style="background:#fff; padding:16px; border-radius:12px; border:1px solid #e2e8f0; margin-bottom:16px;"><label><input type="checkbox" name="phone_public" value="yes" checked><span><strong>Numero visible publiquement</strong></span></label></div>
          <h3 style="margin-top: 30px;">Reception code *</h3>
          <div class="checkbox-block" style="background:#fff; padding:16px; border-radius:12px; border:1px solid #e2e8f0; margin-bottom:12px;"><label><input type="radio" name="contact_preference" value="whatsapp" required> <span><strong>📱 WhatsApp</strong></span></label><div id="whatsapp-number-block" class="hidden" style="margin-top:12px;margin-left:30px"><label>Numero WhatsApp</label><input name="whatsapp_number" type="tel" maxlength="30" placeholder="0194010345" pattern="01[0-9]{8}" title="10 chiffres commençant par 01"></div></div>
          <div class="checkbox-block" style="background:#fff; padding:16px; border-radius:12px; border:1px solid #e2e8f0; margin-bottom:12px;"><label><input type="radio" name="contact_preference" value="email" required> <span><strong>✉️ Email</strong></span></label><div id="email-block" class="hidden" style="margin-top:12px;margin-left:30px"><label>Adresse email *</label><input name="contact_email" type="email" maxlength="254"></div></div>
          
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">
            <div><label>Ville *</label><select id="city" name="city" required><option value="">Choisir</option>${cityOptions}</select></div>
            <div><label>Quartier</label><select id="neighborhood" name="neighborhood"><option value="">Choisir</option></select><div id="neighborhood-other-block" class="hidden" style="margin-top:10px;"><input name="neighborhood_other" maxlength="150" placeholder="Precisez"></div></div>
          </div>

          <div style="background: #eff6ff; padding: 16px; border-radius: 12px; margin-bottom: 16px; border: 1px solid #bfdbfe; position: relative;">
            <label style="color: #1e3a8a; margin-top: 0;">🔍 Rechercher votre métier</label>
            <input type="text" id="search-profession" placeholder="Tapez pour filtrer (ex: maçon, coiffeur...)" oninput="filterProfessions()" autocomplete="off" style="border-radius: 8px; padding: 12px; margin: 0; border: 1px solid #93c5fd; width: 100%;">
            <div id="custom-suggestions" style="background: white; border: 1px solid #cbd5e0; border-radius: 0 0 8px 8px; display: none; max-height: 200px; overflow-y: auto; position: absolute; left: 16px; right: 16px; z-index: 100; box-shadow: 0 4px 6px rgba(0,0,0,0.1);"></div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div><label>Profession *</label><select id="profession" name="profession" required><option value="">Choisir</option>${professionOptions}<option value="__AUTRE__">Autre</option></select><div id="profession-other-block" class="hidden" style="margin-top:10px;"><input name="profession_other" maxlength="150" placeholder="Precisez"></div></div>
            <div><label>Experience</label><select name="experience"><option value="">Selectionnez</option><option value="Debutant">Debutant</option><option value="Moins de 2 ans">Moins de 2 ans</option><option value="2 a 5 ans">2 a 5 ans</option><option value="Plus de 5 ans">Plus de 5 ans</option></select></div>
          </div>
          <label>Description *</label><textarea name="service_description" rows="4" required maxlength="3000"></textarea>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div><label>Zones</label><input name="service_area" maxlength="300" placeholder="Cotonou et environs"></div>
            <div><label>Disponibilite</label><select name="availability"><option value="">Selectionnez</option><option value="Disponible immediatement">Disponible immediatement</option><option value="Sur rendez-vous">Sur rendez-vous</option><option value="A temps partiel">A temps partiel</option></select></div>
          </div>

          <div style="margin-top:20px; background:#f0fdf4; padding:16px; border-radius:12px; border:1px solid #bbf7d0;">
            <label style="color:#065f46;">🎁 Code de parrainage (optionnel)</label>
            <input name="referred_by" maxlength="10" value="${escapeHtml(refCookie)}" placeholder="Ex: p543ht6" style="text-transform:lowercase;">
            <p style="font-size:12px; color:#065f46; margin:0;">Si un ami vous a invité, entrez son code ici.</p>
          </div>

          <hr style="margin:32px 0;border:none;border-top:1px solid #e2e8f0">
          <h3>Localisation & Type d'activité</h3>
          <div class="checkbox-block" style="background:#fff; padding:16px; border-radius:12px; border:1px solid #e2e8f0; margin-bottom:16px;">
            <label><input type="radio" name="type_lieu" value="fixe" onclick="toggleLocalisation(true)"> <span><strong>🏠 J'ai un local fixe (Boutique, salon, garage...)</strong></span></label>
            <label style="margin-top:10px;"><input type="radio" name="type_lieu" value="ambulant" checked onclick="toggleLocalisation(false)"> <span><strong>🚗 Je me déplace chez le client (Ambulant)</strong></span></label>
          </div>

          <div id="localisation-block" class="hidden">
            <label>Adresse exacte / Point de repère</label>
            <input name="adresse_exacte" maxlength="200" placeholder="Ex: Carrefour Ste Rita, à côté de la station Total">
            
            <div style="background:#f9fafb; padding:16px; border-radius:12px; margin-bottom:16px; border:1px solid #e5e7eb;">
              <h4 style="font-size:14px; margin-bottom:12px; color:#374151;">Horaires d'ouverture</h4>
              ${horairesHtml}
            </div>

            <input type="hidden" name="latitude" id="latitude">
            <input type="hidden" name="longitude" id="longitude">
            <button type="button" onclick="getLocation()" style="background:#3b82f6; width:100%; border-radius:12px; margin-bottom:10px;">📍 Utiliser ma position actuelle</button>
            <p id="gps-status" style="text-align:center; color:#2563eb; font-weight:bold;"></p>
          </div>

          <hr style="margin:32px 0;border:none;border-top:1px solid #e2e8f0">
          <h3>Photos obligatoires (KYC)</h3>
          
          <div style="display: flex; align-items: center; gap: 16px; background: #fff; padding: 16px; border-radius: 12px; margin-bottom: 20px; border: 1px dashed #cbd5e0;">
            <img src="https://res.cloudinary.com/gxm35ndf/image/upload/v1792403314/kyc.jpg" alt="Exemple KYC" style="width: 80px; height: 80px; object-fit: cover; border-radius: 8px; border: 2px solid #e2e8f0;">
            <p style="margin: 0; font-size: 13px; color: #475569;"><strong>Exemple de photo KYC :</strong> Vous devez être de face, en tenant votre pièce d'identité à côté de votre visage, sans lunettes ni chapeau.</p>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div><label>1. Photo d'identité (visage) *</label><input id="photo_profil" name="photo_profil" type="file" accept="image/*" required></div>
            <div><label>2. Pièce d'identité (recto) *</label><input id="photo_identite" name="photo_identite" type="file" accept="image/*" required></div>
          </div>
          <label style="margin-top:16px;">3. Photo de vérification KYC (Vous + pièce) *</label>
          <input id="photo_kyc" name="photo_kyc" type="file" accept="image/*" required>
          
          <div class="checkbox-block" style="background:#fff; padding:16px; border-radius:12px; border:1px solid #e2e8f0; margin-top:24px;"><label><input type="checkbox" name="gdpr_consent" value="yes" required> <span>J'accepte la <a href="/confidentialite" target="_blank" style="color:#2563eb;">Politique de confidentialite</a>.</span></label></div>
          <div style="text-align: center; margin-top: 30px;"><button type="submit" style="padding: 16px 40px; font-size: 16px; width: 100%;">Envoyer ma candidature</button></div>
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
        
        document.getElementById('form-inscription').addEventListener('submit', async function(e) {
          if (!document.getElementById('recaptcha_token').value) {
            e.preventDefault();
            const token = await getRecaptchaToken();
            document.getElementById('recaptcha_token').value = token;
            this.submit();
          }
        });

        const allProfessionsList = ${JSON.stringify(allProfNames)};

        function filterProfessions() {
          const search = document.getElementById('search-profession').value.toLowerCase();
          const box = document.getElementById('custom-suggestions');
          
          if (search.length < 2) { 
            box.style.display = 'none'; 
            return; 
          }
          
          let html = '';
          allProfessionsList.forEach(function(profName) {
            if (profName.toLowerCase().includes(search)) {
              html += '<div onclick="selectProfession(this.innerText)" style="padding: 10px 14px; cursor: pointer; border-bottom: 1px solid #f3f4f6; font-size: 14px;">' + profName + '</div>';
            }
          });
          
          if (html) { 
            box.innerHTML = html; 
            box.style.display = 'block'; 
          } else { 
            box.style.display = 'none'; 
          }
        }

        function selectProfession(val) {
          document.getElementById('profession').value = val;
          document.getElementById('search-profession').value = val;
          document.getElementById('custom-suggestions').style.display = 'none';
          document.getElementById('profession').dispatchEvent(new Event('change'));
        }

        ['photo_profil', 'photo_identite', 'photo_kyc'].forEach(id => {
          const input = document.getElementById(id);
          if(input) {
            input.addEventListener('change', function() {
              if (this.files && this.files.length > 0) {
                this.style.border = "3px solid #10b981"; 
                this.style.backgroundColor = "#ecfdf5"; 
                if (!this.nextElementSibling || !this.nextElementSibling.classList.contains('photo-ok')) {
                  const msg = document.createElement('div');
                  msg.className = 'photo-ok';
                  msg.style.cssText = 'color: #10b981; font-size: 13px; font-weight: bold; margin-top: -10px; margin-bottom: 15px;';
                  msg.innerHTML = '✅ Photo sélectionnée';
                  this.parentNode.insertBefore(msg, this.nextSibling);
                }
              }
            });
          }
        });

        citySelect.addEventListener('change', async function() { 
          const city = citySelect.value; 
          neighborhoodSelect.innerHTML = ''; 
          neighborhoodOtherBlock.classList.add('hidden'); 
          if (!city) { neighborhoodSelect.innerHTML = '<option value="">Choisir</option>'; return; } 
          neighborhoodSelect.innerHTML = '<option value="">Chargement...</option>'; 
          try { 
            const res = await fetch('/api/neighborhoods?city=' + encodeURIComponent(city)); 
            const data = await res.json(); 
            neighborhoodSelect.innerHTML = '<option value="">Choisir</option>'; 
            for (const n of data.neighborhoods) { 
              const opt = document.createElement('option'); opt.value = n; opt.textContent = n; neighborhoodSelect.appendChild(opt); 
            } 
            const otherOpt = document.createElement('option'); otherOpt.value = '__AUTRE__'; otherOpt.textContent = 'Autre'; neighborhoodSelect.appendChild(otherOpt); 
          } catch (e) { neighborhoodSelect.innerHTML = '<option value="">Erreur</option>'; } 
        });
        
        neighborhoodSelect.addEventListener('change', function() { 
          if (neighborhoodSelect.value === '__AUTRE__') neighborhoodOtherBlock.classList.remove('hidden'); 
          else neighborhoodOtherBlock.classList.add('hidden');
        });
        
        professionSelect.addEventListener('change', function() { if (professionSelect.value === '__AUTRE__') professionOtherBlock.classList.remove('hidden'); else professionOtherBlock.classList.add('hidden'); });
        whatsappRadio.addEventListener('change', function() { if (whatsappRadio.checked) { document.getElementById('whatsapp-number-block').classList.remove('hidden'); document.getElementById('email-block').classList.add('hidden'); } });
        emailRadio.addEventListener('change', function() { if (emailRadio.checked) { document.getElementById('email-block').classList.remove('hidden'); document.getElementById('whatsapp-number-block').classList.add('hidden'); } });
        
        function toggleLocalisation(isFixe) {
          const block = document.getElementById('localisation-block');
          if (isFixe) block.classList.remove('hidden');
          else block.classList.add('hidden');
        }
        function getLocation() {
          const status = document.getElementById('gps-status');
          if (!navigator.geolocation) { status.innerText = "Non supporté."; return; }
          status.innerText = "Récupération de la position...";
          navigator.geolocation.getCurrentPosition(
            (position) => {
              document.getElementById('latitude').value = position.coords.latitude;
              document.getElementById('longitude').value = position.coords.longitude;
              status.innerText = "✅ Position GPS enregistrée !";
            },
            (error) => { status.innerText = "❌ Impossible de vous localiser."; }
          );
        }
      </script>
    `;
    res.send(page("Devenir professionnel", content, proConnected));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

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

app.post("/candidatures", upload.fields([{ name: "photo_profil", maxCount: 1 }, { name: "photo_identite", maxCount: 1 }, { name: "photo_kyc", maxCount: 1 }]), async (req, res) => {
  const recaptchaToken = req.body.recaptcha_token;
  const isHuman = await verifyRecaptcha(recaptchaToken);
  if (!isHuman) return res.status(400).send(page("Erreur", "<h2>Vérification anti-robot échouée. Veuillez réessayer.</h2>", null));

  const ip = req.ip || "unknown"; const now = Date.now();
  const attempts = contactAttempts.get(`cand_${ip}`) || { count: 0, startedAt: now };
  if (now - attempts.startedAt > 60 * 60 * 1000) { attempts.count = 0; attempts.startedAt = now; }
  if (attempts.count >= 3) return res.status(429).send(page("Trop de tentatives", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>⏳ Trop de tentatives</h1><p>Patientez 1 heure.</p></section>", null));
  attempts.count++; contactAttempts.set(`cand_${ip}`, attempts);

  const { full_name, company_name, phone, npi, phone_public, city, neighborhood, neighborhood_other, profession, profession_other, experience, service_description, service_area, availability, gdpr_consent, contact_preference, whatsapp_number, contact_email, type_lieu, adresse_exacte, latitude, longitude, referred_by } = req.body;

  if (gdpr_consent !== "yes") return res.status(400).send(page("Erreur", "<h2>Consentement RGPD obligatoire.</h2>", null));

  let cleanPhone = String(phone || "").replace(/[\s().-]/g, "");
  cleanPhone = cleanPhone.replace(/^(?:\+?229|00229)/, ""); 
  const beninPhoneRegex = /^01\d{8}$/;
  if (!beninPhoneRegex.test(cleanPhone)) {
    return res.status(400).send(page("Erreur", "<h2>Numéro invalide. Il doit commencer par 01 et contenir 10 chiffres (ex: 0194010345).</h2>", null));
  }

  let cleanWa = "";
  if (whatsapp_number) {
    cleanWa = String(whatsapp_number).replace(/[\s().-]/g, "").replace(/^(?:\+?229|00229)/, "");
    if (!beninPhoneRegex.test(cleanWa)) return res.status(400).send(page("Erreur", "<h2>Numéro WhatsApp invalide. Il doit commencer par 01 et contenir 10 chiffres.</h2>", null));
  }

  const safeNpi = String(npi || "").trim();
  if (safeNpi.length < 8) return res.status(400).send(page("Erreur", "<h2>NPI invalide (au moins 8 caractères).</h2>", null));

  try {
    const duplicateCheck = await pool.query(`SELECT id, payment_status, tracking_code, status FROM professional_applications WHERE (REGEXP_REPLACE(phone, '[()\\s.-]', '', 'g') = $1 OR npi = $2) AND status IN ('pending', 'under_review', 'approved', 'corrections_requested', 'payment_pending')`, [cleanPhone, safeNpi]);
    if (duplicateCheck.rows.length > 0) {
      const dup = duplicateCheck.rows[0];
      if (dup.status === 'payment_pending' && dup.payment_status === 'unpaid') return res.redirect(303, `/paiement/${dup.tracking_code}`);
      return res.status(409).send(page("Inscription impossible", `<section class="card" style="max-width: 600px; margin: 40px auto; text-align: center;"><h1 style="color:#ef4444; justify-content: center;">⚠️ Doublon</h1><p><strong>Un dossier existe déjà avec ce numéro ou ce NPI.</strong></p><a class="button" href="/contact">📩 Nous contacter</a></section>`, null));
    }
  } catch (dbError) { console.error("Erreur vérification doublon :", dbError.message); }

  if (!CONTACT_PREFERENCES.includes(contact_preference)) return res.status(400).send(page("Erreur", "<h2>Preference de contact invalide.</h2>", null));

  const files = req.files || {};
  const photoProfil = files.photo_profil?.[0]; const photoIdentite = files.photo_identite?.[0]; const photoKyc = files.photo_kyc?.[0];
  if (!full_name || !phone || !city || !profession || !service_description || !photoProfil || !photoIdentite || !photoKyc) return res.status(400).send(page("Erreur", "<h2>Informations ou photos manquantes.</h2>", null));

  let finalNeighborhood = (neighborhood === "__AUTRE__") ? neighborhood_other : neighborhood;
  let finalProfession = (profession === "__AUTRE__") ? profession_other : profession;
  const pref = contact_preference; const phoneIsPublic = phone_public === "yes"; const finalCompanyName = company_name && company_name.trim() ? company_name.trim() : null;

  if (!finalProfession || !String(finalProfession).trim()) return res.status(400).send(page("Erreur", "<h2>Métier manquant.</h2>", null));
  if (!finalNeighborhood || !String(finalNeighborhood).trim()) finalNeighborhood = null;
  finalProfession = String(finalProfession).trim().slice(0, 150);
  if (finalNeighborhood) finalNeighborhood = String(finalNeighborhood).trim().slice(0, 150);

  // Vérifier que le code de parrainage n'appartient pas au numéro de téléphone du candidat
  let finalReferredBy = referred_by ? String(referred_by).trim().toLowerCase() : null;
  if (finalReferredBy) {
    const parrainCheck = await pool.query("SELECT id FROM professional_applications WHERE referral_code = $1 AND phone = $2", [finalReferredBy, cleanPhone]);
    if (parrainCheck.rows.length > 0) {
      return res.status(400).send(page("Erreur", "<h2>Vous ne pouvez pas utiliser votre propre code de parrainage.</h2>", null));
    }
  }

  const jours = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"];
  let horairesObj = {};
  jours.forEach(j => {
    if (req.body[`h_${j}_ferme`] === "yes") horairesObj[j] = null;
    else if (req.body[`h_${j}_o`] && req.body[`h_${j}_f`]) horairesObj[j] = { o: req.body[`h_${j}_o`], f: req.body[`h_${j}_f`] };
    else horairesObj[j] = null;
  });
  const horairesJson = JSON.stringify(horairesObj);

  const uploadedUrls = [];
  try {
    const timestamp = Date.now();
    const profilResult = await uploadToCloudinary(photoProfil.buffer, "trouvemoi/profils", `profil_${timestamp}`); uploadedUrls.push(profilResult.secure_url);
    const identiteResult = await uploadToCloudinary(photoIdentite.buffer, "trouvemoi/identites", `identite_${timestamp}`); uploadedUrls.push(identiteResult.secure_url);
    const kycResult = await uploadToCloudinary(photoKyc.buffer, "trouvemoi/kyc", `kyc_${timestamp}`); uploadedUrls.push(kycResult.secure_url);

    let trackingCode = `SUIVI-${crypto.randomInt(10000, 100000)}`;
    
    const finalStatus = BYPASS_PAYMENT ? 'pending' : 'payment_pending';
    const finalPaymentStatus = BYPASS_PAYMENT ? 'paid' : 'unpaid';

    await pool.query(`INSERT INTO professional_applications (full_name, company_name, phone, phone_public, city, neighborhood, profession, experience, service_description, service_area, availability, npi, photo_profil_url, photo_identite_url, photo_kyc_url, photo_activite_url, contact_preference, whatsapp_number, contact_email, pro_code, tracking_code, status, payment_status, payment_amount, type_lieu, adresse_exacte, latitude, longitude, horaires_json, referred_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NULL,$16,$17,$18,NULL,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28) RETURNING id`,
      [full_name, finalCompanyName, cleanPhone, phoneIsPublic, city, finalNeighborhood, finalProfession, experience, service_description, service_area, availability, safeNpi, profilResult.secure_url, identiteResult.secure_url, kycResult.secure_url, pref, cleanWa, contact_email, trackingCode, finalStatus, finalPaymentStatus, PAYMENT_AMOUNT, type_lieu, adresse_exacte, latitude || null, longitude || null, horairesJson, finalReferredBy]);

    if (BYPASS_PAYMENT) {
      res.send(page("Succes", `<section class="card" style="max-width: 600px; margin: 40px auto; text-align: center;"><h1 style="color:#10b981;">Succès !</h1><p>Votre candidature a bien été enregistrée et est en attente d'examen.</p><div class="alert alert-info" style="margin-top:20px;"><strong>Votre code de suivi est : <span style="font-size:24px; font-family:monospace; font-weight:bold;">${escapeHtml(trackingCode)}</span></strong></div><a class="button" href="/suivi-dossier" style="margin-top:20px;">Suivre mon dossier</a></section>`, null));
    } else {
      res.redirect(303, `/paiement/${trackingCode}`);
    }
  } catch (error) {
    console.error("ERREUR COMPLETE INSERT :", error);
    if (uploadedUrls.length > 0) { await Promise.allSettled(uploadedUrls.map(url => deleteFromCloudinary(url))); }
    res.status(500).send(page("Erreur", `<h2>Impossible d'enregistrer.</h2><p style="color:red; background:#fff; padding:10px; border-radius:10px;">${escapeHtml(error.message)}</p>`, null));
  }
});
app.get("/paiement/:tracking", async (req, res) => {
  if (BYPASS_PAYMENT) return res.redirect(303, "/");
  try {
    const proConnected = await getConnectedPro(req);
    const trackingCode = String(req.params.tracking || "").trim().toUpperCase();
    if (!trackingCode) return res.redirect(303, "/");

    const result = await pool.query(`SELECT id, full_name, profession, status, payment_status, payment_amount, payment_ref, tracking_code FROM professional_applications WHERE tracking_code = $1`, [trackingCode]);
    if (!result.rows.length) return res.status(404).send(page("Introuvable", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h2>Dossier introuvable.</h2><a href='/'>Retour</a></section>", null));
    const dossier = result.rows[0];

    if (dossier.payment_status === "paid") {
      return res.send(page("Paiement confirmé", `<section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;"><h1 style="color:#10b981;">✅ Payé</h1><p>Votre dossier est en cours d'examen.</p><div class="pro-code-box" style="margin: 20px 0;"><div class="pro-code-value" style="font-size: 28px;">${escapeHtml(dossier.tracking_code)}</div></div><a class="button" href="/suivi-dossier">📋 Suivre</a></section>`, proConnected));
    }
    if (dossier.status === "approved" || dossier.status === "rejected") return res.redirect(303, `/suivi-dossier`);

    const content = `
      <section class="card" style="max-width: 600px; margin: 40px auto;">
        <div style="text-align:center; margin-bottom:24px;"><h1>💳 Finalisez l'inscription</h1></div>
        <div style="background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; padding: 24px; border-radius: 20px; text-align:center; margin-bottom:24px;"><div style="font-size:48px; font-weight:900; margin:8px 0;">${PAYMENT_AMOUNT} <span style="font-size:20px;">FCFA</span></div></div>
        <div style="background:#f8fafc; padding:16px; border-radius:12px; margin-bottom:20px; text-align:center;"><div style="font-size:24px; font-weight:800; font-family:monospace; color:#1e40af;">${escapeHtml(dossier.tracking_code)}</div></div>
        <div style="text-align:center; margin-top:32px;"><button id="pay-btn" onclick="ouvrirPaiement()" style="font-size:18px; padding:16px 48px; background:#10b981; font-weight:800;">💳 Payer ${PAYMENT_AMOUNT} FCFA</button></div>
        <div style="text-align:center; margin-top:24px; font-size:13px;"><a href="/" style="color:#6b7280;">← Payer plus tard</a></div>
      </section>
      <script src="https://cdn.kkiapay.me/k.js"></script>
      <script>
        function ouvrirPaiement() { openKkiapayWidget({ amount: ${PAYMENT_AMOUNT}, api_key: "${KKIAPAY_PUBLIC_KEY}", sandbox: ${KKIAPAY_SANDBOX}, callback: "${APP_URL}/paiement/verifier", data: "${escapeHtml(dossier.tracking_code)}", theme: "#2563eb", position: "center" }); }
        addSuccessListener(function(response) { if (response && response.transactionId) { window.location.href = "/paiement/verifier?tracking=${encodeURIComponent(dossier.tracking_code)}&transaction_id=" + encodeURIComponent(response.transactionId); } });
      </script>
    `;
    res.send(page("Paiement", content, proConnected));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur technique.</h2>", null)); }
});

app.get("/paiement/verifier", async (req, res) => {
  if (BYPASS_PAYMENT) return res.redirect(303, "/");
  try {
    const proConnected = await getConnectedPro(req);
    const trackingCode = String(req.query.tracking || "").trim().toUpperCase();
    const transactionId = String(req.query.transaction_id || "").trim();
    if (!trackingCode || !transactionId) return res.redirect(303, "/");

    const dossierResult = await pool.query(`SELECT * FROM professional_applications WHERE tracking_code = $1`, [trackingCode]);
    if (!dossierResult.rows.length) return res.redirect(303, "/");
    const dossier = dossierResult.rows[0];

    if (dossier.payment_status === "paid") return res.send(page("Déjà payé", `<section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;"><h1 style="color:#10b981;">✅ Déjà payé</h1><a class="button" href="/suivi-dossier">Voir</a></section>`, proConnected));

    const verification = await verifyKkiapayTransaction(transactionId);
    if (!verification.success) return res.status(400).send(page("Paiement échoué", `<section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;"><h1 style="color:#ef4444;">❌ Non confirmé</h1><a class="button" href="/paiement/${escapeHtml(trackingCode)}">Réessayer</a></section>`, proConnected));

    await pool.query(`UPDATE professional_applications SET payment_status = 'paid', payment_ref = $1, payment_amount = $2, payment_date = NOW(), payment_method = $3, status = 'pending' WHERE id = $4`, [transactionId, verification.amount, verification.method, dossier.id]);
    await logAdminAction("payment_received", "pro", dossier.id, `Montant: ${verification.amount} FCFA | Ref: ${transactionId}`);

    // ✅ NOUVEAU : Créditer le parrain
    if (dossier.referred_by) {
      const parrainResult = await pool.query("SELECT id FROM professional_applications WHERE referral_code = $1", [dossier.referred_by]);
      if (parrainResult.rows.length > 0) {
        await pool.query("UPDATE professional_applications SET referral_balance = referral_balance + 100 WHERE id = $1", [parrainResult.rows[0].id]);
        await logAdminAction("referral_bonus", "pro", dossier.id, `Bonus de 100 FCFA versé au parrain ${dossier.referred_by}`);
      }
    }

    res.send(page("Paiement réussi", `<section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;"><div style="font-size:64px; margin-bottom:16px;">🎉</div><h1 style="color:#10b981;">Paiement réussi !</h1><div class="pro-code-box" style="margin: 24px 0;"><div class="pro-code-value" style="font-size: 28px;">${escapeHtml(dossier.tracking_code)}</div></div><a class="button" href="/suivi-dossier" style="margin-top:16px;">📋 Suivre mon dossier</a></section>`, proConnected));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur technique.</h2>", null)); }
});

app.post("/webhooks/kkiapay", express.json({ limit: "100kb" }), async (req, res) => {
  if (BYPASS_PAYMENT) return res.status(200).json({ received: true });
  try {
    const { transactionId, data } = req.body || {};
    if (!transactionId) return res.status(200).json({ received: true });
    const verification = await verifyKkiapayTransaction(transactionId);
    if (!verification.success) return res.status(200).json({ received: true, verified: false });
    const trackingCode = String(data || "").trim().toUpperCase();
    if (!trackingCode) return res.status(200).json({ received: true });

    const dossierResult = await pool.query(`SELECT * FROM professional_applications WHERE tracking_code = $1`, [trackingCode]);
    if (!dossierResult.rows.length) return res.status(200).json({ received: true });
    const dossier = dossierResult.rows[0];

    if (dossier.payment_status !== "paid") {
      await pool.query(`UPDATE professional_applications SET payment_status = 'paid', payment_ref = $1, payment_amount = $2, payment_date = NOW(), payment_method = $3, status = 'pending' WHERE id = $4`, [transactionId, verification.amount, verification.method, dossier.id]);
      await logAdminAction("payment_received", "pro", dossier.id, `(Webhook) Ref: ${transactionId}`);
      
      // ✅ NOUVEAU : Créditer le parrain (si pas déjà fait)
      if (dossier.referred_by) {
        const parrainResult = await pool.query("SELECT id FROM professional_applications WHERE referral_code = $1", [dossier.referred_by]);
        if (parrainResult.rows.length > 0) {
          await pool.query("UPDATE professional_applications SET referral_balance = referral_balance + 100 WHERE id = $1", [parrainResult.rows[0].id]);
        }
      }
    }
    res.status(200).json({ received: true, processed: true });
  } catch (error) { res.status(200).json({ received: true, error: true }); }
});

app.get("/suivi-dossier", (req, res) => {
  res.send(page("Suivi de dossier", `<section class="card" style="max-width: 500px; margin: 40px auto;"><h1 style="text-align: center; margin-bottom: 24px;">Suivre mon dossier</h1><form action="/suivi-dossier" method="POST"><label>Code de suivi (ex: SUIVI-12345) *</label><input name="tracking_code" required placeholder="SUIVI-XXXXX" maxlength="20" style="text-transform:uppercase; text-align:center; font-size:20px; font-weight:bold;"><button type="submit" style="width: 100%; margin-top:10px;">Voir mon dossier</button></form></section>`, null));
});

app.post("/suivi-dossier", async (req, res) => {
  const ip = req.ip || "unknown"; const now = Date.now();
  const attempts = trackingAttempts.get(ip) || { count: 0, startedAt: now };
  if (now - attempts.startedAt > 15 * 60 * 1000) { attempts.count = 0; attempts.startedAt = now; }
  if (attempts.count >= 10) return res.status(429).send(page("Trop de tentatives", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>⏳ Trop de tentatives</h1></section>", null));
  attempts.count++; trackingAttempts.set(ip, attempts);

  try {
    const code = String(req.body.tracking_code || "").trim().toUpperCase();
    if (!code) return res.redirect(303, "/suivi-dossier");
    const result = await pool.query(`SELECT * FROM professional_applications WHERE tracking_code = $1`, [code]);
    if (!result.rows.length) return res.send(page("Erreur", `<section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;"><h2>Code introuvable.</h2><a href="/suivi-dossier" class="button">Réessayer</a></section>`, null));
    const pro = result.rows[0];

    let statusHtml = "";
    if (pro.status === 'payment_pending') statusHtml = `<div class="alert alert-warning" style="text-align:center;">💳 Paiement requis.<br><div style="margin-top:10px;"><a class="button" href="/paiement/${escapeHtml(pro.tracking_code)}">Payer ${PAYMENT_AMOUNT} FCFA</a></div></div>`;
    else if (pro.status === 'pending') statusHtml = `<div class="alert alert-info" style="text-align:center;">⏳ En cours d'examen.</div>`;
    else if (pro.status === 'approved') statusHtml = `<div class="alert alert-success" style="text-align:center;">✅ Approuvé !<br><br><strong>Code pro : <span style="font-size:24px;">${escapeHtml(pro.pro_code)}</span></strong><br><br><a class="button success" href="/mon-espace-pro">Espace pro</a></div>`;
    else if (pro.status === 'rejected') statusHtml = `<div class="alert alert-danger" style="text-align:center;">❌ Refusé. Motif : ${escapeHtml(pro.rejection_reason || "Non spécifié")}</div>`;
    else if (pro.status === 'corrections_requested') statusHtml = `<div class="alert alert-warning"><h3>⚠️ Corrections</h3><p><strong>Motif :</strong> ${escapeHtml(pro.rejection_reason)}</p><button onclick="document.getElementById('form-correct').classList.remove('hidden')" style="margin-top:10px; background: #f59e0b;">Corriger</button></div><div id="form-correct" class="hidden" style="margin-top:20px"><form action="/candidatures/${pro.id}/corriger" method="POST" enctype="multipart/form-data" style="background:#f8fafc; padding:20px; border-radius:12px;"><input type="hidden" name="tracking_code" value="${escapeHtml(pro.tracking_code)}"><label>Nouvelle photo d'identité</label><input type="file" name="photo_identite" accept="image/*"><label>Nouvelle photo KYC</label><input type="file" name="photo_kyc" accept="image/*"><button type="submit" class="success" style="width:100%; margin-top:10px;">Renvoyer</button></form></div>`;

    res.send(page("Mon dossier", `<section class="card" style="max-width: 600px; margin: 40px auto;"><h1 style="text-align:center;">Dossier de ${escapeHtml(pro.full_name)}</h1>${statusHtml}<p style="text-align:center; margin-top:30px;"><a href="/suivi-dossier">← Retour</a></p></section>`, null));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.post("/candidatures/:id/corriger", upload.fields([{ name: "photo_identite", maxCount: 1 }, { name: "photo_kyc", maxCount: 1 }]), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).send(page("Erreur", "<h2>ID invalide.</h2>", null));
  const files = req.files || {}; const trackingCode = String(req.body.tracking_code || "").trim().toUpperCase();
  try {
    const check = await pool.query("SELECT tracking_code FROM professional_applications WHERE id = $1", [id]);
    if (!check.rows.length || check.rows[0].tracking_code !== trackingCode) return res.status(403).send(page("Erreur", "<h2>Refuse.</h2>", null));
    if (files.photo_identite?.[0]) { const res1 = await uploadToCloudinary(files.photo_identite[0].buffer, "trouvemoi/identites", `id_corr_${Date.now()}`); await pool.query(`UPDATE professional_applications SET photo_identite_url = $1 WHERE id = $2`, [res1.secure_url, id]); }
    if (files.photo_kyc?.[0]) { const res2 = await uploadToCloudinary(files.photo_kyc[0].buffer, "trouvemoi/kyc", `kyc_corr_${Date.now()}`); await pool.query(`UPDATE professional_applications SET photo_kyc_url = $1 WHERE id = $2`, [res2.secure_url, id]); }
    await pool.query(`UPDATE professional_applications SET status = 'pending', rejection_reason = NULL WHERE id = $1`, [id]);
    res.send(page("Succes", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>Mis à jour !</h1><a href='/' class='button'>Accueil</a></section>", null));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.get("/mon-espace-pro", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) {
    return res.send(page("Espace pro", `<section class="card" style="max-width: 500px; margin: 40px auto;"><h1 style="text-align: center;">Espace pro</h1><form action="/mon-espace-pro/login" method="POST"><label>Code pro</label><input name="pro_code" required maxlength="10" placeholder="TM12345" style="text-transform:uppercase; text-align:center; font-size:20px;"><button type="submit" style="width: 100%;">Se connecter</button></form><div style="text-align:center; margin-top:20px; font-size:14px;"><p><a href="/suivi-dossier">Suivre mon dossier</a></p><p><a href="/mon-espace-pro/reinitialiser" style="color:#ef4444;">🔐 Code perdu</a></p></div></section>`, null));
  }

  let offers = [], gdprRequests = [], myReviews = [], stats = { views: 0, phone: 0, wa: 0 }, withdrawals = [];
  try {
    offers = (await pool.query(`SELECT * FROM job_offers WHERE pro_id = $1 ORDER BY created_at DESC`, [proConnected.pro.id])).rows;
    gdprRequests = (await pool.query(`SELECT * FROM gdpr_requests WHERE pro_id = $1 ORDER BY created_at DESC LIMIT 20`, [proConnected.pro.id])).rows;
    myReviews = (await pool.query(`SELECT * FROM reviews WHERE pro_id = $1 ORDER BY created_at DESC LIMIT 10`, [proConnected.pro.id])).rows;
    withdrawals = (await pool.query(`SELECT * FROM withdrawal_requests WHERE pro_id = $1 ORDER BY created_at DESC LIMIT 10`, [proConnected.pro.id])).rows;
    
    const statsRes = await pool.query(`SELECT SUM(views) as v, SUM(phone_clicks) as p, SUM(wa_clicks) as w FROM pro_stats WHERE pro_id = $1 AND date >= CURRENT_DATE - INTERVAL '30 days'`, [proConnected.pro.id]);
    if (statsRes.rows.length) { stats.views = Number(statsRes.rows[0].v || 0); stats.phone = Number(statsRes.rows[0].p || 0); stats.wa = Number(statsRes.rows[0].w || 0); }
  } catch (error) { return res.status(500).send(page("Erreur", "<h2>Erreur technique.</h2>", proConnected)); }

  const now = new Date();
  const offersHtml = offers.map((offer) => {
    const expired = offer.expires_at && new Date(offer.expires_at) < now;
    const statusLabel = JOB_STATUS_LABELS[offer.status] || offer.status;
    return `<article class="card" style="box-shadow:none; border:1px solid #e5e7eb; margin-bottom:16px;"><h2 style="font-size:18px;">${escapeHtml(offer.job_title)}</h2><p><span class="badge badge-${offer.status}">${statusLabel}</span></p><p><strong>Ville :</strong> ${escapeHtml(offer.city)}</p><div class="actions" style="margin-top:16px;">${offer.status === "approved" && !expired ? `<form action="/mon-espace-pro/offre/${offer.id}/close" method="POST" style="display:inline"><button class="warning" type="submit" style="padding:6px 12px; font-size:12px;">🔒 Cloturer</button></form>` : ""} ${offer.status === "closed" ? `<form action="/mon-espace-pro/offre/${offer.id}/reopen" method="POST" style="display:inline"><button class="success" type="submit" style="padding:6px 12px; font-size:12px;">🔓 Rouvrir</button></form>` : ""}</div></article>`;
  }).join("");

  const gdprHtml = gdprRequests.map((req) => `<article class="card" style="padding:16px; margin-bottom:10px;"><p><span class="badge badge-${req.status}">${GDPR_STATUS_LABELS[req.status]}</span> <strong>${GDPR_TYPE_LABELS[req.request_type]}</strong></p></article>`).join("");
  
  const myReviewsHtml = myReviews.map((rev) => `
    <div style="background:#f9fafb; padding:16px; border-radius:12px; margin-bottom:12px; border:1px solid #e5e7eb;">
      <div style="display:flex; justify-content:space-between; margin-bottom:8px;">
        <div style="font-weight:700;">${escapeHtml(rev.author_name)}</div>
        <div><span class="badge badge-${rev.status}">${REVIEW_STATUS_LABELS[rev.status]}</span></div>
      </div>
      <div style="color:#f59e0b; margin-bottom:8px;">${renderStars(rev.rating)}</div>
      ${rev.comment ? `<p style="margin-bottom:12px; font-size:14px; color:#4b5563;">"${escapeHtml(rev.comment)}"</p>` : ""}
      
      ${rev.pro_response ? `
        <div style="background:white; padding:12px; border-left:3px solid #10b981; font-size:13px; color:#065f46; border-radius:4px;">
          <strong>Votre réponse :</strong><br>${escapeHtml(rev.pro_response).replace(/\n/g, "<br>")}
        </div>
      ` : `
        <form action="/mon-espace-pro/avis/${rev.id}/repondre" method="POST" style="margin-top:8px;">
          <textarea name="response" placeholder="Répondre à cet avis..." required maxlength="2000" rows="2" style="width:100%; padding:8px; border-radius:8px; border:1px solid #cbd5e0; font-size:13px; margin-bottom:8px;"></textarea>
          <button type="submit" class="secondary" style="padding:6px 12px; font-size:12px; margin:0;">Répondre</button>
        </form>
      `}
    </div>
  `).join("");

  const phoneStatus = proConnected.pro.phone_public ? `<span class="badge badge-approved">Public</span>` : `<span class="badge badge-closed">Privé</span>`;
  
  const isOnLeave = proConnected.pro.unavailable_until && new Date(proConnected.pro.unavailable_until) > new Date();
  const leaveStatus = isOnLeave ? `<span class="badge badge-rejected">En congés jusqu'au ${new Date(proConnected.pro.unavailable_until).toLocaleDateString("fr-FR")}</span>` : `<span class="badge badge-approved">Actif</span>`;

  res.send(page("Espace pro", `
    <div class="card" style="background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:20px;">
      <div><h2 style="color:white; margin:0;">Bonjour ${escapeHtml(getDisplayName(proConnected.pro))} 👋</h2></div>
      <div style="background:rgba(255,255,255,0.15); padding:12px 24px; border-radius:12px; text-align:center;">
        <div style="font-size:11px; text-transform:uppercase; letter-spacing:1px;">Votre code pro</div>
        <div style="font-size:28px; font-weight:800; font-family:monospace; letter-spacing:2px;">${escapeHtml(proConnected.code)}</div>
      </div>
    </div>
    
    <div style="display:flex; gap:10px; margin-bottom:24px; flex-wrap:wrap;">
      <a class="button" href="/publier-emploi">📢 Publier une offre</a>
      <form action="/mon-espace-pro/logout" method="POST" style="display:inline; margin-left:auto;"><button class="danger" type="submit">Deconnexion</button></form>
    </div>
    
    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap:20px;">
      <section class="card">
        <h2 style="font-size:20px; margin-bottom:16px;">Mes infos</h2>
        <p style="margin-bottom:6px;"><span class="label">Nom :</span> ${escapeHtml(proConnected.pro.full_name)}</p>
        <p style="margin-bottom:6px;"><span class="label">Profession :</span> ${escapeHtml(proConnected.pro.profession)}</p>
        <p style="margin-bottom:6px;"><span class="label">Ville :</span> ${escapeHtml(proConnected.pro.city)}</p>
        <p style="margin-bottom:6px;"><span class="label">Visibilite :</span> ${phoneStatus}</p>
        <p style="margin-bottom:6px;"><span class="label">Statut :</span> ${leaveStatus}</p>

        <div style="margin-top: 20px; padding: 16px; background: #f8fafc; border-radius: 12px; border: 1px solid #e2e8f0;">
          <p style="font-weight: bold; margin-bottom: 12px; font-size:14px; color:#1e40af;">📊 Statistiques (30 derniers jours)</p>
          <div style="display:flex; justify-content:space-between; font-size:13px; margin-bottom:6px;"><span>Vues du profil :</span> <strong>${stats.views}</strong></div>
          <div style="display:flex; justify-content:space-between; font-size:13px; margin-bottom:6px;"><span>Clics "Appeler" :</span> <strong>${stats.phone}</strong></div>
          <div style="display:flex; justify-content:space-between; font-size:13px;"><span>Clics "WhatsApp" :</span> <strong>${stats.wa}</strong></div>
        </div>

        <div style="margin-top: 16px; padding: 16px; background: #fffbeb; border-radius: 12px; border: 1px solid #fde68a;">
          <form action="/mon-espace-pro/conges" method="POST" style="margin:0;">
            <label style="margin-top:0; font-size:12px;">M'absent jusqu'au :</label>
            <input type="date" name="unavailable_until" value="${proConnected.pro.unavailable_until ? new Date(proConnected.pro.unavailable_until).toISOString().split('T')[0] : ''}" style="padding:8px; margin-bottom:8px;">
            <button type="submit" class="warning" style="width: 100%; padding:8px; font-size:13px; border-radius:8px;">Enregistrer congés</button>
          </form>
        </div>

      ${proConnected.pro.type_lieu === 'fixe' ? `
      <div style="margin-top: 20px; padding: 16px; background: #eff6ff; border-radius: 12px; border: 1px solid #bfdbfe;">
        <p style="margin-bottom: 10px; font-weight: bold; font-size:14px; color:#1e40af;">Statut de la boutique :</p>
        <form action="/mon-espace-pro/toggle-status" method="POST" style="margin:0;">
          <button type="submit" class="${proConnected.pro.est_ouvert ? 'success' : 'danger'}" style="width: 100%; border-radius:8px; padding:10px;">
            ${proConnected.pro.est_ouvert ? '🟢 Ouvert (Cliquez pour fermer)' : '🔴 Fermé (Cliquez pour ouvrir)'}
          </button>
        </form>
      </div>
      ` : ""}

      <div class="actions" style="margin-top:20px; display:grid; grid-template-columns: 1fr 1fr; gap:8px;">
        <a class="button secondary" href="/mon-espace-pro/modifier-profil" style="margin:0;">✏️ Modifier profil</a>
        <a class="button secondary" href="/mon-espace-pro/modifier-telephone" style="margin:0;">👁️ Visibilité</a>
        <a class="button secondary" href="/mon-espace-pro/modifier-photo" style="margin:0;">📷 Photo</a>
        <a class="button secondary" href="/mon-espace-pro/modifier-galerie" style="margin:0;">📸 Galerie</a>
      </div>
      </section>
      
      <section class="card">
        <h2 style="font-size:20px; margin-bottom:16px;">Mes avis (${myReviews.length})</h2>
        ${myReviewsHtml || `<p class="muted">Aucun avis pour le moment.</p>`}
      </section>
    </div>

    <section class="card" style="margin-top:20px; background:#f0fdf4; border:1px solid #bbf7d0;">
      <h2 style="font-size:20px; margin-bottom:16px; color:#065f46;">🎁 Parrainage</h2>
      <p style="font-size: 14px; margin-bottom: 12px; color:#065f46;">Invitez un pro et gagnez <strong>100 FCFA</strong> dès qu'il paie son inscription.</p>
      
      <div style="background: white; padding: 12px; border-radius: 8px; margin-bottom: 12px; border:1px solid #e5e7eb;">
        <p style="font-size: 12px; color: #6b7280; margin-bottom: 4px;">Votre code de parrainage :</p>
        <div style="font-size: 24px; font-weight: 800; font-family: monospace; color: #059669;">${proConnected.pro.referral_code || 'En attente...'}</div>
      </div>

      <div style="background: white; padding: 12px; border-radius: 8px; margin-bottom: 12px; border:1px solid #e5e7eb;">
  <p style="font-size: 12px; color: #6b7280; margin-bottom: 4px;">Votre lien de parrainage (à partager) :</p>
  <div style="display: flex; gap: 8px;">
    <input id="referral-link" readonly value="https://trouvemoi.bj/devenir-professionnel?ref=${proConnected.pro.referral_code || ''}" style="width:100%; padding:8px; font-size:12px; background:#f9fafb; border:1px solid #e5e7eb; border-radius:6px;">
    <button type="button" onclick="copyRefLink()" style="margin:0; padding:8px 12px; font-size:12px; border-radius:6px; background:#10b981; color:white; white-space:nowrap;">📋 Copier</button>
  </div>
</div>
      <div style="background: white; padding: 12px; border-radius: 8px; text-align: center; margin-bottom: 12px; border:1px solid #e5e7eb;">
        <div style="font-size: 12px; color: #6b7280; text-transform: uppercase;">Solde disponible</div>
        <div style="font-size: 28px; font-weight: 800; color: #059669;">${proConnected.pro.referral_balance || 0} FCFA</div>
      </div>

      <form action="/mon-espace-pro/demander-retrait" method="POST" style="margin:0; background: white; padding: 12px; border-radius: 8px; border:1px solid #e5e7eb;">
        <label style="margin-top:0; font-size:12px;">Numéro Mobile Money (même nom que l'inscription)</label>
        <input name="phone_number" required maxlength="30" placeholder="0194010345" pattern="01[0-9]{8}" style="padding:8px; margin-bottom:8px;">
        <label style="margin-top:0; font-size:12px;">Montant à retirer (min. 1000 F)</label>
        <input name="amount" type="number" min="1000" max="${proConnected.pro.referral_balance || 0}" required style="padding:8px; margin-bottom:8px;">
        <button type="submit" class="success" style="width: 100%; padding:8px; font-size:13px; border-radius:8px;">Demander le retrait</button>
      </form>

      ${withdrawals.length > 0 ? `
      <div style="margin-top: 12px;">
        <p style="font-size: 12px; font-weight: bold; margin-bottom: 4px;">Historique des retraits :</p>
        ${withdrawals.map(w => `<div style="font-size: 12px; display:flex; justify-content:space-between; padding: 4px 0; border-bottom: 1px solid #e5e7eb;"><span>${w.amount} FCFA</span><span class="badge badge-${w.status === 'pending' ? 'pending' : 'approved'}">${w.status === 'pending' ? 'En attente' : 'Payé'}</span></div>`).join("")}
      </div>
      ` : ""}
    </section>
    
    <section class="card" style="margin-top:20px;">
      <h2 style="font-size:20px; margin-bottom:16px;">Mes offres (${offers.length})</h2>
      ${offersHtml || `<p class="muted">Aucune offre.</p>`}
    </section>
    
    <section class="card" style="margin-top:20px;">
      <h2 style="font-size:20px; margin-bottom:16px;">RGPD & Confidentialité</h2>
      <div class="actions" style="display:flex; gap:10px; flex-wrap:wrap;">
        <a class="button secondary" href="/mon-espace-pro/mes-donnees">📥 Télécharger mes données</a>
        <form action="/mon-espace-pro/demande-suppression" method="POST" style="display:inline; margin:0;">
          <button class="danger" type="submit" onclick="return confirm('⚠️ ATTENTION : Êtes-vous sûr de vouloir supprimer définitivement votre compte ? Cette action est irréversible et supprimera toutes vos données (photos, avis, offres).')">🗑️ Supprimer mon compte</button>
        </form>
      </div>
      ${gdprHtml}
    </section>
    <script>
  function copyRefLink() {
    const copyText = document.getElementById("referral-link");
    copyText.select();
    copyText.setSelectionRange(0, 99999); // Pour les téléphones
    navigator.clipboard.writeText(copyText.value).then(function() {
      alert("✅ Lien copié ! Vous pouvez le coller sur WhatsApp.");
    }).catch(function() {
      alert("❌ Impossible de copier. Veuillez le faire manuellement.");
    });
  }
</script>
  `, proConnected));
});

app.post("/mon-espace-pro/toggle-status", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (proConnected) {
    const newStatus = !proConnected.pro.est_ouvert;
    await pool.query(`UPDATE professional_applications SET est_ouvert = $1 WHERE id = $2`, [newStatus, proConnected.pro.id]);
  }
  res.redirect(303, "/mon-espace-pro");
});

app.post("/mon-espace-pro/conges", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  const date = req.body.unavailable_until;
  const val = date ? new Date(date) : null;
  await pool.query(`UPDATE professional_applications SET unavailable_until = $1 WHERE id = $2`, [val, proConnected.pro.id]);
  res.redirect(303, "/mon-espace-pro");
});

app.post("/mon-espace-pro/avis/:id/repondre", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  const id = Number(req.params.id);
  const response = String(req.body.response || "").trim().slice(0, 2000);
  if (Number.isSafeInteger(id) && id > 0 && response) {
    await pool.query(`UPDATE reviews SET pro_response = $1, pro_response_at = NOW() WHERE id = $2 AND pro_id = $3`, [response, id, proConnected.pro.id]);
  }
  res.redirect(303, "/mon-espace-pro");
});

app.post("/mon-espace-pro/demander-retrait", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  
  const amount = Number(req.body.amount);
  const phone = String(req.body.phone_number || "").trim();
  const solde = Number(proConnected.pro.referral_balance || 0);

  if (amount < 1000) return res.status(400).send(page("Erreur", "<h2>Le montant minimum de retrait est de 1 000 FCFA.</h2>", proConnected));
  if (amount > solde) return res.status(400).send(page("Erreur", "<h2>Votre solde est insuffisant.</h2>", proConnected));
  if (!/^01\d{8}$/.test(phone)) return res.status(400).send(page("Erreur", "<h2>Numéro de téléphone invalide.</h2>", proConnected));

  await pool.query("UPDATE professional_applications SET referral_balance = referral_balance - $1 WHERE id = $2", [amount, proConnected.pro.id]);
  await pool.query("INSERT INTO withdrawal_requests (pro_id, amount, phone_number) VALUES ($1, $2, $3)", [proConnected.pro.id, amount, phone]);
  
  res.redirect(303, "/mon-espace-pro");
});

app.get("/mon-espace-pro/modifier-profil", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");

  const citiesResult = await pool.query("SELECT id, name FROM cities ORDER BY display_order ASC");
  const cityOptions = citiesResult.rows.map(c => `<option value="${escapeHtml(c.name)}" ${proConnected.pro.city === c.name ? 'selected' : ''}>${escapeHtml(c.name)}</option>`).join("");
  
  let neighborhoodOptions = "";
  let currentNeighborhoodInList = false;
  if (proConnected.pro.city) {
    const cityRes = await pool.query("SELECT id FROM cities WHERE name = $1", [proConnected.pro.city]);
    if (cityRes.rows.length) {
      const neighRes = await pool.query("SELECT name FROM neighborhoods WHERE city_id = $1 ORDER BY name ASC", [cityRes.rows[0].id]);
      for (const n of neighRes.rows) {
        const sel = proConnected.pro.neighborhood === n.name;
        if (sel) currentNeighborhoodInList = true;
        neighborhoodOptions += `<option value="${escapeHtml(n.name)}" ${sel ? 'selected' : ''}>${escapeHtml(n.name)}</option>`;
      }
    }
  }
  if (proConnected.pro.neighborhood && !currentNeighborhoodInList) {
    neighborhoodOptions = `<option value="${escapeHtml(proConnected.pro.neighborhood)}" selected>${escapeHtml(proConnected.pro.neighborhood)}</option>` + neighborhoodOptions;
  }

  const h = proConnected.pro.horaires_json ? JSON.parse(proConnected.pro.horaires_json) : {};
  const jours = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"];
  let horairesHtml = "";
  jours.forEach(j => {
    const o = h[j]?.o || "";
    const f = h[j]?.f || "";
    const ferme = h[j] === null;
    horairesHtml += `<div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
      <div style="width:100px; font-weight:600; text-transform:capitalize; font-size:14px;">${j}</div>
      <input type="time" name="h_${j}_o" value="${o}" style="margin:0; width:110px; padding:8px;">
      <span>à</span>
      <input type="time" name="h_${j}_f" value="${f}" style="margin:0; width:110px; padding:8px;">
      <label style="margin:0; display:flex; align-items:center; gap:4px; font-size:12px;"><input type="checkbox" name="h_${j}_ferme" ${ferme ? 'checked' : ''} value="yes" style="margin:0;"> Fermé</label>
    </div>`;
  });

  res.send(page("Modifier Profil", `
    <section class="card" style="max-width: 600px; margin: 40px auto;">
      <h1 style="text-align:center; font-size:24px;">✏️ Modifier mon profil</h1>
      
      <form action="/mon-espace-pro/modifier-profil" method="POST" style="margin-top:24px;">
        
        <label>Ville *</label>
        <select id="city-edit" name="city" required>
          <option value="">Choisir</option>
          ${cityOptions}
        </select>

        <label>Quartier</label>
        <select id="neighborhood-edit" name="neighborhood">
          <option value="">Choisir</option>
          ${neighborhoodOptions}
          <option value="__AUTRE__">Autre (préciser)</option>
        </select>
        <div id="neighborhood-other-block-edit" class="hidden" style="margin-top:10px;">
          <input name="neighborhood_other" maxlength="150" placeholder="Précisez votre quartier">
        </div>

        <hr style="margin:24px 0; border:none; border-top:1px solid #e5e7eb;">
        <h3 style="margin-bottom:16px;">Localisation & Type d'activité</h3>

        <div style="background:#f9fafb; padding:16px; border-radius:12px; border:1px solid #e5e7eb; margin-bottom:16px;">
          <label><input type="radio" name="type_lieu" value="fixe" ${proConnected.pro.type_lieu === 'fixe' ? 'checked' : ''} onclick="toggleLocalisationEdit(true)"> <span><strong>🏠 J'ai un local fixe</strong></span></label>
          <label style="margin-top:10px;"><input type="radio" name="type_lieu" value="ambulant" ${proConnected.pro.type_lieu === 'ambulant' ? 'checked' : ''} onclick="toggleLocalisationEdit(false)"> <span><strong>🚗 Ambulant (se déplace)</strong></span></label>
        </div>

        <div id="localisation-block-edit" class="${proConnected.pro.type_lieu === 'fixe' ? '' : 'hidden'}">
          <label>Adresse exacte / Point de repère</label>
          <input name="adresse_exacte" value="${escapeHtml(proConnected.pro.adresse_exacte || '')}" maxlength="200" placeholder="Ex: Carrefour Ste Rita...">
          
          <div style="background:#f9fafb; padding:16px; border-radius:12px; margin-bottom:16px; border:1px solid #e5e7eb;">
            <h4 style="font-size:14px; margin-bottom:12px; color:#374151;">Horaires d'ouverture</h4>
            ${horairesHtml}
          </div>

          <input type="hidden" name="latitude" id="latitude-edit" value="${proConnected.pro.latitude || ''}">
          <input type="hidden" name="longitude" id="longitude-edit" value="${proConnected.pro.longitude || ''}">
          <button type="button" onclick="getLocationEdit()" style="background:#3b82f6; width:100%; margin-bottom:10px;">📍 Mettre à jour ma position actuelle</button>
          <p id="gps-status-edit" style="text-align:center; color:#2563eb; font-weight:bold;">${proConnected.pro.latitude ? 'Position GPS enregistrée.' : ''}</p>
        </div>

        <div style="text-align:center; margin-top:30px;">
          <button type="submit" class="success" style="width:100%; padding:16px;">💾 Enregistrer les modifications</button>
        </div>
      </form>
      <p style="text-align:center; margin-top:20px;"><a href="/mon-espace-pro" style="color:#6b7280;">← Retour</a></p>
    </section>
    
    <script>
      const cityEdit = document.getElementById('city-edit');
      const neighEdit = document.getElementById('neighborhood-edit');
      const neighOtherEdit = document.getElementById('neighborhood-other-block-edit');

      function toggleNeighborhoodOther() {
        if (neighEdit.value === '__AUTRE__') neighOtherEdit.classList.remove('hidden');
        else neighOtherEdit.classList.add('hidden');
      }
      neighEdit.addEventListener('change', toggleNeighborhoodOther);
      toggleNeighborhoodOther();

      cityEdit.addEventListener('change', async function() {
        const city = cityEdit.value;
        neighEdit.innerHTML = '';
        neighOtherEdit.classList.add('hidden');
        if (!city) { neighEdit.innerHTML = '<option value="">Choisir</option>'; return; }
        neighEdit.innerHTML = '<option value="">Chargement...</option>';
        try {
          const res = await fetch('/api/neighborhoods?city=' + encodeURIComponent(city));
          const data = await res.json();
          neighEdit.innerHTML = '<option value="">Choisir</option>';
          for (const n of data.neighborhoods) {
            const opt = document.createElement('option'); opt.value = n; opt.textContent = n; neighEdit.appendChild(opt);
          }
          const otherOpt = document.createElement('option'); otherOpt.value = '__AUTRE__'; otherOpt.textContent = 'Autre (préciser)'; neighEdit.appendChild(otherOpt);
        } catch (e) { neighEdit.innerHTML = '<option value="">Erreur</option>'; }
      });

      function toggleLocalisationEdit(isFixe) {
        const block = document.getElementById('localisation-block-edit');
        if (isFixe) block.classList.remove('hidden');
        else block.classList.add('hidden');
      }

      function getLocationEdit() {
        const status = document.getElementById('gps-status-edit');
        if (!navigator.geolocation) { status.innerText = "Non supporté."; return; }
        status.innerText = "Récupération...";
        navigator.geolocation.getCurrentPosition(
          (position) => {
            document.getElementById('latitude-edit').value = position.coords.latitude;
            document.getElementById('longitude-edit').value = position.coords.longitude;
            status.innerText = "✅ Nouvelle position enregistrée !";
          },
          (error) { status.innerText = "❌ Impossible de vous localiser."; }
        );
      }
    </script>
  `, proConnected));
});

app.post("/mon-espace-pro/modifier-profil", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");

  const { city, neighborhood, neighborhood_other, type_lieu, adresse_exacte, latitude, longitude } = req.body;
  
  let finalNeighborhood = neighborhood;
  if (neighborhood === "__AUTRE__") {
    const custom = String(neighborhood_other || "").trim().slice(0, 150);
    finalNeighborhood = custom || null;
  }

  const jours = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"];
  let horairesObj = {};
  jours.forEach(j => {
    if (req.body[`h_${j}_ferme`] === "yes") horairesObj[j] = null;
    else if (req.body[`h_${j}_o`] && req.body[`h_${j}_f`]) horairesObj[j] = { o: req.body[`h_${j}_o`], f: req.body[`h_${j}_f`] };
    else horairesObj[j] = null;
  });
  const horairesJson = JSON.stringify(horairesObj);

  try {
    await pool.query(
      `UPDATE professional_applications 
       SET city = $1, neighborhood = $2, type_lieu = $3, adresse_exacte = $4, 
           latitude = $5, longitude = $6, horaires_json = $7 
       WHERE id = $8`,
      [city, finalNeighborhood, type_lieu, adresse_exacte, latitude || null, longitude || null, horairesJson, proConnected.pro.id]
    );
    res.redirect(303, "/mon-espace-pro");
  } catch (e) {
    console.error(e);
    res.status(500).send(page("Erreur", "<h2>Erreur lors de la modification.</h2>", proConnected));
  }
});

app.post("/mon-espace-pro/login", async (req, res) => {
  const ip = req.ip || "unknown"; const now = Date.now(); const key = `pro_${ip}`;
  const attempts = loginAttempts.get(key) || { count: 0, startedAt: now };
  if (now - attempts.startedAt > 15 * 60 * 1000) { attempts.count = 0; attempts.startedAt = now; }
  if (attempts.count >= 10) return res.status(429).send(page("Trop de tentatives", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>⏳ Trop de tentatives</h1></section>", null));
  attempts.count++; loginAttempts.set(key, attempts);

  const code = String(req.body.pro_code || "").trim().toUpperCase();
  if (!/^TM\d{5}$/.test(code)) return res.status(400).send(page("Erreur", "<h2>Code invalide.</h2>", null));
  try {
    const result = await pool.query(`SELECT id FROM professional_applications WHERE pro_code = $1 AND status = 'approved'`, [code]);
    if (!result.rows.length) return res.status(401).send(page("Erreur", "<h2>Code incorrect.</h2>", null));
    loginAttempts.delete(key); setProCookie(res, code); res.redirect(303, "/mon-espace-pro");
  } catch (error) { res.redirect(303, "/mon-espace-pro"); }
});

app.post("/mon-espace-pro/logout", (req, res) => { clearProCookie(res); res.redirect(303, "/mon-espace-pro"); });

app.get("/mon-espace-pro/reinitialiser", (req, res) => {
  res.send(page("Réinitialiser", `<section class="card" style="max-width: 500px; margin: 40px auto;"><h1 style="text-align:center;">🔐 Réinitialiser</h1><form action="/mon-espace-pro/reinitialiser" method="POST"><label>Code de suivi *</label><input name="tracking_code" required maxlength="20" style="text-transform:uppercase; text-align:center;"><button type="submit" class="warning" style="width:100%; margin-top:10px;">🔄 Générer</button></form></section>`, null));
});

app.post("/mon-espace-pro/reinitialiser", async (req, res) => {
  const ip = req.ip || "unknown"; const now = Date.now();
  const attempts = resetAttempts.get(ip) || { count: 0, startedAt: now };
  if (now - attempts.startedAt > 15 * 60 * 1000) { attempts.count = 0; attempts.startedAt = now; }
  if (attempts.count >= 5) return res.status(429).send(page("Trop de tentatives", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>⏳ Trop de tentatives</h1></section>", null));
  attempts.count++; resetAttempts.set(ip, attempts);

  const code = String(req.body.tracking_code || "").trim().toUpperCase();
  if (!code) return res.redirect(303, "/mon-espace-pro/reinitialiser");
  try {
    const result = await pool.query(`SELECT id FROM professional_applications WHERE tracking_code = $1 AND status = 'approved'`, [code]);
    if (!result.rows.length) return res.status(404).send(page("Erreur", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h2>Introuvable.</h2></section>", null));
    const newCode = await generateUniqueProCode();
    await pool.query(`UPDATE professional_applications SET pro_code = $1, pro_code_updated_at = NOW() WHERE id = $2`, [newCode, result.rows[0].id]);
    res.send(page("Nouveau code", `<section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;"><h1 style="color:#10b981;">✅ Généré</h1><div style="background:#1e3a8a; color:white; padding:20px; border-radius:12px; margin:24px 0;"><div style="font-size:12px; opacity:0.8; text-transform:uppercase;">Votre nouveau code pro</div><div style="font-size:42px; font-weight:800; font-family:monospace; letter-spacing:4px;">${escapeHtml(newCode)}</div></div><a class="button" href="/mon-espace-pro">Se connecter</a></section>`, null));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.get("/mon-espace-pro/modifier-telephone", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  res.send(page("Modifier", `<section class="card" style="max-width: 500px; margin: 40px auto;"><h1 style="text-align:center;">Visibilité</h1><form action="/mon-espace-pro/modifier-telephone" method="POST"><div style="background:#f9fafb; padding:16px; border-radius:12px; border:1px solid #e5e7eb;"><label><input type="checkbox" name="phone_public" value="yes" ${proConnected.pro.phone_public ? "checked" : ""}> <span>Rendre mon numéro public</span></label></div><button type="submit" style="width:100%; margin-top:20px;">Enregistrer</button></form></section>`, proConnected));
});

app.post("/mon-espace-pro/modifier-telephone", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  await pool.query(`UPDATE professional_applications SET phone_public = $1 WHERE id = $2`, [req.body.phone_public === "yes", proConnected.pro.id]);
  res.redirect(303, "/mon-espace-pro");
});

app.get("/mon-espace-pro/modifier-photo", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  const hasPhoto = !!proConnected.pro.photo_activite_url;
  const currentPreview = hasPhoto ? `<img src="${escapeHtml(proConnected.pro.photo_activite_url)}" style="width: 100%; height: 220px; object-fit: cover; border-radius: 12px;">` : `<div style="width: 100%; height: 220px; border-radius: 12px; background:#e5e7eb; display:flex; align-items:center; justify-content:center; font-size:32px; opacity:0.3;">👤</div>`;
  const successMsg = req.query.success === "upload" ? `<div class="alert alert-success">✅ Photo mise à jour !</div>` : req.query.success === "delete" ? `<div class="alert alert-info">🗑️ Photo supprimée.</div>` : "";
  res.send(page("Photo", `<section class="card" style="max-width: 500px; margin: 40px auto;"><h1 style="text-align:center;">📷 Photo d'activité</h1>${successMsg}<div style="margin-bottom:24px;">${currentPreview}</div><form action="/mon-espace-pro/modifier-photo" method="POST" enctype="multipart/form-data"><input name="photo_activite" type="file" accept="image/jpeg,image/png,image/webp" required><button type="submit" style="width:100%; margin-top:10px;">📤 Enregistrer</button></form>${hasPhoto ? `<form action="/mon-espace-pro/modifier-photo/supprimer" method="POST" style="margin-top:16px;"><button class="danger" type="submit" style="width:100%;" onclick="return confirm('Supprimer ?')">🗑️ Supprimer</button></form>` : ""}<p style="text-align:center; margin-top:24px;"><a href="/mon-espace-pro">← Retour</a></p></section>`, proConnected));
});

app.post("/mon-espace-pro/modifier-photo", upload.single("photo_activite"), async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected || !req.file) return res.redirect(303, "/mon-espace-pro/modifier-photo");
  try {
    const result = await uploadToCloudinary(req.file.buffer, "trouvemoi/activites", `activite_${proConnected.pro.id}_${Date.now()}`);
    if (proConnected.pro.photo_activite_url) await deleteFromCloudinary(proConnected.pro.photo_activite_url);
    await pool.query(`UPDATE professional_applications SET photo_activite_url = $1 WHERE id = $2`, [result.secure_url, proConnected.pro.id]);
    res.redirect(303, "/mon-espace-pro/modifier-photo?success=upload");
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur upload.</h2>", proConnected)); }
});

app.post("/mon-espace-pro/modifier-photo/supprimer", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  try {
    if (proConnected.pro.photo_activite_url) await deleteFromCloudinary(proConnected.pro.photo_activite_url);
    await pool.query(`UPDATE professional_applications SET photo_activite_url = NULL WHERE id = $1`, [proConnected.pro.id]);
    res.redirect(303, "/mon-espace-pro/modifier-photo?success=delete");
  } catch (e) { res.redirect(303, "/mon-espace-pro/modifier-photo"); }
});

app.get("/mon-espace-pro/modifier-galerie", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  const successMsg = req.query.success ? `<div class="alert alert-success">✅ Galerie mise à jour !</div>` : "";
  res.send(page("Ma Galerie", `<section class="card" style="max-width: 600px; margin: 40px auto;"><h1 style="text-align:center;">📸 Ma Galerie</h1><p style="text-align:center; color:#6b7280; margin-bottom:24px;">Ajoutez jusqu'à 3 photos.</p>${successMsg}<form action="/mon-espace-pro/modifier-galerie" method="POST" enctype="multipart/form-data" style="background:#f9fafb; padding:20px; border-radius:12px;"><div style="margin-bottom:16px;"><label>Photo 1</label>${proConnected.pro.photo_galerie_1 ? `<img src="${proConnected.pro.photo_galerie_1}" style="height:80px; border-radius:8px; margin-bottom:8px; display:block;">` : ""}<input type="file" name="photo1" accept="image/*"></div><div style="margin-bottom:16px;"><label>Photo 2</label>${proConnected.pro.photo_galerie_2 ? `<img src="${proConnected.pro.photo_galerie_2}" style="height:80px; border-radius:8px; margin-bottom:8px; display:block;">` : ""}<input type="file" name="photo2" accept="image/*"></div><div style="margin-bottom:16px;"><label>Photo 3</label>${proConnected.pro.photo_galerie_3 ? `<img src="${proConnected.pro.photo_galerie_3}" style="height:80px; border-radius:8px; margin-bottom:8px; display:block;">` : ""}<input type="file" name="photo3" accept="image/*"></div><button type="submit" style="width:100%; margin-top:10px;">Enregistrer</button></form><p style="text-align:center; margin-top:24px;"><a href="/mon-espace-pro">← Retour</a></p></section>`, proConnected));
});

app.post("/mon-espace-pro/modifier-galerie", upload.fields([{ name: 'photo1', maxCount: 1 }, { name: 'photo2', maxCount: 1 }, { name: 'photo3', maxCount: 1 }]), async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  try {
    const files = req.files; let newGalerie = { 1: proConnected.pro.photo_galerie_1, 2: proConnected.pro.photo_galerie_2, 3: proConnected.pro.photo_galerie_3 };
    for (let i = 1; i <= 3; i++) { if (files && files[`photo${i}`] && files[`photo${i}`][0]) { const result = await uploadToCloudinary(files[`photo${i}`][0].buffer, "trouvemoi/galeries", `galerie_${proConnected.pro.id}_${i}_${Date.now()}`); if (newGalerie[i]) await deleteFromCloudinary(newGalerie[i]); newGalerie[i] = result.secure_url; } }
    await pool.query(`UPDATE professional_applications SET photo_galerie_1 = $1, photo_galerie_2 = $2, photo_galerie_3 = $3 WHERE id = $4`, [newGalerie[1], newGalerie[2], newGalerie[3], proConnected.pro.id]);
    res.redirect(303, "/mon-espace-pro/modifier-galerie?success=1");
  } catch (e) { res.redirect(303, "/mon-espace-pro/modifier-galerie"); }
});

app.get("/mon-espace-pro/mes-donnees", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  try {
    const offersResult = await pool.query(`SELECT * FROM job_offers WHERE pro_id = $1`, [proConnected.pro.id]);
    const gdprResult = await pool.query(`SELECT * FROM gdpr_requests WHERE pro_id = $1`, [proConnected.pro.id]);
    const reviewsResult = await pool.query(`SELECT * FROM reviews WHERE pro_id = $1`, [proConnected.pro.id]);
    const exportData = { utilisateur: proConnected.pro, offres: offersResult.rows, demandes: gdprResult.rows, avis: reviewsResult.rows };
    res.setHeader("Content-Type", "application/json"); res.setHeader("Content-Disposition", `attachment; filename="trouvemoi-${proConnected.code}.json"`); res.send(JSON.stringify(exportData, null, 2));
  } catch (e) { res.status(500).send("Erreur."); }
});

app.post("/mon-espace-pro/demande-suppression", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  await pool.query(`INSERT INTO gdpr_requests (pro_id, request_type, status, message) VALUES ($1, 'deletion', 'pending', $2)`, [proConnected.pro.id, "Demande pro"]);
  res.send(page("Demande", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>Demande envoyée</h1><a href='/mon-espace-pro' class='button'>Retour</a></section>", proConnected));
});

app.post("/mon-espace-pro/offre/:id/close", async (req, res) => { 
  const proConnected = await getConnectedPro(req); 
  if (proConnected) await pool.query(`UPDATE job_offers SET status = 'closed' WHERE id = $1 AND pro_id = $2`, [Number(req.params.id), proConnected.pro.id]); 
  res.redirect(303, "/mon-espace-pro"); 
});

app.post("/mon-espace-pro/offre/:id/reopen", async (req, res) => { 
  const proConnected = await getConnectedPro(req); 
  if (proConnected) await pool.query(`UPDATE job_offers SET status = 'approved', expires_at = NOW() + INTERVAL '${OFFER_DURATION_DAYS} days' WHERE id = $1 AND pro_id = $2 AND status = 'closed'`, [Number(req.params.id), proConnected.pro.id]); 
  res.redirect(303, "/mon-espace-pro"); 
});

app.get("/publier-emploi", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  const contractOptions = JOB_CONTRACT_TYPES.map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join("");
  res.send(page("Publier", `<section class="card" style="max-width: 700px; margin: 0 auto;"><h1 style="text-align:center;">Nouvelle offre</h1><form action="/offres-emploi" method="POST"><label>Entreprise *</label><input name="company_name" required maxlength="200" value="${escapeHtml(getDisplayName(proConnected.pro))}"><label>Poste *</label><input name="job_title" required maxlength="200"><div style="display:grid; grid-template-columns:1fr 1fr; gap:20px;"><div><label>Ville *</label><input name="city" required maxlength="100" value="${escapeHtml(proConnected.pro.city)}"></div><div><label>Contrat *</label><select name="contract_type" required><option value="">Choisir</option>${contractOptions}</select></div></div><label>Description *</label><textarea name="description" required maxlength="5000" rows="6"></textarea><div style="text-align:center; margin-top:20px;"><button type="submit" style="padding:14px 40px;">Soumettre</button><a href="/mon-espace-pro" class="button secondary">Annuler</a></div></form></section>`, proConnected));
});

app.post("/offres-emploi", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  if (!JOB_CONTRACT_TYPES.includes(req.body.contract_type)) return res.status(400).send(page("Erreur", "<h2>Type invalide.</h2>", proConnected));
  try {
    await pool.query(`INSERT INTO job_offers (company_name, job_title, city, contract_type, description, status, pro_id, expires_at) VALUES ($1,$2,$3,$4,$5,'pending',$6, NOW() + INTERVAL '15 days')`, [req.body.company_name, req.body.job_title, req.body.city, req.body.contract_type, req.body.description, proConnected.pro.id]);
    res.send(page("Succes", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>Soumise !</h1><a href='/mon-espace-pro' class='button'>Retour</a></section>", proConnected));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", proConnected)); }
});
app.get("/admin", (req, res) => {
  const session = verifySessionToken(readCookie(req, SESSION_COOKIE));
  if (session) return res.redirect(303, "/admin/dashboard");
  res.send(page("Admin", `<section class="card" style="max-width: 400px; margin: 60px auto;"><h1 style="text-align:center;">Admin</h1><form action="/admin/login" method="POST"><label>Mot de passe</label><input type="password" name="password" required style="text-align:center; font-size:20px;"><button style="width:100%; margin-top:10px;">Connexion</button></form></section>`, null));
});

app.post("/admin/login", (req, res) => {
  const now = Date.now(); const address = req.ip || "unknown";
  let current = loginAttempts.get(address);
  if (current && now - current.startedAt > 15 * 60 * 1000) { loginAttempts.delete(address); current = null; }
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
  let gdprCount = 0, prosPendingCount = 0, reviewsPendingCount = 0, msgsCount = 0, withdrawalsCount = 0;
  try {
    gdprCount = Number((await pool.query("SELECT COUNT(*) FROM gdpr_requests WHERE status = 'pending'")).rows[0].count);
    prosPendingCount = Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status = 'pending'")).rows[0].count);
    reviewsPendingCount = Number((await pool.query("SELECT COUNT(*) FROM reviews WHERE status = 'pending'")).rows[0].count);
    msgsCount = Number((await pool.query("SELECT COUNT(*) FROM contact_messages WHERE is_read = false")).rows[0].count);
    withdrawalsCount = Number((await pool.query("SELECT COUNT(*) FROM withdrawal_requests WHERE status = 'pending'")).rows[0].count);
  } catch (e) {}

  const links = [
    { href: "/admin/dashboard", label: "📊 Dashboard", badge: 0 }, 
    { href: "/admin/suivi", label: "📈 Suivi & Export", badge: 0 }, 
    { href: "/admin/candidatures", label: "📋 Candidatures", badge: prosPendingCount }, 
    { href: "/admin/avis", label: "⭐ Avis", badge: reviewsPendingCount }, 
    { href: "/admin/emplois", label: "💼 Offres", badge: 0 }, 
    { href: "/admin/messages", label: "📩 Messages", badge: msgsCount }, 
    { href: "/admin/rgpd", label: "🔐 RGPD", badge: gdprCount },
    { href: "/admin/retraits", label: "💸 Retraits", badge: withdrawalsCount },
    { href: "/admin/blog", label: "📝 Blog", badge: 0 }
  ];
  return `<section class="card" style="background:#f9fafb; border:1px solid #e5e7eb; padding:16px;"><div class="actions" style="justify-content:center; gap:10px; display:flex; flex-wrap:wrap;">${links.map(l => `<a class="button ${current === l.href ? "" : "secondary"}" href="${l.href}" style="padding:8px 16px; font-size:14px; margin:0;">${l.label}${l.badge > 0 ? ` <span class="badge badge-new">${l.badge}</span>` : ""}</a>`).join("")}</div><div style="text-align:center; margin-top:20px;"><form action="/admin/logout" method="POST"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><button class="danger" style="padding:8px 24px; font-size:14px; margin:0;">Déconnexion</button></form></div></section>`;
}

app.get("/admin/dashboard", requireAdmin, async (req, res) => {
  try {
    const stats = {
      pros: Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status = 'approved'")).rows[0].count),
      prosPending: Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status = 'pending'")).rows[0].count),
      reviews: Number((await pool.query("SELECT COUNT(*) FROM reviews WHERE status = 'pending'")).rows[0].count),
      messages: Number((await pool.query("SELECT COUNT(*) FROM contact_messages WHERE is_read = false")).rows[0].count),
      prosToday: Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE DATE(created_at) = CURRENT_DATE")).rows[0].count)
    };
    const todayResult = await pool.query(`SELECT id, full_name, profession, city, status, created_at FROM professional_applications WHERE DATE(created_at) = CURRENT_DATE ORDER BY created_at DESC`);
    const todayList = todayResult.rows.map(p => `<tr><td style="padding:12px 8px; border-bottom:1px solid #e5e7eb;"><a href="/admin/candidatures" style="color:#2563eb;">${escapeHtml(p.full_name)}</a></td><td style="padding:12px 8px; border-bottom:1px solid #e5e7eb;">${escapeHtml(p.profession)}</td><td style="padding:12px 8px; border-bottom:1px solid #e5e7eb;">${escapeHtml(p.city)}</td><td style="padding:12px 8px; border-bottom:1px solid #e5e7eb;"><span class="badge badge-${p.status}">${STATUS_LABELS[p.status]}</span></td><td style="padding:12px 8px; border-bottom:1px solid #e5e7eb;">${new Date(p.created_at).toLocaleTimeString("fr-FR", {hour: '2-digit', minute:'2-digit'})}</td></tr>`).join("");
    const todayHtml = todayResult.rows.length > 0 ? `<section class="card" style="margin-top:30px;"><h2>📅 Inscriptions du jour (${stats.prosToday})</h2><div style="overflow-x:auto;"><table style="width:100%; border-collapse:collapse; text-align:left; font-size:14px;"><thead><tr style="background:#f9fafb; border-bottom:2px solid #e5e7eb;"><th style="padding:12px 8px;">Nom</th><th style="padding:12px 8px;">Métier</th><th style="padding:12px 8px;">Ville</th><th style="padding:12px 8px;">Statut</th><th style="padding:12px 8px;">Heure</th></tr></thead><tbody>${todayList}</tbody></table></div></section>` : `<section class="card" style="margin-top:30px; text-align:center;"><p class="muted">Aucune inscription aujourd'hui.</p></section>`;
    const menu = await adminMenu("/admin/dashboard", getCsrf(req));
    res.send(page("Dashboard", `<h1 style="text-align:center; margin-bottom:30px;">Tableau de bord</h1>${menu}<div class="stats-grid" style="margin-top:30px;"><div class="stat-card"><div class="stat-number">${stats.pros}</div><div class="stat-label">Approuvés</div></div><div class="stat-card warning"><div class="stat-number">${stats.prosPending}</div><div class="stat-label">En attente</div></div><div class="stat-card danger"><div class="stat-number">${stats.reviews}</div><div class="stat-label">Avis</div></div><div class="stat-card info"><div class="stat-number">${stats.messages}</div><div class="stat-label">Messages</div></div><div class="stat-card success"><div class="stat-number" style="color: #059669;">${stats.prosToday}</div><div class="stat-label">Aujourd'hui</div></div></div>${todayHtml}`, null));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur dashboard.</h2>", null)); }
});

app.get("/admin/suivi", requireAdmin, async (req, res) => {
  try {
    const csrf = getCsrf(req);
    const currentPage = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 50;
    const offset = (currentPage - 1) * limit;

    const countResult = await pool.query(`SELECT COUNT(*) FROM professional_applications`);
    const total = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(total / limit);

    const result = await pool.query(`
      SELECT id, full_name, company_name, phone, npi, city, profession, status, payment_status, created_at, tracking_code, pro_code 
      FROM professional_applications 
      ORDER BY created_at DESC 
      LIMIT $1 OFFSET $2
    `, [limit, offset]);

    const rowsHtml = result.rows.map(p => {
      const dateStr = new Date(p.created_at).toLocaleDateString("fr-FR");
      const paymentBadge = p.payment_status === 'paid' ? '💳 Payé' : '⏳ Impayé';
      const proCode = p.pro_code || "—";
      return `
        <tr style="border-bottom: 1px solid #e5e7eb;">
          <td style="padding: 12px; font-size: 13px;">${dateStr}</td>
          <td style="padding: 12px;">
            <div style="font-weight: 700; color: #111827;">${escapeHtml(p.full_name)}</div>
            <div style="font-size: 12px; color: #6b7280;">${escapeHtml(p.phone)}</div>
          </td>
          <td style="padding: 12px; font-size: 13px;">${escapeHtml(p.profession)}<br><span style="color:#6b7280; font-size:11px;">${escapeHtml(p.city)}</span></td>
          <td style="padding: 12px; font-size: 13px;"><code>${escapeHtml(p.npi)}</code></td>
          <td style="padding: 12px; font-size: 13px;"><span class="badge badge-${p.status}">${STATUS_LABELS[p.status]}</span></td>
          <td style="padding: 12px; font-size: 13px;">${paymentBadge}</td>
          <td style="padding: 12px; font-size: 13px;"><code>${escapeHtml(proCode)}</code></td>
        </tr>
      `;
    }).join("");

    const menu = await adminMenu("/admin/suivi", csrf);
    const paginationHtml = renderPagination(currentPage, totalPages, "/admin/suivi");

    res.send(page("Suivi des Pros", `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h1 style="margin: 0;">Tableau de suivi</h1>
        <a href="/admin/suivi/export" class="button success" style="margin: 0;">📥 Exporter pour Excel (CSV)</a>
      </div>
      ${menu}
      
      <section class="card" style="margin-top: 20px; overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse; text-align: left;">
          <thead>
            <tr style="background: #f9fafb; border-bottom: 2px solid #e5e7eb;">
              <th style="padding: 12px; font-size: 12px; color: #6b7280; text-transform: uppercase;">Date</th>
              <th style="padding: 12px; font-size: 12px; color: #6b7280; text-transform: uppercase;">Professionnel</th>
              <th style="padding: 12px; font-size: 12px; color: #6b7280; text-transform: uppercase;">Métier / Ville</th>
              <th style="padding: 12px; font-size: 12px; color: #6b7280; text-transform: uppercase;">NPI</th>
              <th style="padding: 12px; font-size: 12px; color: #6b7280; text-transform: uppercase;">Statut</th>
              <th style="padding: 12px; font-size: 12px; color: #6b7280; text-transform: uppercase;">Paiement</th>
              <th style="padding: 12px; font-size: 12px; color: #6b7280; text-transform: uppercase;">Code Pro</th>
            </tr>
          </thead>
          <tbody>
            ${rowsHtml || `<tr><td colspan="7" style="text-align: center; padding: 20px; color: #6b7280;">Aucun professionnel enregistré.</td></tr>`}
          </tbody>
        </table>
      </section>
      ${paginationHtml}
    `, null));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.get("/admin/suivi/export", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT full_name, company_name, phone, npi, city, profession, status, payment_status, created_at, tracking_code, pro_code 
      FROM professional_applications 
      ORDER BY created_at DESC
    `);

    let csv = "Date;Nom;Entreprise;Telephone;NPI;Ville;Metier;Statut;Paiement;Code de suivi;Code Pro\n";
    for (const p of result.rows) {
      const dateStr = new Date(p.created_at).toLocaleDateString("fr-FR");
      const status = STATUS_LABELS[p.status] || p.status;
      const payment = p.payment_status === 'paid' ? 'Payé' : 'Impayé';
      const clean = (val) => `"${String(val || '').replace(/;/g, ',').replace(/"/g, '""')}"`;
      csv += `${dateStr};${clean(p.full_name)};${clean(p.company_name)};${clean(p.phone)};${clean(p.npi)};${clean(p.city)};${clean(p.profession)};${clean(status)};${payment};${clean(p.tracking_code)};${clean(p.pro_code)}\n`;
    }

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="suivi_professionnels_${new Date().toISOString().slice(0,10)}.csv"`);
    res.send("\uFEFF" + csv);
  } catch (error) { res.status(500).send("Erreur lors de l'export."); }
});

app.get("/admin/candidatures", requireAdmin, async (req, res) => {
  try {
    const csrf = getCsrf(req); const currentPage = Math.max(1, parseInt(req.query.page) || 1); const limit = 10; const offset = (currentPage - 1) * limit; const filter = String(req.query.filter || "all");
    let filterClause = "";
    if (filter === "unpaid") filterClause = "WHERE payment_status = 'unpaid' AND status = 'payment_pending'";
    else if (filter === "pending") filterClause = "WHERE status = 'pending'";
    else if (filter === "approved") filterClause = "WHERE status = 'approved'";

    const countResult = await pool.query(`SELECT COUNT(*) FROM professional_applications ${filterClause}`);
    const total = parseInt(countResult.rows[0].count); const totalPages = Math.ceil(total / limit);
    const result = await pool.query(`SELECT p.* FROM professional_applications p ${filterClause} ORDER BY CASE WHEN p.status = 'payment_pending' THEN 0 WHEN p.status = 'pending' THEN 1 ELSE 2 END, p.created_at DESC LIMIT $1 OFFSET $2`, [limit, offset]);

    const applications = result.rows.map(c => {
      const statusOptions = ALLOWED_STATUSES.map(s => `<option value="${s}" ${c.status === s ? "selected" : ""}>${STATUS_LABELS[s]}</option>`).join("");
      const paymentBadge = c.payment_status === "paid" ? `<span class="badge" style="background:#d1fae5;color:#065f46;">💳 Payé ${c.payment_amount || 500} FCFA</span>` : c.status === "payment_pending" ? `<span class="badge" style="background:#fef3c7;color:#92400e;">⏳ Impayé</span>` : `<span class="badge" style="background:#e5e7eb;color:#374151;">—</span>`;
      
      const photos = `<div style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom:16px;">${c.photo_profil_url ? `<div style="text-align:center;"><img src="${escapeHtml(c.photo_profil_url)}" style="width:80px; height:80px; object-fit:cover; border-radius:8px; border:2px solid #3b82f6; cursor:pointer;" onclick="zoomImage(this.src)"><div style="font-size:11px; margin-top:4px; font-weight:600;">Identité</div></div>` : ""}${c.photo_identite_url ? `<div style="text-align:center;"><img src="${escapeHtml(c.photo_identite_url)}" style="width:80px; height:80px; object-fit:cover; border-radius:8px; border:2px solid #ef4444; cursor:pointer;" onclick="zoomImage(this.src)"><div style="font-size:11px; margin-top:4px; font-weight:600;">Pièce</div></div>` : ""}${c.photo_kyc_url ? `<div style="text-align:center;"><img src="${escapeHtml(c.photo_kyc_url)}" style="width:80px; height:80px; object-fit:cover; border-radius:8px; border:2px solid #f59e0b; cursor:pointer;" onclick="zoomImage(this.src)"><div style="font-size:11px; margin-top:4px; font-weight:600; color:#b45309;">KYC</div></div>` : ""}</div>`;

      let codeBlock = "";
      if (c.pro_code) {
        const waNumber = c.whatsapp_number || c.phone; const cleanNumber = waNumber.replace(/[()\s.-]/g, "").replace(/^\+/, ""); const baseUrl = `${req.protocol}://${req.get("host")}`; const waMessage = encodeURIComponent(`Bonjour ${c.full_name}, votre candidature sur TrouveMoi a ete approuvee ✅\n\nVotre code : ${c.pro_code}\n\nConnexion : ${baseUrl}/mon-espace-pro`);
        codeBlock = `<div style="background:#eff6ff; padding:12px; border-radius:8px; border:1px solid #bfdbfe; margin-bottom:16px;"><div style="font-size:12px; color:#1e40af; text-transform:uppercase; font-weight:700;">Code généré</div><div style="font-size:24px; font-weight:800; font-family:monospace; color:#1e3a8a; margin:4px 0;">${escapeHtml(c.pro_code)}</div><div style="display:flex; gap:8px; margin-top:8px;"><a class="button whatsapp" href="https://wa.me/${escapeHtml(cleanNumber)}?text=${waMessage}" target="_blank" style="font-size:12px; padding:6px 12px; margin:0;">📱 Envoyer WhatsApp</a><form action="/admin/candidatures/${c.id}/regenerer-code" method="POST" onsubmit="return confirm('Régénérer ?')" style="margin:0;"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><button class="warning" type="submit" style="font-size:12px; padding:6px 12px; margin:0;">🔄 Régénérer</button></form></div></div>`;
      }

      const paymentBlock = c.payment_status === "unpaid" ? `<div class="alert alert-warning" style="font-size:13px; padding:10px; margin-bottom:16px;">⏳ Paiement non effectué. <a href="/paiement/${escapeHtml(c.tracking_code)}" target="_blank">Lien de paiement</a></div>` : "";

      return `
        <details class="admin-details">
          <summary class="admin-summary">
            <div class="admin-summary-info">
              <div>
                <strong style="font-size:16px; color:#111827;">${escapeHtml(c.full_name)}</strong> 
                <span style="color:#6b7280; font-size:14px;">— ${escapeHtml(c.profession)}</span>
              </div>
              <div style="display:flex; gap:10px; align-items:center;">
                <span class="badge badge-${c.status}">${c.status === 'payment_pending' ? '⏳ Attente paie' : STATUS_LABELS[c.status]}</span>
                ${paymentBadge}
              </div>
            </div>
            <div style="margin-left:15px; color:#9ca3af; font-size:20px;">▼</div>
          </summary>
          <div class="admin-content">
            ${photos}
            <div style="background:#f9fafb; padding:16px; border-radius:12px; font-size:14px; margin-bottom:16px; border:1px solid #e5e7eb;">
              <p style="margin-bottom:6px;"><span style="font-weight:700;">NPI :</span> <code>${escapeHtml(c.npi || "Non renseigné")}</code></p>
              <p style="margin-bottom:6px;"><span style="font-weight:700;">Téléphone :</span> ${escapeHtml(c.phone)}</p>
              <p style="margin-bottom:6px;"><span style="font-weight:700;">Ville :</span> ${escapeHtml(c.city)} ${c.neighborhood ? `(${escapeHtml(c.neighborhood)})` : ""}</p>
              <p style="margin-bottom:6px;"><span style="font-weight:700;">Email :</span> ${escapeHtml(c.contact_email || "Non renseigné")}</p>
              <p style="margin-bottom:6px;"><span style="font-weight:700;">Suivi :</span> <code>${escapeHtml(c.tracking_code || "")}</code></p>
              <p><span style="font-weight:700;">Description :</span> ${escapeHtml(c.service_description)}</p>
            </div>
            
            ${paymentBlock}
            ${c.rejection_reason ? `<div class="alert alert-danger" style="font-size:13px; padding:10px; margin-bottom:16px;"><strong>Motif :</strong> ${escapeHtml(c.rejection_reason)}</div>` : ""}
            ${codeBlock}
            
            ${c.status !== 'payment_pending' ? `
            <form action="/admin/candidatures/${c.id}/status" method="POST" style="display:flex; gap:10px; align-items:flex-start; margin-bottom:16px;">
              <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
              <div style="flex:1;"><label style="margin-top:0; font-size:12px;">Statut</label><select name="status" style="margin:0; padding:10px;">${statusOptions}</select></div>
              <div style="flex:2;"><label style="margin-top:0; font-size:12px;">Motif (optionnel)</label><input name="rejection_reason" maxlength="1000" value="${escapeHtml(c.rejection_reason || "")}" placeholder="Ex: Photo floue" style="margin:0; padding:10px;"></div>
              <div style="padding-top:22px;"><button type="submit" style="margin:0; padding:10px 20px;">Enregistrer</button></div>
            </form>
            ` : ""}
            
            <div style="text-align:right;">
              <form action="/admin/candidatures/${c.id}/supprimer" method="POST" style="margin:0;">
                <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
                <button class="danger" onclick="return confirm('Supprimer définitivement ?')" style="padding:8px 16px; font-size:12px; background:transparent; color:#ef4444; border:1px solid #ef4444;">🗑️ Supprimer</button>
              </form>
            </div>
          </div>
        </details>
      `;
    }).join("");

    const menu = await adminMenu("/admin/candidatures", csrf); 
    const paginationHtml = renderPagination(currentPage, totalPages, "/admin/candidatures", filter !== 'all' ? { filter } : {});
    const filterBar = `<div style="display:flex; gap:8px; justify-content:center; flex-wrap:wrap; margin-bottom:20px;"><a class="button ${filter === 'all' ? '' : 'secondary'}" href="/admin/candidatures" style="padding:8px 16px; font-size:13px;">📋 Tout</a><a class="button ${filter === 'unpaid' ? '' : 'secondary'}" href="/admin/candidatures?filter=unpaid" style="padding:8px 16px; font-size:13px;">⏳ Impayés</a><a class="button ${filter === 'pending' ? '' : 'secondary'}" href="/admin/candidatures?filter=pending" style="padding:8px 16px; font-size:13px;">📥 En attente</a><a class="button ${filter === 'approved' ? '' : 'secondary'}" href="/admin/candidatures?filter=approved" style="padding:8px 16px; font-size:13px;">✅ Approuvés</a></div>`;
    
    res.send(page("Candidatures", `<h1 style="text-align:center; margin-bottom:20px;">Candidatures (${total})</h1>${menu}${filterBar}${applications || '<section class="card"><p class="muted" style="text-align:center;">Aucune.</p></section>'}${paginationHtml}`, null));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.post("/admin/candidatures/:id/status", requireAdmin, verifyCsrf, async (req, res) => {
  try {
    const id = Number(req.params.id), status = req.body.status, reason = req.body.rejection_reason || null;
    if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/candidatures");
    if (!ALLOWED_STATUSES.includes(status)) return res.redirect(303, "/admin/candidatures");
    const existing = await pool.query("SELECT pro_code, photo_kyc_url, referral_code FROM professional_applications WHERE id = $1", [id]);
    if (!existing.rows.length) return res.redirect(303, "/admin/candidatures");
    if (status === "approved" && !existing.rows[0].photo_kyc_url) return res.redirect(303, "/admin/candidatures");
    
    if (status === "approved") {
      let newCode = existing.rows[0].pro_code;
      let newRefCode = existing.rows[0].referral_code;
      
      if (!newCode) newCode = await generateUniqueProCode();
      if (!newRefCode) newRefCode = await generateUniqueReferralCode();
      
      await pool.query(`UPDATE professional_applications SET status = $1, pro_code = $2, referral_code = $3, rejection_reason = $4 WHERE id = $5`, [status, newCode, newRefCode, reason, id]);
      await logAdminAction("approve_application", "pro", id, `Code généré: ${newCode} | Code parrainage: ${newRefCode}`);
    } else {
      await pool.query(`UPDATE professional_applications SET status = $1, rejection_reason = $2 WHERE id = $3`, [status, reason, id]);
      await logAdminAction("update_status", "pro", id, `Nouveau statut: ${status}${reason ? ` | Motif: ${reason}` : ""}`);
    }
    res.redirect(303, "/admin/candidatures");
  } catch (error) { res.redirect(303, "/admin/candidatures"); }
});

app.post("/admin/candidatures/:id/regenerer-code", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/candidatures");
  try {
    const check = await pool.query("SELECT id, status, pro_code FROM professional_applications WHERE id = $1", [id]);
    if (!check.rows.length || check.rows[0].status !== "approved") return res.redirect(303, "/admin/candidatures");
    const oldCode = check.rows[0].pro_code; const newCode = await generateUniqueProCode();
    await pool.query(`UPDATE professional_applications SET pro_code = $1, pro_code_updated_at = NOW() WHERE id = $2`, [newCode, id]);
    await logAdminAction("regenerate_code", "pro", id, `Ancien: ${oldCode} | Nouveau: ${newCode}`);
    res.redirect(303, "/admin/candidatures");
  } catch (e) { res.redirect(303, "/admin/candidatures"); }
});

app.post("/admin/candidatures/:id/supprimer", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/candidatures");
  
  let cloudinaryUrls = [];
  try {
    const proResult = await pool.query(`SELECT full_name, phone, photo_profil_url, photo_identite_url, photo_kyc_url, photo_activite_url, photo_galerie_1, photo_galerie_2, photo_galerie_3 FROM professional_applications WHERE id = $1`, [id]);
    if (!proResult.rows.length) return res.redirect(303, "/admin/candidatures");
    const p = proResult.rows[0];
    cloudinaryUrls = [p.photo_profil_url, p.photo_identite_url, p.photo_kyc_url, p.photo_activite_url, p.photo_galerie_1, p.photo_galerie_2, p.photo_galerie_3].filter(u => u);
    
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`DELETE FROM contact_messages WHERE pro_id = $1`, [id]);
      await client.query(`DELETE FROM reviews WHERE pro_id = $1`, [id]);
      await client.query(`DELETE FROM gdpr_requests WHERE pro_id = $1`, [id]);
      await client.query(`DELETE FROM withdrawal_requests WHERE pro_id = $1`, [id]);
      await client.query(`DELETE FROM job_offers WHERE pro_id = $1`, [id]);
      await client.query(`DELETE FROM professional_applications WHERE id = $1`, [id]);
      await client.query('COMMIT');
    } catch (txErr) {
      await client.query('ROLLBACK');
      throw txErr;
    } finally {
      client.release();
    }
    
    await Promise.allSettled(cloudinaryUrls.map(url => deleteFromCloudinary(url)));
    await logAdminAction("delete_application", "pro", id, `Nom: ${p.full_name} | Téléphone: ${p.phone}`);
    res.redirect(303, "/admin/candidatures");
  } catch (e) {
    console.error("Erreur suppression pro:", e.message);
    res.redirect(303, "/admin/candidatures");
  }
});

app.get("/admin/avis", requireAdmin, async (req, res) => {
  try {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT r.*, p.full_name AS pro_name FROM reviews r LEFT JOIN professional_applications p ON p.id = r.pro_id ORDER BY CASE WHEN r.status = 'pending' THEN 0 ELSE 1 END, r.created_at DESC`);
    const reviews = result.rows.map(r => `
      <article class="card" style="margin-bottom:20px;">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:10px;">
          <div><h2 style="margin-bottom:4px; font-size:18px;">Avis de ${escapeHtml(r.author_name)}</h2><p class="muted" style="font-size:14px;">Concernant : <strong>${escapeHtml(r.pro_name || "Inconnu")}</strong></p></div>
          <span class="badge badge-${r.status}">${REVIEW_STATUS_LABELS[r.status]}</span>
        </div>
        <div class="review-stars" style="margin:10px 0; font-size:24px; color:#f59e0b;">${renderStars(r.rating)}</div>
        <p style="background:#f9fafb; padding:16px; border-radius:12px; font-style:italic;">"${escapeHtml(r.comment || "Aucun commentaire")}"</p>
        
        ${r.pro_response ? `<div style="margin-top:12px; padding:12px; background:#eff6ff; border-left:3px solid #3b82f6; border-radius:6px; font-size:13px;"><strong>Réponse du pro :</strong><br>${escapeHtml(r.pro_response)}</div>` : ""}
        
        <div class="actions" style="margin-top:16px;">
          <form action="/admin/avis/${r.id}/statut" method="POST" style="display:inline">
            <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
            <input type="hidden" name="status" value="approved">
            <button class="success" style="padding:8px 24px; font-size:14px;">Approuver</button>
          </form>
          <form action="/admin/avis/${r.id}/statut" method="POST" style="display:inline">
            <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
            <input type="hidden" name="status" value="rejected">
            <button class="danger" style="padding:8px 24px; font-size:14px;">Rejeter</button>
          </form>
        </div>
      </article>
    `).join("");
    const menu = await adminMenu("/admin/avis", csrf);
    res.send(page("Avis", `<h1 style="text-align:center; margin-bottom:30px;">Avis</h1>${menu}${reviews || '<section class="card"><p class="muted" style="text-align:center;">Aucun avis.</p></section>'}`, null));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.post("/admin/avis/:id/statut", requireAdmin, verifyCsrf, async (req, res) => { 
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/avis");
  if (REVIEW_STATUSES.includes(req.body.status)) { 
    await pool.query(`UPDATE reviews SET status = $1, processed_at = NOW() WHERE id = $2`, [req.body.status, id]); 
    await logAdminAction(`review_${req.body.status}`, "review", id, null); 
  } 
  res.redirect(303, "/admin/avis"); 
});

app.get("/admin/emplois", requireAdmin, async (req, res) => {
  try {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT j.*, p.full_name AS pro_name FROM job_offers j LEFT JOIN professional_applications p ON p.id = j.pro_id ORDER BY CASE WHEN j.status = 'pending' THEN 0 ELSE 1 END, j.created_at DESC`);
    const jobs = result.rows.map(j => `<article class="card" style="margin-bottom:20px;"><h2 style="font-size:18px;">${escapeHtml(j.job_title)} <span class="badge badge-${j.status}">${JOB_STATUS_LABELS[j.status]}</span></h2><p class="muted" style="font-size:14px;">Posté par : <strong>${escapeHtml(j.pro_name || "Inconnu")}</strong></p><div style="background:#f9fafb; padding:16px; border-radius:12px; margin:16px 0;"><p style="margin-bottom:4px;"><strong>Ville :</strong> ${escapeHtml(j.city)} | <strong>Contrat :</strong> ${escapeHtml(j.contract_type)}</p><p>${escapeHtml(j.description)}</p></div><form action="/admin/emplois/${j.id}/status" method="POST" style="display:flex; align-items:center; gap:10px;"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><select name="status" style="margin:0; width:auto; padding:8px 16px;">${JOB_STATUSES.map(s => `<option value="${s}" ${j.status === s ? "selected" : ""}>${JOB_STATUS_LABELS[s]}</option>`).join("")}</select><button style="margin:0; padding:10px 20px; font-size:14px;">Mettre à jour</button></form></article>`).join("");
    const menu = await adminMenu("/admin/emplois", csrf);
    res.send(page("Emplois", `<h1 style="text-align:center; margin-bottom:30px;">Offres</h1>${menu}${jobs || '<section class="card"><p class="muted" style="text-align:center;">Aucune.</p></section>'}`, null));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.post("/admin/emplois/:id/status", requireAdmin, verifyCsrf, async (req, res) => { 
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/emplois");
  if (JOB_STATUSES.includes(req.body.status)) { 
    await pool.query(`UPDATE job_offers SET status = $1 WHERE id = $2`, [req.body.status, id]); 
    await logAdminAction(`job_${req.body.status}`, "job", id, null); 
  } 
  res.redirect(303, "/admin/emplois"); 
});

app.get("/admin/messages", requireAdmin, async (req, res) => {
  try {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT * FROM contact_messages ORDER BY is_read ASC, created_at DESC`);
    const messages = result.rows.map(m => `<article class="card" style="margin-bottom:20px; ${m.is_read ? 'opacity:0.6' : 'border-left:4px solid #3b82f6;'}"><h2 style="font-size:18px;">${escapeHtml(m.subject)}</h2><p class="muted" style="font-size:14px;"><strong>De :</strong> ${escapeHtml(m.name)} (${escapeHtml(m.email || m.phone || '')})</p>${m.pro_id ? `<p class="muted" style="font-size:12px;">Pro ID : ${m.pro_id}</p>` : ""}<p style="background:#f9fafb; padding:16px; border-radius:12px; margin:16px 0;">${escapeHtml(m.message)}</p><p class="muted" style="font-size:12px;">Reçu le : ${new Date(m.created_at).toLocaleString("fr-FR")}</p>${!m.is_read ? `<form action="/admin/messages/${m.id}/read" method="POST" style="margin-top:10px;"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><button class="secondary" style="padding:8px 16px; font-size:14px;">Marquer lu</button></form>` : ""}</article>`).join("");
    const menu = await adminMenu("/admin/messages", csrf);
    res.send(page("Messages", `<h1 style="text-align:center; margin-bottom:30px;">Messages</h1>${menu}${messages || '<section class="card"><p class="muted" style="text-align:center;">Aucun.</p></section>'}`, null));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.post("/admin/messages/:id/read", requireAdmin, verifyCsrf, async (req, res) => { 
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/messages");
  await pool.query(`UPDATE contact_messages SET is_read = true WHERE id = $1`, [id]); 
  res.redirect(303, "/admin/messages"); 
});

app.get("/admin/rgpd", requireAdmin, async (req, res) => {
  try {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT g.*, p.full_name AS pro_name FROM gdpr_requests g LEFT JOIN professional_applications p ON p.id = g.pro_id ORDER BY CASE WHEN g.status = 'pending' THEN 0 ELSE 1 END, g.created_at DESC`);
    const reqs = result.rows.map(r => `<article class="card" style="margin-bottom:20px;"><h2 style="font-size:18px;">${GDPR_TYPE_LABELS[r.request_type]} - ${escapeHtml(r.pro_name || "Inconnu")}</h2><p style="margin-top:8px;"><span class="badge badge-${r.status}">${GDPR_STATUS_LABELS[r.status]}</span></p><p style="background:#f9fafb; padding:16px; border-radius:12px; margin:16px 0;">${escapeHtml(r.message)}</p><p class="muted" style="font-size:12px;">Demande le : ${new Date(r.created_at).toLocaleString("fr-FR")}</p>${r.status === "pending" ? `<form action="/admin/rgpd/${r.id}/traiter" method="POST" style="margin-top:10px;"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><button class="success" style="padding:8px 16px; font-size:14px;">Traiter</button></form>` : ""}</article>`).join("");
    const menu = await adminMenu("/admin/rgpd", csrf);
    res.send(page("RGPD", `<h1 style="text-align:center; margin-bottom:30px;">RGPD</h1>${menu}${reqs || '<section class="card"><p class="muted" style="text-align:center;">Aucune.</p></section>'}`, null));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.post("/admin/rgpd/:id/traiter", requireAdmin, verifyCsrf, async (req, res) => { 
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/rgpd");
  
  try {
    const reqResult = await pool.query("SELECT pro_id, request_type FROM gdpr_requests WHERE id = $1", [id]);
    if (!reqResult.rows.length) return res.redirect(303, "/admin/rgpd");
    
    const { pro_id, request_type } = reqResult.rows[0];

    if (request_type === 'deletion' && pro_id) {
      const proResult = await pool.query(`SELECT full_name, phone, photo_profil_url, photo_identite_url, photo_kyc_url, photo_activite_url, photo_galerie_1, photo_galerie_2, photo_galerie_3 FROM professional_applications WHERE id = $1`, [pro_id]);
      if (proResult.rows.length) {
        const p = proResult.rows[0];
        const cloudinaryUrls = [p.photo_profil_url, p.photo_identite_url, p.photo_kyc_url, p.photo_activite_url, p.photo_galerie_1, p.photo_galerie_2, p.photo_galerie_3].filter(u => u);
        
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          await client.query(`DELETE FROM contact_messages WHERE pro_id = $1`, [pro_id]);
          await client.query(`DELETE FROM reviews WHERE pro_id = $1`, [pro_id]);
          await client.query(`DELETE FROM withdrawal_requests WHERE pro_id = $1`, [pro_id]);
          await client.query(`DELETE FROM job_offers WHERE pro_id = $1`, [pro_id]);
          await client.query(`DELETE FROM professional_applications WHERE id = $1`, [pro_id]);
          await client.query('COMMIT');
        } catch (txErr) {
          await client.query('ROLLBACK');
          throw txErr;
        } finally {
          client.release();
        }
        
        await Promise.allSettled(cloudinaryUrls.map(url => deleteFromCloudinary(url)));
        await logAdminAction("gdpr_deletion", "pro", pro_id, `Nom: ${p.full_name} | Téléphone: ${p.phone}`);
      }
    }

    await pool.query(`UPDATE gdpr_requests SET status = 'processed', processed_at = NOW() WHERE id = $1`, [id]); 
    await logAdminAction("gdpr_processed", "gdpr", id, `Type: ${request_type}`);
    res.redirect(303, "/admin/rgpd"); 
  } catch (e) {
    console.error("Erreur RGPD:", e);
    res.redirect(303, "/admin/rgpd");
  }
});

app.get("/admin/retraits", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  try {
    const result = await pool.query(`SELECT w.*, p.full_name, p.pro_code FROM withdrawal_requests w JOIN professional_applications p ON p.id = w.pro_id ORDER BY CASE WHEN w.status = 'pending' THEN 0 ELSE 1 END, w.created_at DESC`);
    
    const requests = result.rows.map(w => `
      <article class="card" style="margin-bottom:20px; ${w.status === 'pending' ? 'border-left:4px solid #f59e0b;' : ''}">
        <h2 style="font-size:18px;">${escapeHtml(w.full_name)} (${escapeHtml(w.pro_code)})</h2>
        <p><strong>Montant :</strong> ${w.amount} FCFA</p>
        <p><strong>Numéro :</strong> ${escapeHtml(w.phone_number)}</p>
        <p><strong>Statut :</strong> <span class="badge badge-${w.status === 'pending' ? 'pending' : 'approved'}">${w.status === 'pending' ? 'En attente' : 'Payé'}</span></p>
        ${w.status === 'pending' ? `
        <form action="/admin/retraits/${w.id}/approuver" method="POST" style="margin-top:10px;">
          <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
          <button class="success" onclick="return confirm('Confirmez-vous avoir payé ${w.amount} FCFA au ${w.phone_number} ?')">✅ Approuver et Marquer comme Payé</button>
        </form>` : ""}
      </article>
    `).join("");

    const menu = await adminMenu("/admin/retraits", csrf);
    res.send(page("Retraits", `<h1 style="text-align:center; margin-bottom:30px;">Demandes de retrait</h1>${menu}${requests || '<section class="card"><p class="muted" style="text-align:center;">Aucune demande.</p></section>'}`, null));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.post("/admin/retraits/:id/approuver", requireAdmin, verifyCsrf, async (req, res) => {
  await pool.query("UPDATE withdrawal_requests SET status = 'processed', processed_at = NOW() WHERE id = $1", [Number(req.params.id)]);
  res.redirect(303, "/admin/retraits");
});

app.get("/admin/blog", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  try {
    const result = await pool.query(`SELECT * FROM blog_posts ORDER BY created_at DESC`);
    const posts = result.rows.map(p => `
      <article class="card" style="margin-bottom: 20px;">
        <div style="display:flex; justify-content:space-between;">
          <h2 style="font-size: 18px;">${escapeHtml(p.title)}</h2>
          <span class="badge badge-approved">Publié</span>
        </div>
        <p class="muted" style="font-size:14px; margin-top:8px;">Lien : <a href="/blog/${p.slug}" target="_blank" style="color:#2563eb;">/blog/${p.slug}</a></p>
      </article>
    `).join("");
    
    const menu = await adminMenu("/admin/blog", csrf);
    res.send(page("Blog", `
      <h1 style="text-align:center; margin-bottom:30px;">Gestion du Blog</h1>
      ${menu}
      
      <section class="card" style="margin-top:20px; background:#f8fafc;">
        <h2>Ajouter un article</h2>
        <form action="/admin/blog" method="POST" style="margin-top:16px;">
          <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
          <label>Titre de l'article *</label>
          <input name="title" required maxlength="255" placeholder="Ex: Comment trouver un bon maçon à Cotonou">
          
          <label>Lien URL (Slug) *</label>
          <input name="slug" required maxlength="255" placeholder="Ex: comment-trouver-bon-macon-cotonou" pattern="[a-z0-9-]+" title="Uniquement des minuscules, chiffres et tirets">
          
          <label>Description courte (SEO) *</label>
          <textarea name="meta_description" required maxlength="255" rows="2" placeholder="Résumé de l'article pour Google..."></textarea>
          
          <label>Contenu de l'article *</label>
          <textarea name="content" required rows="10" placeholder="Écrivez votre article ici..."></textarea>
          
          <button type="submit" class="success" style="margin-top:10px;">Publier l'article</button>
        </form>
      </section>

      <section class="card" style="margin-top:20px;">
        <h2>Articles publiés (${result.rows.length})</h2>
        ${posts || '<p class="muted">Aucun article.</p>'}
      </section>
    `, null));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.post("/admin/blog", requireAdmin, verifyCsrf, async (req, res) => {
  const { title, slug, meta_description, content } = req.body;
  try {
    await pool.query(`INSERT INTO blog_posts (title, slug, meta_description, content) VALUES ($1, $2, $3, $4)`, [title, slug, meta_description, content]);
    res.redirect(303, "/admin/blog");
  } catch (e) {
    res.status(500).send(page("Erreur", "<h2>Erreur. Le slug est peut-être déjà utilisé.</h2><a href='/admin/blog'>Retour</a>", null));
  }
});

app.post("/admin/logout", requireAdmin, verifyCsrf, (req, res) => { clearSessionCookie(res); res.redirect(303, "/admin"); });
app.get("/a-propos", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  res.send(page("A propos", `<section class="card" style="max-width: 800px; margin: 0 auto;"><h1 style="text-align:center;">A propos de TrouveMoi</h1><p style="font-size: 16px; margin-top: 20px;"><strong>TrouveMoi</strong> est la plateforme beninoise de mise en relation entre les clients et les professionnels qualifies.</p><h2 style="margin-top: 30px;">Notre mission</h2><p>Simplifier la recherche de professionnels de confiance au Benin. TrouveMoi centralise les pros de votre ville et vous permet de les contacter en un clic, en toute securite grace a la verification KYC.</p><h2 style="margin-top: 30px;">Nos services</h2><ul style="margin-left:20px;margin-bottom:24px; font-size:15px; line-height:2;"><li>Annuaire de professionnels verifies</li><li>Recherche intuitive par ville, quartier et metier</li><li>Contact direct par telephone ou WhatsApp</li><li>Publication et consultation d'offres d'emploi</li><li>Systeme d'avis clients moderes</li></ul><div style="text-align:center; margin-top:30px;"><a class="button" href="/contact">Nous contacter</a> <a class="button secondary" href="/">Voir les professionnels</a></div></section>`, proConnected));
});

app.get("/conditions", (req, res) => {
  res.send(page("Conditions", `<section class="card" style="max-width: 800px; margin: 0 auto;"><h1 style="text-align:center;">Conditions d'utilisation</h1><p class="muted" style="text-align:center; margin-bottom:30px;">Dernière mise à jour : ${new Date().toLocaleDateString("fr-FR")}</p><h2>1. Acceptation</h2><p>En utilisant TrouveMoi, vous acceptez ces conditions.</p><h2>2. Nature du service</h2><p>TrouveMoi est une plateforme de mise en relation. Nous ne fournissons pas directement de services professionnels.</p><h2>3. Inscription des professionnels</h2><p>Les pros doivent fournir des informations exactes (dont leur NPI). Toute fausse déclaration entraîne le rejet définitif du dossier.</p><h2>4. Frais d'inscription</h2><p>L'inscription des professionnels est soumise à des frais uniques de ${PAYMENT_AMOUNT} FCFA. Ces frais couvrent les coûts de vérification d'identité (KYC) et de traitement de votre dossier. <strong>En cas de refus définitif de votre dossier par nos équipes (hors fausse déclaration), ces frais vous seront intégralement remboursés.</strong></p><h2>5. Avis clients</h2><p>Les avis sont modérés. Tout avis injurieux, diffamatoire ou spam sera supprimé sans préavis.</p></section>`, null));
});

app.get("/mentions-legales", (req, res) => {
  res.send(page("Mentions légales", `
    <section class="card" style="max-width: 800px; margin: 0 auto;">
      <h1 style="text-align:center;">Mentions Légales</h1>
      <p class="muted" style="text-align:center; margin-bottom:30px;">Dernière mise à jour : ${new Date().toLocaleDateString("fr-FR")}</p>
      
      <h2>1. Éditeur du site</h2>
      <p>Le site <strong>TrouveMoi</strong> est édité et exploité par :</p>
      <ul style="margin-left: 20px; margin-bottom: 20px; line-height: 1.8;">
        <li><strong>Raison sociale :</strong> ADK SERVICES</li>
        <li><strong>Forme juridique :</strong> Entreprise Individuelle</li>
        <li><strong>N° RCCM :</strong> RB/COT/18 A 40963</li>
        <li><strong>N° IFU :</strong> 0201810443413</li>
        <li><strong>Localisation :</strong> Cotonou, Bénin</li>
        <li><strong>Contact :</strong> contact@trouvemoi.bj</li>
      </ul>
      <p>Pour toute demande d'information supplémentaire, veuillez utiliser notre <a href="/contact" style="color:#2563eb;">formulaire de contact</a> ou nous écrire à l'adresse email professionnelle ci-dessus.</p>

      <h2>2. Responsable de la publication</h2>
      <p>Le responsable de la publication est <strong>M. AKPE David</strong>, en sa qualité de Gérant de ADK SERVICES.</p>

      <h2>3. Hébergement</h2>
      <p>Le site est hébergé par : <strong>Render</strong>.</p>

      <h2>4. Propriété intellectuelle</h2>
      <p>L'ensemble du contenu du site TrouveMoi (textes, images, logos, base de données) est la propriété exclusive de ADK SERVICES. Toute reproduction, même partielle, sans autorisation écrite préalable est strictement interdite.</p>
    </section>
  `, null));
});

app.get("/confidentialite", (req, res) => {
  res.send(page("Confidentialite", `<section class="card" style="max-width: 800px; margin: 0 auto;"><h1 style="text-align:center;">Politique de confidentialité</h1><p class="muted" style="text-align:center; margin-bottom:30px;">Dernière mise à jour : ${new Date().toLocaleDateString("fr-FR")}</p><h2>1. Données collectées</h2><p>Nom, téléphone, NPI, ville, métier, photos (profil et KYC), avis, messages, données de paiement.</p><h2>2. Utilisation</h2><p>Mise en relation, affichage des profils, vérification d'identité, gestion des offres et avis.</p><h2>3. Protection</h2><p>Les photos d'identité et de vérification KYC sont strictement privées. Seuls les administrateurs y ont accès pour validation.</p><h2>4. Vos droits</h2><p>Vous disposez des droits d'accès, rectification, suppression et opposition. Contactez-nous via le <a href="/contact" style="color:#2563eb;">formulaire de contact</a>.</p></section>`, null));
});

app.get("/contact", async (req, res) => {
  const proConnected = await getConnectedPro(req); 
  const proId = String(req.query.pro || "").trim();
  const reportId = String(req.query.report || "").trim();
  
  const defaultSubject = reportId ? `Signalement du professionnel #${reportId}` : "";
  const defaultMessage = reportId ? `Bonjour, je souhaite signaler le professionnel #${reportId} pour le motif suivant : \n\n` : "";

  res.send(page("Contact", `<section class="card" style="max-width: 600px; margin: 0 auto;"><h1 style="text-align:center;">Nous contacter</h1><p style="text-align:center; color:#6b7280; margin-bottom:30px;">Une question ? Écrivez-nous.</p><form id="form-contact" action="/contact" method="POST"><input type="hidden" name="recaptcha_token" id="recaptcha_token_contact" value=""><input type="hidden" name="pro_id" value="${escapeHtml(proId)}"><label>Votre nom *</label><input name="name" required maxlength="150"><div style="display:grid; grid-template-columns:1fr 1fr; gap:20px;"><div><label>Votre email</label><input type="email" name="email" maxlength="254"></div><div><label>Votre téléphone</label><input type="tel" name="phone" maxlength="30" placeholder="0194010345"></div></div><label>Sujet *</label><input name="subject" value="${escapeHtml(defaultSubject)}" required maxlength="200"><label>Message *</label><textarea name="message" required rows="5" maxlength="5000">${escapeHtml(defaultMessage)}</textarea><div style="text-align:center; margin-top:20px;"><button type="submit" style="padding:14px 40px;">Envoyer</button></div></form><script>document.getElementById('form-contact').addEventListener('submit', async function(e) { if (!document.getElementById('recaptcha_token_contact').value) { e.preventDefault(); const token = await getRecaptchaToken(); document.getElementById('recaptcha_token_contact').value = token; this.submit(); } });</script></section>`, proConnected));
});

app.post("/contact", async (req, res) => {
  const recaptchaToken = req.body.recaptcha_token;
  const isHuman = await verifyRecaptcha(recaptchaToken);
  if (!isHuman) return res.status(400).send(page("Erreur", "<h2>Vérification anti-robot échouée.</h2>", null));

  const { name, email, phone, subject, message, pro_id } = req.body;
  if (!name || !subject || !message || (!email && !phone)) return res.status(400).send(page("Erreur", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h2>Infos manquantes.</h2><a href='/contact' class='button'>Retour</a></section>", null));
  
  const safeEmail = String(email || "").trim().slice(0, 254);
  if (safeEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(safeEmail)) {
    return res.status(400).send(page("Erreur", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h2>Email invalide.</h2><a href='/contact' class='button'>Retour</a></section>", null));
  }
  
  let safePhone = String(phone || "").trim().replace(/[\s().-]/g, "").slice(0, 30);
  if (safePhone) {
    let phoneNorm = safePhone.replace(/^(?:\+?229|00229)/, "");
    if (!/^01\d{8}$/.test(phoneNorm)) {
      return res.status(400).send(page("Erreur", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h2>Numéro de téléphone invalide.</h2><p>Format attendu : 01XXXXXXXX (10 chiffres commençant par 01).</p><a href='/contact' class='button'>Retour</a></section>", null));
    }
    safePhone = phoneNorm;
  } else {
    safePhone = null;
  }
  
  const ip = req.ip || "unknown"; const now = Date.now(); const attempts = contactAttempts.get(ip) || { count: 0, startedAt: now };
  if (now - attempts.startedAt > 60 * 60 * 1000) { attempts.count = 0; attempts.startedAt = now; }
  if (attempts.count >= 3) return res.status(429).send(page("Trop de tentatives", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>⏳ Trop de messages</h1><p>Patientez 1 heure.</p><a class='button' href='/'>Accueil</a></section>", null));
  attempts.count++; contactAttempts.set(ip, attempts);

  try {
    let proIdInt = null;
    if (/^\d+$/.test(String(pro_id || ""))) { const candidate = parseInt(pro_id, 10); if (Number.isSafeInteger(candidate) && candidate > 0) { const exists = await pool.query("SELECT 1 FROM professional_applications WHERE id = $1 AND status = 'approved'", [candidate]); if (exists.rows.length) proIdInt = candidate; } }
    await pool.query(`INSERT INTO contact_messages (name, email, phone, subject, message, pro_id) VALUES ($1, $2, $3, $4, $5, $6)`, [String(name).slice(0, 150), safeEmail || null, safePhone, String(subject).slice(0, 200), String(message).slice(0, 5000), proIdInt]);
    res.send(page("Succes", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>Message envoyé !</h1><p>Nous vous répondrons vite.</p><a class='button' href='/'>Retour à l'accueil</a></section>", null));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur d'envoi.</h2>", null)); }
});

app.get("/blog", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  try {
    const result = await pool.query(`SELECT slug, title, meta_description, created_at FROM blog_posts ORDER BY created_at DESC`);
    const posts = result.rows.map(p => `
      <article class="card" style="margin-bottom:20px;">
        <h2 style="font-size:22px;"><a href="/blog/${p.slug}" style="color:#1e40af; text-decoration:none;">${escapeHtml(p.title)}</a></h2>
        <div style="font-size:12px; color:#6b7280; margin-bottom:10px;">Publié le ${new Date(p.created_at).toLocaleDateString("fr-FR")}</div>
        <p style="color:#4b5563; font-size:15px;">${escapeHtml(p.meta_description || "")}</p>
        <a href="/blog/${p.slug}" class="button secondary" style="margin-top:10px;">Lire la suite →</a>
      </article>
    `).join("");
    
    res.send(page("Blog", `<div style="max-width:800px; margin:0 auto;"><h1 style="text-align:center; margin-bottom:30px;">Le Blog de TrouveMoi</h1>${posts || '<p style="text-align:center;">Aucun article pour le moment.</p>'}</div>`, proConnected));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.get("/blog/:slug", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  try {
    const result = await pool.query(`SELECT * FROM blog_posts WHERE slug = $1`, [req.params.slug]);
    if (!result.rows.length) return res.redirect(303, "/blog");
    const post = result.rows[0];
    
    res.send(page(post.title, `
      <div style="max-width:800px; margin:0 auto; background:white; padding:40px; border-radius:16px; box-shadow:0 4px 20px rgba(0,0,0,0.04);">
        <a href="/blog" style="color:#6b7280; text-decoration:none; font-size:14px; margin-bottom:20px; display:inline-block;">← Retour au blog</a>
        <h1 style="color:#1e3a8a; font-size:32px; margin-bottom:10px;">${escapeHtml(post.title)}</h1>
        <div style="font-size:13px; color:#6b7280; margin-bottom:30px; border-bottom:1px solid #e5e7eb; padding-bottom:20px;">Publié le ${new Date(post.created_at).toLocaleDateString("fr-FR")}</div>
        <div style="font-size:16px; line-height:1.8; color:#374151; white-space:pre-wrap;">${escapeHtml(post.content)}</div>
      </div>
    `, proConnected));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.get("/partenariats", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  res.send(page("Partenariats", `
    <section class="card" style="max-width: 800px; margin: 0 auto; text-align: center; padding: 40px;">
      <div style="font-size: 60px; margin-bottom: 20px;">🤝</div>
      <h1 style="color:#1e3a8a;">Partenariats & Associations</h1>
      <p style="font-size: 16px; color: #4b5563; margin-bottom: 30px;">Vous êtes une association de métiers (coiffeurs, maçons, taxis-motos) ou une organisation professionnelle au Bénin ?</p>
      <div style="background: #eff6ff; padding: 24px; border-radius: 12px; border: 1px solid #bfdbfe; text-align: left; margin-bottom: 30px;">
        <h3 style="color:#1e3a8a; margin-bottom: 10px;">Pourquoi devenir partenaire ?</h3>
        <ul style="margin-left: 20px; line-height: 1.8; color: #1e40af;">
          <li>Inscrivez vos membres en masse sur TrouveMoi.</li>
          <li>Offrez à vos adhérents une vitrine numérique gratuite.</li>
          <li>Aidez-les à trouver plus de clients au quotidien.</li>
          <li>Bénéficiez d'un accompagnement dédié.</li>
        </ul>
      </div>
      <a href="/contact?subject=Partenariat" class="button success" style="font-size: 16px; padding: 14px 30px;">Devenir Partenaire</a>
    </section>
  `, proConnected));
});

app.get("/manifest.json", (req, res) => {
  res.json({
    name: "TrouveMoi - Pros du Bénin",
    short_name: "TrouveMoi",
    description: "Trouvez un professionnel vérifié au Bénin",
    start_url: "/",
    display: "standalone",
    background_color: "#f4f7f6",
    theme_color: "#1e40af",
    icons: [
      { src: "https://res.cloudinary.com/gxm35ndf/image/upload/v1792957201/IMG-20261025-WA0002.jpg", sizes: "192x192", type: "image/jpeg" },
      { src: "https://res.cloudinary.com/gxm35ndf/image/upload/v1792957201/IMG-20261025-WA0002.jpg:", sizes: "512x512", type: "image/jpeg" }
    ]
  });
});

app.get("/sw.js", (req, res) => {
  res.type("application/javascript");
  res.send(`
    const CACHE_NAME = 'trouvemoi-v1';
    self.addEventListener('install', (e) => { self.skipWaiting(); });
    self.addEventListener('activate', (e) => { e.waitUntil(clients.claim()); });
    self.addEventListener('fetch', (e) => {
      e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
    });
  `);
});

app.get("/health", (req, res) => res.json({ status: "ok", application: "TrouveMoi", time: new Date().toISOString() }));

app.get("/health/database", async (req, res) => {
  const healthToken = process.env.HEALTH_TOKEN;
  if (healthToken) {
    const providedToken = String(req.query.token || "").trim();
    if (!providedToken || !safeEqual(providedToken, healthToken)) {
      return res.status(404).send("Not found");
    }
  }
  try { await pool.query("SELECT 1"); res.json({ status: "ok", database: "connected" }); } catch (e) { res.status(500).json({ status: "error", message: "database unreachable" }); }
});

app.get("/cron/cleanup", async (req, res) => {
  const cronSecret = process.env.CRON_SECRET;
  if (cronSecret && String(req.query.token || "").trim() !== cronSecret) {
    return res.status(401).send("Non autorisé");
  }
  
  try {
    let deletedCount = 0;
    
    const expired = await pool.query(`SELECT id, photo_profil_url, photo_identite_url, photo_kyc_url, photo_activite_url, photo_galerie_1, photo_galerie_2, photo_galerie_3 FROM professional_applications WHERE status = 'payment_pending' AND payment_status = 'unpaid' AND created_at < NOW() - INTERVAL '48 hours'`);
    for (const row of expired.rows) {
      await Promise.allSettled([row.photo_profil_url, row.photo_identite_url, row.photo_kyc_url, row.photo_activite_url, row.photo_galerie_1, row.photo_galerie_2, row.photo_galerie_3].map(url => url && deleteFromCloudinary(url)));
      await pool.query(`DELETE FROM professional_applications WHERE id = $1`, [row.id]);
      deletedCount++;
    }

    const oldRejected = await pool.query(`SELECT id, photo_profil_url, photo_identite_url, photo_kyc_url, photo_activite_url, photo_galerie_1, photo_galerie_2, photo_galerie_3 FROM professional_applications WHERE status IN ('rejected', 'corrections_requested') AND updated_at < NOW() - INTERVAL '90 days'`);
    for (const row of oldRejected.rows) {
      await Promise.allSettled([row.photo_profil_url, row.photo_identite_url, row.photo_kyc_url, row.photo_activite_url, row.photo_galerie_1, row.photo_galerie_2, row.photo_galerie_3].map(url => url && deleteFromCloudinary(url)));
      await pool.query(`DELETE FROM professional_applications WHERE id = $1`, [row.id]);
      deletedCount++;
    }

    res.json({ success: true, deleted: deletedCount });
  } catch (e) {
    console.error("Erreur cron cleanup:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

function getSafeHost(req) {
  return String(req.get("host") || "").replace(/[^a-zA-Z0-9.:\-]/g, "");
}

app.get("/robots.txt", (req, res) => {
  const safeHost = getSafeHost(req);
  res.type("text/plain").send(`User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /mon-espace-pro\nDisallow: /suivi-dossier\nDisallow: /paiement\nSitemap: ${req.protocol}://${safeHost}/sitemap.xml`);
});

app.get("/sitemap.xml", async (req, res) => {
  try {
    const safeHost = getSafeHost(req);
    const base = `${req.protocol}://${safeHost}`;
    const pros = await pool.query(`SELECT id FROM professional_applications WHERE status = 'approved' LIMIT 1000`);
    const posts = await pool.query(`SELECT slug FROM blog_posts LIMIT 500`);
    const urls = [`${base}/`, `${base}/recherche`, `${base}/emplois`, `${base}/devenir-professionnel`, `${base}/a-propos`, `${base}/contact`, `${base}/conditions`, `${base}/confidentialite`, `${base}/blog`, ...pros.rows.map(p => `${base}/pro/${p.id}`), ...posts.rows.map(p => `${base}/blog/${p.slug}`)];
    const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.map(u => `  <url><loc>${u}</loc></url>`).join("\n")}\n</urlset>`;
    res.type("application/xml").send(xml);
  } catch (e) { res.status(500).send("error"); }
});

app.use((req, res) => { res.status(404).send(page("Introuvable", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>404</h1><p>La page demandée n'existe pas.</p><a class='button' href='/'>Retour</a></section>", null)); });

app.use((err, req, res, next) => {
  console.error("Erreur non geree :", err.message);
  if (res.headersSent) return next(err);
  if (err.code === "LIMIT_FILE_SIZE") return res.status(413).send(page("Erreur", "<h2>Fichier trop volumineux (max 5 Mo).</h2>", null));
  if (err.message && err.message.includes("Format non autorise")) return res.status(400).send(page("Erreur", "<h2>Format d'image non autorise.</h2>", null));
  res.status(500).send(page("Erreur", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>Une erreur est survenue</h1><p>Veuillez réessayer plus tard.</p><a class='button' href='/'>Accueil</a></section>", null));
});
async function startServer() {
  try {
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
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        payment_status VARCHAR(20) NOT NULL DEFAULT 'unpaid',
        payment_ref VARCHAR(100), payment_amount INTEGER DEFAULT 1500, payment_date TIMESTAMP, payment_method VARCHAR(30),
        latitude DECIMAL(10, 8), longitude DECIMAL(11, 8), adresse_exacte TEXT, type_lieu VARCHAR(20) DEFAULT 'ambulant', est_ouvert BOOLEAN DEFAULT true,
        heure_ouverture VARCHAR(10), heure_fermeture VARCHAR(10),
        horaires_json TEXT, unavailable_until TIMESTAMP,
        referral_code VARCHAR(10) UNIQUE, referral_balance INTEGER DEFAULT 0, referred_by VARCHAR(10),
        photo_galerie_1 TEXT, photo_galerie_2 TEXT, photo_galerie_3 TEXT
      )
    `);

    const migrations = [
      `ALTER TABLE professional_applications DROP CONSTRAINT IF EXISTS professional_applications_status_check`,
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
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS payment_status VARCHAR(20) NOT NULL DEFAULT 'unpaid'`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS payment_ref VARCHAR(100)`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS payment_amount INTEGER DEFAULT 1500`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS payment_date TIMESTAMP`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS payment_method VARCHAR(30)`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS latitude DECIMAL(10, 8)`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS longitude DECIMAL(11, 8)`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS adresse_exacte TEXT`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS type_lieu VARCHAR(20) DEFAULT 'ambulant'`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS est_ouvert BOOLEAN DEFAULT true`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS heure_ouverture VARCHAR(10)`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS heure_fermeture VARCHAR(10)`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS horaires_json TEXT`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS unavailable_until TIMESTAMP`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS referral_code VARCHAR(10) UNIQUE`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS referral_balance INTEGER DEFAULT 0`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS referred_by VARCHAR(10)`,
      `ALTER TABLE reviews ADD COLUMN IF NOT EXISTS pro_response TEXT`,
      `ALTER TABLE reviews ADD COLUMN IF NOT EXISTS pro_response_at TIMESTAMP`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS photo_galerie_1 TEXT`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS photo_galerie_2 TEXT`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS photo_galerie_3 TEXT`,
      `UPDATE professional_applications SET payment_status = 'paid', payment_date = created_at WHERE status IN ('approved', 'pending', 'under_review') AND payment_status = 'unpaid'`
    ];
    for (const q of migrations) { try { await pool.query(q); } catch (e) { console.warn("Migration ignoree :", e.message); } }

    await pool.query(`CREATE TABLE IF NOT EXISTS job_offers (id SERIAL PRIMARY KEY, company_name VARCHAR(200) NOT NULL, job_title VARCHAR(200) NOT NULL, city VARCHAR(100) NOT NULL, contract_type VARCHAR(50) NOT NULL, description TEXT NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'pending', pro_id INTEGER REFERENCES professional_applications(id) ON DELETE SET NULL, expires_at TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS cities (id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL UNIQUE, display_order INTEGER NOT NULL DEFAULT 0)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS neighborhoods (id SERIAL PRIMARY KEY, city_id INTEGER NOT NULL REFERENCES cities(id) ON DELETE CASCADE, name VARCHAR(150) NOT NULL, UNIQUE (city_id, name))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS professions (id SERIAL PRIMARY KEY, name VARCHAR(150) NOT NULL UNIQUE, category VARCHAR(100), display_order INTEGER NOT NULL DEFAULT 0)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS contact_messages (id SERIAL PRIMARY KEY, name VARCHAR(150) NOT NULL, email VARCHAR(254), phone VARCHAR(30), subject VARCHAR(200) NOT NULL, message TEXT NOT NULL, is_read BOOLEAN NOT NULL DEFAULT false, pro_id INTEGER REFERENCES professional_applications(id) ON DELETE SET NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS gdpr_requests (id SERIAL PRIMARY KEY, pro_id INTEGER REFERENCES professional_applications(id) ON DELETE SET NULL, request_type VARCHAR(30) NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'pending', message TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, processed_at TIMESTAMP)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS reviews (id SERIAL PRIMARY KEY, pro_id INTEGER NOT NULL REFERENCES professional_applications(id) ON DELETE CASCADE, author_name VARCHAR(100) NOT NULL, rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5), comment TEXT, status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, processed_at TIMESTAMP)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS admin_logs (id SERIAL PRIMARY KEY, action VARCHAR(100) NOT NULL, target_type VARCHAR(50), target_id INTEGER, details TEXT, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS pro_stats (id SERIAL PRIMARY KEY, pro_id INTEGER REFERENCES professional_applications(id) ON DELETE CASCADE, date DATE NOT NULL DEFAULT CURRENT_DATE, views INTEGER DEFAULT 0, phone_clicks INTEGER DEFAULT 0, wa_clicks INTEGER DEFAULT 0, UNIQUE(pro_id, date))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS client_favorites (id SERIAL PRIMARY KEY, visitor_id VARCHAR(64) NOT NULL, pro_id INTEGER REFERENCES professional_applications(id) ON DELETE CASCADE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(visitor_id, pro_id))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS blog_posts (id SERIAL PRIMARY KEY, slug VARCHAR(255) UNIQUE NOT NULL, title VARCHAR(255) NOT NULL, content TEXT NOT NULL, meta_description VARCHAR(255), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS withdrawal_requests (id SERIAL PRIMARY KEY, pro_id INTEGER REFERENCES professional_applications(id) ON DELETE CASCADE, amount INTEGER NOT NULL, phone_number VARCHAR(30) NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'pending', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, processed_at TIMESTAMP)`);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_reviews_pro_id ON reviews(pro_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_reviews_status ON reviews(status)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_pros_status ON professional_applications(status)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_pros_city_profession ON professional_applications(city, profession)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_pros_npi ON professional_applications(npi)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_jobs_status ON job_offers(status)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_read ON contact_messages(is_read)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_admin_logs_created ON admin_logs(created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_admin_logs_action ON admin_logs(action)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_payment_status ON professional_applications(payment_status)`);

    const citiesData = [["Cotonou", 1], ["Abomey-Calavi", 2], ["Porto-Novo", 3], ["Parakou", 4], ["Bohicon", 5], ["Natitingou", 6], ["Ouidah", 7], ["Abomey", 8], ["Lokossa", 9], ["Djougou", 10], ["Kandi", 11], ["Malanville", 12], ["Savalou", 13], ["Dassa-Zoumè", 14], ["Savè", 15], ["Nikki", 16], ["Tchaourou", 17], ["Allada", 18], ["Comè", 19], ["Banikoara", 20], ["Sakété", 21], ["Pobè", 22], ["Adjohoun", 23], ["Akpro-Missérété", 24], ["Avrankou", 25], ["Sèmè-Podji", 26], ["Aplahoué", 27], ["Dogbo", 28], ["Grand-Popo", 29], ["Zagnanado", 30], ["Agbangnizoun", 31], ["Ouaké", 32], ["Bassila", 33], ["Boukoumbé", 34], ["Tanguiéta", 35], ["Copargo", 36], ["Glazoué", 37], ["Bantè", 38], ["Ouèssè", 39], ["Kalalé", 40]];
    for (const [name, order] of citiesData) { await pool.query(`INSERT INTO cities (name, display_order) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING`, [name, order]); }

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
      if (cityRes.rows.length) { for (const n of neighborhoods) { await pool.query(`INSERT INTO neighborhoods (city_id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [cityRes.rows[0].id, n]); } }
    }

    const profs = [
      ["Maçon", "Bâtiment"], ["Plombier", "Bâtiment"], ["Électricien", "Bâtiment"], ["Carreleur", "Bâtiment"], ["Peintre en bâtiment", "Bâtiment"], ["Menuisier bois", "Bâtiment"], ["Menuisier aluminium", "Bâtiment"], ["Soudeur", "Bâtiment"], ["Ferrailleur", "Bâtiment"], ["Charpentier", "Bâtiment"], ["Étanchéiste (toiture)", "Bâtiment"], ["Vitrier", "Bâtiment"], ["Serrurier", "Bâtiment"], ["Blindage de portes", "Bâtiment"], ["Domoticien", "Bâtiment"], ["Architecte", "Bâtiment"], ["Dessinateur bâtiment", "Bâtiment"], ["Géomètre", "Bâtiment"], ["Ingénieur BTP", "Bâtiment"], ["Conducteur de travaux", "Bâtiment"], ["Poseur de pavés", "Bâtiment"], ["Tailleur de pierre", "Bâtiment"], ["Marbrier", "Bâtiment"], ["Bétonnier", "Bâtiment"], ["Constructeur de cases traditionnelles", "Bâtiment"], ["Briquetier", "Bâtiment"], ["Tuilier", "Bâtiment"],
      ["Installateur de panneaux solaires", "Énergie"], ["Technicien de groupe électrogène", "Énergie"],
      ["Orpailleur", "Mines"], ["Extracteur de sable", "Mines"], ["Extracteur de gravier", "Mines"], ["Producteur de sel", "Mines"],
      ["Chaudronnier", "Métallurgie"], ["Tourneur", "Métallurgie"], ["Fraiseur", "Métallurgie"], ["Fondeur", "Métallurgie"], ["Ferronnier d'art", "Métallurgie"], ["Tréfileur", "Métallurgie"], ["Armurier", "Métallurgie"], ["Forgeron", "Métallurgie"], ["Perlier", "Métallurgie"],
      ["Ébéniste", "Bois"], ["Tapissier", "Bois"], ["Bûcheron", "Bois"], ["Charbonnier", "Bois"], ["Scieur de bois", "Bois"], ["Constructeur de pirogues", "Bois"], ["Sculpteur sur bois", "Bois"], ["Fabricant d'instruments de musique", "Bois"], ["Menuisier sur bambou", "Bois"], ["Vannier", "Bois"],
      ["Couturier", "Textile"], ["Couturière", "Textile"], ["Tailleur", "Textile"], ["Brodeur", "Textile"], ["Retoucheur", "Textile"], ["Styliste modéliste", "Textile"], ["Cordonnier", "Textile"], ["Tisserand", "Textile"], ["Fileur", "Textile"], ["Teinturier", "Textile"], ["Sérigraphe sur tissu", "Textile"], ["Tanneur", "Textile"], ["Maroquinier", "Textile"], ["Bottier", "Textile"], ["Sellier", "Textile"], ["Gainier", "Textile"], ["Relieur", "Textile"], ["Cireur de chaussures", "Textile"], ["Graveur sur cuir", "Textile"],
      ["Femme de ménage", "Maison"], ["Repassage à domicile", "Maison"], ["Cuisinier", "Maison"], ["Cuisinière", "Maison"], ["Gardien", "Maison"], ["Vigile", "Maison"], ["Nounou", "Maison"], ["Garde d'enfants", "Maison"], ["Jardinier", "Maison"], ["Désinsectisation", "Maison"], ["Dératisation", "Maison"], ["Plombier-déboucheur", "Maison"], ["Majordome", "Maison"], ["Chef de maison", "Maison"], ["Paysagiste", "Maison"], ["Blanchisseur", "Maison"], ["Pressing", "Maison"], ["Spécialiste en nettoyage de locaux", "Maison"], ["Spécialiste en traitement des déchets", "Maison"],
      ["Infirmier à domicile", "Santé"], ["Infirmière à domicile", "Santé"], ["Sage-femme", "Santé"], ["Kinésithérapeute", "Santé"], ["Aide-soignant", "Santé"], ["Pharmacien", "Santé"], ["Opticien", "Santé"], ["Lunetier", "Santé"], ["Psychologue", "Santé"], ["Thérapeute de couple", "Santé"], ["Nutritionniste", "Santé"], ["Diététicien", "Santé"], ["Coach sportif", "Santé"], ["Personal Trainer", "Santé"], ["Vétérinaire", "Santé"], ["Toiletteur pour animaux", "Santé"], ["Ostéopathe", "Santé"], ["Naturopathe", "Santé"], ["Garde-malade", "Santé"], ["Auxiliaire de vie", "Santé"], ["Prothésiste dentaire", "Santé"], ["Préparateur de pharmacopée traditionnelle", "Santé"],
      ["Coiffeur", "Beauté"], ["Coiffeuse", "Beauté"], ["Tresseuse", "Beauté"], ["Barbier", "Beauté"], ["Esthéticienne", "Beauté"], ["Maquilleuse", "Beauté"], ["Manucure", "Beauté"], ["Pédicure", "Beauté"], ["Masseur", "Beauté"], ["Masseuse", "Beauté"], ["Tatoueur", "Beauté"], ["Prothésiste ongulaire", "Beauté"], ["Nail Art", "Beauté"], ["Lash maker (Extensions de cils)", "Beauté"], ["Maquilleur professionnel", "Beauté"], ["Fabricant de savons", "Beauté"], ["Fabricant de parfums", "Beauté"], ["Fabricant de cosmétiques", "Beauté"],
      ["Mécanicien auto", "Automobile"], ["Mécanicien moto", "Automobile"], ["Électricien auto", "Automobile"], ["Carrossier", "Automobile"], ["Tôlier", "Automobile"], ["Vulcanisateur", "Automobile"], ["Chauffeur de taxi", "Transport"], ["Chauffeur de moto-taxi", "Transport"], ["Chauffeur personnel", "Transport"], ["Déménageur", "Transport"], ["Livreur", "Transport"], ["Coursier", "Transport"], ["Chauffeur de poids lourd", "Transport"], ["Camionneur", "Transport"], ["Transitaire", "Transport"], ["Déclarant en douane", "Transport"], ["Mécanicien agricole", "Automobile"],
      ["Traiteur", "Restauration"], ["Pâtissier", "Restauration"], ["Boulanger", "Restauration"], ["Vendeur de nourriture", "Restauration"], ["Boucher", "Restauration"], ["Charcutier", "Restauration"], ["Poissonnier", "Restauration"], ["Barista", "Restauration"], ["Chef à domicile", "Restauration"], ["Wedding Cake Designer", "Restauration"], ["Barman", "Événementiel"], ["Mixologue", "Événementiel"], ["Hôte(sse) d'accueil", "Événementiel"], ["Protocole", "Événementiel"], ["Fleuriste", "Événementiel"], ["Art floral", "Événementiel"], ["Décorateur floral", "Événementiel"],
      ["Guide touristique", "Tourisme"], ["Réceptionniste d'hôtel", "Tourisme"], ["Concierge d'hôtel", "Tourisme"], ["Maître d'hôtel", "Tourisme"], ["Sommelier", "Tourisme"], ["Gouvernant d'établissement hôtelier", "Tourisme"],
      ["Transformateur de fruits/légumes", "Agroalimentaire"], ["Fabricant de condiments", "Agroalimentaire"], ["Fabricant d'huiles", "Agroalimentaire"], ["Transformateur de poissons", "Agroalimentaire"], ["Fabricant de produits laitiers", "Agroalimentaire"], ["Apiculteur", "Agroalimentaire"], ["Biscuitier", "Agroalimentaire"], ["Confiseur", "Agroalimentaire"], ["Fabricant d'aliments pour animaux", "Agroalimentaire"],
      ["Bijoutier", "Artisanat d'art"], ["Orfèvre", "Artisanat d'art"], ["Joaillier", "Artisanat d'art"], ["Bronzier", "Artisanat d'art"], ["Sculpteur sur pierre", "Artisanat d'art"], ["Sculpteur sur métal", "Artisanat d'art"], ["Potier", "Artisanat d'art"], ["Céramiste", "Artisanat d'art"], ["Verrier", "Artisanat d'art"], ["Fabricant de jeux et jouets traditionnels", "Artisanat d'art"], ["Encadreur", "Artisanat d'art"], ["Graveur", "Artisanat d'art"], ["Maquettiste", "Artisanat d'art"],
      ["Développeur web", "Informatique"], ["Développeur mobile", "Informatique"], ["Informaticien", "Informatique"], ["Réparateur de téléphone", "Informatique"], ["Réparateur d'ordinateur", "Informatique"], ["Graphiste", "Informatique"], ["Community manager", "Informatique"], ["Photographe", "Informatique"], ["Vidéaste", "Informatique"], ["Ingénieur réseau", "Informatique"], ["Monteur vidéo", "Informatique"], ["Motion Designer", "Informatique"], ["Pilote de drone", "Informatique"], ["Expert en cybersécurité", "Informatique"], ["Webmaster", "Informatique"], ["Gestionnaire de site web", "Informatique"], ["Data Analyst", "Informatique"], ["Testeur de jeux vidéo", "Informatique"], ["E-sport manager", "Informatique"], ["Créateur de contenu", "Informatique"], ["Cameraman", "Médias"], ["Imprimeur", "Médias"], ["Installateur/réparateur de matériel audiovisuel", "Médias"], ["Influenceur", "Médias"],
      ["Professeur de Maths", "Éducation"], ["Professeur de Français", "Éducation"], ["Professeur d'Anglais", "Éducation"], ["Enseignant primaire", "Éducation"], ["Formateur informatique", "Éducation"], ["Coach scolaire", "Éducation"], ["Aide aux devoirs", "Éducation"],
      ["Comptable", "Professionnel"], ["Fiscaliste", "Professionnel"], ["Juriste", "Professionnel"], ["Avocat", "Professionnel"], ["Notaire", "Professionnel"], ["Traducteur", "Professionnel"], ["Rédacteur de contenu", "Professionnel"], ["Secrétaire", "Professionnel"], ["Assistant administratif", "Professionnel"], ["Consultant", "Professionnel"], ["Démarcheur", "Professionnel"], ["Agent de sécurité", "Professionnel"], ["Caissier", "Commerce"], ["Magasinier", "Commerce"], ["Gestionnaire de stock", "Commerce"],
      ["Agent immobilier", "Immobilier"], ["Courtier", "Immobilier"], ["Agriculteur", "Agriculture"], ["Maraîcher", "Agriculture"], ["Éleveur", "Agriculture"], ["Pêcheur", "Agriculture"], ["Pépiniériste", "Agriculture"], ["Climatisation", "Divers"], ["Froid", "Divers"], ["Antenniste", "Divers"], ["Puisatier", "Divers"], ["Réparateur de télévision", "Divers"], ["Réparateur d'électroménager", "Divers"],
      ["Quincaillerie", "Boutiques & Commerces"], ["Boutique de tissus et mercerie", "Boutiques & Commerces"], ["Mercerie", "Boutiques & Commerces"], ["Boutique de téléphones et accessoires", "Boutiques & Commerces"], ["Cabine téléphonique", "Boutiques & Commerces"], ["Boutique de pièces détachées (auto/moto)", "Boutiques & Commerces"], ["Épicerie fine / Alimentation générale", "Boutiques & Commerces"], ["Boutique de cosmétiques et parfums", "Boutiques & Commerces"], ["Boutique de matériaux de construction", "Boutiques & Commerces"], ["Librairie / Papeterie / Fournitures scolaires", "Boutiques & Commerces"], ["Boutique d'électroménager", "Boutiques & Commerces"], ["Boutique d'ameublement et décoration", "Boutiques & Commerces"], ["Boutique de meubles et matelas", "Boutiques & Commerces"], ["Animalerie", "Boutiques & Commerces"], ["Boutique de prêt-à-porter / Vêtements", "Boutiques & Commerces"], ["Boutique de lingerie et layette", "Boutiques & Commerces"], ["Friperie", "Boutiques & Commerces"], ["Boutique d'articles de sport et de loisirs", "Boutiques & Commerces"], ["Boutique de jeux vidéo et consoles", "Boutiques & Commerces"], ["Boutique d'articles de fête et événementiel", "Boutiques & Commerces"], ["Boutique de bricolage", "Boutiques & Commerces"], ["Boutique de chaussures et maroquinerie", "Boutiques & Commerces"], ["Boutique de jouets", "Boutiques & Commerces"], ["Boutique de souvenirs / Artisanat local", "Boutiques & Commerces"], ["Pharmacie / Dépôt de médicaments", "Boutiques & Commerces"], ["Boutique de pagnes et tissus", "Boutiques & Commerces"], ["Boutique de céréales et condiments", "Boutiques & Commerces"], ["Boutique de tubercules et huiles alimentaires", "Boutiques & Commerces"], ["Boutique d'ustensiles de cuisine", "Boutiques & Commerces"], ["Boutique de bijoux", "Boutiques & Commerces"], ["Boutique de produits d'entretien et détergents", "Boutiques & Commerces"], ["Débit de boissons / Bar", "Boutiques & Commerces"], ["Boutique de matériel d'électricité et de plomberie", "Boutiques & Commerces"], ["Boutique de produits locaux et agroalimentaires", "Boutiques & Commerces"], ["Concept store / Boutique de mode", "Boutiques & Commerces"], ["Boutique d'art et de décoration", "Boutiques & Commerces"]
    ];
    let orderCounter = 0;
    for (const [name, category] of profs) { orderCounter += 1; await pool.query(`INSERT INTO professions (name, category, display_order) VALUES ($1, $2, $3) ON CONFLICT (name) DO NOTHING`, [name, category, orderCounter]); }

    setInterval(async () => {
      try {
        const expired = await pool.query(`SELECT id, photo_profil_url, photo_identite_url, photo_kyc_url, photo_activite_url, photo_galerie_1, photo_galerie_2, photo_galerie_3 FROM professional_applications WHERE status = 'payment_pending' AND payment_status = 'unpaid' AND created_at < NOW() - INTERVAL '48 hours'`);
        for (const row of expired.rows) {
          await Promise.allSettled([row.photo_profil_url, row.photo_identite_url, row.photo_kyc_url, row.photo_activite_url, row.photo_galerie_1, row.photo_galerie_2, row.photo_galerie_3].map(url => url && deleteFromCloudinary(url)));
          await pool.query(`DELETE FROM professional_applications WHERE id = $1`, [row.id]);
        }
        
        const oldRejected = await pool.query(`SELECT id, photo_profil_url, photo_identite_url, photo_kyc_url, photo_activite_url, photo_galerie_1, photo_galerie_2, photo_galerie_3 FROM professional_applications WHERE status IN ('rejected', 'corrections_requested') AND updated_at < NOW() - INTERVAL '90 days'`);
        for (const row of oldRejected.rows) {
          await Promise.allSettled([row.photo_profil_url, row.photo_identite_url, row.photo_kyc_url, row.photo_activite_url, row.photo_galerie_1, row.photo_galerie_2, row.photo_galerie_3].map(url => url && deleteFromCloudinary(url)));
          await pool.query(`DELETE FROM professional_applications WHERE id = $1`, [row.id]);
        }
      } catch (e) { console.error("Erreur cleanup :", e.message); }
    }, 6 * 60 * 60 * 1000);

    console.log("✅ Toutes les tables sont prêtes et à jour !");
    app.listen(PORT, "0.0.0.0", () => { console.log(`🚀 TrouveMoi démarré sur le port ${PORT}.`); });
  } catch (error) { console.error("❌ Erreur au démarrage :", error); process.exit(1); }
}
startServer();
