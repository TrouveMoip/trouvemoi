const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const compression = require("compression");

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === "production";

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
const PAYMENT_AMOUNT = 1500;
const REFERRAL_BONUS = 100;
const WITHDRAWAL_MIN = 1000;

const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ADMIN_SESSION_SECRET = process.env.ADMIN_SESSION_SECRET;
const HEALTH_TOKEN = process.env.HEALTH_TOKEN;
const CRON_SECRET = process.env.CRON_SECRET;
const KKIAPAY_WEBHOOK_SECRET = process.env.KKIAPAY_WEBHOOK_SECRET;
const PAYMENT_ALLOW_UNBOUND = process.env.PAYMENT_ALLOW_UNBOUND === "true";
const TERMII_API_KEY = process.env.TERMII_API_KEY;
const TERMII_SENDER_ID = process.env.TERMII_SENDER_ID || "TrouveMoi";
const ADMIN_TOTP_SECRET = process.env.ADMIN_TOTP_SECRET;
const ERROR_WEBHOOK_URL = process.env.ERROR_WEBHOOK_URL;
const EMAIL_WEBHOOK_URL = process.env.EMAIL_WEBHOOK_URL;

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) { console.error("Erreur : ADMIN_PASSWORD manquant."); process.exit(1); }
if (!ADMIN_SESSION_SECRET || ADMIN_SESSION_SECRET.length < 32) { console.error("Erreur : ADMIN_SESSION_SECRET manquant."); process.exit(1); }
if (IS_PRODUCTION && !RECAPTCHA_SECRET_KEY) { console.error("Erreur : RECAPTCHA_SECRET_KEY obligatoire."); process.exit(1); }
if (IS_PRODUCTION && BYPASS_PAYMENT) { console.error("Erreur : BYPASS_PAYMENT interdit."); process.exit(1); }
if (!BYPASS_PAYMENT && (!KKIAPAY_PUBLIC_KEY || !KKIAPAY_PRIVATE_KEY)) { console.error("Erreur : cles Kkiapay manquantes."); process.exit(1); }
if (IS_PRODUCTION && (!HEALTH_TOKEN || !CRON_SECRET)) { console.error("Erreur : HEALTH_TOKEN et CRON_SECRET obligatoires."); process.exit(1); }

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

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "geolocation=(self)");
  if (IS_PRODUCTION) { res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains"); }
  next();
});

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

function escapeHtml(value) { return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function safeEqual(a, b) {
  const b1 = Buffer.from(String(a ?? ""));
  const b2 = Buffer.from(String(b ?? ""));
  if (b1.length === 0 || b1.length !== b2.length) return false;
  return crypto.timingSafeEqual(b1, b2);
}

function normalizePhone(value) { return String(value || "").trim().replace(/[()\s.-]/g, ""); }

function cleanBeninPhone(value) {
  const normalized = normalizePhone(value).replace(/^(?:\+?229|00229)/, "");
  return /^01\d{8}$/.test(normalized) ? normalized : null;
}

function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const character of String(input || "").toUpperCase().replace(/[^A-Z2-7]/g, "")) {
    const value = alphabet.indexOf(character);
    if (value === -1) continue;
    bits += value.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) { bytes.push(parseInt(bits.slice(index, index + 8), 2)); }
  return Buffer.from(bytes);
}

function verifyTotp(secret, token) {
  const submitted = String(token || "").replace(/\s/g, "");
  if (!/^\d{6}$/.test(submitted)) return false;
  const key = base32Decode(secret);
  if (!key.length) return false;
  const counter = Math.floor(Date.now() / 30000);
  for (let offset = -1; offset <= 1; offset += 1) {
    const buffer = Buffer.alloc(8);
    buffer.writeBigUInt64BE(BigInt(counter + offset));
    const hmac = crypto.createHmac("sha1", key).update(buffer).digest();
    const position = hmac[hmac.length - 1] & 0x0f;
    const code = ((hmac.readUInt32BE(position) & 0x7fffffff) % 1000000).toString().padStart(6, "0");
    if (safeEqual(code, submitted)) return true;
  }
  return false;
}

async function verifyRecaptcha(token) {
  if (!RECAPTCHA_SECRET_KEY) return !IS_PRODUCTION;
  if (!token) return false;
  try {
    const res = await fetch("https://www.google.com/recaptcha/api/siteverify", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: `secret=${RECAPTCHA_SECRET_KEY}&response=${token}` });
    const data = await res.json();
    return data.success && data.score >= 0.5;
  } catch (e) { return false; }
}

function createSessionToken(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${encoded}.${crypto.createHmac("sha256", ADMIN_SESSION_SECRET).update(encoded).digest("base64url")}`;
}

function verifySessionToken(token) {
  try {
    if (!token) return null;
    const [encoded, signature] = token.split(".");
    if (!encoded || !signature) return null;
    const expected = crypto.createHmac("sha256", ADMIN_SESSION_SECRET).update(encoded).digest("base64url");
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

function setSessionCookie(res, token) { 
  const currentCookies = res.getHeader("Set-Cookie") || [];
  const newCookie = `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_DURATION / 1000}`;
  res.setHeader("Set-Cookie", Array.isArray(currentCookies) ? [...currentCookies, newCookie] : [currentCookies, newCookie].filter(Boolean));
}
function clearSessionCookie(res) { 
  const currentCookies = res.getHeader("Set-Cookie") || [];
  const newCookie = `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
  res.setHeader("Set-Cookie", Array.isArray(currentCookies) ? [...currentCookies, newCookie] : [currentCookies, newCookie].filter(Boolean));
}
function setProCookie(res, code) { 
  const currentCookies = res.getHeader("Set-Cookie") || [];
  const newCookie = `${PRO_COOKIE}=${code}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_DURATION / 1000}`;
  res.setHeader("Set-Cookie", Array.isArray(currentCookies) ? [...currentCookies, newCookie] : [currentCookies, newCookie].filter(Boolean));
}
function clearProCookie(res) { 
  const currentCookies = res.getHeader("Set-Cookie") || [];
  const newCookie = `${PRO_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
  res.setHeader("Set-Cookie", Array.isArray(currentCookies) ? [...currentCookies, newCookie] : [currentCookies, newCookie].filter(Boolean));
}

async function requireAdmin(req, res, next) {
  const session = verifySessionToken(readCookie(req, SESSION_COOKIE));
  if (!session || typeof session.jti !== "string") { clearSessionCookie(res); return res.redirect(303, "/admin"); }
  try {
    const active = await pool.query(`SELECT 1 FROM admin_sessions WHERE jti = $1 AND revoked_at IS NULL AND expires_at > NOW()`, [session.jti]);
    if (!active.rows.length) { clearSessionCookie(res); return res.redirect(303, "/admin"); }
  } catch (error) { console.error("Erreur verification session admin :", error.message); return res.status(503).send(page("Erreur", "<h2>Service temporairement indisponible.</h2>", null)); }
  req.adminSession = session;
  next();
}

function verifyCsrf(req, res, next) {
  const csrf = req.adminSession?.csrf;
  if (!csrf || !req.body.csrfToken || !safeEqual(req.body.csrfToken, csrf)) { return res.status(403).send(page("Refuse", "<h1>Erreur CSRF</h1>", null)); }
  next();
}

function generateProCode() { return `TM${crypto.randomInt(10000000, 100000000)}`; }
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

function generateClientCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (let index = 0; index < 6; index += 1) code += alphabet[crypto.randomInt(0, alphabet.length)];
  return code;
}

async function getOrCreateClientCode(visitorId) {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const code = generateClientCode();
    try {
      const result = await pool.query(`INSERT INTO client_codes (code, visitor_id) VALUES ($1, $2) ON CONFLICT (visitor_id) DO UPDATE SET visitor_id = EXCLUDED.visitor_id RETURNING code`, [code, visitorId]);
      if (result.rows.length) return result.rows[0].code;
    } catch (error) { if (error.code !== "23505") throw error; }
  }
  return null;
}

function getDisplayName(person) { return (person?.company_name?.trim() || person?.full_name || ""); }
function getCsrf(req) { return req.adminSession?.csrf || ""; }

async function logAdminAction(action, targetType, targetId, details) {
  try { await pool.query(`INSERT INTO admin_logs (action, target_type, target_id, details) VALUES ($1, $2, $3, $4)`, [action, targetType, targetId, details]); } catch (e) { console.error("Erreur log admin :", e.message); }
}

function reportError(context, error) {
  const message = error?.message || String(error || "erreur inconnue");
  console.error(`[${context}]`, message);
  if (!ERROR_WEBHOOK_URL) return;
  fetch(ERROR_WEBHOOK_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ application: "TrouveMoi", context, message, stack: String(error?.stack || "").slice(0, 2000), at: new Date().toISOString() }) }).catch(() => {});
}

async function takeRateLimit(key, max, windowMs) {
  try {
    const seconds = Math.max(1, Math.ceil(windowMs / 1000));
    const result = await pool.query(`
  INSERT INTO rate_limits_v2 ("limit_key", count, window_start) VALUES ($1, 1, NOW())
  ON CONFLICT ("limit_key") DO UPDATE SET
    count = CASE
      WHEN rate_limits_v2.window_start < NOW() - make_interval(secs => $2::double precision)
      THEN 1 ELSE rate_limits_v2.count + 1 END,
    window_start = CASE
      WHEN rate_limits_v2.window_start < NOW() - make_interval(secs => $2::double precision)
      THEN NOW() ELSE rate_limits_v2.window_start END
  RETURNING count
`, [key, seconds]);
    return Number(result.rows[0].count) <= max;
  } catch (error) { console.error("Erreur limitation de debit :", error.message); return true; }
}

async function clearRateLimit(key) {
  try { await pool.query("DELETE FROM rate_limits WHERE limit_key = $1", [key]); } catch (error) { console.error("Erreur reinitialisation limitation :", error.message); }
}

function toInternationalBenin(phone) {
  const digits = normalizePhone(phone).replace(/^\+/, "");
  if (/^22901\d{8}$/.test(digits)) return digits;
  if (/^01\d{8}$/.test(digits)) return `229${digits}`;
  return null;
}

async function queueNotification({ recipient, body, subject = null, channel = "sms" }) {
  const target = String(recipient || "").trim();
  if (!target) return;
  try { await pool.query(`INSERT INTO notifications (channel, recipient, subject, body) VALUES ($1, $2, $3, $4)`, [channel, target.slice(0, 254), subject, String(body || "").slice(0, 1000)]); } catch (error) { console.error("Erreur file notification :", error.message); }
}

async function processNotifications(limit = 10) {
  const pending = await pool.query(`SELECT id, channel, recipient, subject, body FROM notifications WHERE status = 'pending' AND channel IN ('sms', 'email') ORDER BY created_at ASC LIMIT $1`, [limit]);
  let sent = 0;
  for (const item of pending.rows) {
    try {
      if (item.channel === "sms") {
        if (!TERMII_API_KEY) continue;
        const to = toInternationalBenin(item.recipient);
        if (!to) { await pool.query(`UPDATE notifications SET status = 'failed', error = 'numero invalide' WHERE id = $1`, [item.id]).catch(() => {}); continue; }
        const response = await fetch("https://api.ng.termii.com/api/sms/send", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ to, from: TERMII_SENDER_ID, sms: item.body, type: "plain", channel: "generic", api_key: TERMII_API_KEY }) });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
      } else if (item.channel === "email") {
        if (!EMAIL_WEBHOOK_URL) continue;
        const response = await fetch(EMAIL_WEBHOOK_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ to: item.recipient, subject: item.subject || "TrouveMoi", body: item.body }) });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
      } else { continue; }
      await pool.query(`UPDATE notifications SET status = 'sent', sent_at = NOW(), error = NULL WHERE id = $1`, [item.id]);
      sent += 1;
    } catch (error) { await pool.query(`UPDATE notifications SET status = 'failed', error = $1 WHERE id = $2`, [String(error.message).slice(0, 500), item.id]).catch(() => {}); }
  }
  return { sent, total: pending.rowCount };
}

function paymentMatchesDossier(verification, dossier) {
  const reference = String(verification.reference || "").trim().toUpperCase();
  if (!reference) return !IS_PRODUCTION || PAYMENT_ALLOW_UNBOUND;
  return reference === String(dossier.tracking_code || "").trim().toUpperCase();
}

async function settlePayment({ dossierId, transactionId, amount, method, source }) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)", [String(transactionId)]);
    const reused = await client.query(`SELECT id FROM professional_applications WHERE payment_ref = $1 AND id <> $2 LIMIT 1`, [transactionId, dossierId]);
    if (reused.rows.length) { await client.query("ROLLBACK"); return { ok: false, reason: "transaction_already_used" }; }
    const updated = await client.query(`
      UPDATE professional_applications SET payment_status = 'paid', payment_ref = $1, payment_amount = $2, payment_date = NOW(), payment_method = $3,
      status = CASE WHEN status = 'payment_pending' THEN 'pending' ELSE status END, updated_at = NOW()
      WHERE id = $4 AND payment_status <> 'paid' RETURNING id, referred_by, tracking_code, phone, contact_email
    `, [transactionId, amount, method, dossierId]);
    if (!updated.rowCount) { await client.query("ROLLBACK"); return { ok: true, alreadyPaid: true }; }
    const dossier = updated.rows[0];
    if (dossier.referred_by) {
      const parrain = await client.query(`SELECT id FROM professional_applications WHERE referral_code = $1`, [dossier.referred_by]);
      if (parrain.rows.length) { await client.query(`UPDATE professional_applications SET referral_balance = referral_balance + $1, updated_at = NOW() WHERE id = $2`, [REFERRAL_BONUS, parrain.rows[0].id]); }
    }
    await client.query("COMMIT");
    await logAdminAction("payment_received", "pro", dossierId, `${source} | Montant: ${amount} FCFA | Ref: ${transactionId}`);
    await queueNotification({ recipient: dossier.phone, body: `TrouveMoi: paiement recu (${amount} FCFA). Votre dossier ${dossier.tracking_code} est en cours d'examen.` });
    if (dossier.contact_email) { await queueNotification({ channel: "email", recipient: dossier.contact_email, subject: "Paiement reçu - TrouveMoi", body: `Bonjour, nous confirmons la réception de votre paiement de ${amount} FCFA. Votre dossier ${dossier.tracking_code} est en cours d'examen.` }); }
    if (dossier.referred_by) { await logAdminAction("referral_bonus", "pro", dossierId, `Bonus de ${REFERRAL_BONUS} FCFA verse au parrain ${dossier.referred_by}`); }
    return { ok: true, alreadyPaid: false };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function verifyKkiapayTransaction(transactionId) {
  try {
    const res = await fetch(`https://api.kkiapay.me/api/v1/transactions/status`, { method: "POST", headers: { "Content-Type": "application/json", "x-api-key": KKIAPAY_PUBLIC_KEY, "x-private-key": KKIAPAY_PRIVATE_KEY }, body: JSON.stringify({ transactionId }) });
    if (!res.ok) return { success: false, reason: `HTTP ${res.status}` };
    const data = await res.json();
    const rawReference = data.data ?? data.metadata ?? data.reference ?? null;
    let reference = rawReference;
    if (Array.isArray(reference)) reference = reference[0] ?? null;
    if (reference && typeof reference === "object") { reference = reference.tracking_code || reference.trackingCode || reference.reference || reference.code || null; }
    return { success: data.status === "SUCCESS" && Number(data.amount) >= PAYMENT_AMOUNT, amount: Number(data.amount || 0), method: data.method || null, reference: reference ? String(reference) : null };
  } catch (e) { return { success: false, reason: "network" }; }
}

function renderStars(rating) {
  let html = "";
  const full = Math.floor(rating), half = (rating - full) >= 0.5;
  for (let i = 1; i <= 5; i++) html += (i <= full) ? "★" : (i === full + 1 && half) ? "⯨" : "☆";
  return html;
}

function renderKycBadge(person, size) {
  if (!person || !person.kyc_verified) return "";
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
  return `<nav><a href="/">Professionnels</a><a href="/mes-favoris">❤️ Favoris</a><a href="/emplois">Emploi</a><a href="/devenir-professionnel">Devenir pro</a><a href="/mon-espace-pro">Espace pro</a><a href="/mon-compte">Mon compte</a><a href="/contact">Contact</a></nav>`;
}
function page(title, content, proConnected, meta = {}) {
  const pageTitle = `${meta.title || title} - TrouveMoi`;
  const pageDescription = meta.description || "TrouveMoi - Mise en relation entre clients et professionnels verifies au Benin.";
  const canonicalUrl = meta.canonical ? `${APP_URL}${meta.canonical}` : null;
  return `
    <!DOCTYPE html>
    <html lang="fr">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="description" content="${escapeHtml(pageDescription)}">
      ${canonicalUrl ? `<link rel="canonical" href="${escapeHtml(canonicalUrl)}">` : ""}
      <meta property="og:title" content="${escapeHtml(pageTitle)}">
      <meta property="og:description" content="${escapeHtml(pageDescription)}">
      <meta property="og:type" content="website">
      <meta property="og:site_name" content="TrouveMoi">
      <meta property="og:url" content="${escapeHtml(canonicalUrl || APP_URL)}">
      <meta name="twitter:card" content="summary">
      <meta name="theme-color" content="#1e40af">
      <link rel="manifest" href="/manifest.json">
      <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 50 50'%3E%3Crect width='50' height='50' rx='10' fill='%231e40af'/%3E%3Ctext x='25' y='35' text-anchor='middle' font-family='Arial' font-size='22' font-weight='900' fill='white'%3ETM%3C/text%3E%3C/svg%3E">
      <title>${escapeHtml(pageTitle)}</title>
      <script src="https://www.google.com/recaptcha/api.js?render=6LelG_0tAAAAAGyx3z4xqCkxZ6rga6sF0RQ_RUtC"></script>
      <script>
        (function () {
          var GA_ID = "G-6YQ5R6M4ET";
          function loadAnalytics() {
            if (window.__tmGaLoaded) return;
            window.__tmGaLoaded = true;
            var tag = document.createElement("script");
            tag.async = true;
            tag.src = "https://www.googletagmanager.com/gtag/js?id=" + GA_ID;
            document.head.appendChild(tag);
            window.dataLayer = window.dataLayer || [];
            function gtag() { window.dataLayer.push(arguments); }
            window.gtag = gtag;
            gtag("js", new Date());
            gtag("config", GA_ID);
          }
          var consent = localStorage.getItem("tm_analytics_consent");
          if (consent === "yes") { loadAnalytics(); return; }
          if (consent === "no") return;
          document.addEventListener("DOMContentLoaded", function () {
            var bar = document.createElement("div");
            bar.style.cssText = "position:fixed;left:0;right:0;bottom:0;z-index:99999;background:#111827;color:#fff;padding:14px 20px;display:flex;gap:12px;align-items:center;justify-content:center;flex-wrap:wrap;font-size:14px;";
            var text = document.createElement("span");
            text.textContent = "Nous utilisons des cookies de mesure d'audience pour améliorer le site.";
            var accept = document.createElement("button");
            accept.textContent = "Accepter";
            accept.style.cssText = "background:#10b981;color:#fff;border:none;padding:8px 16px;border-radius:8px;cursor:pointer;";
            var refuse = document.createElement("button");
            refuse.textContent = "Refuser";
            refuse.style.cssText = "background:#374151;color:#fff;border:none;padding:8px 16px;border-radius:8px;cursor:pointer;";
            accept.onclick = function () { localStorage.setItem("tm_analytics_consent", "yes"); bar.remove(); loadAnalytics(); };
            refuse.onclick = function () { localStorage.setItem("tm_analytics_consent", "no"); bar.remove(); };
            bar.appendChild(text);
            bar.appendChild(accept);
            bar.appendChild(refuse);
            document.body.appendChild(bar);
          });
        })();
      </script>
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
        .star-rating-input label:hover, .star-rating-input label:hover ~ label, .star-rating-input input[type="radio"]:checked ~ label { color: #f59e0b; }
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
            <a href="https://www.facebook.com/profile.php?id=61595327533405" target="_blank" class="facebook-btn">
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
          navigator.serviceWorker.getRegistrations().then(function (registrations) {
            registrations.forEach(function (registration) { registration.unregister(); });
          }).catch(function () {});
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
    const totalPros = totalAllPros;
    const totalPages = Math.ceil(totalPros / limit);

    const query = `SELECT p.id, p.full_name, p.company_name, p.phone, p.phone_public, p.city, p.neighborhood, p.profession, p.experience, p.service_description, p.service_area, p.availability, p.photo_activite_url, p.type_lieu, p.latitude, p.longitude, p.est_ouvert, p.kyc_verified, 
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
              <div class="pro-name">${escapeHtml(displayName)} ${renderKycBadge(person)}</div>
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
          <div style="color: white; font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 20px;">Pros vérifiés</div>
          
          <h1 style="font-size: 32px; font-weight: 800; color: white; margin-bottom: 12px; line-height: 1.2;">Trouvez le professionnel<br><span style="color: #fbbf24;">qu'il vous faut près de chez vous.</span></h1>
          <p style="font-size: 16px; color: rgba(255,255,255,0.9); margin-bottom: 30px;">Des professionnels vérifiés au Bénin, en 1 clic.</p>
          
<a href="/recherche" class="button" style="background: #f59e0b; color: white; font-size: 18px; padding: 16px 40px; font-weight: 800; border-radius: 50px; box-shadow: 0 4px 15px rgba(245,158,11,0.4);">🔍 Rechercher un pro</a>

<div style="margin-top: 20px; max-width: 600px; margin-left: auto; margin-right: auto;">
  <form action="/recherche" method="GET" style="display: flex; gap: 8px; background: white; padding: 8px; border-radius: 50px; box-shadow: 0 4px 15px rgba(0,0,0,0.2);">
    <input name="profession" placeholder="Quel métier ? (ex: maçon)" style="flex: 1; border: none; padding: 12px 20px; border-radius: 50px; margin: 0; font-size: 15px;">
    <input name="city" placeholder="Ville" style="flex: 0 0 140px; border: none; padding: 12px 20px; border-radius: 50px; margin: 0; font-size: 15px; background: #f3f4f6;">
    <button type="submit" style="margin: 0; padding: 12px 24px; border-radius: 50px; background: #2563eb;">Go</button>
  </form>
</div>        </div>
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
    const lat = Number(req.query.lat);
    const lng = Number(req.query.lng);
    const hasCoords = Number.isFinite(lat) && Number.isFinite(lng) && Math.abs(lat) <= 90 && Math.abs(lng) <= 180;
    
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
      if (category) { values.push(category); whereClause += ` AND (p.profession_category = $${values.length} OR p.profession IN (SELECT name FROM professions WHERE category = $${values.length}))`; }

      const countResult = await pool.query(`SELECT COUNT(*) FROM professional_applications p ${whereClause}`, values);
      totalPros = parseInt(countResult.rows[0].count);
      totalPages = Math.ceil(totalPros / limit);

      let orderBy = "p.created_at DESC";
      if (sort === "rating") {
        orderBy = "avg_rating DESC, reviews_count DESC, p.created_at DESC";
      } else if (sort === "distance" && hasCoords) {
        orderBy = `(6371 * acos(LEAST(1, cos(radians(${lat})) * cos(radians(p.latitude)) * cos(radians(p.longitude) - radians(${lng})) + sin(radians(${lat})) * sin(radians(p.latitude))))) ASC NULLS LAST, p.created_at DESC`;
      }

      const queryValues = [...values, visitorId, limit, offset];
      const query = `
        SELECT p.id, p.full_name, p.company_name, p.phone, p.phone_public, p.city, p.neighborhood, p.profession, p.service_description, p.type_lieu, p.latitude, p.longitude, p.kyc_verified, 
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
                <div class="pro-name">${escapeHtml(displayName)} ${renderKycBadge(person)}</div>
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

          <select id="sort-select" name="sort" style="flex: 0 0 150px; border: 1px solid #cbd5e0; margin: 0; padding: 16px; font-size: 14px; border-radius: 12px; background: white;">
            <option value="pertinence" ${sort === 'pertinence' ? 'selected' : ''}>Plus récents</option>
            <option value="rating" ${sort === 'rating' ? 'selected' : ''}>Mieux notés</option>
            <option value="distance" ${sort === 'distance' ? 'selected' : ''}>Plus proches</option>
          </select>

          <button type="button" onclick="useMyPosition()" class="button secondary" style="flex: 0 0 170px; margin: 0; padding: 16px; border-radius: 12px; font-size: 14px;">📍 Autour de moi</button>

          <button type="submit" style="flex: 0 0 120px; border-radius: 12px; padding: 16px; margin: 0; background: #f59e0b; font-size: 16px; font-weight: 800; color: white; box-shadow: 0 4px 12px rgba(245,158,11,0.3);">🔍 Filtrer</button>

          <input type="hidden" name="lat" id="lat-input" value="${hasCoords ? lat : ""}">
          <input type="hidden" name="lng" id="lng-input" value="${hasCoords ? lng : ""}">
          
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
        function useMyPosition() {
          if (!navigator.geolocation) {
            alert("La géolocalisation n'est pas disponible sur cet appareil.");
            return;
          }
          navigator.geolocation.getCurrentPosition(function (position) {
            document.getElementById('lat-input').value = position.coords.latitude;
            document.getElementById('lng-input').value = position.coords.longitude;
            document.getElementById('sort-select').value = 'distance';
            document.querySelector('form[action="/recherche"]').submit();
          }, function () {
            alert("Impossible de vous localiser. Vous pouvez choisir une ville manuellement.");
          });
        }

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
});app.post("/api/track/:id/:type", async (req, res) => {
  try {
    const id = Number(req.params.id);
    const type = req.params.type;
    const visitorId = getOrCreateVisitorId(req, res);
    if (!Number.isSafeInteger(id) || id < 1) return res.json({ ok: false });
    let col = "";
    if (type === "phone") col = "phone_clicks";
    else if (type === "wa") col = "wa_clicks";
    else return res.json({ ok: false });

    await pool.query(`INSERT INTO pro_stats (pro_id, date, ${col}, last_visitor_id) VALUES ($1, CURRENT_DATE, 1, $2) ON CONFLICT (pro_id, date) DO UPDATE SET ${col} = pro_stats.${col} + 1, last_visitor_id = $2`, [id, visitorId]);

    if (type === "phone" || type === "wa") {
      await pool.query(`INSERT INTO contact_events (pro_id, visitor_id, type) VALUES ($1, $2, $3)`, [id, visitorId, type]);
    }

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
            <div class="pro-name">${escapeHtml(displayName)} ${renderKycBadge(person)}</div>
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

app.get("/mon-compte", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const visitorId = getOrCreateVisitorId(req, res);
  
  const clientResult = await pool.query(`SELECT * FROM client_codes WHERE visitor_id = $1`, [visitorId]);
  const client = clientResult.rows[0];
  
  const favorites = await pool.query(`SELECT COUNT(*) FROM client_favorites WHERE visitor_id = $1`, [visitorId]);
  const count = Number(favorites.rows[0]?.count || 0);

  let topSection = "";

  if (!client || !client.phone) {
    topSection = `
      <h2 style="text-align:center;">Créer mon compte client</h2>
      <p style="font-size:14px; color:#4b5563; text-align:center; margin-bottom:20px;">Enregistrez-vous pour sécuriser vos favoris.</p>
      <form action="/mon-compte/enregistrer" method="POST">
        <label>Nom complet *</label>
        <input name="full_name" required maxlength="150" placeholder="Ex: Jean Dupont">
        <label>Numéro de téléphone *</label>
        <input name="phone" type="tel" required pattern="01[0-9]{8}" placeholder="0194010345" title="10 chiffres commençant par 01">
        <button type="submit" style="width:100%; margin-top:10px; background: #2563eb;">Créer mon compte</button>
      </form>
    `;
  } else {
    const code = await getOrCreateClientCode(visitorId);
    topSection = `
      <h2 style="text-align:center;">Bonjour ${escapeHtml(client.full_name)}</h2>
      <p style="font-size:14px; color:#4b5563; text-align:center;">Votre code de récupération secret :</p>
      <div class="pro-code-box" style="margin: 20px 0;">
        <div style="font-size:12px; text-transform:uppercase; letter-spacing:1px; opacity:0.85;">Code de récupération</div>
        <div class="pro-code-value" style="font-size:36px; letter-spacing: 5px;">${escapeHtml(code || "Indisponible")}</div>
      </div>
      <p style="font-size:14px; text-align:center;"><strong>${count}</strong> favori(s) enregistré(s).</p>
      <div style="text-align:center; margin:16px 0;"><a class="button" href="/mes-favoris">❤️ Voir mes favoris</a></div>
    `;
  }

  const bottomSection = `
    <hr style="border:none; border-top:1px solid #e5e7eb; margin:24px 0;">
    <h2 style="font-size:18px; text-align:center;">Restaurer mes favoris</h2>
    <p style="font-size:13px; color:#6b7280; margin-bottom:12px; text-align:center;">Entrez votre numéro de téléphone pour recevoir votre code par SMS.</p>
    <form action="/mon-compte/reinitialiser" method="POST">
      <label>Numéro de téléphone</label>
      <input name="phone" type="tel" required pattern="01[0-9]{8}" placeholder="0194010345" style="text-align:center;">
      <button type="submit" class="warning" style="width:100%; margin-top:8px;">Recevoir mon code par SMS</button>
    </form>
  `;

  res.send(page("Mon compte", `
    <section class="card" style="max-width: 600px; margin: 40px auto;">
      ${topSection}
      ${bottomSection}
    </section>
  `, proConnected));
});

app.post("/mon-compte/enregistrer", async (req, res) => {
  const visitorId = getOrCreateVisitorId(req, res);
  const fullName = String(req.body.full_name || "").trim().slice(0, 150);
  const phone = cleanBeninPhone(req.body.phone);

  if (!fullName || !phone) {
    return res.status(400).send(page("Erreur", "<h2>Nom ou numéro invalide.</h2><a href='/mon-compte'>Retour</a>", null));
  }

  const existingPhone = await pool.query(`SELECT id FROM client_codes WHERE phone = $1`, [phone]);
  
  if (existingPhone.rows.length > 0) {
    return res.status(400).send(page("Compte existant", `
      <section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;">
        <h1 style="color:#ef4444;">⚠️ Numéro déjà utilisé</h1>
        <p>Un compte existe déjà avec ce numéro. Utilisez le formulaire <strong>"Restaurer mes favoris"</strong> pour recevoir votre code.</p>
        <a href="/mon-compte" class="button">Retour</a>
      </section>
    `, null));
  }

  await getOrCreateClientCode(visitorId);
  await pool.query(`UPDATE client_codes SET full_name = $1, phone = $2 WHERE visitor_id = $3`, [fullName, phone, visitorId]);
  res.redirect(303, "/mon-compte");
});

app.post("/mon-compte/reinitialiser", async (req, res) => {
  const ip = req.ip || "unknown";
  if (!(await takeRateLimit(`client_reset:${ip}`, 3, 60 * 60 * 1000))) {
    return res.status(429).send(page("Trop de tentatives", "<section class='card'><h1>⏳ Trop de tentatives</h1><p>Patientez 1 heure.</p></section>", null));
  }

  const phone = cleanBeninPhone(req.body.phone);
  if (!phone) {
    return res.status(400).send(page("Erreur", "<h2>Numéro de téléphone invalide.</h2><a href='/mon-compte'>Retour</a>", null));
  }

  try {
    const smsCountResult = await pool.query(`
      SELECT COUNT(*) FROM notifications 
      WHERE recipient = $1 AND channel = 'sms' AND created_at >= date_trunc('month', CURRENT_DATE)
    `, [phone]);

    if (Number(smsCountResult.rows[0].count) >= 2) {
      return res.status(429).send(page("Limite atteinte", `
        <section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;">
          <h1 style="color:#f59e0b;">⚠️ Limite atteinte</h1>
          <p>Vous avez déjà demandé 2 codes par SMS ce mois-ci.</p>
          <p>Pour des raisons de sécurité et de coût, cette limite est stricte. Veuillez contacter notre support via WhatsApp si vous avez un problème.</p>
          <a href="/contact" class="button">Nous contacter</a>
        </section>
      `, null));
    }
  } catch (error) {
    console.error("Erreur vérification limite SMS :", error.message);
  }

  const clientResult = await pool.query(`SELECT code FROM client_codes WHERE phone = $1`, [phone]);
  
  if (!clientResult.rows.length) {
    return res.status(404).send(page("Erreur", "<h2>Aucun compte trouvé avec ce numéro.</h2><p>Vérifiez le numéro ou créez un compte.</p><a href='/mon-compte'>Retour</a>", null));
  }

  const code = clientResult.rows[0].code;
  
  await queueNotification({
    recipient: phone,
    body: `TrouveMoi: Votre code de récupération est ${code}. Gardez-le précieusement.`
  });

  res.send(page("Code envoyé", `<section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;"><h1>📩 SMS envoyé</h1><p>Si un compte est associé à ce numéro, vous recevrez un SMS avec votre code de récupération dans quelques instants.</p><a href="/mon-compte" class="button">Retour</a></section>`, null));
});
  try {
    const proConnected = await getConnectedPro(req);
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/");

    const visitorId = getOrCreateVisitorId(req, res);

    pool.query(`INSERT INTO pro_stats (pro_id, date, views) VALUES ($1, CURRENT_DATE, 1) ON CONFLICT (pro_id, date) DO UPDATE SET views = pro_stats.views + 1`, [id]).catch(() => {});

    const result = await pool.query(`
      SELECT p.*, (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count, (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating,
      EXISTS(SELECT 1 FROM client_favorites cf WHERE cf.pro_id = p.id AND cf.visitor_id = $2) AS is_favorite
      FROM professional_applications p WHERE p.id = $1 AND p.status = 'approved'`, [id, visitorId]);
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
      let h = {};
      try { h = JSON.parse(person.horaires_json); } catch (parseError) { h = {}; }
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

    const jsonLd = {
      "@context": "https://schema.org",
      "@type": "LocalBusiness",
      name: displayName,
      description: person.service_description || undefined,
      url: `${APP_URL}/pro/${person.id}`,
      telephone: person.phone_public ? person.phone : undefined,
      address: {
        "@type": "PostalAddress",
        addressLocality: person.city,
        streetAddress: person.adresse_exacte || undefined,
        addressCountry: "BJ"
      },
      areaServed: person.service_area || undefined,
      aggregateRating: reviewsCount > 0 ? {
        "@type": "AggregateRating",
        ratingValue: avgRating.toFixed(1),
        reviewCount: reviewsCount
      } : undefined
    };
    const jsonLdHtml = `<script type="application/ld+json">${JSON.stringify(jsonLd).replace(/</g, "\\u003c")}</script>`;

    const mapLat = Number(person.latitude);
    const mapLng = Number(person.longitude);
    const hasMap = Number.isFinite(mapLat) && Number.isFinite(mapLng);
    const mapBbox = hasMap
      ? `${(mapLng - 0.008).toFixed(6)}%2C${(mapLat - 0.008).toFixed(6)}%2C${(mapLng + 0.008).toFixed(6)}%2C${(mapLat + 0.008).toFixed(6)}`
      : "";

    const content = `
      <div style="max-width: 800px; margin: 0 auto;">
        ${jsonLdHtml}
        ${leaveBadge}
        <div class="card" style="text-align: center; padding: 32px 24px; position:relative;">
          <div class="favorite-btn ${person.is_favorite ? 'active' : ''}" onclick="toggleFav(event, ${person.id})" style="top:16px; right:16px;">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="${person.is_favorite ? '#ef4444' : 'none'}" stroke="${person.is_favorite ? '#ef4444' : '#6b7280'}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"></path></svg>
          </div>
          ${isTopPro ? `<div style="margin-bottom:12px;"><span class="top-pro-badge" style="font-size:14px; padding:8px 16px;">⭐ Top Pro</span></div>` : ""}
          ${openStatusBadge}
          <h1 style="color: #111827; font-size: 28px; margin-bottom: 6px;">${escapeHtml(displayName)} ${renderKycBadge(person, "lg")}</h1>
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
              ${hasMap ? `<iframe title="Carte de localisation" loading="lazy" src="https://www.openstreetmap.org/export/embed.html?bbox=${mapBbox}&layer=mapnik&marker=${mapLat}%2C${mapLng}" style="width:100%; height:220px; border:1px solid #bfdbfe; border-radius:8px; margin-top:12px;"></iframe>` : ""}
            ` : ""}
          </div> 
          ` : ""}

          <div style="margin-top: 24px;">${contactButtons}</div>
        </div>

        ${galerieHtml}

        <div class="card" style="background: #f9fafb;">
          <h2 style="font-size: 18px; margin-bottom: 16px;">Avis des clients (${reviewsCount})</h2>
          ${ratingSummary}${reviewsHtml || `<p style="color: #6b7280; font-style: italic; font-size: 14px;">Aucun avis pour le moment.</p>`}
          ${reviewsCount > 5 ? `<div style="text-align:center; margin-top:12px;"><a href="/pro/${person.id}/avis/tous" style="color:#2563eb; font-size:14px; font-weight:600;">Voir les ${reviewsCount} avis →</a></div>` : ""}
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
    res.send(page(displayName, content, proConnected, {
      title: `${displayName} - ${person.profession}`,
      description: (person.service_description || "").slice(0, 160) || undefined,
      canonical: `/pro/${person.id}`
    }));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.get("/pro/:id/avis/tous", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/");

    const proResult = await pool.query(
      `SELECT p.id, p.full_name, p.company_name, p.profession,
              (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count,
              (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating
         FROM professional_applications p
        WHERE p.id = $1 AND p.status = 'approved'`,
      [id]
    );
    if (!proResult.rows.length) return res.redirect(303, "/");
    const person = proResult.rows[0];
    const displayName = getDisplayName(person);

    const currentPage = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 20;
    const offset = (currentPage - 1) * limit;
    const total = Number(person.reviews_count || 0);
    const totalPages = Math.ceil(total / limit);
    const avgRating = Number(person.avg_rating || 0);

    const result = await pool.query(
      `SELECT author_name, rating, comment, pro_response, created_at
         FROM reviews
        WHERE pro_id = $1 AND status = 'approved'
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3`,
      [id, limit, offset]
    );

    const reviewsHtml = result.rows.map((rev) => `
      <article class="card" style="margin-bottom:14px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
          <strong>${escapeHtml(rev.author_name)}</strong>
          <span style="color:#f59e0b;">${renderStars(rev.rating)}</span>
        </div>
        <div style="font-size:12px; color:#9ca3af; margin-bottom:8px;">${new Date(rev.created_at).toLocaleDateString("fr-FR")}</div>
        ${rev.comment ? `<p style="font-size:14px; color:#374151;">${escapeHtml(rev.comment).replace(/\n/g, "<br>")}</p>` : ""}
        ${rev.pro_response ? `<div style="margin-top:10px; padding:10px; background:#f0fdf4; border-left:3px solid #10b981; border-radius:4px; font-size:13px; color:#065f46;"><strong>Réponse du professionnel :</strong><br>${escapeHtml(rev.pro_response).replace(/\n/g, "<br>")}</div>` : ""}
      </article>
    `).join("");

    res.send(page(`Avis - ${displayName}`, `
      <div style="max-width: 800px; margin: 0 auto;">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:20px;">
          <h1 style="margin:0;">Tous les avis sur ${escapeHtml(displayName)}</h1>
          <a href="/pro/${id}" style="color:#6b7280; font-size:14px;">← Retour au profil</a>
        </div>
        <div class="alert alert-info" style="text-align:center;">
          ${total > 0 ? `${renderStars(avgRating)} <strong>${avgRating.toFixed(1)}</strong> sur ${total} avis` : "Aucun avis pour le moment."}
        </div>
        ${reviewsHtml || `<div class="card"><p class="muted" style="text-align:center;">Aucun avis publié.</p></div>`}
        ${renderPagination(currentPage, totalPages, `/pro/${id}/avis/tous`)}
        <div style="text-align:center; margin-top:20px;">
          <a class="button warning" href="/pro/${id}/avis" style="margin:0;">⭐ Laisser un avis</a>
        </div>
      </div>
    `, proConnected));
  } catch (error) {
    console.error("Erreur liste des avis :", error.message);
    res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null));
  }
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
  const ip = req.ip || "unknown";
  if (!(await takeRateLimit(`review:${ip}`, 5, 60 * 60 * 1000))) return res.status(429).send(page("Trop de tentatives", "<section class='card'><h1>⏳ Trop de tentatives</h1><p>Patientez 1 heure.</p><a class='button' href='/'>Accueil</a></section>", null));

  try {
    const proId = Number(req.params.id);
    const visitorId = getOrCreateVisitorId(req, res);
    if (!Number.isSafeInteger(proId) || proId < 1) return res.redirect(303, "/");
    const check = await pool.query(`SELECT id FROM professional_applications WHERE id = $1 AND status = 'approved'`, [proId]);
    if (!check.rows.length) return res.redirect(303, "/");

    const contactProof = await pool.query(`
      SELECT 1 FROM contact_events
       WHERE pro_id = $1 AND visitor_id = $2 AND created_at >= NOW() - INTERVAL '30 days'
       UNION ALL
      SELECT 1 FROM pro_stats
       WHERE pro_id = $1 AND last_visitor_id = $2
         AND (phone_clicks > 0 OR wa_clicks > 0)
         AND date >= CURRENT_DATE - INTERVAL '30 days'
       LIMIT 1
    `, [proId, visitorId]);
    
    if (contactProof.rows.length === 0) {
      return res.status(403).send(page("Preuve de contact requise", `<section class="card" style="max-width: 600px; margin: 40px auto; text-align: center;"><h1 style="color:#ef4444;">🔒 Preuve de contact requise</h1><p>Pour garantir l'authenticité des avis, seuls les clients ayant contacté ce professionnel via TrouveMoi (Appel ou WhatsApp) dans les 30 derniers jours peuvent laisser un avis.</p><a class="button" href="/pro/${proId}" style="margin-top:20px;">Retour au profil</a></section>`, null));
    }

    const ratingNum = Number(req.body.rating);
    if (!Number.isInteger(ratingNum) || ratingNum < 1 || ratingNum > 5) return res.status(400).send(page("Erreur", "<h2>Note invalide (1 a 5).</h2>", null));
    const author = String(req.body.author_name || "").trim().slice(0, 100);
    if (!author) return res.status(400).send(page("Erreur", "<h2>Nom requis.</h2>", null));
    const comment = String(req.body.comment || "").slice(0, 3000);

    const alreadyReviewed = await pool.query(`SELECT id FROM reviews WHERE pro_id = $1 AND visitor_id = $2 LIMIT 1`, [proId, visitorId]);
    if (alreadyReviewed.rows.length) {
      return res.status(409).send(page("Avis deja depose", `<section class="card" style="max-width: 600px; margin: 40px auto; text-align:center;"><h1>✅ Avis deja enregistre</h1><p>Vous avez deja laisse un avis sur ce professionnel. Merci !</p><a class="button" href="/pro/${proId}">Retour au profil</a></section>`, null));
    }

    try {
      await pool.query(`INSERT INTO reviews (pro_id, author_name, rating, comment, status, visitor_id) VALUES ($1, $2, $3, $4, 'pending', $5)`, [proId, author, ratingNum, comment, visitorId]);
    } catch (insertError) {
      if (insertError.code === "23505") {
        return res.status(409).send(page("Avis deja depose", `<section class="card" style="max-width: 600px; margin: 40px auto; text-align:center;"><h1>✅ Avis deja enregistre</h1><p>Vous avez deja laisse un avis sur ce professionnel.</p><a class="button" href="/pro/${proId}">Retour au profil</a></section>`, null));
      }
      throw insertError;
    }
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
});app.get("/api/neighborhoods", async (req, res) => {
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

  const ip = req.ip || "unknown";
  if (!(await takeRateLimit(`candidature:${ip}`, 3, 60 * 60 * 1000))) return res.status(429).send(page("Trop de tentatives", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>⏳ Trop de tentatives</h1><p>Patientez 1 heure.</p></section>", null));

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

  let finalReferredBy = referred_by ? String(referred_by).trim().toLowerCase() : null;
  if (finalReferredBy) {
    const parrainCheck = await pool.query("SELECT id FROM professional_applications WHERE referral_code = $1 AND phone = $2", [finalReferredBy, cleanPhone]);
    if (parrainCheck.rows.length > 0) {
      return res.status(400).send(page("Erreur", "<h2>Vous ne pouvez pas utiliser votre propre code de parrainage.</h2>", null));
    }
  }

  const professionCategoryResult = await pool.query("SELECT category FROM professions WHERE name = $1", [finalProfession]);
  const professionCategory = professionCategoryResult.rows[0]?.category || "Autre";

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

    let trackingCode = `SUIVI-${crypto.randomInt(10000000, 100000000)}`;
    
    const finalStatus = BYPASS_PAYMENT ? 'pending' : 'payment_pending';
    const finalPaymentStatus = BYPASS_PAYMENT ? 'paid' : 'unpaid';

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const lockKey = `pro:${[cleanPhone, safeNpi].sort().join("|")}`;
      await client.query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)", [lockKey]);

      const duplicate = await client.query(
        `SELECT id, status, payment_status, tracking_code FROM professional_applications
          WHERE (REGEXP_REPLACE(phone, '[()\\s.-]', '', 'g') = $1 OR npi = $2)
            AND status IN ('pending', 'under_review', 'approved', 'corrections_requested', 'payment_pending')
          LIMIT 1`,
        [cleanPhone, safeNpi]
      );
      if (duplicate.rows.length) {
        await client.query("ROLLBACK");
        await Promise.allSettled(uploadedUrls.map(url => deleteFromCloudinary(url)));
        const existing = duplicate.rows[0];
        if (existing.status === "payment_pending" && existing.payment_status === "unpaid") {
          return res.redirect(303, `/paiement/${existing.tracking_code}`);
        }
        return res.status(409).send(page("Inscription impossible", `<section class="card" style="max-width: 600px; margin: 40px auto; text-align: center;"><h1 style="color:#ef4444; justify-content: center;">⚠️ Doublon</h1><p><strong>Un dossier existe déjà avec ce numéro ou ce NPI.</strong></p><a class="button" href="/contact">📩 Nous contacter</a></section>`, null));
      }

      await client.query(`INSERT INTO professional_applications (full_name, company_name, phone, phone_public, city, neighborhood, profession, experience, service_description, service_area, availability, npi, photo_profil_url, photo_identite_url, photo_kyc_url, photo_activite_url, contact_preference, whatsapp_number, contact_email, pro_code, tracking_code, status, payment_status, payment_amount, type_lieu, adresse_exacte, latitude, longitude, horaires_json, referred_by, profession_category) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NULL,$16,$17,$18,NULL,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29) RETURNING id`,
        [full_name, finalCompanyName, cleanPhone, phoneIsPublic, city, finalNeighborhood, finalProfession, experience, service_description, service_area, availability, safeNpi, profilResult.secure_url, identiteResult.secure_url, kycResult.secure_url, pref, cleanWa, contact_email, trackingCode, finalStatus, finalPaymentStatus, PAYMENT_AMOUNT, type_lieu, adresse_exacte, latitude || null, longitude || null, horairesJson, finalReferredBy, professionCategory]);
      await client.query("COMMIT");
    } catch (transactionError) {
      await client.query("ROLLBACK").catch(() => {});
      throw transactionError;
    } finally {
      client.release();
    }

    if (BYPASS_PAYMENT) {
      res.send(page("Succes", `<section class="card" style="max-width: 600px; margin: 40px auto; text-align: center;"><h1 style="color:#10b981;">Succès !</h1><p>Votre candidature a bien été enregistrée et est en attente d'examen.</p><div class="alert alert-info" style="margin-top:20px;"><strong>Votre code de suivi est : <span style="font-size:24px; font-family:monospace; font-weight:bold;">${escapeHtml(trackingCode)}</span></strong></div><a class="button" href="/suivi-dossier" style="margin-top:20px;">Suivre mon dossier</a></section>`, null));
    } else {
      res.redirect(303, `/paiement/${trackingCode}`);
    }
  } catch (error) {
    console.error("ERREUR COMPLETE INSERT :", error);
    if (uploadedUrls.length > 0) { await Promise.allSettled(uploadedUrls.map(url => deleteFromCloudinary(url))); }
    res.status(500).send(page("Erreur", `<h2>Impossible d'enregistrer.</h2><p>Veuillez réessayer ou nous contacter.</p>`, null));
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

    if (!paymentMatchesDossier(verification, dossier)) {
      await logAdminAction("payment_unbound", "pro", dossier.id, `Ref: ${transactionId} | Reference: ${verification.reference || "absente"}`);
      return res.status(400).send(page("Paiement non reconnu", `<section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;"><h1 style="color:#ef4444;">❌ Paiement non reconnu</h1><p>Cette transaction ne correspond pas à ce dossier. Si vous avez bien payé, contactez-nous avec votre référence.</p><a class="button" href="/contact">Nous contacter</a></section>`, proConnected));
    }

    const settlement = await settlePayment({
      dossierId: dossier.id,
      transactionId,
      amount: verification.amount,
      method: verification.method,
      source: "verification"
    });

    if (!settlement.ok) {
      return res.status(409).send(page("Paiement déjà utilisé", `<section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;"><h1 style="color:#ef4444;">❌ Transaction déjà utilisée</h1><p>Cette transaction a déjà servi à payer un autre dossier.</p><a class="button" href="/contact">Nous contacter</a></section>`, proConnected));
    }
    if (settlement.alreadyPaid) {
      return res.send(page("Déjà payé", `<section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;"><h1 style="color:#10b981;">✅ Déjà payé</h1><a class="button" href="/suivi-dossier">Voir mon dossier</a></section>`, proConnected));
    }

    res.send(page("Paiement réussi", `<section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;"><div style="font-size:64px; margin-bottom:16px;">🎉</div><h1 style="color:#10b981;">Paiement réussi !</h1><div class="pro-code-box" style="margin: 24px 0;"><div class="pro-code-value" style="font-size: 28px;">${escapeHtml(dossier.tracking_code)}</div></div><a class="button" href="/suivi-dossier" style="margin-top:16px;">📋 Suivre mon dossier</a></section>`, proConnected));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur technique.</h2>", null)); }
});

app.post("/webhooks/kkiapay", express.json({ limit: "100kb" }), async (req, res) => {
  if (BYPASS_PAYMENT) return res.status(200).json({ received: true });
  try {
    if (KKIAPAY_WEBHOOK_SECRET) {
      const provided = String(req.query.token || req.get("x-webhook-secret") || "");
      if (!safeEqual(provided, KKIAPAY_WEBHOOK_SECRET)) {
        return res.status(401).json({ received: false });
      }
    }

    const { transactionId } = req.body || {};
    if (!transactionId) return res.status(200).json({ received: true });

    const verification = await verifyKkiapayTransaction(transactionId);
    if (!verification.success) return res.status(200).json({ received: true, verified: false });

    let trackingCode = String(verification.reference || "").trim().toUpperCase();
    if (!trackingCode && !IS_PRODUCTION) {
      trackingCode = String(req.body.data || "").trim().toUpperCase();
    }
    if (!trackingCode) return res.status(200).json({ received: true, verified: false, reason: "reference absente" });

    const dossierResult = await pool.query(`SELECT * FROM professional_applications WHERE tracking_code = $1`, [trackingCode]);
    if (!dossierResult.rows.length) return res.status(200).json({ received: true, verified: true, matched: false });
    const dossier = dossierResult.rows[0];

    if (!paymentMatchesDossier(verification, dossier)) {
      await logAdminAction("payment_unbound", "pro", dossier.id, `Webhook | Ref: ${transactionId}`);
      return res.status(200).json({ received: true, verified: true, matched: false });
    }

    const settlement = await settlePayment({
      dossierId: dossier.id,
      transactionId,
      amount: verification.amount,
      method: verification.method,
      source: "webhook"
    });

    return res.status(200).json({
      received: true,
      processed: settlement.ok,
      alreadyPaid: Boolean(settlement.alreadyPaid),
      transactionAlreadyUsed: settlement.reason === "transaction_already_used"
    });
  } catch (error) {
    console.error("Erreur webhook Kkiapay :", error.message);
    return res.status(200).json({ received: true, error: true });
  }
});

app.get("/suivi-dossier", (req, res) => {
  res.send(page("Suivi de dossier", `<section class="card" style="max-width: 500px; margin: 40px auto;"><h1 style="text-align: center; margin-bottom: 24px;">Suivre mon dossier</h1><form action="/suivi-dossier" method="POST"><label>Code de suivi (ex: SUIVI-12345) *</label><input name="tracking_code" required placeholder="SUIVI-XXXXX" maxlength="20" style="text-transform:uppercase; text-align:center; font-size:20px; font-weight:bold;"><button type="submit" style="width: 100%; margin-top:10px;">Voir mon dossier</button></form></section>`, null));
});

app.post("/suivi-dossier", async (req, res) => {
  const ip = req.ip || "unknown";
  if (!(await takeRateLimit(`tracking:${ip}`, 10, 15 * 60 * 1000))) return res.status(429).send(page("Trop de tentatives", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>⏳ Trop de tentatives</h1></section>", null));

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
});app.get("/mon-espace-pro", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) {
    return res.send(page("Espace pro", `<section class="card" style="max-width: 500px; margin: 40px auto;"><h1 style="text-align: center;">Espace pro</h1><form action="/mon-espace-pro/login" method="POST"><label>Code pro</label><input name="pro_code" required maxlength="10" placeholder="TM12345678" style="text-transform:uppercase; text-align:center; font-size:20px;"><button type="submit" style="width: 100%;">Se connecter</button></form><div style="text-align:center; margin-top:20px; font-size:14px;"><p><a href="/suivi-dossier">Suivre mon dossier</a></p><p><a href="/mon-espace-pro/reinitialiser" style="color:#ef4444;">🔐 Code perdu</a></p></div></section>`, null));
  }

  let offers = [], gdprRequests = [], myReviews = [], stats = { views: 0, phone: 0, wa: 0 }, withdrawals = [];
  let stats90 = { views: 0, phone: 0, wa: 0 };
  let statsAll = { views: 0, phone: 0, wa: 0 };
  
  try {
    offers = (await pool.query(`SELECT * FROM job_offers WHERE pro_id = $1 ORDER BY created_at DESC`, [proConnected.pro.id])).rows;
    gdprRequests = (await pool.query(`SELECT * FROM gdpr_requests WHERE pro_id = $1 ORDER BY created_at DESC LIMIT 20`, [proConnected.pro.id])).rows;
    myReviews = (await pool.query(`SELECT * FROM reviews WHERE pro_id = $1 AND status = 'approved' ORDER BY created_at DESC LIMIT 10`, [proConnected.pro.id])).rows;
    withdrawals = (await pool.query(`SELECT * FROM withdrawal_requests WHERE pro_id = $1 ORDER BY created_at DESC LIMIT 10`, [proConnected.pro.id])).rows;
    
    const statsRes = await pool.query(`SELECT SUM(views) as v, SUM(phone_clicks) as p, SUM(wa_clicks) as w FROM pro_stats WHERE pro_id = $1 AND date >= CURRENT_DATE - INTERVAL '30 days'`, [proConnected.pro.id]);
    if (statsRes.rows.length) { stats.views = Number(statsRes.rows[0].v || 0); stats.phone = Number(statsRes.rows[0].p || 0); stats.wa = Number(statsRes.rows[0].w || 0); }

    const stats90Res = await pool.query(`SELECT SUM(views) as v, SUM(phone_clicks) as p, SUM(wa_clicks) as w FROM pro_stats WHERE pro_id = $1 AND date >= CURRENT_DATE - INTERVAL '90 days'`, [proConnected.pro.id]);
    if (stats90Res.rows.length) { stats90.views = Number(stats90Res.rows[0].v || 0); stats90.phone = Number(stats90Res.rows[0].p || 0); stats90.wa = Number(stats90Res.rows[0].w || 0); }

    const statsAllRes = await pool.query(`SELECT SUM(views) as v, SUM(phone_clicks) as p, SUM(wa_clicks) as w FROM pro_stats WHERE pro_id = $1`, [proConnected.pro.id]);
    if (statsAllRes.rows.length) { statsAll.views = Number(statsAllRes.rows[0].v || 0); statsAll.phone = Number(statsAllRes.rows[0].p || 0); statsAll.wa = Number(statsAllRes.rows[0].w || 0); }
  } catch (error) { return res.status(500).send(page("Erreur", "<h2>Erreur technique.</h2>", proConnected)); }

  const now = new Date();
  const offersHtml = offers.map((offer) => {
    const expired = offer.expires_at && new Date(offer.expires_at) < now;
    const statusLabel = JOB_STATUS_LABELS[offer.status] || offer.status;
    return `<article class="card" style="box-shadow:none; border:1px solid #e5e7eb; margin-bottom:16px;"><h2 style="font-size:18px;">${escapeHtml(offer.job_title)}</h2><p><span class="badge badge-${offer.status}">${statusLabel}</span> <span style="font-size:12px; color:#6b7280;">${escapeHtml(offer.contract_type || "")}</span></p><p><strong>Ville :</strong> ${escapeHtml(offer.city)}</p><div class="actions" style="margin-top:16px; display:flex; gap:8px; flex-wrap:wrap;">${offer.status === "approved" && !expired ? `<form action="/mon-espace-pro/offre/${offer.id}/close" method="POST" style="display:inline; margin:0;"><button class="warning" type="submit" style="padding:6px 12px; font-size:12px;">🔒 Cloturer</button></form>` : ""} ${offer.status === "closed" ? `<form action="/mon-espace-pro/offre/${offer.id}/reopen" method="POST" style="display:inline; margin:0;"><button class="success" type="submit" style="padding:6px 12px; font-size:12px;">🔓 Rouvrir</button></form>` : ""} <a class="button secondary" href="/mon-espace-pro/offre/${offer.id}/modifier" style="padding:6px 12px; font-size:12px; margin:0;">✏️ Modifier</a> <form action="/mon-espace-pro/offre/${offer.id}/supprimer" method="POST" style="display:inline; margin:0;" onsubmit="return confirm('Supprimer définitivement cette offre ?')"><button class="danger" type="submit" style="padding:6px 12px; font-size:12px;">🗑️ Supprimer</button></form></div></article>`;
  }).join("");

  const gdprHtml = gdprRequests.map((req) => `<article class="card" style="padding:16px; margin-bottom:10px;"><p><span class="badge badge-${req.status}">${GDPR_STATUS_LABELS[req.status]}</span> <strong>${GDPR_TYPE_LABELS[req.request_type]}</strong></p></article>`).join("");
  const pendingDeletion = gdprRequests.some((request) => request.request_type === "deletion" && request.status === "pending");
  
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
      <details style="margin-top:10px;">
        <summary style="font-size:12px; color:#ef4444; cursor:pointer;">⚠️ Signaler cet avis</summary>
        <form action="/mon-espace-pro/avis/${rev.id}/signaler" method="POST" style="margin-top:8px;">
          <textarea name="reason" required maxlength="1000" rows="2" placeholder="Expliquez pourquoi cet avis est problématique (injures, faux avis, concurrent...)" style="width:100%; padding:8px; border-radius:8px; border:1px solid #cbd5e0; font-size:13px; margin-bottom:8px;"></textarea>
          <button type="submit" class="danger" style="padding:6px 12px; font-size:12px; margin:0;">Envoyer le signalement</button>
        </form>
      </details>
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

          <div style="border-top:1px solid #e2e8f0; margin-top:12px; padding-top:10px;">
            <p style="font-weight:bold; font-size:13px; color:#1e40af; margin-bottom:6px;">📊 90 derniers jours</p>
            <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;"><span>Vues :</span> <strong>${stats90.views}</strong></div>
            <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;"><span>Appels :</span> <strong>${stats90.phone}</strong></div>
            <div style="display:flex; justify-content:space-between; font-size:12px;"><span>WhatsApp :</span> <strong>${stats90.wa}</strong></div>
          </div>

          <div style="border-top:1px solid #e2e8f0; margin-top:12px; padding-top:10px;">
            <p style="font-weight:bold; font-size:13px; color:#1e40af; margin-bottom:6px;">📊 Depuis l'inscription</p>
            <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;"><span>Vues :</span> <strong>${statsAll.views}</strong></div>
            <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;"><span>Appels :</span> <strong>${statsAll.phone}</strong></div>
            <div style="display:flex; justify-content:space-between; font-size:12px;"><span>WhatsApp :</span> <strong>${statsAll.wa}</strong></div>
          </div>
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
      <p style="font-size: 14px; margin-bottom: 12px; color:#065f46;">Invitez un pro et gagnez <strong>${REFERRAL_BONUS} FCFA</strong> dès qu'il paie son inscription.</p>
      
      <div style="background: white; padding: 12px; border-radius: 8px; margin-bottom: 12px; border:1px solid #e5e7eb;">
        <p style="font-size: 12px; color: #6b7280; margin-bottom: 4px;">Votre code de parrainage :</p>
        <div style="font-size: 24px; font-weight: 800; font-family: monospace; color: #059669;">${proConnected.pro.referral_code || 'En attente...'}</div>
      </div>

      <div style="background: white; padding: 12px; border-radius: 8px; margin-bottom: 12px; border:1px solid #e5e7eb;">
  <p style="font-size: 12px; color: #6b7280; margin-bottom: 4px;">Votre lien de parrainage (à partager) :</p>
  <div style="display: flex; gap: 8px;">
    <input id="referral-link" readonly value="${APP_URL}/devenir-professionnel?ref=${proConnected.pro.referral_code || ''}" style="width:100%; padding:8px; font-size:12px; background:#f9fafb; border:1px solid #e5e7eb; border-radius:6px;">
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
        <label style="margin-top:0; font-size:12px;">Montant à retirer (min. ${WITHDRAWAL_MIN} F)</label>
        <input name="amount" type="number" min="${WITHDRAWAL_MIN}" max="${proConnected.pro.referral_balance || 0}" required style="padding:8px; margin-bottom:8px;">
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
      ${pendingDeletion ? `<div class="alert alert-warning"><strong>Suppression de compte en cours.</strong> Votre demande est en attente de traitement. Vous pouvez encore l'annuler.<form action="/mon-espace-pro/annuler-suppression" method="POST" style="margin-top:10px;"><button class="secondary" type="submit" style="margin:0;">Annuler la demande de suppression</button></form></div>` : ""}
      <div class="actions" style="display:flex; gap:10px; flex-wrap:wrap;">
        <a class="button secondary" href="/mon-espace-pro/mes-donnees">📥 Télécharger mes données</a>
        ${pendingDeletion ? "" : `<form action="/mon-espace-pro/demande-suppression" method="POST" style="display:inline; margin:0;">
          <button class="danger" type="submit" onclick="return confirm('⚠️ ATTENTION : Êtes-vous sûr de vouloir supprimer définitivement votre compte ? Cette action est irréversible et supprimera toutes vos données (photos, avis, offres).')">🗑️ Supprimer mon compte</button>
        </form>`}
      </div>
      ${gdprHtml}
    </section>
    <script>
  function copyRefLink() {
    const copyText = document.getElementById("referral-link");
    copyText.select();
    copyText.setSelectionRange(0, 99999);
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

  if (!Number.isSafeInteger(amount) || amount < WITHDRAWAL_MIN) return res.status(400).send(page("Erreur", `<h2>Le montant minimum de retrait est de ${WITHDRAWAL_MIN} FCFA.</h2>`, proConnected));
  if (amount > solde) return res.status(400).send(page("Erreur", "<h2>Votre solde est insuffisant.</h2>", proConnected));
  if (!/^01\d{8}$/.test(phone)) return res.status(400).send(page("Erreur", "<h2>Numéro de téléphone invalide.</h2>", proConnected));

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const debit = await client.query(
      `UPDATE professional_applications
          SET referral_balance = referral_balance - $1, updated_at = NOW()
        WHERE id = $2 AND referral_balance >= $1
        RETURNING referral_balance`,
      [amount, proConnected.pro.id]
    );
    if (!debit.rowCount) {
      await client.query("ROLLBACK");
      return res.status(400).send(page("Erreur", "<h2>Votre solde est insuffisant.</h2>", proConnected));
    }
    await client.query(
      `INSERT INTO withdrawal_requests (pro_id, amount, phone_number) VALUES ($1, $2, $3)`,
      [proConnected.pro.id, amount, phone]
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Erreur demande de retrait :", error.message);
    return res.status(500).send(page("Erreur", "<h2>Impossible d'enregistrer la demande de retrait.</h2>", proConnected));
  } finally {
    client.release();
  }

  await logAdminAction("withdrawal_requested", "pro", proConnected.pro.id, `Montant: ${amount} FCFA | Numero: ${phone}`);
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

  let h = {};
  try { h = proConnected.pro.horaires_json ? JSON.parse(proConnected.pro.horaires_json) : {}; } catch (parseError) { h = {}; }
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

        <h3 style="margin-bottom:12px;">Identité et contact</h3>

        <label>Nom complet (Vérifié KYC - Non modifiable)</label>
<input name="full_name" value="${escapeHtml(proConnected.pro.full_name)}" readonly style="background:#e5e7eb; cursor:not-allowed; color:#6b7280;">

<label>Nom de l'entreprise (Modifiable)</label>
<input name="company_name" maxlength="200" value="${escapeHtml(proConnected.pro.company_name || '')}" placeholder="Ex: ADK Services">

<label>Téléphone *</label>
<input name="phone" type="tel" required maxlength="30" pattern="01[0-9]{8}" title="10 chiffres commençant par 01" value="${escapeHtml(proConnected.pro.phone)}">
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
          <div>
            <label>Préférence de contact</label>
            <select name="contact_preference">
              <option value="whatsapp" ${proConnected.pro.contact_preference === 'whatsapp' ? 'selected' : ''}>WhatsApp</option>
              <option value="email" ${proConnected.pro.contact_preference === 'email' ? 'selected' : ''}>E-mail</option>
            </select>
          </div>
          <div>
            <label>Numéro WhatsApp</label>
            <input name="whatsapp_number" type="tel" maxlength="30" pattern="01[0-9]{8}" title="10 chiffres commençant par 01" value="${escapeHtml(proConnected.pro.whatsapp_number || '')}">
          </div>
        </div>

        <label>E-mail</label>
        <input name="contact_email" type="email" maxlength="254" value="${escapeHtml(proConnected.pro.contact_email || '')}">

        <hr style="margin:24px 0; border:none; border-top:1px solid #e5e7eb;">

        <h3 style="margin-bottom:12px;">Localisation</h3>

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

  const { company_name, phone, contact_email, contact_preference, whatsapp_number, city, neighborhood, neighborhood_other, type_lieu, adresse_exacte, latitude, longitude } = req.body;

  const cleanPhone = cleanBeninPhone(phone);
 if (!cleanPhone) {
  return res.status(400).send(page("Erreur", "<h2>Téléphone invalide (format 01XXXXXXXX).</h2>", proConnected));
}

  const email = String(contact_email || "").trim().slice(0, 254);
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return res.status(400).send(page("Erreur", "<h2>Adresse e-mail invalide.</h2>", proConnected));
  }

  const cleanWhatsapp = whatsapp_number ? cleanBeninPhone(whatsapp_number) : null;
  if (whatsapp_number && !cleanWhatsapp) {
    return res.status(400).send(page("Erreur", "<h2>Numéro WhatsApp invalide.</h2>", proConnected));
  }

  const preference = CONTACT_PREFERENCES.includes(contact_preference) ? contact_preference : "whatsapp";

  const duplicate = await pool.query(
    `SELECT id FROM professional_applications
      WHERE REGEXP_REPLACE(phone, '[()\\s.-]', '', 'g') = $1
        AND id <> $2
        AND status IN ('pending', 'under_review', 'approved', 'corrections_requested', 'payment_pending')
      LIMIT 1`,
    [cleanPhone, proConnected.pro.id]
  );
  if (duplicate.rows.length) {
    return res.status(409).send(page("Erreur", "<h2>Ce numéro de téléphone est déjà utilisé par un autre dossier.</h2>", proConnected));
  }

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
       SET company_name = $1, phone = $2, contact_email = $3, contact_preference = $4,
     whatsapp_number = $5, city = $6, neighborhood = $7, type_lieu = $8,
     adresse_exacte = $9, latitude = $10, longitude = $11, horaires_json = $12,
     updated_at = NOW()
 WHERE id = $13`,
[company_name || null, cleanPhone, email || null, preference, cleanWhatsapp, city, finalNeighborhood, type_lieu, adresse_exacte, latitude || null, longitude || null, horairesJson, proConnected.pro.id]
    );
    if (cleanPhone !== proConnected.pro.phone) {
      await logAdminAction("pro_phone_updated", "pro", proConnected.pro.id, `Ancien: ${proConnected.pro.phone} | Nouveau: ${cleanPhone}`);
    }
    res.redirect(303, "/mon-espace-pro");
  } catch (e) {
    console.error(e);
    res.status(500).send(page("Erreur", "<h2>Erreur lors de la modification.</h2>", proConnected));
  }
});

app.post("/mon-espace-pro/login", async (req, res) => {
  const ip = req.ip || "unknown";
  const rateKey = `pro_login:${ip}`;
  if (!(await takeRateLimit(rateKey, 10, 15 * 60 * 1000))) return res.status(429).send(page("Trop de tentatives", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>⏳ Trop de tentatives</h1></section>", null));

  const code = String(req.body.pro_code || "").trim().toUpperCase();
  if (!/^TM\d{5,8}$/.test(code)) return res.status(400).send(page("Erreur", "<h2>Code invalide.</h2>", null));
  try {
    const result = await pool.query(`SELECT id FROM professional_applications WHERE pro_code = $1 AND status = 'approved'`, [code]);
    if (!result.rows.length) return res.status(401).send(page("Erreur", "<h2>Code incorrect.</h2>", null));
    await clearRateLimit(rateKey); setProCookie(res, code); res.redirect(303, "/mon-espace-pro");
  } catch (error) { res.redirect(303, "/mon-espace-pro"); }
});

app.post("/mon-espace-pro/logout", (req, res) => { clearProCookie(res); res.redirect(303, "/mon-espace-pro"); });

app.get("/mon-espace-pro/reinitialiser", (req, res) => {
  res.send(page("Réinitialiser", `<section class="card" style="max-width: 500px; margin: 40px auto;"><h1 style="text-align:center;">🔐 Réinitialiser</h1><p style="font-size:14px; color:#6b7280;">Pour des raisons de sécurité, le code de suivi seul ne suffit plus.</p><form action="/mon-espace-pro/reinitialiser" method="POST"><label>Code de suivi *</label><input name="tracking_code" required maxlength="20" style="text-transform:uppercase; text-align:center;"><label>4 derniers chiffres de votre téléphone *</label><input name="phone_last4" required inputmode="numeric" pattern="[0-9]{4}" maxlength="4" placeholder="0345" style="text-align:center;"><button type="submit" class="warning" style="width:100%; margin-top:10px;">🔄 Générer</button></form></section>`, null));
});

app.post("/mon-espace-pro/reinitialiser", async (req, res) => {
  const ip = req.ip || "unknown";
  if (!(await takeRateLimit(`reset:${ip}`, 5, 15 * 60 * 1000))) return res.status(429).send(page("Trop de tentatives", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>⏳ Trop de tentatives</h1></section>", null));

  const code = String(req.body.tracking_code || "").trim().toUpperCase();
  const phoneLast4 = String(req.body.phone_last4 || "").trim();
  if (!code || !/^\d{4}$/.test(phoneLast4)) return res.redirect(303, "/mon-espace-pro/reinitialiser");
  try {
    const result = await pool.query(`SELECT id, phone FROM professional_applications WHERE tracking_code = $1 AND status = 'approved'`, [code]);
    if (!result.rows.length || normalizePhone(result.rows[0].phone).slice(-4) !== phoneLast4) {
      return res.status(404).send(page("Erreur", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h2>Introuvable.</h2><p>Vérifiez le code de suivi et les 4 derniers chiffres du téléphone.</p></section>", null));
    }
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

app.post("/mon-espace-pro/avis/:id/signaler", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");

  const id = Number(req.params.id);
  const reason = String(req.body.reason || "").trim().slice(0, 1000);
  if (!Number.isSafeInteger(id) || id < 1 || !reason) {
    return res.status(400).send(page("Erreur", "<h2>Motif du signalement requis.</h2>", proConnected));
  }

  const review = await pool.query(`SELECT id FROM reviews WHERE id = $1 AND pro_id = $2`, [id, proConnected.pro.id]);
  if (!review.rows.length) return res.status(404).send(page("Erreur", "<h2>Avis introuvable.</h2>", proConnected));

  const existing = await pool.query(`SELECT id FROM review_reports WHERE review_id = $1 AND status = 'pending' LIMIT 1`, [id]);
  if (existing.rows.length) {
    return res.send(page("Déjà signalé", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>Signalement déjà enregistré</h1><p>Notre équipe examine déjà cet avis.</p><a href='/mon-espace-pro' class='button'>Retour</a></section>", proConnected));
  }

  await pool.query(`INSERT INTO review_reports (review_id, pro_id, reason) VALUES ($1, $2, $3)`, [id, proConnected.pro.id, reason]);
  await logAdminAction("review_reported", "review", id, `Par ${getDisplayName(proConnected.pro)} | ${reason}`);
  res.send(page("Signalement", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>Signalement envoyé</h1><p>Notre équipe va examiner cet avis.</p><a href='/mon-espace-pro' class='button'>Retour</a></section>", proConnected));
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
  const slots = [1, 2, 3].map((index) => {
    const url = proConnected.pro[`photo_galerie_${index}`];
    return `<div style="margin-bottom:16px;">
      <label>Photo ${index}</label>
      ${url ? `<img src="${escapeHtml(url)}" style="height:80px; border-radius:8px; margin-bottom:8px; display:block;">
        <form action="/mon-espace-pro/modifier-galerie/${index}/supprimer" method="POST" style="margin:0 0 8px;">
          <button class="danger" type="submit" onclick="return confirm('Supprimer cette photo ?')" style="padding:6px 12px; font-size:12px; margin:0;">🗑️ Supprimer</button>
        </form>` : ""}
      <input type="file" name="photo${index}" accept="image/*">
    </div>`;
  }).join("");

  res.send(page("Ma Galerie", `<section class="card" style="max-width: 600px; margin: 40px auto;"><h1 style="text-align:center;">📸 Ma Galerie</h1><p style="text-align:center; color:#6b7280; margin-bottom:24px;">Ajoutez jusqu'à 3 photos, ou supprimez celles que vous ne voulez plus.</p>${successMsg}<form action="/mon-espace-pro/modifier-galerie" method="POST" enctype="multipart/form-data" style="background:#f9fafb; padding:20px; border-radius:12px;">${slots}<button type="submit" style="width:100%; margin-top:10px;">Enregistrer</button></form><p style="text-align:center; margin-top:24px;"><a href="/mon-espace-pro">← Retour</a></p></section>`, proConnected));
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

app.post("/mon-espace-pro/modifier-galerie/:slot/supprimer", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");

  const slot = Number(req.params.slot);
  if (![1, 2, 3].includes(slot)) return res.redirect(303, "/mon-espace-pro/modifier-galerie");

  const column = `photo_galerie_${slot}`;
  const url = proConnected.pro[column];
  try {
    if (url) await deleteFromCloudinary(url);
    await pool.query(`UPDATE professional_applications SET ${column} = NULL, updated_at = NOW() WHERE id = $1`, [proConnected.pro.id]);
    res.redirect(303, "/mon-espace-pro/modifier-galerie?success=1");
  } catch (error) {
    console.error("Erreur suppression photo galerie :", error.message);
    res.redirect(303, "/mon-espace-pro/modifier-galerie");
  }
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

  const existing = await pool.query(
    `SELECT id FROM gdpr_requests WHERE pro_id = $1 AND request_type = 'deletion' AND status = 'pending' LIMIT 1`,
    [proConnected.pro.id]
  );
  if (existing.rows.length) {
    return res.send(page("Demande déjà en cours", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>Demande déjà en cours</h1><p>Votre demande de suppression est déjà enregistrée. Vous pouvez l'annuler depuis votre espace.</p><a href='/mon-espace-pro' class='button'>Retour</a></section>", proConnected));
  }

  await pool.query(`INSERT INTO gdpr_requests (pro_id, request_type, status, message) VALUES ($1, 'deletion', 'pending', $2)`, [proConnected.pro.id, "Demande pro"]);
  await logAdminAction("gdpr_deletion_requested", "pro", proConnected.pro.id, "Demande de suppression de compte");
  res.send(page("Demande", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>Demande envoyée</h1><p>Votre demande sera traitée dans un délai maximum de 30 jours. Vous pouvez l'annuler à tout moment depuis votre espace.</p><a href='/mon-espace-pro' class='button'>Retour</a></section>", proConnected));
});

app.post("/mon-espace-pro/annuler-suppression", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  await pool.query(
    `UPDATE gdpr_requests SET status = 'rejected', processed_at = NOW()
      WHERE pro_id = $1 AND request_type = 'deletion' AND status = 'pending'`,
    [proConnected.pro.id]
  );
  await logAdminAction("gdpr_deletion_cancelled", "pro", proConnected.pro.id, "Demande de suppression annulee");
  res.redirect(303, "/mon-espace-pro");
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

app.get("/mon-espace-pro/offre/:id/modifier", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/mon-espace-pro");

  const result = await pool.query(`SELECT * FROM job_offers WHERE id = $1 AND pro_id = $2`, [id, proConnected.pro.id]);
  if (!result.rows.length) return res.redirect(303, "/mon-espace-pro");
  const offer = result.rows[0];
  const contractOptions = JOB_CONTRACT_TYPES.map((t) => `<option value="${escapeHtml(t)}" ${offer.contract_type === t ? "selected" : ""}>${escapeHtml(t)}</option>`).join("");

  res.send(page("Modifier l'offre", `
    <section class="card" style="max-width: 700px; margin: 0 auto;">
      <h1 style="text-align:center;">Modifier l'offre</h1>
      <form action="/mon-espace-pro/offre/${offer.id}/modifier" method="POST">
        <label>Entreprise *</label><input name="company_name" required maxlength="200" value="${escapeHtml(offer.company_name)}">
        <label>Poste *</label><input name="job_title" required maxlength="200" value="${escapeHtml(offer.job_title)}">
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px;">
          <div><label>Ville *</label><input name="city" required maxlength="100" value="${escapeHtml(offer.city)}"></div>
          <div><label>Contrat *</label><select name="contract_type" required>${contractOptions}</select></div>
        </div>
        <label>Description *</label><textarea name="description" required maxlength="5000" rows="6">${escapeHtml(offer.description)}</textarea>
        <h3 style="margin-top:20px;">Contacts</h3>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px;">
          <div><label>Téléphone</label><input name="contact_phone" type="tel" maxlength="30" value="${escapeHtml(offer.contact_phone || "")}"></div>
          <div><label>WhatsApp</label><input name="contact_whatsapp" type="tel" maxlength="30" value="${escapeHtml(offer.contact_whatsapp || "")}"></div>
        </div>
        <label>E-mail</label><input name="contact_email" type="email" maxlength="254" value="${escapeHtml(offer.contact_email || "")}">
        <p style="font-size:12px; color:#6b7280;">Toute modification renvoie l'offre en modération.</p>
        <div style="text-align:center; margin-top:20px;"><button type="submit">Enregistrer</button><a href="/mon-espace-pro" class="button secondary">Annuler</a></div>
      </form>
    </section>`, proConnected));
});

app.post("/mon-espace-pro/offre/:id/modifier", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/mon-espace-pro");
  if (!JOB_CONTRACT_TYPES.includes(req.body.contract_type)) return res.status(400).send(page("Erreur", "<h2>Type invalide.</h2>", proConnected));

  const rawPhone = String(req.body.contact_phone || "").trim();
  const rawWhatsapp = String(req.body.contact_whatsapp || "").trim();
  const contactPhone = rawPhone ? cleanBeninPhone(rawPhone) : null;
  const contactWhatsapp = rawWhatsapp ? cleanBeninPhone(rawWhatsapp) : null;
  const contactEmail = String(req.body.contact_email || "").trim().slice(0, 254);

  if ((rawPhone && !contactPhone) || (rawWhatsapp && !contactWhatsapp)) {
    return res.status(400).send(page("Erreur", "<h2>Numéro de contact invalide (format 01XXXXXXXX).</h2>", proConnected));
  }
  if (!contactPhone && !contactWhatsapp && !contactEmail) {
    return res.status(400).send(page("Erreur", "<h2>Indiquez au moins un moyen de contact.</h2>", proConnected));
  }

  try {
    await pool.query(
      `UPDATE job_offers
          SET company_name = $1, job_title = $2, city = $3, contract_type = $4,
              description = $5, contact_phone = $6, contact_whatsapp = $7,
              contact_email = $8, status = 'pending'
        WHERE id = $9 AND pro_id = $10`,
      [req.body.company_name, req.body.job_title, req.body.city, req.body.contract_type, req.body.description, contactPhone, contactWhatsapp, contactEmail || null, id, proConnected.pro.id]
    );
    await logAdminAction("job_edited_by_pro", "job", id, `Offre modifiee par ${getDisplayName(proConnected.pro)}`);
    res.redirect(303, "/mon-espace-pro");
  } catch (error) {
    console.error("Erreur modification offre :", error.message);
    res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", proConnected));
  }
});

app.post("/mon-espace-pro/offre/:id/supprimer", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/mon-espace-pro");
  try {
    const result = await pool.query(`DELETE FROM job_offers WHERE id = $1 AND pro_id = $2 RETURNING job_title`, [id, proConnected.pro.id]);
    if (result.rowCount) await logAdminAction("job_deleted_by_pro", "job", id, `Offre supprimee : ${result.rows[0].job_title}`);
  } catch (error) {
    console.error("Erreur suppression offre :", error.message);
  }
  res.redirect(303, "/mon-espace-pro");
});

app.get("/publier-emploi", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  const contractOptions = JOB_CONTRACT_TYPES.map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join("");
  res.send(page("Publier", `<section class="card" style="max-width: 700px; margin: 0 auto;"><h1 style="text-align:center;">Nouvelle offre</h1><form action="/offres-emploi" method="POST"><label>Entreprise *</label><input name="company_name" required maxlength="200" value="${escapeHtml(getDisplayName(proConnected.pro))}"><label>Poste *</label><input name="job_title" required maxlength="200"><div style="display:grid; grid-template-columns:1fr 1fr; gap:20px;"><div><label>Ville *</label><input name="city" required maxlength="100" value="${escapeHtml(proConnected.pro.city)}"></div><div><label>Contrat *</label><select name="contract_type" required><option value="">Choisir</option>${contractOptions}</select></div></div><label>Description *</label><textarea name="description" required maxlength="5000" rows="6"></textarea><h3 style="margin-top:20px;">Comment les candidats vous contactent</h3><div style="display:grid; grid-template-columns:1fr 1fr; gap:20px;"><div><label>Téléphone</label><input name="contact_phone" type="tel" maxlength="30" value="${escapeHtml(proConnected.pro.phone || "")}" placeholder="0194010345"></div><div><label>WhatsApp</label><input name="contact_whatsapp" type="tel" maxlength="30" value="${escapeHtml(proConnected.pro.whatsapp_number || proConnected.pro.phone || "")}" placeholder="0194010345"></div></div><label>E-mail (optionnel)</label><input name="contact_email" type="email" maxlength="254" value="${escapeHtml(proConnected.pro.contact_email || "")}"><p style="font-size:12px; color:#6b7280;">Au moins un moyen de contact est requis.</p><div style="text-align:center; margin-top:20px;"><button type="submit" style="padding:14px 40px;">Soumettre</button><a href="/mon-espace-pro" class="button secondary">Annuler</a></div></form></section>`, proConnected));
});

app.post("/offres-emploi", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  if (!JOB_CONTRACT_TYPES.includes(req.body.contract_type)) return res.status(400).send(page("Erreur", "<h2>Type invalide.</h2>", proConnected));

  const rawPhone = String(req.body.contact_phone || "").trim();
  const rawWhatsapp = String(req.body.contact_whatsapp || "").trim();
  const contactPhone = rawPhone ? cleanBeninPhone(rawPhone) : null;
  const contactWhatsapp = rawWhatsapp ? cleanBeninPhone(rawWhatsapp) : null;
  const contactEmail = String(req.body.contact_email || "").trim().slice(0, 254);

  if ((rawPhone && !contactPhone) || (rawWhatsapp && !contactWhatsapp)) {
    return res.status(400).send(page("Erreur", "<h2>Numéro de contact invalide (format 01XXXXXXXX).</h2>", proConnected));
  }
  if (!contactPhone && !contactWhatsapp && !contactEmail) {
    return res.status(400).send(page("Erreur", "<h2>Indiquez au moins un moyen de contact.</h2>", proConnected));
  }

  try {
    await pool.query(
      `INSERT INTO job_offers (company_name, job_title, city, contract_type, description, status, pro_id, expires_at, contact_phone, contact_whatsapp, contact_email)
       VALUES ($1,$2,$3,$4,$5,'pending',$6, NOW() + INTERVAL '15 days', $7, $8, $9)`,
      [req.body.company_name, req.body.job_title, req.body.city, req.body.contract_type, req.body.description, proConnected.pro.id, contactPhone, contactWhatsapp, contactEmail || null]
    );
    res.send(page("Succes", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>Soumise !</h1><p>Votre offre sera vérifiée avant publication.</p><a href='/mon-espace-pro' class='button'>Retour</a></section>", proConnected));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", proConnected)); }
});app.get("/admin", async (req, res) => {
  const session = verifySessionToken(readCookie(req, SESSION_COOKIE));
  if (session?.jti) {
    try {
      const active = await pool.query(
        `SELECT 1 FROM admin_sessions WHERE jti = $1 AND revoked_at IS NULL AND expires_at > NOW()`,
        [session.jti]
      );
      if (active.rows.length) return res.redirect(303, "/admin/dashboard");
    } catch (error) {
      console.error("Erreur verification session admin :", error.message);
    }
  }
  clearSessionCookie(res);
  res.send(page("Admin", `<section class="card" style="max-width: 400px; margin: 60px auto;"><h1 style="text-align:center;">Admin</h1><form action="/admin/login" method="POST"><label>Mot de passe</label><input type="password" name="password" required style="text-align:center; font-size:20px;">${ADMIN_TOTP_SECRET ? `<label>Code de validation (6 chiffres)</label><input name="totp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required style="text-align:center; font-size:20px; letter-spacing:4px;">` : ""}<button style="width:100%; margin-top:10px;">Connexion</button></form></section>`, null));
});

app.post("/admin/login", async (req, res) => {
  const address = req.ip || "unknown";
  const rateKey = `admin_login:${address}`;
  if (!(await takeRateLimit(rateKey, 5, 15 * 60 * 1000))) return res.status(429).send("Trop de tentatives.");
  if (!safeEqual(req.body.password || "", ADMIN_PASSWORD)) {
    return res.status(401).send(page("Refuse", "<h2>Mot de passe incorrect.</h2>", null));
  }
  if (ADMIN_TOTP_SECRET && !verifyTotp(ADMIN_TOTP_SECRET, req.body.totp)) {
    return res.status(401).send(page("Refuse", "<h2>Code de validation incorrect.</h2>", null));
  }

  await clearRateLimit(rateKey);
  const expiresAt = Date.now() + SESSION_DURATION;
  const jti = crypto.randomBytes(16).toString("hex");
  const session = { jti, expiresAt, csrf: crypto.randomBytes(32).toString("hex") };

  try {
    await pool.query(
      `INSERT INTO admin_sessions (jti, expires_at) VALUES ($1, to_timestamp($2 / 1000.0))`,
      [jti, expiresAt]
    );
  } catch (error) {
    console.error("Erreur creation session admin :", error.message);
    return res.status(500).send(page("Erreur", "<h2>Connexion impossible pour le moment.</h2>", null));
  }

  setSessionCookie(res, createSessionToken(session));
  res.redirect(303, "/admin/dashboard");
});

async function adminMenu(current, csrf) {
  let gdprCount = 0, prosPendingCount = 0, reviewsPendingCount = 0, msgsCount = 0, withdrawalsCount = 0, reportsCount = 0, notificationsFailed = 0;
  try {
    gdprCount = Number((await pool.query("SELECT COUNT(*) FROM gdpr_requests WHERE status = 'pending'")).rows[0].count);
    prosPendingCount = Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status IN ('pending', 'under_review', 'corrections_requested')")).rows[0].count);
    reviewsPendingCount = Number((await pool.query("SELECT COUNT(*) FROM reviews WHERE status = 'pending'")).rows[0].count);
    msgsCount = Number((await pool.query("SELECT COUNT(*) FROM contact_messages WHERE is_read = false")).rows[0].count);
    withdrawalsCount = Number((await pool.query("SELECT COUNT(*) FROM withdrawal_requests WHERE status = 'pending'")).rows[0].count);
    reportsCount = Number((await pool.query("SELECT COUNT(*) FROM review_reports WHERE status = 'pending'")).rows[0].count);
    notificationsFailed = Number((await pool.query("SELECT COUNT(*) FROM notifications WHERE status = 'failed'")).rows[0].count);
  } catch (e) {}

  const links = [
    { href: "/admin/dashboard", label: "📊 Dashboard", badge: 0 }, 
    { href: "/admin/suivi", label: "📈 Suivi & Export", badge: 0 }, 
    { href: "/admin/candidatures", label: "📋 Candidatures", badge: prosPendingCount }, 
    { href: "/admin/avis", label: "⭐ Avis", badge: reviewsPendingCount }, 
    { href: "/admin/signalisations", label: "🚩 Signalements", badge: reportsCount }, 
    { href: "/admin/emplois", label: "💼 Offres", badge: 0 }, 
    { href: "/admin/messages", label: "📩 Messages", badge: msgsCount }, 
    { href: "/admin/rgpd", label: "🔐 RGPD", badge: gdprCount },
    { href: "/admin/retraits", label: "💸 Retraits", badge: withdrawalsCount },
    { href: "/admin/blog", label: "📝 Blog", badge: 0 },
    { href: "/admin/logs", label: "🗂️ Journal", badge: 0 },
    { href: "/admin/notifications", label: "📨 Notifications", badge: notificationsFailed }
  ];
  return `<section class="card" style="background:#f9fafb; border:1px solid #e5e7eb; padding:16px;"><div class="actions" style="justify-content:center; gap:10px; display:flex; flex-wrap:wrap;">${links.map(l => `<a class="button ${current === l.href ? "" : "secondary"}" href="${l.href}" style="padding:8px 16px; font-size:14px; margin:0;">${l.label}${l.badge > 0 ? ` <span class="badge badge-new">${l.badge}</span>` : ""}</a>`).join("")}</div><div style="text-align:center; margin-top:20px;"><form action="/admin/logout" method="POST"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><button class="danger" style="padding:8px 24px; font-size:14px; margin:0;">Déconnexion</button></form></div></section>`;
}

app.get("/admin/dashboard", requireAdmin, async (req, res) => {
  try {
    const stats = {
      pros: Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status = 'approved'")).rows[0].count),
      prosPending: Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status IN ('pending', 'under_review', 'corrections_requested')")).rows[0].count),
      reviews: Number((await pool.query("SELECT COUNT(*) FROM reviews WHERE status = 'pending'")).rows[0].count),
      messages: Number((await pool.query("SELECT COUNT(*) FROM contact_messages WHERE is_read = false")).rows[0].count),
      prosToday: Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE DATE(created_at) = CURRENT_DATE")).rows[0].count)
    };
    const last7DaysResult = await pool.query(`SELECT DATE(created_at) as day, COUNT(*) as count FROM professional_applications WHERE created_at >= CURRENT_DATE - INTERVAL '7 days' GROUP BY DATE(created_at) ORDER BY day ASC`);
    const last7Days = last7DaysResult.rows;
    const maxDayCount = Math.max(1, ...last7Days.map((day) => Number(day.count)));
    const last7DaysHtml = last7Days.length > 0 ? `<section class="card" style="margin-top:30px;"><h2>📈 Inscriptions des 7 derniers jours</h2><div style="display:flex; align-items:flex-end; gap:8px; height:150px; margin-top:16px;">${last7Days.map((day) => { const count = Number(day.count); const height = Math.max(6, Math.round((count / maxDayCount) * 100)); const label = new Date(day.day).toLocaleDateString("fr-FR", { weekday: "short", day: "2-digit" }); return `<div style="flex:1; text-align:center;"><div style="height:${height}px; background:#3b82f6; border-radius:6px 6px 0 0;"></div><div style="font-size:11px; color:#6b7280; margin-top:4px;">${label}</div><div style="font-size:12px; font-weight:700;">${count}</div></div>`; }).join("")}</div></section>` : "";
    const todayResult = await pool.query(`SELECT id, full_name, profession, city, status, created_at FROM professional_applications WHERE DATE(created_at) = CURRENT_DATE ORDER BY created_at DESC`);
    const todayList = todayResult.rows.map(p => `<tr><td style="padding:12px 8px; border-bottom:1px solid #e5e7eb;"><a href="/admin/candidatures" style="color:#2563eb;">${escapeHtml(p.full_name)}</a></td><td style="padding:12px 8px; border-bottom:1px solid #e5e7eb;">${escapeHtml(p.profession)}</td><td style="padding:12px 8px; border-bottom:1px solid #e5e7eb;">${escapeHtml(p.city)}</td><td style="padding:12px 8px; border-bottom:1px solid #e5e7eb;"><span class="badge badge-${p.status}">${STATUS_LABELS[p.status]}</span></td><td style="padding:12px 8px; border-bottom:1px solid #e5e7eb;">${new Date(p.created_at).toLocaleTimeString("fr-FR", {hour: '2-digit', minute:'2-digit'})}</td></tr>`).join("");
    const todayHtml = todayResult.rows.length > 0 ? `<section class="card" style="margin-top:30px;"><h2>📅 Inscriptions du jour (${stats.prosToday})</h2><div style="overflow-x:auto;"><table style="width:100%; border-collapse:collapse; text-align:left; font-size:14px;"><thead><tr style="background:#f9fafb; border-bottom:2px solid #e5e7eb;"><th style="padding:12px 8px;">Nom</th><th style="padding:12px 8px;">Métier</th><th style="padding:12px 8px;">Ville</th><th style="padding:12px 8px;">Statut</th><th style="padding:12px 8px;">Heure</th></tr></thead><tbody>${todayList}</tbody></table></div></section>` : `<section class="card" style="margin-top:30px; text-align:center;"><p class="muted">Aucune inscription aujourd'hui.</p></section>`;
    const menu = await adminMenu("/admin/dashboard", getCsrf(req));
    res.send(page("Dashboard", `<h1 style="text-align:center; margin-bottom:30px;">Tableau de bord</h1>${menu}<div class="stats-grid" style="margin-top:30px;"><div class="stat-card"><div class="stat-number">${stats.pros}</div><div class="stat-label">Approuvés</div></div><div class="stat-card warning"><div class="stat-number">${stats.prosPending}</div><div class="stat-label">En attente</div></div><div class="stat-card danger"><div class="stat-number">${stats.reviews}</div><div class="stat-label">Avis</div></div><div class="stat-card info"><div class="stat-number">${stats.messages}</div><div class="stat-label">Messages</div></div><div class="stat-card success"><div class="stat-number" style="color: #059669;">${stats.prosToday}</div><div class="stat-label">Aujourd'hui</div></div></div>${todayHtml}${last7DaysHtml}`, null));
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
      const paymentBadge = p.payment_status === 'paid' ? '💳 Payé' : p.payment_status === 'refunded' ? '💸 Remboursé' : '⏳ Impayé';
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

    const includeNpi = req.query.npi === "full";
    const maskNpi = (value) => value ? `****${String(value).slice(-4)}` : "";

    let csv = "Date;Nom;Entreprise;Telephone;NPI;Ville;Metier;Statut;Paiement;Code de suivi;Code Pro\n";
    for (const p of result.rows) {
      const dateStr = new Date(p.created_at).toLocaleDateString("fr-FR");
      const status = STATUS_LABELS[p.status] || p.status;
      const payment = p.payment_status === 'paid' ? 'Payé' : p.payment_status === 'refunded' ? 'Remboursé' : 'Impayé';
      const clean = (val) => {
        let text = String(val ?? "");
        if (/^[=+\-@\t\r]/.test(text)) text = "'" + text;
        return `"${text.replace(/;/g, ',').replace(/"/g, '""')}"`;
      };
      csv += `${dateStr};${clean(p.full_name)};${clean(p.company_name)};${clean(p.phone)};${clean(includeNpi ? p.npi : maskNpi(p.npi))};${clean(p.city)};${clean(p.profession)};${clean(status)};${payment};${clean(p.tracking_code)};${clean(p.pro_code)}\n`;
    }

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="suivi_professionnels_${new Date().toISOString().slice(0,10)}.csv"`);
    res.send("\uFEFF" + csv);
  } catch (error) { res.status(500).send("Erreur lors de l'export."); }
});

const KYC_FIELDS = new Set(["photo_profil_url", "photo_identite_url", "photo_kyc_url"]);

app.get("/admin/kyc/:id/:field", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const field = String(req.params.field || "");
  if (!Number.isSafeInteger(id) || id < 1 || !KYC_FIELDS.has(field)) {
    return res.status(404).send("Not found");
  }

  try {
    const result = await pool.query(`SELECT ${field} AS url FROM professional_applications WHERE id = $1`, [id]);
    const url = result.rows[0]?.url;
    if (!url || !/^https:\/\/res\.cloudinary\.com\//.test(url)) return res.status(404).send("Not found");

    const upstream = await fetch(url, { redirect: "follow" });
    if (!upstream.ok) return res.status(404).send("Not found");

    const contentType = upstream.headers.get("content-type") || "image/jpeg";
    if (!contentType.startsWith("image/")) return res.status(415).send("Unsupported media type");

    const buffer = Buffer.from(await upstream.arrayBuffer());
    if (buffer.length > 6 * 1024 * 1024) return res.status(413).send("Too large");

    res.setHeader("Content-Type", contentType);
    res.setHeader("Cache-Control", "private, no-store");
    res.setHeader("X-Robots-Tag", "noindex, nofollow");
    res.send(buffer);
  } catch (error) {
    console.error("Erreur proxy KYC :", error.message);
    res.status(502).send("Bad gateway");
  }
});

app.get("/admin/candidatures", requireAdmin, async (req, res) => {
  try {
    const csrf = getCsrf(req);
    const currentPage = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 10;
    const offset = (currentPage - 1) * limit;
    const filter = String(req.query.filter || "all");
    const q = String(req.query.q || "").trim().slice(0, 100);

    let filterClause = "";
    if (filter === "unpaid") filterClause = "WHERE payment_status = 'unpaid' AND status = 'payment_pending'";
    else if (filter === "pending") filterClause = "WHERE status = 'pending'";
    else if (filter === "approved") filterClause = "WHERE status = 'approved'";

    const params = [];
    let searchClause = "";
    if (q) {
      params.push(`%${q}%`);
      searchClause = `${filterClause ? "AND" : "WHERE"} (full_name ILIKE $1 OR phone ILIKE $1 OR npi ILIKE $1 OR tracking_code ILIKE $1)`;
    }
    const whereClause = `${filterClause} ${searchClause}`;

    const countResult = await pool.query(`SELECT COUNT(*) FROM professional_applications ${whereClause}`, params);
    const total = parseInt(countResult.rows[0].count); const totalPages = Math.ceil(total / limit);
    const result = await pool.query(`SELECT p.* FROM professional_applications p ${whereClause} ORDER BY CASE WHEN p.status = 'payment_pending' THEN 0 WHEN p.status = 'pending' THEN 1 ELSE 2 END, p.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`, [...params, limit, offset]);

    const applications = result.rows.map(c => {
      const statusOptions = ALLOWED_STATUSES.map(s => `<option value="${s}" ${c.status === s ? "selected" : ""}>${STATUS_LABELS[s]}</option>`).join("");
      const paymentBadge = c.payment_status === "refunded" ? `<span class="badge" style="background:#e0e7ff;color:#3730a3;">💸 Remboursé</span>` : c.payment_status === "paid" ? `<span class="badge" style="background:#d1fae5;color:#065f46;">💳 Payé ${c.payment_amount ?? PAYMENT_AMOUNT} FCFA</span>` : c.status === "payment_pending" ? `<span class="badge" style="background:#fef3c7;color:#92400e;">⏳ Impayé</span>` : `<span class="badge" style="background:#e5e7eb;color:#374151;">—</span>`;
      
      const photos = `<div style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom:16px;">${c.photo_profil_url ? `<div style="text-align:center;"><img src="/admin/kyc/${c.id}/photo_profil_url" style="width:80px; height:80px; object-fit:cover; border-radius:8px; border:2px solid #3b82f6; cursor:pointer;" onclick="zoomImage(this.src)"><div style="font-size:11px; margin-top:4px; font-weight:600;">Identité</div></div>` : ""}${c.photo_identite_url ? `<div style="text-align:center;"><img src="/admin/kyc/${c.id}/photo_identite_url" style="width:80px; height:80px; object-fit:cover; border-radius:8px; border:2px solid #ef4444; cursor:pointer;" onclick="zoomImage(this.src)"><div style="font-size:11px; margin-top:4px; font-weight:600;">Pièce</div></div>` : ""}${c.photo_kyc_url ? `<div style="text-align:center;"><img src="/admin/kyc/${c.id}/photo_kyc_url" style="width:80px; height:80px; object-fit:cover; border-radius:8px; border:2px solid #f59e0b; cursor:pointer;" onclick="zoomImage(this.src)"><div style="font-size:11px; margin-top:4px; font-weight:600; color:#b45309;">KYC</div></div>` : ""}</div>`;

      let codeBlock = "";
      if (c.pro_code) {
        const waNumber = c.whatsapp_number || c.phone; const cleanNumber = waNumber.replace(/[()\s.-]/g, "").replace(/^\+/, ""); const baseUrl = `${req.protocol}://${req.get("host")}`; const waMessage = encodeURIComponent(`Bonjour ${c.full_name}, votre candidature sur TrouveMoi a ete approuvee ✅\n\nVotre code : ${c.pro_code}\n\nConnexion : ${baseUrl}/mon-espace-pro`);
        codeBlock = `<div style="background:#eff6ff; padding:12px; border-radius:8px; border:1px solid #bfdbfe; margin-bottom:16px;"><div style="font-size:12px; color:#1e40af; text-transform:uppercase; font-weight:700;">Code généré</div><div style="font-size:24px; font-weight:800; font-family:monospace; color:#1e3a8a; margin:4px 0;">${escapeHtml(c.pro_code)}</div><div style="display:flex; gap:8px; margin-top:8px;"><a class="button whatsapp" href="https://wa.me/${escapeHtml(cleanNumber)}?text=${waMessage}" target="_blank" style="font-size:12px; padding:6px 12px; margin:0;">📱 Envoyer WhatsApp</a><form action="/admin/candidatures/${c.id}/regenerer-code" method="POST" onsubmit="return confirm('Régénérer ?')" style="margin:0;"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><button class="warning" type="submit" style="font-size:12px; padding:6px 12px; margin:0;">🔄 Régénérer</button></form></div></div>`;
      }

      const paymentBlock = c.payment_status === "unpaid" ? `<div class="alert alert-warning" style="font-size:13px; padding:10px; margin-bottom:16px;">⏳ Paiement non effectué. <a href="/paiement/${escapeHtml(c.tracking_code)}" target="_blank">Lien de paiement</a></div>` : "";

      const refundBlock = c.payment_status === "paid" ? `
        <details style="margin-bottom:16px; background:#fffbeb; border:1px solid #fde68a; border-radius:12px; padding:12px;">
          <summary style="cursor:pointer; font-weight:700; color:#92400e;">💸 Rembourser ce dossier</summary>
          <p style="font-size:13px; color:#92400e; margin-top:8px;">Effectuez le remboursement dans Kkiapay, puis enregistrez la référence ci-dessous. Le dossier sera marqué « remboursé » et retiré de la liste publique.</p>
          <form action="/admin/candidatures/${c.id}/rembourser" method="POST" style="margin-top:8px;">
            <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
            <label style="font-size:12px;">Référence du remboursement *</label>
            <input name="refund_ref" required maxlength="100" style="margin:0 0 8px; padding:8px;">
            <label style="font-size:12px;">Motif</label>
            <input name="reason" maxlength="500" style="margin:0 0 8px; padding:8px;">
            <button class="warning" type="submit" onclick="return confirm('Confirmer le remboursement de ce dossier ?')" style="margin:0;">Enregistrer le remboursement</button>
          </form>
        </details>` : c.payment_status === "refunded" ? `<div class="alert alert-info" style="font-size:13px; padding:10px; margin-bottom:16px;">💸 Dossier remboursé le ${c.refunded_at ? new Date(c.refunded_at).toLocaleDateString("fr-FR") : "—"} (réf. ${escapeHtml(c.payment_refund_ref || "—")}).</div>` : "";

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
            ${refundBlock}
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
              <a class="button secondary" href="/admin/candidatures/${c.id}/modifier" style="padding:8px 16px; font-size:12px; margin-right:8px;">✏️ Modifier</a>
              <form action="/admin/candidatures/${c.id}/supprimer" method="POST" style="margin:0; display:inline;">
                <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
                <button class="danger" onclick="return confirm('Supprimer définitivement ?')" style="padding:8px 16px; font-size:12px; background:transparent; color:#ef4444; border:1px solid #ef4444;">🗑️ Supprimer</button>
              </form>
            </div>
          </div>
        </details>
      `;
    }).join("");

    const menu = await adminMenu("/admin/candidatures", csrf); 
    const paginationHtml = renderPagination(currentPage, totalPages, "/admin/candidatures", { ...(filter !== 'all' ? { filter } : {}), ...(q ? { q } : {}) });
    const filterBar = `<div style="display:flex; gap:8px; justify-content:center; flex-wrap:wrap; margin-bottom:20px;"><a class="button ${filter === 'all' ? '' : 'secondary'}" href="/admin/candidatures" style="padding:8px 16px; font-size:13px;">📋 Tout</a><a class="button ${filter === 'unpaid' ? '' : 'secondary'}" href="/admin/candidatures?filter=unpaid" style="padding:8px 16px; font-size:13px;">⏳ Impayés</a><a class="button ${filter === 'pending' ? '' : 'secondary'}" href="/admin/candidatures?filter=pending" style="padding:8px 16px; font-size:13px;">📥 En attente</a><a class="button ${filter === 'approved' ? '' : 'secondary'}" href="/admin/candidatures?filter=approved" style="padding:8px 16px; font-size:13px;">✅ Approuvés</a></div>`;
    const searchBar = `<form action="/admin/candidatures" method="GET" style="max-width:620px; margin:0 auto 16px; display:flex; gap:8px;">${filter !== 'all' ? `<input type="hidden" name="filter" value="${escapeHtml(filter)}">` : ""}<input name="q" value="${escapeHtml(q)}" placeholder="Nom, téléphone, NPI ou code de suivi" style="margin:0;"><button type="submit" style="margin:0; padding:12px 20px;">🔍 Rechercher</button></form>`;
    
    res.send(page("Candidatures", `<h1 style="text-align:center; margin-bottom:20px;">Candidatures (${total})</h1>${menu}${searchBar}${filterBar}${applications || '<section class="card"><p class="muted" style="text-align:center;">Aucune.</p></section>'}${paginationHtml}`, null));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.get("/admin/candidatures/:id/modifier", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/candidatures");

  const result = await pool.query(`SELECT * FROM professional_applications WHERE id = $1`, [id]);
  if (!result.rows.length) return res.redirect(303, "/admin/candidatures");
  const p = result.rows[0];

  res.send(page("Modifier le dossier", `
    <section class="card" style="max-width: 700px; margin: 40px auto;">
      <h1 style="text-align:center;">Modifier le dossier #${p.id}</h1>
      <form action="/admin/candidatures/${p.id}/modifier" method="POST">
        <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
        <label>Nom complet *</label>
        <input name="full_name" required maxlength="150" value="${escapeHtml(p.full_name)}">
        <label>Société</label>
        <input name="company_name" maxlength="200" value="${escapeHtml(p.company_name || "")}">
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
          <div><label>Téléphone *</label><input name="phone" required maxlength="30" value="${escapeHtml(p.phone)}"></div>
          <div><label>NPI</label><input name="npi" maxlength="15" value="${escapeHtml(p.npi || "")}"></div>
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
          <div><label>Ville *</label><input name="city" required maxlength="100" value="${escapeHtml(p.city)}"></div>
          <div><label>Quartier</label><input name="neighborhood" maxlength="150" value="${escapeHtml(p.neighborhood || "")}"></div>
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
          <div><label>Métier *</label><input name="profession" required maxlength="150" value="${escapeHtml(p.profession)}"></div>
          <div><label>E-mail</label><input name="contact_email" type="email" maxlength="254" value="${escapeHtml(p.contact_email || "")}"></div>
        </div>
        <label><input type="checkbox" name="phone_public" value="yes" ${p.phone_public ? "checked" : ""}> Numéro visible publiquement</label>
        <div style="text-align:center; margin-top:24px;"><button type="submit">💾 Enregistrer</button><a href="/admin/candidatures" class="button secondary">Annuler</a></div>
      </form>
    </section>`, null));
});app.post("/admin/candidatures/:id/modifier", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/candidatures");

  const fullName = String(req.body.full_name || "").trim().slice(0, 150);
  const phone = cleanBeninPhone(req.body.phone);
  const city = String(req.body.city || "").trim().slice(0, 100);
  const profession = String(req.body.profession || "").trim().slice(0, 150);
  if (!fullName || !phone || !city || !profession) {
    return res.status(400).send(page("Erreur", "<h2>Nom, téléphone, ville et métier sont obligatoires.</h2>", null));
  }

  const npi = String(req.body.npi || "").trim().slice(0, 100);
  if (npi && npi.length < 8) return res.status(400).send(page("Erreur", "<h2>NPI invalide.</h2>", null));

  const email = String(req.body.contact_email || "").trim().slice(0, 254);
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return res.status(400).send(page("Erreur", "<h2>E-mail invalide.</h2>", null));
  }

  const duplicate = await pool.query(
    `SELECT id FROM professional_applications
      WHERE id <> $1
        AND (REGEXP_REPLACE(phone, '[()\\s.-]', '', 'g') = $2 OR ($3::text IS NOT NULL AND npi = $3))
        AND status IN ('pending', 'under_review', 'approved', 'corrections_requested', 'payment_pending')
      LIMIT 1`,
    [id, phone, npi || null]
  );
  if (duplicate.rows.length) {
    return res.status(409).send(page("Erreur", "<h2>Ce téléphone ou ce NPI est déjà utilisé par un autre dossier.</h2>", null));
  }

  await pool.query(
    `UPDATE professional_applications
        SET full_name = $1, company_name = $2, phone = $3, npi = $4, city = $5,
            neighborhood = $6, profession = $7,
            profession_category = COALESCE((SELECT category FROM professions WHERE name = $7), 'Autre'),
            contact_email = $8, phone_public = $9,
            updated_at = NOW()
      WHERE id = $10`,
    [fullName, String(req.body.company_name || "").trim().slice(0, 200) || null, phone, npi || null, city, String(req.body.neighborhood || "").trim().slice(0, 150) || null, profession, email || null, req.body.phone_public === "yes", id]
  );
  await logAdminAction("pro_edited_by_admin", "pro", id, `Nom: ${fullName} | Téléphone: ${phone}`);
  res.redirect(303, "/admin/candidatures");
});

app.post("/admin/candidatures/:id/status", requireAdmin, verifyCsrf, async (req, res) => {
  try {
    const id = Number(req.params.id), status = req.body.status, reason = req.body.rejection_reason || null;
    if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/candidatures");
    if (!ALLOWED_STATUSES.includes(status)) return res.redirect(303, "/admin/candidatures");
    const existing = await pool.query("SELECT pro_code, photo_kyc_url, referral_code, payment_status, phone, contact_email, full_name FROM professional_applications WHERE id = $1", [id]);
    if (!existing.rows.length) return res.redirect(303, "/admin/candidatures");
    if (status === "approved" && !existing.rows[0].photo_kyc_url) return res.redirect(303, "/admin/candidatures");
    if (status === "approved" && !BYPASS_PAYMENT && existing.rows[0].payment_status !== "paid") {
      return res.status(400).send(page("Paiement requis", `<section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;"><h2>Ce dossier n'est pas encore payé.</h2><p>Les frais d'inscription doivent être encaissés avant l'approbation.</p><a class="button" href="/admin/candidatures">Retour aux candidatures</a></section>`, null));
    }
    
    if (status === "approved") {
      let newCode = existing.rows[0].pro_code;
      let newRefCode = existing.rows[0].referral_code;
      
      if (!newCode) newCode = await generateUniqueProCode();
      if (!newRefCode) newRefCode = await generateUniqueReferralCode();
      
      await pool.query(`UPDATE professional_applications SET status = $1, pro_code = $2, referral_code = $3, rejection_reason = $4, kyc_verified = true WHERE id = $5`, [status, newCode, newRefCode, reason, id]);
      await logAdminAction("approve_application", "pro", id, `Code généré: ${newCode} | Code parrainage: ${newRefCode}`);
      await queueNotification({
        recipient: existing.rows[0].phone,
        body: `TrouveMoi: votre dossier est approuve. Votre code pro est ${newCode}. Connexion: ${APP_URL}/mon-espace-pro`
      });
      if (existing.rows[0].contact_email) {
        await queueNotification({
          channel: "email",
          recipient: existing.rows[0].contact_email,
          subject: "Votre dossier TrouveMoi est approuvé",
          body: `Bonjour ${existing.rows[0].full_name}, votre dossier est approuvé. Votre code pro est ${newCode}. Connectez-vous sur ${APP_URL}/mon-espace-pro`
        });
      }
    } else {
      await pool.query(`UPDATE professional_applications SET status = $1, rejection_reason = $2 WHERE id = $3`, [status, reason, id]);
      await logAdminAction("update_status", "pro", id, `Nouveau statut: ${status}${reason ? ` | Motif: ${reason}` : ""}`);
      if (status === "rejected" || status === "corrections_requested") {
        const body = status === "rejected"
          ? `TrouveMoi: votre dossier est refuse. Motif: ${reason || "non precise"}.`
          : `TrouveMoi: des corrections sont demandees. Motif: ${reason || "non precise"}.`;
        await queueNotification({ recipient: existing.rows[0].phone, body });
        if (existing.rows[0].contact_email) {
          await queueNotification({
            channel: "email",
            recipient: existing.rows[0].contact_email,
            subject: status === "rejected" ? "Votre dossier TrouveMoi est refusé" : "Corrections demandées - TrouveMoi",
            body: `Bonjour ${existing.rows[0].full_name}, ${body}`
          });
        }
      }
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

app.post("/admin/candidatures/:id/rembourser", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/candidatures");

  const refundRef = String(req.body.refund_ref || "").trim().slice(0, 100);
  const reason = String(req.body.reason || "").trim().slice(0, 500) || "Remboursement";
  if (!refundRef) return res.status(400).send(page("Erreur", "<h2>Référence de remboursement requise.</h2>", null));

  try {
    const result = await pool.query(
      `UPDATE professional_applications
          SET payment_status = 'refunded', payment_refund_ref = $1, refunded_at = NOW(),
              status = CASE WHEN status IN ('approved', 'pending', 'under_review', 'corrections_requested') THEN 'rejected' ELSE status END,
              rejection_reason = $2, updated_at = NOW()
        WHERE id = $3 AND payment_status = 'paid'
        RETURNING id, payment_amount`,
      [refundRef, reason, id]
    );
    if (!result.rowCount) {
      return res.status(400).send(page("Erreur", "<h2>Ce dossier n'est pas remboursable (déjà remboursé ou non payé).</h2>", null));
    }
    await logAdminAction("payment_refunded", "pro", id, `Ref: ${refundRef} | Montant: ${result.rows[0].payment_amount} FCFA | Motif: ${reason}`);
    res.redirect(303, "/admin/candidatures");
  } catch (error) {
    console.error("Erreur remboursement :", error.message);
    res.status(500).send(page("Erreur", "<h2>Erreur lors du remboursement.</h2>", null));
  }
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
    const currentPage = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 50;
    const offset = (currentPage - 1) * limit;
    const countResult = await pool.query("SELECT COUNT(*) FROM reviews");
    const total = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(total / limit);
    const result = await pool.query(`SELECT r.*, p.full_name AS pro_name FROM reviews r LEFT JOIN professional_applications p ON p.id = r.pro_id ORDER BY CASE WHEN r.status = 'pending' THEN 0 ELSE 1 END, r.created_at DESC LIMIT $1 OFFSET $2`, [limit, offset]);
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
    res.send(page("Avis", `<h1 style="text-align:center; margin-bottom:30px;">Avis (${total})</h1>${menu}${reviews || '<section class="card"><p class="muted" style="text-align:center;">Aucun avis.</p></section>'}${renderPagination(currentPage, totalPages, "/admin/avis")}`, null));
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
    const currentPage = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 50;
    const offset = (currentPage - 1) * limit;
    const countResult = await pool.query("SELECT COUNT(*) FROM job_offers");
    const total = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(total / limit);
    const result = await pool.query(`SELECT j.*, p.full_name AS pro_name FROM job_offers j LEFT JOIN professional_applications p ON p.id = j.pro_id ORDER BY CASE WHEN j.status = 'pending' THEN 0 ELSE 1 END, j.created_at DESC LIMIT $1 OFFSET $2`, [limit, offset]);
    const offers = result.rows.map(j => `<article class="card" style="margin-bottom:20px;"><h2 style="font-size:18px;">${escapeHtml(j.job_title)}</h2><p class="muted" style="font-size:14px;">Par : <strong>${escapeHtml(j.pro_name || "Inconnu")}</strong></p><p><span class="badge badge-${j.status}">${JOB_STATUS_LABELS[j.status]}</span></p><p style="background:#f9fafb; padding:16px; border-radius:12px; margin:16px 0;">${escapeHtml(j.description)}</p><div class="actions" style="margin-top:16px;">${j.status === 'pending' ? `<form action="/admin/emplois/${j.id}/statut" method="POST" style="display:inline"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><input type="hidden" name="status" value="approved"><button class="success" style="padding:8px 24px; font-size:14px;">Approuver</button></form><form action="/admin/emplois/${j.id}/statut" method="POST" style="display:inline"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><input type="hidden" name="status" value="rejected"><button class="danger" style="padding:8px 24px; font-size:14px;">Rejeter</button></form>` : ""}</div></article>`).join("");
    const menu = await adminMenu("/admin/emplois", csrf);
    res.send(page("Offres d'emploi", `<h1 style="text-align:center; margin-bottom:30px;">Offres (${total})</h1>${menu}${offers || '<section class="card"><p class="muted" style="text-align:center;">Aucune offre.</p></section>'}${renderPagination(currentPage, totalPages, "/admin/emplois")}`, null));
  } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.post("/admin/emplois/:id/statut", requireAdmin, verifyCsrf, async (req, res) => { 
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/emplois");
  if (JOB_STATUSES.includes(req.body.status)) { 
    await pool.query(`UPDATE job_offers SET status = $1 WHERE id = $2`, [req.body.status, id]); 
    await logAdminAction(`job_${req.body.status}`, "job", id, null); 
  } 
  res.redirect(303, "/admin/emplois"); 
});

app.get("/admin/signalisations", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  const result = await pool.query(`SELECT r.*, v.comment AS review_comment, v.author_name, p.full_name AS pro_name FROM review_reports r JOIN reviews v ON v.id = r.review_id JOIN professional_applications p ON p.id = v.pro_id ORDER BY CASE WHEN r.status = 'pending' THEN 0 ELSE 1 END, r.created_at DESC`);
  const reports = result.rows.map(r => `<article class="card" style="margin-bottom:20px;"><h2 style="font-size:18px;">Signalement de ${escapeHtml(r.pro_name)}</h2><p style="margin-top:8px;"><span class="badge badge-${r.status === 'pending' ? 'pending' : 'processed'}">${r.status === 'pending' ? 'En attente' : 'Traité'}</span></p><div style="background:#f9fafb; padding:16px; border-radius:12px; margin:16px 0;"><p style="font-weight:bold; margin-bottom:8px;">Motif du signalement :</p><p>${escapeHtml(r.reason)}</p><p style="font-weight:bold; margin-top:16px; margin-bottom:8px;">Avis concerné :</p><p style="font-style:italic;">"${escapeHtml(r.review_comment)}" par ${escapeHtml(r.author_name)}</p></div>${r.status === 'pending' ? `<div style="display:flex; gap:10px;"><form action="/admin/signalisations/${r.id}/supprimer-avis" method="POST" style="margin:0;"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><button class="danger" style="padding:8px 16px; font-size:14px;">Supprimer l'avis</button></form><form action="/admin/signalisations/${r.id}/rejeter" method="POST" style="margin:0;"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><button class="secondary" style="padding:8px 16px; font-size:14px;">Rejeter le signalement</button></form></div>` : ""}</article>`).join("");
  const menu = await adminMenu("/admin/signalisations", csrf);
  res.send(page("Signalements", `<h1 style="text-align:center; margin-bottom:30px;">Signalements</h1>${menu}${reports || '<section class="card"><p class="muted" style="text-align:center;">Aucun signalement.</p></section>'}`, null));
});

app.post("/admin/signalisations/:id/supprimer-avis", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/signalisations");
  const report = await pool.query(`SELECT review_id FROM review_reports WHERE id = $1`, [id]);
  if (report.rows.length) {
    await pool.query(`DELETE FROM reviews WHERE id = $1`, [report.rows[0].review_id]);
    await pool.query(`UPDATE review_reports SET status = 'processed', processed_at = NOW() WHERE id = $1`, [id]);
    await logAdminAction("review_deleted_by_report", "review", report.rows[0].review_id, `Suite au signalement ${id}`);
  }
  res.redirect(303, "/admin/signalisations");
});

app.post("/admin/signalisations/:id/rejeter", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/signalisations");
  await pool.query(`UPDATE review_reports SET status = 'rejected', processed_at = NOW() WHERE id = $1`, [id]);
  res.redirect(303, "/admin/signalisations");
});

app.get("/admin/messages", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  const result = await pool.query(`SELECT * FROM contact_messages ORDER BY created_at DESC`);
  const messages = result.rows.map(m => `<article class="card" style="margin-bottom:20px;"><h2 style="font-size:18px;">${escapeHtml(m.name)}</h2><p class="muted" style="font-size:14px;">Email : ${escapeHtml(m.email)} ${m.phone ? `| Tel : ${escapeHtml(m.phone)}` : ""}</p><p style="background:#f9fafb; padding:16px; border-radius:12px; margin:16px 0;">${escapeHtml(m.message)}</p><p class="muted" style="font-size:12px;">Reçu le ${new Date(m.created_at).toLocaleString("fr-FR")}</p></article>`).join("");
  const menu = await adminMenu("/admin/messages", csrf);
  res.send(page("Messages", `<h1 style="text-align:center; margin-bottom:30px;">Messages</h1>${menu}${messages || '<section class="card"><p class="muted" style="text-align:center;">Aucun message.</p></section>'}`, null));
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
    const currentPage = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 50;
    const offset = (currentPage - 1) * limit;
    const countResult = await pool.query("SELECT COUNT(*) FROM withdrawal_requests");
    const total = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(total / limit);
    const result = await pool.query(`SELECT w.*, p.full_name, p.pro_code FROM withdrawal_requests w JOIN professional_applications p ON p.id = w.pro_id ORDER BY CASE WHEN w.status = 'pending' THEN 0 ELSE 1 END, w.created_at DESC LIMIT $1 OFFSET $2`, [limit, offset]);
    
    const requests = result.rows.map(w => `
      <article class="card" style="margin-bottom:20px; ${w.status === 'pending' ? 'border-left:4px solid #f59e0b;' : ''}">
        <h2 style="font-size:18px;">${escapeHtml(w.full_name)} (${escapeHtml(w.pro_code)})</h2>
        <p><strong>Montant :</strong> ${w.amount} FCFA</p>
        <p><strong>Numéro :</strong> ${escapeHtml(w.phone_number)}</p>
        <p><strong>Statut :</strong> <span class="badge badge-${w.status === 'pending' ? 'pending' : w.status === 'rejected' ? 'rejected' : 'approved'}">${w.status === 'pending' ? 'En attente' : w.status === 'rejected' ? 'Refusé (recrédité)' : 'Payé'}</span></p>
        ${w.status === 'pending' ? `
        <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:10px;">
          <form action="/admin/retraits/${w.id}/approuver" method="POST" style="margin:0;">
            <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
            <button class="success" onclick="return confirm('Confirmez-vous avoir payé ${w.amount} FCFA au ${w.phone_number} ?')">✅ Approuver et marquer comme payé</button>
          </form>
          <form action="/admin/retraits/${w.id}/rejeter" method="POST" style="margin:0;">
            <input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}">
            <button class="danger" onclick="return confirm('Refuser ce retrait et recréditer ${w.amount} FCFA au professionnel ?')">↩️ Refuser et recréditer</button>
          </form>
        </div>` : ""}
      </article>
    `).join("");

    const menu = await adminMenu("/admin/retraits", csrf);
    res.send(page("Retraits", `<h1 style="text-align:center; margin-bottom:30px;">Demandes de retrait (${total})</h1>${menu}${requests || '<section class="card"><p class="muted" style="text-align:center;">Aucune demande.</p></section>'}${renderPagination(currentPage, totalPages, "/admin/retraits")}`, null));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

app.post("/admin/retraits/:id/approuver", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/retraits");

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const updated = await client.query(
      `UPDATE withdrawal_requests SET status = 'processed', processed_at = NOW()
        WHERE id = $1 AND status = 'pending'
        RETURNING pro_id, amount, phone_number`,
      [id]
    );
    if (updated.rowCount) {
      await logAdminAction("withdrawal_processed", "withdrawal", id, `Montant: ${updated.rows[0].amount} FCFA | Numero: ${updated.rows[0].phone_number}`);
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Erreur validation retrait :", error.message);
  } finally {
    client.release();
  }
  res.redirect(303, "/admin/retraits");
});app.post("/admin/retraits/:id/rejeter", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/admin/retraits");

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const rejected = await client.query(
      `UPDATE withdrawal_requests SET status = 'rejected', processed_at = NOW()
        WHERE id = $1 AND status = 'pending'
        RETURNING pro_id, amount`,
      [id]
    );
    if (rejected.rowCount) {
      const reqData = rejected.rows[0];
      await client.query(
        `UPDATE professional_applications SET referral_balance = referral_balance + $1, updated_at = NOW() WHERE id = $2`,
        [reqData.amount, reqData.pro_id]
      );
      await logAdminAction("withdrawal_rejected", "withdrawal", id, `Montant recrédité: ${reqData.amount} FCFA`);
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Erreur rejet retrait :", error.message);
  } finally {
    client.release();
  }
  res.redirect(303, "/admin/retraits");
});

app.post("/admin/logout", requireAdmin, verifyCsrf, async (req, res) => {
  await pool.query(`UPDATE admin_sessions SET revoked_at = NOW() WHERE jti = $1`, [req.adminSession.jti]).catch(() => {});
  clearSessionCookie(res);
  res.redirect(303, "/admin");
});

/* --- BLOG --- */
app.get("/admin/blog", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  const articles = (await pool.query(`SELECT * FROM blog_posts ORDER BY created_at DESC`)).rows;
  const list = articles.map(a => `<article class="card" style="margin-bottom:20px;"><h2 style="font-size:18px;">${escapeHtml(a.title)}</h2><p class="muted" style="font-size:13px;">Publié le ${new Date(a.created_at).toLocaleDateString("fr-FR")} - ${a.published ? 'En ligne' : 'Brouillon'}</p><div class="actions" style="margin-top:10px;"><a class="button secondary" href="/admin/blog/${a.id}/modifier" style="padding:6px 12px; font-size:12px;">✏️ Modifier</a><form action="/admin/blog/${a.id}/supprimer" method="POST" style="display:inline; margin:0;"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><button class="danger" onclick="return confirm('Supprimer ?')" style="padding:6px 12px; font-size:12px;">🗑️ Supprimer</button></form></div></article>`).join("");
  const menu = await adminMenu("/admin/blog", csrf);
  res.send(page("Blog", `<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;"><h1 style="margin:0;">Blog</h1><a class="button" href="/admin/blog/nouveau">➕ Nouvel article</a></div>${menu}${list || '<section class="card"><p class="muted" style="text-align:center;">Aucun article.</p></section>'}`, null));
});

app.get("/admin/blog/nouveau", requireAdmin, (req, res) => {
  const csrf = getCsrf(req);
  res.send(page("Nouvel article", `<section class="card" style="max-width:700px; margin:0 auto;"><h1>Nouvel article</h1><form action="/admin/blog/nouveau" method="POST"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><label>Titre *</label><input name="title" required maxlength="200"><label>Contenu *</label><textarea name="content" required rows="12" style="min-height:250px;"></textarea><label><input type="checkbox" name="published" value="yes"> Publier immédiatement</label><div style="margin-top:20px;"><button type="submit">Enregistrer</button><a href="/admin/blog" class="button secondary">Annuler</a></div></form></section>`, null));
});

app.post("/admin/blog/nouveau", requireAdmin, verifyCsrf, async (req, res) => {
  const title = String(req.body.title || "").trim().slice(0, 200);
  const content = String(req.body.content || "").trim();
  const published = req.body.published === "yes";
  if (!title || !content) return res.redirect(303, "/admin/blog/nouveau");
  const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "") + "-" + crypto.randomInt(1000, 9999);
  await pool.query(`INSERT INTO blog_posts (title, slug, content, published) VALUES ($1, $2, $3, $4)`, [title, slug, content, published]);
  res.redirect(303, "/admin/blog");
});

app.get("/admin/blog/:id/modifier", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  const article = (await pool.query(`SELECT * FROM blog_posts WHERE id = $1`, [Number(req.params.id)])).rows[0];
  if (!article) return res.redirect(303, "/admin/blog");
  res.send(page("Modifier article", `<section class="card" style="max-width:700px; margin:0 auto;"><h1>Modifier l'article</h1><form action="/admin/blog/${article.id}/modifier" method="POST"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><label>Titre *</label><input name="title" required maxlength="200" value="${escapeHtml(article.title)}"><label>Contenu *</label><textarea name="content" required rows="12" style="min-height:250px;">${escapeHtml(article.content)}</textarea><label><input type="checkbox" name="published" value="yes" ${article.published ? "checked" : ""}> Publier</label><div style="margin-top:20px;"><button type="submit">Enregistrer</button><a href="/admin/blog" class="button secondary">Annuler</a></div></form></section>`, null));
});

app.post("/admin/blog/:id/modifier", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  const title = String(req.body.title || "").trim().slice(0, 200);
  const content = String(req.body.content || "").trim();
  const published = req.body.published === "yes";
  await pool.query(`UPDATE blog_posts SET title = $1, content = $2, published = $3 WHERE id = $4`, [title, content, published, id]);
  res.redirect(303, "/admin/blog");
});

app.post("/admin/blog/:id/supprimer", requireAdmin, verifyCsrf, async (req, res) => {
  await pool.query(`DELETE FROM blog_posts WHERE id = $1`, [Number(req.params.id)]);
  res.redirect(303, "/admin/blog");
});

app.get("/admin/logs", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  const currentPage = Math.max(1, parseInt(req.query.page) || 1);
  const limit = 50;
  const offset = (currentPage - 1) * limit;
  const countResult = await pool.query("SELECT COUNT(*) FROM admin_logs");
  const total = parseInt(countResult.rows[0].count);
  const totalPages = Math.ceil(total / limit);
  const logs = (await pool.query(`SELECT * FROM admin_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2`, [limit, offset])).rows;
  const rows = logs.map(l => `<tr style="border-bottom:1px solid #e5e7eb;"><td style="padding:10px; font-size:12px;">${new Date(l.created_at).toLocaleString("fr-FR")}</td><td style="padding:10px; font-size:13px; font-weight:bold;">${escapeHtml(l.action)}</td><td style="padding:10px; font-size:13px;">${escapeHtml(l.target_type)} #${l.target_id || "-"}</td><td style="padding:10px; font-size:12px; color:#6b7280;">${escapeHtml(l.details || "")}</td></tr>`).join("");
  const menu = await adminMenu("/admin/logs", csrf);
  res.send(page("Journal", `<h1 style="text-align:center; margin-bottom:30px;">Journal d'activité</h1>${menu}<section class="card" style="overflow-x:auto;"><table style="width:100%; border-collapse:collapse;"><thead><tr style="background:#f9fafb;"><th style="padding:10px; text-align:left; font-size:12px;">Date</th><th style="padding:10px; text-align:left; font-size:12px;">Action</th><th style="padding:10px; text-align:left; font-size:12px;">Cible</th><th style="padding:10px; text-align:left; font-size:12px;">Détails</th></tr></thead><tbody>${rows || '<tr><td colspan="4" style="text-align:center; padding:20px;">Aucun log.</td></tr>'}</tbody></table></section>${renderPagination(currentPage, totalPages, "/admin/logs")}`, null));
});

app.get("/admin/notifications", requireAdmin, async (req, res) => {
  const csrf = getCsrf(req);
  const notifications = (await pool.query(`SELECT * FROM notifications ORDER BY created_at DESC LIMIT 100`)).rows;
  const rows = notifications.map(n => `<tr style="border-bottom:1px solid #e5e7eb;"><td style="padding:10px; font-size:12px;">${new Date(n.created_at).toLocaleString("fr-FR")}</td><td style="padding:10px; font-size:12px;">${n.channel}</td><td style="padding:10px; font-size:13px;">${escapeHtml(n.recipient)}</td><td style="padding:10px; font-size:12px;">${escapeHtml(n.body).slice(0, 100)}...</td><td style="padding:10px;"><span class="badge badge-${n.status === 'sent' ? 'approved' : n.status === 'failed' ? 'rejected' : 'pending'}">${n.status}</span></td></tr>`).join("");
  const menu = await adminMenu("/admin/notifications", csrf);
  res.send(page("Notifications", `<h1 style="text-align:center; margin-bottom:30px;">Notifications (100 dernières)</h1>${menu}<section class="card" style="overflow-x:auto;"><table style="width:100%; border-collapse:collapse;"><thead><tr style="background:#f9fafb;"><th style="padding:10px; text-align:left; font-size:12px;">Date</th><th style="padding:10px; text-align:left; font-size:12px;">Type</th><th style="padding:10px; text-align:left; font-size:12px;">Destinataire</th><th style="padding:10px; text-align:left; font-size:12px;">Message</th><th style="padding:10px; text-align:left; font-size:12px;">Statut</th></tr></thead><tbody>${rows || '<tr><td colspan="5" style="text-align:center; padding:20px;">Aucune notification.</td></tr>'}</tbody></table></section>`, null));
});

/* --- PAGES STATIQUES --- */
app.get("/contact", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const proId = req.query.pro ? Number(req.query.pro) : null;
  const reportId = req.query.report ? Number(req.query.report) : null;
  const success = req.query.success === "1";
  
  let contextHtml = "";
  if (proId) {
    const proResult = await pool.query(`SELECT full_name, company_name FROM professional_applications WHERE id = $1`, [proId]);
    if (proResult.rows.length) {
      contextHtml = `<div class="alert alert-info">Vous contactez : <strong>${escapeHtml(proResult.rows[0].company_name || proResult.rows[0].full_name)}</strong></div>`;
    }
  } else if (reportId) {
    contextHtml = `<div class="alert alert-danger">⚠️ Vous signalez le professionnel #${reportId}.</div>`;
  }

  res.send(page("Contact", `
    <section class="card" style="max-width: 600px; margin: 40px auto;">
      <h1 style="text-align:center;">Contactez-nous</h1>
      ${success ? `<div class="alert alert-success">✅ Votre message a bien été envoyé. Nous vous répondrons rapidement.</div>` : ""}
      ${contextHtml}
      <form action="/contact" method="POST">
        <input type="hidden" name="pro_id" value="${proId || ""}">
        <input type="hidden" name="report_id" value="${reportId || ""}">
        <label>Votre nom *</label>
        <input name="name" required maxlength="100">
        <label>Votre email *</label>
        <input name="email" type="email" required maxlength="254">
        <label>Votre téléphone (optionnel)</label>
        <input name="phone" type="tel" maxlength="30">
        <label>Message *</label>
        <textarea name="message" required rows="5" maxlength="3000"></textarea>
        <button type="submit" style="width:100%; margin-top:10px;">Envoyer le message</button>
      </form>
    </section>
  `, proConnected));
});

app.post("/contact", async (req, res) => {
  const ip = req.ip || "unknown";
  if (!(await takeRateLimit(`contact:${ip}`, 5, 60 * 60 * 1000))) return res.status(429).send(page("Trop de tentatives", "<section class='card'><h1>⏳ Trop de tentatives</h1><p>Patientez 1 heure.</p></section>", null));

  const name = String(req.body.name || "").trim().slice(0, 100);
  const email = String(req.body.email || "").trim().slice(0, 254);
  const phone = String(req.body.phone || "").trim().slice(0, 30);
  const message = String(req.body.message || "").trim().slice(0, 3000);
  const proId = req.body.pro_id ? Number(req.body.pro_id) : null;
  const reportId = req.body.report_id ? Number(req.body.report_id) : null;

  if (!name || !email || !message) return res.redirect(303, "/contact");

  try {
    await pool.query(
      `INSERT INTO contact_messages (name, email, phone, message, pro_id, report_id) VALUES ($1, $2, $3, $4, $5, $6)`,
      [name, email, phone || null, message, proId || null, reportId || null]
    );
    res.redirect(303, "/contact?success=1");
  } catch (e) { res.redirect(303, "/contact"); }
});

app.get("/a-propos", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  res.send(page("À propos", `<section class="card" style="max-width: 800px; margin: 40px auto;"><h1>À propos de TrouveMoi</h1><p>TrouveMoi est la première plateforme béninoise qui met en relation directe les clients avec des professionnels vérifiés de leur quartier.</p><p>Notre mission est de valoriser le savoir-faire local tout en garantissant aux clients des prestations de qualité, en toute confiance.</p></section>`, proConnected));
});

app.get("/mentions-legales", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  res.send(page("Mentions légales", `<section class="card" style="max-width: 800px; margin: 40px auto;"><h1>Mentions légales</h1><h2>Éditeur du site</h2><p>TrouveMoi.bj<br>Contact : contact@trouvemoi.bj</p><h2>Hébergement</h2><p>Render (San Francisco, USA)</p><h2>Propriété intellectuelle</h2><p>Tous les éléments du site TrouveMoi.bj sont protégés par le droit d'auteur.</p></section>`, proConnected));
});

app.get("/confidentialite", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  res.send(page("Confidentialité", `<section class="card" style="max-width: 800px; margin: 40px auto;"><h1>Politique de confidentialité</h1><p>Nous collectons vos données personnelles (nom, téléphone, adresse) uniquement dans le but de faciliter la mise en relation entre clients et professionnels.</p><p>Vos données ne sont en aucun cas revendues à des tiers.</p><p>Conformément au RGPD, vous pouvez demander la suppression de vos données depuis votre espace pro.</p></section>`, proConnected));
});

app.get("/conditions", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  res.send(page("Conditions", `<section class="card" style="max-width: 800px; margin: 40px auto;"><h1>Conditions Générales d'Utilisation</h1><p>L'utilisation de TrouveMoi.bj implique l'acceptation pleine et entière des présentes conditions.</p><p>Les professionnels s'engagent à fournir des informations exactes et à traiter les clients avec respect.</p></section>`, proConnected));
});

app.get("/partenariats", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  res.send(page("Partenariats", `<section class="card" style="max-width: 800px; margin: 40px auto;"><h1>Partenariats</h1><p>Vous souhaitez collaborer avec TrouveMoi ? Contactez-nous à contact@trouvemoi.bj.</p></section>`, proConnected));
});

app.get("/blog", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const articles = (await pool.query(`SELECT * FROM blog_posts WHERE published = true ORDER BY created_at DESC`)).rows;
  const list = articles.map(a => `<article class="card" style="margin-bottom:20px;"><h2 style="font-size:20px;"><a href="/blog/${a.slug}" style="text-decoration:none; color:#1e40af;">${escapeHtml(a.title)}</a></h2><p class="muted" style="font-size:13px;">Publié le ${new Date(a.created_at).toLocaleDateString("fr-FR")}</p><p style="margin-top:10px; color:#4b5563;">${escapeHtml(a.content).slice(0, 200)}...</p></article>`).join("");
  res.send(page("Blog", `<h1 style="text-align:center; margin-bottom:30px;">Le Blog de TrouveMoi</h1><div style="max-width:800px; margin:0 auto;">${list || '<p style="text-align:center;">Aucun article pour le moment.</p>'}</div>`, proConnected));
});

app.get("/blog/:slug", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const article = (await pool.query(`SELECT * FROM blog_posts WHERE slug = $1 AND published = true`, [req.params.slug])).rows[0];
  if (!article) return res.redirect(303, "/blog");
  res.send(page(article.title, `<article class="card" style="max-width:800px; margin:40px auto;"><h1 style="font-size:28px;">${escapeHtml(article.title)}</h1><p class="muted" style="font-size:13px; margin-bottom:20px;">Publié le ${new Date(article.created_at).toLocaleDateString("fr-FR")}</p><div style="line-height:1.8; color:#374151;">${escapeHtml(article.content).replace(/\n/g, "<br>")}</div><p style="margin-top:30px;"><a href="/blog" style="color:#2563eb;">← Retour au blog</a></p></article>`, proConnected));
});

app.get("/manifest.json", (req, res) => {
  res.json({
    name: "TrouveMoi",
    short_name: "TrouveMoi",
    description: "Trouvez le professionnel qu'il vous faut près de chez vous.",
    start_url: "/",
    display: "standalone",
    background_color: "#ffffff",
    theme_color: "#1e40af",
    icons: [{ src: "https://res.cloudinary.com/gxm35ndf/image/upload/v1792582418/pros.jpg", sizes: "512x512", type: "image/jpeg" }]
  });
});

app.get("/health", async (req, res) => {
  const token = req.query.token || req.headers["x-health-token"];
  if (HEALTH_TOKEN && token !== HEALTH_TOKEN) return res.status(401).send("Unauthorized");
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", time: new Date().toISOString() });
  } catch (e) { res.status(500).json({ status: "error" }); }
});

app.get("/cron/cleanup", async (req, res) => {
  const token = req.query.token || req.headers["x-cron-secret"];
  if (!safeEqual(token || "", CRON_SECRET || "")) return res.status(401).send("Unauthorized");
  try {
    const cleaned = await cleanupExpiredDossiers();
    const notifications = await processNotifications(20);
    res.json({ ok: true, cleaned, notifications });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

async function cleanupExpiredDossiers() {
  const expired = await pool.query(
    `SELECT id FROM professional_applications WHERE status = 'payment_pending' AND created_at < NOW() - INTERVAL '48 hours'`
  );
  if (!expired.rowCount) return 0;

  const ids = expired.rows.map((r) => r.id);
  const photos = await pool.query(
    `SELECT photo_profil_url, photo_identite_url, photo_kyc_url FROM professional_applications WHERE id = ANY($1::int[])`,
    [ids]
  );
  const urls = photos.rows.flatMap((row) => [row.photo_profil_url, row.photo_identite_url, row.photo_kyc_url]).filter(Boolean);

  await pool.query(`DELETE FROM professional_applications WHERE id = ANY($1::int[])`, [ids]);
  await Promise.allSettled(urls.map((url) => deleteFromCloudinary(url)));
  await logAdminAction("cleanup_expired", "pro", null, `${ids.length} dossiers impayes de plus de 48h supprimes`);
  return ids.length;
}

/* --- DEMARRAGE DU SERVEUR ET MIGRATIONS --- */
async function runVersionedMigrations(statements, key, version) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)", [`migration:${key}`]);
    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (key VARCHAR(100) PRIMARY KEY, version INTEGER NOT NULL, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`);
    const current = await client.query(`SELECT version FROM schema_migrations WHERE key = $1`, [key]);
    if (current.rows.length && Number(current.rows[0].version) >= version) {
      await client.query("ROLLBACK");
      return;
    }
    for (const sql of statements) {
      try { await client.query(sql); } catch (e) {
        if (!["42701", "42P07", "42710"].includes(e.code)) throw e;
      }
    }
    await client.query(`INSERT INTO schema_migrations (key, version) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET version = EXCLUDED.version, updated_at = NOW()`, [key, version]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function startServer() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS professional_applications (
        id SERIAL PRIMARY KEY, full_name VARCHAR(150) NOT NULL, company_name VARCHAR(200), phone VARCHAR(30) NOT NULL, phone_public BOOLEAN NOT NULL DEFAULT true,
        city VARCHAR(100) NOT NULL, neighborhood VARCHAR(150), profession VARCHAR(150) NOT NULL, experience VARCHAR(50), service_description TEXT NOT NULL,
        service_area VARCHAR(300), availability VARCHAR(100), npi VARCHAR(15), photo_profil_url TEXT NOT NULL, photo_identite_url TEXT NOT NULL, photo_kyc_url TEXT NOT NULL,
        photo_activite_url TEXT, photo_galerie_1 TEXT, photo_galerie_2 TEXT, photo_galerie_3 TEXT, contact_preference VARCHAR(20) DEFAULT 'whatsapp', whatsapp_number VARCHAR(30),
        contact_email VARCHAR(254), pro_code VARCHAR(20) UNIQUE, pro_code_updated_at TIMESTAMP, tracking_code VARCHAR(20) UNIQUE, status VARCHAR(50) NOT NULL DEFAULT 'pending',
        rejection_reason TEXT, payment_status VARCHAR(20) NOT NULL DEFAULT 'unpaid', payment_ref VARCHAR(100) UNIQUE, payment_amount INTEGER, payment_date TIMESTAMP, payment_method VARCHAR(50),
        type_lieu VARCHAR(20) DEFAULT 'ambulant', adresse_exacte VARCHAR(200), latitude DECIMAL(10, 8), longitude DECIMAL(11, 8), est_ouvert BOOLEAN NOT NULL DEFAULT true, horaires_json TEXT,
        unavailable_until TIMESTAMP, kyc_verified BOOLEAN NOT NULL DEFAULT false, referral_code VARCHAR(10) UNIQUE, referred_by VARCHAR(10), referral_balance INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS reviews (
        id SERIAL PRIMARY KEY, pro_id INTEGER NOT NULL REFERENCES professional_applications(id) ON DELETE CASCADE, author_name VARCHAR(100) NOT NULL, rating INTEGER NOT NULL,
        comment TEXT, pro_response TEXT, pro_response_at TIMESTAMP, status VARCHAR(20) NOT NULL DEFAULT 'pending', visitor_id VARCHAR(64), created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, processed_at TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS pro_stats (
        pro_id INTEGER NOT NULL REFERENCES professional_applications(id) ON DELETE CASCADE, date DATE NOT NULL, views INTEGER NOT NULL DEFAULT 0, phone_clicks INTEGER NOT NULL DEFAULT 0,
        wa_clicks INTEGER NOT NULL DEFAULT 0, last_visitor_id VARCHAR(64), PRIMARY KEY (pro_id, date)
      );
      CREATE TABLE IF NOT EXISTS client_favorites (
        id SERIAL PRIMARY KEY, visitor_id VARCHAR(64) NOT NULL, pro_id INTEGER NOT NULL REFERENCES professional_applications(id) ON DELETE CASCADE, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(visitor_id, pro_id)
      );
      CREATE TABLE IF NOT EXISTS gdpr_requests (
        id SERIAL PRIMARY KEY, pro_id INTEGER REFERENCES professional_applications(id) ON DELETE CASCADE, request_type VARCHAR(50) NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'pending',
        message TEXT, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, processed_at TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS admin_logs (
        id SERIAL PRIMARY KEY, action VARCHAR(100) NOT NULL, target_type VARCHAR(50), target_id INTEGER, details TEXT, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS cities (id SERIAL PRIMARY KEY, name VARCHAR(100) UNIQUE NOT NULL, display_order INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS neighborhoods (id SERIAL PRIMARY KEY, city_id INTEGER NOT NULL REFERENCES cities(id) ON DELETE CASCADE, name VARCHAR(150) NOT NULL, UNIQUE(city_id, name));
      CREATE TABLE IF NOT EXISTS professions (id SERIAL PRIMARY KEY, name VARCHAR(150) UNIQUE NOT NULL, category VARCHAR(100), display_order INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS job_offers (
        id SERIAL PRIMARY KEY, company_name VARCHAR(200) NOT NULL, job_title VARCHAR(200) NOT NULL, city VARCHAR(100) NOT NULL, contract_type VARCHAR(50) NOT NULL,
        description TEXT NOT NULL, contact_phone VARCHAR(30), contact_whatsapp VARCHAR(30), contact_email VARCHAR(254), pro_id INTEGER REFERENCES professional_applications(id) ON DELETE CASCADE,
        status VARCHAR(20) NOT NULL DEFAULT 'pending', created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, expires_at TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS withdrawal_requests (
        id SERIAL PRIMARY KEY, pro_id INTEGER NOT NULL REFERENCES professional_applications(id) ON DELETE CASCADE, amount INTEGER NOT NULL, phone_number VARCHAR(30) NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'pending', created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, processed_at TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS contact_messages (
        id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(254) NOT NULL, phone VARCHAR(30), message TEXT NOT NULL,
        pro_id INTEGER, report_id INTEGER, is_read BOOLEAN NOT NULL DEFAULT false, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS blog_posts (id SERIAL PRIMARY KEY, title VARCHAR(200) NOT NULL, slug VARCHAR(250) UNIQUE NOT NULL, content TEXT NOT NULL, published BOOLEAN NOT NULL DEFAULT false, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
    `);

    const migrations = [
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS unavailable_until TIMESTAMP`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS referral_code VARCHAR(10) UNIQUE`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS referred_by VARCHAR(10)`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS referral_balance INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS est_ouvert BOOLEAN NOT NULL DEFAULT true`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS horaires_json TEXT`,
      `ALTER TABLE job_offers ADD COLUMN IF NOT EXISTS pro_id INTEGER REFERENCES professional_applications(id) ON DELETE CASCADE`,
      `ALTER TABLE job_offers ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP`,
      `ALTER TABLE contact_messages ADD COLUMN IF NOT EXISTS pro_id INTEGER`,
      `ALTER TABLE contact_messages ADD COLUMN IF NOT EXISTS report_id INTEGER`,
      `CREATE TABLE IF NOT EXISTS withdrawal_requests (id SERIAL PRIMARY KEY, pro_id INTEGER NOT NULL REFERENCES professional_applications(id) ON DELETE CASCADE, amount INTEGER NOT NULL, phone_number VARCHAR(30) NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'pending', created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, processed_at TIMESTAMP)`
    ];

    const postMigrations = [
      `ALTER TABLE job_offers ADD COLUMN IF NOT EXISTS contact_phone VARCHAR(30)`,
      `ALTER TABLE job_offers ADD COLUMN IF NOT EXISTS contact_whatsapp VARCHAR(30)`,
      `ALTER TABLE job_offers ADD COLUMN IF NOT EXISTS contact_email VARCHAR(254)`,
      `ALTER TABLE job_offers ADD COLUMN IF NOT EXISTS salary VARCHAR(100)`,
      `ALTER TABLE job_offers ADD COLUMN IF NOT EXISTS qualifications TEXT`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS profession_category VARCHAR(100)`,
      `UPDATE professional_applications p SET profession_category = pr.category FROM professions pr WHERE p.profession = pr.name AND p.profession_category IS NULL`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS kyc_verified BOOLEAN NOT NULL DEFAULT false`,
      `UPDATE professional_applications SET kyc_verified = true WHERE status = 'approved'`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS payment_refund_ref VARCHAR(100)`,
      `ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS refunded_at TIMESTAMP`,
      `CREATE TABLE IF NOT EXISTS contact_events (id SERIAL PRIMARY KEY, pro_id INTEGER NOT NULL REFERENCES professional_applications(id) ON DELETE CASCADE, visitor_id VARCHAR(64) NOT NULL, type VARCHAR(10) NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
      `CREATE INDEX IF NOT EXISTS idx_contact_events_pro_visitor ON contact_events(pro_id, visitor_id, created_at DESC)`,
      `DELETE FROM reviews a USING reviews b WHERE a.id > b.id AND a.pro_id = b.pro_id AND a.visitor_id IS NOT NULL AND a.visitor_id = b.visitor_id`,
      `CREATE UNIQUE INDEX IF NOT EXISTS uniq_reviews_pro_visitor ON reviews(pro_id, visitor_id) WHERE visitor_id IS NOT NULL`,
      `CREATE INDEX IF NOT EXISTS idx_withdrawals_status ON withdrawal_requests(status)`,
      `CREATE INDEX IF NOT EXISTS idx_pros_payment_ref ON professional_applications(payment_ref)`,
      `CREATE TABLE IF NOT EXISTS admin_sessions (jti VARCHAR(64) PRIMARY KEY, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, expires_at TIMESTAMP NOT NULL, revoked_at TIMESTAMP)`,
      `CREATE TABLE IF NOT EXISTS review_reports (id SERIAL PRIMARY KEY, review_id INTEGER NOT NULL REFERENCES reviews(id) ON DELETE CASCADE, pro_id INTEGER REFERENCES professional_applications(id) ON DELETE CASCADE, reason TEXT NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'pending', created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, processed_at TIMESTAMP)`,
      `CREATE INDEX IF NOT EXISTS idx_review_reports_status ON review_reports(status)`,
      `CREATE TABLE IF NOT EXISTS notifications (id SERIAL PRIMARY KEY, channel VARCHAR(20) NOT NULL, recipient VARCHAR(254) NOT NULL, subject VARCHAR(200), body TEXT NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'pending', error TEXT, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, sent_at TIMESTAMP)`,
`CREATE TABLE IF NOT EXISTS rate_limits_v2 (limit_key VARCHAR(200) PRIMARY KEY, count INTEGER NOT NULL DEFAULT 0, window_start TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`,  
      `CREATE TABLE IF NOT EXISTS client_codes (code VARCHAR(12) PRIMARY KEY, visitor_id VARCHAR(64) NOT NULL UNIQUE, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
      `ALTER TABLE client_codes ADD COLUMN IF NOT EXISTS full_name VARCHAR(150)`,
      `ALTER TABLE client_codes ADD COLUMN IF NOT EXISTS phone VARCHAR(30)`
    ];
    // await runVersionedMigrations([...migrations, ...postMigrations], "schema", 1);

    // Création manuelle de la table de sécurité
await pool.query(`
  CREATE TABLE IF NOT EXISTS rate_limits_v2 (
    limit_key VARCHAR(200) PRIMARY KEY, 
    count INTEGER NOT NULL DEFAULT 0, 
    window_start TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);
    await pool.query(`ALTER TABLE client_codes ADD COLUMN IF NOT EXISTS full_name VARCHAR(150)`);
await pool.query(`ALTER TABLE client_codes ADD COLUMN IF NOT EXISTS phone VARCHAR(30)`);
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
        await cleanupExpiredDossiers();
        processNotifications(10).catch((error) => console.error("Erreur notifications :", error.message));
      } catch (e) { console.error("Erreur cleanup :", e.message); }
    }, 6 * 60 * 60 * 1000);

    console.log("✅ Toutes les tables sont prêtes et à jour !");
    app.listen(PORT, "0.0.0.0", () => { console.log(`🚀 TrouveMoi démarré sur le port ${PORT}.`); });
  } catch (error) { console.error("❌ Erreur au démarrage :", error); process.exit(1); }
}

process.on("unhandledRejection", (reason) => reportError("unhandledRejection", reason));
process.on("uncaughtException", (error) => {
  reportError("uncaughtException", error);
  setTimeout(() => process.exit(1), 500);
});

startServer();
