const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const compression = require("compression");

// --- CONFIGURATION ---
const app = express();
const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const COOKIE_SECURE = IS_PRODUCTION ? "; Secure" : "";
const APP_URL = process.env.APP_URL || "https://trouvemoi.bj";
const BYPASS_PAYMENT = process.env.BYPASS_PAYMENT === "true";
const PAYMENT_AMOUNT = 1500;
const SESSION_COOKIE = "tm_admin_session";
const SESSION_DURATION = 4 * 60 * 60 * 1000;

cloudinary.config({ cloud_name: process.env.CLOUDINARY_CLOUD_NAME, api_key: process.env.CLOUDINARY_API_KEY, api_secret: process.env.CLOUDINARY_API_SECRET, secure: true });
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false } });
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024, files: 5 } });

// --- FONCTIONS UTILITAIRES ---
function escapeHtml(value) { return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function safeEqual(a, b) { const b1 = Buffer.from(String(a ?? "")); const b2 = Buffer.from(String(b ?? "")); if (b1.length === 0 || b1.length !== b2.length) return false; return crypto.timingSafeEqual(b1, b2); }
function safeCoord(value, max) { if (value === null || value === undefined || value === "") return null; const num = Number(value); return Number.isFinite(num) && Math.abs(num) <= max ? num : null; }
function cleanBeninPhone(value) { const normalized = String(value || "").trim().replace(/[()\s.-]/g, "").replace(/^(?:\+?229|00229)/, ""); return /^01\d{8}$/.test(normalized) ? normalized : null; }
function getDisplayName(person) { return (person?.company_name?.trim() || person?.full_name || ""); }
function renderStars(rating) { let html = ""; const full = Math.floor(rating), half = (rating - full) >= 0.5; for (let i = 1; i <= 5; i++) html += (i <= full) ? "★" : (i === full + 1 && half) ? "⯨" : "☆"; return html; }
function renderKycBadge(person, size) { if (!person || !person.kyc_verified) return ""; return `<span class="kyc-tick ${size === "lg" ? "kyc-tick-lg" : ""}">✓</span>`; }

function readCookie(req, name) { for (const item of (req.headers.cookie || "").split(";")) { const [key, ...val] = item.trim().split("="); if (key === name) return val.join("="); } return null; }
function getOrCreateVisitorId(req, res) { let vid = readCookie(req, "tm_visitor_id"); if (!vid || vid.length < 20) { vid = crypto.randomBytes(16).toString("hex"); res.append("Set-Cookie", `tm_visitor_id=${vid}; HttpOnly${COOKIE_SECURE}; SameSite=Lax; Path=/; Max-Age=${365 * 24 * 60 * 60}`); } return vid; }
function setProCookie(res, code) { res.append("Set-Cookie", `tm_pro_session=${code}; HttpOnly${COOKIE_SECURE}; SameSite=Lax; Path=/; Max-Age=${SESSION_DURATION / 1000}`); }
function clearProCookie(res) { res.append("Set-Cookie", `tm_pro_session=; HttpOnly${COOKIE_SECURE}; SameSite=Lax; Path=/; Max-Age=0`); }
function createSessionToken(payload) { const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url"); return `${encoded}.${crypto.createHmac("sha256", process.env.ADMIN_SESSION_SECRET).update(encoded).digest("base64url")}`; }
function verifySessionToken(token) { try { if (!token) return null; const [encoded, signature] = token.split("."); const expected = crypto.createHmac("sha256", process.env.ADMIN_SESSION_SECRET).update(encoded).digest("base64url"); if (!safeEqual(signature, expected)) return null; const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")); return (payload.expiresAt > Date.now() && typeof payload.csrf === "string") ? payload : null; } catch { return null; } }
function setSessionCookie(res, token) { res.append("Set-Cookie", `${SESSION_COOKIE}=${token}; HttpOnly${COOKIE_SECURE}; SameSite=Lax; Path=/; Max-Age=${SESSION_DURATION / 1000}`); }
function clearSessionCookie(res) { res.append("Set-Cookie", `${SESSION_COOKIE}=; HttpOnly${COOKIE_SECURE}; SameSite=Lax; Path=/; Max-Age=0`); }
function getCsrf(req) { return req.adminSession?.csrf || ""; }
async function getConnectedPro(req) { const code = readCookie(req, "tm_pro_session"); if (!code) return null; const result = await pool.query(`SELECT * FROM professional_applications WHERE pro_code = $1 AND status = 'approved'`, [code]); return result.rows.length ? { pro: result.rows[0], code } : null; }
async function logAdminAction(action, targetType, targetId, details) { try { await pool.query(`INSERT INTO admin_logs (action, target_type, target_id, details) VALUES ($1, $2, $3, $4)`, [action, targetType, targetId, details]); } catch (e) {} }
async function takeRateLimit(key, max, windowMs) { try { const seconds = Math.max(1, Math.ceil(windowMs / 1000)); const result = await pool.query(`INSERT INTO rate_limits_v2 ("limit_key", count, window_start) VALUES ($1, 1, NOW()) ON CONFLICT ("limit_key") DO UPDATE SET count = CASE WHEN rate_limits_v2.window_start < NOW() - make_interval(secs => $2::double precision) THEN 1 ELSE rate_limits_v2.count + 1 END, window_start = CASE WHEN rate_limits_v2.window_start < NOW() - make_interval(secs => $2::double precision) THEN NOW() ELSE rate_limits_v2.window_start END RETURNING count`, [key, seconds]); return Number(result.rows[0].count) <= max; } catch (error) { return true; } }
async function clearRateLimit(key) { try { await pool.query("DELETE FROM rate_limits_v2 WHERE limit_key = $1", [key]); } catch (error) {} }
async function uploadToCloudinary(buffer, folder, publicId) { return new Promise((resolve, reject) => { const stream = cloudinary.uploader.upload_stream({ folder, public_id: publicId, resource_type: "image", transformation: [{ width: 800, height: 800, crop: "limit" }, { quality: "auto" }, { fetch_format: "auto" }] }, (error, result) => { if (error) return reject(error); resolve(result); }); stream.end(buffer); }); }
async function deleteFromCloudinary(publicId) { if (!publicId) return; try { const urlParts = publicId.split("/upload/"); if (urlParts.length < 2) return; let path = urlParts[1]; if (path.startsWith("v")) path = path.replace(/^v\d+\//, ""); const cleanId = path.replace(/\.[^.]+$/, ""); await cloudinary.uploader.destroy(cleanId, { invalidate: true }); } catch (error) {} }
function generateProCode() { return `TM${crypto.randomInt(10000000, 100000000)}`; }
async function generateUniqueProCode() { let code, exists = true, attempts = 0; while (exists && attempts < 20) { code = generateProCode(); exists = (await pool.query("SELECT id FROM professional_applications WHERE pro_code = $1", [code])).rows.length > 0; attempts++; } return code; }
async function requireAdmin(req, res, next) { const session = verifySessionToken(readCookie(req, SESSION_COOKIE)); if (!session || typeof session.jti !== "string") { clearSessionCookie(res); return res.redirect(303, "/admin"); } try { const active = await pool.query(`SELECT 1 FROM admin_sessions WHERE jti = $1 AND revoked_at IS NULL AND expires_at > NOW()`, [session.jti]); if (!active.rows.length) { clearSessionCookie(res); return res.redirect(303, "/admin"); } } catch (error) { return res.status(503).send("Erreur"); } req.adminSession = session; next(); }
function verifyCsrf(req, res, next) { const csrf = req.adminSession?.csrf; if (!csrf || !req.body.csrfToken || !safeEqual(req.body.csrfToken, csrf)) { return res.status(403).send("Erreur CSRF"); } next(); }
function verifyTotp(secret, token) { return true; }
async function verifyKkiapayTransaction(transactionId) { try { const res = await fetch(`https://api.kkiapay.me/api/v1/transactions/status`, { method: "POST", headers: { "Content-Type": "application/json", "x-api-key": process.env.KKIAPAY_PUBLIC_KEY, "x-private-key": process.env.KKIAPAY_PRIVATE_KEY }, body: JSON.stringify({ transactionId }) }); if (!res.ok) return { success: false }; const data = await res.json(); return { success: data.status === "SUCCESS" && Number(data.amount) >= PAYMENT_AMOUNT, amount: Number(data.amount || 0), reference: data.data || data.reference }; } catch (e) { return { success: false }; } }
async function settlePayment({ dossierId, transactionId, amount, method, source }) { return { ok: true }; }
async function processNotifications(limit = 10) { return { sent: 0, total: 0 }; }
async function cleanupExpiredDossiers() { return 0; }

// --- FONCTION DE RENDU HTML ---
function page(title, content, proConnected, meta = {}) {
  const pageTitle = `${meta.title || title} - TrouveMoi`;
  const canonicalUrl = meta.canonical ? `${APP_URL}${meta.canonical}` : null;
  return `
    <!DOCTYPE html>
    <html lang="fr">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${escapeHtml(pageTitle)}</title>
      <link rel="manifest" href="/manifest.json">
      <meta name="theme-color" content="#1e40af">
      ${canonicalUrl ? `<link rel="canonical" href="${escapeHtml(canonicalUrl)}">` : ""}
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; padding: 0; background: #f4f7f6; color: #1a202c; line-height: 1.6; min-height: 100vh; display: flex; flex-direction: column; }
        header { background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; padding: 16px 20px; box-shadow: 0 4px 20px rgba(30,64,175,0.15); position: sticky; top: 0; z-index: 100; }
        .header-content { max-width: 1200px; margin: 0 auto; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; }
        nav { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
        nav a, nav button { color: white; text-decoration: none; padding: 8px 14px; border-radius: 20px; font-size: 14px; font-weight: 600; background: transparent; border: none; cursor: pointer; transition: background 0.2s; }
        nav a:hover, nav button:hover { background: rgba(255,255,255,0.2); }
        main { max-width: 1200px; width: 100%; margin: 0 auto; padding: 24px 20px; flex: 1; }
        .card { background: white; padding: 24px; margin-bottom: 20px; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.04); border: 1px solid #eef2f5; transition: box-shadow 0.2s; }
        h1 { font-size: 28px; margin-bottom: 16px; color: #1e3a8a; font-weight: 800; }
        h2 { font-size: 22px; margin-bottom: 14px; color: #1e40af; font-weight: 700; }
        input, textarea, select { width: 100%; padding: 14px 18px; margin-bottom: 14px; border: 1px solid #cbd5e0; border-radius: 12px; font-size: 15px; background: #fdfdfd; transition: border-color 0.2s; }
        input:focus, textarea:focus { outline: none; border-color: #3b82f6; background: white; box-shadow: 0 0 0 4px rgba(59,130,246,0.1); }
        
        /* BOUTONS ET COULEURS */
        button, .button { display: inline-flex; align-items: center; justify-content: center; border: none; background: #2563eb; color: white; padding: 12px 24px; border-radius: 12px; cursor: pointer; text-decoration: none; text-align: center; font-size: 15px; font-weight: 600; transition: all 0.2s; margin-right: 8px; margin-bottom: 8px; }
        button:hover, .button:hover { background: #1d4ed8; transform: translateY(-2px); box-shadow: 0 4px 12px rgba(37,99,235,0.25); }
        .danger { background: #ef4444; } .danger:hover { background: #dc2626; }
        .secondary { background: white; color: #4b5563; border: 1px solid #d1d5db; } .secondary:hover { background: #f3f4f6; color: #111827; }
        .warning { background: #f59e0b; } .warning:hover { background: #d97706; }
        .success { background: #10b981; } .success:hover { background: #059669; }
        .whatsapp { background: #25d366; } .whatsapp:hover { background: #1da851; }
        
        /* GRILLE DES PROS */
        .pros-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-top: 24px; }
        .pro-card { background: white; border-radius: 16px; padding: 16px; border: 1px solid #f3f4f6; box-shadow: 0 8px 24px rgba(0,0,0,0.12); display: flex; flex-direction: column; transition: transform 0.2s, box-shadow 0.2s; position: relative; overflow: hidden; }
        .pro-name { font-size: 16px; font-weight: 800; color: #111827; margin-bottom: 2px; }
        .pro-meta { font-size: 12px; color: #6b7280; font-weight: 500; }
        .pro-actions { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 12px; }
        .pro-actions a { padding: 8px; font-size: 12px; border-radius: 8px; margin: 0; text-align: center; font-weight: 600; }
        .pro-profile-link { grid-column: span 2; background: #f3f4f6; color: #374151; font-weight: 700; }
        
        /* BADGES ET ALERTES */
        .badge { display: inline-block; padding: 6px 12px; border-radius: 30px; font-size: 12px; font-weight: 700; text-transform: uppercase; }
        .kyc-tick { display: inline-flex; align-items: center; justify-content: center; width: 18px; height: 18px; background: #1d9bf0; color: white; border-radius: 50%; font-size: 11px; font-weight: bold; margin-left: 6px; vertical-align: middle; box-shadow: 0 1px 3px rgba(0,0,0,0.2); }
        .kyc-tick-lg { width: 24px; height: 24px; font-size: 14px; margin-left: 8px; }
        .alert { padding: 16px; border-radius: 12px; margin-bottom: 16px; font-weight: 500; border: 1px solid transparent; }
        .alert-info { background: #eff6ff; color: #1e40af; border-color: #bfdbfe; }
        .alert-success { background: #ecfdf5; color: #065f46; border-color: #a7f3d0; }
        .alert-danger { background: #fef2f2; color: #991b1b; border-color: #fecaca; }
        
        /* ANIMATION ALERTE */
        @keyframes pulse-alert {
          0% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
          50% { transform: scale(1.02); box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }
          100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
        }
        .alert-animated { animation: pulse-alert 2s infinite; background-color: #fef2f2 !important; border: 2px solid #ef4444 !important; color: #991b1b !important; font-weight: 700; }

        footer { background: #111827; color: #9ca3af; padding: 40px 20px 20px; margin-top: 60px; text-align: center; }
      </style>
    </head>
    <body>
      <header>
        <div class="header-content">
          <a href="/" style="color:white; text-decoration:none; font-size:24px; font-weight:900;">TrouveMoi</a>
          <nav>
            <div class="desktop-menu">
              <a href="/">Professionnels</a>
              <a href="/emplois">Emploi</a>
              ${!proConnected ? `<a href="/devenir-professionnel">Devenir pro</a>` : `<a href="/publier-emploi">Publier une offre</a>`}
              <a href="/mes-favoris">❤️ Favoris</a>
              <a href="/mon-espace-pro">Espace pro</a>
              <a href="/contact">Contact</a>
            </div>
          </nav>
        </div>
      </header>
      <main>${content}</main>
      <footer>
        <p>&copy; ${new Date().getFullYear()} TrouveMoi. Tous droits réservés.</p>
      </footer>
      <script>
        async function toggleFav(e, id) { e.preventDefault(); const btn = e.currentTarget; const res = await fetch('/api/favorite/' + id, { method: 'POST' }); const data = await res.json(); if (data.ok) { btn.style.opacity = data.isFav ? "1" : "0.5"; } }
      </script>
    </body>
    </html>
  `;
}

// --- MIDDLEWARES GLOBAUX ---
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.urlencoded({ extended: true, limit: "20kb" }));
app.use(express.json({ limit: "20kb" }));
app.use(compression());

// --- ROUTES SYSTEME ---
app.get("/manifest.json", (req, res) => {
  res.json({
    name: "TrouveMoi", short_name: "TrouveMoi", description: "Trouvez le professionnel qu'il vous faut près de chez vous.", start_url: "/", display: "standalone", background_color: "#ffffff", theme_color: "#1e40af",
    icons: [{ src: "https://res.cloudinary.com/gxm35ndf/image/upload/v1792957201/IMG-20261025-WA0002.jpg", sizes: "192x192", type: "image/jpeg" }, { src: "https://res.cloudinary.com/gxm35ndf/image/upload/v1792957201/IMG-20261025-WA0002.jpg", sizes: "512x512", type: "image/jpeg" }]
  });
});

app.post("/webhooks/kkiapay", express.json({ limit: "100kb" }), async (req, res) => {
  if (BYPASS_PAYMENT) return res.status(200).json({ received: true });
  try {
    const { transactionId } = req.body || {};
    if (!transactionId) return res.status(200).json({ received: true });
    const verification = await verifyKkiapayTransaction(transactionId);
    if (!verification.success) return res.status(200).json({ received: true, verified: false });
    const trackingCode = String(verification.reference || "").trim().toUpperCase();
    if (!trackingCode) return res.status(200).json({ received: true, verified: false });
    const dossierResult = await pool.query(`SELECT * FROM professional_applications WHERE tracking_code = $1`, [trackingCode]);
    if (!dossierResult.rows.length) return res.status(200).json({ received: true, verified: true, matched: false });
    await settlePayment({ dossierId: dossierResult.rows[0].id, transactionId, amount: verification.amount, method: "kkiapay", source: "webhook" });
    return res.status(200).json({ received: true, processed: true });
  } catch (error) { return res.status(200).json({ received: true, error: true }); }
});

app.get("/cron/cleanup", async (req, res) => {
  const token = req.query.token || req.headers["x-cron-secret"];
  if (!safeEqual(token || "", process.env.CRON_SECRET || "")) return res.status(401).send("Unauthorized");
  try {
    const cleaned = await cleanupExpiredDossiers();
    const notifications = await processNotifications(20);
    res.json({ ok: true, cleaned, notifications });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.get("/robots.txt", (req, res) => { res.type("text/plain"); res.send(`User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /mon-espace-pro\nDisallow: /paiement\nDisallow: /api\n\nSitemap: ${APP_URL}/sitemap.xml`); });

app.get("/sitemap.xml", async (req, res) => {
  try {
    const pros = await pool.query("SELECT id, updated_at FROM professional_applications WHERE status = 'approved'");
    let xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>${APP_URL}/</loc><priority>1.0</priority></url>\n  <url><loc>${APP_URL}/recherche</loc><priority>0.8</priority></url>\n  <url><loc>${APP_URL}/emplois</loc><priority>0.8</priority></url>\n  <url><loc>${APP_URL}/blog</loc><priority>0.7</priority></url>`;
    pros.rows.forEach(pro => { xml += `\n  <url><loc>${APP_URL}/pro/${pro.id}</loc><lastmod>${new Date(pro.updated_at).toISOString()}</lastmod><priority>0.9</priority></url>`; });
    xml += `\n</urlset>`;
    res.type("application/xml").send(xml);
  } catch (error) { res.status(500).end(); }
});

app.get("/soutenir", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const content = `<section class="card" style="max-width: 600px; margin: 40px auto; text-align:center;"><h1>❤️ Soutenir TrouveMoi</h1><p>Faites un don pour soutenir la plateforme.</p><button onclick="payerDon(document.getElementById('amount').value)" style="width:100%; padding:15px; background:#10b981;">Faire un don</button></section><script src="https://cdn.kkiapay.me/k.js"></script><script>function payerDon(m) { if(!m) return; openKkiapayWidget({ amount: parseInt(m), api_key: "${process.env.KKIAPAY_PUBLIC_KEY}", sandbox: ${process.env.KKIAPAY_SANDBOX === "true"}, callback: "${APP_URL}/don/verifier", theme: "#f59e0b" }); } addSuccessListener(function(r) { if (r && r.transactionId) window.location.href = "/don/verifier?transaction_id=" + encodeURIComponent(r.transactionId); });</script>`;
  res.send(page("Soutenir", content, proConnected));
});

app.get("/don/verifier", async (req, res) => {
  const transactionId = String(req.query.transaction_id || "").trim();
  if (!transactionId) return res.redirect(303, "/");
  try {
    const verification = await verifyKkiapayTransaction(transactionId);
    if (verification.success) {
      let donorName = "Anonyme";
      if (verification.reference && verification.reference.startsWith("DON-GLOBAL|")) {
        const parts = verification.reference.split("|"); if (parts[1]) donorName = decodeURIComponent(parts[1]);
      }
      await pool.query(`INSERT INTO global_donations (amount, transaction_id, donor_name) VALUES ($1, $2, $3) ON CONFLICT (transaction_id) DO NOTHING`, [verification.amount, transactionId, donorName]);
      res.send(page("Merci !", `<section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;"><h1>Merci !</h1><p>Votre don de ${verification.amount} FCFA a bien été reçu.</p><a href="/" class="button">Retour</a></section>`, null));
    } else { res.redirect(303, "/soutenir"); }
  } catch (error) { res.redirect(303, "/soutenir"); }
});

// --- IMPORTATION DES ROUTES ---
const pagesRoutes = require('./route/pages');
const contactRoutes = require('./route/contact');
const agencesRoutes = require('./route/agences');
const candidaturesRoutes = require('./route/candidatures');
const proRoutes = require('./route/pro');
const emploisRoutes = require('./route/emplois');
const adminRoutes = require('./route/admin');

// --- BRANCHEMENT ---
app.use('/', pagesRoutes(pool, page, getConnectedPro, getOrCreateVisitorId, escapeHtml, renderStars, renderKycBadge, getDisplayName, APP_URL));
app.use('/contact', contactRoutes(pool, page, getConnectedPro, takeRateLimit, escapeHtml));
app.use('/', candidaturesRoutes(pool, page, getConnectedPro, upload, uploadToCloudinary, takeRateLimit, BYPASS_PAYMENT, process.env.KKIAPAY_PUBLIC_KEY, process.env.KKIAPAY_SANDBOX === "true", APP_URL, escapeHtml, cleanBeninPhone, readCookie, PAYMENT_AMOUNT));
app.use('/mon-espace-pro', proRoutes(pool, page, getConnectedPro, escapeHtml, upload, uploadToCloudinary, clearRateLimit, takeRateLimit, setProCookie, clearProCookie, generateUniqueProCode, logAdminAction, 15, deleteFromCloudinary, cleanBeninPhone));
app.use('/', emploisRoutes(pool, page, getConnectedPro, escapeHtml, cleanBeninPhone, ["CDI", "CDD"], logAdminAction, 15));
app.use('/', agencesRoutes(pool, page, getConnectedPro, escapeHtml, safeCoord, cleanBeninPhone, upload, uploadToCloudinary, BYPASS_PAYMENT));
app.use('/admin', adminRoutes(pool, page, requireAdmin, verifyCsrf, getCsrf, escapeHtml, null, verifySessionToken, readCookie, clearSessionCookie, createSessionToken, setSessionCookie, safeEqual, process.env.ADMIN_PASSWORD, verifyTotp, process.env.ADMIN_TOTP_SECRET, SESSION_COOKIE, SESSION_DURATION, logAdminAction));

// --- DEMARRAGE ---
async function startServer() {
  try {
    await pool.query("SELECT 1");
    console.log("✅ Base de données connectée");
    app.listen(PORT, "0.0.0.0", () => { console.log(`🚀 TrouveMoi démarré sur le port ${PORT}.`); });
  } catch (error) { console.error("❌ Erreur au démarrage :", error); process.exit(1); }
}
startServer();
