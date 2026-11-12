const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const compression = require("compression");
const fetch = require("node-fetch");
const admin = require("firebase-admin");
const rateLimit = require("express-rate-limit");

// --- CONFIGURATION ---
const app = express(); 
const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const COOKIE_SECURE = IS_PRODUCTION ? "; Secure" : "";
const APP_URL = process.env.APP_URL || "https://trouvemoi.bj";
const BYPASS_PAYMENT = process.env.BYPASS_PAYMENT === "true";
const REFERRAL_BONUS = 100;
const QUARTIERS_BENIN = {
  "Cotonou": ["Akpakpa", "Cadjehoun", "Fidjrossè", "Ganhi", "Gbégamey", "Sainte-Rita", "Sikècodji", "Zogbo", "Agla", "Aïbatin", "Dantokpa", "Houéyiho", "Ladji", "Vèdoko"],
  "Porto-Novo": ["Djègan-Kpèvi", "Ouando", "Tokpa", "Zongo", "Attakè", "Avrankou"],
  "Parakou": ["Zongo", "Titirou", "Ganhi", "Ladji", "Tourou"],
  "Abomey-Calavi": ["Calavi Centre", "Godomey", "Zogbadjè", "Akassato", "Togba", "Hèvié"],
  "Bohicon": ["Bohicon Centre", "Saclo", "Passagon", "Sodohomè"],
  "Natitingou": ["Natitingou Centre", "Kouandé", "Toucountouna"],
  "Ouidah": ["Ouidah Centre", "Djègbadji", "Pahou", "Sèmè"],
  "Lokossa": ["Lokossa Centre", "Houin", "Ouèssè"],
  "Kandi": ["Kandi Centre", "Angaradébou", "Sonsoro"],
  "Malanville": ["Malanville Centre", "Garou", "Toumboutou"]
};
const VILLES_BENIN = [
  "Abomey", "Abomey-Calavi", "Adjohoun", "Adja-Ouèrè", "Agbangnizoun", "Athiémé", "Avrankou",
  "Banikoara", "Bantè", "Bassila", "Bembèrèkè", "Bohicon", "Bonou", "Boukoumbé",
  "Comè", "Copargo", "Cotonou",
  "Dangbo", "Dassa-Zoumè", "Djakotomey", "Djidja", "Dogbo", "Dassa-Zoumé",
  "Glazoué", "Gogounou", "Grand-Popo", "Guilmaro",
  "Ifangni", "Igolo",
  "Kalalé", "Kandi", "Karimama", "Kérou", "Kétou", "Klouékanmè", "Kouandé",
  "Lalo", "Lokossa",
  "Malanville", "Matéri",
  "Natitingou", "N'Dali", "Nikki",
  "Ouaké", "Ouidah", "Ouinhi",
  "Parakou", "Pèrèrè", "Pobè", "Porto-Novo",
  "Sakété", "Savalou", "Savè", "Sèmè-Podji", "Sinendé", "Ségbana", "So-Ava",
  "Tanguiéta", "Tchaourou", "Toffo", "Tori-Bossito", "Toucountouna",
  "Zagnanado", "Za-Kpota", "Zè", "Zogbodomey"
];
const METIERS_LOCAL_FIXE = [
  "Restaurant", "Boutique", "Supérette", "Supermarché", "Alimentation générale", "Épicerie", "Pharmacie", "Parapharmacie", "Boulangerie", "Pâtisserie", "Boucherie", "Poissonnerie", "Vente de fruits et légumes", "Vente de produits surgelés", "Dépôt de boissons", "Dépôt de gaz domestique", "Quincaillerie", "Agence immobilière", "Boutique de vente téléphones et accessoires", "Boutique Apple Store", "Distributeur agréé Canal+", "Boutique de vente de mèches", "Compagnie d'assurance", "Compagnie de transport", "Boutique de vente appareils électroménager", "Boutique de vêtements", "Boutique de chaussures", "Boutique de sacs et accessoires de mode", "Boutique de tissus et pagnes", "Boutique de cosmétiques", "Boutique de parfumerie", "Boutique de jouets", "Boutique de vente de produits chinois", "Librairie", "Papeterie", "Bijouterie", "Cave à vin", "Magasin de meubles", "Magasin de décoration intérieure", "Magasin de matériaux de construction", "Magasin de peinture", "Magasin de fournitures scolaires", "Magasin de pièces électroniques", "Magasin de matériel informatique", "Barber shop", "Lavage moto",
  "Fast-food", "Maquis", "Cafétéria", "Glacier", "Pizzeria", "Restaurant africain", "Restaurant gastronomique", "Bar", "Discothèque", "Hôtel", "Auberge", "Résidence meublée", "Maison d'hôtes", "Camping", "Espace événementiel", "Salle de réception", "Salle de jeux", "Salle de sport", "Salle de fitness", "Piscine", "Centre de loisirs",
  "Clinique", "Hôpital", "Cabinet médical", "Cabinet dentaire", "Cabinet ophtalmologique", "Laboratoire d'analyses médicales", "Centre de radiologie", "Centre de soins", "Centre de kinésithérapie", "Centre de vaccination", "Cabinet vétérinaire", "Opticien", "Centre de bien-être", "Institut de massage", "Centre dermatologique",
  "École maternelle", "École primaire", "Collège", "Lycée", "Université", "Établissement d'enseignement supérieur", "Centre de formation professionnelle", "Centre de formation informatique", "Auto-école", "Crèche", "Garderie", "Centre de soutien scolaire", "Centre de langues", "Bibliothèque",
  "Garage", "Garage automobile", "Garage moto", "Station-service", "Centre de lavage automobile", "Vente de véhicules", "Location de véhicules", "Agence de location de motos", "Vente de pneus", "Vente de batteries automobiles", "Vente de lubrifiants", "Centre de vidange", "Centre de diagnostic automobile", "Carrosserie automobile", "Auto-électricité", "Vulcanisateur", "Boutique de vente de pièces détachées de moto", "Boutique de vente de pièces détachées automobiles", "Agence de transport interurbain", "Agence de voyage", "Gare routière", "Compagnie de livraison", "Entreprise de déménagement", "Agence de fret et transit",
  "Cabinet comptable", "Cabinet juridique", "Cabinet d'avocats", "Cabinet de conseil", "Agence de communication", "Agence de publicité", "Agence de marketing digital", "Agence web", "Agence de graphisme", "Agence de création audiovisuelle", "Cabinet d'architecture", "Cabinet de géomètre", "Agence de sécurité privée", "Agence de nettoyage", "Entreprise de gardiennage", "Agence de recrutement", "Cabinet de ressources humaines", "Cabinet d'expertise immobilière", "Agence de décoration événementielle", "Pompes funèbres",
  "Banque", "Institution de microfinance", "Agence de transfert d'argent", "Agence Mobile Money", "Agence de change", "Agence d'assurance", "Agence de paiement électronique", "Agence de télécommunications", "Boutique de vente de cartes SIM", "Centre de services téléphoniques", "Agence de services financiers",
  "Atelier de couture", "Atelier de broderie", "Atelier de menuiserie", "Atelier de soudure", "Atelier de mécanique", "Atelier de réparation de téléphones", "Atelier de réparation informatique", "Atelier de réparation électroménager", "Atelier de réparation électronique", "Atelier de réparation de réfrigérateurs", "Entreprise de plomberie", "Entreprise d'électricité", "Entreprise de construction", "Entreprise de BTP", "Entreprise de carrelage", "Entreprise de peinture bâtiment", "Entreprise de vitrerie", "Entreprise de climatisation", "Entreprise de forage", "Entreprise de forage et installation de pompes", "Entreprise de décoration intérieure", "Entreprise de menuiserie aluminium", "Entreprise de menuiserie bois", "Atelier de fabrication métallique", "Entreprise de paysagisme",
  "Salon de beauté", "Salon de coiffure", "Salon de coiffure mixte", "Institut de beauté", "Salon de manucure", "Salon de pédicure", "Centre de soins capillaires", "Salon de tresses", "Atelier de confection", "Pressing", "Blanchisserie", "Teinturerie", "Photographe professionnel", "Studio photo", "Studio d'enregistrement", "Imprimerie", "Centre de photocopie", "Cybercafé",
  "Service de secrétariat", "Service de traduction", "Service de rédaction", "Service informatique", "Service de dépannage", "Service de livraison à domicile", "Service de jardinage", "Service de décoration", "Service traiteur", "Service de location de matériel", "Service événementiel", "Service de maintenance", "Service de réparation", "Service de nettoyage à domicile", "Autres activités"
];
const METIERS_SENSIBLES = [
  "Médecin", "Pharmacien", "Dentiste", "Infirmier", "Sage-femme", "Kinésithérapeute", "Technicien de laboratoire",
  "Avocat", "Notaire",
  "Architecte", "Géomètre topographe",
  "Agent de sécurité"
];
const PAYMENT_AMOUNT = 1500;
const SESSION_COOKIE = "tm_admin_session";
const SESSION_DURATION = 4 * 60 * 60 * 1000;

cloudinary.config({ cloud_name: process.env.CLOUDINARY_CLOUD_NAME, api_key: process.env.CLOUDINARY_API_KEY, api_secret: process.env.CLOUDINARY_API_SECRET, secure: true });
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false } });
const upload = multer({ 
  storage: multer.memoryStorage(), 
  limits: { fileSize: 10 * 1024 * 1024, files: 5 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Format de fichier non supporté. Seules les images sont autorisées."));
    }
  }
});

// --- FONCTIONS UTILITAIRES ---
function escapeHtml(value) { return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function safeEqual(a, b) { const b1 = Buffer.from(String(a ?? "")); const b2 = Buffer.from(String(b ?? "")); if (b1.length === 0 || b1.length !== b2.length) return false; return crypto.timingSafeEqual(b1, b2); }
function safeCoord(value, max) { if (value === null || value === undefined || value === "") return null; const num = Number(value); return Number.isFinite(num) && Math.abs(num) <= max ? num : null; }
function cleanBeninPhone(value) { const normalized = String(value || "").trim().replace(/[()\s.-]/g, "").replace(/^(?:\+?229|00229)/, ""); return /^01\d{8}$/.test(normalized) ? normalized : null; }

// --- FONCTION D'ENVOI DE SMS (eSMS Africa) ---
async function sendSMS(telephone, message) {
  if (!process.env.SMSPRO_API_KEY) return { error: "Pas de clé API" };
  try {
    const cleanPhone = String(telephone).replace(/\D/g, "").replace(/^(?:00229|229)/, "");
    const finalPhone = "+229" + cleanPhone;

    const response = await fetch("https://sms.esmsafrica.io/api/v1/messages", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${process.env.SMSPRO_API_KEY}`,
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({
        sender: "TrouveMoi",
        recipient: finalPhone,
        message: message
      })
    });
    
    const data = await response.json();
    console.log("📱 Résultat envoi SMS eSMS :", data);
    return data;
  } catch (error) {
    console.error("❌ Erreur d'envoi de SMS eSMS :", error.message);
    return { error: true };
  }
}

// --- FONCTION D'ENVOI DE NOTIFICATIONS PUSH ---
async function sendPushNotification(title, body) {
  if (!process.env.FIREBASE_PROJECT_ID) return;
  try {
    const result = await pool.query("SELECT token FROM push_tokens");
    const tokens = result.rows.map(r => r.token);
    if (tokens.length === 0) return;

    const message = {
      notification: { title: title, body: body },
      tokens: tokens
    };

    const response = await admin.messaging().sendEachForMulticast(message);
    console.log(`📡 Push envoyées : ${response.successCount} succès, ${response.failureCount} échecs`);
  } catch (error) {
    console.error("❌ Erreur envoi push:", error);
  }
}

function getDisplayName(person) { return (person?.company_name?.trim() || person?.full_name || ""); }
function renderStars(rating) { let html = ""; const full = Math.floor(rating), half = (rating - full) >= 0.5; for (let i = 1; i <= 5; i++) html += (i <= full) ? "★" : (i === full + 1 && half) ? "⯨" : "☆"; return html; }
function renderKycBadge(person, size) { if (!person || !person.kyc_verified) return ""; return `<span class="kyc-tick ${size === "lg" ? "kyc-tick-lg" : ""}">✓</span>`; }
function readCookie(req, name) { for (const item of (req.headers.cookie || "").split(";")) { const [key, ...val] = item.trim().split("="); if (key === name) return val.join("="); } return null; }
function getOrCreateVisitorId(req, res) { let vid = readCookie(req, "tm_visitor_id"); if (!vid || vid.length < 20) { vid = crypto.randomBytes(16).toString("hex"); res.append("Set-Cookie", `tm_visitor_id=${vid}; HttpOnly${COOKIE_SECURE}; SameSite=Lax; Path=/; Max-Age=${365 * 24 * 60 * 60}`); } return vid; }
function setProCookie(res, code) { 
  res.append("Set-Cookie", `tm_pro_session=${code}; HttpOnly${COOKIE_SECURE}; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 60 * 60}`); 
}
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
async function uploadToCloudinary(buffer, folder, publicId) { 
  return new Promise((resolve, reject) => { 
    const stream = cloudinary.uploader.upload_stream({ 
      folder, 
      public_id: publicId, 
      resource_type: "image",
      incoming_transformation: [
        { width: 1000, height: 1000, crop: "limit" }, 
        { quality: "auto:good" }, 
        { fetch_format: "auto" }
      ],
      transformation: [
        { width: 800, height: 800, crop: "limit" }, 
        { quality: "auto" }, 
        { fetch_format: "auto" }
      ]
    }, (error, result) => { 
      if (error) return reject(error); 
      resolve(result); 
    }); 
    stream.end(buffer); 
  }); 
}
async function deleteFromCloudinary(publicId) { if (!publicId) return; try { const urlParts = publicId.split("/upload/"); if (urlParts.length < 2) return; let path = urlParts[1]; if (path.startsWith("v")) path = path.replace(/^v\d+\//, ""); const cleanId = path.replace(/\.[^.]+$/, ""); await cloudinary.uploader.destroy(cleanId, { invalidate: true }); } catch (error) {} }
function generateProCode() { return `TM${crypto.randomInt(10000000, 100000000)}`; }
async function generateUniqueProCode() { let code, exists = true, attempts = 0; while (exists && attempts < 20) { code = generateProCode(); exists = (await pool.query("SELECT id FROM professional_applications WHERE pro_code = $1", [code])).rows.length > 0; attempts++; } return code; }
async function requireAdmin(req, res, next) { const session = verifySessionToken(readCookie(req, SESSION_COOKIE)); if (!session || typeof session.jti !== "string") { clearSessionCookie(res); return res.redirect(303, "/admin"); } try { const active = await pool.query(`SELECT 1 FROM admin_sessions WHERE jti = $1 AND revoked_at IS NULL AND expires_at > NOW()`, [session.jti]); if (!active.rows.length) { clearSessionCookie(res); return res.redirect(303, "/admin"); } } catch (error) { return res.status(503).send("Erreur"); } req.adminSession = session; next(); }
function verifyCsrf(req, res, next) { const csrf = req.adminSession?.csrf; if (!csrf || !req.body.csrfToken || !safeEqual(req.body.csrfToken, csrf)) { return res.status(403).send("Erreur CSRF"); } next(); }

function verifyTotp(secret, token) {
  if (!secret || !token) return false;
  try {
    const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    const cleanSecret = secret.toUpperCase().replace(/=+$/, "");
    for (let i = 0; i < cleanSecret.length; i++) {
      const val = base32chars.indexOf(cleanSecret.charAt(i));
      if (val === -1) throw new Error("Secret invalide");
      bits += val.toString(2).padStart(5, "0");
    }
    const secretBuffer = Buffer.alloc(Math.floor(bits.length / 8));
    for (let i = 0; i < secretBuffer.length; i++) {
      secretBuffer[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
    }
    const epoch = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epoch / 30);
    const buffer = Buffer.alloc(8);
    buffer.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
    buffer.writeUInt32BE(counter % 0x100000000, 4);
    const hmac = crypto.createHmac("sha1", secretBuffer);
    hmac.update(buffer);
    const hmacResult = hmac.digest();
    const offset = hmacResult[hmacResult.length - 1] & 0xf;
    const code = (
      ((hmacResult[offset] & 0x7f) << 24) |
      ((hmacResult[offset + 1] & 0xff) << 16) |
      ((hmacResult[offset + 2] & 0xff) << 8) |
      (hmacResult[offset + 3] & 0xff)
    ) % 1000000;
    const validCode = code.toString().padStart(6, "0");
    return safeEqual(validCode, token);
  } catch (e) {
    return false;
  }
}

async function verifyKkiapayTransaction(transactionId) { try { const res = await fetch(`https://api.kkiapay.me/api/v1/transactions/status`, { method: "POST", headers: { "Content-Type": "application/json", "x-api-key": process.env.KKIAPAY_PUBLIC_KEY, "x-private-key": process.env.KKIAPAY_PRIVATE_KEY }, body: JSON.stringify({ transactionId }) }); if (!res.ok) return { success: false }; const data = await res.json(); return { success: data.status === "SUCCESS" && Number(data.amount) >= PAYMENT_AMOUNT, amount: Number(data.amount || 0), reference: data.data || data.reference }; } catch (e) { return { success: false }; } }

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
    return { ok: true, alreadyPaid: false };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error; 
  } finally {
    client.release();
  }
}
async function processNotifications(limit = 10) { return { sent: 0, total: 0 }; }
async function cleanupExpiredDossiers() { return 0; }

// --- FONCTION DE RENDU HTML (DESIGN PREMIUM & DOUX) ---
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
      <meta name="theme-color" content="#1e40af">
      ${canonicalUrl ? `<link rel="canonical" href="${escapeHtml(canonicalUrl)}">` : ""}
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; 
          padding: 0; background: #f8fafc; color: #1e293b; line-height: 1.6; 
          min-height: 100vh; display: flex; flex-direction: column; 
        }
        header { background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; padding: 16px 20px; box-shadow: 0 4px 20px rgba(30,64,175,0.15); position: sticky; top: 0; z-index: 100; }
        .header-content { max-width: 1200px; margin: 0 auto; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; }
        nav { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
        nav a, nav button { color: white; text-decoration: none; padding: 8px 14px; border-radius: 20px; font-size: 14px; font-weight: 600; background: transparent; border: none; cursor: pointer; transition: background 0.2s; }
        nav a:hover, nav button:hover { background: rgba(255,255,255,0.2); }
        main { max-width: 1200px; width: 100%; margin: 0 auto; padding: 24px 20px; flex: 1; }
        .card { background: white; padding: 28px; margin-bottom: 24px; border-radius: 20px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05), 0 8px 10px -6px rgba(0, 0, 0, 0.01); border: 1px solid #f1f5f9; transition: transform 0.3s ease, box-shadow 0.3s ease; }
        .card:hover { transform: translateY(-4px); box-shadow: 0 20px 30px -5px rgba(0, 0, 0, 0.1); }
        h1 { font-size: 32px; margin-bottom: 20px; color: #0f172a; font-weight: 800; letter-spacing: -0.5px; }
        h2 { font-size: 24px; margin-bottom: 16px; color: #1e40af; font-weight: 700; }
        input, textarea, select { width: 100%; padding: 16px 20px; margin-bottom: 16px; border: 1px solid #e2e8f0; border-radius: 14px; font-size: 15px; background: #f8fafc; color: #1e293b; transition: all 0.2s; }
        input:focus, textarea:focus, select:focus { outline: none; border-color: #3b82f6; background: white; box-shadow: 0 0 0 4px rgba(59,130,246,0.1); }
        button, .button { display: inline-flex; align-items: center; justify-content: center; border: none; background: #2563eb; color: white; padding: 14px 28px; border-radius: 14px; cursor: pointer; text-decoration: none; text-align: center; font-size: 15px; font-weight: 600; transition: all 0.2s; margin-right: 8px; margin-bottom: 8px; }
        button:hover, .button:hover { background: #1d4ed8; transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgba(37, 99, 235, 0.3); }
        .danger { background: #ef4444; } .danger:hover { background: #dc2626; box-shadow: 0 10px 15px -3px rgba(239, 68, 68, 0.3); }
        .secondary { background: white; color: #4b5563; border: 1px solid #d1d5db; } .secondary:hover { background: #f3f4f6; color: #111827; }
        .warning { background: #f59e0b; } .warning:hover { background: #d97706; box-shadow: 0 10px 15px -3px rgba(245, 158, 11, 0.3); }
        .success { background: #10b981; } .success:hover { background: #059669; box-shadow: 0 10px 15px -3px rgba(16, 185, 129, 0.3); }
        .whatsapp { background: #25d366; } .whatsapp:hover { background: #1da851; box-shadow: 0 10px 15px -3px rgba(37, 211, 102, 0.3); }
        .pros-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-top: 24px; }
        .pro-card { background: white; border-radius: 20px; padding: 24px; border: 1px solid #f1f5f9; box-shadow: 0 4px 15px rgba(0,0,0,0.03); display: flex; flex-direction: column; transition: all 0.3s ease; position: relative; overflow: hidden; }
        .pro-card:hover { transform: translateY(-5px); box-shadow: 0 15px 30px rgba(0,0,0,0.08); }
        .pro-name { font-size: 18px; font-weight: 800; color: #0f172a; margin-bottom: 4px; }
        .pro-meta { font-size: 13px; color: #64748b; font-weight: 500; }
        .pro-actions { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 16px; }
        .pro-actions a { padding: 10px; font-size: 13px; border-radius: 10px; margin: 0; text-align: center; font-weight: 600; }
        .pro-profile-link { grid-column: span 2; background: #f1f5f9; color: #334155; font-weight: 700; }
        .badge { display: inline-block; padding: 6px 12px; border-radius: 30px; font-size: 12px; font-weight: 700; text-transform: uppercase; }
        .kyc-tick { display: inline-flex; align-items: center; justify-content: center; width: 18px; height: 18px; background: #3b82f6; color: white; border-radius: 50%; font-size: 11px; font-weight: bold; margin-left: 6px; vertical-align: middle; box-shadow: 0 2px 5px rgba(59,130,246,0.4); }
        .kyc-tick-lg { width: 24px; height: 24px; font-size: 14px; margin-left: 8px; }
        .alert { padding: 16px; border-radius: 12px; margin-bottom: 16px; font-weight: 500; border: 1px solid transparent; }
        .alert-info { background: #eff6ff; color: #1e40af; border-color: #bfdbfe; }
        .alert-success { background: #ecfdf5; color: #065f46; border-color: #a7f3d0; }
        .alert-danger { background: #fef2f2; color: #991b1b; border-color: #fecaca; }
        @keyframes pulse-alert { 0% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); } 50% { transform: scale(1.02); box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); } 100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); } }
        .alert-animated { animation: pulse-alert 2s infinite; background-color: #fef2f2 !important; border: 2px solid #ef4444 !important; color: #991b1b !important; font-weight: 700; }
        footer { background: #0f172a; color: #94a3b8; padding: 60px 20px 20px; margin-top: 80px; }
        .footer-content { max-width: 1200px; margin: 0 auto; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 32px; }
        .footer-col h4 { color: white; margin-bottom: 16px; font-size: 15px; text-transform: uppercase; font-weight: 800; }
        .footer-col a { display: block; color: #94a3b8; text-decoration: none; padding: 6px 0; font-size: 14px; transition: color 0.2s; }
        .footer-col a:hover { color: white; }
        .footer-bottom { max-width: 1200px; margin: 32px auto 0; padding-top: 24px; border-top: 1px solid #1e293b; text-align: center; font-size: 13px; color: #64748b; }
        .desktop-menu { display: flex; gap: 6px; align-items: center; }
        .mobile-menu { display: none; }
        .fancy-label { font-weight: 600; color: #334155; margin-bottom: 6px; display: block; font-size: 14px; }
        .fancy-input { width: 100%; padding: 14px 16px; border-radius: 12px; border: 1px solid #e2e8f0; background: #f8fafc; color: #1e293b; margin-bottom: 18px; transition: all 0.2s; }
        .fancy-input:focus { background: white; border-color: #3b82f6; box-shadow: 0 0 0 4px rgba(59,130,246,0.1); outline: none; }
        @media (max-width: 768px) {
          header { padding: 14px 16px; }
          .header-content { flex-direction: column; text-align: center; }
          .desktop-menu { display: none; }
          .mobile-menu { display: flex; flex-direction: column; width: 100%; position: relative; margin-top: 10px; }
          .main-links { display: flex; justify-content: space-between; align-items: center; width: 100%; }
          .burger-btn { background: transparent; border: none; color: white; font-size: 28px; cursor: pointer; }
          .mobile-dropdown { display: none; flex-direction: column; background: #1e3a8a; position: absolute; top: 100%; left: 0; right: 0; z-index: 1000; padding: 10px; border-radius: 10px; box-shadow: 0 4px 10px rgba(0,0,0,0.3); margin-top: 5px; }
          .mobile-dropdown.show { display: flex; }
          .mobile-dropdown a { padding: 12px; text-align: center; border-bottom: 1px solid rgba(255,255,255,0.1); width: 100%; display: block; }
          .pros-grid { grid-template-columns: 1fr; } 
          .pro-card { padding: 20px; }
          .pro-actions { display: flex; flex-direction: column; }
          .pro-actions a { padding: 12px; font-size: 14px; }
          .footer-content { grid-template-columns: 1fr; text-align: center; }
          .footer-col a { display: inline-block; margin: 0 10px; }
        }
        img { max-width: 100%; height: auto; content-visibility: auto; }
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
              <a href="/mon-compte">Mon compte</a>
              <a href="/contact">Contact</a> 
              <button id="btn-notif" style="display: none;"></button>
            </div>
            <div class="mobile-menu">
              <div class="main-links">
                <a href="/">Professionnels</a>
                <a href="/emplois">Emploi</a>
                <button class="burger-btn" onclick="document.getElementById('mobile-dropdown').classList.toggle('show')">☰</button>
              </div>
              <div id="mobile-dropdown" class="mobile-dropdown">
                <a href="/devenir-professionnel">Devenir pro</a>
                <a href="/mes-favoris">❤️ Favoris</a>
                <a href="/mon-compte">Mon compte</a>
                <a href="/mon-espace-pro">Espace pro</a>
                <a href="/contact">Contact</a>
              </div>
            </div>
          </nav>
        </div>
      </header>
      <main>${content}</main>
      
      <footer>
        <div class="footer-content">
          <div class="footer-col">
            <h4>TrouveMoi</h4>
            <p style="color:#94a3b8;font-size:14px; margin-bottom: 10px;">La plateforme beninoise de mise en relation.</p>
            <a href="https://www.facebook.com/profile.php?id=61595327533405" target="_blank" style="display:inline-flex; align-items:center; justify-content:center; background:#1877F2; color:white; padding:10px 20px; border-radius:8px; text-decoration:none; font-weight:600; font-size:14px; margin-top:10px;">
              <svg width="18" height="18" fill="currentColor" viewBox="0 0 24 24" style="margin-right: 8px;"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.469h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.469h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/></svg>
              Facebook
            </a>
          </div>
          <div class="footer-col">
            <h4>Navigation</h4>
            <a href="/">Professionnels</a>
            <a href="/mes-favoris">Mes favoris</a>
            <a href="/emplois">Offres d'emploi</a>
            <a href="/devenir-professionnel">Devenir professionnel</a>
            <a href="/mon-espace-pro">Espace pro</a>
          </div>
          <div class="footer-col">
            <h4>Informations</h4>
            <a href="/a-propos">A propos</a>
            <a href="/contact">Contact</a>
            <a href="/blog">Blog</a>
            <a href="/partenariats">Partenariats</a>
            <a href="/conditions">Conditions</a>
            <a href="/mentions-legales">Mentions légales</a>
            <a href="/confidentialite">Confidentialite</a>
          </div>
          <div class="footer-col">
            <h4>Soutenir TrouveMoi</h4>
            <p style="color:#94a3b8;font-size:13px; margin-bottom:10px;">Vous avez été satisfait de nos services ?</p>
            <a href="/soutenir" style="display:inline-block; background:#f59e0b; color:white; padding:10px 20px; border-radius:20px; text-decoration:none; font-weight:bold; font-size:14px;">❤️ Faire un don</a>
          </div>
          <div class="footer-col">
            <h4>Contact</h4>
            <a href="mailto:contact@trouvemoi.bj">contact@trouvemoi.bj</a>
          </div>
        </div>
        <div class="footer-bottom">&copy; ${new Date().getFullYear()} TrouveMoi. Tous droits reserves.</div>
      </footer>
      
      <script>
      async function toggleFav(e, id) { 
        e.preventDefault(); 
        const btn = e.currentTarget; 
        const svg = btn.querySelector('svg');
        const path = svg ? svg.querySelector('path') : null;
        
        if (path) {
            const isCurrentlyRed = svg.getAttribute('fill') === '#ef4444';
            svg.setAttribute('fill', isCurrentlyRed ? 'none' : '#ef4444');
            svg.setAttribute('stroke', isCurrentlyRed ? '#6b7280' : '#ef4444');
        }

        const res = await fetch('/api/favorite/' + id, { method: 'POST' }); 
        const data = await res.json(); 
        
        if (data.ok) { 
            if (path) {
                svg.setAttribute('fill', data.isFav ? '#ef4444' : 'none');
                svg.setAttribute('stroke', data.isFav ? '#ef4444' : '#6b7280');
            }
            if (btn.classList.contains('favorite-btn') && btn.classList.contains('active')) {
                if (!data.isFav) btn.classList.remove('active');
            }
        } else {
            if (path) {
                const isCurrentlyRed = svg.getAttribute('fill') === '#ef4444';
                svg.setAttribute('fill', isCurrentlyRed ? 'none' : '#ef4444');
                svg.setAttribute('stroke', isCurrentlyRed ? '#6b7280' : '#ef4444');
            }
        }
        return data; 
      }
      </script>

<div id="image-modal" style="display:none; position:fixed; z-index:9999; padding-top:50px; left:0; top:0; width:100%; height:100%; overflow:auto; background-color:rgba(0,0,0,0.9);" onclick="if(event.target.id === 'image-modal') this.style.display='none'">
  <span style="position:absolute; top:15px; right:35px; color:#fff; font-size:40px; font-weight:bold; cursor:pointer; z-index:10000;" onclick="document.getElementById('image-modal').style.display='none'">&times;</span>
  <div style="position:absolute; top:15px; left:15px; z-index:10000; display:flex; gap:10px;" onclick="event.stopPropagation()">
    <button onclick="rotateImage(-90)" style="background:#2563eb; color:white; border:none; padding:10px 15px; border-radius:8px; cursor:pointer; font-weight:bold;">↺ Tourner à gauche</button>
    <button onclick="rotateImage(90)" style="background:#2563eb; color:white; border:none; padding:10px 15px; border-radius:8px; cursor:pointer; font-weight:bold;">↻ Tourner à droite</button>
  </div>
  <img id="modal-img" style="margin: auto; display: block; max-width: 90%; max-height: 90vh; border-radius: 12px; transition: transform 0.3s;">
</div>

<script>
  let currentRotation = 0;
  function zoomImage(src) { 
    document.getElementById('image-modal').style.display = 'block'; 
    document.getElementById('modal-img').src = src; 
    currentRotation = 0; 
    document.getElementById('modal-img').style.transform = 'rotate(0deg)';
  }
  function rotateImage(degrees) {
    currentRotation += degrees;
    document.getElementById('modal-img').style.transform = 'rotate(' + currentRotation + 'deg)';
  }
</script>

<script type="module" style="display:none;">
  import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
  import { getMessaging, getToken } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-messaging.js";

  const firebaseConfig = {
    apiKey: "AIzaSyAX6ooPWJb2LWbWop-YxAcCjpgtoMzkIDA",
    authDomain: "trouvemoi-c1b01.firebaseapp.com",
    projectId: "trouvemoi-c1b01",
    storageBucket: "trouvemoi-c1b01.appspot.com",
    messagingSenderId: "317041094178",
    appId: "1:317041094178:web:8c5fce11bc259b4d3d647b"
  };

  const app = initializeApp(firebaseConfig);
  let messaging = null;

  if ('serviceWorker' in navigator && 'Notification' in window) {
    navigator.serviceWorker.register('/firebase-messaging-sw.js')
    .then((registration) => {
      messaging = getMessaging(app);
      window.swRegistration = registration;
    })
    .catch((err) => console.error("Erreur ServiceWorker:", err));
  }

  window.demanderNotifications = async function() {
    const btn = document.getElementById('btn-notif');
    if(btn) btn.innerText = "⏳ Chargement...";

    setTimeout(async () => {
      try {
        const permission = await Notification.requestPermission();
        
        if (permission === 'granted') {
          if(btn) btn.innerText = "⏳ Récupération...";
          
          getToken(messaging, { 
            serviceWorkerRegistration: window.swRegistration,
            vapidKey: "BJrlYFSaouHz6rqkvtplC7PQLlyowVXVRaZ4EC-b3t6ddShMBm7-qNMEg4o8XVKlkxDawBFO8GVfkavlAXOAe7o"
          })
          .then((currentToken) => {
            if (currentToken) {
              if(btn) {
                btn.innerText = "✅ Alertes OK";
                btn.style.background = "#10b981"; 
              }
              fetch('/api/save-token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: currentToken })
              }).then(() => console.log('Token sauvegardé !'));
            }
          }).catch((err) => {
            console.error('Erreur token :', err);
            if(btn) {
                btn.innerText = "❌ Erreur";
                btn.style.background = "#ef4444";
            }
            alert("Détail de l'erreur Firebase : " + err.message);
          });
        } else {
          alert("Vous avez refusé les notifications.");
          if(btn) btn.innerText = "🔔 Activer les alertes";
        }
      } catch (e) {
        console.error(e);
        if(btn) btn.innerText = "🔔 Activer les alertes";
      }
    }, 1500);
  }
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

// Limite globale : max 100 requêtes par minute par IP
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: "Trop de requêtes, veuillez patienter.",
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

// --- ROUTES SYSTEME ---
// 1. Route pour ENVOYER le code par SMS
app.post("/api/send-otp", express.json(), async (req, res) => {
  const phone = cleanBeninPhone(req.body.phone);
  if (!phone) return res.status(400).json({ ok: false, error: "Numéro invalide (01XXXXXXXX)" });

  if (!(await takeRateLimit(`otp:send:${phone}`, 1, 60 * 1000))) {
    return res.status(429).json({ ok: false, error: "Patientez 1 minute avant de redemander." });
  }

  try {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query(
      `INSERT INTO otp_codes (phone, code, expires_at) VALUES ($1, $2, $3) 
       ON CONFLICT (phone) DO UPDATE SET code = $2, expires_at = $3`,
      [phone, code, expiresAt]
    );

    // 🛠️ MODE TEST : On n'envoie pas de vrai SMS pour l'instant
    console.log(`📱 CODE OTP POUR ${phone} : ${code}`);
    
    res.json({ ok: true, message: "SMS simulé ! Regardez les logs Render." });
    
  } catch (e) {
    res.status(500).json({ ok: false });
  }
});

// 2. Route pour VÉRIFIER le code
async function verifyOTP(phone, code) {
  if (!phone || !code) return false;
  
  // 🛠️ CODE MAGIQUE POUR LES TESTS (À SUPPRIMER APRÈS)
  if (code === "123456") {
    console.log("⚠️ Bypass activé : Code magique utilisé pour", phone);
    return true;
  }
  
  const result = await pool.query(`SELECT code FROM otp_codes WHERE phone = $1 AND expires_at > NOW()`, [phone]);
  if (!result.rows.length) return false;
  return safeEqual(result.rows[0].code, code);
}

// --- CRÉATION DU FICHIER POUR LES NOTIFICATIONS (FIREBASE) ---
app.get("/firebase-messaging-sw.js", (req, res) => {
  res.setHeader("Content-Type", "application/javascript");
  res.send(`
    importScripts('https://www.gstatic.com/firebasejs/10.8.0/firebase-app-compat.js');
    importScripts('https://www.gstatic.com/firebasejs/10.8.0/firebase-messaging-compat.js');

    firebase.initializeApp({
      apiKey: "AIzaSyAX6ooPWJb2LWbWop-YxAcCjpgtoMzkIDA",
      authDomain: "trouvemoi-c1b01.firebaseapp.com",
      projectId: "trouvemoi-c1b01",
      storageBucket: "trouvemoi-c1b01.appspot.com",
      messagingSenderId: "317041094178",
      appId: "1:317041094178:web:8c5fce11bc259b4d3d647b"
    });

    const messaging = firebase.messaging();

    messaging.onBackgroundMessage((payload) => {
      console.log('[firebase-messaging-sw.js] Message reçu en arrière-plan : ', payload);
      const notificationTitle = payload.notification.title;
      const notificationOptions = {
        body: payload.notification.body,
        icon: 'https://res.cloudinary.com/gxm35ndf/image/upload/v1794045762/TROUVEMOI_PNG.jpg'
      };
      self.registration.showNotification(notificationTitle, notificationOptions);
    });
  `);
});

app.get("/manifest.json", (req, res) => {
  res.json({
    name: "TrouveMoi",
    short_name: "TrouveMoi",
    description: "Trouvez le professionnel qu'il vous faut.",
    start_url: "/",
    display: "standalone",
    background_color: "#ffffff",
    theme_color: "#1e40af",
    icons: [
      {
        src: "https://res.cloudinary.com/gxm35ndf/image/upload/v1794045762/TROUVEMOI_PNG.jpg",
        sizes: "192x192",
        type: "image/png",
        purpose: "any maskable"
      },
      {
        src: "https://res.cloudinary.com/gxm35ndf/image/upload/v1794045762/TROUVEMOI_PNG.jpg",
        sizes: "512x512",
        type: "image/png",
        purpose: "any maskable"
      }
    ]
  });
});

app.post("/api/save-token", express.json(), async (req, res) => {
  try {
    const token = String(req.body.token || "").trim();
    if (!token) return res.json({ ok: false });
    await pool.query(`CREATE TABLE IF NOT EXISTS push_tokens (id SERIAL PRIMARY KEY, token TEXT UNIQUE, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`INSERT INTO push_tokens (token) VALUES ($1) ON CONFLICT (token) DO NOTHING`, [token]);
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: false });
  }
});

app.post("/webhooks/kkiapay", express.json({ limit: "100kb" }), async (req, res) => {
  if (BYPASS_PAYMENT) return res.status(200).json({ received: true });
  try {
    if (process.env.KKIAPAY_WEBHOOK_SECRET) {
      const provided = String(req.query.token || req.get("x-webhook-secret") || "");
      if (!safeEqual(provided, process.env.KKIAPAY_WEBHOOK_SECRET)) {
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

    const settlement = await settlePayment({
      dossierId: dossier.id,
      transactionId,
      amount: verification.amount,
      method: verification.method,
      source: "webhook"
    });

    return res.status(200).json({ received: true, processed: settlement.ok });
  } catch (error) { 
    console.error("Erreur webhook Kkiapay :", error.message);
    return res.status(200).json({ received: true, error: true });
  }
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
app.get("/sitemap.xml", async (req, res) => { res.type("application/xml").send(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${APP_URL}/</loc></url></urlset>`); });

app.get("/soutenir", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const content = `
    <section class="card" style="max-width: 600px; margin: 40px auto; text-align:center;">
      <h1 style="color:#f59e0b;">❤️ Soutenir TrouveMoi</h1>
      <p style="color:#4b5563; margin-bottom:30px;">Votre expérience sur TrouveMoi a été satisfaisante ? Vous avez trouvé le professionnel qu'il vous fallait ? Faites-nous un don pour soutenir la plateforme et nous aider à l'améliorer chaque jour.</p>
      <div style="background:#f8fafc; padding:24px; border-radius:12px; border:1px solid #e2e8f0; margin-bottom:20px;">
        <label style="font-size:16px; margin-bottom:10px; display:block;">Entrez le montant de votre don (FCFA) :</label>
        <input type="number" id="custom-amount" placeholder="Ex: 500" min="100" style="text-align:center; font-size:24px; font-weight:bold; max-width:250px; margin:0 auto 15px auto; padding:15px;">
        <div style="margin: 15px 0; text-align: left; max-width: 350px; margin-left: auto; margin-right: auto;">
          <label style="display: flex; align-items: center; cursor: pointer; font-weight: 500; color: #4b5563;">
            <input type="checkbox" id="is-anonymous" onchange="toggleNameField()" style="width: 20px; height: 20px; margin-right: 10px;">
            Je préfère rester anonyme
          </label>
        </div>
        <div id="name-field" style="margin-bottom:15px;">
          <label style="font-size:14px; display:block; margin-bottom:5px;">Votre nom (ou nom de l'entreprise) :</label>
          <input type="text" id="donor-name" placeholder="Ex: Jean Dupont" style="text-align:center; max-width:350px; margin:0 auto; padding:12px; width:100%; border:1px solid #cbd5e0; border-radius:8px;">
        </div>
        <button onclick="payerDon(document.getElementById('custom-amount').value)" style="width:100%; padding:15px; font-size:18px; background:#10b981; color:white; border:none; border-radius:12px; font-weight:bold; margin-top:10px;">Faire un don</button>
      </div>
      <p style="margin-top:20px;"><a href="/" style="color:#6b7280; font-size:14px;">← Retour à l'accueil</a></p>
    </section>
    <script src="https://cdn.kkiapay.me/k.js"></script>
    <script>
      function toggleNameField() {
        const isAnon = document.getElementById('is-anonymous').checked;
        document.getElementById('name-field').style.display = isAnon ? 'none' : 'block';
        if (isAnon) document.getElementById('donor-name').value = "";
      }
      function payerDon(montant) {
        const amount = parseInt(montant);
        if (!amount || amount < 100) { alert("Le montant minimum est de 100 FCFA."); return; }
        const isAnon = document.getElementById('is-anonymous').checked;
        let donorName = "Anonyme";
        if (!isAnon) {
          donorName = document.getElementById('donor-name').value.trim();
          if (!donorName) { alert("Veuillez entrer votre nom ou cocher 'Je préfère rester anonyme'."); return; }
        }
        const kkiapayData = "DON-GLOBAL|" + encodeURIComponent(donorName);
        openKkiapayWidget({ amount: amount, api_key: "${process.env.KKIAPAY_PUBLIC_KEY}", sandbox: ${process.env.KKIAPAY_SANDBOX === "true"}, callback: "${APP_URL}/don/verifier", data: kkiapayData, theme: "#f59e0b", position: "center" });
      }
      addSuccessListener(function(response) {
        if (response && response.transactionId) { window.location.href = "/don/verifier?transaction_id=" + encodeURIComponent(response.transactionId); }
      });
    </script>
  `;
  res.send(page("Soutenir TrouveMoi", content, proConnected));
});

app.get("/don/verifier", async (req, res) => {
  const transactionId = String(req.query.transaction_id || req.query.transactionId || "").trim();
  if (!transactionId) return res.redirect(303, "/");

  try {
    const verification = await verifyKkiapayTransaction(transactionId);
    
    if (verification.success) {
      await pool.query(
        `INSERT INTO global_donations (amount, donor_name, transaction_id) VALUES ($1, $2, $3) ON CONFLICT (transaction_id) DO NOTHING`,
        [verification.amount, "Donateur TrouveMoi", transactionId]
      );

      return res.send(page("Merci !", `
        <section class="card" style="text-align:center; margin:60px auto; max-width:500px;">
          <h1 style="color:#10b981;">❤️ Merci infiniment !</h1>
          <p>Votre don de <strong>${verification.amount} FCFA</strong> a bien été reçu.</p>
          <p>Il nous aidera à améliorer TrouveMoi chaque jour.</p>
          <a href="/" class="button success" style="margin-top:20px; width:100%;">Retour à l'accueil</a>
        </section>
      `, null));
    }
    
    res.redirect(303, "/");
  } catch (e) {
    console.error("Erreur don :", e.message);
    res.redirect(303, "/");
  }
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
app.use('/', pagesRoutes(pool, page, getConnectedPro, getOrCreateVisitorId, escapeHtml, renderStars, renderKycBadge, getDisplayName, APP_URL, cleanBeninPhone, takeRateLimit, verifyKkiapayTransaction, settlePayment, PAYMENT_AMOUNT, verifyOTP, QUARTIERS_BENIN));
app.use('/contact', contactRoutes(pool, page, getConnectedPro, takeRateLimit, escapeHtml, sendSMS));
app.use('/', candidaturesRoutes(pool, page, getConnectedPro, upload, uploadToCloudinary, takeRateLimit, BYPASS_PAYMENT, process.env.KKIAPAY_PUBLIC_KEY, process.env.KKIAPAY_SANDBOX === "true", APP_URL, escapeHtml, cleanBeninPhone, readCookie, PAYMENT_AMOUNT, METIERS_LOCAL_FIXE, METIERS_SENSIBLES, sendSMS, verifyOTP, sendPushNotification, VILLES_BENIN));
app.use('/mon-espace-pro', proRoutes(pool, page, getConnectedPro, escapeHtml, upload, uploadToCloudinary, clearRateLimit, takeRateLimit, setProCookie, clearProCookie, generateUniqueProCode, logAdminAction, 15, deleteFromCloudinary, cleanBeninPhone, sendSMS, verifyOTP, safeCoord));
app.use('/', emploisRoutes(pool, page, getConnectedPro, escapeHtml, cleanBeninPhone, ["CDI", "CDD"], logAdminAction, 15));
app.use('/', agencesRoutes(pool, page, getConnectedPro, escapeHtml, safeCoord, cleanBeninPhone, upload, uploadToCloudinary, BYPASS_PAYMENT));
app.use('/admin', adminRoutes(pool, page, requireAdmin, verifyCsrf, getCsrf, escapeHtml, null, verifySessionToken, readCookie, clearSessionCookie, createSessionToken, setSessionCookie, safeEqual, process.env.ADMIN_PASSWORD, verifyTotp, process.env.ADMIN_TOTP_SECRET, SESSION_COOKIE, SESSION_DURATION, logAdminAction, deleteFromCloudinary));

// --- GESTION DES ERREURS ---
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).send(page("Erreur", "<h2>Une des photos est trop lourde (max 10 Mo).</h2><a href='/devenir-professionnel'>Réessayer</a>", null));
    }
  }
  console.error("Erreur serveur :", err);
  res.status(500).send("Erreur serveur");
});

// --- DEMARRAGE ---
async function startServer() {
  try {
    await pool.query("SELECT 1");

    // --- INSERTION DES MÉTIERS D'ÉTABLISSEMENTS ---
    const etablissements = [
      { name: "Restaurant", cat: "Établissements" }, { name: "Boutique", cat: "Établissements" }, { name: "Supérette", cat: "Établissements" }, { name: "Pharmacie", cat: "Établissements" }, { name: "Agence immobilière", cat: "Établissements" }, { name: "Garage", cat: "Établissements" }, { name: "Salon de beauté", cat: "Établissements" }, { name: "Hôtel", cat: "Établissements" }
    ];
    for (let e of etablissements) {
      await pool.query(`INSERT INTO professions (name, category) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING`, [e.name, e.cat]);
    }

    // --- MÉTIERS INSPIRÉS DES NOMENCLATURES OFFICIELLES DU BÉNIN ---
    const metiersOfficiels = [
      { name: "Maçon", cat: "Bâtiment & TP" }, { name: "Coffreur", cat: "Bâtiment & TP" }, { name: "Ferrailleur", cat: "Bâtiment & TP" }, { name: "Charpentier", cat: "Bâtiment & TP" }, { name: "Couvreur", cat: "Bâtiment & TP" }, { name: "Plombier", cat: "Bâtiment & TP" }, { name: "Électricien Bâtiment", cat: "Bâtiment & TP" }, { name: "Peintre en bâtiment", cat: "Bâtiment & TP" }, { name: "Carreleur", cat: "Bâtiment & TP" }, { name: "Géomètre topographe", cat: "Bâtiment & TP" }, { name: "Technicien d'étude du bâtiment", cat: "Bâtiment & TP" }, { name: "Constructeur d'ouvrages en béton armé", cat: "Bâtiment & TP" },
      { name: "Menuisier bois", cat: "Menuiserie & Bois" }, { name: "Ébéniste", cat: "Menuiserie & Bois" }, { name: "Menuisier aluminium", cat: "Menuiserie & Bois" }, { name: "Vitrier", cat: "Menuiserie & Bois" }, { name: "Technicien constructeur ouvrage bois", cat: "Menuiserie & Bois" },
      { name: "Soudeur", cat: "Métal & Métallurgie" }, { name: "Métallier", cat: "Métal & Métallurgie" }, { name: "Ferronnier d'art", cat: "Métal & Métallurgie" }, { name: "Fondeur de bronze", cat: "Métal & Métallurgie" }, { name: "Bijoutier", cat: "Métal & Métallurgie" }, { name: "Orfèvre", cat: "Métal & Métallurgie" },
      { name: "Sculpteur sur bois", cat: "Artisanat d'Art" }, { name: "Potier", cat: "Artisanat d'Art" }, { name: "Céramiste", cat: "Artisanat d'Art" }, { name: "Vannier", cat: "Artisanat d'Art" }, { name: "Maroquinier d'art", cat: "Artisanat d'Art" }, { name: "Tisserand", cat: "Artisanat d'Art" }, { name: "Brodeur", cat: "Artisanat d'Art" }, { name: "Teinturier", cat: "Artisanat d'Art" }, { name: "Décorateur floral", cat: "Artisanat d'Art" }, { name: "Créateur de parfums", cat: "Artisanat d'Art" }, { name: "Paysagiste", cat: "Artisanat d'Art" }, { name: "Créateur d'espaces verts", cat: "Artisanat d'Art" },
      { name: "Mécanicien automobile", cat: "Automobile & Mécanique" }, { name: "Électricien automobile", cat: "Automobile & Mécanique" }, { name: "Tôlier", cat: "Automobile & Mécanique" }, { name: "Technicien diagnostic auto", cat: "Automobile & Mécanique" }, { name: "Contrôleur technique automobile", cat: "Automobile & Mécanique" }, { name: "Mécanicien moto", cat: "Automobile & Mécanique" },
      { name: "Technicien en énergies renouvelables", cat: "Énergie & Froid" }, { name: "Installateur photovoltaïque", cat: "Énergie & Froid" }, { name: "Technicien froid et climatisation", cat: "Énergie & Froid" }, { name: "Ascensoriste", cat: "Énergie & Froid" }, { name: "Domoticien", cat: "Énergie & Froid" },
      { name: "Aviculteur", cat: "Agriculture & Élevage" }, { name: "Cuniculteur", cat: "Agriculture & Élevage" }, { name: "Éleveur de bovins", cat: "Agriculture & Élevage" }, { name: "Éleveur de porcins", cat: "Agriculture & Élevage" }, { name: "Pisciculteur", cat: "Agriculture & Élevage" }, { name: "Aquaculteur", cat: "Agriculture & Élevage" }, { name: "Horticulteur", cat: "Agriculture & Élevage" }, { name: "Maraîcher", cat: "Agriculture & Élevage" }, { name: "Pépiniériste", cat: "Agriculture & Élevage" }, { name: "Producteur céréalier", cat: "Agriculture & Élevage" }, { name: "Producteur de racines et tubercules", cat: "Agriculture & Élevage" }, { name: "Arboriculteur fruitier", cat: "Agriculture & Élevage" }, { name: "Exploitant palmier à huile", cat: "Agriculture & Élevage" },
      { name: "Technicien Canal+ / Installateur parabole", cat: "Numérique & Tech" }, { name: "Technicien réseau / Câblage", cat: "Numérique & Tech" }, { name: "Développeur web", cat: "Numérique & Tech" }, { name: "Développeur mobile", cat: "Numérique & Tech" }, { name: "Cybersécurité", cat: "Numérique & Tech" }, { name: "Data Analyst", cat: "Numérique & Tech" }, { name: "Expert IA / Big Data", cat: "Numérique & Tech" }, { name: "Marketing digital", cat: "Numérique & Tech" }, { name: "Graphiste", cat: "Numérique & Tech" }, { name: "Community Manager", cat: "Numérique & Tech" }, { name: "Technicien maintenance informatique", cat: "Numérique & Tech" },
      { name: "Infirmier", cat: "Santé" }, { name: "Sage-femme", cat: "Santé" }, { name: "Technicien de laboratoire", cat: "Santé" }, { name: "Aide-soignant", cat: "Santé" }, { name: "Kinésithérapeute", cat: "Santé" }, { name: "Secrétaire médical", cat: "Santé" }, { name: "Dentiste", cat: "Santé" }, { name: "Pharmacien", cat: "Santé" },
      { name: "Cuisinier", cat: "Hôtellerie & Restauration" }, { name: "Pâtissier", cat: "Hôtellerie & Restauration" }, { name: "Boulanger", cat: "Hôtellerie & Restauration" }, { name: "Serveur", cat: "Hôtellerie & Restauration" }, { name: "Réceptionniste d'hôtel", cat: "Hôtellerie & Restauration" }, { name: "Guide touristique", cat: "Hôtellerie & Restauration" }, { name: "Agent d'entretien hôtelier", cat: "Hôtellerie & Restauration" }, { name: "Traiteur", cat: "Hôtellerie & Restauration" },
      { name: "Comptable", cat: "Services & Administration" }, { name: "Secrétaire administratif", cat: "Services & Administration" }, { name: "Agent administratif", cat: "Services & Administration" }, { name: "Juriste", cat: "Services & Administration" }, { name: "Assistant RH", cat: "Services & Administration" }, { name: "Agent de sécurité", cat: "Sécurité & Gardiennage" }, { name: "Gardien", cat: "Services & Administration" }, { name: "Femme de ménage", cat: "Services & Administration" }, { name: "Jardinier", cat: "Services & Administration" }, { name: "Chauffeur", cat: "Services & Administration" }, { name: "Livreur", cat: "Services & Administration" },
      { name: "Professeur", cat: "Éducation & Formation" }, { name: "Instituteur", cat: "Éducation & Formation" }, { name: "Répétiteur", cat: "Éducation & Formation" }, { name: "Formateur professionnel", cat: "Éducation & Formation" },
      { name: "Restaurant", cat: "Commerce & Boutiques" }, { name: "Boutique", cat: "Commerce & Boutiques" }, { name: "Supérette", cat: "Commerce & Boutiques" }, { name: "Supermarché", cat: "Commerce & Boutiques" }, { name: "Alimentation générale", cat: "Commerce & Boutiques" }, { name: "Épicerie", cat: "Commerce & Boutiques" }, { name: "Pharmacie", cat: "Commerce & Boutiques" }, { name: "Parapharmacie", cat: "Commerce & Boutiques" }, { name: "Boulangerie", cat: "Commerce & Boutiques" }, { name: "Pâtisserie", cat: "Commerce & Boutiques" }, { name: "Boucherie", cat: "Commerce & Boutiques" }, { name: "Poissonnerie", cat: "Commerce & Boutiques" }, { name: "Vente de fruits et légumes", cat: "Commerce & Boutiques" }, { name: "Vente de produits surgelés", cat: "Commerce & Boutiques" }, { name: "Dépôt de boissons", cat: "Commerce & Boutiques" }, { name: "Dépôt de gaz domestique", cat: "Commerce & Boutiques" }, { name: "Quincaillerie", cat: "Commerce & Boutiques" }, { name: "Agence immobilière", cat: "Commerce & Boutiques" }, { name: "Boutique de vente de téléphones et accessoires", cat: "Commerce & Boutiques" }, { name: "Boutique Apple Store", cat: "Commerce & Boutiques" }, { name: "Distributeur agréé Canal+", cat: "Commerce & Boutiques" }, { name: "Boutique de vente de mèches", cat: "Commerce & Boutiques" }, { name: "Compagnie d'assurance", cat: "Commerce & Boutiques" }, { name: "Compagnie de transport", cat: "Commerce & Boutiques" }, { name: "Boutique de vente d'appareils électroménagers", cat: "Commerce & Boutiques" }, { name: "Boutique de vêtements", cat: "Commerce & Boutiques" }, { name: "Boutique de chaussures", cat: "Commerce & Boutiques" }, { name: "Boutique de sacs et accessoires de mode", cat: "Commerce & Boutiques" }, { name: "Boutique de tissus et pagnes", cat: "Commerce & Boutiques" }, { name: "Boutique de cosmétiques", cat: "Commerce & Boutiques" }, { name: "Boutique de parfumerie", cat: "Commerce & Boutiques" }, { name: "Boutique de jouets", cat: "Commerce & Boutiques" }, { name: "Boutique de vente de produits chinois", cat: "Commerce & Boutiques" }, { name: "Librairie", cat: "Commerce & Boutiques" }, { name: "Papeterie", cat: "Commerce & Boutiques" }, { name: "Bijouterie", cat: "Commerce & Boutiques" }, { name: "Cave à vin", cat: "Commerce & Boutiques" }, { name: "Magasin de meubles", cat: "Commerce & Boutiques" }, { name: "Magasin de décoration intérieure", cat: "Commerce & Boutiques" }, { name: "Magasin de matériaux de construction", cat: "Commerce & Boutiques" }, { name: "Magasin de peinture", cat: "Commerce & Boutiques" }, { name: "Magasin de fournitures scolaires", cat: "Commerce & Boutiques" }, { name: "Magasin de pièces électroniques", cat: "Commerce & Boutiques" }, { name: "Magasin de matériel informatique", cat: "Commerce & Boutiques" }, { name: "Barber shop", cat: "Commerce & Boutiques" }, { name: "Lavage moto", cat: "Commerce & Boutiques" },
      { name: "Fast-food", cat: "Restauration & Loisirs" }, { name: "Maquis", cat: "Restauration & Loisirs" }, { name: "Cafétéria", cat: "Restauration & Loisirs" }, { name: "Glacier", cat: "Restauration & Loisirs" }, { name: "Pizzeria", cat: "Restauration & Loisirs" }, { name: "Restaurant africain", cat: "Restauration & Loisirs" }, { name: "Restaurant gastronomique", cat: "Restauration & Loisirs" }, { name: "Bar", cat: "Restauration & Loisirs" }, { name: "Discothèque", cat: "Restauration & Loisirs" }, { name: "Hôtel", cat: "Restauration & Loisirs" }, { name: "Auberge", cat: "Restauration & Loisirs" }, { name: "Résidence meublée", cat: "Restauration & Loisirs" }, { name: "Maison d'hôtes", cat: "Restauration & Loisirs" }, { name: "Camping", cat: "Restauration & Loisirs" }, { name: "Espace événementiel", cat: "Restauration & Loisirs" }, { name: "Salle de réception", cat: "Restauration & Loisirs" }, { name: "Salle de jeux", cat: "Restauration & Loisirs" }, { name: "Salle de sport", cat: "Restauration & Loisirs" }, { name: "Salle de fitness", cat: "Restauration & Loisirs" }, { name: "Piscine", cat: "Restauration & Loisirs" }, { name: "Centre de loisirs", cat: "Restauration & Loisirs" },
      { name: "Clinique", cat: "Santé & Bien-être" }, { name: "Hôpital", cat: "Santé & Bien-être" }, { name: "Cabinet médical", cat: "Santé & Bien-être" }, { name: "Cabinet dentaire", cat: "Santé & Bien-être" }, { name: "Cabinet ophtalmologique", cat: "Santé & Bien-être" }, { name: "Laboratoire d'analyses médicales", cat: "Santé & Bien-être" }, { name: "Centre de radiologie", cat: "Santé & Bien-être" }, { name: "Centre de soins", cat: "Santé & Bien-être" }, { name: "Centre de kinésithérapie", cat: "Santé & Bien-être" }, { name: "Centre de vaccination", cat: "Santé & Bien-être" }, { name: "Cabinet vétérinaire", cat: "Santé & Bien-être" }, { name: "Opticien", cat: "Santé & Bien-être" }, { name: "Centre de bien-être", cat: "Santé & Bien-être" }, { name: "Institut de massage", cat: "Santé & Bien-être" }, { name: "Centre dermatologique", cat: "Santé & Bien-être" },
      { name: "École maternelle", cat: "Éducation & Formation" }, { name: "École primaire", cat: "Éducation & Formation" }, { name: "Collège", cat: "Éducation & Formation" }, { name: "Lycée", cat: "Éducation & Formation" }, { name: "Université", cat: "Éducation & Formation" }, { name: "Établissement d'enseignement supérieur", cat: "Éducation & Formation" }, { name: "Centre de formation professionnelle", cat: "Éducation & Formation" }, { name: "Centre de formation informatique", cat: "Éducation & Formation" }, { name: "Auto-école", cat: "Éducation & Formation" }, { name: "Crèche", cat: "Éducation & Formation" }, { name: "Garderie", cat: "Éducation & Formation" }, { name: "Centre de soutien scolaire", cat: "Éducation & Formation" }, { name: "Centre de langues", cat: "Éducation & Formation" }, { name: "Bibliothèque", cat: "Éducation & Formation" },
      { name: "Garage", cat: "Automobile & Transport" }, { name: "Garage automobile", cat: "Automobile & Transport" }, { name: "Garage moto", cat: "Automobile & Transport" }, { name: "Station-service", cat: "Automobile & Transport" }, { name: "Centre de lavage automobile", cat: "Automobile & Transport" }, { name: "Vente de véhicules", cat: "Automobile & Transport" }, { name: "Location de véhicules", cat: "Automobile & Transport" }, { name: "Agence de location de motos", cat: "Automobile & Transport" }, { name: "Vente de pneus", cat: "Automobile & Transport" }, { name: "Vente de batteries automobiles", cat: "Automobile & Transport" }, { name: "Vente de lubrifiants", cat: "Automobile & Transport" }, { name: "Centre de vidange", cat: "Automobile & Transport" }, { name: "Centre de diagnostic automobile", cat: "Automobile & Transport" }, { name: "Carrosserie automobile", cat: "Automobile & Transport" }, { name: "Auto-électricité", cat: "Automobile & Transport" }, { name: "Vulcanisateur", cat: "Automobile & Transport" }, { name: "Boutique de vente de pièces détachées de moto", cat: "Automobile & Transport" }, { name: "Boutique de vente de pièces détachées automobiles", cat: "Automobile & Transport" }, { name: "Agence de transport interurbain", cat: "Automobile & Transport" }, { name: "Agence de voyage", cat: "Automobile & Transport" }, { name: "Gare routière", cat: "Automobile & Transport" }, { name: "Compagnie de livraison", cat: "Automobile & Transport" }, { name: "Entreprise de déménagement", cat: "Automobile & Transport" }, { name: "Agence de fret et transit", cat: "Automobile & Transport" },
      { name: "Cabinet comptable", cat: "Services & Administration" }, { name: "Cabinet juridique", cat: "Services & Administration" }, { name: "Cabinet d'avocats", cat: "Services & Administration" }, { name: "Cabinet de conseil", cat: "Services & Administration" }, { name: "Agence de communication", cat: "Services & Administration" }, { name: "Agence de publicité", cat: "Services & Administration" }, { name: "Agence de marketing digital", cat: "Services & Administration" }, { name: "Agence web", cat: "Services & Administration" }, { name: "Agence de graphisme", cat: "Services & Administration" }, { name: "Agence de création audiovisuelle", cat: "Services & Administration" }, { name: "Cabinet d'architecture", cat: "Services & Administration" }, { name: "Cabinet de géomètre", cat: "Services & Administration" }, { name: "Agence de sécurité privée", cat: "Services & Administration" }, { name: "Agence de nettoyage", cat: "Services & Administration" }, { name: "Entreprise de gardiennage", cat: "Services & Administration" }, { name: "Agence de recrutement", cat: "Services & Administration" }, { name: "Cabinet de ressources humaines", cat: "Services & Administration" }, { name: "Cabinet d'expertise immobilière", cat: "Services & Administration" }, { name: "Agence de décoration événementielle", cat: "Services & Administration" }, { name: "Pompes funèbres", cat: "Services & Administration" },
      { name: "Banque", cat: "Finance & Télécoms" }, { name: "Institution de microfinance", cat: "Finance & Télécoms" }, { name: "Agence de transfert d'argent", cat: "Finance & Télécoms" }, { name: "Agence Mobile Money", cat: "Finance & Télécoms" }, { name: "Agence de change", cat: "Finance & Télécoms" }, { name: "Agence d'assurance", cat: "Finance & Télécoms" }, { name: "Agence de paiement électronique", cat: "Finance & Télécoms" }, { name: "Agence de télécommunications", cat: "Finance & Télécoms" }, { name: "Boutique de vente de cartes SIM", cat: "Finance & Télécoms" }, { name: "Centre de services téléphoniques", cat: "Finance & Télécoms" }, { name: "Agence de services financiers", cat: "Finance & Télécoms" },
      { name: "Atelier de couture", cat: "Artisanat & Construction" }, { name: "Atelier de broderie", cat: "Artisanat & Construction" }, { name: "Atelier de menuiserie", cat: "Artisanat & Construction" }, { name: "Atelier de soudure", cat: "Artisanat & Construction" }, { name: "Atelier de mécanique", cat: "Artisanat & Construction" }, { name: "Atelier de réparation de téléphones", cat: "Artisanat & Construction" }, { name: "Atelier de réparation informatique", cat: "Artisanat & Construction" }, { name: "Atelier de réparation électroménager", cat: "Artisanat & Construction" }, { name: "Atelier de réparation électronique", cat: "Artisanat & Construction" }, { name: "Atelier de réparation de réfrigérateurs", cat: "Artisanat & Construction" }, { name: "Entreprise de plomberie", cat: "Artisanat & Construction" }, { name: "Entreprise d'électricité", cat: "Artisanat & Construction" }, { name: "Entreprise de construction", cat: "Artisanat & Construction" }, { name: "Entreprise de BTP", cat: "Artisanat & Construction" }, { name: "Entreprise de carrelage", cat: "Artisanat & Construction" }, { name: "Entreprise de peinture bâtiment", cat: "Artisanat & Construction" }, { name: "Entreprise de vitrerie", cat: "Artisanat & Construction" }, { name: "Entreprise de climatisation", cat: "Artisanat & Construction" }, { name: "Entreprise de forage", cat: "Artisanat & Construction" }, { name: "Entreprise de forage et installation de pompes", cat: "Artisanat & Construction" }, { name: "Entreprise de décoration intérieure", cat: "Artisanat & Construction" }, { name: "Entreprise de menuiserie aluminium", cat: "Artisanat & Construction" }, { name: "Entreprise de menuiserie bois", cat: "Artisanat & Construction" }, { name: "Atelier de fabrication métallique", cat: "Artisanat & Construction" }, { name: "Entreprise de paysagisme", cat: "Artisanat & Construction" },
      { name: "Salon de beauté", cat: "Beauté & Mode" }, { name: "Salon de coiffure", cat: "Beauté & Mode" }, { name: "Salon de coiffure mixte", cat: "Beauté & Mode" }, { name: "Institut de beauté", cat: "Beauté & Mode" }, { name: "Salon de manucure", cat: "Beauté & Mode" }, { name: "Salon de pédicure", cat: "Beauté & Mode" }, { name: "Centre de soins capillaires", cat: "Beauté & Mode" }, { name: "Salon de tresses", cat: "Beauté & Mode" }, { name: "Atelier de confection", cat: "Beauté & Mode" }, { name: "Pressing", cat: "Beauté & Mode" }, { name: "Blanchisserie", cat: "Beauté & Mode" }, { name: "Teinturerie", cat: "Beauté & Mode" }, { name: "Photographe professionnel", cat: "Beauté & Mode" }, { name: "Studio photo", cat: "Beauté & Mode" }, { name: "Studio d'enregistrement", cat: "Beauté & Mode" }, { name: "Imprimerie", cat: "Beauté & Mode" }, { name: "Centre de photocopie", cat: "Beauté & Mode" }, { name: "Cybercafé", cat: "Beauté & Mode" },
      { name: "Service de secrétariat", cat: "Autres Services" }, { name: "Service de traduction", cat: "Autres Services" }, { name: "Service de rédaction", cat: "Autres Services" }, { name: "Service informatique", cat: "Autres Services" }, { name: "Service de dépannage", cat: "Autres Services" }, { name: "Service de livraison à domicile", cat: "Autres Services" }, { name: "Service de jardinage", cat: "Autres Services" }, { name: "Service de décoration", cat: "Autres Services" }, { name: "Service traiteur", cat: "Autres Services" }, { name: "Service de location de matériel", cat: "Autres Services" }, { name: "Service événementiel", cat: "Autres Services" }, { name: "Service de maintenance", cat: "Autres Services" }, { name: "Service de réparation", cat: "Autres Services" }, { name: "Service de nettoyage à domicile", cat: "Autres Services" }, { name: "Autres activités", cat: "Autres Services" }
    ];

    for (let m of metiersOfficiels) {
      await pool.query(`INSERT INTO professions (name, category) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING`, [m.name, m.cat]);
    }

    // --- INITIALISATION DE FIREBASE ---
    if (process.env.FIREBASE_PROJECT_ID) {
      admin.initializeApp({
        projectId: process.env.FIREBASE_PROJECT_ID,
      });
      console.log("🔥 Firebase connecté");
    }
    // --- CRÉATION DES COLONNES MANQUANTES POUR LES PROS ---
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS company_name VARCHAR(255)`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS phone_public BOOLEAN DEFAULT false`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS neighborhood VARCHAR(255)`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS experience VARCHAR(255)`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS service_area VARCHAR(255)`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS availability VARCHAR(255)`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS contact_preference VARCHAR(50)`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS contact_email VARCHAR(255)`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS whatsapp_number VARCHAR(50)`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS referred_by VARCHAR(50)`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS type_lieu VARCHAR(50)`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS adresse_exacte TEXT`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS horaires_json TEXT`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS referral_code VARCHAR(50)`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS referral_balance INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS unavailable_until DATE`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS photo_activite_url TEXT`);
    await pool.query(`ALTER TABLE professional_applications ADD COLUMN IF NOT EXISTS kyc_verified BOOLEAN DEFAULT false`);
    await pool.query(`ALTER TABLE reviews ADD COLUMN IF NOT EXISTS pro_reply TEXT`);
    await pool.query(`ALTER TABLE reviews ADD COLUMN IF NOT EXISTS pro_reply_date TIMESTAMP`);
    
    // --- CRÉATION DE LA TABLE POUR LES DONS ---
    await pool.query(`CREATE TABLE IF NOT EXISTS global_donations (
        id SERIAL PRIMARY KEY, 
        amount INTEGER, 
        donor_name VARCHAR(255), 
        transaction_id VARCHAR(255) UNIQUE, 
        created_at TIMESTAMP DEFAULT NOW()
    )`);
    
    // --- CRÉATION DE LA TABLE POUR LES CODES SMS (OTP) ---
    await pool.query(`CREATE TABLE IF NOT EXISTS otp_codes (
        phone VARCHAR(50) PRIMARY KEY, 
        code VARCHAR(10), 
        expires_at TIMESTAMP
    )`);

    // --- CRÉATION DES TABLES MANQUANTES ---
    await pool.query(`CREATE TABLE IF NOT EXISTS withdrawal_requests (
        id SERIAL PRIMARY KEY, pro_id INTEGER, amount INTEGER, phone_number VARCHAR(50), status VARCHAR(50) DEFAULT 'pending', created_at TIMESTAMP DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS contact_events (
        id SERIAL PRIMARY KEY, pro_id INTEGER, visitor_id VARCHAR(100), type VARCHAR(50), created_at TIMESTAMP DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS client_codes (
        visitor_id VARCHAR(100) PRIMARY KEY, code VARCHAR(50), full_name VARCHAR(255), phone VARCHAR(50), password_hash TEXT, created_at TIMESTAMP DEFAULT NOW()
    )`);
    
    await pool.query(`ALTER TABLE client_codes ADD COLUMN IF NOT EXISTS password_hash TEXT`);
    
    // --- MISE À JOUR DE LA TABLE CONTACT ---
    await pool.query(`ALTER TABLE contact_messages ADD COLUMN IF NOT EXISTS pro_id INTEGER`);
    await pool.query(`ALTER TABLE contact_messages ADD COLUMN IF NOT EXISTS report_id INTEGER`);
    await pool.query(`ALTER TABLE contact_messages ALTER COLUMN subject DROP NOT NULL`);
    
    console.log("✅ Base de données connectée");
    app.listen(PORT, "0.0.0.0", () => { console.log(`🚀 TrouveMoi démarré sur le port ${PORT}.`); });
  } catch (error) { console.error("❌ Erreur au démarrage :", error); process.exit(1); }
}
startServer();
