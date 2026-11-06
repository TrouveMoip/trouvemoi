const express = require('express');
const crypto = require('crypto');

module.exports = function(pool, page, requireAdmin, verifyCsrf, getCsrf, escapeHtml, adminMenu, verifySessionToken, readCookie, clearSessionCookie, createSessionToken, setSessionCookie, safeEqual, ADMIN_PASSWORD, verifyTotp, ADMIN_TOTP_SECRET, SESSION_COOKIE, SESSION_DURATION, logAdminAction) {
  const router = express.Router();

  router.get("/", async (req, res) => {
    const session = verifySessionToken(readCookie(req, SESSION_COOKIE));
    if (session?.jti) {
      const active = await pool.query(`SELECT 1 FROM admin_sessions WHERE jti = $1 AND revoked_at IS NULL AND expires_at > NOW()`, [session.jti]);
      if (active.rows.length) return res.redirect(303, "/admin/dashboard");
    }
    clearSessionCookie(res);
    res.send(page("Admin", `<section class="card" style="max-width: 400px; margin: 60px auto;"><h1 style="text-align:center;">Admin</h1><form action="/admin/login" method="POST"><label>Mot de passe</label><input type="password" name="password" required style="text-align:center; font-size:20px;"><label>Code de validation (6 chiffres)</label><input name="totp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required style="text-align:center; font-size:20px;"><button style="width:100%; margin-top:10px;">Connexion</button></form></section>`, null));
  });

  router.post("/login", async (req, res) => {
    if (!safeEqual(req.body.password || "", ADMIN_PASSWORD)) return res.status(401).send(page("Refuse", "<h2>Mot de passe incorrect.</h2>", null));
    if (!verifyTotp(ADMIN_TOTP_SECRET, req.body.totp)) return res.status(401).send(page("Refuse", "<h2>Code de validation incorrect.</h2>", null));
    
    const expiresAt = Date.now() + SESSION_DURATION;
    const jti = crypto.randomBytes(16).toString("hex");
    const session = { jti, expiresAt, csrf: crypto.randomBytes(32).toString("hex") };
    await pool.query(`INSERT INTO admin_sessions (jti, expires_at) VALUES ($1, to_timestamp($2 / 1000.0))`, [jti, expiresAt]);
    setSessionCookie(res, createSessionToken(session));
    res.redirect(303, "/admin/dashboard");
  });

  router.get("/dashboard", requireAdmin, async (req, res) => {
    const menu = await adminMenu("/admin/dashboard", getCsrf(req));
    res.send(page("Dashboard", `<h1>Tableau de bord</h1>${menu}`, null));
  });

  router.get("/agences", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT a.*, p.full_name AS parent_name FROM agencies a JOIN professional_applications p ON a.parent_pro_id = p.id WHERE a.status != 'pending_payment' ORDER BY a.created_at DESC`);
    const rows = result.rows.map(a => `<article class="card"><h2>${escapeHtml(a.name)}</h2>${a.status === 'pending_validation' ? `<form action="/admin/agences/${a.id}/statut" method="POST"><input type="hidden" name="csrfToken" value="${csrf}"><button name="status" value="approved" class="success">Approuver</button> <button name="status" value="rejected" class="danger">Refuser</button></form>` : ""}</article>`).join("");
    res.send(page("Agences", `<h1>Agences</h1>${await adminMenu("/admin/agences", csrf)}${rows}`, null));
  });

  router.post("/agences/:id/statut", requireAdmin, verifyCsrf, async (req, res) => {
    await pool.query(`UPDATE agencies SET status = $1, updated_at = NOW() WHERE id = $2`, [req.body.status, Number(req.params.id)]);
    res.redirect(303, "/admin/agences");
  });

  router.get("/retraits", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT w.*, p.full_name FROM withdrawal_requests w JOIN professional_applications p ON p.id = w.pro_id ORDER BY w.created_at DESC`);
    const rows = result.rows.map(w => `<article class="card"><h2>${escapeHtml(w.full_name)} - ${w.amount} FCFA</h2>${w.status === 'pending' ? `<form action="/admin/retraits/${w.id}/approuver" method="POST"><input type="hidden" name="csrfToken" value="${csrf}"><button class="success">Approuver</button></form>` : w.status}</article>`).join("");
    res.send(page("Retraits", `<h1>Retraits</h1>${await adminMenu("/admin/retraits", csrf)}${rows}`, null));
  });

  router.post("/retraits/:id/approuver", requireAdmin, verifyCsrf, async (req, res) => {
    await pool.query(`UPDATE withdrawal_requests SET status = 'processed' WHERE id = $1`, [Number(req.params.id)]);
    res.redirect(303, "/admin/retraits");
  });

  router.get("/messages", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT * FROM contact_messages ORDER BY created_at DESC`);
    const messages = result.rows.map(m => `<article class="card"><h2>${escapeHtml(m.name)}</h2><p>${escapeHtml(m.email)}</p><p>${escapeHtml(m.message)}</p></article>`).join("");
    await pool.query(`UPDATE contact_messages SET is_read = true WHERE is_read = false`);
    res.send(page("Messages", `<h1>Messages</h1>${await adminMenu("/admin/messages", csrf)}${messages}`, null));
  });

  router.post("/logout", requireAdmin, verifyCsrf, async (req, res) => {
    await pool.query(`UPDATE admin_sessions SET revoked_at = NOW() WHERE jti = $1`, [req.adminSession.jti]).catch(() => {});
    clearSessionCookie(res); res.redirect(303, "/admin");
  });

  return router;
};
