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
    res.send(page("Admin", `<section class="card" style="max-width: 400px; margin: 60px auto;"><h1 style="text-align:center;">Admin</h1><form action="/admin/login" method="POST"><label>Mot de passe</label><input type="password" name="password" required><label>Code de validation (6 chiffres)</label><input name="totp" required maxlength="6"><button style="width:100%;">Connexion</button></form></section>`, null));
  });

  router.post("/login", async (req, res) => {
    if (!safeEqual(req.body.password || "", ADMIN_PASSWORD)) return res.status(401).send(page("Refuse", "<h2>Mot de passe incorrect.</h2>", null));
    
    // Note: On utilise verifyTotp passé depuis server.js
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
    res.send(page("Dashboard", `<h1>Tableau de bord</h1>${menu}<p>Bienvenue dans votre espace d'administration.</p>`, null));
  });

  router.get("/agences", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT a.*, p.full_name AS parent_name FROM agencies a JOIN professional_applications p ON a.parent_pro_id = p.id WHERE a.status != 'pending_payment' ORDER BY a.created_at DESC`);
    const rows = result.rows.map(a => `
      <article class="card" style="margin-bottom:20px; border-left: 4px solid #8b5cf6;">
        <h2>${escapeHtml(a.name)}</h2><p>Réseau : ${escapeHtml(a.parent_name)}</p><p>Statut : ${a.status}</p>
        ${a.status === 'pending_validation' ? `<form action="/admin/agences/${a.id}/statut" method="POST"><input type="hidden" name="csrfToken" value="${csrf}"><button name="status" value="approved" class="success">Approuver</button> <button name="status" value="rejected" class="danger">Refuser</button></form>` : ""}
      </article>`).join("");
    const menu = await adminMenu("/admin/agences", csrf);
    res.send(page("Agences", `<h1>Gestion des Agences</h1>${menu}${rows}`, null));
  });

  router.post("/agences/:id/statut", requireAdmin, verifyCsrf, async (req, res) => {
    await pool.query(`UPDATE agencies SET status = $1, updated_at = NOW() WHERE id = $2`, [req.body.status, Number(req.params.id)]);
    res.redirect(303, "/admin/agences");
  });

  router.post("/logout", requireAdmin, verifyCsrf, async (req, res) => {
    await pool.query(`UPDATE admin_sessions SET revoked_at = NOW() WHERE jti = $1`, [req.adminSession.jti]).catch(() => {});
    clearSessionCookie(res); res.redirect(303, "/admin");
  });

  // Route pour les messages
  router.get("/messages", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT * FROM contact_messages ORDER BY created_at DESC`);
    const messages = result.rows.map(m => `<article class="card" style="margin-bottom:20px;"><h2 style="font-size:18px;">${escapeHtml(m.name)}</h2><p class="muted" style="font-size:14px;">Email : ${escapeHtml(m.email)} ${m.phone ? `| Tel : ${escapeHtml(m.phone)}` : ""}</p><p style="background:#f9fafb; padding:16px; border-radius:12px; margin:16px 0;">${escapeHtml(m.message)}</p><p class="muted" style="font-size:12px;">Reçu le ${new Date(m.created_at).toLocaleString("fr-FR")}</p></article>`).join("");
    const menu = await adminMenu("/admin/messages", csrf);
    await pool.query(`UPDATE contact_messages SET is_read = true WHERE is_read = false`);
    res.send(page("Messages", `<h1 style="text-align:center; margin-bottom:30px;">Messages</h1>${menu}${messages || '<section class="card"><p class="muted" style="text-align:center;">Aucun message.</p></section>'}`, null));
  });

  return router;
};
