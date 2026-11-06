const express = require('express');
const crypto = require('crypto');

module.exports = function(pool, page, requireAdmin, verifyCsrf, getCsrf, escapeHtml, adminMenu, verifySessionToken, readCookie, clearSessionCookie, createSessionToken, setSessionCookie, safeEqual, ADMIN_PASSWORD, verifyTotp, ADMIN_TOTP_SECRET, SESSION_COOKIE, SESSION_DURATION, logAdminAction) {
  const router = express.Router();

  // LA FONCTION adminMenu COMPLETE AVEC TOUS LES BOUTONS
  async function customAdminMenu(current, csrf) {
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
      { href: "/admin/agences", label: "🏢 Agences", badge: 0 },
      { href: "/admin/avis", label: "⭐ Avis", badge: reviewsPendingCount }, 
      { href: "/admin/signalisations", label: "🚩 Signalements", badge: reportsCount }, 
      { href: "/admin/emplois", label: "💼 Offres", badge: 0 }, 
      { href: "/admin/messages", label: "📩 Messages", badge: msgsCount }, 
      { href: "/admin/rgpd", label: "🔐 RGPD", badge: gdprCount },
      { href: "/admin/retraits", label: "💸 Retraits", badge: withdrawalsCount },
      { href: "/admin/dons", label: "❤️ Dons", badge: 0 },
      { href: "/admin/blog", label: "📝 Blog", badge: 0 },
      { href: "/admin/logs", label: "🗂️ Journal", badge: 0 },
      { href: "/admin/qrcode", label: "📱 QR Code", badge: 0 },
      { href: "/admin/notifications", label: "📨 Notifications", badge: notificationsFailed }
    ];
    return `<section class="card" style="background:#f9fafb; border:1px solid #e5e7eb; padding:16px;"><div class="actions" style="justify-content:center; gap:10px; display:flex; flex-wrap:wrap;">${links.map(l => `<a class="button ${current === l.href ? "" : "secondary"}" href="${l.href}" style="padding:8px 16px; font-size:14px; margin:0;">${l.label}${l.badge > 0 ? ` <span class="badge badge-new" style="background:red; color:white; padding:2px 6px; border-radius:10px; font-size:10px;">${l.badge}</span>` : ""}</a>`).join("")}</div><div style="text-align:center; margin-top:20px;"><form action="/admin/logout" method="POST"><input type="hidden" name="csrfToken" value="${escapeHtml(csrf)}"><button class="danger" style="padding:8px 24px; font-size:14px; margin:0;">Déconnexion</button></form></div></section>`;
  }

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
    const stats = {
      pros: Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status = 'approved'")).rows[0].count),
      prosPending: Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status IN ('pending', 'under_review', 'corrections_requested')")).rows[0].count),
      reviews: Number((await pool.query("SELECT COUNT(*) FROM reviews WHERE status = 'pending'")).rows[0].count),
      messages: Number((await pool.query("SELECT COUNT(*) FROM contact_messages WHERE is_read = false")).rows[0].count),
      prosToday: Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE DATE(created_at) = CURRENT_DATE")).rows[0].count)
    };
    const menu = await customAdminMenu("/admin/dashboard", getCsrf(req));
    res.send(page("Dashboard", `<h1 style="text-align:center; margin-bottom:30px;">Tableau de bord</h1>${menu}<div class="stats-grid" style="margin-top:30px;"><div class="stat-card"><div class="stat-number">${stats.pros}</div><div class="stat-label">Approuvés</div></div><div class="stat-card warning"><div class="stat-number">${stats.prosPending}</div><div class="stat-label">En attente</div></div><div class="stat-card danger"><div class="stat-number">${stats.reviews}</div><div class="stat-label">Avis</div></div><div class="stat-card info"><div class="stat-number">${stats.messages}</div><div class="stat-label">Messages</div></div><div class="stat-card success"><div class="stat-number" style="color: #059669;">${stats.prosToday}</div><div class="stat-label">Aujourd'hui</div></div></div>`, null));
  });

 // ==========================================
  // GESTION DES AGENCES (Admin)
  // ==========================================
  router.get("/agences", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT a.*, p.full_name AS parent_name FROM agencies a JOIN professional_applications p ON a.parent_pro_id = p.id WHERE a.status != 'pending_payment' ORDER BY a.created_at DESC`);
    const rows = result.rows.map(a => `
      <article class="card" style="margin-bottom:20px; border-left: 4px solid #8b5cf6;">
        <div style="display:flex; justify-content:space-between;">
          <div><h2 style="font-size:18px;">${escapeHtml(a.name)}</h2><p class="muted" style="font-size:14px;">Réseau : <strong>${escapeHtml(a.parent_name)}</strong></p><p style="font-size:13px;">📍 ${escapeHtml(a.address)}</p></div>
          <div>${a.status === 'pending_validation' ? `<span class="badge" style="background:#fef3c7;color:#92400e;">⏳ À valider</span>` : a.status === 'approved' ? `<span class="badge" style="background:#d1fae5;color:#065f46;">✅ Validée</span>` : `<span class="badge" style="background:#fee2e2;color:#991b1b;">❌ Refusée</span>`}</div>
        </div>
        ${a.status === 'pending_validation' ? `<div style="margin-top:15px; display:flex; gap:10px;"><form action="/admin/agences/${a.id}/statut" method="POST" style="margin:0;"><input type="hidden" name="csrfToken" value="${csrf}"><button name="status" value="approved" class="success">Approuver</button></form><form action="/admin/agences/${a.id}/statut" method="POST" style="margin:0;"><input type="hidden" name="csrfToken" value="${csrf}"><button name="status" value="rejected" class="danger">Refuser</button></form></div>` : ""}
      </article>`).join("");
    res.send(page("Agences", `<h1 style="text-align:center; margin-bottom:20px;">Gestion des Agences</h1>${await customAdminMenu("/admin/agences", csrf)}${rows || "<p>Aucune agence.</p>"}`, null));
  });

  router.post("/agences/:id/statut", requireAdmin, verifyCsrf, async (req, res) => {
    if (["approved", "rejected"].includes(req.body.status)) {
      await pool.query(`UPDATE agencies SET status = $1, updated_at = NOW() WHERE id = $2`, [req.body.status, Number(req.params.id)]);
      await logAdminAction(`agency_${req.body.status}`, "agency", Number(req.params.id), null);
    }
    res.redirect(303, "/admin/agences");
  });

  // ==========================================
  // SUIVI & EXPORT
  // ==========================================
  router.get("/suivi", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT id, full_name, phone, npi, city, profession, status, payment_status, created_at, pro_code FROM professional_applications ORDER BY created_at DESC LIMIT 50`);
    const rows = result.rows.map(p => `<tr style="border-bottom:1px solid #e5e7eb;"><td style="padding:12px; font-size:13px;">${new Date(p.created_at).toLocaleDateString("fr-FR")}</td><td style="padding:12px;"><div style="font-weight:700;">${escapeHtml(p.full_name)}</div><div style="font-size:12px; color:#6b7280;">${escapeHtml(p.phone)}</div></td><td style="padding:12px;">${escapeHtml(p.profession)}<br><span style="color:#6b7280; font-size:11px;">${escapeHtml(p.city)}</span></td><td style="padding:12px;">${p.payment_status === 'paid' ? '💳 Payé' : '⏳ Impayé'}</td><td style="padding:12px;"><code>${escapeHtml(p.pro_code || "—")}</code></td></tr>`).join("");
    res.send(page("Suivi", `<h1 style="text-align:center;">Tableau de suivi</h1>${await customAdminMenu("/admin/suivi", csrf)}<section class="card" style="margin-top:20px; overflow-x:auto;"><table style="width:100%; border-collapse:collapse;"><thead><tr style="background:#f9fafb;"><th>Date</th><th>Professionnel</th><th>Métier</th><th>Paiement</th><th>Code Pro</th></tr></thead><tbody>${rows}</tbody></table></section>`, null));
  });

  router.get("/suivi/export", requireAdmin, async (req, res) => {
    const result = await pool.query(`SELECT full_name, phone, npi, city, profession, status, payment_status, created_at, pro_code FROM professional_applications ORDER BY created_at DESC`);
    let csv = "Date;Nom;Telephone;NPI;Ville;Metier;Statut;Paiement;Code Pro\n";
    for (const p of result.rows) {
      const clean = (val) => `"${String(val ?? "").replace(/"/g, '""')}"`;
      csv += `${new Date(p.created_at).toLocaleDateString("fr-FR")};${clean(p.full_name)};${clean(p.phone)};${clean(p.npi)};${clean(p.city)};${clean(p.profession)};${clean(p.status)};${clean(p.payment_status)};${clean(p.pro_code)}\n`;
    }
    res.setHeader("Content-Type", "text/csv; charset=utf-8"); res.setHeader("Content-Disposition", `attachment; filename="suivi_${new Date().toISOString().slice(0,10)}.csv"`); res.send("\uFEFF" + csv);
  });

  // ==========================================
  // PROXY KYC
  // ==========================================
  const KYC_FIELDS = new Set(["photo_profil_url", "photo_identite_url", "photo_kyc_url"]);
  router.get("/kyc/:id/:field", requireAdmin, async (req, res) => {
    const id = Number(req.params.id); const field = String(req.params.field || "");
    if (!Number.isSafeInteger(id) || id < 1 || !KYC_FIELDS.has(field)) return res.status(404).send("Not found");
    try {
      const result = await pool.query(`SELECT ${field} AS url FROM professional_applications WHERE id = $1`, [id]);
      const url = result.rows[0]?.url;
      if (!url || !/^https:\/\/res\.cloudinary\.com\//.test(url)) return res.status(404).send("Not found");
      const upstream = await fetch(url, { redirect: "follow" });
      if (!upstream.ok) return res.status(404).send("Not found");
      const buffer = Buffer.from(await upstream.arrayBuffer());
      res.setHeader("Content-Type", upstream.headers.get("content-type") || "image/jpeg"); res.setHeader("Cache-Control", "private, no-store"); res.send(buffer);
    } catch (error) { res.status(502).send("Bad gateway"); }
  });

  // ==========================================
  // CANDIDATURES
  // ==========================================
  router.get("/candidatures", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT p.* FROM professional_applications p ORDER BY CASE WHEN p.status = 'payment_pending' THEN 0 WHEN p.status = 'pending' THEN 1 ELSE 2 END, p.created_at DESC LIMIT 20`);
    const apps = result.rows.map(c => `<details class="admin-details"><summary class="admin-summary"><div class="admin-summary-info"><div><strong style="font-size:16px;">${escapeHtml(c.full_name)}</strong> <span style="color:#6b7280;">— ${escapeHtml(c.profession)}</span></div><div><span class="badge badge-${c.status}">${c.status === 'payment_pending' ? '⏳ Attente paie' : c.status}</span></div></div></summary><div class="admin-content"><p>Téléphone: ${escapeHtml(c.phone)} | NPI: ${escapeHtml(c.npi)}</p><div style="display:flex; gap:10px;">${c.photo_profil_url ? `<img src="/admin/kyc/${c.id}/photo_profil_url" style="width:80px;height:80px;object-fit:cover;border-radius:8px;">` : ""}${c.photo_kyc_url ? `<img src="/admin/kyc/${c.id}/photo_kyc_url" style="width:80px;height:80px;object-fit:cover;border-radius:8px;">` : ""}</div><form action="/admin/candidatures/${c.id}/status" method="POST" style="margin-top:16px;"><input type="hidden" name="csrfToken" value="${csrf}"><select name="status"><option value="approved">Approuver</option><option value="rejected">Rejeter</option></select><input name="rejection_reason" placeholder="Motif"><button type="submit">Valider</button></form></div></details>`).join("");
    res.send(page("Candidatures", `<h1>Candidatures</h1>${await customAdminMenu("/admin/candidatures", csrf)}${apps}`, null));
  });

  router.post("/candidatures/:id/status", requireAdmin, verifyCsrf, async (req, res) => {
    const id = Number(req.params.id); const status = req.body.status; const reason = req.body.rejection_reason || null;
    if (status === "approved") {
      const newCode = await generateUniqueProCode(); 
      await pool.query(`UPDATE professional_applications SET status = $1, pro_code = $2, kyc_verified = true WHERE id = $3`, [status, newCode, id]);
    } else {
      await pool.query(`UPDATE professional_applications SET status = $1, rejection_reason = $2 WHERE id = $3`, [status, reason, id]);
      if (status === "rejected") await pool.query(`UPDATE job_offers SET status = 'closed' WHERE pro_id = $1`, [id]);
    }
    res.redirect(303, "/admin/candidatures");
  });

  // ==========================================
  // AVIS & SIGNALEMENTS
  // ==========================================
  router.get("/avis", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT r.*, p.full_name AS pro_name FROM reviews r LEFT JOIN professional_applications p ON p.id = r.pro_id ORDER BY CASE WHEN r.status = 'pending' THEN 0 ELSE 1 END, r.created_at DESC LIMIT 50`);
    const rows = result.rows.map(r => `<article class="card"><h2>${escapeHtml(r.author_name)}</h2><p>Avis sur : ${escapeHtml(r.pro_name)}</p><p>"${escapeHtml(r.comment || "")}"</p><form action="/admin/avis/${r.id}/statut" method="POST"><input type="hidden" name="csrfToken" value="${csrf}"><button name="status" value="approved" class="success">Approuver</button> <button name="status" value="rejected" class="danger">Rejeter</button></form></article>`).join("");
    res.send(page("Avis", `<h1>Avis</h1>${await customAdminMenu("/admin/avis", csrf)}${rows}`, null));
  });

  router.post("/avis/:id/statut", requireAdmin, verifyCsrf, async (req, res) => {
    if (["pending", "approved", "rejected"].includes(req.body.status)) await pool.query(`UPDATE reviews SET status = $1 WHERE id = $2`, [req.body.status, Number(req.params.id)]);
    res.redirect(303, "/admin/avis");
  });

  // MESSAGES
  router.get("/messages", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT * FROM contact_messages ORDER BY created_at DESC`);
    const msgs = result.rows.map(m => `<article class="card"><h2>${escapeHtml(m.name)}</h2><p>Email: ${escapeHtml(m.email)} | Tel: ${escapeHtml(m.phone || "-")}</p><p style="background:#f9fafb; padding:10px;">${escapeHtml(m.message)}</p></article>`).join("");
    await pool.query(`UPDATE contact_messages SET is_read = true WHERE is_read = false`);
    res.send(page("Messages", `<h1>Messages</h1>${await customAdminMenu("/admin/messages", csrf)}${msgs}`, null));
  });

  // RETRAITS & RGPD
  router.get("/retraits", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT w.*, p.full_name FROM withdrawal_requests w JOIN professional_applications p ON p.id = w.pro_id ORDER BY w.created_at DESC`);
    const rows = result.rows.map(w => `<article class="card"><h2>${escapeHtml(w.full_name)} - ${w.amount} FCFA</h2><p>Numéro: ${escapeHtml(w.phone_number)}</p>${w.status === 'pending' ? `<form action="/admin/retraits/${w.id}/approuver" method="POST"><input type="hidden" name="csrfToken" value="${csrf}"><button class="success">Approuver</button></form>` : `<span class="badge">${w.status}</span>`}</article>`).join("");
    res.send(page("Retraits", `<h1>Retraits</h1>${await customAdminMenu("/admin/retraits", csrf)}${rows}`, null));
  });

  router.post("/retraits/:id/approuver", requireAdmin, verifyCsrf, async (req, res) => {
    await pool.query(`UPDATE withdrawal_requests SET status = 'processed' WHERE id = $1 AND status = 'pending'`, [Number(req.params.id)]);
    res.redirect(303, "/admin/retraits");
  });

  router.get("/rgpd", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT g.*, p.full_name AS pro_name FROM gdpr_requests g LEFT JOIN professional_applications p ON p.id = g.pro_id ORDER BY g.created_at DESC`);
    const rows = result.rows.map(r => `<article class="card"><h2>${r.request_type} - ${escapeHtml(r.pro_name || "Inconnu")}</h2><p>Statut: ${r.status}</p>${r.status === "pending" ? `<form action="/admin/rgpd/${r.id}/traiter" method="POST"><input type="hidden" name="csrfToken" value="${csrf}"><button class="success">Traiter</button></form>` : ""}</article>`).join("");
    res.send(page("RGPD", `<h1>RGPD</h1>${await customAdminMenu("/admin/rgpd", csrf)}${rows}`, null));
  });

  router.post("/rgpd/:id/traiter", requireAdmin, verifyCsrf, async (req, res) => {
    await pool.query(`UPDATE gdpr_requests SET status = 'processed', processed_at = NOW() WHERE id = $1`, [Number(req.params.id)]);
    res.redirect(303, "/admin/rgpd");
  });

  // DÉCONNEXION
  router.post("/logout", requireAdmin, verifyCsrf, async (req, res) => {
    await pool.query(`UPDATE admin_sessions SET revoked_at = NOW() WHERE jti = $1`, [req.adminSession.jti]).catch(() => {});
    clearSessionCookie(res); res.redirect(303, "/admin");
  });

  return router;
};
