const express = require('express');
const crypto = require('crypto');

module.exports = function(pool, page, requireAdmin, verifyCsrf, getCsrf, escapeHtml, adminMenu, verifySessionToken, readCookie, clearSessionCookie, createSessionToken, setSessionCookie, safeEqual, ADMIN_PASSWORD, verifyTotp, ADMIN_TOTP_SECRET, SESSION_COOKIE, SESSION_DURATION, logAdminAction, generateUniqueProCode, deleteFromCloudinary,sendSMS) {
  const router = express.Router();

  // LA FONCTION adminMenu COMPLETE AVEC TOUS LES BOUTONS
  async function customAdminMenu(current, csrf) {
    let gdprCount = 0, prosPendingCount = 0, reviewsPendingCount = 0, msgsCount = 0, withdrawalsCount = 0, reportsCount = 0, notificationsFailed = 0, jobsPendingCount = 0;
    try {
      gdprCount = Number((await pool.query("SELECT COUNT(*) FROM gdpr_requests WHERE status = 'pending'")).rows[0].count);
      prosPendingCount = Number((await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status IN ('pending', 'under_review', 'corrections_requested')")).rows[0].count);
      reviewsPendingCount = Number((await pool.query("SELECT COUNT(*) FROM reviews WHERE status = 'pending'")).rows[0].count);
      msgsCount = Number((await pool.query("SELECT COUNT(*) FROM contact_messages WHERE is_read = false")).rows[0].count);
      withdrawalsCount = Number((await pool.query("SELECT COUNT(*) FROM withdrawal_requests WHERE status = 'pending'")).rows[0].count);
      reportsCount = Number((await pool.query("SELECT COUNT(*) FROM review_reports WHERE status = 'pending'")).rows[0].count);
      notificationsFailed = Number((await pool.query("SELECT COUNT(*) FROM notifications WHERE status = 'failed'")).rows[0].count);
      jobsPendingCount = Number((await pool.query("SELECT COUNT(*) FROM job_offers WHERE status = 'pending'")).rows[0].count);
    } catch (e) {}

    const links = [
      { href: "/admin/dashboard", label: "📊 Dashboard", badge: 0 }, 
      { href: "/admin/suivi", label: "📈 Suivi & Export", badge: 0 }, 
      { href: "/admin/candidatures", label: "📋 Candidatures", badge: prosPendingCount }, 
      { href: "/admin/agences", label: "🏢 Agences", badge: 0 },
      { href: "/admin/avis", label: "⭐ Avis", badge: reviewsPendingCount }, 
      { href: "/admin/signalisations", label: "🚩 Signalements", badge: reportsCount }, 
      { href: "/admin/emplois", label: "💼 Offres", badge: jobsPendingCount }, 
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
    
    res.send(page("Admin", `
      <section class="card" style="max-width: 400px; margin: 60px auto;">
        <h1 style="text-align:center;">Admin</h1>
        <form action="/admin/login" method="POST">
          <label>Mot de passe</label>
          <div style="position:relative; margin-bottom:15px;">
            <input type="password" name="password" id="pass-input" required style="text-align:center; font-size:20px; padding-right: 40px;">
            <span onclick="document.getElementById('pass-input').type = document.getElementById('pass-input').type === 'password' ? 'text' : 'password'" style="position:absolute; right:15px; top:50%; transform:translateY(-50%); cursor:pointer; color:#6b7280; font-size:20px;">👁️</span>
          </div>
          
          <label>Code de validation (6 chiffres)</label>
          <div style="position:relative; margin-bottom:20px;">
            <input type="text" name="totp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" id="totp-input" required style="text-align:center; font-size:20px; letter-spacing:4px; padding-right: 40px;">
            <span onclick="document.getElementById('totp-input').type = document.getElementById('totp-input').type === 'text' ? 'password' : 'text'" style="position:absolute; right:15px; top:50%; transform:translateY(-50%); cursor:pointer; color:#6b7280; font-size:20px;">👁️</span>
          </div>
          
          <button style="width:100%; margin-top:10px;">Connexion</button>
        </form>
      </section>
    `, null));
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
    try {
      if (["approved", "rejected"].includes(req.body.status)) {
        await pool.query(`UPDATE agencies SET status = $1, updated_at = NOW() WHERE id = $2`, [req.body.status, Number(req.params.id)]);
        await logAdminAction(`agency_${req.body.status}`, "agency", Number(req.params.id), null);
      }
    } catch (e) { console.error("Erreur agence admin:", e); }
    res.redirect(303, "/admin/agences");
  });

  // ==========================================
  // SUIVI DES PROS & EXPORT
  // ==========================================
  router.get("/suivi", requireAdmin, async (req, res) => {
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
      return `
        <tr style="border-bottom: 1px solid #e5e7eb;">
          <td style="padding: 12px; font-size: 13px;">${dateStr}</td>
          <td style="padding: 12px;">
            <div style="font-weight: 700; color: #111827;">${escapeHtml(p.full_name)}</div>
            <div style="font-size: 12px; color: #6b7280;">${escapeHtml(p.phone)}</div>
          </td>
          <td style="padding: 12px; font-size: 13px;">${escapeHtml(p.profession)}<br><span style="color:#6b7280; font-size:11px;">${escapeHtml(p.city)}</span></td>
          <td style="padding: 12px; font-size: 13px;"><code>${escapeHtml(p.npi)}</code></td>
          <td style="padding: 12px; font-size: 13px;">${paymentBadge}</td>
          <td style="padding: 12px; font-size: 13px;"><code>${escapeHtml(p.pro_code || "—")}</code></td>
        </tr>
      `;
    }).join("");

    const menu = await customAdminMenu("/admin/suivi", csrf);
    
    res.send(page("Suivi des Pros", `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 10px;">
        <h1 style="margin: 0;">Tableau de suivi</h1>
        <a href="/admin/suivi/export" class="button success" style="margin: 0; padding: 12px 24px; font-size: 14px;">📥 Exporter pour Excel (CSV)</a>
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
              <th style="padding: 12px; font-size: 12px; color: #6b7280; text-transform: uppercase;">Paiement</th>
              <th style="padding: 12px; font-size: 12px; color: #6b7280; text-transform: uppercase;">Code Pro</th>
            </tr>
          </thead>
          <tbody>
            ${rowsHtml || `<tr><td colspan="6" style="text-align: center; padding: 20px; color: #6b7280;">Aucun professionnel enregistré.</td></tr>`}
          </tbody>
        </table>
      </section>
    `, null));
  });

  router.get("/suivi/export", requireAdmin, async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT full_name, company_name, phone, npi, city, profession, status, payment_status, created_at, tracking_code, pro_code 
        FROM professional_applications 
        ORDER BY created_at DESC
      `);

      let csv = "Date;Nom;Entreprise;Telephone;NPI;Ville;Metier;Statut;Paiement;Code de suivi;Code Pro\n";
      for (const p of result.rows) {
        const dateStr = new Date(p.created_at).toLocaleDateString("fr-FR");
        const payment = p.payment_status === 'paid' ? 'Payé' : p.payment_status === 'refunded' ? 'Remboursé' : 'Impayé';
        const clean = (val) => `"${String(val ?? "").replace(/"/g, '""')}"`;
        csv += `${dateStr};${clean(p.full_name)};${clean(p.company_name)};${clean(p.phone)};${clean(p.npi)};${clean(p.city)};${clean(p.profession)};${clean(p.status)};${payment};${clean(p.tracking_code)};${clean(p.pro_code)}\n`;
      }

      res.setHeader("Content-Type", "text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="suivi_professionnels_${new Date().toISOString().slice(0,10)}.csv"`);
      res.send("\uFEFF" + csv);
    } catch (error) { res.status(500).send("Erreur lors de l'export."); }
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
    const result = await pool.query(`
      SELECT p.*, pr.category AS profession_category 
      FROM professional_applications p
      LEFT JOIN professions pr ON p.profession = pr.name
      WHERE p.status != 'payment_pending' 
      ORDER BY CASE WHEN p.status = 'pending' THEN 0 ELSE 1 END, p.created_at DESC LIMIT 50
    `);
    
    const apps = result.rows.map(c => {
      const photos = `
        <div style="display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px;">
          ${c.photo_profil_url ? `<div style="text-align:center;"><img src="/admin/kyc/${c.id}/photo_profil_url" style="width:100px; height:100px; object-fit:cover; border-radius:8px; border:2px solid #3b82f6; cursor:pointer;" onclick="zoomImage(this.src)"><div style="font-size:11px; margin-top:4px; font-weight:600;">Visage</div></div>` : ""}
          ${c.photo_identite_url ? `<div style="text-align:center;"><img src="/admin/kyc/${c.id}/photo_identite_url" style="width:100px; height:100px; object-fit:cover; border-radius:8px; border:2px solid #ef4444; cursor:pointer;" onclick="zoomImage(this.src)"><div style="font-size:11px; margin-top:4px; font-weight:600;">Pièce d'identité</div></div>` : ""}
          ${c.photo_kyc_url ? `<div style="text-align:center;"><img src="/admin/kyc/${c.id}/photo_kyc_url" style="width:100px; height:100px; object-fit:cover; border-radius:8px; border:2px solid #f59e0b; cursor:pointer;" onclick="zoomImage(this.src)"><div style="font-size:11px; margin-top:4px; font-weight:600; color:#b45309;">KYC (Visage + Pièce)</div></div>` : ""}
        </div>`;

      let codeBlock = "";
      if (c.status === 'approved' && c.pro_code) {
        const waNumber = c.whatsapp_number || c.phone;
        const cleanWa = String(waNumber).replace(/[()\s.-]/g, "").replace(/^\+/, "");
        const waMessage = encodeURIComponent(`Bonjour ${c.full_name}, votre candidature sur TrouveMoi a été approuvée ✅\n\nVotre code de connexion est : ${c.pro_code}\n\nConnectez-vous ici : https://trouvemoi.bj/mon-espace-pro`);  
        codeBlock = `
          <div style="background:#eff6ff; padding:16px; border-radius:12px; border:1px solid #bfdbfe; margin-bottom:16px;">
            <div style="font-size:12px; color:#1e40af; text-transform:uppercase; font-weight:700; margin-bottom:5px;">Code de connexion généré</div>
            <div style="font-size:28px; font-weight:800; font-family:monospace; color:#1e3a8a; letter-spacing:2px; margin-bottom:12px;">${escapeHtml(c.pro_code)}</div>
            <div style="display:flex; gap:10px;">
              <a href="https://wa.me/${cleanWa}?text=${waMessage}" target="_blank" class="button whatsapp" style="font-size:13px; padding:8px 16px; margin:0; flex:1; text-align:center;">📱 Envoyer par WhatsApp</a>
            </div>
          </div>
        `;
      }
      
      let actionButtons = "";
      if (c.status === 'pending' || c.status === 'under_review') {
        actionButtons = `
          <div style="display:flex; gap:10px; margin-top:20px; border-top:1px solid #e5e7eb; padding-top:15px;">
            <form action="/admin/candidatures/${c.id}/status" method="POST" style="margin:0; flex:1;">
              <input type="hidden" name="csrfToken" value="${csrf}">
              <input type="hidden" name="status" value="approved">
              <button class="success" style="width:100%; padding:12px; font-size:14px;">✅ Approuver le dossier</button>
            </form>
            <form action="/admin/candidatures/${c.id}/status" method="POST" style="margin:0; flex:1;">
              <input type="hidden" name="csrfToken" value="${csrf}">
              <input type="hidden" name="status" value="rejected">
              <div style="display:flex; gap:8px;">
                <input name="rejection_reason" placeholder="Motif du refus..." style="margin:0; padding:10px; font-size:13px; flex:1;">
                <button class="danger" style="padding:12px; font-size:14px; margin:0;">❌ Rejeter</button>
              </div>
            </form>
          </div>`;
      } else {
        const statusLabel = c.status === 'approved' ? '✅ Approuvé' : c.status === 'rejected' ? '❌ Rejeté' : c.status === 'payment_pending' ? '⏳ En attente de paiement' : c.status;
        actionButtons = `
          <div style="margin-top:15px; padding:10px; background:#f9fafb; border-radius:8px; text-align:center; font-weight:bold; color:#374151;">
            Statut actuel : ${statusLabel}
          </div>
          ${codeBlock}
        `;
      }

      return `
        <details class="admin-details">
          <summary class="admin-summary">
            <div class="admin-summary-info">
              <div style="display:flex; align-items:center; gap:15px;">
                ${c.photo_profil_url ? `<img src="/admin/kyc/${c.id}/photo_profil_url" style="width:40px; height:40px; object-fit:cover; border-radius:50%; border:2px solid #3b82f6;">` : ""}
                <div>
                  <strong style="font-size:16px; color:#111827;">${escapeHtml(c.full_name)}</strong> 
                  <span style="color:#6b7280; font-size:14px; margin-left:5px;">— ${escapeHtml(c.profession)}</span>
                </div>
              </div>
              <div>
                <span class="badge" style="background:${c.status === 'approved' ? '#d1fae5' : c.status === 'rejected' ? '#fee2e2' : '#fef3c7'}; color:${c.status === 'approved' ? '#065f46' : c.status === 'rejected' ? '#991b1b' : '#92400e'};">
                  ${c.status === 'approved' ? 'Approuvé' : c.status === 'rejected' ? 'Refusé' : c.status === 'payment_pending' ? 'Attente Paiement' : 'En attente'}
                </span>
              </div>
            </div>
            <div style="margin-left:15px; color:#9ca3af; font-size:20px;">▼</div>
          </summary>
          <div class="admin-content">
            ${photos}
            
            <div style="background:#f8fafc; padding:16px; border-radius:12px; border:1px solid #e5e7eb; font-size:14px; margin-bottom:15px;">
              <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                <p><strong>Téléphone :</strong> ${escapeHtml(c.phone)}</p>
                <p><strong>NPI :</strong> ${escapeHtml(c.npi)}</p>
                <p><strong>Catégorie :</strong> <span class="badge" style="background:#eff6ff; color:#1e40af;">${escapeHtml(c.profession_category || 'Non classée')}</span></p>
                <p><strong>Ville :</strong> ${escapeHtml(c.city)}</p>
                <p><strong>Quartier :</strong> ${escapeHtml(c.neighborhood || "-")}</p>
                <p><strong>Email :</strong> ${escapeHtml(c.contact_email || "-")}</p>
                <p><strong>Code suivi :</strong> <code>${escapeHtml(c.tracking_code)}</code></p>
              </div>
            </div>
            
            ${actionButtons}
          </div>
        </details>
      `;
    }).join("");

    res.send(page("Candidatures", `
      <h1 style="text-align:center; margin-bottom:20px;">Gestion des Candidatures</h1>
      ${await customAdminMenu("/admin/candidatures", csrf)}
      <div style="margin-top:20px;">${apps || "<p>Aucune candidature.</p>"}</div>
    `, null));
  });

 router.post("/candidatures/:id/status", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id); 
  const status = req.body.status; 
  const reason = req.body.rejection_reason || null;
  
  try {
    if (status === "approved") {
      const newCode = await generateUniqueProCode(); 
      const proResult = await pool.query(`SELECT full_name, phone FROM professional_applications WHERE id = $1`, [id]);
      
      await pool.query(`UPDATE professional_applications SET status = $1, pro_code = $2, kyc_verified = true WHERE id = $3`, [status, newCode, id]);
      
      // ✅ ENVOI DU SMS AUTOMATIQUE AVEC LE CODE PRO
      if (proResult.rows.length > 0) {
        const pro = proResult.rows[0];
        const messageSMS = `Félicitations ${pro.full_name} ! Votre compte TrouveMoi est validé. Votre code de connexion est : ${newCode}. Gardez-le précieusement.`;
        await sendSMS(pro.phone, messageSMS);
      }
      
    } else {
      await pool.query(`UPDATE professional_applications SET status = $1, rejection_reason = $2 WHERE id = $3`, [status, reason, id]);
      if (status === "rejected") await pool.query(`UPDATE job_offers SET status = 'closed' WHERE pro_id = $1`, [id]);
    }
    res.redirect(303, "/admin/candidatures");
  } catch (e) {
    console.error("Erreur changement statut:", e);
    res.redirect(303, "/admin/candidatures");
  }
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
    try {
      const id = Number(req.params.id);
      const status = String(req.body.status || "");

      if (["pending", "approved", "rejected"].includes(status)) {
        await pool.query(`UPDATE reviews SET status = $1, processed_at = NOW() WHERE id = $2`, [status, id]);
        await logAdminAction(`review_${status}`, "review", id, null);
      }
      
      res.redirect(303, "/admin/avis");
    } catch (error) {
      console.error("Erreur statut avis :", error.message);
      res.redirect(303, "/admin/avis");
    }
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
    const result = await pool.query(`SELECT w.*, p.full_name, p.pro_code FROM withdrawal_requests w JOIN professional_applications p ON p.id = w.pro_id ORDER BY CASE WHEN w.status = 'pending' THEN 0 ELSE 1 END, w.created_at DESC`);
    const rows = result.rows.map(w => `
      <article class="card" style="margin-bottom:20px;">
        <h2>${escapeHtml(w.full_name)} (${escapeHtml(w.pro_code)})</h2>
        <p><strong>Montant :</strong> ${w.amount} FCFA</p>
        <p><strong>Numéro :</strong> ${escapeHtml(w.phone_number)}</p>
        <p><strong>Statut :</strong> ${w.status}</p>
        ${w.status === 'pending' ? `<div style="display:flex; gap:10px;"><form action="/admin/retraits/${w.id}/approuver" method="POST"><input type="hidden" name="csrfToken" value="${csrf}"><button class="success">Approuver</button></form><form action="/admin/retraits/${w.id}/rejeter" method="POST"><input type="hidden" name="csrfToken" value="${csrf}"><button class="danger">Rejeter</button></form></div>` : ""}
      </article>
    `).join("");
    res.send(page("Retraits", `<h1>Retraits</h1>${await customAdminMenu("/admin/retraits", csrf)}${rows || "<p>Aucune demande.</p>"}`, null));
  });

  router.post("/retraits/:id/approuver", requireAdmin, verifyCsrf, async (req, res) => {
    await pool.query(`UPDATE withdrawal_requests SET status = 'processed' WHERE id = $1 AND status = 'pending'`, [Number(req.params.id)]);
    res.redirect(303, "/admin/retraits");
  });

  router.post("/retraits/:id/rejeter", requireAdmin, verifyCsrf, async (req, res) => {
    const id = Number(req.params.id);
    try {
      const result = await pool.query(`SELECT pro_id, amount FROM withdrawal_requests WHERE id = $1 AND status = 'pending'`, [id]);
      
      if (result.rows.length) {
        const withdrawal = result.rows[0];
        // On re-crédite le solde du pro
        await pool.query(`UPDATE professional_applications SET referral_balance = referral_balance + $1 WHERE id = $2`, [withdrawal.amount, withdrawal.pro_id]);
        // On marque le retrait comme rejeté
        await pool.query(`UPDATE withdrawal_requests SET status = 'rejected', processed_at = NOW() WHERE id = $1`, [id]);
        
        await logAdminAction("withdrawal_rejected", "pro", withdrawal.pro_id, `Retrait de ${withdrawal.amount} FCFA rejeté. Solde recrédité.`);
      }
      res.redirect(303, "/admin/retraits");
    } catch (error) {
      console.error("Erreur rejet retrait:", error);
      res.redirect(303, "/admin/retraits");
    }
  });

  router.get("/rgpd", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT g.*, p.full_name AS pro_name FROM gdpr_requests g LEFT JOIN professional_applications p ON p.id = g.pro_id ORDER BY g.created_at DESC`);
    const rows = result.rows.map(r => `<article class="card"><h2>${escapeHtml(r.request_type)} - ${escapeHtml(r.pro_name || "Inconnu")}</h2><p>Statut: ${escapeHtml(r.status)}</p>${r.status === "pending" ? `<form action="/admin/rgpd/${r.id}/traiter" method="POST"><input type="hidden" name="csrfToken" value="${csrf}"><button class="success">Traiter</button></form>` : ""}</article>`).join("");
    res.send(page("RGPD", `<h1>RGPD</h1>${await customAdminMenu("/admin/rgpd", csrf)}${rows}`, null));
  });

  router.post("/rgpd/:id/traiter", requireAdmin, verifyCsrf, async (req, res) => {
    const id = Number(req.params.id);
    try {
      const requestResult = await pool.query(`SELECT pro_id FROM gdpr_requests WHERE id = $1`, [id]);
      
      if (requestResult.rows.length && requestResult.rows[0].pro_id) {
        const proId = requestResult.rows[0].pro_id;

        const proResult = await pool.query(`SELECT photo_profil_url, photo_identite_url, photo_kyc_url, photo_activite_url FROM professional_applications WHERE id = $1`, [proId]);
        
        if (proResult.rows.length) {
          const pro = proResult.rows[0];
          const photos = [pro.photo_profil_url, pro.photo_identite_url, pro.photo_kyc_url, pro.photo_activite_url];
          
          for (let p of photos) {
            if (p) {
              try { await deleteFromCloudinary(p); } catch (e) { console.error("Erreur Cloudinary:", e); }
            }
          }
        }

        // Suppression des données en base
        await pool.query(`DELETE FROM job_offers WHERE pro_id = $1`, [proId]);
        await pool.query(`DELETE FROM agencies WHERE parent_pro_id = $1`, [proId]);
        await pool.query(`DELETE FROM reviews WHERE pro_id = $1`, [proId]);
        await pool.query(`DELETE FROM withdrawal_requests WHERE pro_id = $1`, [proId]);
        await pool.query(`DELETE FROM contact_events WHERE pro_id = $1`, [proId]);
        await pool.query(`DELETE FROM pro_stats WHERE pro_id = $1`, [proId]);
        await pool.query(`DELETE FROM professional_applications WHERE id = $1`, [proId]);
        
        await pool.query(`UPDATE gdpr_requests SET status = 'processed', processed_at = NOW() WHERE id = $1`, [id]);
        await logAdminAction("gdpr_deleted_pro", "pro", proId, "Compte professionnel supprimé définitivement (DB + Cloudinary)");
      } else {
        await pool.query(`UPDATE gdpr_requests SET status = 'processed', processed_at = NOW() WHERE id = $1`, [id]);
      }
      
      res.redirect(303, "/admin/rgpd");
    } catch (error) {
      console.error("Erreur suppression RGPD:", error);
      res.status(500).send("Erreur lors de la suppression.");
    }
  });

  // DÉCONNEXION
  router.post("/logout", requireAdmin, verifyCsrf, async (req, res) => {
    await pool.query(`UPDATE admin_sessions SET revoked_at = NOW() WHERE jti = $1`, [req.adminSession.jti]).catch(() => {});
    clearSessionCookie(res); res.redirect(303, "/admin");
  });

  // SIGNALEMENTS D'AVIS
  router.get("/signalisations", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT r.*, v.comment AS review_comment, v.author_name, p.full_name AS pro_name FROM review_reports r JOIN reviews v ON v.id = r.review_id JOIN professional_applications p ON p.id = v.pro_id ORDER BY CASE WHEN r.status = 'pending' THEN 0 ELSE 1 END, r.created_at DESC`);
    const reports = result.rows.map(r => `<article class="card"><h2>Signalement de ${escapeHtml(r.pro_name)}</h2><p><strong>Motif :</strong> ${escapeHtml(r.reason)}</p><p><strong>Avis concerné :</strong> "${escapeHtml(r.review_comment)}" par ${escapeHtml(r.author_name)}</p>${r.status === 'pending' ? `<div style="display:flex; gap:10px;"><form action="/admin/signalisations/${r.id}/supprimer-avis" method="POST" style="margin:0;"><input type="hidden" name="csrfToken" value="${csrf}"><button class="danger">Supprimer l'avis</button></form><form action="/admin/signalisations/${r.id}/rejeter" method="POST" style="margin:0;"><input type="hidden" name="csrfToken" value="${csrf}"><button class="secondary">Rejeter le signalement</button></form></div>` : `<span class="badge">${escapeHtml(r.status)}</span>`}</article>`).join("");
    res.send(page("Signalements", `<h1>Signalements</h1>${await customAdminMenu("/admin/signalisations", csrf)}${reports || "<p>Aucun signalement.</p>"}`, null));
  });

  router.post("/signalisations/:id/supprimer-avis", requireAdmin, verifyCsrf, async (req, res) => {
    const id = Number(req.params.id);
    try {
      const report = await pool.query(`SELECT review_id FROM review_reports WHERE id = $1`, [id]);
      if (report.rows.length) {
        await pool.query(`DELETE FROM reviews WHERE id = $1`, [report.rows[0].review_id]);
        await pool.query(`UPDATE review_reports SET status = 'processed', processed_at = NOW() WHERE id = $1`, [id]);
      }
    } catch(e) { console.error("Erreur suppression avis signalé", e); }
    res.redirect(303, "/admin/signalisations");
  });

  router.post("/signalisations/:id/rejeter", requireAdmin, verifyCsrf, async (req, res) => {
    await pool.query(`UPDATE review_reports SET status = 'rejected', processed_at = NOW() WHERE id = $1`, [Number(req.params.id)]);
    res.redirect(303, "/admin/signalisations");
  });

  // OFFRES D'EMPLOI (Admin)
  router.get("/emplois", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT j.*, p.full_name AS pro_name FROM job_offers j LEFT JOIN professional_applications p ON p.id = j.pro_id ORDER BY CASE WHEN j.status = 'pending' THEN 0 ELSE 1 END, j.created_at DESC`);
    const offers = result.rows.map(j => `<article class="card"><h2>${escapeHtml(j.job_title)}</h2><p>Par : ${escapeHtml(j.pro_name || "Inconnu")}</p><p>${escapeHtml(j.description)}</p>${j.status === 'pending' ? `<div style="display:flex; gap:10px;"><form action="/admin/emplois/${j.id}/statut" method="POST" style="margin:0;"><input type="hidden" name="csrfToken" value="${csrf}"><button name="status" value="approved" class="success">Approuver</button></form><form action="/admin/emplois/${j.id}/statut" method="POST" style="margin:0;"><input type="hidden" name="csrfToken" value="${csrf}"><button name="status" value="rejected" class="danger">Rejeter</button></form></div>` : `<span class="badge">${escapeHtml(j.status)}</span>`}</article>`).join("");
    res.send(page("Offres d'emploi", `<h1>Offres d'emploi</h1>${await customAdminMenu("/admin/emplois", csrf)}${offers || "<p>Aucune offre.</p>"}`, null));
  });

  router.post("/emplois/:id/statut", requireAdmin, verifyCsrf, async (req, res) => {
    await pool.query(`UPDATE job_offers SET status = $1 WHERE id = $2`, [req.body.status, Number(req.params.id)]);
    res.redirect(303, "/admin/emplois");
  });

  // DONS & BLOG & LOGS & QR CODE & NOTIFICATIONS
  router.get("/dons", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT * FROM global_donations ORDER BY created_at DESC`);
    const rows = result.rows.map(d => `<tr style="border-bottom:1px solid #e5e7eb;"><td style="padding:12px;">${new Date(d.created_at).toLocaleString("fr-FR")}</td><td style="padding:12px; font-weight:bold; color:#10b981;">${d.amount} FCFA</td><td style="padding:12px;">${escapeHtml(d.donor_name)}</td></tr>`).join("");
    res.send(page("Dons", `<h1>Dons reçus</h1>${await customAdminMenu("/admin/dons", csrf)}<section class="card"><table style="width:100%; border-collapse:collapse;"><thead><tr style="background:#f9fafb;"><th>Date</th><th>Montant</th><th>Donateur</th></tr></thead><tbody>${rows}</tbody></table></section>`, null));
  });

  router.get("/blog", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const articles = (await pool.query(`SELECT * FROM blog_posts ORDER BY created_at DESC`)).rows;
    const list = articles.map(a => `<article class="card"><h2>${escapeHtml(a.title)}</h2><p>${a.published ? 'En ligne' : 'Brouillon'}</p><form action="/admin/blog/${a.id}/supprimer" method="POST" style="margin:0;"><input type="hidden" name="csrfToken" value="${csrf}"><button class="danger">Supprimer</button></form></article>`).join("");
    res.send(page("Blog", `<h1>Blog</h1>${await customAdminMenu("/admin/blog", csrf)}<a href="/admin/blog/nouveau" class="button" style="margin-bottom:20px;">➕ Nouvel article</a>${list || "<p>Aucun article.</p>"}`, null));
  });

  router.get("/blog/nouveau", requireAdmin, (req, res) => {
    const csrf = getCsrf(req);
    res.send(page("Nouvel article", `<section class="card" style="max-width:700px; margin:0 auto;"><h1>Nouvel article</h1><form action="/admin/blog/nouveau" method="POST"><input type="hidden" name="csrfToken" value="${csrf}"><label>Titre</label><input name="title" required><label>Contenu</label><textarea name="content" required rows="10"></textarea><button type="submit">Publier</button></form></section>`, null));
  });

  router.post("/blog/nouveau", requireAdmin, verifyCsrf, async (req, res) => {
    const slug = req.body.title.toLowerCase().replace(/[^a-z0-9]+/g, "-") + "-" + crypto.randomInt(1000, 9999);
    await pool.query(`INSERT INTO blog_posts (title, slug, content, published) VALUES ($1, $2, $3, true)`, [req.body.title, slug, req.body.content]);
    res.redirect(303, "/admin/blog");
  });

  router.post("/blog/:id/supprimer", requireAdmin, verifyCsrf, async (req, res) => {
    await pool.query(`DELETE FROM blog_posts WHERE id = $1`, [Number(req.params.id)]);
    res.redirect(303, "/admin/blog");
  });

  router.get("/logs", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const logs = (await pool.query(`SELECT * FROM admin_logs ORDER BY created_at DESC LIMIT 100`)).rows;
    const rows = logs.map(l => `<tr style="border-bottom:1px solid #e5e7eb;"><td style="padding:10px; font-size:12px;">${new Date(l.created_at).toLocaleString("fr-FR")}</td><td style="padding:10px; font-weight:bold;">${escapeHtml(l.action)}</td><td style="padding:10px;">${escapeHtml(l.details || "")}</td></tr>`).join("");
    res.send(page("Journal", `<h1>Journal d'activité</h1>${await customAdminMenu("/admin/logs", csrf)}<section class="card"><table style="width:100%; border-collapse:collapse;"><thead><tr style="background:#f9fafb;"><th>Date</th><th>Action</th><th>Détails</th></tr></thead><tbody>${rows}</tbody></table></section>`, null));
  });

  router.get("/qrcode", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(process.env.APP_URL || "https://trouvemoi.bj")}`;
    res.send(page("QR Code", `<h1>QR Code Officiel</h1>${await customAdminMenu("/admin/qrcode", csrf)}<section class="card" style="text-align:center;"><img src="${qrUrl}" style="width:250px; border-radius:8px;"><p>Scannez pour visiter le site.</p></section>`, null));
  });

  router.get("/notifications", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const notifs = (await pool.query(`SELECT * FROM notifications ORDER BY created_at DESC LIMIT 100`)).rows;
    const rows = notifs.map(n => `<tr style="border-bottom:1px solid #e5e7eb;"><td style="padding:10px; font-size:12px;">${new Date(n.created_at).toLocaleString("fr-FR")}</td><td style="padding:10px;">${escapeHtml(n.recipient)}</td><td style="padding:10px;">${escapeHtml(n.body)}</td><td style="padding:10px;"><span class="badge">${escapeHtml(n.status)}</span></td></tr>`).join("");
    res.send(page("Notifications", `<h1>Notifications</h1>${await customAdminMenu("/admin/notifications", csrf)}<section class="card"><table style="width:100%; border-collapse:collapse;"><thead><tr style="background:#f9fafb;"><th>Date</th><th>Destinataire</th><th>Message</th><th>Statut</th></tr></thead><tbody>${rows}</tbody></table></section>`, null));
  });

  // ==========================================
  // PARAMÈTRES ADMIN (Sécurité)
  // ==========================================
  router.get("/parametres", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    res.send(page("Paramètres", `
      <h1 style="text-align:center; margin-bottom:20px;">⚙️ Paramètres Administrateur</h1>
      ${await customAdminMenu("/admin/parametres", csrf)}
      
      <section class="card" style="max-width: 500px; margin: 40px auto;">
        <h2 style="font-size: 18px; margin-bottom: 16px;">🔒 Changer le mot de passe</h2>
        <form action="/admin/parametres/mot-de-passe" method="POST">
          <input type="hidden" name="csrfToken" value="${csrf}">
          <label>Ancien mot de passe</label>
          <input type="password" name="old_password" required>
          <label>Nouveau mot de passe (min. 12 caractères)</label>
          <input type="password" name="new_password" required minlength="12">
          <button type="submit" class="success" style="width:100%; margin-top:10px;">💾 Enregistrer le nouveau mot de passe</button>
        </form>
      </section>

      <section class="card" style="max-width: 500px; margin: 40px auto;">
        <h2 style="font-size: 18px; margin-bottom: 16px;">📊 Informations système</h2>
        <p style="font-size:14px; color:#4b5563;"><strong>Mode :</strong> ${process.env.NODE_ENV || "development"}</p>
        <p style="font-size:14px; color:#4b5563;"><strong>Base de données :</strong> Connectée</p>
        <p style="font-size:14px; color:#4b5563;"><strong>Version Node :</strong> ${process.version}</p>
      </section>
    `, null));
  });

  router.post("/parametres/mot-de-passe", requireAdmin, verifyCsrf, async (req, res) => {
    if (req.body.old_password !== process.env.ADMIN_PASSWORD) {
      return res.status(400).send(page("Erreur", "<h2>Ancien mot de passe incorrect.</h2>", null));
    }
    
    res.send(page("Succès", `
      <section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;">
        <h1>✅ Vérification réussie</h1>
        <p style="margin-bottom:20px;">Votre ancien mot de passe est correct.</p>
        <div class="alert alert-warning" style="text-align:left;">
          <strong>⚠️ Important :</strong> Pour des raisons de sécurité, le mot de passe administrateur ne peut pas être modifié directement depuis cette page. Vous devez le changer dans les variables d'environnement sur Render (Variable <code>ADMIN_PASSWORD</code>).
        </div>
        <a href="/admin/parametres" class="button" style="margin-top:20px;">← Retour</a>
      </section>
    `, null));
  });

  return router;
};
