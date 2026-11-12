const express = require('express');
const crypto = require('crypto');

module.exports = function(pool, page, requireAdmin, verifyCsrf, getCsrf, escapeHtml, adminMenu, verifySessionToken, readCookie, clearSessionCookie, createSessionToken, setSessionCookie, safeEqual, ADMIN_PASSWORD, verifyTotp, ADMIN_TOTP_SECRET, SESSION_COOKIE, SESSION_DURATION, logAdminAction, generateUniqueProCode, deleteFromCloudinary, sendSMS) {
  const router = express.Router();

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
            <span onclick="document.getElementById('totp-input').type = document.getElementById('totp-input').type === 'password' ? 'text' : 'password'" style="position:absolute; right:15px; top:50%; transform:translateY(-50%); cursor:pointer; color:#6b7280; font-size:20px;">👁️</span>
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
  // GESTION DES CANDIDATURES (SYSTÈME ACCORDÉON)
  // ==========================================
  router.get("/candidatures", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const showArchived = req.query.archives === "1";

    let whereClause = showArchived 
      ? `WHERE p.status IN ('rejected', 'suspended')` 
      : `WHERE p.status IN ('pending', 'under_review', 'approved')`;

    const result = await pool.query(`
      SELECT p.*, pr.category AS profession_category 
      FROM professional_applications p
      LEFT JOIN professions pr ON p.profession = pr.name
      ${whereClause}
      ORDER BY CASE WHEN p.status = 'pending' THEN 0 ELSE 1 END, p.created_at DESC
    `);
    
    const apps = result.rows.map(c => {
      let statusColor = "#f59e0b", statusLabel = "En attente";
      if (c.status === 'approved') { statusColor = "#10b981"; statusLabel = "Approuvé"; }
      else if (c.status === 'rejected') { statusColor = "#ef4444"; statusLabel = "Rejeté"; }
      else if (c.status === 'suspended') { statusColor = "#f97316"; statusLabel = "Suspendu"; }

      let actionButtons = "";
      if (c.status === 'pending' || c.status === 'under_review') {
        actionButtons = `
          <div style="display:flex; flex-direction:column; gap:8px;">
            <form action="/admin/candidatures/${c.id}/status" method="POST" style="margin:0;">
              <input type="hidden" name="csrfToken" value="${csrf}">
              <input type="hidden" name="status" value="approved">
              <button class="success" style="width:100%; padding:8px; font-size:13px; border-radius:8px;">✅ Approuver</button>
            </form>
            <form action="/admin/candidatures/${c.id}/status" method="POST" style="margin:0;">
              <input type="hidden" name="csrfToken" value="${csrf}">
              <input type="hidden" name="status" value="rejected">
              <div style="display:flex; gap:5px;">
                <input name="rejection_reason" placeholder="Motif du rejet..." required style="margin:0; padding:6px; font-size:12px; flex:1; border-radius:6px;">
                <button class="danger" style="padding:6px 10px; font-size:12px; margin:0; border-radius:6px;">❌ Rejeter</button>
              </div>
            </form>
          </div>`;
      } else if (c.status === 'approved') {
        actionButtons = `
          <div style="display:flex; flex-direction:column; gap:8px;">
            <div style="background:#eff6ff; padding:8px; border-radius:8px; text-align:center;">
              <div style="font-size:10px; color:#1e40af; text-transform:uppercase;">Code Pro</div>
              <div style="font-size:16px; font-weight:bold; font-family:monospace; color:#1e3a8a;">${escapeHtml(c.pro_code || '-')}</div>
            </div>
            <form action="/admin/candidatures/${c.id}/regenerer-code" method="POST" style="margin:0;">
              <input type="hidden" name="csrfToken" value="${csrf}">
              <button class="warning" style="width:100%; padding:8px; font-size:12px; border-radius:8px;">🔄 Nouveau code</button>
            </form>
            <form action="/admin/candidatures/${c.id}/status" method="POST" style="margin:0;">
              <input type="hidden" name="csrfToken" value="${csrf}">
              <input type="hidden" name="status" value="suspended"> 
              <button class="warning" style="width:100%; padding:8px; font-size:12px; border-radius:8px; background:#f97316;">⏸️ Suspendre</button>
            </form>
            <form action="/admin/candidatures/${c.id}/supprimer" method="POST" style="margin:0;" onsubmit="return confirm('⚠️ Supprimer définitivement ?');">
              <input type="hidden" name="csrfToken" value="${csrf}">
              <button class="danger" style="width:100%; padding:8px; font-size:12px; border-radius:8px;">🗑️ Supprimer</button>
            </form>
          </div>`;
      } else if (c.status === 'suspended') {
        actionButtons = `
          <div style="display:flex; flex-direction:column; gap:8px;">
            <form action="/admin/candidatures/${c.id}/status" method="POST" style="margin:0;">
              <input type="hidden" name="csrfToken" value="${csrf}">
              <input type="hidden" name="status" value="approved">
              <button class="success" style="width:100%; padding:8px; font-size:13px; border-radius:8px;">▶️ Réactiver</button>
            </form>
            <form action="/admin/candidatures/${c.id}/supprimer" method="POST" style="margin:0;" onsubmit="return confirm('⚠️ Supprimer définitivement ?');">
              <input type="hidden" name="csrfToken" value="${csrf}">
              <button class="danger" style="width:100%; padding:8px; font-size:13px; border-radius:8px;">🗑️ Supprimer</button>
            </form>
          </div>`;
      } else if (c.status === 'rejected') {
        actionButtons = `
          <div style="display:flex; flex-direction:column; gap:8px;">
            <div style="background:#fee2e2; padding:8px; border-radius:8px; font-size:12px; color:#991b1b;">
              <strong>Motif :</strong> ${escapeHtml(c.rejection_reason || 'Non précisé')}
            </div>
            <form action="/admin/candidatures/${c.id}/supprimer" method="POST" style="margin:0;" onsubmit="return confirm('⚠️ Supprimer définitivement ?');">
              <input type="hidden" name="csrfToken" value="${csrf}">
              <button class="danger" style="width:100%; padding:8px; font-size:13px; border-radius:8px;">🗑️ Supprimer</button>
            </form>
          </div>`;
      }

      return `
        <details style="background:white; border-radius:12px; border:1px solid #e5e7eb; box-shadow:0 2px 4px rgba(0,0,0,0.02); overflow:hidden; border-left:4px solid ${statusColor}; margin-bottom:10px;">
          
          <summary style="padding:12px 15px; display:flex; align-items:center; gap:12px; cursor:pointer; list-style:none; outline:none;">
            ${c.photo_profil_url ? `<img src="/admin/kyc/${c.id}/photo_profil_url" style="width:40px; height:40px; object-fit:cover; border-radius:50%; border:2px solid #e2e8f0;">` : `<div style="width:40px; height:40px; background:#f1f5f9; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:16px;">👤</div>`}
            <div style="flex:1; min-width:0;">
              <div style="font-size:15px; font-weight:700; color:#0f172a; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(c.full_name)}</div>
              <div style="font-size:12px; color:#64748b;">${escapeHtml(c.profession)} • ${escapeHtml(c.city)}</div>
            </div>
            <span style="background:${statusColor}20; color:${statusColor}; padding:4px 10px; border-radius:12px; font-size:11px; font-weight:800; text-transform:uppercase; white-space:nowrap;">${statusLabel}</span>
            <div style="color:#94a3b8; font-size:18px; margin-left:5px;">▼</div>
          </summary>

          <div style="padding:15px; border-top:1px solid #f1f5f9; background:#fafafa;">
            <!-- Infos -->
            <div style="font-size:13px; display:flex; flex-direction:column; gap:6px;">
              <div style="display:flex; justify-content:space-between;"><span style="color:#64748b;">Téléphone</span><strong>${escapeHtml(c.phone)}</strong></div>
              <div style="display:flex; justify-content:space-between;"><span style="color:#64748b;">NPI</span><strong>${escapeHtml(c.npi)}</strong></div>
              <div style="display:flex; justify-content:space-between;"><span style="color:#64748b;">Ville</span><strong>${escapeHtml(c.city)}</strong></div>
              <div style="display:flex; justify-content:space-between;"><span style="color:#64748b;">Quartier</span><strong>${escapeHtml(c.neighborhood || '-')}</strong></div>
              <div style="display:flex; justify-content:space-between;"><span style="color:#64748b;">Code suivi</span><strong>${escapeHtml(c.tracking_code)}</strong></div>
              
              <div style="margin-top:10px; display:flex; gap:10px; flex-wrap:wrap;">
                ${c.photo_profil_url ? `<img src="/admin/kyc/${c.id}/photo_profil_url" onclick="zoomImage(this.src)" style="width:50px; height:50px; object-fit:cover; border-radius:6px; cursor:pointer; border:1px solid #cbd5e1;" title="Visage">` : ''}
                ${c.photo_identite_url ? `<img src="/admin/kyc/${c.id}/photo_identite_url" onclick="zoomImage(this.src)" style="width:50px; height:50px; object-fit:cover; border-radius:6px; cursor:pointer; border:1px solid #cbd5e1;" title="Pièce d'identité">` : ''}
                ${c.photo_kyc_url ? `<img src="/admin/kyc/${c.id}/photo_kyc_url" onclick="zoomImage(this.src)" style="width:50px; height:50px; object-fit:cover; border-radius:6px; cursor:pointer; border:1px solid #cbd5e1;" title="Photo KYC">` : ''}
              </div>
            </div>

            <!-- Actions -->
            <div style="margin-top:15px; padding-top:15px; border-top:1px dashed #e2e8f0;">
              ${actionButtons}
            </div>
          </div>
        </details>
      `;
    }).join("");

    res.send(page("Candidatures", `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; flex-wrap:wrap; gap:10px;">
        <h1 style="margin:0; font-size:24px;">Candidatures</h1>
        <a href="/admin/candidatures${showArchived ? '' : '?archives=1'}" class="button ${showArchived ? 'success' : 'secondary'}" style="margin:0; font-size:14px;">
          ${showArchived ? '👈 Retour aux candidatures actives' : '🗂️ Voir les rejetés & suspendus'}
        </a>
      </div>
      
      ${await customAdminMenu("/admin/candidatures", csrf)}
      
      <style>
        details summary::-webkit-details-marker { display: none; }
        details[open] summary { background: #f8fafc; border-bottom: 1px solid #e5e7eb; }
        details[open] summary div:last-child { transform: rotate(180deg); }
      </style>

      <div style="margin-top:20px;">
        ${apps || `<p style="text-align:center; color:#64748b; padding:40px;">Aucun dossier dans cette section.</p>`}
      </div>
    `, null));
  });

  // Action : Changer le statut (Approuver, Rejeter, Suspendre)
  router.post("/candidatures/:id/status", requireAdmin, verifyCsrf, async (req, res) => {
    const id = Number(req.params.id); 
    const status = req.body.status; 
    const reason = req.body.rejection_reason || null;
    
    try {
      if (status === "approved") {
        const current = await pool.query(`SELECT status, pro_code, full_name, phone FROM professional_applications WHERE id = $1`, [id]);
        const isReactivation = current.rows[0]?.status === 'suspended';
        
        if (isReactivation) {
          await pool.query(`UPDATE professional_applications SET status = 'approved' WHERE id = $1`, [id]);
        } else {
          const newCode = await generateUniqueProCode(); 
          await pool.query(`UPDATE professional_applications SET status = $1, pro_code = $2, kyc_verified = true WHERE id = $3`, [status, newCode, id]);
          
          if (current.rows.length > 0) {
            const pro = current.rows[0];
            const messageSMS = `Félicitations ${pro.full_name} ! Votre compte TrouveMoi est validé. Votre code de connexion est : ${newCode}. Gardez-le précieusement.`;
            try { await sendSMS(pro.phone, messageSMS); } catch(e) { console.error("Erreur SMS:", e); }
          }
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

  // Action : Régénérer le code
router.post("/candidatures/:id/regenerer-code", requireAdmin, verifyCsrf, async (req, res) => {
  const id = Number(req.params.id);
  try {
    console.log("--- DÉBUT GÉNÉRATION CODE POUR ID:", id);
    
    const newCode = await generateUniqueProCode();
    console.log("1. Nouveau code généré:", newCode); 

    // On tente de sauvegarder le code
    const updateResult = await pool.query(`UPDATE professional_applications SET pro_code = $1 WHERE id = $2 RETURNING id`, [newCode, id]);
    
    if (updateResult.rowCount === 0) {
      console.log("❌ ERREUR: Aucune ligne mise à jour. L'ID n'existe pas ?");
      return res.redirect(303, "/admin/candidatures");
    }
    
    console.log("2. Code sauvegardé en base pour l'ID:", id);

    const proResult = await pool.query(`SELECT full_name, phone FROM professional_applications WHERE id = $1`, [id]);
    
    if (proResult.rows.length > 0) {
      const pro = proResult.rows[0];
      const messageSMS = `Bonjour ${pro.full_name}, voici votre nouveau code de connexion TrouveMoi : ${newCode}. Gardez-le précieusement.`;
      try { 
        await sendSMS(pro.phone, messageSMS); 
      } catch(e) { 
        console.log("3. Erreur SMS ignorée (mode test)"); 
      }
    }
    
    await logAdminAction("pro_code_regenerated", "pro", id, "Code régénéré par admin");
    console.log("4. Log admin enregistré.");
    
    res.redirect(303, "/admin/candidatures");
  } catch (e) {
    console.error("❌ ERREUR CRITIQUE REGENERATION CODE:", e.message);
    res.status(500).send("Erreur: " + e.message);
  }
});

  // Action : Supprimer définitivement
  router.post("/candidatures/:id/supprimer", requireAdmin, verifyCsrf, async (req, res) => { 
    const id = Number(req.params.id);
    try {
      const proResult = await pool.query(`SELECT photo_profil_url, photo_identite_url, photo_kyc_url, photo_activite_url FROM professional_applications WHERE id = $1`, [id]);
      if (proResult.rows.length) {
        const pro = proResult.rows[0];
        for (let p of [pro.photo_profil_url, pro.photo_identite_url, pro.photo_kyc_url, pro.photo_activite_url]) {
          if (p) { try { await deleteFromCloudinary(p); } catch (e) {} }
        }
      }
      await pool.query(`DELETE FROM job_offers WHERE pro_id = $1`, [id]);
      await pool.query(`DELETE FROM agencies WHERE parent_pro_id = $1`, [id]);
      await pool.query(`DELETE FROM reviews WHERE pro_id = $1`, [id]);
      await pool.query(`DELETE FROM withdrawal_requests WHERE pro_id = $1`, [id]);
      await pool.query(`DELETE FROM contact_events WHERE pro_id = $1`, [id]);
      await pool.query(`DELETE FROM pro_stats WHERE pro_id = $1`, [id]);
      await pool.query(`DELETE FROM professional_applications WHERE id = $1`, [id]);
      
      await logAdminAction("pro_deleted_by_admin", "pro", id, "Compte supprimé définitivement par admin");
      res.redirect(303, "/admin/candidatures");
    } catch (e) {
      res.redirect(303, "/admin/candidatures");
    }
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
  // AUTRES ROUTES (Agences, Avis, Retraits, etc.)
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
    } catch (error) { res.redirect(303, "/admin/avis"); }
  });

  router.get("/messages", requireAdmin, async (req, res) => {
    const csrf = getCsrf(req);
    const result = await pool.query(`SELECT * FROM contact_messages ORDER BY created_at DESC`);
    const msgs = result.rows.map(m => `<article class="card"><h2>${escapeHtml(m.name)}</h2><p>Email: ${escapeHtml(m.email)} | Tel: ${escapeHtml(m.phone || "-")}</p><p style="background:#f9fafb; padding:10px;">${escapeHtml(m.message)}</p></article>`).join("");
    await pool.query(`UPDATE contact_messages SET is_read = true WHERE is_read = false`);
    res.send(page("Messages", `<h1>Messages</h1>${await customAdminMenu("/admin/messages", csrf)}${msgs}`, null));
  });

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
        await pool.query(`UPDATE professional_applications SET referral_balance = referral_balance + $1 WHERE id = $2`, [withdrawal.amount, withdrawal.pro_id]);
        await pool.query(`UPDATE withdrawal_requests SET status = 'rejected', processed_at = NOW() WHERE id = $1`, [id]);
        await logAdminAction("withdrawal_rejected", "pro", withdrawal.pro_id, `Retrait de ${withdrawal.amount} FCFA rejeté. Solde recrédité.`);
      }
      res.redirect(303, "/admin/retraits");
    } catch (error) { res.redirect(303, "/admin/retraits"); }
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
          for (let p of [pro.photo_profil_url, pro.photo_identite_url, pro.photo_kyc_url, pro.photo_activite_url]) {
            if (p) { try { await deleteFromCloudinary(p); } catch (e) {} }
          }
        }
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
    } catch (error) { res.status(500).send("Erreur lors de la suppression."); }
  });

  router.post("/logout", requireAdmin, verifyCsrf, async (req, res) => {
    await pool.query(`UPDATE admin_sessions SET revoked_at = NOW() WHERE jti = $1`, [req.adminSession.jti]).catch(() => {});
    clearSessionCookie(res); res.redirect(303, "/admin");
  });

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
