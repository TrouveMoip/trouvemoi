const express = require('express');

module.exports = function(pool, page, getConnectedPro, escapeHtml, cleanBeninPhone, JOB_CONTRACT_TYPES, logAdminAction, OFFER_DURATION_DAYS) {
  const router = express.Router();

  // --- FONCTION DE PAGINATION ---
  function renderPagination(currentPage, totalPages, baseUrl, queryParams = {}) {
    if (totalPages <= 1) return "";
    const buildUrl = (pageNum) => { const params = new URLSearchParams(queryParams); params.set("page", pageNum); return `${baseUrl}?${params.toString()}`; };
    let html = `<div style="display:flex; justify-content:center; align-items:center; gap:15px; margin: 30px 0; flex-wrap: wrap;">`;
    if (currentPage > 1) html += `<a href="${buildUrl(currentPage - 1)}" class="button secondary" style="margin:0">← Précédent</a>`;
    else html += `<span class="button secondary" style="margin:0; opacity:0.5;">← Précédent</span>`;
    html += `<span style="font-weight:bold; color:#4a5568;">Page ${currentPage} sur ${totalPages}</span>`;
    if (currentPage < totalPages) html += `<a href="${buildUrl(currentPage + 1)}" class="button secondary" style="margin:0">Suivant →</a>`;
    else html += `<span class="button secondary" style="margin:0; opacity:0.5;">Suivant →</span>`;
    html += `</div>`;
    return html;
  }

  // --- FONCTION POUR LES BOUTONS DE CONTACT ---
  function jobContactButtons(job) {
    const parts = [];
    if (job.contact_phone) {
      const clean = cleanBeninPhone(job.contact_phone);
      if (clean) parts.push(`<a href="tel:+229${escapeHtml(clean)}" class="button" style="background:#e0e7ff; color:#1e3a8a; margin-right: 8px; font-size:13px; padding: 8px 16px;">📞 Appeler</a>`);
    }
    if (job.contact_whatsapp) {
      const clean = cleanBeninPhone(job.contact_whatsapp);
      if (clean) parts.push(`<a href="https://wa.me/229${escapeHtml(clean)}?text=${encodeURIComponent("Bonjour, je vous contacte via TrouveMoi au sujet de votre offre d'emploi. Merci.")}" target="_blank" class="button whatsapp" style="margin-right: 8px; font-size:13px; padding: 8px 16px;">💬 WhatsApp</a>`);
    }
    if (job.contact_email) {
      parts.push(`<a href="mailto:${escapeHtml(job.contact_email)}?subject=${encodeURIComponent("Candidature - " + (job.job_title || "Offre TrouveMoi"))}" class="button secondary" style="font-size:13px; padding: 8px 16px;">✉️ E-mail</a>`);
    }
    if (!parts.length) return "";
    return `<div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:16px;">${parts.join("")}</div>`;
  }

  // ==========================================
  // 1. PAGE PUBLIQUE DES EMPLOIS
  // ==========================================
  router.get("/emplois", async (req, res) => {
    try {
      const proConnected = await getConnectedPro(req);
      const keyword = String(req.query.keyword || "").trim(); 
      const city = String(req.query.city || "").trim();
      const currentPage = Math.max(1, parseInt(req.query.page) || 1); 
      const limit = 10; const offset = (currentPage - 1) * limit;

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
  <article class="card" style="border-left: 4px solid #10b981; padding: 20px; margin-bottom: 16px;">
    <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:10px;">
      <div>
        <h2 style="font-size: 20px; color: #1e3a8a; margin-bottom: 4px;">${escapeHtml(job.job_title)}</h2>
        <div style="font-size: 14px; font-weight: 600; color: #4b5563;">🏢 ${escapeHtml(job.company_name)}</div>
      </div>
      <span class="badge" style="background: #eff6ff; color: #1e40af; font-size: 12px; padding: 6px 12px;">${escapeHtml(job.contract_type)}</span>
    </div>
    
    <div style="display:flex; gap:16px; font-size:13px; color:#6b7280; margin-top:12px;">
      <span>📍 ${escapeHtml(job.city)}</span>
    </div>
    
    <p style="margin-top: 12px; font-size: 14px; color: #374151; line-height: 1.6;">${escapeHtml(job.description).replace(/\n/g, "<br>").slice(0, 300)}...</p>
    <div style="text-align:right; margin-top:10px;">
  <a href="/emplois/${job.id}" style="color:#2563eb; font-weight:600; font-size:14px; text-decoration:none;">Lire la suite →</a>
</div>
    
    <div style="display:flex; gap:10px; margin-top:16px; border-top:1px solid #e5e7eb; padding-top:16px;">
      ${job.contact_phone ? `<a href="tel:+229${escapeHtml(cleanBeninPhone(job.contact_phone))}" class="button" style="background:#e0e7ff; color:#1e3a8a; font-size:13px; padding:8px 16px; margin:0;">📞 Appeler</a>` : ""}
      ${job.contact_whatsapp ? `<a href="https://wa.me/229${escapeHtml(cleanBeninPhone(job.contact_whatsapp))}" target="_blank" class="button whatsapp" style="font-size:13px; padding:8px 16px; margin:0;">💬 WhatsApp</a>` : ""}
      ${job.contact_email ? `<a href="mailto:${escapeHtml(job.contact_email)}" class="button secondary" style="font-size:13px; padding:8px 16px; margin:0;">✉️ E-mail</a>` : ""}
    </div>
  </article>
`).join("");

      const paginationHtml = renderPagination(currentPage, totalPages, "/emplois", { keyword, city });

      res.send(page("Emploi", `
        <h1 style="text-align: center; margin-bottom: 30px;">Offres d'emploi</h1>
        <section class="card" style="max-width: 800px; margin: 0 auto 30px auto;">
          <form action="/emplois" method="GET" style="display:flex; gap:10px; flex-wrap:wrap;">
            <input name="keyword" value="${escapeHtml(keyword)}" placeholder="Mot clé (ex: comptable)" style="flex:1 1 200px; margin:0;">
            <input name="city" value="${escapeHtml(city)}" placeholder="Ville" style="flex:1 1 200px; margin:0;">
            <button style="margin:0; padding:14px 30px;">Rechercher</button>
          </form>
        </section>
        <h2 style="text-align: center; margin-bottom: 20px;">Résultats (${totalJobs})</h2>
        ${jobs || `<section class="card"><p style="text-align:center;">Aucune offre pour le moment.</p></section>`}
        ${paginationHtml}
      `, proConnected));
    } catch (error) { res.status(500).send(page("Erreur", "<h2>Une erreur est survenue.</h2>", null)); }
  });

  // ==========================================
  // 2. PUBLIER UNE OFFRE (GET & POST)
  // ==========================================
  router.get("/publier-emploi", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    
    const contractOptions = JOB_CONTRACT_TYPES.map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join("");
    
    res.send(page("Publier", `
      <section class="card" style="max-width: 700px; margin: 0 auto;">
        <h1 style="text-align:center;">Nouvelle offre</h1>
        <form action="/offres-emploi" method="POST">
          <label>Entreprise *</label>
          <input name="company_name" required maxlength="200" value="${escapeHtml(proConnected.pro.company_name || proConnected.pro.full_name)}">
          
          <label>Poste *</label>
          <input name="job_title" required maxlength="200">
          
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px;">
            <div><label>Ville *</label><input name="city" required maxlength="100" value="${escapeHtml(proConnected.pro.city)}"></div>
            <div><label>Contrat *</label><select name="contract_type" required><option value="">Choisir</option>${contractOptions}</select></div>
          </div>
          
          <label>Description *</label>
          <textarea name="description" required maxlength="5000" rows="6"></textarea>
          
          <h3 style="margin-top:20px;">Comment les candidats vous contactent</h3>
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px;">
            <div><label>Téléphone</label><input name="contact_phone" type="tel" maxlength="30" value="${escapeHtml(proConnected.pro.phone || "")}" placeholder="0194010345"></div>
            <div><label>WhatsApp</label><input name="contact_whatsapp" type="tel" maxlength="30" value="${escapeHtml(proConnected.pro.whatsapp_number || proConnected.pro.phone || "")}" placeholder="0194010345"></div>
          </div>
          <label>E-mail (optionnel)</label>
<input name="contact_email" type="email" maxlength="254" value="${escapeHtml(proConnected.pro.contact_email || "")}">
          <label>E-mail (optionnel)</label>
          <input name="contact_email" type="email" maxlength="254" value="${escapeHtml(proConnected.pro.contact_email || "")}">
          
          <p style="font-size:12px; color:#6b7280;">Au moins un moyen de contact est requis.</p>
          <div style="text-align:center; margin-top:20px;">
            <button type="submit" style="padding:14px 40px;">Soumettre</button>
            <a href="/mon-espace-pro" class="button secondary">Annuler</a>
          </div>
        </form>
      </section>
    `, proConnected));
  });

  router.post("/offres-emploi", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    if (!JOB_CONTRACT_TYPES.includes(req.body.contract_type)) return res.status(400).send(page("Erreur", "<h2>Type invalide.</h2>", proConnected));

    const rawPhone = String(req.body.contact_phone || "").trim();
    const rawWhatsapp = String(req.body.contact_whatsapp || "").trim();
    const contactPhone = rawPhone ? cleanBeninPhone(rawPhone) : null;
    const contactWhatsapp = rawWhatsapp ? cleanBeninPhone(rawWhatsapp) : null;
    const contactEmail = String(req.body.contact_email || "").trim().slice(0, 254);

    if ((rawPhone && !contactPhone) || (rawWhatsapp && !contactWhatsapp)) return res.status(400).send(page("Erreur", "<h2>Numéro de contact invalide (format 01XXXXXXXX).</h2>", proConnected));
    if (!contactPhone && !contactWhatsapp && !contactEmail) return res.status(400).send(page("Erreur", "<h2>Indiquez au moins un moyen de contact.</h2>", proConnected));

    try {
      await pool.query(
        `INSERT INTO job_offers (company_name, job_title, city, contract_type, description, status, pro_id, expires_at, contact_phone, contact_whatsapp, contact_email) VALUES ($1,$2,$3,$4,$5,'pending',$6, NOW() + INTERVAL '15 days', $7, $8, $9)`,
        [req.body.company_name, req.body.job_title, req.body.city, req.body.contract_type, req.body.description, proConnected.pro.id, contactPhone, contactWhatsapp, contactEmail || null]
      );
      res.send(page("Succes", "<section class='card' style='max-width: 500px; margin: 40px auto; text-align:center;'><h1>Soumise !</h1><p>Votre offre sera vérifiée avant publication.</p><a href='/mon-espace-pro' class='button'>Retour</a></section>", proConnected));
    } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", proConnected)); }
  });

  // ==========================================
  // 3. MODIFIER, CLÔTURER, ROUVRIR, SUPPRIMER
  // ==========================================
  router.get("/mon-espace-pro/offre/:id/modifier", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    const id = Number(req.params.id);
    
    const result = await pool.query(`SELECT * FROM job_offers WHERE id = $1 AND pro_id = $2`, [id, proConnected.pro.id]);
    if (!result.rows.length) return res.redirect(303, "/mon-espace-pro");
    const offer = result.rows[0];
    const contractOptions = JOB_CONTRACT_TYPES.map((t) => `<option value="${escapeHtml(t)}" ${offer.contract_type === t ? "selected" : ""}>${escapeHtml(t)}</option>`).join("");

    res.send(page("Modifier l'offre", `
      <section class="card" style="max-width: 700px; margin: 0 auto;">
        <h1 style="text-align:center;">Modifier l'offre</h1>
        <form action="/mon-espace-pro/offre/${offer.id}/modifier" method="POST">
          <label>Entreprise *</label><input name="company_name" required value="${escapeHtml(offer.company_name)}">
          <label>Poste *</label><input name="job_title" required value="${escapeHtml(offer.job_title)}">
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px;">
            <div><label>Ville *</label><input name="city" required value="${escapeHtml(offer.city)}"></div>
            <div><label>Contrat *</label><select name="contract_type" required>${contractOptions}</select></div>
          </div>
          <label>Description *</label><textarea name="description" required rows="6">${escapeHtml(offer.description)}</textarea>
          <h3 style="margin-top:20px;">Contacts</h3>
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px;">
            <div><label>Téléphone</label><input name="contact_phone" value="${escapeHtml(offer.contact_phone || "")}"></div>
            <div><label>WhatsApp</label><input name="contact_whatsapp" value="${escapeHtml(offer.contact_whatsapp || "")}"></div>
          </div>
          <label>E-mail</label><input name="contact_email" type="email" value="${escapeHtml(offer.contact_email || "")}">
          <p style="font-size:12px; color:#6b7280;">Toute modification renvoie l'offre en modération.</p>
          <div style="text-align:center; margin-top:20px;"><button type="submit">Enregistrer</button><a href="/mon-espace-pro" class="button secondary">Annuler</a></div>
        </form>
      </section>
    `, proConnected));
  });

  router.post("/mon-espace-pro/offre/:id/modifier", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    const id = Number(req.params.id);
    
    const contactPhone = req.body.contact_phone ? cleanBeninPhone(req.body.contact_phone) : null;
    const contactWhatsapp = req.body.contact_whatsapp ? cleanBeninPhone(req.body.contact_whatsapp) : null;
    const contactEmail = String(req.body.contact_email || "").trim().slice(0, 254);
    
    await pool.query(
      `UPDATE job_offers SET company_name = $1, job_title = $2, city = $3, contract_type = $4, description = $5, contact_phone = $6, contact_whatsapp = $7, contact_email = $8, status = 'pending' WHERE id = $9 AND pro_id = $10`,
      [req.body.company_name, req.body.job_title, req.body.city, req.body.contract_type, req.body.description, contactPhone, contactWhatsapp, contactEmail || null, id, proConnected.pro.id]
    );
    await logAdminAction("job_edited_by_pro", "job", id, `Offre modifiee par ${proConnected.pro.full_name}`);
    res.redirect(303, "/mon-espace-pro");
  });

  router.post("/mon-espace-pro/offre/:id/close", async (req, res) => { 
    const proConnected = await getConnectedPro(req); 
    if (proConnected) await pool.query(`UPDATE job_offers SET status = 'closed' WHERE id = $1 AND pro_id = $2`, [Number(req.params.id), proConnected.pro.id]); 
    res.redirect(303, "/mon-espace-pro"); 
  });

  router.post("/mon-espace-pro/offre/:id/reopen", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (proConnected) await pool.query(`UPDATE job_offers SET status = 'approved', expires_at = NOW() + INTERVAL '${OFFER_DURATION_DAYS} days' WHERE id = $1 AND pro_id = $2 AND status = 'closed'`, [Number(req.params.id), proConnected.pro.id]);
    res.redirect(303, "/mon-espace-pro");
  });

  router.post("/mon-espace-pro/offre/:id/supprimer", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    try {
      const result = await pool.query(`DELETE FROM job_offers WHERE id = $1 AND pro_id = $2 RETURNING job_title`, [Number(req.params.id), proConnected.pro.id]);
      if (result.rowCount) await logAdminAction("job_deleted_by_pro", "job", Number(req.params.id), `Offre supprimee : ${result.rows[0].job_title}`);
    } catch (error) { console.error("Erreur suppression offre :", error.message); }
    res.redirect(303, "/mon-espace-pro");
  });
  
// PAGE DE DÉTAIL D'UNE OFFRE D'EMPLOI
router.get("/emplois/:id", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const id = Number(req.params.id);
    
    // On récupère l'offre
    const result = await pool.query(`SELECT * FROM job_offers WHERE id = $1 AND status = 'approved'`, [id]);
    if (!result.rows.length) return res.redirect(303, "/emplois");
    const job = result.rows[0];

    // On prépare les boutons de contact
    let contactButtons = "";
    if (job.contact_phone) {
      contactButtons += `<a href="tel:+229${escapeHtml(cleanBeninPhone(job.contact_phone))}" class="button" style="background:#e0e7ff; color:#1e3a8a; width:100%; margin-bottom:10px;">📞 Appeler</a>`;
    }
    if (job.contact_whatsapp) {
      contactButtons += `<a href="https://wa.me/229${escapeHtml(cleanBeninPhone(job.contact_whatsapp))}?text=${encodeURIComponent("Bonjour, je vous contacte via TrouveMoi au sujet de votre offre d'emploi.")}" target="_blank" class="button whatsapp" style="width:100%; margin-bottom:10px;">💬 WhatsApp</a>`;
    }
    if (job.contact_email) {
      contactButtons += `<a href="mailto:${escapeHtml(job.contact_email)}?subject=${encodeURIComponent("Candidature - " + job.job_title)}" class="button secondary" style="width:100%;">✉️ Envoyer un e-mail</a>`;
    }

    res.send(page(job.job_title, `
      <div style="max-width: 800px; margin: 40px auto;">
        <div class="card" style="padding: 32px 24px;">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:20px;">
            <div>
              <h1 style="font-size: 28px; color: #1e3a8a; margin-bottom: 8px;">${escapeHtml(job.job_title)}</h1>
              <div style="font-size: 16px; font-weight: 600; color: #4b5563;">🏢 ${escapeHtml(job.company_name)}</div>
            </div>
            <span class="badge" style="background: #eff6ff; color: #1e40af; font-size: 14px; padding: 8px 16px;">${escapeHtml(job.contract_type)}</span>
          </div>

          <div style="display:flex; gap:20px; font-size:14px; color:#6b7280; border-bottom:1px solid #e5e7eb; padding-bottom:20px; margin-bottom:20px;">
            <span>📍 ${escapeHtml(job.city)}</span>
            <span>📅 Publiée le ${new Date(job.created_at).toLocaleDateString("fr-FR")}</span>
          </div>

          <h2 style="font-size: 20px; color: #1f2937; margin-bottom: 12px;">Description du poste</h2>
          <p style="font-size: 15px; line-height: 1.8; color: #374151; white-space: pre-line;">${escapeHtml(job.description)}</p>
        </div>

        <div class="card" style="text-align: center;">
          <h2 style="font-size: 20px; margin-bottom: 16px;">Comment postuler ?</h2>
          <p style="color: #6b7280; margin-bottom: 20px;">Contactez directement l'entreprise via les moyens ci-dessous :</p>
          <div style="max-width: 400px; margin: 0 auto;">
            ${contactButtons}
          </div>
        </div>
        
        <div style="text-align: center; margin-top: 20px;">
          <a href="/emplois" style="color: #6b7280; text-decoration: underline;">← Retour à toutes les offres</a>
        </div>
      </div>
    `, proConnected));
  } catch (error) {
    res.status(500).send(page("Erreur", "<h2>Une erreur est survenue.</h2>", null));
  }
});
  return router;
};
