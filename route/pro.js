const express = require('express');

module.exports = function(pool, page, getConnectedPro, escapeHtml, upload, uploadToCloudinary, clearRateLimit, takeRateLimit, setProCookie, clearProCookie, generateUniqueProCode, logAdminAction, OFFER_DURATION_DAYS, deleteFromCloudinary, cleanBeninPhone, APP_URL) {
  const router = express.Router();

  router.post("/login", async (req, res) => {
    const ip = req.ip || "unknown"; const ipKey = `pro_login:ip:${ip}`;
    if (!(await takeRateLimit(ipKey, 30, 15 * 60 * 1000))) return res.status(429).send(page("Trop de tentatives", "<h1>⏳ Trop de tentatives</h1>", null));
    const code = String(req.body.pro_code || "").trim().toUpperCase();
    const codeKey = `pro_login:code:${code}`;
    if (!(await takeRateLimit(codeKey, 3, 15 * 60 * 1000))) return res.status(429).send(page("Trop de tentatives", "<h1>⏳ Trop de tentatives sur ce code</h1>", null));
    try {
      const result = await pool.query(`SELECT id FROM professional_applications WHERE pro_code = $1 AND status = 'approved'`, [code]);
      if (!result.rows.length) return res.status(401).send(page("Erreur", "<h2>Code incorrect.</h2>", null));
      await clearRateLimit(codeKey); setProCookie(res, code); res.redirect(303, "/mon-espace-pro");
    } catch (error) { res.redirect(303, "/mon-espace-pro"); }
  });

  router.post("/logout", (req, res) => { clearProCookie(res); res.redirect(303, "/mon-espace-pro"); });

  router.get("/", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.send(page("Espace pro", `<section class="card" style="max-width: 500px; margin: 40px auto;"><h1 style="text-align: center;">Espace pro</h1><form action="/mon-espace-pro/login" method="POST"><label>Code pro</label><input name="pro_code" required maxlength="10" placeholder="TM12345678" style="text-transform:uppercase; text-align:center; font-size:20px;"><button type="submit" style="width: 100%;">Se connecter</button></form></section>`, null));

    let offers = [], gdprRequests = [], myReviews = [], withdrawals = [];
    let stats30 = { views: 0, phone: 0, wa: 0 }, stats90 = { views: 0, phone: 0, wa: 0 }, statsAll = { views: 0, phone: 0, wa: 0 };
    
    try {
      offers = (await pool.query(`SELECT * FROM job_offers WHERE pro_id = $1 ORDER BY created_at DESC`, [proConnected.pro.id])).rows;
      gdprRequests = (await pool.query(`SELECT * FROM gdpr_requests WHERE pro_id = $1 ORDER BY created_at DESC LIMIT 20`, [proConnected.pro.id])).rows;
      myReviews = (await pool.query(`SELECT * FROM reviews WHERE pro_id = $1 AND status = 'approved' ORDER BY created_at DESC LIMIT 10`, [proConnected.pro.id])).rows;
      withdrawals = (await pool.query(`SELECT * FROM withdrawal_requests WHERE pro_id = $1 ORDER BY created_at DESC LIMIT 10`, [proConnected.pro.id])).rows;
      
      const s30 = await pool.query(`SELECT SUM(views) as v, SUM(phone_clicks) as p, SUM(wa_clicks) as w FROM pro_stats WHERE pro_id = $1 AND date >= CURRENT_DATE - INTERVAL '30 days'`, [proConnected.pro.id]);
      if (s30.rows.length) { stats30 = { views: Number(s30.rows[0].v || 0), phone: Number(s30.rows[0].p || 0), wa: Number(s30.rows[0].w || 0) }; }
      
      const s90 = await pool.query(`SELECT SUM(views) as v, SUM(phone_clicks) as p, SUM(wa_clicks) as w FROM pro_stats WHERE pro_id = $1 AND date >= CURRENT_DATE - INTERVAL '90 days'`, [proConnected.pro.id]);
      if (s90.rows.length) { stats90 = { views: Number(s90.rows[0].v || 0), phone: Number(s90.rows[0].p || 0), wa: Number(s90.rows[0].w || 0) }; }
      
      const sAll = await pool.query(`SELECT SUM(views) as v, SUM(phone_clicks) as p, SUM(wa_clicks) as w FROM pro_stats WHERE pro_id = $1`, [proConnected.pro.id]);
      if (sAll.rows.length) { statsAll = { views: Number(sAll.rows[0].v || 0), phone: Number(sAll.rows[0].p || 0), wa: Number(sAll.rows[0].w || 0) }; }
    } catch (error) { return res.status(500).send(page("Erreur", "<h2>Erreur technique.</h2>", proConnected)); }

    const pendingDeletion = gdprRequests.some(r => r.request_type === "deletion" && r.status === "pending");
    const isOnLeave = proConnected.pro.unavailable_until && new Date(proConnected.pro.unavailable_until) > new Date();
    const leaveStatus = isOnLeave ? `<span class="badge" style="background:#fee2e2;color:#991b1b;">En congés jusqu'au ${new Date(proConnected.pro.unavailable_until).toLocaleDateString("fr-FR")}</span>` : `<span class="badge" style="background:#d1fae5;color:#065f46;">Actif</span>`;

    res.send(page("Espace pro", `
      <div class="card" style="background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:20px;">
        <div><h2 style="color:white; margin:0;">Bonjour ${escapeHtml(proConnected.pro.company_name || proConnected.pro.full_name)} 👋</h2></div>
        <div style="background:rgba(255,255,255,0.15); padding:12px 24px; border-radius:12px; text-align:center;">
          <div style="font-size:11px; text-transform:uppercase; letter-spacing:1px;">Votre code pro</div>
          <div style="font-size:28px; font-weight:800; font-family:monospace; letter-spacing:2px;">${escapeHtml(proConnected.code)}</div>
        </div>
      </div>
      
      <div style="display:flex; gap:10px; margin-bottom:24px; flex-wrap:wrap;">
        <a class="button" href="/publier-emploi">📢 Publier une offre</a>
        <a class="button" href="/mon-espace-pro/agences" style="background: #dbeafe; color: #1e40af;">📋 Mes agences</a>
        <a class="button" href="/mon-espace-pro/agences/nouvelle" style="background: #8b5cf6;">🏢 Ajouter une agence</a>
        <form action="/mon-espace-pro/logout" method="POST" style="display:inline; margin-left:auto;"><button class="danger" type="submit">Déconnexion</button></form>
      </div>
      
      <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap:20px;">
        <section class="card">
          <h2 style="font-size:20px; margin-bottom:16px;">Mes infos</h2>
          <p><span class="label">Nom :</span> ${escapeHtml(proConnected.pro.full_name)}</p>
          <p><span class="label">Profession :</span> ${escapeHtml(proConnected.pro.profession)}</p>
          <p><span class="label">Ville :</span> ${escapeHtml(proConnected.pro.city)}</p>
          <p><span class="label">Statut :</span> ${leaveStatus}</p>

          <div style="margin-top: 20px; padding: 16px; background: #f8fafc; border-radius: 12px; border: 1px solid #e2e8f0;">
            <p style="font-weight: bold; margin-bottom: 12px; font-size:14px; color:#1e40af;">📊 Statistiques (30 derniers jours)</p>
            <div style="display:flex; justify-content:space-between; font-size:13px; margin-bottom:6px;"><span>Vues du profil :</span> <strong>${stats30.views}</strong></div>
            <div style="display:flex; justify-content:space-between; font-size:13px; margin-bottom:6px;"><span>Clics "Appeler" :</span> <strong>${stats30.phone}</strong></div>
            <div style="display:flex; justify-content:space-between; font-size:13px;"><span>Clics "WhatsApp" :</span> <strong>${stats30.wa}</strong></div>
          </div>

          <div style="margin-top: 16px; padding: 16px; background: #fffbeb; border-radius: 12px; border: 1px solid #fde68a;">
            <form action="/mon-espace-pro/conges" method="POST" style="margin:0;">
              <label style="margin-top:0; font-size:12px;">M'absent jusqu'au :</label>
              <input type="date" name="unavailable_until" value="${proConnected.pro.unavailable_until ? new Date(proConnected.pro.unavailable_until).toISOString().split('T')[0] : ''}" style="padding:8px; margin-bottom:8px;">
              <button type="submit" class="warning" style="width: 100%; padding:8px; font-size:13px; border-radius:8px;">Enregistrer congés</button>
            </form>
          </div>

          <div class="actions" style="margin-top:20px; display:grid; grid-template-columns: 1fr 1fr; gap:8px;">
            <a class="button secondary" href="/mon-espace-pro/modifier-profil">✏️ Modifier profil</a>
            <a class="button secondary" href="/mon-espace-pro/modifier-telephone">👁️ Visibilité</a>
            <a class="button secondary" href="/mon-espace-pro/modifier-photo">📷 Photo</a>
            <a class="button secondary" href="/mon-espace-pro/modifier-galerie">📸 Galerie</a>
          </div>
        </section>
        
        <section class="card">
          <h2 style="font-size:20px; margin-bottom:16px;">🎁 Parrainage</h2>
          <p style="font-size: 14px; margin-bottom: 12px;">Invitez un pro et gagnez <strong>100 FCFA</strong> dès qu'il paie son inscription.</p>
          
          <div style="background: white; padding: 12px; border-radius: 8px; margin-bottom: 12px; border:1px solid #e5e7eb;">
            <p style="font-size: 12px; color: #6b7280; margin-bottom: 4px;">Votre code de parrainage :</p>
            <div style="font-size: 24px; font-weight: 800; font-family: monospace; color: #059669;">${proConnected.pro.referral_code || 'En attente...'}</div>
          </div>

          <div style="background: white; padding: 12px; border-radius: 8px; margin-bottom: 12px; border:1px solid #e5e7eb;">
            <p style="font-size: 12px; color: #6b7280; margin-bottom: 4px;">Votre lien de parrainage :</p>
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
            <label style="margin-top:0; font-size:12px;">Numéro Mobile Money</label>
            <input name="phone_number" required maxlength="30" placeholder="01XXXXXXXX" pattern="01[0-9]{8}" style="padding:8px; margin-bottom:8px;">
            <label style="margin-top:0; font-size:12px;">Montant à retirer (min. 1000 F)</label>
            <input name="amount" type="number" min="1000" max="${proConnected.pro.referral_balance || 0}" required style="padding:8px; margin-bottom:8px;">
            <button type="submit" class="success" style="width: 100%; padding:8px; font-size:13px; border-radius:8px;">Demander le retrait</button>
          </form>
        </section>
      </div>
      
      <section class="card" style="margin-top:20px;">
        <h2 style="font-size:20px; margin-bottom:16px;">Mes offres (${offers.length})</h2>
        ${offers.length > 0 ? offers.map(offer => `
          <article class="card" style="box-shadow:none; border:1px solid #e5e7eb; margin-bottom:16px;">
            <h2 style="font-size:18px;">${escapeHtml(offer.job_title)}</h2>
            <p><span class="badge badge-${offer.status}">${offer.status}</span></p>
            <div class="actions" style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap;">
              ${offer.status === "approved" ? `<form action="/mon-espace-pro/offre/${offer.id}/close" method="POST" style="margin:0;"><button class="warning" type="submit" style="padding:6px 12px; font-size:12px;">🔒 Cloturer</button></form>` : ""}
              ${offer.status === "closed" ? `<form action="/mon-espace-pro/offre/${offer.id}/reopen" method="POST" style="margin:0;"><button class="success" type="submit" style="padding:6px 12px; font-size:12px;">🔓 Rouvrir</button></form>` : ""}
              <a class="button secondary" href="/mon-espace-pro/offre/${offer.id}/modifier" style="padding:6px 12px; font-size:12px; margin:0;">✏️ Modifier</a>
              <form action="/mon-espace-pro/offre/${offer.id}/supprimer" method="POST" style="margin:0;"><button class="danger" type="submit" style="padding:6px 12px; font-size:12px;">🗑️ Supprimer</button></form>
            </div>
          </article>
        `).join("") : `<p class="muted">Aucune offre.</p>`}
      </section>

      <section class="card" style="margin-top:20px;">
        <h2 style="font-size:20px; margin-bottom:16px;">RGPD & Confidentialité</h2>
        <div class="actions" style="display:flex; gap:10px; flex-wrap:wrap;">
          <a class="button secondary" href="/mon-espace-pro/mes-donnees">📥 Télécharger mes données</a>
          <form action="/mon-espace-pro/demande-suppression" method="POST" style="display:inline; margin:0;">
            <button class="danger" type="submit" onclick="return confirm('⚠️ Êtes-vous sûr de vouloir supprimer définitivement votre compte ?')">🗑️ Supprimer mon compte</button>
          </form>
        </div>
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

  router.post("/conges", async (req, res) => {
    const proConnected = await getConnectedPro(req); if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    await pool.query(`UPDATE professional_applications SET unavailable_until = $1 WHERE id = $2`, [req.body.unavailable_until ? new Date(req.body.unavailable_until) : null, proConnected.pro.id]);
    res.redirect(303, "/mon-espace-pro");
  });

  router.get("/modifier-profil", async (req, res) => {
    const proConnected = await getConnectedPro(req); if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    res.send(page("Modifier Profil", `
      <section class="card" style="max-width: 600px; margin: 40px auto;">
        <h1 style="text-align:center; font-size:24px;">✏️ Modifier mon profil</h1>
        <form action="/mon-espace-pro/modifier-profil" method="POST" style="margin-top:24px;">
          <h3 style="margin-bottom:12px;">Identité et contact</h3>
          <label>Nom complet (Vérifié KYC - Non modifiable)</label>
          <input name="full_name" value="${escapeHtml(proConnected.pro.full_name)}" readonly style="background:#e5e7eb; cursor:not-allowed; color:#6b7280;">
          <label>Nom de l'entreprise (Modifiable)</label>
          <input name="company_name" maxlength="200" value="${escapeHtml(proConnected.pro.company_name || '')}">
          <label>Téléphone *</label>
          <input name="phone" type="tel" required maxlength="30" pattern="01[0-9]{8}" value="${escapeHtml(proConnected.pro.phone)}">
          
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
            <div><label>Préférence de contact</label><select name="contact_preference"><option value="whatsapp" ${proConnected.pro.contact_preference === 'whatsapp' ? 'selected' : ''}>WhatsApp</option><option value="email" ${proConnected.pro.contact_preference === 'email' ? 'selected' : ''}>E-mail</option></select></div>
            <div><label>Numéro WhatsApp</label><input name="whatsapp_number" type="tel" maxlength="30" pattern="01[0-9]{8}" value="${escapeHtml(proConnected.pro.whatsapp_number || '')}"></div>
          </div>
          <label>E-mail</label>
          <input name="contact_email" type="email" maxlength="254" value="${escapeHtml(proConnected.pro.contact_email || '')}">
          
          <div style="text-align:center; margin-top:30px;"><button type="submit" class="success" style="width:100%; padding:16px;">💾 Enregistrer les modifications</button></div>
        </form>
        <p style="text-align:center; margin-top:20px;"><a href="/mon-espace-pro" style="color:#6b7280;">← Retour</a></p>
      </section>
    `, proConnected));
  });

  router.post("/modifier-profil", async (req, res) => {
    const proConnected = await getConnectedPro(req); if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    const { company_name, phone, contact_email, contact_preference, whatsapp_number } = req.body;
    const cleanPhone = cleanBeninPhone(phone);
    if (!cleanPhone) return res.status(400).send(page("Erreur", "<h2>Téléphone invalide.</h2>", proConnected));
    const cleanWhatsapp = whatsapp_number ? cleanBeninPhone(whatsapp_number) : null;
    const email = String(contact_email || "").trim().slice(0, 254);
    const preference = ["whatsapp", "email"].includes(contact_preference) ? contact_preference : "whatsapp";
    
    await pool.query(`UPDATE professional_applications SET company_name = $1, phone = $2, contact_email = $3, contact_preference = $4, whatsapp_number = $5, updated_at = NOW() WHERE id = $6`, [company_name || null, cleanPhone, email || null, preference, cleanWhatsapp, proConnected.pro.id]);
    res.redirect(303, "/mon-espace-pro");
  });

  router.get("/mes-donnees", async (req, res) => {
    const proConnected = await getConnectedPro(req); if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    try {
      const offersResult = await pool.query(`SELECT * FROM job_offers WHERE pro_id = $1`, [proConnected.pro.id]);
      const gdprResult = await pool.query(`SELECT * FROM gdpr_requests WHERE pro_id = $1`, [proConnected.pro.id]);
      const reviewsResult = await pool.query(`SELECT * FROM reviews WHERE pro_id = $1`, [proConnected.pro.id]);
      const agenciesResult = await pool.query(`SELECT * FROM agencies WHERE parent_pro_id = $1`, [proConnected.pro.id]);
      const exportData = { utilisateur: proConnected.pro, offres: offersResult.rows, demandes: gdprResult.rows, avis: reviewsResult.rows, agences: agenciesResult.rows };
      res.setHeader("Content-Type", "application/json"); res.setHeader("Content-Disposition", `attachment; filename="trouvemoi-${proConnected.code}.json"`); res.send(JSON.stringify(exportData, null, 2));
    } catch (e) { res.status(500).send("Erreur."); }
  });

  router.post("/demande-suppression", async (req, res) => {
    const proConnected = await getConnectedPro(req); if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    const existing = await pool.query(`SELECT id FROM gdpr_requests WHERE pro_id = $1 AND request_type = 'deletion' AND status = 'pending' LIMIT 1`, [proConnected.pro.id]);
    if (existing.rows.length) return res.send(page("Déjà demandé", "<h1>Déjà en cours</h1>", proConnected));
    await pool.query(`INSERT INTO gdpr_requests (pro_id, request_type, status, message) VALUES ($1, 'deletion', 'pending', $2)`, [proConnected.pro.id, "Demande pro"]);
    await logAdminAction("gdpr_deletion_requested", "pro", proConnected.pro.id, "Demande de suppression de compte");
    res.redirect(303, "/mon-espace-pro");
  });

  router.post("/annuler-suppression", async (req, res) => {
    const proConnected = await getConnectedPro(req); if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    await pool.query(`UPDATE gdpr_requests SET status = 'rejected', processed_at = NOW() WHERE pro_id = $1 AND request_type = 'deletion' AND status = 'pending'`, [proConnected.pro.id]);
    res.redirect(303, "/mon-espace-pro");
  });

  router.get("/modifier-photo", async (req, res) => {
    const proConnected = await getConnectedPro(req); if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    res.send(page("Photo", `<section class="card" style="max-width: 500px; margin: 40px auto;"><h1 style="text-align:center;">📷 Photo d'activité</h1><form action="/mon-espace-pro/modifier-photo" method="POST" enctype="multipart/form-data"><input name="photo_activite" type="file" accept="image/*" required><button type="submit" style="width:100%; margin-top:10px;">📤 Enregistrer</button></form><p style="text-align:center; margin-top:24px;"><a href="/mon-espace-pro">← Retour</a></p></section>`, proConnected));
  });

  router.post("/modifier-photo", upload.single("photo_activite"), async (req, res) => {
    const proConnected = await getConnectedPro(req); if (!proConnected || !req.file) return res.redirect(303, "/mon-espace-pro/modifier-photo");
    const photoKey = `photo_main_limit:${proConnected.pro.id}`;
    if (!(await takeRateLimit(photoKey, 1, 7 * 24 * 60 * 60 * 1000))) return res.status(429).send(page("Limite atteinte", "<h1>⏳ 1 fois par semaine.</h1>", proConnected));
    try {
      const result = await uploadToCloudinary(req.file.buffer, "trouvemoi/activites", `activite_${proConnected.pro.id}_${Date.now()}`);
      if (proConnected.pro.photo_activite_url) await deleteFromCloudinary(proConnected.pro.photo_activite_url);
      await pool.query(`UPDATE professional_applications SET photo_activite_url = $1 WHERE id = $2`, [result.secure_url, proConnected.pro.id]);
      res.redirect(303, "/mon-espace-pro");
    } catch (e) { await clearRateLimit(photoKey); res.redirect(303, "/mon-espace-pro/modifier-photo"); }
  });

  router.get("/modifier-galerie", async (req, res) => {
    const proConnected = await getConnectedPro(req); if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    res.send(page("Galerie", `<section class="card" style="max-width: 600px; margin: 40px auto;"><h1>📸 Galerie</h1><form action="/mon-espace-pro/modifier-galerie" method="POST" enctype="multipart/form-data"><input type="file" name="photo1"><input type="text" name="desc1" placeholder="Description"><input type="file" name="photo2"><input type="text" name="desc2" placeholder="Description"><button type="submit" style="width:100%;">Enregistrer</button></form><p style="text-align:center; margin-top:24px;"><a href="/mon-espace-pro">← Retour</a></p></section>`, proConnected));
  });

  router.post("/modifier-galerie", upload.fields([{ name: 'photo1', maxCount: 1 }, { name: 'photo2', maxCount: 1 }]), async (req, res) => {
    const proConnected = await getConnectedPro(req); if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    const galleryKey = `gallery_limit:${proConnected.pro.id}`;
    if (!(await takeRateLimit(galleryKey, 1, 7 * 24 * 60 * 60 * 1000))) return res.status(429).send(page("Limite atteinte", "<h1>⏳ 1 fois par semaine.</h1>", proConnected));
    res.redirect(303, "/mon-espace-pro");
  });
router.get("/modifier-telephone", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  res.send(page("Visibilité", `
    <section class="card" style="max-width: 500px; margin: 40px auto;">
      <h1 style="text-align:center;">👁️ Visibilité du numéro</h1>
      <form action="/mon-espace-pro/modifier-telephone" method="POST">
        <div style="background:#f9fafb; padding:16px; border-radius:12px; border:1px solid #e5e7eb;">
          <label><input type="checkbox" name="phone_public" value="yes" ${proConnected.pro.phone_public ? "checked" : ""}> <span>Rendre mon numéro public sur mon profil</span></label>
        </div>
        <button type="submit" style="width:100%; margin-top:20px;">Enregistrer</button>
      </form>
      <p style="text-align:center; margin-top:20px;"><a href="/mon-espace-pro" style="color:#6b7280;">← Retour</a></p>
    </section>
  `, proConnected));
});

router.post("/modifier-telephone", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  await pool.query(`UPDATE professional_applications SET phone_public = $1 WHERE id = $2`, [req.body.phone_public === "yes", proConnected.pro.id]);
  res.redirect(303, "/mon-espace-pro");
});
  return router;
};
