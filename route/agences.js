const express = require('express');

module.exports = function(pool, page, getConnectedPro, escapeHtml, safeCoord, cleanBeninPhone, upload, uploadToCloudinary, BYPASS_PAYMENT) {
  const router = express.Router();

  // --- 1. LISTE DES AGENCES DU PRO ---
  router.get("/mon-espace-pro/agences", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");

    const agenciesResult = await pool.query("SELECT * FROM agencies WHERE parent_pro_id = $1 ORDER BY created_at DESC", [proConnected.pro.id]);
    const listHtml = agenciesResult.rows.map(a => {
      let badge = "";
      if (a.status === "pending_payment") badge = `<span class="badge" style="background:#fef3c7;color:#92400e;">⏳ Attente paiement</span>`;
      else if (a.status === "pending_validation") badge = `<span class="badge" style="background:#dbeafe;color:#1e40af;">⏳ Attente validation</span>`;
      else if (a.status === "approved") badge = `<span class="badge" style="background:#d1fae5;color:#065f46;">✅ En ligne</span>`;
      else badge = `<span class="badge" style="background:#fee2e2;color:#991b1b;">❌ Refusée</span>`;

      return `
        <a href="/mon-espace-pro/agences/${a.id}" style="text-decoration:none; color:inherit; display:block; margin-bottom:12px;" onmouseover="this.style.opacity='0.8'" onmouseout="this.style.opacity='1'">
          <div style="padding:16px; border:1px solid #e5e7eb; border-radius:12px; background:white; display:flex; justify-content:space-between; align-items:center;">
            <div><strong style="font-size:16px; color:#1e40af;">${escapeHtml(a.name)}</strong><br><span style="font-size:13px; color:#6b7280;">📍 ${escapeHtml(a.address)}</span></div>
            <div>${badge}</div>
          </div>
        </a>`;
    }).join("");

    res.send(page("Mes Agences", `
      <section class="card" style="max-width: 700px; margin: 40px auto;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
          <h1 style="margin:0;">📋 Mes Agences</h1>
          <a href="/mon-espace-pro" class="button secondary" style="margin:0;">← Retour</a>
        </div>
        ${listHtml || `<div style="text-align:center; padding:40px; background:#f9fafb; border-radius:12px; border:1px dashed #cbd5e0;"><p style="color:#6b7280;">Vous n'avez pas encore d'agence.</p></div>`}
      </section>`, proConnected));
  });

  // --- 2. AJOUTER UNE AGENCE (GET) ---
  router.get("/mon-espace-pro/agences/nouvelle", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");

    res.send(page("Ajouter une agence", `
      <section class="card" style="max-width: 700px; margin: 40px auto;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
          <h1 style="margin:0;">➕ Ajouter une agence</h1>
          <a href="/mon-espace-pro/agences" class="button secondary" style="margin:0;">← Retour</a>
        </div>
        <div style="background:#f8fafc; padding:20px; border-radius:12px; border:1px solid #e2e8f0;">
          <form action="/mon-espace-pro/agences/nouvelle" method="POST" enctype="multipart/form-data">
            <label>Nom de l'agence *</label><input name="name" required maxlength="200">
            <label>Adresse exacte *</label><input name="address" required maxlength="300">
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:10px;">
              <div><label>Téléphone (optionnel)</label><input name="agency_phone" type="tel" maxlength="30" placeholder="Ex: 0194010345"></div>
              <div><label>WhatsApp (optionnel)</label><input name="agency_whatsapp" type="tel" maxlength="30" placeholder="Ex: 0194010345"></div>
            </div>
            <input type="hidden" name="latitude" id="agency-lat"><input type="hidden" name="longitude" id="agency-lng">
            <button type="button" onclick="getLocationAgency()" style="background:#3b82f6; width:100%; margin-bottom:10px;">📍 Utiliser ma position actuelle</button>
            <p id="gps-status-agency" style="text-align:center; color:#2563eb; font-weight:bold;"></p>
            <label>Photo 1 *</label><input name="photo_1" type="file" accept="image/*" required>
            <input name="desc1" maxlength="150" placeholder="Description photo 1" style="margin-top:-10px; margin-bottom:10px;">
            <label>Photo 2</label><input name="photo_2" type="file" accept="image/*">
            <input name="desc2" maxlength="150" placeholder="Description photo 2" style="margin-top:-10px; margin-bottom:10px;">
            <label>Photo 3</label><input name="photo_3" type="file" accept="image/*">
            <input name="desc3" maxlength="150" placeholder="Description photo 3" style="margin-top:-10px; margin-bottom:15px;">
            <button type="submit" style="width:100%; padding:14px;">Payer 1500 FCFA et créer</button>
          </form>
        </div>
      </section>
      <script>
        function getLocationAgency() {
          const status = document.getElementById('gps-status-agency');
          navigator.geolocation.getCurrentPosition(
            (position) => { document.getElementById('agency-lat').value = position.coords.latitude; document.getElementById('agency-lng').value = position.coords.longitude; status.innerText = "✅ Position GPS enregistrée !"; },
            (error) => { status.innerText = "❌ Impossible de vous localiser."; }, { enableHighAccuracy: true, timeout: 10000 }
          );
        }
      </script>`, proConnected));
  });

  // --- 3. AJOUTER UNE AGENCE (POST + KKIAPAY) ---
  router.post("/mon-espace-pro/agences/nouvelle", upload.fields([{ name: "photo_1", maxCount: 1 }, { name: "photo_2", maxCount: 1 }, { name: "photo_3", maxCount: 1 }]), async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    const { name, address, latitude, longitude, agency_phone, agency_whatsapp } = req.body;
    const desc1 = String(req.body.desc1 || "").trim().slice(0, 150);
    const desc2 = String(req.body.desc2 || "").trim().slice(0, 150);
    const desc3 = String(req.body.desc3 || "").trim().slice(0, 150);
    const files = req.files || {};

    try {
      const p1 = await uploadToCloudinary(files.photo_1[0].buffer, "trouvemoi/agences", `agence_${Date.now()}_1`);
      let p2url = null; let p3url = null;
      if (files.photo_2?.[0]) { const r = await uploadToCloudinary(files.photo_2[0].buffer, "trouvemoi/agences", `agence_${Date.now()}_2`); p2url = r.secure_url; }
      if (files.photo_3?.[0]) { const r = await uploadToCloudinary(files.photo_3[0].buffer, "trouvemoi/agences", `agence_${Date.now()}_3`); p3url = r.secure_url; }

      const insertResult = await pool.query(
        `INSERT INTO agencies (parent_pro_id, name, address, latitude, longitude, photo_1, photo_2, photo_3, photo_1_desc, photo_2_desc, photo_3_desc, phone, whatsapp_number, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, ${BYPASS_PAYMENT ? "'pending_validation'" : "'pending_payment'"}) RETURNING id`,
        [proConnected.pro.id, name, address, safeCoord(latitude, 90), safeCoord(longitude, 180), p1.secure_url, p2url, p3url, desc1 || null, desc2 || null, desc3 || null, cleanBeninPhone(agency_phone) || null, cleanBeninPhone(agency_whatsapp) || null]
      );
      const agencyId = insertResult.rows[0].id;

      if (BYPASS_PAYMENT) return res.send(page("Succès", "<h1>🎉 Agence créée (Mode Test)</h1><a href='/mon-espace-pro/agences'>Retour</a>", proConnected));

      res.send(page("Paiement Agence", `
        <section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;">
          <h1>💳 Finalisez l'ouverture</h1>
          <button onclick="openKkiapayWidget({ amount: 1500, api_key: '${process.env.KKIAPAY_PUBLIC_KEY}', sandbox: ${process.env.KKIAPAY_SANDBOX === "true"}, callback: '${process.env.APP_URL}/mon-espace-pro/agences/verifier?agency_id=${agencyId}', data: 'AGENCE-${agencyId}' })" style="padding:16px; background:#10b981; width:100%;">Payer 1500 FCFA</button>
        </section>
        <script src="https://cdn.kkiapay.me/k.js"></script>`, proConnected));
    } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur upload.</h2>", proConnected)); }
  });

  // --- 4. DETAILS D'UNE AGENCE (PRIVÉ) ---
  router.get("/mon-espace-pro/agences/:id", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");
  const id = Number(req.params.id);
  const result = await pool.query(`SELECT * FROM agencies WHERE id = $1 AND parent_pro_id = $2`, [id, proConnected.pro.id]);
  if (!result.rows.length) return res.redirect(303, "/mon-espace-pro/agences");
  const agency = result.rows[0];

  const statsRes = await pool.query(`SELECT SUM(views) as v, SUM(phone_clicks) as p, SUM(wa_clicks) as w FROM agency_stats WHERE agency_id = $1`, [id]);
  const stats = { views: Number(statsRes.rows[0]?.v || 0), phone: Number(statsRes.rows[0]?.p || 0), wa: Number(statsRes.rows[0]?.w || 0) };

  let badge = agency.status === 'approved' ? `<span class="badge" style="background:#d1fae5;color:#065f46;">✅ En ligne</span>` : `<span class="badge" style="background:#fef3c7;color:#92400e;">⏳ En attente</span>`;

  res.send(page("Détails de l'agence", `
    <section class="card" style="max-width: 700px; margin: 40px auto;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
        <h1 style="margin:0;">🏢 ${escapeHtml(agency.name)}</h1>
        <div style="display:flex; gap:10px;"><a href="/mon-espace-pro/agences/${agency.id}/modifier" class="button" style="background:#f59e0b; margin:0;">✏️ Modifier</a><a href="/mon-espace-pro/agences" class="button secondary" style="margin:0;">← Retour</a></div>
      </div>
      <div style="margin-bottom:20px;">${badge}</div>
      <div style="background:#f9fafb; padding:20px; border-radius:12px; margin-bottom:20px;">
        <p><strong>Adresse :</strong> ${escapeHtml(agency.address)}</p>
        <p><strong>Téléphone :</strong> ${escapeHtml(agency.phone || "Numéro du compte principal")}</p>
        <p><strong>WhatsApp :</strong> ${escapeHtml(agency.whatsapp_number || "Numéro du compte principal")}</p>
      </div>
      <div style="background:#f8fafc; padding:16px; border-radius:12px; border:1px solid #e2e8f0; margin-bottom:20px;">
        <h3 style="font-size:16px; color:#1e40af; margin-bottom:12px;">📊 Statistiques de cette agence</h3>
        <div style="display:flex; justify-content:space-between; margin-bottom:6px;"><span>Vues de la page :</span> <strong>${stats.views}</strong></div>
        <div style="display:flex; justify-content:space-between; margin-bottom:6px;"><span>Clics "Appeler" :</span> <strong>${stats.phone}</strong></div>
        <div style="display:flex; justify-content:space-between;"><span>Clics "WhatsApp" :</span> <strong>${stats.wa}</strong></div>
      </div>
      <h3 style="font-size:16px; margin-bottom:10px;">Photos de l'agence</h3>
      <div style="display:flex; gap:10px; flex-wrap:wrap;">
        ${agency.photo_1 ? `<img src="${escapeHtml(agency.photo_1)}" style="width:100px; height:100px; object-fit:cover; border-radius:8px;">` : ""}
        ${agency.photo_2 ? `<img src="${escapeHtml(agency.photo_2)}" style="width:100px; height:100px; object-fit:cover; border-radius:8px;">` : ""}
        ${agency.photo_3 ? `<img src="${escapeHtml(agency.photo_3)}" style="width:100px; height:100px; object-fit:cover; border-radius:8px;">` : ""}
      </div>
    </section>`, proConnected));
});

  // --- 5. MODIFIER UNE AGENCE (GET + POST) ---
  router.get("/mon-espace-pro/agences/:id/modifier", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    const result = await pool.query(`SELECT * FROM agencies WHERE id = $1 AND parent_pro_id = $2`, [Number(req.params.id), proConnected.pro.id]);
    if (!result.rows.length) return res.redirect(303, "/mon-espace-pro/agences");
    const agency = result.rows[0];

    res.send(page("Modifier l'agence", `
      <section class="card" style="max-width: 700px; margin: 40px auto;">
        <form action="/mon-espace-pro/agences/${agency.id}/modifier" method="POST" enctype="multipart/form-data">
          <label>Nom de l'agence *</label><input name="name" required value="${escapeHtml(agency.name)}">
          <label>Adresse exacte *</label><input name="address" required value="${escapeHtml(agency.address)}">
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;"><div><label>Téléphone</label><input name="agency_phone" value="${escapeHtml(agency.phone || '')}"></div><div><label>WhatsApp</label><input name="agency_whatsapp" value="${escapeHtml(agency.whatsapp_number || '')}"></div></div>
          <button type="submit" style="width:100%; margin-top:20px;">Enregistrer</button>
        </form>
      </section>`, proConnected));
  });

  router.post("/mon-espace-pro/agences/:id/modifier", upload.fields([{ name: "photo_1", maxCount: 1 }, { name: "photo_2", maxCount: 1 }, { name: "photo_3", maxCount: 1 }]), async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    const id = Number(req.params.id);
    const { name, address, latitude, longitude, agency_phone, agency_whatsapp } = req.body;
    const files = req.files || {};
    const current = await pool.query(`SELECT photo_1, photo_2, photo_3 FROM agencies WHERE id = $1 AND parent_pro_id = $2`, [id, proConnected.pro.id]);
    if (!current.rows.length) return res.redirect(303, "/mon-espace-pro/agences");
    
    let p1 = current.rows[0].photo_1; let p2 = current.rows[0].photo_2; let p3 = current.rows[0].photo_3;
    if (files.photo_1?.[0]) { const r = await uploadToCloudinary(files.photo_1[0].buffer, "trouvemoi/agences", `agence_${Date.now()}_1`); p1 = r.secure_url; }
    
    await pool.query(`UPDATE agencies SET name = $1, address = $2, photo_1 = $3, photo_2 = $4, photo_3 = $5, latitude = $6, longitude = $7, phone = $8, whatsapp_number = $9, status = 'pending_validation' WHERE id = $10 AND parent_pro_id = $11`, 
    [name, address, p1, p2, p3, safeCoord(latitude, 90), safeCoord(longitude, 180), cleanBeninPhone(agency_phone) || null, cleanBeninPhone(agency_whatsapp) || null, id, proConnected.pro.id]);
    res.redirect(303, `/mon-espace-pro/agences/${id}`);
  });

  // --- 6. STATS API & SUPPRESSION ---
  router.post("/api/track-agency/:id/:type", async (req, res) => {
    const id = Number(req.params.id); const type = req.params.type;
    let col = type === "phone" ? "phone_clicks" : (type === "wa" ? "wa_clicks" : null);
    if (!col) return res.json({ ok: false });
    await pool.query(`INSERT INTO agency_stats (agency_id, date, ${col}) VALUES ($1, CURRENT_DATE, 1) ON CONFLICT (agency_id, date) DO UPDATE SET ${col} = agency_stats.${col} + 1`, [id]);
    res.json({ ok: true });
  });

  router.post("/mon-espace-pro/agences/:id/supprimer", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    await pool.query(`DELETE FROM agencies WHERE id = $1 AND parent_pro_id = $2`, [Number(req.params.id), proConnected.pro.id]);
    res.redirect(303, "/mon-espace-pro/agences");
  });

  return router;
};
