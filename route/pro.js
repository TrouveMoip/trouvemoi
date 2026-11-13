const express = require('express');
const crypto = require('crypto');

module.exports = function(pool, page, getConnectedPro, escapeHtml, upload, uploadToCloudinary, clearRateLimit, takeRateLimit, setProCookie, clearProCookie, generateUniqueProCode, logAdminAction, OFFER_DURATION_DAYS, deleteFromCloudinary, cleanBeninPhone, APP_URL, sendSMS, verifyOTP, safeCoord) {
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
    if (!proConnected) return res.send(page("Espace pro", `
      <section class="card" style="max-width: 500px; margin: 40px auto;">
        <h1 style="text-align: center;">Espace pro</h1>
        <form action="/mon-espace-pro/login" method="POST">
          <label>Code pro</label>
          <input name="pro_code" required maxlength="10" placeholder="TM12345678" style="text-transform:uppercase; text-align:center; font-size:20px;">
          <button type="submit" style="width: 100%;">Se connecter</button>
        </form>
        
        <div style="text-align:center; margin-top:20px;">
          <a href="/mon-espace-pro/reinitialiser" style="color:#ef4444; font-size:14px; text-decoration:none;">🔐 Code perdu ?</a>
        </div>
      </section>
    `, null));
    // ✅ Sécurité : Si le pro n'a pas de code de parrainage, on lui en crée un
if (!proConnected.pro.referral_code) {
  const newRefCode = crypto.randomBytes(3).toString('hex');
  await pool.query(`UPDATE professional_applications SET referral_code = $1 WHERE id = $2`, [newRefCode, proConnected.pro.id]);
  proConnected.pro.referral_code = newRefCode; // On met à jour la variable pour l'affichage immédiat
}

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
            <a class="button secondary" href="/mon-espace-pro/mes-avis">⭐ Mes Avis</a>
            <a class="button secondary" href="/mon-espace-pro/mes-messages">📩 Mes Messages</a>
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
          ${withdrawals.length > 0 ? `
          <div style="margin-top: 16px; background: white; padding: 12px; border-radius: 8px; border:1px solid #e5e7eb;">
            <p style="font-size: 12px; font-weight: bold; margin-bottom: 8px; color:#374151;">Historique des retraits</p>
            ${withdrawals.map(w => `
              <div style="display:flex; justify-content:space-between; align-items:center; font-size: 13px; padding: 6px 0; border-bottom: 1px solid #f3f4f6;">
                <span>${new Date(w.created_at).toLocaleDateString("fr-FR")} - <strong>${w.amount} FCFA</strong></span>
                <span class="badge" style="background:${w.status === 'pending' ? '#fef3c7' : w.status === 'rejected' ? '#fee2e2' : '#d1fae5'}; color:${w.status === 'pending' ? '#92400e' : w.status === 'rejected' ? '#991b1b' : '#065f46'}; font-size:10px;">
                  ${w.status === 'pending' ? 'En attente' : w.status === 'rejected' ? 'Refusé (recrédité)' : 'Payé'}
                </span>
              </div>
            `).join("")}
          </div>` : ""}
        </section>
      </div>
      
      <section class="card" style="margin-top:20px;">
        <h2 style="font-size:20px; margin-bottom:16px;">Mes offres (${offers.length})</h2>
        ${offers.length > 0 ? offers.map(offer => `
          <article class="card" style="box-shadow:none; border:1px solid #e5e7eb; margin-bottom:16px;">
            <h2 style="font-size:18px;">${escapeHtml(offer.job_title)}</h2>
            <p><span class="badge badge-${offer.status}">${escapeHtml(offer.status)}</span></p>
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
          <input name="phone" id="phone-input" type="tel" required maxlength="30" pattern="01[0-9]{8}" value="${escapeHtml(proConnected.pro.phone)}">

          <div style="background:#eff6ff; padding:16px; border-radius:12px; margin-bottom:16px; border:1px solid #bfdbfe;">
            <label style="margin-top:0; color:#1e3a8a; font-weight:bold;">Vérification du numéro (Obligatoire pour changer)</label>
            <div style="display:flex; gap:10px; margin-bottom:10px;">
              <button type="button" onclick="demanderCode()" style="margin-bottom:0; padding: 12px 20px; white-space: nowrap; background: #3b82f6; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight:bold; width:100%;">📩 Recevoir le code par SMS</button>
            </div>
            <div id="otp-block" style="display:none;">
              <input name="otp_code" id="otp-code" placeholder="Entrez le code SMS" required style="margin-bottom:0;">
            </div>
          </div>
          
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
            <div><label>Préférence de contact</label><select name="contact_preference"><option value="whatsapp" ${proConnected.pro.contact_preference === 'whatsapp' ? 'selected' : ''}>WhatsApp</option><option value="email" ${proConnected.pro.contact_preference === 'email' ? 'selected' : ''}>E-mail</option></select></div>
            <div><label>Numéro WhatsApp</label><input name="whatsapp_number" type="tel" maxlength="30" pattern="01[0-9]{8}" value="${escapeHtml(proConnected.pro.whatsapp_number || '')}"></div>
          </div>
          <label>E-mail</label>
          <input name="contact_email" type="email" maxlength="254" value="${escapeHtml(proConnected.pro.contact_email || '')}">
          
          <h3 style="margin-top:24px; margin-bottom:12px; border-top:1px solid #e5e7eb; padding-top:20px;">📍 Localisation (si vous avez un local)</h3>
          
          <label>Adresse exacte / Point de repère</label>
          <input name="adresse_exacte" maxlength="200" value="${escapeHtml(proConnected.pro.adresse_exacte || '')}" placeholder="Ex: Carrefour Ste Rita">
          
          <input type="hidden" name="latitude" id="latitude" value="${proConnected.pro.latitude || ''}">
          <input type="hidden" name="longitude" id="longitude" value="${proConnected.pro.longitude || ''}">
          
          <button type="button" onclick="getLocation()" style="background:#3b82f6; width:100%; border-radius:12px; margin-bottom:10px; color:white; border:none; padding:10px; cursor:pointer;">📍 Mettre à jour ma position GPS</button>
          <p id="gps-status" style="text-align:center; color:#2563eb; font-weight:bold; font-size:13px;"></p>
          
          <div style="text-align:center; margin-top:30px;"><button type="submit" class="success" style="width:100%; padding:16px;">💾 Enregistrer les modifications</button></div>
        </form>
        <p style="text-align:center; margin-top:20px;"><a href="/mon-espace-pro" style="color:#6b7280;">← Retour</a></p>
      </section>
      <script>
        async function demanderCode() {
          const phoneInput = document.getElementById('phone-input');
          const phone = phoneInput.value;
          if (!phone || !/^01[0-9]{8}$/.test(phone)) { alert("Entrez un numéro valide (ex: 01XXXXXXXX)"); return; }
          
          const btn = event.target;
          btn.innerText = "Envoi..."; btn.disabled = true;
          
          try {
            const res = await fetch('/api/send-otp', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({ phone: phone })
            });
            const data = await res.json();
            if (data.ok) {
              alert("✅ Code envoyé ! Vérifiez vos SMS.");
              document.getElementById('otp-block').style.display = 'block';
              btn.innerText = "Renvoyer";
            } else {
              alert(data.error || "Erreur d'envoi.");
              btn.innerText = "Recevoir";
            }
          } catch(e) {
            alert("Erreur réseau.");
            btn.innerText = "Recevoir";
          }
          btn.disabled = false;
        }

        function getLocation() {
          const status = document.getElementById('gps-status');
          status.innerText = "Récupération...";
          navigator.geolocation.getCurrentPosition(
            (position) => {
              document.getElementById('latitude').value = position.coords.latitude;
              document.getElementById('longitude').value = position.coords.longitude;
              status.innerText = "✅ Position GPS mise à jour !";
            },
            () => { status.innerText = "❌ Impossible de vous localiser."; }
          );
        }
      </script>
    `, proConnected));
  });

  router.post("/modifier-profil", async (req, res) => {
    const proConnected = await getConnectedPro(req); if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    const { company_name, phone, contact_email, contact_preference, whatsapp_number } = req.body;
    const cleanPhone = cleanBeninPhone(phone);
    const otpCode = String(req.body.otp_code || "").trim();

    if (cleanPhone !== proConnected.pro.phone) {
      const codeValide = await verifyOTP(cleanPhone, otpCode);
      if (!codeValide) {
        return res.status(400).send(page("Erreur", "<h2>Code SMS invalide ou expiré. Vous ne pouvez pas changer de numéro sans le vérifier.</h2><a href='/mon-espace-pro/modifier-profil'>Retour</a>", proConnected));
      }
    }
    if (!cleanPhone) return res.status(400).send(page("Erreur", "<h2>Téléphone invalide.</h2>", proConnected));
    const cleanWhatsapp = whatsapp_number ? cleanBeninPhone(whatsapp_number) : null;
    const email = String(contact_email || "").trim().slice(0, 254);
    const preference = ["whatsapp", "email"].includes(contact_preference) ? contact_preference : "whatsapp";
    
    await pool.query(`UPDATE professional_applications SET company_name = $1, phone = $2, contact_email = $3, contact_preference = $4, whatsapp_number = $5, adresse_exacte = $6, latitude = $7, longitude = $8, updated_at = NOW() WHERE id = $9`, 
    [company_name || null, cleanPhone, email || null, preference, cleanWhatsapp, req.body.adresse_exacte || null, safeCoord(req.body.latitude, 90), safeCoord(req.body.longitude, 180), proConnected.pro.id]);
    res.redirect(303, "/mon-espace-pro");
  });

  router.get("/mes-donnees", async (req, res) => {
    const proConnected = await getConnectedPro(req); if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    try {
      const offersResult = await pool.query(`SELECT * FROM job_offers WHERE pro_id = $1`, [proConnected.pro.id]);
      const gdprResult = await pool.query(`SELECT * FROM gdpr_requests WHERE pro_id = $1`, [proConnected.pro.id]);
      const reviewsResult = await pool.query(`SELECT * FROM reviews WHERE pro_id = $1`, [proConnected.pro.id]);
      const agenciesResult = await pool.query(`SELECT * FROM agencies WHERE parent_pro_id = $1`, [proConnected.pro.id]);
      const withdrawalsResult = await pool.query(`SELECT * FROM withdrawal_requests WHERE pro_id = $1`, [proConnected.pro.id]);
      const statsResult = await pool.query(`SELECT * FROM pro_stats WHERE pro_id = $1`, [proConnected.pro.id]);

      const exportData = { 
        utilisateur: proConnected.pro, 
        offres: offersResult.rows, 
        demandes_rgpd: gdprResult.rows, 
        avis: reviewsResult.rows, 
        agences: agenciesResult.rows,
        retraits: withdrawalsResult.rows,
        statistiques_quotidiennes: statsResult.rows
      };
      res.setHeader("Content-Type", "application/json"); 
      res.setHeader("Content-Disposition", `attachment; filename="trouvemoi-${proConnected.code}.json"`); 
      res.send(JSON.stringify(exportData, null, 2));
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

  try {
    const files = req.files || {};
    let url1 = proConnected.pro.photo_galerie_1;
    let url2 = proConnected.pro.photo_galerie_2;
    const desc1 = String(req.body.desc1 || "").trim().slice(0, 150);
    const desc2 = String(req.body.desc2 || "").trim().slice(0, 150);

    if (files.photo1?.[0]) {
      const r = await uploadToCloudinary(files.photo1[0].buffer, "trouvemoi/galeries", `galerie_${proConnected.pro.id}_1_${Date.now()}`);
      url1 = r.secure_url;
    }
    if (files.photo2?.[0]) {
      const r = await uploadToCloudinary(files.photo2[0].buffer, "trouvemoi/galeries", `galerie_${proConnected.pro.id}_2_${Date.now()}`);
      url2 = r.secure_url;
    }

    await pool.query(`UPDATE professional_applications SET photo_galerie_1 = $1, photo_galerie_1_desc = $2, photo_galerie_2 = $3, photo_galerie_2_desc = $4 WHERE id = $5`,
      [url1, desc1 || null, url2, desc2 || null, proConnected.pro.id]);
    
    res.redirect(303, "/mon-espace-pro");
  } catch (e) {
    console.error("Erreur upload galerie:", e);
    await clearRateLimit(galleryKey);
    res.redirect(303, "/mon-espace-pro/modifier-galerie");
  }
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

  // RÉINITIALISATION DU CODE PRO
  router.get("/reinitialiser", (req, res) => {
    res.send(page("Récupérer mon code", `
      <section class="card" style="max-width: 500px; margin: 40px auto;">
        <h1 style="text-align:center;">🔐 Récupérer mon code</h1>
        <p style="font-size:14px; color:#6b7280; text-align:center; margin-bottom:20px;">
          Entrez le numéro de téléphone utilisé lors de votre inscription.
        </p>
        
        <form action="/mon-espace-pro/reinitialiser" method="POST">
          <label>Votre numéro de téléphone *</label>
          <input name="phone" type="tel" required pattern="01[0-9]{8}" placeholder="01XXXXXXXX" style="text-align:center;">
          
          <button type="submit" class="warning" style="width:100%; margin-top:10px;">Recevoir un code par SMS</button>
        </form>
        
        <p style="text-align:center; margin-top:20px;"><a href="/mon-espace-pro" style="color:#6b7280;">← Retour</a></p>
      </section>
    `, null));
  });

  router.post("/reinitialiser", async (req, res) => {
    const phone = cleanBeninPhone(req.body.phone);
    if (!phone) return res.redirect(303, "/mon-espace-pro/reinitialiser");

    try {
      const result = await pool.query(`SELECT id, full_name FROM professional_applications WHERE phone = $1 AND status = 'approved'`, [phone]);
      if (!result.rows.length) {
        return res.status(404).send(page("Erreur", "<h2>Aucun compte trouvé avec ce numéro.</h2><a href='/mon-espace-pro/reinitialiser'>Réessayer</a>", null));
      }

      const currentMonth = new Date().getMonth();
      const currentYear = new Date().getFullYear();
      const limitKey = `reset_pro_limit:${phone}:${currentYear}-${currentMonth}`;
      
      const attempts = await pool.query(`SELECT count FROM rate_limits_v2 WHERE limit_key = $1`, [limitKey]);
      const count = attempts.rows.length ? Number(attempts.rows[0].count) : 0;

      if (count >= 5) {
        return res.status(429).send(page("Limite atteinte", "<section class='card' style='text-align:center; padding:40px;'><h1 style='color:#f59e0b;'>⚠️ Limite atteinte</h1><p>Vous avez atteint la limite de 5 demandes par mois. Veuillez contacter l'administrateur.</p><a href='/contact' class='button'>Contacter l'admin</a></section>", null));
      }

      const code = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

      await pool.query(
        `INSERT INTO otp_codes (phone, code, expires_at) VALUES ($1, $2, $3) 
         ON CONFLICT (phone) DO UPDATE SET code = $2, expires_at = $3`,
        [phone, code, expiresAt]
      );

      await sendSMS(phone, `Votre code de récupération TrouveMoi est : ${code}. Il expire dans 10 minutes.`);

      await pool.query(
        `INSERT INTO rate_limits_v2 (limit_key, count, window_start) VALUES ($1, 1, NOW()) 
         ON CONFLICT (limit_key) DO UPDATE SET count = rate_limits_v2.count + 1`,
        [limitKey]
      );

      res.send(page("Vérification", `
        <section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;">
          <h1>📩 SMS envoyé</h1>
          <p>Entrez le code à 6 chiffres reçu au <strong>${escapeHtml(phone)}</strong>.</p>
          
          <form action="/mon-espace-pro/verifier-code-pro" method="POST">
            <input type="hidden" name="phone" value="${escapeHtml(phone)}">
            <input name="otp_code" type="text" required maxlength="6" placeholder="123456" style="text-align:center; font-size:24px; letter-spacing:5px;">
            <button type="submit" class="success" style="width:100%;">Vérifier le code</button>
          </form>
        </section>
      `, null));

    } catch (error) {
      console.error("Erreur réinit pro :", error.message);
      res.redirect(303, "/mon-espace-pro/reinitialiser");
    }
  });

  router.post("/verifier-code-pro", async (req, res) => {
    const phone = cleanBeninPhone(req.body.phone);
    const otpCode = String(req.body.otp_code || "").trim();

    try {
      const isCodeValid = await verifyOTP(phone, otpCode);
      if (!isCodeValid) {
        return res.status(400).send(page("Erreur", "<h2>Code SMS invalide ou expiré.</h2><a href='/mon-espace-pro/reinitialiser'>Recommencer</a>", null));
      }

      const result = await pool.query(`SELECT id, full_name FROM professional_applications WHERE phone = $1`, [phone]);
      const pro = result.rows[0];
      const newCode = await generateUniqueProCode();
      
      await pool.query(`UPDATE professional_applications SET pro_code = $1 WHERE id = $2`, [newCode, pro.id]);
      await logAdminAction("pro_code_reset", "pro", pro.id, `Numéro : ${phone} | Nouveau code : ${newCode}`);

      res.send(page("Nouveau Code", `
        <section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;">
          <h1>✅ Nouveau code généré</h1>
          <p>Bonjour ${escapeHtml(pro.full_name)}, voici votre nouveau code de connexion :</p>
          <div style="background:#1e3a8a; color:white; padding:20px; border-radius:12px; margin:20px 0;">
            <div style="font-size:32px; font-weight:800; font-family:monospace; letter-spacing:4px;">${escapeHtml(newCode)}</div>
          </div>
          <a href="/mon-espace-pro" class="button success" style="margin-top:20px; width:100%;">Se connecter</a>
        </section>
      `, null));

    } catch (error) {
      res.redirect(303, "/mon-espace-pro/reinitialiser");
    }
  });
 
// MES MESSAGES (Boîte de réception du Pro)
router.get("/mes-messages", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");

  // On récupère les messages destinés à ce pro
  const result = await pool.query(`SELECT * FROM contact_messages WHERE pro_id = $1 ORDER BY created_at DESC`, [proConnected.pro.id]);
  
  const messagesHtml = result.rows.map(m => `
    <article class="card" style="margin-bottom:16px; border-left:4px solid #3b82f6;">
      <div style="display:flex; justify-content:space-between; margin-bottom:10px;">
        <strong style="color:#1e293b;">${escapeHtml(m.name)}</strong>
        <span style="font-size:12px; color:#64748b;">${new Date(m.created_at).toLocaleDateString("fr-FR")}</span>
      </div>
      <p style="font-size:13px; color:#64748b; margin-bottom:10px;">
        📧 ${escapeHtml(m.email)} | 📞 ${escapeHtml(m.phone || "Non renseigné")}
      </p>
      <div style="background:#f8fafc; padding:15px; border-radius:8px; font-size:14px; color:#374151;">
        ${escapeHtml(m.message)}
      </div>
      <div style="margin-top:15px; display:flex; gap:10px;">
        ${m.email ? `<a href="mailto:${escapeHtml(m.email)}?subject=Réponse à votre message TrouveMoi" class="button" style="font-size:12px; padding:8px 16px;">✉️ Répondre par Email</a>` : ''}
        ${m.phone ? `<a href="https://wa.me/229${escapeHtml(m.phone.replace(/\D/g, '').replace(/^(00229|229)/, ''))}" target="_blank" class="button whatsapp" style="font-size:12px; padding:8px 16px;">💬 Répondre sur WhatsApp</a>` : ''}
      </div>
    </article>
  `).join("");

  res.send(page("Mes Messages", `
    <div style="max-width: 800px; margin: 0 auto;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
        <h1>📩 Mes Messages</h1>
        <a href="/mon-espace-pro" class="button secondary" style="margin:0;">← Retour</a>
      </div>
      ${messagesHtml || "<div class='card' style='text-align:center; padding:40px;'><p style='color:#64748b;'>Vous n'avez pas encore reçu de message.</p></div>"}
    </div>
  `, proConnected));
});

  router.get("/mes-avis", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");

    const result = await pool.query(`SELECT * FROM reviews WHERE pro_id = $1 AND status = 'approved' ORDER BY created_at DESC`, [proConnected.pro.id]);
    
    const avisHtml = result.rows.map(r => `
      <article class="card" style="margin-bottom:16px;">
        <div style="display:flex; justify-content:space-between;">
          <strong>${escapeHtml(r.author_name)}</strong>
          <span style="color:#f59e0b; font-size:18px;">${"★".repeat(r.rating)}${"☆".repeat(5 - r.rating)}</span>
        </div>
        <p style="margin-top:10px; font-style:italic; color:#4b5563;">"${escapeHtml(r.comment || 'Pas de commentaire')}"</p>
        
        ${r.pro_reply ? `
          <div style="background:#f0fdf4; border-left:4px solid #10b981; padding:12px; margin-top:12px; border-radius:4px;">
            <strong style="color:#065f46; font-size:13px;">Votre réponse :</strong>
            <p style="font-size:14px; margin:4px 0 0 0;">${escapeHtml(r.pro_reply)}</p>
          </div>
        ` : `
          <form action="/mon-espace-pro/repondre-avis/${r.id}" method="POST" style="margin-top:12px;">
            <input name="reply" required placeholder="Écrivez votre réponse ici..." style="padding:12px; font-size:14px; margin-bottom:8px; background:#f8fafc;">
            <button type="submit" class="success" style="padding:8px 16px; font-size:13px; border-radius:8px;">Répondre</button>
          </form>
        `}
      </article>
    `).join("");

    res.send(page("Mes Avis", `
      <div style="max-width: 700px; margin: 0 auto;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
          <h1>⭐ Mes Avis</h1>
          <a href="/mon-espace-pro" class="button secondary" style="margin:0;">← Retour</a>
        </div>
        ${avisHtml || "<p style='text-align:center; color:#6b7280;'>Vous n'avez pas encore d'avis approuvé.</p>"}
      </div>
    `, proConnected));
  });

  router.post("/repondre-avis/:id", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    
    const id = Number(req.params.id);
    const reply = String(req.body.reply || "").trim().slice(0, 1000);

    if (reply) {
      await pool.query(`UPDATE reviews SET pro_reply = $1, pro_reply_date = NOW() WHERE id = $2 AND pro_id = $3`, [reply, id, proConnected.pro.id]);
    }
    res.redirect(303, "/mon-espace-pro/mes-avis");
  });

  // ==========================================
  // DEMANDE DE RETRAIT (PARRAINAGE)
  // ==========================================
  router.post("/demander-retrait", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");

    const amount = Number(req.body.amount);
    const phoneNumber = cleanBeninPhone(req.body.phone_number);

    if (!phoneNumber || isNaN(amount) || amount < 1000) {
      return res.status(400).send(page("Erreur", "<h2>Montant ou numéro invalide (minimum 1000 FCFA).</h2><a href='/mon-espace-pro'>Retour</a>", proConnected));
    }

    if (amount > Number(proConnected.pro.referral_balance)) {
      return res.status(400).send(page("Erreur", "<h2>Solde insuffisant. Vous ne pouvez pas retirer plus que ce que vous avez.</h2><a href='/mon-espace-pro'>Retour</a>", proConnected));
    }

    try {
      await pool.query(`UPDATE professional_applications SET referral_balance = referral_balance - $1 WHERE id = $2`, [amount, proConnected.pro.id]);
      await pool.query(`INSERT INTO withdrawal_requests (pro_id, amount, phone_number, status) VALUES ($1, $2, $3, 'pending')`, [proConnected.pro.id, amount, phoneNumber]);
      
      res.redirect(303, "/mon-espace-pro");
    } catch (e) {
      console.error("Erreur retrait:", e);
      res.status(500).send(page("Erreur", "<h2>Erreur lors de la demande de retrait.</h2><a href='/mon-espace-pro'>Retour</a>", proConnected));
    }
  });

  return router;
};
