const express = require('express');

module.exports = function(pool, page, getConnectedPro, upload, uploadToCloudinary, takeRateLimit, BYPASS_PAYMENT, KKIAPAY_PUBLIC_KEY, KKIAPAY_SANDBOX, APP_URL, escapeHtml, cleanBeninPhone, readCookie, PAYMENT_AMOUNT) {
const router = express.Router();

  router.get("/devenir-professionnel", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    const citiesResult = await pool.query("SELECT id, name FROM cities ORDER BY display_order ASC");
    const professionsResult = await pool.query("SELECT id, name, category FROM professions ORDER BY display_order ASC");
    const cityOptions = citiesResult.rows.map((c) => `<option value="${escapeHtml(c.name)}">${escapeHtml(c.name)}</option>`).join("");
    
    const professionsByCategory = {};
    for (const p of professionsResult.rows) { const cat = p.category || "Autres"; if (!professionsByCategory[cat]) professionsByCategory[cat] = []; professionsByCategory[cat].push(p.name); }
    const professionOptions = Object.entries(professionsByCategory).map(([category, names]) => `<optgroup label="${escapeHtml(category)}" class="prof-group">${names.map(name => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join("")}</optgroup>`).join("");

    const jours = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"];
    let horairesHtml = "";
    jours.forEach(j => {
      horairesHtml += `<div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;"><div style="width:100px; font-weight:600; text-transform:capitalize; font-size:14px;">${j}</div><input type="time" name="h_${j}_o" style="margin:0; width:110px; padding:8px;"><span>à</span><input type="time" name="h_${j}_f" style="margin:0; width:110px; padding:8px;"><label style="margin:0; display:flex; align-items:center; gap:4px; font-size:12px;"><input type="checkbox" name="h_${j}_ferme" value="yes" style="margin:0;"> Fermé</label></div>`;
    });

    const allProfNames = professionsResult.rows.map(p => p.name);
    const refCookie = readCookie(req, "tm_ref") || "";

    const content = `
      <section class="card" style="max-width: 800px; margin: 0 auto;">
        <h1 style="text-align: center; margin-bottom: 24px;">Devenir professionnel</h1>
        <div class="alert alert-warning"><h3 style="color: #92400e; margin-bottom: 8px;">💳 Frais d'inscription : ${PAYMENT_AMOUNT} FCFA</h3><p style="margin: 0; font-size: 14px;">Des frais d'inscription sont requis pour l'étude de votre dossier.</p></div>        
        <form id="form-inscription" action="/candidatures" method="POST" enctype="multipart/form-data" style="background: #f8fafc; padding: 24px; border-radius: 16px;">
          <input type="hidden" name="recaptcha_token" id="recaptcha_token" value="">
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;"><div><label>Nom complet *</label><input name="full_name" required maxlength="150"></div><div><label>Societe</label><input name="company_name" maxlength="200"></div></div>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;"><div><label>Telephone *</label><input name="phone" type="tel" required maxlength="30" pattern="01[0-9]{8}"></div><div><label>NPI *</label><input name="npi" required maxlength="15"></div></div>
          
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">
            <div><label>Ville *</label><select id="city" name="city" required><option value="">Choisir</option>${cityOptions}</select></div>
            <div><label>Profession *</label><select id="profession" name="profession" required><option value="">Choisir</option>${professionOptions}</select></div>
          </div>
          
          <label>Description *</label><textarea name="service_description" rows="4" required maxlength="3000"></textarea>
          
          <hr style="margin:24px 0; border:none; border-top:1px solid #e2e8f0">
          <h3>Photos obligatoires (KYC)</h3>
          <div><label>1. Photo d'identité (visage) *</label><input name="photo_profil" type="file" accept="image/*" required></div>
          <div><label>2. Pièce d'identité (recto) *</label><input name="photo_identite" type="file" accept="image/*" required></div>
          <div><label>3. Photo de vérification KYC *</label><input name="photo_kyc" type="file" accept="image/*" required></div>
          
          <div class="checkbox-block" style="margin-top:24px;"><label><input type="checkbox" name="gdpr_consent" value="yes" required> <span>J'accepte la <a href="/confidentialite" target="_blank">Politique de confidentialite</a>.</span></label></div>
          <div style="text-align: center; margin-top: 30px;"><button type="submit" style="padding: 16px 40px; font-size: 16px; width: 100%;">Envoyer ma candidature</button></div>
        </form>
      </section>
      <script>
        document.getElementById('form-inscription').addEventListener('submit', async function(e) {
          if (!document.getElementById('recaptcha_token').value) {
            e.preventDefault();
            const token = await getRecaptchaToken();
            document.getElementById('recaptcha_token').value = token;
            this.submit();
          }
        });
      </script>
    `;
    res.send(page("Devenir professionnel", content, proConnected));
  });

  router.post("/candidatures", upload.fields([{ name: "photo_profil", maxCount: 1 }, { name: "photo_identite", maxCount: 1 }, { name: "photo_kyc", maxCount: 1 }]), async (req, res) => {
    const files = req.files || {};
    const { full_name, phone, npi, city, profession, service_description } = req.body;
    try {
      const p1 = await uploadToCloudinary(files.photo_profil[0].buffer, "trouvemoi/profils", `profil_${Date.now()}`);
      const p2 = await uploadToCloudinary(files.photo_identite[0].buffer, "trouvemoi/identites", `id_${Date.now()}`);
      const p3 = await uploadToCloudinary(files.photo_kyc[0].buffer, "trouvemoi/kyc", `kyc_${Date.now()}`);
      const trackingCode = `SUIVI-${Math.floor(Math.random() * 90000000) + 10000000}`;
      
      await pool.query(
        `INSERT INTO professional_applications (full_name, phone, npi, city, profession, service_description, photo_profil_url, photo_identite_url, photo_kyc_url, tracking_code, status, payment_status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
        [full_name, phone, npi, city, profession, service_description, p1.secure_url, p2.secure_url, p3.secure_url, trackingCode, BYPASS_PAYMENT ? 'pending' : 'payment_pending', BYPASS_PAYMENT ? 'paid' : 'unpaid']
      );
      if (BYPASS_PAYMENT) return res.send(page("Succès", `<h1>Inscription validée (Mode Test)</h1><p>Code de suivi : ${trackingCode}</p><a href="/">Accueil</a>`, null));
      res.redirect(303, `/paiement/${trackingCode}`);
    } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur lors de l'enregistrement.</h2>", null)); }
  });

  return router;
};
