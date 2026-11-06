const express = require('express');

module.exports = function(pool, page, getConnectedPro, upload, uploadToCloudinary, verifyRecaptcha, takeRateLimit, BYPASS_PAYMENT, KKIAPAY_PUBLIC_KEY, KKIAPAY_SANDBOX, APP_URL) {
  const router = express.Router();

  router.get("/devenir-professionnel", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    res.send(page("Devenir professionnel", `
      <section class="card" style="max-width: 800px; margin: 0 auto;">
        <h1 style="text-align: center;">Devenir professionnel</h1>
        <form action="/candidatures" method="POST" enctype="multipart/form-data">
          <label>Nom complet *</label><input name="full_name" required>
          <label>Téléphone *</label><input name="phone" type="tel" required>
          <label>NPI *</label><input name="npi" required>
          <label>Ville *</label><input name="city" required>
          <label>Profession *</label><input name="profession" required>
          <label>Description *</label><textarea name="service_description" required></textarea>
          <label>Photo Profil *</label><input type="file" name="photo_profil" required>
          <label>Photo Identité *</label><input type="file" name="photo_identite" required>
          <label>Photo KYC *</label><input type="file" name="photo_kyc" required>
          <button type="submit" style="width:100%; margin-top:20px;">Envoyer</button>
        </form>
      </section>`, proConnected));
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

  // --- SUIVI DE DOSSIER & PAIEMENT ---
  router.get("/suivi-dossier", (req, res) => res.send(page("Suivi", "<h1>Entrez votre code</h1><form method='POST' action='/suivi-dossier'><input name='tracking_code'><button>Voir</button></form>", null)));
  
  router.post("/suivi-dossier", async (req, res) => {
    const result = await pool.query(`SELECT * FROM professional_applications WHERE tracking_code = $1`, [req.body.tracking_code]);
    if (!result.rows.length) return res.send(page("Erreur", "<h1>Introuvable</h1>", null));
    res.send(page("Dossier", `<h1>Statut : ${result.rows[0].status}</h1>`, null));
  });

  router.get("/paiement/:tracking", async (req, res) => {
    const result = await pool.query(`SELECT tracking_code, status FROM professional_applications WHERE tracking_code = $1`, [req.params.tracking]);
    if (!result.rows.length) return res.redirect(303, "/");
    res.send(page("Paiement", `
      <section class="card" style="text-align:center;"><h1>💳 Payer 1500 FCFA</h1>
      <button onclick="openKkiapayWidget({ amount: 1500, api_key: '${KKIAPAY_PUBLIC_KEY}', sandbox: ${KKIAPAY_SANDBOX}, callback: '${APP_URL}/paiement/verifier?tracking=${result.rows[0].tracking_code}' })">Payer</button></section>
      <script src="https://cdn.kkiapay.me/k.js"></script>`, null));
  });

  return router;
};
