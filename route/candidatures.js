const express = require('express');

module.exports = function(pool, page, getConnectedPro, upload, uploadToCloudinary, takeRateLimit, BYPASS_PAYMENT, KKIAPAY_PUBLIC_KEY, KKIAPAY_SANDBOX, APP_URL, escapeHtml, cleanBeninPhone, readCookie, PAYMENT_AMOUNT, METIERS_LOCAL_FIXE, METIERS_SENSIBLES, sendSMS, verifyOTP, sendPushNotification) {
  const router = express.Router();

  router.get("/devenir-professionnel", async (req, res) => { 
  const proConnected = await getConnectedPro(req);
  const citiesResult = await pool.query("SELECT id, name FROM cities ORDER BY display_order ASC");
  const professionsResult = await pool.query("SELECT id, name, category FROM professions ORDER BY display_order ASC");

  const cityOptions = citiesResult.rows.map((c) => `<option value="${escapeHtml(c.name)}">${escapeHtml(c.name)}</option>`).join("");
  const professionsByCategory = {};
  for (const p of professionsResult.rows) { const cat = p.category || "Autres"; if (!professionsByCategory[cat]) professionsByCategory[cat] = []; professionsByCategory[cat].push(p.name); }
  const professionOptions = Object.entries(professionsByCategory).map(([category, names]) => `<optgroup label="${escapeHtml(category)}">${names.map(name => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join("")}</optgroup>`).join("");
  
  const jours = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"];
  let horairesHtml = "";
  jours.forEach(j => {
    horairesHtml += `<div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
      <div style="width:100px; font-weight:600; text-transform:capitalize; font-size:14px; color:#475569;">${j}</div>
      <input type="time" name="h_${j}_o" style="margin:0; width:110px; padding:8px; background:#f8fafc; border:1px solid #e2e8f0;">
      <span style="color:#94a3b8;">à</span>
      <input type="time" name="h_${j}_f" style="margin:0; width:110px; padding:8px; background:#f8fafc; border:1px solid #e2e8f0;">
      <label style="margin:0; display:flex; align-items:center; gap:4px; font-size:12px; color:#64748b;"><input type="checkbox" name="h_${j}_ferme" value="yes" style="margin:0;"> Fermé</label>
    </div>`;
  });

  const refFromUrl = String(req.query.ref || "").trim().toLowerCase();
  const refCookie = refFromUrl || readCookie(req, "tm_ref") || "";
  
  const content = `
    <style>
      .form-page { display: none; }
      .form-page.active { display: block; animation: fadeIn 0.4s; }
      @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
      
      .step-indicator { display: flex; justify-content: space-between; margin-bottom: 30px; position: relative; z-index: 1; }
      .step-item { flex: 1; text-align: center; position: relative; }
      .step-circle { width: 40px; height: 40px; border-radius: 50%; background: #e2e8f0; color: #64748b; display: inline-flex; align-items: center; justify-content: center; font-weight: bold; font-size: 16px; margin-bottom: 8px; transition: all 0.3s; border: 3px solid white; box-shadow: 0 0 0 1px #e2e8f0; }
      .step-item.active .step-circle { background: #3b82f6; color: white; box-shadow: 0 0 0 1px #3b82f6; }
      .step-item.completed .step-circle { background: #10b981; color: white; box-shadow: 0 0 0 1px #10b981; }
      .step-label { font-size: 12px; color: #64748b; font-weight: 600; }
      .step-item.active .step-label { color: #3b82f6; }
      
      /* Style pour les champs */
      .fancy-label { font-weight: 600; color: #334155; margin-bottom: 6px; display: block; font-size: 14px; }
      .fancy-input { width: 100%; padding: 14px 16px; border-radius: 12px; border: 1px solid #cbd5e1; background: #f8fafc; margin-bottom: 18px; transition: all 0.2s; }
      .fancy-input:focus { background: white; border-color: #3b82f6; box-shadow: 0 0 0 4px rgba(59,130,246,0.1); outline: none; }
    </style>

    <section style="max-width: 700px; margin: 0 auto;">
      <h1 style="text-align: center; margin-bottom: 24px; color: #1e3a8a;">Devenir professionnel</h1>
      
      <!-- Menu des étapes visuel -->
      <div class="step-indicator">
        <div class="step-item active" id="indicator-1">
          <div class="step-circle">1</div>
          <div class="step-label">Identité</div>
        </div>
        <div class="step-item" id="indicator-2">
          <div class="step-circle">2</div>
          <div class="step-label">Métier</div>
        </div>
        <div class="step-item" id="indicator-3">
          <div class="step-circle">3</div>
          <div class="step-label">Localisation</div>
        </div>
        <div class="step-item" id="indicator-4">
          <div class="step-circle">4</div>
          <div class="step-label">KYC</div>
        </div>
      </div>

      <form id="form-inscription" action="/candidatures" method="POST" enctype="multipart/form-data">
        
        <!-- ÉTAPE 1 -->
        <div id="step-1" class="form-page active" style="background:white; padding:28px; border-radius:20px; box-shadow:0 10px 25px rgba(0,0,0,0.05); border:1px solid #f1f5f9;">
          <h2 style="color:#1e40af; margin-bottom:20px; font-size:20px;">👤 Qui êtes-vous ?</h2>
          
          <label class="fancy-label">Nom et prénoms *</label>
          <input name="full_name" id="input_full_name" required maxlength="150" placeholder="Ex: Jean Dupont" class="fancy-input">
          
          <label class="fancy-label">Société (facultatif)</label>
          <input name="company_name" id="input_company_name" maxlength="200" placeholder="Ex: Momo BTP" class="fancy-input">
          
          <label class="fancy-label">NPI (Numéro Personnel d'Identification) *</label>
          <input name="npi" id="input_npi" required maxlength="15" placeholder="Ex: 1234567890" class="fancy-input">
          
          <label class="fancy-label">N° Téléphone *</label>
          <input name="phone" id="input_phone" type="tel" required maxlength="30" placeholder="01XXXXXXXX" pattern="01[0-9]{8}" class="fancy-input">
          
          <div style="background:#eff6ff; padding:20px; border-radius:16px; margin-top:10px; border:1px dashed #93c5fd;">
            <label style="margin-top:0; color:#1e3a8a; font-weight:bold; display:flex; align-items:center; gap:8px;">
              <span style="font-size:20px;">📱</span> Vérification du numéro
            </label>
            <p style="font-size:12px; color:#3b82f6; margin-bottom:10px;">Nous vous enverrons un code par SMS pour confirmer.</p>
            <div style="display:flex; gap:10px;">
              <input name="phone_verif" id="phone_verif_input" type="tel" placeholder="Numéro à vérifier" style="margin-bottom:0; background:#fff;" class="fancy-input" readonly>
              <button type="button" onclick="demanderCodePro()" style="margin-bottom:0; padding: 12px 20px; white-space: nowrap; background: #3b82f6; color: white; border: none; border-radius: 12px; cursor: pointer; font-weight:bold;">Recevoir</button>
            </div>
            <div id="otp-block" style="display:none; margin-top:12px;">
              <input name="otp_code" id="otp_code_input" placeholder="Entrez le code à 6 chiffres" required style="margin-bottom:0; background:#fff; text-align:center; letter-spacing:4px; font-size:18px;" class="fancy-input">
            </div>
          </div>

          <button type="button" onclick="nextStep(1)" style="width:100%; margin-top:24px; padding:16px; font-size:16px; font-weight:bold; border-radius:12px;">Suivant →</button>
        </div>

        <!-- ÉTAPE 2 -->
        <div id="step-2" class="form-page" style="background:white; padding:28px; border-radius:20px; box-shadow:0 10px 25px rgba(0,0,0,0.05); border:1px solid #f1f5f9;">
          <h2 style="color:#1e40af; margin-bottom:20px; font-size:20px;">🛠️ Votre Métier</h2>
          
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
  <div>
    <label class="fancy-label">Ville *</label>
    <select id="city" name="city" required class="fancy-input"><option value="">Choisir</option>${cityOptions}</select>
  </div>
  <div>
    <label class="fancy-label">Quartier *</label>
    <select id="neighborhood" name="neighborhood" required class="fancy-input"><option value="">Choisir</option></select>
  </div>
</div>
          <div id="neighborhood-other-block" class="hidden" style="margin-top:-10px; margin-bottom:18px;"><input name="neighborhood_other" maxlength="150" placeholder="Précisez votre quartier" class="fancy-input"></div>

          <label class="fancy-label">Profession *</label>
          <select id="profession" name="profession" required class="fancy-input"><option value="">Choisir</option>${professionOptions}</select>
          
          <label class="fancy-label">Description de vos services *</label>
          <textarea name="service_description" rows="4" required maxlength="3000" placeholder="Décrivez ce que vous faites, vos spécialités..." class="fancy-input"></textarea>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
              <div><label class="fancy-label">Expérience</label><select name="experience" class="fancy-input"><option value="">Sélectionnez</option><option value="Débutant">Débutant</option><option value="Moins de 2 ans">Moins de 2 ans</option><option value="2 à 5 ans">2 à 5 ans</option><option value="Plus de 5 ans">Plus de 5 ans</option></select></div>
              <div><label class="fancy-label">Disponibilité</label><select name="availability" class="fancy-input"><option value="">Sélectionnez</option><option value="Disponible immédiatement">Disponible immédiatement</option><option value="Sur rendez-vous">Sur rendez-vous</option><option value="À temps partiel">À temps partiel</option></select></div>
          </div>
          <label class="fancy-label">Zone d'intervention</label>
          <input name="service_area" maxlength="300" placeholder="Ex: Cotonou et environs" class="fancy-input">

          <div style="display:flex; gap:12px; margin-top:10px;">
            <button type="button" onclick="prevStep(2)" class="secondary" style="width:40%; padding:16px; border-radius:12px; font-weight:bold;">← Retour</button>
            <button type="button" onclick="nextStep(2)" style="width:60%; padding:16px; font-size:16px; font-weight:bold; border-radius:12px;">Suivant →</button>
          </div>
        </div>

        <!-- ÉTAPE 3 -->
        <div id="step-3" class="form-page" style="background:white; padding:28px; border-radius:20px; box-shadow:0 10px 25px rgba(0,0,0,0.05); border:1px solid #f1f5f9;">
          <h2 style="color:#1e40af; margin-bottom:20px; font-size:20px;">📍 Localisation & Horaires</h2>
          
          <div style="background:#f8fafc; padding:20px; border-radius:16px; border:1px solid #e2e8f0; margin-bottom:20px;">
            <label class="fancy-label" style="margin-top:0; margin-bottom:12px;">Comment travaillez-vous ?</label>
            <label style="display:flex; align-items:center; gap:10px; margin-bottom:12px; cursor:pointer;"><input type="radio" name="type_lieu" value="fixe" onclick="toggleLocalisation(true)" style="width:20px; height:20px;"> <span><strong>🏠 J'ai un local fixe (Boutique, salon, garage...)</strong></span></label>
            <label style="display:flex; align-items:center; gap:10px; cursor:pointer;"><input type="radio" name="type_lieu" value="ambulant" checked onclick="toggleLocalisation(false)" style="width:20px; height:20px;"> <span><strong>🚗 Je me déplace chez le client (Ambulant)</strong></span></label>
          </div>

          <div id="localisation-block" class="hidden">
            <label class="fancy-label">Adresse exacte / Point de repère</label>
            <input name="adresse_exacte" maxlength="200" placeholder="Ex: Carrefour Ste Rita, à côté de la station Total" class="fancy-input">
            
            <div style="background:#f8fafc; padding:20px; border-radius:16px; margin-bottom:20px; border:1px solid #e2e8f0;">
              <label class="fancy-label" style="margin-top:0;">🕒 Horaires d'ouverture</label>
              ${horairesHtml}
            </div>

            <input type="hidden" name="latitude" id="latitude">
            <input type="hidden" name="longitude" id="longitude">
            <button type="button" onclick="getLocation()" style="background:#e0e7ff; color:#1e3a8a; width:100%; border-radius:12px; margin-bottom:10px; padding:14px; font-weight:bold; border:1px solid #c7d2fe;">📍 Utiliser ma position actuelle</button>
            <p id="gps-status" style="text-align:center; color:#2563eb; font-weight:bold; font-size:14px;"></p>
          </div>

          <div style="display:flex; gap:12px; margin-top:10px;">
            <button type="button" onclick="prevStep(3)" class="secondary" style="width:40%; padding:16px; border-radius:12px; font-weight:bold;">← Retour</button>
            <button type="button" onclick="nextStep(3)" style="width:60%; padding:16px; font-size:16px; font-weight:bold; border-radius:12px;">Suivant →</button>
          </div>
        </div>

        <!-- ÉTAPE 4 -->
        <div id="step-4" class="form-page" style="background:white; padding:28px; border-radius:20px; box-shadow:0 10px 25px rgba(0,0,0,0.05); border:1px solid #f1f5f9;">
          <h2 style="color:#1e40af; margin-bottom:20px; font-size:20px;">🛡️ Vérification (KYC)</h2>
          
          <div style="display: flex; align-items: center; gap: 16px; background: #fffbeb; padding: 16px; border-radius: 16px; margin-bottom: 24px; border: 1px solid #fde68a;">
            <img src="https://res.cloudinary.com/gxm35ndf/image/upload/v1792403314/kyc.jpg" style="width: 80px; height: 80px; object-fit: cover; border-radius: 12px; border:2px solid white; box-shadow:0 2px 5px rgba(0,0,0,0.1);">
            <p style="margin: 0; font-size: 13px; color: #92400e; line-height:1.4;"><strong>Exemple :</strong> Vous devez être de face, en tenant votre pièce d'identité à côté de votre visage, sans lunettes ni chapeau.</p>
          </div>

          <div style="display: grid; grid-template-columns: 1fr; gap: 16px;">
            <div>
              <label class="fancy-label">1. Photo de votre visage *</label>
              <input name="photo_profil" type="file" accept="image/*" required class="fancy-input" style="padding:10px; background:#fff;">
            </div>
            <div>
              <label class="fancy-label">2. Photo de la pièce d'identité (Recto) *</label>
              <input name="photo_identite" type="file" accept="image/*" required class="fancy-input" style="padding:10px; background:#fff;">
            </div>
            <div>
              <label class="fancy-label">3. Photo KYC (Visage + Pièce ensemble) *</label>
              <input name="photo_kyc" type="file" accept="image/*" required class="fancy-input" style="padding:10px; background:#fff;">
            </div>
          </div>
          
          <div style="background:#f0fdf4; padding:20px; border-radius:16px; border:1px solid #bbf7d0; margin-top:10px;">
            <label class="fancy-label" style="color:#065f46; margin-top:0;">🎁 Code de parrainage (Optionnel)</label>
            <input name="referred_by" maxlength="10" value="${escapeHtml(refCookie)}" placeholder="Ex: p543ht6" style="text-transform:lowercase; margin-bottom:0; border-color:#86efac;" class="fancy-input">
          </div>

          <div style="margin-top:20px; display:flex; align-items:flex-start; gap:10px;">
            <input type="checkbox" name="gdpr_consent" value="yes" required style="width:20px; height:20px; margin-top:2px;">
            <span style="font-size:14px; color:#475569;">J'accepte la <a href="/confidentialite" target="_blank" style="color:#2563eb; font-weight:bold;">Politique de confidentialité</a> et je certifie sur l'honneur l'exactitude de ces informations.</span>
          </div>

          <div style="display:flex; gap:12px; margin-top:24px;">
            <button type="button" onclick="prevStep(4)" class="secondary" style="width:40%; padding:16px; border-radius:12px; font-weight:bold;">← Retour</button>
            <button type="submit" id="submit-btn" style="width:60%; padding:16px; font-size:16px; font-weight:bold; border-radius:12px; background:#10b981;">✅ Envoyer</button>
          </div>
        </div>
      </form>
    </section>

    <script>
      function showStep(step) {
        // Cacher toutes les pages
        document.querySelectorAll('.form-page').forEach(el => el.classList.remove('active'));
        // Afficher la page actuelle
        document.getElementById('step-' + step).classList.add('active');
        
        // Mettre à jour les indicateurs du haut
        for (let i = 1; i <= 4; i++) {
          const indicator = document.getElementById('indicator-' + i);
          indicator.classList.remove('active', 'completed');
          if (i < step) indicator.classList.add('completed');
          if (i === step) indicator.classList.add('active');
        }
      }
      
      function nextStep(step) {
        if (step === 1) {
          const phone = document.getElementById('input_phone').value;
          const otp = document.getElementById('otp_code_input').value;
          if(!phone || !otp) { alert("Veuillez remplir le téléphone et le code SMS."); return; }
        }
        if (step === 2) {
          const city = document.getElementById('city').value;
          const prof = document.getElementById('profession').value;
          if(!city || !prof) { alert("Veuillez choisir votre ville et profession."); return; }
        }
        showStep(step + 1);
      }
      function prevStep(step) { showStep(step - 1); }
      
      function toggleLocalisation(isFixe) {
        document.getElementById('localisation-block').style.display = isFixe ? 'block' : 'none';
      }
      function getLocation() {
        const status = document.getElementById('gps-status');
        navigator.geolocation.getCurrentPosition(
          (position) => {
            document.getElementById('latitude').value = position.coords.latitude;
            document.getElementById('longitude').value = position.coords.longitude;
            status.innerText = "✅ Position GPS enregistrée !";
          },
          () => { status.innerText = "❌ Impossible de vous localiser."; }
        );
      }

      document.getElementById('input_phone').addEventListener('input', function() {
          document.getElementById('phone_verif_input').value = this.value;
      });

      async function demanderCodePro() {
        const phone = document.getElementById('input_phone').value;
        if (!phone || !/^01[0-9]{8}$/.test(phone)) { alert("Entrez un numéro valide (ex: 0194010345)"); return; }
        
        const btn = event.target;
        btn.innerText = "..."; btn.disabled = true;
        
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
      
      document.getElementById('city').addEventListener('change', async function() { 
          const city = this.value; const select = document.getElementById('neighborhood');
          select.innerHTML = '<option value="">Chargement...</option>'; 
          try { 
            const res = await fetch('/api/neighborhoods?city=' + encodeURIComponent(city)); 
            const data = await res.json(); 
            select.innerHTML = '<option value="">Choisir</option>'; 
            for (const n of data.neighborhoods) { const opt = document.createElement('option'); opt.value = n; opt.textContent = n; select.appendChild(opt); }
            const otherOpt = document.createElement('option'); otherOpt.value = '__AUTRE__'; otherOpt.textContent = 'Autre'; select.appendChild(otherOpt); 
          } catch (e) { select.innerHTML = '<option value="">Erreur</option>'; } 
      });
      document.getElementById('neighborhood').addEventListener('change', function() { 
          document.getElementById('neighborhood-other-block').style.display = (this.value === 'AUTRE') ? 'block' : 'none';
      });
    </script>
  `;
  res.send(page("Devenir professionnel", content, proConnected));
});
  router.post("/candidatures", upload.fields([{ name: "photo_profil", maxCount: 1 }, { name: "photo_identite", maxCount: 1 }, { name: "photo_kyc", maxCount: 1 }]), async (req, res) => {
    const files = req.files || {};
    
    const { 
      full_name, company_name, phone, npi, city, profession, service_description,
      contact_preference, contact_email, whatsapp_number, experience, service_area, availability,
      referred_by, type_lieu, adresse_exacte, latitude, longitude, phone_public
    } = req.body;

    const otpCode = String(req.body.otp_code || "").trim();
    const neighborhood = req.body.neighborhood === 'Autre' ? req.body.neighborhood_other : req.body.neighborhood;

    const horaires = {};
    ['lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi', 'dimanche'].forEach(j => {
      if (!req.body[`h_${j}_ferme`]) {
        const o = req.body[`h_${j}_o`];
        const f = req.body[`h_${j}_f`];
        if (o && f) horaires[j] = { o, f };
      }
    });
    const horaires_json = Object.keys(horaires).length > 0 ? JSON.stringify(horaires) : null;
    const lat = Number(latitude) || null;
    const lng = Number(longitude) || null;

    try {
      const p1 = await uploadToCloudinary(files.photo_profil[0].buffer, "trouvemoi/profils", `profil_${Date.now()}`);
      const p2 = await uploadToCloudinary(files.photo_identite[0].buffer, "trouvemoi/identites", `id_${Date.now()}`);
      const p3 = await uploadToCloudinary(files.photo_kyc[0].buffer, "trouvemoi/kyc", `kyc_${Date.now()}`);
      
      const trackingCode = `SUIVI-${Math.floor(Math.random() * 90000000) + 10000000}`;
      
      await pool.query(
        `INSERT INTO professional_applications (
          full_name, company_name, phone, phone_public, npi, city, neighborhood, profession, 
          service_description, experience, service_area, availability, contact_preference, contact_email, whatsapp_number, 
          referred_by, type_lieu, adresse_exacte, latitude, longitude, horaires_json,
          photo_profil_url, photo_identite_url, photo_kyc_url, tracking_code, status, payment_status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27)`,
        [
          full_name, company_name || null, phone, phone_public === 'yes', npi, city, neighborhood || null, profession,
          service_description, experience || null, service_area || null, availability || null, contact_preference, contact_email || null, whatsapp_number || null,
          referred_by || null, type_lieu || 'ambulant', adresse_exacte || null, lat, lng, horaires_json,
          p1.secure_url, p2.secure_url, p3.secure_url, trackingCode, 
          BYPASS_PAYMENT ? 'pending' : 'payment_pending', 
          BYPASS_PAYMENT ? 'paid' : 'unpaid'
        ]
      );

      // 👇 C'EST ICI QU'ON AJOUTE LA NOTIFICATION 👇
      sendPushNotification("Nouveau Professionnel ! 🚀", `${full_name} (${profession}) vient de s'inscrire sur TrouveMoi.`);

      if (BYPASS_PAYMENT) return res.send(page("Succès", `<h1>Inscription validée (Mode Test)</h1><p>Code de suivi : ${trackingCode}</p><a href="/">Accueil</a>`, null));
      
      res.redirect(303, `/paiement/${trackingCode}`);
    } catch (e) { 
      console.error("Erreur d'enregistrement du pro :", e.message);
      res.status(500).send(page("Erreur", "<h2>Erreur lors de l'enregistrement. Vérifiez que tous les champs sont bien remplis.</h2>", null)); 
    }
  });

  return router;
};
 
