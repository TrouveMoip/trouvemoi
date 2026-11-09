const express = require('express');

module.exports = function(pool, page, getConnectedPro, upload, uploadToCloudinary, takeRateLimit, BYPASS_PAYMENT, KKIAPAY_PUBLIC_KEY, KKIAPAY_SANDBOX, APP_URL, escapeHtml, cleanBeninPhone, readCookie, PAYMENT_AMOUNT, METIERS_LOCAL_FIXE, METIERS_SENSIBLES, sendSMS, verifyOTP) {
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
      <div style="width:100px; font-weight:600; text-transform:capitalize; font-size:14px;">${j}</div>
      <input type="time" name="h_${j}_o" style="margin:0; width:110px; padding:8px;">
      <span>à</span>
      <input type="time" name="h_${j}_f" style="margin:0; width:110px; padding:8px;">
      <label style="margin:0; display:flex; align-items:center; gap:4px; font-size:12px;"><input type="checkbox" name="h_${j}_ferme" value="yes" style="margin:0;"> Fermé</label>
    </div>`;
  });

  const refFromUrl = String(req.query.ref || "").trim().toLowerCase();
  const refCookie = refFromUrl || readCookie(req, "tm_ref") || "";
  
  // Styles pour les étapes (espacés et propres)
  const stepStyle = `background:white; padding:24px; border-radius:16px; box-shadow:0 4px 12px rgba(0,0,0,0.05); border:1px solid #e5e7eb; margin-bottom:20px; display:none;`;
  const activeStepStyle = `display:block;`;

  const content = `
    <section style="max-width: 700px; margin: 0 auto;">
      <h1 style="text-align: center; margin-bottom: 10px;">Devenir professionnel</h1>
      
      <!-- Barre de progression -->
      <div style="display:flex; justify-content:space-between; margin-bottom:30px; background:#e5e7eb; height:8px; border-radius:4px;">
        <div id="progress-bar" style="width:25%; background:#3b82f6; height:100%; border-radius:4px; transition:width 0.3s;"></div>
      </div>

      <form id="form-inscription" action="/candidatures" method="POST" enctype="multipart/form-data">
        
        <!-- ÉTAPE 1 : IDENTITÉ (Ordre respecté) -->
        <div id="step-1" style="${stepStyle} ${activeStepStyle}">
          <h2 style="color:#1e40af; margin-bottom:20px;">1. Votre Identité</h2>
          
          <label>Nom et prénoms *</label>
          <input name="full_name" id="input_full_name" required maxlength="150" placeholder="Ex: Jean Dupont">
          
          <label>Société (facultatif)</label>
          <input name="company_name" id="input_company_name" maxlength="200" placeholder="Ex: Momo BTP">
          
          <label>NPI (Numéro Personnel d'Identification) *</label>
          <input name="npi" id="input_npi" required maxlength="15" placeholder="Ex: 1234567890">
          
          <label>N° Téléphone *</label>
          <input name="phone" id="input_phone" type="tel" required maxlength="30" placeholder="01XXXXXXXX" pattern="01[0-9]{8}">
          
          <div style="background:#eff6ff; padding:16px; border-radius:12px; margin-top:15px; border:1px solid #bfdbfe;">
            <label style="margin-top:0; color:#1e3a8a; font-weight:bold;">Vérification du numéro (Obligatoire)</label>
            <div style="display:flex; gap:10px;">
              <input name="phone_verif" id="phone_verif_input" type="tel" placeholder="Numéro à vérifier" style="margin-bottom:0;" readonly>
              <button type="button" onclick="demanderCodePro()" style="margin-bottom:0; padding: 12px; white-space: nowrap; background: #3b82f6; color: white; border: none; border-radius: 8px; cursor: pointer;">Recevoir</button>
            </div>
            <div id="otp-block" style="display:none; margin-top:10px;">
              <input name="otp_code" id="otp_code_input" placeholder="Entrez le code SMS à 6 chiffres" required style="margin-bottom:0;">
            </div>
          </div>

          <button type="button" onclick="nextStep(1)" style="width:100%; margin-top:20px;">Suivant →</button>
        </div>

        <!-- ÉTAPE 2 : MÉTIER -->
        <div id="step-2" style="${stepStyle}">
          <h2 style="color:#1e40af; margin-bottom:20px;">2. Votre Métier</h2>
          
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div><label>Ville *</label><select id="city" name="city" required><option value="">Choisir</option>${cityOptions}</select></div>
            <div><label>Quartier</label><select id="neighborhood" name="neighborhood"><option value="">Choisir</option></select></div>
          </div>
          <div id="neighborhood-other-block" class="hidden" style="margin-bottom:14px;"><input name="neighborhood_other" maxlength="150" placeholder="Précisez votre quartier"></div>

          <label>Profession *</label>
          <select id="profession" name="profession" required><option value="">Choisir</option>${professionOptions}</select>
          
          <label>Description de vos services *</label>
          <textarea name="service_description" rows="4" required maxlength="3000" placeholder="Décrivez ce que vous faites..."></textarea>

          <div style="display:flex; gap:10px; margin-top:20px;">
            <button type="button" onclick="prevStep(2)" class="secondary" style="width:50%;">← Retour</button>
            <button type="button" onclick="nextStep(2)" style="width:50%;">Suivant →</button>
          </div>
        </div>

        <!-- ÉTAPE 3 : LOCALISATION -->
        <div id="step-3" style="${stepStyle}">
          <h2 style="color:#1e40af; margin-bottom:20px;">3. Localisation & Horaires</h2>
          
          <div class="checkbox-block" style="background:#f9fafb; padding:16px; border-radius:12px; border:1px solid #e5e7eb; margin-bottom:16px;">
            <label><input type="radio" name="type_lieu" value="fixe" onclick="toggleLocalisation(true)"> <span><strong>🏠 J'ai un local fixe</strong></span></label>
            <label style="margin-top:10px;"><input type="radio" name="type_lieu" value="ambulant" checked onclick="toggleLocalisation(false)"> <span><strong>🚗 Je me déplace chez le client</strong></span></label>
          </div>

          <div id="localisation-block" class="hidden">
            <label>Adresse exacte / Point de repère</label>
            <input name="adresse_exacte" maxlength="200" placeholder="Ex: Carrefour Ste Rita">
            
            <div style="background:#f9fafb; padding:16px; border-radius:12px; margin-bottom:16px; border:1px solid #e5e7eb;">
              <h4 style="font-size:14px; margin-bottom:12px; color:#374151;">Horaires d'ouverture</h4>
              ${horairesHtml}
            </div>

            <input type="hidden" name="latitude" id="latitude">
            <input type="hidden" name="longitude" id="longitude">
            <button type="button" onclick="getLocation()" style="background:#3b82f6; width:100%; border-radius:12px; margin-bottom:10px;">📍 Utiliser ma position actuelle</button>
            <p id="gps-status" style="text-align:center; color:#2563eb; font-weight:bold;"></p>
          </div>

          <div style="display:flex; gap:10px; margin-top:20px;">
            <button type="button" onclick="prevStep(3)" class="secondary" style="width:50%;">← Retour</button>
            <button type="button" onclick="nextStep(3)" style="width:50%;">Suivant →</button>
          </div>
        </div>

        <!-- ÉTAPE 4 : KYC & PHOTOS -->
        <div id="step-4" style="${stepStyle}">
          <h2 style="color:#1e40af; margin-bottom:20px;">4. Vérification (KYC)</h2>
          
          <div style="display: flex; align-items: center; gap: 16px; background: #fff; padding: 16px; border-radius: 12px; margin-bottom: 20px; border: 1px dashed #cbd5e0;">
            <img src="https://res.cloudinary.com/gxm35ndf/image/upload/v1792403314/kyc.jpg" style="width: 80px; height: 80px; object-fit: cover; border-radius: 8px;">
            <p style="margin: 0; font-size: 13px; color: #475569;"><strong>Exemple :</strong> Vous devez être de face, en tenant votre pièce d'identité à côté de votre visage.</p>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div><label>1. Photo visage *</label><input name="photo_profil" type="file" accept="image/*" required></div>
            <div><label>2. Pièce d'identité *</label><input name="photo_identite" type="file" accept="image/*" required></div>
          </div>
          <label style="margin-top:16px;">3. Photo KYC (Visage + Pièce) *</label>
          <input name="photo_kyc" type="file" accept="image/*" required>
          
          <div class="checkbox-block" style="background:#fff; padding:16px; border-radius:12px; border:1px solid #e2e8f0; margin-top:24px;">
            <label><input type="checkbox" name="gdpr_consent" value="yes" required> <span>J'accepte la <a href="/confidentialite" target="_blank" style="color:#2563eb;">Politique de confidentialité</a>.</span></label>
          </div>
          
          <div style="margin-top:20px; background:#f0fdf4; padding:16px; border-radius:12px; border:1px solid #bbf7d0;">
            <label style="color:#065f46;">🎁 Code de parrainage (optionnel)</label>
            <input name="referred_by" maxlength="10" value="${escapeHtml(refCookie)}" placeholder="Ex: p543ht6" style="text-transform:lowercase;">
          </div>

          <button type="submit" id="submit-btn" style="width:100%; margin-top:20px; padding:16px; font-size:16px; background:#10b981;">Envoyer ma candidature</button>
        </div>
      </form>
    </section>

    <script>
      // Logique des étapes
      let currentStep = 1;
      function showStep(step) {
        document.querySelectorAll('[id^="step-"]').forEach(el => el.style.display = 'none');
        document.getElementById('step-' + step).style.display = 'block';
        document.getElementById('progress-bar').style.width = (step * 25) + '%';
        currentStep = step;
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
      function prevStep(step) {
        showStep(step - 1);
      }
      
      // Logique GPS et SMS
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

      // Copier le numéro dans la case de vérification
      document.getElementById('input_phone').addEventListener('input', function() {
          document.getElementById('phone_verif_input').value = this.value;
      });

      // Demander le code SMS
      async function demanderCodePro() {
        const phone = document.getElementById('input_phone').value;
        if (!phone || !/^01[0-9]{8}$/.test(phone)) { alert("Entrez un numéro valide (ex: 0194010345)"); return; }
        
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
      
      // Gestion du quartier "Autre"
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
          document.getElementById('neighborhood-other-block').style.display = (this.value === '__AUTRE__') ? 'block' : 'none';
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

    const neighborhood = req.body.neighborhood === '__AUTRE__' ? req.body.neighborhood_other : req.body.neighborhood;

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
    // Vérification du code SMS
const codeValide = await verifyOTP(phone, otpCode);
if (!codeValide) {
  return res.status(400).send(page("Erreur", "<h2>Code SMS invalide ou expiré.</h2><a href='/devenir-professionnel'>Retour au formulaire</a>", null));
}

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
      if (process.env.ADMIN_PHONE) {
  sendSMS(process.env.ADMIN_PHONE, `🔔 TrouveMoi - Nouveau Pro inscrit : ${full_name} (${profession}).`);
}

      if (BYPASS_PAYMENT) return res.send(page("Succès", `<h1>Inscription validée (Mode Test)</h1><p>Code de suivi : ${trackingCode}</p><a href="/">Accueil</a>`, null));
      
      res.redirect(303, `/paiement/${trackingCode}`);
    } catch (e) { 
      console.error("Erreur d'enregistrement du pro :", e.message);
      res.status(500).send(page("Erreur", "<h2>Erreur lors de l'enregistrement. Vérifiez que tous les champs sont bien remplis.</h2>", null)); 
    }
  });

  return router;
};
