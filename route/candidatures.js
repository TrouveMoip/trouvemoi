const express = require('express');

module.exports = function(pool, page, getConnectedPro, upload, uploadToCloudinary, takeRateLimit, BYPASS_PAYMENT, KKIAPAY_PUBLIC_KEY, KKIAPAY_SANDBOX, APP_URL, escapeHtml, cleanBeninPhone, readCookie, PAYMENT_AMOUNT, METIERS_LOCAL_FIXE, METIERS_SENSIBLES, sendSMS, verifyOTP, sendPushNotification, VILLES_BENIN) {
  const router = express.Router();

  router.get("/devenir-professionnel", async (req, res) => { 
  const proConnected = await getConnectedPro(req);
  const professionsResult = await pool.query("SELECT id, name, category FROM professions ORDER BY display_order ASC");

  const cityList = VILLES_BENIN; 
  const cityOptions = cityList.map((c) => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join("");
  
  const professionsByCategory = {};
  for (const p of professionsResult.rows) { const cat = p.category || "Autres"; if (!professionsByCategory[cat]) professionsByCategory[cat] = []; professionsByCategory[cat].push(p.name); }
  const professionOptions = Object.values(professionsByCategory).flat().map(name => `<option value="${escapeHtml(name)}">`).join("");  
  
 const jours = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"];
let horairesHtml = "";
jours.forEach(j => {
  horairesHtml += `
    <div style="display:flex; align-items:center; justify-content:space-between; padding:10px 0; border-bottom:1px solid #e2e8f0; gap:10px;">
      <div style="width:70px; font-weight:600; text-transform:capitalize; font-size:14px; color:#334155;">${j}</div>
      
      <div style="display:flex; align-items:center;">
        <!-- On utilise une checkbox cachée pour gérer l'état ouvert/fermé -->
        <input type="checkbox" name="h_${j}_open" value="yes" id="open_${j}" checked onchange="toggleJour('${j}')" style="display:none;">
        
        <button type="button" onclick="document.getElementById('open_${j}').click()" id="btn_${j}" style="background:#10b981; color:white; border:none; padding:6px 12px; border-radius:20px; font-size:12px; font-weight:bold; cursor:pointer; width:70px;">Ouvert</button>
      </div>

      <div id="heures_${j}" style="display:flex; align-items:center; gap:5px;">
        <input type="time" name="h_${j}_o" style="margin:0; padding:4px; border:1px solid #cbd5e1; border-radius:6px; font-size:12px; width:85px; background:#f8fafc;">
        <span style="color:#94a3b8; font-size:12px;">à</span>
        <input type="time" name="h_${j}_f" style="margin:0; padding:4px; border:1px solid #cbd5e1; border-radius:6px; font-size:12px; width:85px; background:#f8fafc;">
      </div>
    </div>
  `;
});

  const refFromUrl = String(req.query.ref || "").trim().toLowerCase();
  const refCookie = refFromUrl || readCookie(req, "tm_ref") || "";
  const metiersLocalFixeJson = JSON.stringify(METIERS_LOCAL_FIXE);
  
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
      
      .fancy-label { font-weight: 600; color: #334155; margin-bottom: 6px; display: block; font-size: 14px; }
      .fancy-input { width: 100%; padding: 14px 16px; border-radius: 12px; border: 1px solid #cbd5e1; background: #f8fafc; margin-bottom: 18px; transition: all 0.2s; }
      .fancy-input:focus { background: white; border-color: #3b82f6; box-shadow: 0 0 0 4px rgba(59,130,246,0.1); outline: none; }
    </style>

    <section style="max-width: 700px; margin: 0 auto;">
      <h1 style="text-align: center; margin-bottom: 24px; color: #1e3a8a;">Devenir professionnel</h1>
      
      <div style="background:#fffbeb; border:1px solid #fde68a; border-left:4px solid #f59e0b; padding:16px; border-radius:8px; margin-bottom:24px; text-align:center;">
        <p style="margin:0; color:#92400e; font-size:15px; font-weight:600;">💳 Frais d'inscription : <span style="font-size:18px; font-weight:800;">1500 FCFA</span></p>
        <p style="margin:4px 0 0 0; color:#92400e; font-size:13px;">Ce montant devra être réglé à la fin du formulaire afin de procéder à l’activation de votre profil.</p>
      </div>

      <div class="step-indicator">
        <div class="step-item active" id="indicator-1"><div class="step-circle">1</div><div class="step-label">Identité</div></div>
        <div class="step-item" id="indicator-2"><div class="step-circle">2</div><div class="step-label">Métier</div></div>
        <div class="step-item" id="indicator-3"><div class="step-circle">3</div><div class="step-label">Localisation</div></div>
        <div class="step-item" id="indicator-4"><div class="step-circle">4</div><div class="step-label">KYC</div></div>
      </div>

      <form id="form-inscription" action="/candidatures" method="POST" enctype="multipart/form-data">
        
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

          <label class="fancy-label">Adresse E-mail (facultatif)</label>
          <input name="contact_email" type="email" maxlength="254" placeholder="Ex: jean@gmail.com" class="fancy-input">
          
          <div style="background:#eff6ff; padding:20px; border-radius:16px; margin-top:10px; border:1px dashed #93c5fd;">
            <label style="margin-top:0; color:#1e3a8a; font-weight:bold; display:flex; align-items:center; gap:8px;">
              <span style="font-size:20px;">📱</span> Vérification du numéro
            </label>
            <p style="font-size:12px; color:#3b82f6; margin-bottom:10px;">Nous vous enverrons un code par SMS pour confirmer.</p>
            <div style="display:flex; gap:10px;">
              <button type="button" onclick="demanderCodePro()" style="width:100%; margin-bottom:0; padding: 14px; white-space: nowrap; background: #3b82f6; color: white; border: none; border-radius: 12px; cursor: pointer; font-weight:bold;">📩 Recevoir mon code par SMS</button>
            </div>
            <div id="otp-block" style="display:none; margin-top:12px;">
              <input name="otp_code" id="otp_code_input" placeholder="Entrez le code à 6 chiffres" style="margin-bottom:0; background:#fff; text-align:center; letter-spacing:4px; font-size:18px;" class="fancy-input">
            </div>

            <div style="margin-top:15px; border-top:1px solid #bfdbfe; padding-top:15px;">
              <label class="fancy-label" style="color:#1e3a8a; font-size:13px;">Ce numéro de téléphone est-il aussi votre numéro WhatsApp ? *</label>
              <div style="display:flex; gap:15px; margin-bottom:10px;">
                <label style="display:flex; align-items:center; gap:5px; cursor:pointer;"><input type="radio" name="is_wa_same" value="yes" required onclick="toggleWaField(false)"> Oui</label>
                <label style="display:flex; align-items:center; gap:5px; cursor:pointer;"><input type="radio" name="is_wa_same" value="no" required onclick="toggleWaField(true)"> Non</label>
              </div>
              <div id="wa-field" style="display:none;">
                <input name="whatsapp_number" id="whatsapp_input" type="tel" maxlength="30" placeholder="Entrez votre autre numéro WhatsApp (01XXXXXXXX)" pattern="01[0-9]{8}" class="fancy-input" style="margin-bottom:0; background:#fff;">
              </div>
            </div>
          </div>

          <button type="button" onclick="nextStep(1)" style="width:100%; margin-top:24px; padding:16px; font-size:16px; font-weight:bold; border-radius:12px;">Suivant →</button>
        </div>

        <div id="step-2" class="form-page" style="background:white; padding:28px; border-radius:20px; box-shadow:0 10px 25px rgba(0,0,0,0.05); border:1px solid #f1f5f9;">
          <h2 style="color:#1e40af; margin-bottom:20px; font-size:20px;">🛠️ Votre Métier</h2>
          
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div>
              <label class="fancy-label">Ville *</label>
              <div style="margin-bottom:10px;">
                <input type="text" id="search-city" placeholder="🔍 Rechercher votre ville..." style="padding:12px; border-radius:12px; border:1px solid #e2e8f0; width:100%;" oninput="filterCities()">
              </div>
              <select id="city" name="city" required class="fancy-input" size="1"><option value="">Choisir</option>${cityOptions}</select>
            </div>
            <div>
              <label class="fancy-label">Quartier *</label>
              <select id="neighborhood" name="neighborhood" required class="fancy-input"><option value="">Choisir</option></select>
            </div>
          </div>
          <div id="neighborhood-other-block" class="hidden" style="margin-top:-10px; margin-bottom:18px;"><input name="neighborhood_other" maxlength="150" placeholder="Précisez votre quartier" class="fancy-input"></div>

          <label class="fancy-label">Profession *</label>
          <input type="text" id="profession" name="profession" list="profession-list" required placeholder="Tapez votre métier (ex: Plombier)..." class="fancy-input" autocomplete="off">
          <datalist id="profession-list">
            ${professionOptions}
          </datalist>
          
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

        <div id="step-3" class="form-page" style="background:white; padding:28px; border-radius:20px; box-shadow:0 10px 25px rgba(0,0,0,0.05); border:1px solid #f1f5f9;">
          <h2 style="color:#1e40af; margin-bottom:20px; font-size:20px;">📍 Localisation & Horaires</h2>
          
          <div style="background:#f8fafc; padding:20px; border-radius:16px; border:1px solid #e2e8f0; margin-bottom:20px;">
            <label class="fancy-label" style="margin-top:0; margin-bottom:12px;">Comment travaillez-vous ?</label>
            <label style="display:flex; align-items:center; gap:10px; margin-bottom:12px; cursor:pointer;"><input type="radio" id="radio-fixe" name="type_lieu" value="fixe" onclick="toggleLocalisation(true)" style="width:20px; height:20px;"> <span><strong>🏠 J'ai un local fixe (Boutique, salon, garage...)</strong></span></label>
            <label style="display:flex; align-items:center; gap:10px; cursor:pointer;"><input type="radio" id="radio-ambulant" name="type_lieu" value="ambulant" checked onclick="toggleLocalisation(false)" style="width:20px; height:20px;"> <span><strong>🚗 Je me déplace chez le client (Ambulant)</strong></span></label>
          </div>

          <div id="localisation-block" class="hidden">
            <label class="fancy-label">Adresse exacte / Point de repère</label>
            <!-- ✅ J'ai retiré le "required" ici pour que ça marche quand le champ est désactivé -->
            <input name="adresse_exacte" maxlength="200" placeholder="Ex: Carrefour Ste Rita, à côté de la station Total" class="fancy-input">
            
            <input type="hidden" name="latitude" id="latitude">
            <input type="hidden" name="longitude" id="longitude">
            <button type="button" onclick="getLocation()" style="background:#e0e7ff; color:#1e3a8a; width:100%; border-radius:12px; margin-bottom:10px; padding:14px; font-weight:bold; border:1px solid #c7d2fe;">📍 Utiliser ma position actuelle</button>
            <p id="gps-status" style="text-align:center; color:#2563eb; font-weight:bold; font-size:14px;"></p>

            <div style="background:#f8fafc; padding:20px; border-radius:16px; margin-bottom:20px; border:1px solid #e2e8f0;">
              <label class="fancy-label" style="margin-top:0;">🕒 Horaires d'ouverture</label>
              ${horairesHtml}
            </div>
          </div>

          <div style="display:flex; gap:12px; margin-top:10px;">
            <button type="button" onclick="prevStep(3)" class="secondary" style="width:40%; padding:16px; border-radius:12px; font-weight:bold;">← Retour</button>
            <button type="button" onclick="nextStep(3)" style="width:60%; padding:16px; font-size:16px; font-weight:bold; border-radius:12px;">Suivant →</button>
          </div>
        </div>

        <div id="step-4" class="form-page" style="background:white; padding:28px; border-radius:20px; box-shadow:0 10px 25px rgba(0,0,0,0.05); border:1px solid #f1f5f9;">
          <h2 style="color:#1e40af; margin-bottom:20px; font-size:20px;">🛡️ Vérification (KYC)</h2>
          
          <div style="display: flex; align-items: center; gap: 16px; background: #fffbeb; padding: 16px; border-radius: 16px; margin-bottom: 24px; border: 1px solid #fde68a;">
            <img src="https://res.cloudinary.com/gxm35ndf/image/upload/v1792403314/kyc.jpg" style="width: 80px; height: 80px; object-fit: cover; border-radius: 12px; border:2px solid white; box-shadow:0 2px 5px rgba(0,0,0,0.1);">
            <p style="margin: 0; font-size: 13px; color: #92400e; line-height:1.4;"><strong>Exemple :</strong> Vous devez être de face, en tenant votre pièce d'identité à côté de votre visage, sans lunettes ni chapeau.</p>
          </div>

          <div style="display: grid; grid-template-columns: 1fr; gap: 16px;">
            <div>
              <label class="fancy-label">1. Photo de votre visage *</label>
              <input name="photo_profil" id="photo_profil" type="file" accept="image/*" required class="fancy-input" style="padding:10px; background:#fff;">
            </div>
            <div>
              <label class="fancy-label">2. Photo de la pièce d'identité (Recto) *</label>
              <input name="photo_identite" id="photo_identite" type="file" accept="image/*" required class="fancy-input" style="padding:10px; background:#fff;">
            </div>
            <div>
              <label class="fancy-label">3. Photo KYC (Visage + Pièce ensemble) *</label>
              <input name="photo_kyc" id="photo_kyc" type="file" accept="image/*" required class="fancy-input" style="padding:10px; background:#fff;">
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

          <div style="margin-top:24px; padding:16px; background:#fffbeb; border:1px solid #fde68a; border-left:4px solid #f59e0b; border-radius:8px;">
            <p style="margin:0; color:#92400e; font-size:14px;">💳 <strong>Rappel :</strong> Après avoir cliqué sur "Envoyer", vous serez redirigé vers le paiement sécurisé des frais d'inscription de <strong>1500 FCFA</strong>. Votre profil ne sera activé qu'après ce paiement et la validation de notre équipe.</p>
          </div>

          <div style="display:flex; gap:12px; margin-top:24px;">
            <button type="button" onclick="prevStep(4)" class="secondary" style="width:40%; padding:16px; border-radius:12px; font-weight:bold;">← Retour</button>
            <button type="submit" id="submit-btn" style="width:60%; padding:16px; font-size:16px; font-weight:bold; border-radius:12px; background:#10b981;">✅ Envoyer</button>
          </div>
        </div>
      </form>
    </section>

    <script>
    // --- LOGIQUE DES ÉTAPES ---
    function showStep(step) {
      document.querySelectorAll('.form-page').forEach(el => el.classList.remove('active'));
      document.getElementById('step-' + step).classList.add('active');
      for (let i = 1; i <= 4; i++) {
        const indicator = document.getElementById('indicator-' + i);
        indicator.classList.remove('active', 'completed');
        if (i < step) indicator.classList.add('completed');
        if (i === step) indicator.classList.add('active');
      }
    }
    
    function nextStep(step) {
      if (step === 1) {
        const name = document.getElementById('input_full_name').value.trim();
        const npi = document.getElementById('input_npi').value.trim();
        const phone = document.getElementById('input_phone').value.trim();
        const otp = document.getElementById('otp_code_input').value.trim();
        const waSame = document.querySelector('input[name="is_wa_same"]:checked');

        if(!name || !npi || !phone) { alert("Veuillez remplir le nom, le NPI et le téléphone."); return; }
        if(!otp) { alert("Veuillez entrer le code SMS reçu."); return; }
        if(!waSame) { alert("Veuillez indiquer si votre numéro de téléphone est aussi votre WhatsApp."); return; }
        
        if(waSame.value === 'no') {
           const waInput = document.getElementById('whatsapp_input').value.trim();
           if(!waInput || !/^01[0-9]{8}$/.test(waInput)) {
             alert("Veuillez entrer un numéro WhatsApp valide (ex: 01XXXXXXXX)."); return;
           }
        }
      }
      if (step === 2) {
        const city = document.getElementById('city').value;
        const prof = document.getElementById('profession').value;
        if(!city || !prof) { alert("Veuillez choisir votre ville et profession."); return; }
      }
      showStep(step + 1);
    }
    function prevStep(step) { showStep(step - 1); }
    
    // --- LOGIQUE LOCALISATION & GPS ---
    function toggleLocalisation(isFixe) {
      document.getElementById('localisation-block').style.display = isFixe ? 'block' : 'none';
    }
   
    function getLocation() {
      const status = document.getElementById('gps-status');
      status.innerText = "⏳ Récupération de votre position...";
      
      navigator.geolocation.getCurrentPosition(
        (position) => {
          document.getElementById('latitude').value = position.coords.latitude;
          document.getElementById('longitude').value = position.coords.longitude;
          
          status.innerText = "✅ Position GPS enregistrée !";
          
          // ✅ On demande au pro s'il est exactement sur place
const isExactLocation = confirm("📍 Êtes-vous exactement sur le lieu de votre établissement ? Cliquez sur OK si vous êtes sur place. Cliquez sur Annuler si vous êtes ailleurs.");          
          const adresseInput = document.querySelector('input[name="adresse_exacte"]');
          
          if (isExactLocation) {
            // Si OUI : On désactive le champ adresse (grisé)
            adresseInput.value = "Position GPS exacte enregistrée";
            adresseInput.disabled = true;
            adresseInput.style.background = "#e5e7eb";
            adresseInput.style.cursor = "not-allowed";
          } else {
            // Si NON : On laisse le champ actif
            adresseInput.disabled = false;
            adresseInput.style.background = "";
            adresseInput.style.cursor = "";
            adresseInput.value = "";
            adresseInput.focus();
          }
        },
        () => { 
          status.innerText = "❌ Impossible de vous localiser. Veuillez autoriser le GPS ou écrire l'adresse manuellement."; 
        }
      );
    }

    // --- LOGIQUE METIERS (BOUTON GRIS) ---
    const METIERS_LOCAL_FIXE = ${metiersLocalFixeJson};
    
    document.getElementById('profession').addEventListener('change', function() {
      const metierActuel = this.value;
      const radioAmbulant = document.getElementById('radio-ambulant');
      const radioFixe = document.getElementById('radio-fixe');
      
      if (METIERS_LOCAL_FIXE.includes(metierActuel)) {
        radioFixe.checked = true; 
        radioAmbulant.disabled = true; 
        radioAmbulant.parentElement.style.opacity = '0.5'; 
        toggleLocalisation(true); 
      } else {
        radioAmbulant.disabled = false; 
        radioAmbulant.parentElement.style.opacity = '1';
      }
    });

    // --- LOGIQUE VILLES & QUARTIERS (Appel API) ---
    function filterCities() {
      const search = document.getElementById('search-city').value.toLowerCase();
      const select = document.getElementById('city');
      const options = select.options;
      for (let i = 1; i < options.length; i++) { 
        const txt = options[i].text.toLowerCase();
        options[i].style.display = txt.includes(search) ? "block" : "none";
      }
      let visibleCount = 0; let lastVisible = null;
      for (let i = 1; i < options.length; i++) {
        if (options[i].style.display !== "none") { visibleCount++; lastVisible = options[i]; }
      }
      if (visibleCount === 1) select.value = lastVisible.value;
    }

    document.getElementById('city').addEventListener('change', async function() { 
      const city = this.value; const select = document.getElementById('neighborhood');
      select.innerHTML = '<option value="">Chargement...</option>'; 
      try { 
        const res = await fetch('/api/neighborhoods?city=' + encodeURIComponent(city)); 
        const data = await res.json(); 
        select.innerHTML = '<option value="">Choisir</option>'; 
        for (const n of data.neighborhoods) { 
          const opt = document.createElement('option'); opt.value = n; opt.textContent = n; select.appendChild(opt); 
        }
      } catch (e) { select.innerHTML = '<option value="">Erreur</option>'; } 
    });

    document.getElementById('neighborhood').addEventListener('change', function() { 
      document.getElementById('neighborhood-other-block').style.display = (this.value === 'Autre') ? 'block' : 'none';
    });

    // --- LOGIQUE SMS ---
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
          alert("✅ Code envoyé ! Vérifiez vos SMS (ou les logs Render).");
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

    function toggleWaField(show) {
      const waField = document.getElementById('wa-field');
      const waInput = document.getElementById('whatsapp_input');
      if (show) {
        waField.style.display = 'block';
        waInput.required = true;
      } else {
        waField.style.display = 'none';
        waInput.required = false;
        waInput.value = ''; // On vide le champ si on choisit "Oui"
      }
    }

    // --- LOGIQUE PHOTOS (FOND VERT) ---
    ['photo_profil', 'photo_identite', 'photo_kyc'].forEach(id => {
      const input = document.getElementById(id);
      if(input) {
        input.addEventListener('change', function() {
          if (this.files && this.files.length > 0) {
            this.parentElement.style.border = "2px solid #10b981";
            this.parentElement.style.backgroundColor = "#ecfdf5";
            this.parentElement.style.borderRadius = "8px";
            this.parentElement.style.padding = "10px";
            
            if (!this.parentElement.querySelector('.photo-ok')) {
              const msg = document.createElement('div');
              msg.className = 'photo-ok';
              msg.style.cssText = 'color: #10b981; font-size: 12px; font-weight: bold; margin-top: 5px;';
              msg.innerHTML = '✅ Photo sélectionnée';
              this.parentElement.appendChild(msg);
            }
          }
        });
      }
    });
    </script>
  `;
  res.send(page("Devenir professionnel", content, proConnected));
});

  router.post("/candidatures", upload.fields([{ name: "photo_profil", maxCount: 1 }, { name: "photo_identite", maxCount: 1 }, { name: "photo_kyc", maxCount: 1 }]), async (req, res) => {
    const files = req.files || {};
    
    const { 
      full_name, company_name, phone, npi, city, profession, service_description,
      contact_preference, contact_email, experience, service_area, availability,
      referred_by, type_lieu, adresse_exacte, latitude, longitude, phone_public
    } = req.body;

    // ✅ Gestion du numéro WhatsApp
    let whatsapp_number = req.body.whatsapp_number;
    if (req.body.is_wa_same === 'yes') {
      whatsapp_number = phone; // Si c'est le même, on prend le numéro principal
    }

    const otpCode = String(req.body.otp_code || "").trim();
    const neighborhood = req.body.neighborhood === 'Autre' ? req.body.neighborhood_other : req.body.neighborhood;

    const horaires = {};
    ['lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi', 'dimanche'].forEach(j => {
if (req.body[`h_${j}_status`] === 'open') {
      const o = req.body[`h_${j}_o`];
        const f = req.body[`h_${j}_f`];
        if (o && f) horaires[j] = { o, f };
      }
    });
    const horaires_json = Object.keys(horaires).length > 0 ? JSON.stringify(horaires) : null;
    const lat = Number(latitude) || null;
    const lng = Number(longitude) || null;

    try {
      // ✅ VÉRIFICATION DU CODE SMS OBLIGATOIRE
      const codeValide = await verifyOTP(phone, otpCode);
      if (!codeValide) {
        return res.status(400).send(page("Erreur", "<h2>Code SMS invalide ou expiré. Veuillez recommencer.</h2><a href='/devenir-professionnel'>Retour</a>", null));
      }

      // ✅ VÉRIFICATION ANTI-DOUBLON : NPI ET TELEPHONE
      const existingPro = await pool.query(`SELECT id FROM professional_applications WHERE npi = $1 OR phone = $2`, [npi, phone]);
      if (existingPro.rows.length) {
        return res.status(400).send(page("Erreur", "<h2>Un dossier existe déjà avec ce NPI ou ce numéro de téléphone.</h2><p>Si vous avez déjà un compte, veuillez vous connecter ou contacter le support.</p><a href='/devenir-professionnel'>Retour</a>", null));
      }

      if (!files.photo_profil || !files.photo_profil[0] || !files.photo_identite || !files.photo_identite[0] || !files.photo_kyc || !files.photo_kyc[0]) {
        return res.status(400).send(page("Erreur", "<h2>Veuillez bien sélectionner les 3 photos.</h2><a href='/devenir-professionnel'>Retour</a>", null));
      }

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
