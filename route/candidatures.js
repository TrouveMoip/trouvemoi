const express = require('express');

module.exports = function(pool, page, getConnectedPro, upload, uploadToCloudinary, takeRateLimit, BYPASS_PAYMENT, KKIAPAY_PUBLIC_KEY, KKIAPAY_SANDBOX, APP_URL, escapeHtml, cleanBeninPhone, readCookie, PAYMENT_AMOUNT, METIERS_LOCAL_FIXE, METIERS_SENSIBLES) {
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
    horairesHtml += `<div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
      <div style="width:100px; font-weight:600; text-transform:capitalize; font-size:14px;">${j}</div>
      <input type="time" name="h_${j}_o" style="margin:0; width:110px; padding:8px;">
      <span>à</span>
      <input type="time" name="h_${j}_f" style="margin:0; width:110px; padding:8px;">
      <label style="margin:0; display:flex; align-items:center; gap:4px; font-size:12px;"><input type="checkbox" name="h_${j}_ferme" value="yes" style="margin:0;"> Fermé</label>
    </div>`;
  });

  const allProfNames = professionsResult.rows.map(p => p.name);
  const refFromUrl = String(req.query.ref || "").trim().toLowerCase();
  const refCookie = refFromUrl || readCookie(req, "tm_ref") || "";
  const warningHtml = refCookie ? `<div class="alert alert-warning" style="margin-bottom: 20px; border-left: 4px solid #f59e0b;"><strong>⚠️ AVERTISSEMENT IMPORTANT :</strong><br><br>Vous accédez à ce formulaire via un lien de parrainage.<br><br><strong>Si vous n'êtes pas un professionnel qualifié ou si votre métier n'est pas inscrit sur la plateforme TrouveMoi, veuillez ne pas continuer cette inscription.</strong><br><br>L'inscription n'est validée qu'après vérification de votre dossier (KYC). En cas de refus (faux profil, métier non inscrit sur la plateforme), les frais d'inscription ne seront pas remboursés.</div>` : "";

  const content = `
    <section class="card" style="max-width: 800px; margin: 0 auto;">
      <h1 style="text-align: center; margin-bottom: 24px;">Devenir professionnel</h1>
      ${warningHtml}
      <div class="alert alert-warning">
        <h3 style="color: #92400e; margin-bottom: 8px;">💳 Frais d'inscription : ${PAYMENT_AMOUNT} FCFA</h3>
        <p style="margin: 0; font-size: 14px;">Des frais d'inscription de <strong>${PAYMENT_AMOUNT} FCFA</strong> sont requis pour l'étude et la validation de votre dossier.</p>
      </div>        
      <form id="form-inscription" action="/candidatures" method="POST" enctype="multipart/form-data" style="background: #f8fafc; padding: 24px; border-radius: 16px; border: 1px solid #e2e8f0;">
        <input type="hidden" name="recaptcha_token" id="recaptcha_token" value="">
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
          <div><label>Nom complet *</label><input name="full_name" required maxlength="150" placeholder="momo"></div>
          <div><label>Societe (facultatif)</label><input name="company_name" maxlength="200" placeholder="momo BTP"></div>
        </div>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
          <div><label>Telephone *</label><input name="phone" type="tel" required maxlength="30" placeholder="0100000000" pattern="01[0-9]{8}" title="10 chiffres commençant par 01"></div>
          <div><label>NPI *</label><input name="npi" required maxlength="15" placeholder="1234567890"></div>
        </div>
        
        <div class="checkbox-block" style="background:#fff; padding:16px; border-radius:12px; border:1px solid #e2e8f0; margin-bottom:16px;"><label><input type="checkbox" name="phone_public" value="yes" checked><span><strong>Numero visible publiquement</strong></span></label></div>
        <h3 style="margin-top: 30px;">Reception code *</h3>
        <div class="checkbox-block" style="background:#fff; padding:16px; border-radius:12px; border:1px solid #e2e8f0; margin-bottom:12px;"><label><input type="radio" name="contact_preference" value="whatsapp" required> <span><strong>📱 WhatsApp</strong></span></label><div id="whatsapp-number-block" class="hidden" style="margin-top:12px;margin-left:30px"><label>Numero WhatsApp</label><input name="whatsapp_number" type="tel" maxlength="30" placeholder="0194010345" pattern="01[0-9]{8}" title="10 chiffres commençant par 01"></div></div>
        <div class="checkbox-block" style="background:#fff; padding:16px; border-radius:12px; border:1px solid #e2e8f0; margin-bottom:12px;"><label><input type="radio" name="contact_preference" value="email" required> <span><strong>✉️ Email</strong></span></label><div id="email-block" class="hidden" style="margin-top:12px;margin-left:30px"><label>Adresse email *</label><input name="contact_email" type="email" maxlength="254"></div></div>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">
          <div><label>Ville *</label><select id="city" name="city" required><option value="">Choisir</option>${cityOptions}</select></div>
          <div><label>Quartier</label><select id="neighborhood" name="neighborhood"><option value="">Choisir</option></select><div id="neighborhood-other-block" class="hidden" style="margin-top:10px;"><input name="neighborhood_other" maxlength="150" placeholder="Precisez"></div></div>
        </div>

        <div style="background: #eff6ff; padding: 16px; border-radius: 12px; margin-bottom: 16px; border: 1px solid #bfdbfe; position: relative;">
          <label style="color: #1e3a8a; margin-top: 0;">🔍 Rechercher votre métier</label>
          <input type="text" id="search-profession" placeholder="Tapez pour filtrer (ex: maçon, coiffeur...)" oninput="filterProfessions()" autocomplete="off" style="border-radius: 8px; padding: 12px; margin: 0; border: 1px solid #93c5fd; width: 100%;">
          <div id="custom-suggestions" style="background: white; border: 1px solid #cbd5e0; border-radius: 0 0 8px 8px; display: none; max-height: 200px; overflow-y: auto; position: absolute; left: 16px; right: 16px; z-index: 100; box-shadow: 0 4px 6px rgba(0,0,0,0.1);"></div>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
          <div><label>Profession *</label><select id="profession" name="profession" required><option value="">Choisir</option>${professionOptions}</select></div>
          <div><label>Experience</label><select name="experience"><option value="">Selectionnez</option><option value="Debutant">Debutant</option><option value="Moins de 2 ans">Moins de 2 ans</option><option value="2 a 5 ans">2 a 5 ans</option><option value="Plus de 5 ans">Plus de 5 ans</option></select></div>
        </div>
        
        <label>Description *</label><textarea name="service_description" rows="4" required maxlength="3000"></textarea>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
          <div><label>Zones</label><input name="service_area" maxlength="300" placeholder="Cotonou et environs"></div>
          <div><label>Disponibilite</label><select name="availability"><option value="">Selectionnez</option><option value="Disponible immediatement">Disponible immediatement</option><option value="Sur rendez-vous">Sur rendez-vous</option><option value="A temps partiel">A temps partiel</option></select></div>
        </div>

        <div style="margin-top:20px; background:#f0fdf4; padding:16px; border-radius:12px; border:1px solid #bbf7d0;">
          <label style="color:#065f46;">🎁 Code de parrainage (optionnel)</label>
          <input name="referred_by" maxlength="10" value="${escapeHtml(refCookie)}" placeholder="Ex: p543ht6" style="text-transform:lowercase;">
          <p style="font-size:12px; color:#065f46; margin:0;">Si un ami vous a invité, entrez son code ici.</p>
        </div>

        <hr style="margin:32px 0;border:none;border-top:1px solid #e2e8f0">
        <h3>Localisation & Type d'activité</h3>
        <div class="checkbox-block" style="background:#fff; padding:16px; border-radius:12px; border:1px solid #e2e8f0; margin-bottom:16px;">
          <label><input type="radio" name="type_lieu" value="fixe" onclick="toggleLocalisation(true)"> <span><strong>🏠 J'ai un local fixe (Boutique, salon, garage...)</strong></span></label>
          <label style="margin-top:10px;"><input type="radio" name="type_lieu" value="ambulant" checked onclick="toggleLocalisation(false)"> <span><strong>🚗 Je me déplace chez le client (Ambulant)</strong></span></label>
        </div>

        <div id="localisation-block" class="hidden">
          <label>Adresse exacte / Point de repère</label>
          <input name="adresse_exacte" maxlength="200" placeholder="Ex: Carrefour Ste Rita, à côté de la station Total">
          
          <div style="background:#f9fafb; padding:16px; border-radius:12px; margin-bottom:16px; border:1px solid #e5e7eb;">
            <h4 style="font-size:14px; margin-bottom:12px; color:#374151;">Horaires d'ouverture</h4>
            ${horairesHtml}
          </div>

          <input type="hidden" name="latitude" id="latitude">
          <input type="hidden" name="longitude" id="longitude">
          <button type="button" onclick="getLocation()" style="background:#3b82f6; width:100%; border-radius:12px; margin-bottom:10px;">📍 Utiliser ma position actuelle</button>
          <p id="gps-status" style="text-align:center; color:#2563eb; font-weight:bold;"></p>
        </div>

        <hr style="margin:32px 0;border:none;border-top:1px solid #e2e8f0">
        <h3>Photos obligatoires (KYC)</h3>
        
        <div style="display: flex; align-items: center; gap: 16px; background: #fff; padding: 16px; border-radius: 12px; margin-bottom: 20px; border: 1px dashed #cbd5e0;">
          <img src="https://res.cloudinary.com/gxm35ndf/image/upload/v1792403314/kyc.jpg" alt="Exemple KYC" style="width: 80px; height: 80px; object-fit: cover; border-radius: 8px; border: 2px solid #e2e8f0;">
          <p style="margin: 0; font-size: 13px; color: #475569;"><strong>Exemple de photo KYC :</strong> Vous devez être de face, en tenant votre pièce d'identité à côté de votre visage, sans lunettes ni chapeau.</p>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
          <div><label>1. Photo d'identité (visage) *</label><input id="photo_profil" name="photo_profil" type="file" accept="image/*" capture="user" required></div>
          <div><label>2. Pièce d'identité (recto) *</label><input id="photo_identite" name="photo_identite" type="file" accept="image/*" capture="environment" required></div>
        </div>
        <label style="margin-top:16px;">3. Photo de vérification KYC (Vous + pièce) *</label>
        <input id="photo_kyc" name="photo_kyc" type="file" accept="image/*" capture="user" required>
        
        <!-- CHECKBOX POLITIQUE DE CONFIDENTIALITE (juste avant le bouton) -->
        <div class="checkbox-block" style="background:#fff; padding:16px; border-radius:12px; border:1px solid #e2e8f0; margin-top:24px;">
          <label style="display:flex; align-items:center; gap:8px;">
            <input type="checkbox" name="gdpr_consent" value="yes" required> 
            <span>J'accepte la <a href="/confidentialite" target="_blank" style="color:#2563eb;">Politique de confidentialite</a>.</span>
          </label>
        </div>
        
        <div style="text-align: center; margin-top: 30px;">
          <button type="submit" style="padding: 16px 40px; font-size: 16px; width: 100%;">Envoyer ma candidature</button>
        </div>

        <div id="alert-metier-sensible" class="alert alert-danger hidden" style="margin-bottom: 20px; border-left: 4px solid #ef4444;">
          <strong>⚠️ ATTENTION - PROFESSION RÉGLEMENTÉE</strong><br><br>
          Ce métier exige une autorisation d'État. Votre dossier fera l'objet d'une <strong>vérification approfondie</strong> (Appel téléphonique et demande de Carte Professionnelle).<br><br>
          <strong>Si vous ne pouvez pas justifier de votre agrément légal, ne continuez pas et ne payez pas.</strong> Aucun remboursement ne sera effectué en cas de rejet.
        </div>
      </form>
    </section>
    
    <script>
      const citySelect = document.getElementById('city'); 
      const neighborhoodSelect = document.getElementById('neighborhood'); 
      const neighborhoodOtherBlock = document.getElementById('neighborhood-other-block'); 
      const professionSelect = document.getElementById('profession'); 
      const whatsappRadio = document.querySelector('input[name="contact_preference"][value="whatsapp"]'); 
      const emailRadio = document.querySelector('input[name="contact_preference"][value="email"]');
      
      document.getElementById('form-inscription').addEventListener('submit', async function(e) {
        if (!document.getElementById('recaptcha_token').value) {
          e.preventDefault();
          const token = await getRecaptchaToken();
          document.getElementById('recaptcha_token').value = token;
          this.submit();
        }
      });

      const allProfessionsList = ${JSON.stringify(allProfNames)};

      function filterProfessions() {
        const search = document.getElementById('search-profession').value.toLowerCase();
        const box = document.getElementById('custom-suggestions');
        if (search.length < 2) { box.style.display = 'none'; return; }
        let html = '';
        allProfessionsList.forEach(function(profName) {
          if (profName.toLowerCase().includes(search)) {
            html += '<div onclick="selectProfession(this.innerText)" style="padding: 10px 14px; cursor: pointer; border-bottom: 1px solid #f3f4f6; font-size: 14px;">' + profName + '</div>';
          }
        });
        if (html) { box.innerHTML = html; box.style.display = 'block'; } else { box.style.display = 'none'; }
      }

      function selectProfession(val) {
        document.getElementById('profession').value = val;
        document.getElementById('search-profession').value = val;
        document.getElementById('custom-suggestions').style.display = 'none';
        document.getElementById('profession').dispatchEvent(new Event('change'));
      }

      ['photo_profil', 'photo_identite', 'photo_kyc'].forEach(id => {
        const input = document.getElementById(id);
        if(input) {
          input.addEventListener('change', function() {
            if (this.files && this.files.length > 0) {
              this.style.border = "3px solid #10b981"; 
              this.style.backgroundColor = "#ecfdf5"; 
              if (!this.nextElementSibling || !this.nextElementSibling.classList.contains('photo-ok')) {
                const msg = document.createElement('div');
                msg.className = 'photo-ok';
                msg.style.cssText = 'color: #10b981; font-size: 13px; font-weight: bold; margin-top: -10px; margin-bottom: 15px;';
                msg.innerHTML = '✅ Photo sélectionnée';
                this.parentNode.insertBefore(msg, this.nextSibling);
              }
            }
          });
        }
      });

      citySelect.addEventListener('change', async function() { 
        const city = citySelect.value; 
        neighborhoodSelect.innerHTML = ''; 
        neighborhoodOtherBlock.classList.add('hidden'); 
        if (!city) { neighborhoodSelect.innerHTML = '<option value="">Choisir</option>'; return; } 
        neighborhoodSelect.innerHTML = '<option value="">Chargement...</option>'; 
        try { 
          const res = await fetch('/api/neighborhoods?city=' + encodeURIComponent(city)); 
          const data = await res.json(); 
          neighborhoodSelect.innerHTML = '<option value="">Choisir</option>'; 
          for (const n of data.neighborhoods) { 
            const opt = document.createElement('option'); opt.value = n; opt.textContent = n; neighborhoodSelect.appendChild(opt); 
          } 
          const otherOpt = document.createElement('option'); otherOpt.value = '__AUTRE__'; otherOpt.textContent = 'Autre'; neighborhoodSelect.appendChild(otherOpt); 
        } catch (e) { neighborhoodSelect.innerHTML = '<option value="">Erreur</option>'; } 
      });
      
      neighborhoodSelect.addEventListener('change', function() { 
        if (neighborhoodSelect.value === '__AUTRE__') neighborhoodOtherBlock.classList.remove('hidden'); 
        else neighborhoodOtherBlock.classList.add('hidden');
      });

      const METIERS_SENSIBLES = ${JSON.stringify(METIERS_SENSIBLES)};
      const METIERS_LOCAL_FIXE = ${JSON.stringify(METIERS_LOCAL_FIXE)};
      
      professionSelect.addEventListener('change', function() {
        const metierActuel = professionSelect.value;
        const radioAmbulant = document.querySelector('input[name="type_lieu"][value="ambulant"]');
        const radioFixe = document.querySelector('input[name="type_lieu"][value="fixe"]');
        
        if (METIERS_LOCAL_FIXE.includes(metierActuel)) {
          radioFixe.checked = true; 
          radioAmbulant.disabled = true; 
          radioAmbulant.parentElement.style.opacity = '0.5'; 
          toggleLocalisation(true); 
        } else {
          radioAmbulant.disabled = false; 
          radioAmbulant.parentElement.style.opacity = '1';
        }

        const alertSensible = document.getElementById('alert-metier-sensible');
        if (alertSensible) {
          if (METIERS_SENSIBLES.includes(metierActuel)) alertSensible.classList.remove('hidden');
          else alertSensible.classList.add('hidden');
        }
      });
      
      whatsappRadio.addEventListener('change', function() { if (whatsappRadio.checked) { document.getElementById('whatsapp-number-block').classList.remove('hidden'); document.getElementById('email-block').classList.add('hidden'); } });
      emailRadio.addEventListener('change', function() { if (emailRadio.checked) { document.getElementById('email-block').classList.remove('hidden'); document.getElementById('whatsapp-number-block').classList.add('hidden'); } });
      
      function toggleLocalisation(isFixe) {
        const block = document.getElementById('localisation-block');
        if (isFixe) block.classList.remove('hidden');
        else block.classList.add('hidden');
      }
      
      function getLocation() {
        const status = document.getElementById('gps-status');
        if (!navigator.geolocation) { status.innerText = "Non supporté."; return; }
        status.innerText = "Récupération de la position...";
        navigator.geolocation.getCurrentPosition(
          (position) => {
            document.getElementById('latitude').value = position.coords.latitude;
            document.getElementById('longitude').value = position.coords.longitude;
            status.innerText = "✅ Position GPS enregistrée !";
          },
          (error) => { status.innerText = "❌ Impossible de vous localiser."; }
        );
      }
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
