const express = require('express');

module.exports = function(pool, page, getConnectedPro, getOrCreateVisitorId, escapeHtml, renderStars, renderKycBadge, getDisplayName, APP_URL) {
  const router = express.Router();

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

  // ==========================================
  // 1. PAGE D'ACCUEIL
  // ==========================================
  router.get("/", async (req, res) => {
    try {
      const proConnected = await getConnectedPro(req);
      const visitorId = getOrCreateVisitorId(req, res);
      const rawRef = typeof req.query.ref === "string" ? req.query.ref.trim().toLowerCase() : "";
      const refCode = /^[a-z0-9]{7}$/.test(rawRef) ? rawRef : null;
      if (refCode) res.append("Set-Cookie", `tm_ref=${refCode}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 24 * 60 * 60}`);

      const currentPage = Math.max(1, parseInt(req.query.page) || 1);
      const limit = 6; const offset = (currentPage - 1) * limit;
      const totalAllProsResult = await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status = 'approved'");
      const totalAllPros = parseInt(totalAllProsResult.rows[0].count);
      const totalPages = Math.ceil(totalAllPros / limit);

      const query = `SELECT p.id, p.full_name, p.company_name, p.phone, p.phone_public, p.city, p.profession, p.service_description, p.latitude, p.longitude, p.kyc_verified, (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count, (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating, EXISTS(SELECT 1 FROM client_favorites cf WHERE cf.pro_id = p.id AND cf.visitor_id = $3) AS is_favorite FROM professional_applications p WHERE p.status = 'approved' ORDER BY p.created_at DESC LIMIT $1 OFFSET $2`;
      const result = await pool.query(query, [limit, offset, visitorId]);

      const agenciesAccueil = await pool.query(`SELECT a.id, a.name, a.address, p.company_name AS parent_name FROM agencies a JOIN professional_applications p ON a.parent_pro_id = p.id WHERE a.status = 'approved' ORDER BY a.created_at DESC LIMIT 3`);
      let agenciesAccueilHtml = "";
      if (agenciesAccueil.rows.length > 0) {
        agenciesAccueilHtml = `<h2 style="text-align: center; margin: 40px 0 20px 0;">🏢 Nos nouvelles agences</h2><div class="pros-grid">${agenciesAccueil.rows.map(ag => `<article class="pro-card" style="border-left: 4px solid #8b5cf6;"><div class="pro-name">${escapeHtml(ag.name)}</div><div class="pro-meta" style="color: #8b5cf6; font-weight: 700; font-size: 11px;">Réseau : ${escapeHtml(ag.parent_name || "Indépendant")}</div><div class="pro-meta">📍 ${escapeHtml(ag.address)}</div><div class="pro-actions" style="margin-top: 12px;"><a href="/agence/${ag.id}" class="button pro-profile-link" style="padding: 8px; font-size: 13px; background:#8b5cf6; color:white;">Voir l'agence →</a></div></article>`).join("")}</div>`;
      }

      const palettes = ["#d97706", "#dc2626", "#7c3aed", "#0891b2", "#db2777", "#2563eb", "#059669", "#ca8a04"];
      const prosCards = result.rows.map((person) => {
        const displayName = getDisplayName(person);
        const reviewsCount = Number(person.reviews_count || 0);
        const avgRating = Number(person.avg_rating || 0);
        let hash = 0; const key = String(person.profession); for (let i = 0; i < key.length; i++) { hash = ((hash << 5) - hash) + key.charCodeAt(i); hash = hash & hash; }
        const borderColor = palettes[Math.abs(hash) % palettes.length];
        
        let rawPhone = (person.phone || "").replace(/\D/g, ""); if (rawPhone.startsWith("00229")) rawPhone = rawPhone.substring(5); if (rawPhone.startsWith("229")) rawPhone = rawPhone.substring(3);
        const cleanPhone = rawPhone; const waNumber = /^\d{8,10}$/.test(rawPhone) ? "229" + rawPhone : null;
        let actionButtons = person.phone_public && cleanPhone ? `<a href="tel:+229${escapeHtml(cleanPhone)}" class="button" style="background:#e0e7ff; color:#1e3a8a;">📞 Appeler</a>${waNumber ? `<a href="https://wa.me/${waNumber}" target="_blank" class="button whatsapp">💬 WhatsApp</a>` : ""}` : `<a href="/contact?pro=${person.id}" class="button" style="background:#e0e7ff; color:#1e3a8a; grid-column: span 2;">📩 Contacter</a>`;

        return `
          <article class="pro-card" style="border-left: 4px solid ${borderColor}; position:relative;">
            <div class="favorite-btn ${person.is_favorite ? 'active' : ''}" onclick="toggleFav(event, ${person.id})" style="position:absolute; top:12px; right:12px; cursor:pointer;">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="${person.is_favorite ? '#ef4444' : 'none'}" stroke="${person.is_favorite ? '#ef4444' : '#6b7280'}" stroke-width="2"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"></path></svg>
            </div>
            <div class="pro-name">${escapeHtml(displayName)} ${renderKycBadge(person)}</div>
            <div class="pro-meta" style="color: ${borderColor}; font-weight: 700; font-size: 11px;">${escapeHtml(person.profession)}</div>
            <div class="pro-meta">📍 ${escapeHtml(person.city)}</div>
            <div style="margin: 8px 0;">${reviewsCount > 0 ? renderStars(avgRating) : "Pas d'avis"}</div>
            <div class="pro-actions">${actionButtons}<a href="/pro/${person.id}" class="button pro-profile-link">Voir le profil →</a></div>
          </article>`;
      }).join("");

      const content = `
        <div style="background: white; border-radius: 24px; padding: 40px 20px; margin-bottom: 40px; display: flex; flex-wrap: wrap; align-items: center; gap: 40px;">
          <div style="flex: 1 1 400px;">
            <div style="background: #eff6ff; color: #1e40af; padding: 6px 16px; border-radius: 20px; font-weight: 700; display:inline-block; margin-bottom: 20px;">Déjà ${totalAllPros} pros vérifiés</div>
            <h1 style="font-size: 38px; color: #1e3a8a;">Trouvez le professionnel <span style="color: #f59e0b;">qu'il vous faut.</span></h1>
            <a href="/recherche" class="button" style="background: #f59e0b; font-size: 18px; padding: 16px 40px; border-radius: 50px;">🔍 Rechercher un pro</a>
          </div>
          <div style="flex: 1 1 400px; position: relative; min-height: 350px;">
            <img src="https://res.cloudinary.com/gxm35ndf/image/upload/f_auto,q_auto,w_600/v1793214672/ali-mkumbwa-PxlKOcj0a3Q-unsplash_1.jpg" style="width: 85%; height: 320px; object-fit: cover; border-radius: 24px; margin-left: auto; display:block;">
            <img src="https://res.cloudinary.com/gxm35ndf/image/upload/f_auto,q_auto,w_500/v1793214724/ali-mkumbwa-1SAFRlUY0lk-unsplash.jpg" style="width: 55%; height: 220px; object-fit: cover; border-radius: 20px; position: absolute; bottom: 0px; left: 0px; border: 4px solid white;">
          </div>
        </div>
        
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; max-width: 800px; margin: 50px auto;">
          <a href="/devenir-professionnel" style="background: #2563eb; color: white; padding: 24px; border-radius: 16px; text-decoration: none; text-align: center; font-weight: 700;">👤 Devenir professionnel</a>
          <a href="/emplois" style="background: #10b981; color: white; padding: 24px; border-radius: 16px; text-decoration: none; text-align: center; font-weight: 700;">💼 Offres d'emploi</a>
        </div>

        <div class="alert alert-animated" style="text-align: center;"><strong>⚠️ ATTENTION :</strong> Ne payez jamais un professionnel avant de l'avoir rencontré.</div>
        ${agenciesAccueilHtml}
        <h2 style="text-align: center; margin: 40px 0 20px 0;">Derniers professionnels inscrits</h2>
        <div class="pros-grid">${prosCards}</div>
        ${renderPagination(currentPage, totalPages, "/")}
      `;
      res.send(page("Accueil", content, proConnected));
    } catch (error) { res.status(500).send(page("Erreur", "<h2>Une erreur technique est survenue.</h2>", null)); }
  });

  // ==========================================
  // 2. PAGE PROFIL PUBLIC (Complet avec GPS, Horaires, Similar)
  // ==========================================
  router.get("/pro/:id", async (req, res) => { 
    try {
      const proConnected = await getConnectedPro(req); const id = Number(req.params.id);
      if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/");
      const visitorId = getOrCreateVisitorId(req, res);
      pool.query(`INSERT INTO pro_stats (pro_id, date, views) VALUES ($1, CURRENT_DATE, 1) ON CONFLICT (pro_id, date) DO UPDATE SET views = pro_stats.views + 1`, [id]).catch(() => {});

      const result = await pool.query(`SELECT p.*, (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count, (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating, EXISTS(SELECT 1 FROM client_favorites cf WHERE cf.pro_id = p.id AND cf.visitor_id = $2) AS is_favorite FROM professional_applications p WHERE p.id = $1 AND p.status = 'approved'`, [id, visitorId]);
      if (!result.rows.length) return res.redirect(303, "/");
      const person = result.rows[0];
      const displayName = getDisplayName(person);

      const similarResult = await pool.query(`SELECT p.id, p.full_name, p.company_name, p.city, p.profession, (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') as avg_rating FROM professional_applications p WHERE p.status = 'approved' AND p.id != $1 AND (p.city = $2 OR p.profession = $3) ORDER BY RANDOM() LIMIT 3`, [id, person.city, person.profession]);
      const similarHtml = similarResult.rows.map(sim => `<a href="/pro/${sim.id}" class="card" style="display:block; padding:16px; text-decoration:none; margin-bottom:10px; border-left:4px solid #2563eb;"><div style="font-weight:700; color:#111827;">${escapeHtml(sim.company_name || sim.full_name)}</div><div style="font-size:13px; color:#6b7280;">${escapeHtml(sim.profession)} à ${escapeHtml(sim.city)} • ${Number(sim.avg_rating).toFixed(1)} ⭐</div></a>`).join("");

      let rawPhone = (person.phone || "").replace(/\D/g, ""); if (rawPhone.startsWith("00229")) rawPhone = rawPhone.substring(5); if (rawPhone.startsWith("229")) rawPhone = rawPhone.substring(3);
      const phoneClean = rawPhone; const whatsappNumber = /^\d{8,10}$/.test(rawPhone) ? "229" + rawPhone : null;
      
      let contactButtons = person.phone_public && phoneClean ? `<div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:16px;"><a class="button" href="tel:+229${escapeHtml(phoneClean)}" style="margin:0; background: #e0e7ff; color: #1e3a8a; font-size: 16px;">📞 Appeler</a>${whatsappNumber ? `<a class="button whatsapp" href="https://wa.me/${whatsappNumber}" target="_blank" style="margin:0; font-size: 16px;">💬 WhatsApp</a>` : `<a class="button secondary" href="/contact?pro=${person.id}" style="margin:0; font-size:16px;">📩 Contacter</a>`}</div>` : `<div class="alert alert-info">Ce professionnel a choisi de ne pas afficher son numéro.</div><div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;"><a class="button" href="/contact?pro=${person.id}" style="margin:0; background: #e0e7ff; color: #1e3a8a;">📩 Contacter</a></div>`;

      const openStatusBadge = (person.type_lieu === 'fixe' && person.est_ouvert) ? `<div style="margin-bottom: 16px;"><span class="badge" style="background:#d1fae5; color:#065f46; font-size: 14px; padding: 8px 16px;">🟢 Ouvert actuellement</span></div>` : "";
      
      let horairesHtml = "";
      if (person.horaires_json) {
        let h = {}; try { h = JSON.parse(person.horaires_json); } catch (e) { h = {}; }
        const jours = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"];
        let rows = "";
        jours.forEach(j => {
          if (h[j]) rows += `<div style="display:flex; justify-content:space-between; font-size:13px; border-bottom:1px solid #e5e7eb; padding:4px 0;"><span style="text-transform:capitalize;">${j}</span><span style="font-weight:600;">${h[j].o} - ${h[j].f}</span></div>`;
          else rows += `<div style="display:flex; justify-content:space-between; font-size:13px; border-bottom:1px solid #e5e7eb; padding:4px 0;"><span style="text-transform:capitalize;">${j}</span><span style="color:#ef4444; font-weight:600;">Fermé</span></div>`;
        });
        horairesHtml = `<div style="margin-top:12px; background:white; padding:12px; border-radius:8px;">${rows}</div>`;
      }

      const galerieData = [{ url: person.photo_galerie_1, desc: person.photo_galerie_1_desc }, { url: person.photo_galerie_2, desc: person.photo_galerie_2_desc }, { url: person.photo_galerie_3, desc: person.photo_galerie_3_desc }].filter(item => item.url);
      let galerieHtml = galerieData.length > 0 ? `<div class="card"><h2>📸 Galerie Photos</h2><div style="display:flex; gap:10px;">${galerieData.map(item => `<div style="text-align:center;"><img src="${escapeHtml(item.url)}" style="width:100px; height:100px; object-fit:cover; border-radius:8px;">${item.desc ? `<p style="font-size:12px; margin-top:4px;">${escapeHtml(item.desc)}</p>` : ""}</div>`).join("")}</div></div>` : "";

      const content = `
        <div style="max-width: 800px; margin: 0 auto;">
          <div class="card" style="padding: 32px 24px; position:relative; text-align:center;">
            <div style="margin-bottom:12px;"><a href="#" onclick="toggleFav(event, ${person.id})" class="button secondary" style="padding:8px 16px;">${person.is_favorite ? '❤️ Retirer des favoris' : '🤍 Ajouter aux favoris'}</a></div>
            ${openStatusBadge}
            <h1 style="color: #111827; font-size: 28px; margin-bottom: 6px;">${escapeHtml(displayName)} ${renderKycBadge(person, "lg")}</h1>
            <div style="color: #2563eb; font-size: 16px; font-weight: 700; text-transform: uppercase;">${escapeHtml(person.profession)}</div>
            <div style="color: #6b7280; margin-top: 8px;">📍 ${escapeHtml(person.city)}${person.neighborhood ? ` - ${escapeHtml(person.neighborhood)}` : ""}</div>
            <div style="font-size: 22px; color: #f59e0b; margin-top: 12px;">${renderStars(Number(person.avg_rating || 0))} <span style="font-size:15px; color:#6b7280;">(${person.reviews_count} avis)</span></div>
          </div>
          
          <div class="card">
            <h2>À propos</h2>
            <p style="white-space: pre-line;">${escapeHtml(person.service_description)}</p>
            ${person.type_lieu === 'fixe' ? `<div style="margin-top: 24px; background: #eff6ff; padding: 20px; border-radius: 12px;"><h3 style="font-size: 16px; margin-bottom: 8px; color: #1e3a8a;">📍 Localisation</h3><p>${person.adresse_exacte ? escapeHtml(person.adresse_exacte) : "Non spécifiée"}</p>${horairesHtml}${person.latitude && person.longitude ? `<a href="https://www.google.com/maps/search/?api=1&query=${escapeHtml(String(person.latitude))},${escapeHtml(String(person.longitude))}" target="_blank" class="button" style="background: #2563eb; width: 100%; border-radius: 8px; margin-top:12px;">🗺️ Voir l'itinéraire</a>` : ""}</div>` : ""}
            <div style="margin-top: 24px;">${contactButtons}</div>
          </div>

          ${galerieHtml}

          <div class="card" style="background: #f9fafb;">
            <h2>Avis des clients (${person.reviews_count})</h2>
            ${Number(person.reviews_count) > 0 ? `<div class="alert alert-info">${renderStars(Number(person.avg_rating))} Note moyenne</div>` : `<p>Aucun avis pour le moment.</p>`}
            <a href="/pro/${person.id}/avis" class="button warning" style="width: 100%; margin-top: 10px;">⭐ Laisser un avis</a>
          </div>

          ${similarHtml ? `<div style="margin-top: 24px;"><h2>Vous aimerez aussi...</h2>${similarHtml}</div>` : ""}
        </div>`;
      res.send(page(displayName, content, proConnected, { title: `${displayName} - ${person.profession}` }));
    } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
  });

  // ==========================================
  // 3. PAGE AGENCE & STATIQUES
  // ==========================================
  router.get("/agence/:id", async (req, res) => {
    try {
      const proConnected = await getConnectedPro(req); const id = Number(req.params.id);
      if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/");
      const result = await pool.query(`SELECT a.*, p.full_name, p.company_name, p.phone AS parent_phone, p.whatsapp_number AS parent_wa, p.phone_public, p.kyc_verified, p.profession FROM agencies a JOIN professional_applications p ON a.parent_pro_id = p.id WHERE a.id = $1 AND a.status = 'approved'`, [id]);
      if (!result.rows.length) return res.redirect(303, "/");
      const agency = result.rows[0]; const parentName = getDisplayName(agency);
      
      const displayPhone = agency.phone || agency.parent_phone; const displayWa = agency.whatsapp_number || agency.parent_wa;
      let contactButtons = "";
      if (agency.phone_public && displayPhone) {
        const cleanPhone = displayPhone.replace(/\D/g, "").replace(/^(?:00229|229)/, ""); const cleanWa = displayWa ? displayWa.replace(/\D/g, "").replace(/^(?:00229|229)/, "") : "";
        const waNumber = /^\d{8,10}$/.test(cleanWa) ? "229" + cleanWa : null;
        contactButtons = `<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 16px;"><a class="button" href="tel:+229${escapeHtml(cleanPhone)}" style="margin: 0; background: #e0e7ff; color: #1e3a8a;">📞 Appeler</a>${waNumber ? `<a class="button whatsapp" href="https://wa.me/${waNumber}" target="_blank" style="margin: 0;">💬 WhatsApp</a>` : ""}</div>`;
      }

      res.send(page(agency.name, `<div style="max-width: 800px; margin: 0 auto;"><div class="card" style="text-align:center;"><span class="badge" style="background:#8b5cf6; color:white;">🏢 Agence officielle</span><h1>${escapeHtml(agency.name)} ${renderKycBadge(agency, "lg")}</h1><div style="color: #2563eb; font-weight: bold;">Réseau : ${escapeHtml(parentName)}</div><div style="margin-top:20px; background:#eff6ff; padding:20px; border-radius:12px;"><p>${escapeHtml(agency.address)}</p>${agency.latitude ? `<a href="https://www.google.com/maps/search/?api=1&query=${agency.latitude},${agency.longitude}" target="_blank" class="button" style="background:#2563eb; width:100%; margin-top:10px;">🗺️ Itinéraire</a>` : ""}</div>${contactButtons}</div><div style="text-align:center; margin-top:24px;"><a href="/pro/${agency.parent_pro_id}" class="button secondary">← Profil de ${escapeHtml(parentName)}</a></div></div>`, proConnected, { title: agency.name }));
      pool.query(`INSERT INTO agency_stats (agency_id, date, views, last_visitor_id) VALUES ($1, CURRENT_DATE, 1, $2) ON CONFLICT (agency_id, date) DO UPDATE SET views = CASE WHEN agency_stats.last_visitor_id = $2 THEN agency_stats.views ELSE agency_stats.views + 1 END, last_visitor_id = $2`, [id, getOrCreateVisitorId(req, res)]).catch(() => {});
    } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
  });

  router.get("/a-propos", async (req, res) => res.send(page("À propos", "<h1>À propos</h1>", await getConnectedPro(req))));
  router.get("/partenariats", async (req, res) => res.send(page("Partenariats", "<h1>Partenariats</h1>", await getConnectedPro(req))));
  router.get("/conditions", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const content = `
    <section class="card" style="max-width: 800px; margin: 40px auto; padding: 30px;">
      <h1 style="font-size: 28px; color: #1e3a8a; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; margin-bottom: 20px;">Conditions Générales d'Utilisation (CGU)</h1>
      
      <p style="font-size: 14px; color: #6b7280; margin-bottom: 20px;">
        Site web : www.trouvemoi.bj<br>
        Structure : ADK Services<br>
        Dernière mise à jour : 26/10/2026
      </p>
      
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 1 : Objet</h2>
      <p>Les présentes Conditions Générales d'Utilisation (CGU) ont pour objet de définir les modalités d'accès et d'utilisation de la plateforme TrouveMoi.</p>
      <p>TrouveMoi est une plateforme numérique de mise en relation entre des clients et des professionnels (artisans, prestataires de services, etc.) au Bénin. TrouveMoi agit en tant qu'intermédiaire technique et ne fournit pas directement les services proposés par les professionnels.</p>
      
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 2 : Accès au service</h2>
      <p>L'accès à la plateforme est gratuit pour les clients qui souhaitent consulter les profils des professionnels.</p>
      <p>Pour les professionnels, l'inscription est soumise au paiement de frais d'inscription et à la validation de leur dossier (KYC) par l'équipe d'ADK Services. L'inscription ne devient effective qu'après validation du profil par l'administrateur.</p>
      
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 3 : Obligations des Utilisateurs (Clients)</h2>
      <p>En utilisant le site, le client s'engage à :</p>
      <ul style="margin-left: 20px; color: #4b5563; line-height: 1.6;">
        <li>Ne pas utiliser la plateforme à des fins frauduleuses ou illégales.</li>
        <li>Ne pas usurper l'identité d'un tiers.</li>
        <li>Faire preuve de prudence : TrouveMoi rappelle qu'il est fortement déconseillé de payer un professionnel avant de l'avoir rencontré physiquement et d'avoir évalué le travail.</li>
        <li>Respecter les professionnels contactés.</li>
      </ul>
      
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 4 : Obligations des Professionnels</h2>
      <p>En s'inscrivant, le professionnel s'engage à :</p>
      <ul style="margin-left: 20px; color: #4b5563; line-height: 1.6;">
        <li>Fournir des informations exactes et véridiques lors de son inscription (nom légal, NPI, téléphone, adresse).</li>
        <li>Fournir des documents d'identité authentiques pour la vérification KYC. Toute tentative de fraude ou d'usurpation d'identité entraînera le rejet définitif du dossier sans remboursement.</li>
        <li>Ne pas créer de faux profils ou de faux avis.</li>
        <li>Réaliser les prestations promises auprès des clients avec professionnalisme et dans le respect des lois béninoises.</li>
      </ul>
      
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 5 : Responsabilité de la plateforme</h2>
      <p>ADK Services met tout en œuvre pour vérifier l'identité des professionnels via le processus KYC. Cependant, TrouveMoi ne peut être tenu responsable :</p>
      <ul style="margin-left: 20px; color: #4b5563; line-height: 1.6;">
        <li>De la qualité, de la sécurité ou de la légalité des services fournis par les professionnels.</li>
        <li>Des litiges financiers ou commerciaux pouvant survenir entre un client et un professionnel.</li>
        <li>Des dommages directs ou indirects résultant de l'utilisation des coordonnées fournies sur la plateforme.</li>
      </ul>
      
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 6 : Avis des clients</h2>
      <p>Les clients ayant contacté un professionnel via la plateforme peuvent laisser un avis. ADK Services se réserve le droit de modérer, de masquer ou de supprimer tout avis contenant des propos injurieux, diffamatoires, ou ne respectant pas la charte de la plateforme.</p>
      
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 7 : Propriété Intellectuelle</h2>
      <p>Le code source, la structure, les logos, les textes et les graphismes de la plateforme TrouveMoi sont la propriété exclusive d'ADK Services. Toute reproduction ou utilisation non autorisée est strictement interdite.</p>
      
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 8 : Protection des Données Personnelles</h2>
      <p>Dans le cadre de l'utilisation de la plateforme, des données personnelles sont collectées (Nom, Téléphone, NPI, Photos). Le traitement de ces données est détaillé dans notre Politique de Confidentialité, accessible sur le site, et est conforme au Code du Numérique en République du Bénin et aux directives de l'APDP.</p>
      
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 9 : Suspension et Résiliation</h2>
      <p>ADK Services se réserve le droit de suspendre ou de supprimer définitivement le compte d'un utilisateur (client ou professionnel) en cas de non-respect des présentes CGU, de comportement frauduleux, de fausses déclarations, ou de non-paiement des frais d'abonnement ou d'inscription.</p>
      
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 10 : Modification des CGU</h2>
      <p>ADK Services se réserve le droit de modifier les présentes CGU à tout moment. Les utilisateurs seront informés de toute modification majeure par une notification sur le site.</p>
      
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 11 : Droit applicable et Juridiction</h2>
      <p>Les présentes CGU sont soumises au droit béninois. En cas de litige, et à défaut de résolution amiable, les tribunaux de Cotonou (Bénin) seront seuls compétents.</p>
      
      <div style="margin-top: 40px; text-align: center;">
        <button onclick="window.print()" class="button no-print" style="background: #2563eb; margin-bottom: 10px;">🖨️ Imprimer cette page</button>
        <br><a href="/" class="button secondary">← Retour à l'accueil</a>
      </div>
    </section>
  `;
  res.send(page("Conditions Générales", content, proConnected));
});
  
// PAGES LÉGALES
router.get("/mentions-legales", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const content = `
    <section class="card" style="max-width: 800px; margin: 40px auto; padding: 40px; line-height: 1.8; text-align: justify;">
      <h1 style="font-size: 26px; color: #111827; margin-bottom: 30px; font-weight: bold;">Mentions légales</h1>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">Déclaration à l'APDP</h2>
      <p style="margin-bottom: 16px; color: #374151;">
        Conformément à la loi 2017-20 portant code du numérique en République du Bénin (Livre 5ième relatif à la protection des données personnelles et de la vie privée), le site a fait l'objet d'une déclaration auprès de l'Autorité de Protection des Données Personnelles (<a href="https://www.apdp.bj" target="_blank" style="color: #2563eb; text-decoration: underline;">www.apdp.bj</a>) sous le numéro 
        <span style="font-style: italic; border-bottom: 1px dashed #6b7280; padding: 0 4px;">[ Numéro de récépissé en cours d'attribution ]</span>.
      </p>
      <p style="margin-bottom: 16px; color: #374151;">
        En tout état de cause <strong>ADK SERVICES</strong> collecte des informations personnelles relatives à l'utilisateur que pour le besoin de certains services proposés par le site <strong>trouvemoi.bj</strong>. L'utilisateur fournit ces informations en toute connaissance de cause, notamment lorsqu'il procède par lui-même à leur saisie. Conformément aux dispositions de la loi 2017-20 portant code du numérique en République du Bénin, tout utilisateur dispose d'un droit d'accès, de rectification et d'opposition aux données personnelles le concernant, en effectuant sa demande écrite et signée, accompagnée d'une copie du titre d'identité avec signature du titulaire de la pièce, en précisant l'adresse à laquelle la réponse doit être envoyée. Aucune information personnelle de l'utilisateur du site <strong>trouvemoi.bj</strong> n'est publiée à l'insu de l'utilisateur, échangée, transférée, cédée ou vendue sur un support quelconque à des tiers.
      </p>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">Droit d'accès</h2>
      <p style="margin-bottom: 16px; color: #374151;">
        En application de cette loi, les internautes disposent d'un droit d'accès, de rectification, de modification et de suppression concernant les données qui les concernent personnellement. Ce droit peut être exercé par voie postale auprès de <strong>ADK SERVICES</strong> ou par voie électronique à l'adresse email suivante : <strong>contact@trouvemoi.bj</strong>. Les informations personnelles collectées ne sont en aucun cas confiées à des tiers.
      </p>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">Confidentialité</h2>
      <p style="margin-bottom: 16px; color: #374151;">
        Vos données personnelles sont confidentielles et ne seront en aucun cas communiquées à des tiers.
      </p>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">Propriété intellectuelle</h2>
      <p style="margin-bottom: 16px; color: #374151;">
        Tout le contenu du présent site, incluant, de façon non limitative, les graphismes, images, textes, vidéos, animations, sons, logos, gifs et icônes ainsi que leur mise en forme sont la propriété exclusive de <strong>ADK SERVICES</strong> à l'exception des marques, logos ou contenus appartenant à d'autres sociétés partenaires ou auteurs.
      </p>
      <p style="margin-bottom: 16px; color: #374151;">
        Toute reproduction, distribution, modification, adaptation, retransmission ou publication, même partielle, de ces différents éléments est strictement interdite sans l'accord exprès par écrit de <strong>ADK SERVICES</strong>.
      </p>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">Conditions de service</h2>
      <p style="margin-bottom: 16px; color: #374151;">
        L'utilisation de la plateforme <strong>TrouveMoi</strong> implique l'acceptation pleine et entière des présentes conditions. Les professionnels s'engagent à fournir des informations exactes notamment lors de la vérification d'identité (KYC) et à traiter les clients avec respect. Les clients s'engagent à ne pas utiliser la plateforme à des fins frauduleuses. <strong>TrouveMoi</strong> se réserve le droit de suspendre ou supprimer tout compte ne respectant pas ces règles, ou dont le dossier KYC s'avérerait falsifié. <strong>TrouveMoi</strong> agit en tant qu'intermédiaire technique de mise en relation et ne peut être tenu responsable des litiges commerciaux entre clients et professionnels.
      </p>
      <div style="margin-top: 40px; text-align: center;" class="no-print">
        <button onclick="window.print()" class="button no-print" style="background: #2563eb; margin-bottom: 10px;">🖨️ Imprimer cette page</button>
        <br>
        <a href="/" class="button secondary">← Retour à l'accueil</a>
      </div>
    </section>
  `;
  res.send(page("Mentions Légales", content, proConnected));
});

router.get("/conditions", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const content = `
    <section class="card" style="max-width: 800px; margin: 40px auto; padding: 30px;">
      <h1 style="font-size: 28px; color: #1e3a8a; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; margin-bottom: 20px;">Conditions Générales d'Utilisation (CGU)</h1>
      <p style="font-size: 14px; color: #6b7280; margin-bottom: 20px;">Site web : www.trouvemoi.bj<br>Structure : ADK Services<br>Dernière mise à jour : 26/10/2026</p>
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 1 : Objet</h2>
      <p>Les présentes Conditions Générales d'Utilisation (CGU) ont pour objet de définir les modalités d'accès et d'utilisation de la plateforme TrouveMoi. TrouveMoi est une plateforme numérique de mise en relation entre des clients et des professionnels (artisans, prestataires de services, etc.) au Bénin. TrouveMoi agit en tant qu'intermédiaire technique et ne fournit pas directement les services proposés par les professionnels.</p>
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 2 : Accès au service</h2>
      <p>L'accès à la plateforme est gratuit pour les clients qui souhaitent consulter les profils des professionnels. Pour les professionnels, l'inscription est soumise au paiement de frais d'inscription et à la validation de leur dossier (KYC) par l'équipe d'ADK Services. L'inscription ne devient effective qu'après validation du profil par l'administrateur.</p>
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 3 : Obligations des Utilisateurs (Clients)</h2>
      <p>En utilisant le site, le client s'engage à :</p>
      <ul style="margin-left: 20px; color: #4b5563; line-height: 1.6;"><li>Ne pas utiliser la plateforme à des fins frauduleuses ou illégales.</li><li>Ne pas usurper l'identité d'un tiers.</li><li>Faire preuve de prudence : TrouveMoi rappelle qu'il est fortement déconseillé de payer un professionnel avant de l'avoir rencontré physiquement et d'avoir évalué le travail.</li><li>Respecter les professionnels contactés.</li></ul>
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 4 : Obligations des Professionnels</h2>
      <p>En s'inscrivant, le professionnel s'engage à :</p>
      <ul style="margin-left: 20px; color: #4b5563; line-height: 1.6;"><li>Fournir des informations exactes et véridiques lors de son inscription (nom légal, NPI, téléphone, adresse).</li><li>Fournir des documents d'identité authentiques pour la vérification KYC. Toute tentative de fraude ou d'usurpation d'identité entraînera le rejet définitif du dossier sans remboursement.</li><li>Ne pas créer de faux profils ou de faux avis.</li><li>Réaliser les prestations promises auprès des clients avec professionnalisme et dans le respect des lois béninoises.</li></ul>
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 5 : Responsabilité de la plateforme</h2>
      <p>ADK Services met tout en œuvre pour vérifier l'identité des professionnels via le processus KYC. Cependant, TrouveMoi ne peut être tenu responsable :</p>
      <ul style="margin-left: 20px; color: #4b5563; line-height: 1.6;"><li>De la qualité, de la sécurité ou de la légalité des services fournis par les professionnels.</li><li>Des litiges financiers ou commerciaux pouvant survenir entre un client et un professionnel.</li><li>Des dommages directs ou indirects résultant de l'utilisation des coordonnées fournies sur la plateforme.</li></ul>
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 6 : Avis des clients</h2>
      <p>Les clients ayant contacté un professionnel via la plateforme peuvent laisser un avis. ADK Services se réserve le droit de modérer, de masquer ou de supprimer tout avis contenant des propos injurieux, diffamatoires, ou ne respectant pas la charte de la plateforme.</p>
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 7 : Propriété Intellectuelle</h2>
      <p>Le code source, la structure, les logos, les textes et les graphismes de la plateforme TrouveMoi sont la propriété exclusive d'ADK Services. Toute reproduction ou utilisation non autorisée est strictement interdite.</p>
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 8 : Protection des Données Personnelles</h2>
      <p>Dans le cadre de l'utilisation de la plateforme, des données personnelles sont collectées (Nom, Téléphone, NPI, Photos). Le traitement de ces données est détaillé dans notre Politique de Confidentialité, accessible sur le site, et est conforme au Code du Numérique en République du Bénin et aux directives de l'APDP.</p>
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 9 : Suspension et Résiliation</h2>
      <p>ADK Services se réserve le droit de suspendre ou de supprimer définitivement le compte d'un utilisateur (client ou professionnel) en cas de non-respect des présentes CGU, de comportement frauduleux, de fausses déclarations, ou de non-paiement des frais d'abonnement ou d'inscription.</p>
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 10 : Modification des CGU</h2>
      <p>ADK Services se réserve le droit de modifier les présentes CGU à tout moment. Les utilisateurs seront informés de toute modification majeure par une notification sur le site.</p>
      <h2 style="font-size: 20px; color: #1e40af; margin-top: 24px;">Article 11 : Droit applicable et Juridiction</h2>
      <p>Les présentes CGU sont soumises au droit béninois. En cas de litige, et à défaut de résolution amiable, les tribunaux de Cotonou (Bénin) seront seuls compétents.</p>
      <div style="margin-top: 40px; text-align: center;"><button onclick="window.print()" class="button no-print" style="background: #2563eb; margin-bottom: 10px;">🖨️ Imprimer cette page</button><br><a href="/" class="button secondary">← Retour à l'accueil</a></div>
    </section>
  `;
  res.send(page("Conditions Générales", content, proConnected));
});
  return router;
};
