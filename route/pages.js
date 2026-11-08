const express = require('express');
const crypto = require('crypto');
bcrypt = require('bcrypt');
module.exports = function(pool, page, getConnectedPro, getOrCreateVisitorId, escapeHtml, renderStars, renderKycBadge, getDisplayName, APP_URL, cleanBeninPhone, takeRateLimit, verifyKkiapayTransaction, settlePayment, PAYMENT_AMOUNT) {
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
  // 2. PAGE DE RECHERCHE
  // ==========================================
  router.get("/recherche", async (req, res) => {
    try {
      const proConnected = await getConnectedPro(req);
      const visitorId = getOrCreateVisitorId(req, res);
      const profession = String(req.query.profession || "").trim().slice(0, 150);
      const city = String(req.query.city || "").trim().slice(0, 100);
      const category = String(req.query.category || "").trim().slice(0, 100);
      const neighborhood = String(req.query.neighborhood || "").trim().slice(0, 150);
      const sort = String(req.query.sort || "pertinence").trim();
      const hasLat = req.query.lat !== "" && req.query.lat != null; const hasLng = req.query.lng !== "" && req.query.lng != null;
      const lat = hasLat ? Number(req.query.lat) : NaN; const lng = hasLng ? Number(req.query.lng) : NaN;
      const hasCoords = Number.isFinite(lat) && Number.isFinite(lng) && Math.abs(lat) <= 90 && Math.abs(lng) <= 180;
      const isSearching = profession !== "" || city !== "" || category !== "" || neighborhood !== "";
      
      const currentPage = Math.max(1, parseInt(req.query.page) || 1); const limit = 12; const offset = (currentPage - 1) * limit;
      let result = { rows: [] }; let totalPros = 0; let totalPages = 0; let prosSection = ""; let paginationHtml = ""; let agencesSearchHtml = "";

      if (isSearching) {
        let whereClause = ` WHERE p.status = 'approved'`; const values = [];
        if (profession) { values.push(`%${profession}%`); whereClause += ` AND (p.profession ILIKE $${values.length} OR p.company_name ILIKE $${values.length} OR p.full_name ILIKE $${values.length})`; }
        if (city) { values.push(`%${city}%`); whereClause += ` AND p.city ILIKE $${values.length}`; }
        if (neighborhood) { values.push(`%${neighborhood}%`); whereClause += ` AND p.neighborhood ILIKE $${values.length}`; }
        if (category) { values.push(category); whereClause += ` AND (p.profession_category = $${values.length} OR p.profession IN (SELECT name FROM professions WHERE category = $${values.length}))`; }

        const countResult = await pool.query(`SELECT COUNT(*) FROM professional_applications p ${whereClause}`, values);
        totalPros = parseInt(countResult.rows[0].count); totalPages = Math.ceil(totalPros / limit);

        let orderBy = "p.created_at DESC";
        if (sort === "rating") orderBy = "avg_rating DESC, reviews_count DESC, p.created_at DESC";
        else if (sort === "distance" && hasCoords) orderBy = `(6371 * acos(LEAST(1, cos(radians(${lat})) * cos(radians(p.latitude)) * cos(radians(p.longitude) - radians(${lng})) + sin(radians(${lat})) * sin(radians(p.latitude))))) ASC NULLS LAST`;

        const queryValues = [...values, visitorId, limit, offset];
        const query = `SELECT p.id, p.full_name, p.company_name, p.phone, p.phone_public, p.city, p.profession, p.service_description, p.latitude, p.longitude, p.kyc_verified, (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count, (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating, EXISTS(SELECT 1 FROM client_favorites cf WHERE cf.pro_id = p.id AND cf.visitor_id = $${queryValues.length - 2}) AS is_favorite FROM professional_applications p ${whereClause} ORDER BY ${orderBy} LIMIT $${queryValues.length - 1} OFFSET $${queryValues.length}`;
        result = await pool.query(query, queryValues);

        let agenceQuery = `SELECT a.id, a.name, a.address, p.company_name AS parent_name FROM agencies a JOIN professional_applications p ON a.parent_pro_id = p.id WHERE a.status = 'approved'`;
        let agenceValues = [];
        if (profession) { agenceValues.push(`%${profession}%`); agenceQuery += ` AND (a.name ILIKE $${agenceValues.length} OR p.profession ILIKE $${agenceValues.length})`; }
        if (city) { agenceValues.push(`%${city}%`); agenceQuery += ` AND a.address ILIKE $${agenceValues.length}`; }
        agenceQuery += ` LIMIT 3`;
        const agencesSearch = await pool.query(agenceQuery, agenceValues);
        
        if (agencesSearch.rows.length > 0) {
          agencesSearchHtml = `<h2 style="text-align: center; margin: 30px 0 20px 0;">🏢 Agences correspondantes</h2><div class="pros-grid" style="margin-bottom: 40px;">${agencesSearch.rows.map(ag => `<article class="pro-card" style="border-left: 4px solid #8b5cf6;"><div class="pro-name">${escapeHtml(ag.name)}</div><div class="pro-meta" style="color: #8b5cf6;">Réseau : ${escapeHtml(ag.parent_name)}</div><div class="pro-meta">📍 ${escapeHtml(ag.address)}</div><div class="pro-actions" style="margin-top:10px;"><a href="/agence/${ag.id}" class="button" style="grid-column: span 2; background:#8b5cf6; color:white;">Voir l'agence</a></div></article>`).join("")}</div>`;
        }

        prosSection = `<div class="pros-grid" id="pros-grid">${result.rows.map(person => `<article class="pro-card"><div class="pro-name">${escapeHtml(getDisplayName(person))}</div><div class="pro-meta" style="color:#2563eb;">${escapeHtml(person.profession)}</div><div class="pro-meta">📍 ${escapeHtml(person.city)}</div><div class="pro-actions" style="margin-top:10px;"><a href="/pro/${person.id}" class="button" style="grid-column: span 2; background:#f3f4f6; color:#374151;">Voir le profil</a></div></article>`).join("")}</div>`;
        paginationHtml = renderPagination(currentPage, totalPages, "/recherche", { profession, city, category, neighborhood, sort, ...(hasCoords ? { lat, lng } : {}) });
      }

      const content = `
        <h1 style="text-align: center;">Rechercher un professionnel</h1>
        <section class="card" style="max-width: 900px; margin: 0 auto 30px auto; background: #f8fafc;">
          <form action="/recherche" method="GET" style="display: flex; flex-wrap: wrap; gap: 12px;">
            <input name="profession" value="${escapeHtml(profession)}" placeholder="Métiers ou nom..." style="flex: 1 1 200px; margin: 0; padding: 16px; border-radius: 12px;">
            <input name="city" value="${escapeHtml(city)}" placeholder="Villes..." style="flex: 1 1 200px; margin: 0; padding: 16px; border-radius: 12px;">
            <input name="neighborhood" value="${escapeHtml(neighborhood)}" placeholder="Quartier..." style="flex: 1 1 200px; margin: 0; padding: 16px; border-radius: 12px;">
            <select name="sort" id="sort-select" style="flex: 0 0 150px; margin: 0; padding: 16px; border-radius: 12px;">
              <option value="pertinence" ${sort === 'pertinence' ? 'selected' : ''}>Plus récents</option>
              <option value="rating" ${sort === 'rating' ? 'selected' : ''}>Mieux notés</option>
              <option value="distance" ${sort === 'distance' ? 'selected' : ''}>Plus proches</option>
            </select>
            <button type="button" onclick="useMyPosition()" class="button secondary" style="flex: 0 0 170px; margin: 0; padding: 16px; border-radius: 12px;">📍 Autour de moi</button>
            <button type="submit" style="flex: 0 0 120px; border-radius: 12px; padding: 16px; margin: 0; background: #f59e0b; font-weight: 800; color: white;">🔍 Filtrer</button>
            <input type="hidden" name="lat" id="lat-input" value="${hasCoords ? lat : ""}"><input type="hidden" name="lng" id="lng-input" value="${hasCoords ? lng : ""}">
          </form>
        </section>
        ${isSearching ? `<h2 style="text-align: center;">Résultats (${totalPros})</h2>${agencesSearchHtml}${prosSection}${paginationHtml}` : `<p style="text-align:center;">Entrez un métier ou une ville pour commencer.</p>`}
        <script>
          function useMyPosition() {
            if (!navigator.geolocation) { alert("Non disponible."); return; }
            navigator.geolocation.getCurrentPosition(function (position) {
              document.getElementById('lat-input').value = position.coords.latitude; document.getElementById('lng-input').value = position.coords.longitude; document.getElementById('sort-select').value = 'distance';
              document.querySelector('form[action="/recherche"]').submit();
            }, function () { alert("Impossible de vous localiser."); });
          }
        </script>
      `;
      res.send(page("Recherche", content, proConnected));
    } catch (error) { res.status(500).send(page("Erreur", "<h2>Erreur technique</h2>", null)); }
  });

  // ==========================================
  // 3. PAGE PROFIL PUBLIC
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
      
let contactButtons = person.phone_public && phoneClean ? `<div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:16px;"><a class="button" href="tel:+229${escapeHtml(phoneClean)}" onclick="fetch('/api/track/${person.id}/phone', {method:'POST', keepalive:true})" style="margin:0; background: #e0e7ff; color: #1e3a8a; font-size: 16px;">📞 Appeler</a>${whatsappNumber ? `<a class="button whatsapp" href="https://wa.me/${whatsappNumber}" onclick="fetch('/api/track/${person.id}/wa', {method:'POST', keepalive:true})" target="_blank" style="margin:0; font-size: 16px;">💬 WhatsApp</a>` : `<a class="button secondary" href="/contact?pro=${person.id}" style="margin:0; font-size:16px;">📩 Contacter</a>`}</div>` : `<div class="alert alert-info">Ce professionnel a choisi de ne pas afficher son numéro.</div><div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;"><a class="button" href="/contact?pro=${person.id}" style="margin:0; background: #e0e7ff; color: #1e3a8a;">📩 Contacter</a></div>`;
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
  // 4. PAGE AGENCE PUBLIQUE
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
        contactButtons = `<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 16px;">
  <a class="button" href="tel:+229${escapeHtml(cleanPhone)}" onclick="fetch('/api/track-agency/${agency.id}/phone', {method:'POST', keepalive:true})" style="margin: 0; background: #e0e7ff; color: #1e3a8a;">📞 Appeler</a>
${waNumber ? `<a class="button whatsapp" href="https://wa.me/${waNumber}" onclick="fetch('/api/track-agency/${agency.id}/wa', {method:'POST', keepalive:true})" target="_blank" style="margin: 0;">💬 WhatsApp</a>` : ""}
</div>`;
      }

    pool.query(`INSERT INTO agency_stats (agency_id, date, views, last_visitor_id) VALUES ($1, CURRENT_DATE, 1, $2) ON CONFLICT (agency_id, date) DO UPDATE SET views = CASE WHEN agency_stats.last_visitor_id = $2 THEN agency_stats.views ELSE agency_stats.views + 1 END, last_visitor_id = $2`, [id, getOrCreateVisitorId(req, res)]).catch(() => {});
    res.send(page(agency.name, `<div style="max-width: 800px; margin: 0 auto;"><div class="card" style="text-align:center;"><span class="badge" style="background:#8b5cf6; color:white;">🏢 Agence officielle</span><h1>${escapeHtml(agency.name)} ${renderKycBadge(agency, "lg")}</h1><div style="color: #2563eb; font-weight: bold;">Réseau : ${escapeHtml(parentName)}</div><div style="margin-top:20px; background:#eff6ff; padding:20px; border-radius:12px;"><p>${escapeHtml(agency.address)}</p>${agency.latitude ? `<a href="https://www.google.com/maps/search/?api=1&query=${agency.latitude},${agency.longitude}" target="_blank" class="button" style="background:#2563eb; width:100%; margin-top:10px;">🗺️ Itinéraire</a>` : ""}</div>${contactButtons}</div><div style="text-align:center; margin-top:24px;"><a href="/pro/${agency.parent_pro_id}" class="button secondary">← Profil de ${escapeHtml(parentName)}</a></div></div>`, proConnected, { title: agency.name }));
  } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
});

  // ==========================================
  // 5. PAGES STATIQUES
  // ==========================================
 router.get("/a-propos", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  res.send(page("À propos", `<section class="card" style="max-width: 800px; margin: 40px auto; padding: 40px; line-height: 1.8;"><h1>À propos de TrouveMoi</h1><p>TrouveMoi est la première plateforme béninoise qui met en relation directe les clients avec des professionnels vérifiés de leur quartier.</p><p>Notre mission est de valoriser le savoir-faire local tout en garantissant aux clients des prestations de qualité, en toute confiance.</p></section>`, proConnected));
});

router.get("/partenariats", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  res.send(page("Partenariats", `<section class="card" style="max-width: 800px; margin: 40px auto; padding: 40px; line-height: 1.8;"><h1>Partenariats</h1><p>Vous souhaitez collaborer avec TrouveMoi ? Contactez-nous à <strong>contact@trouvemoi.bj</strong>.</p></section>`, proConnected));
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

router.get("/mentions-legales", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const content = `
    <section class="card" style="max-width: 800px; margin: 40px auto; padding: 40px; line-height: 1.8; text-align: justify;">
      <h1 style="font-size: 26px; color: #111827; margin-bottom: 30px; font-weight: bold;">Mentions légales</h1>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">Déclaration à l'APDP</h2>
      <p style="margin-bottom: 16px; color: #374151;">Conformément à la loi 2017-20 portant code du numérique en République du Bénin (Livre 5ième relatif à la protection des données personnelles et de la vie privée), le site a fait l'objet d'une déclaration auprès de l'Autorité de Protection des Données Personnelles (<a href="https://www.apdp.bj" target="_blank" style="color: #2563eb; text-decoration: underline;">www.apdp.bj</a>) sous le numéro <span style="font-style: italic; border-bottom: 1px dashed #6b7280; padding: 0 4px;">[ Numéro de récépissé en cours d'attribution ]</span>.</p>
      <p style="margin-bottom: 16px; color: #374151;">En tout état de cause <strong>ADK SERVICES</strong> collecte des informations personnelles relatives à l'utilisateur que pour le besoin de certains services proposés par le site <strong>trouvemoi.bj</strong>. L'utilisateur fournit ces informations en toute connaissance de cause, notamment lorsqu'il procède par lui-même à leur saisie. Conformément aux dispositions de la loi 2017-20 portant code du numérique en République du Bénin, tout utilisateur dispose d'un droit d'accès, de rectification et d'opposition aux données personnelles le concernant, en effectuant sa demande écrite et signée, accompagnée d'une copie du titre d'identité avec signature du titulaire de la pièce, en précisant l'adresse à laquelle la réponse doit être envoyée. Aucune information personnelle de l'utilisateur du site <strong>trouvemoi.bj</strong> n'est publiée à l'insu de l'utilisateur, échangée, transférée, cédée ou vendue sur un support quelconque à des tiers.</p>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">Droit d'accès</h2>
      <p style="margin-bottom: 16px; color: #374151;">En application de cette loi, les internautes disposent d'un droit d'accès, de rectification, de modification et de suppression concernant les données qui les concernent personnellement. Ce droit peut être exercé par voie postale auprès de <strong>ADK SERVICES</strong> ou par voie électronique à l'adresse email suivante : <strong>contact@trouvemoi.bj</strong>. Les informations personnelles collectées ne sont en aucun cas confiées à des tiers.</p>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">Confidentialité</h2>
      <p style="margin-bottom: 16px; color: #374151;">Vos données personnelles sont confidentielles et ne seront en aucun cas communiquées à des tiers.</p>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">Propriété intellectuelle</h2>
      <p style="margin-bottom: 16px; color: #374151;">Tout le contenu du présent site, incluant, de façon non limitative, les graphismes, images, textes, vidéos, animations, sons, logos, gifs et icônes ainsi que leur mise en forme sont la propriété exclusive de <strong>ADK SERVICES</strong> à l'exception des marques, logos ou contenus appartenant à d'autres sociétés partenaires ou auteurs.</p>
      <p style="margin-bottom: 16px; color: #374151;">Toute reproduction, distribution, modification, adaptation, retransmission ou publication, même partielle, de ces différents éléments est strictement interdite sans l'accord exprès par écrit de <strong>ADK SERVICES</strong>.</p>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">Conditions de service</h2>
      <p style="margin-bottom: 16px; color: #374151;">L'utilisation de la plateforme <strong>TrouveMoi</strong> implique l'acceptation pleine et entière des présentes conditions. Les professionnels s'engagent à fournir des informations exactes notamment lors de la vérification d'identité (KYC) et à traiter les clients avec respect. Les clients s'engagent à ne pas utiliser la plateforme à des fins frauduleuses. <strong>TrouveMoi</strong> se réserve le droit de suspendre ou supprimer tout compte ne respectant pas ces règles, ou dont le dossier KYC s'avérerait falsifié. <strong>TrouveMoi</strong> agit en tant qu'intermédiaire technique de mise en relation et ne peut être tenu responsable des litiges commerciaux entre clients et professionnels.</p>
      <div style="margin-top: 40px; text-align: center;" class="no-print"><button onclick="window.print()" class="button no-print" style="background: #2563eb; margin-bottom: 10px;">🖨️ Imprimer cette page</button><br><a href="/" class="button secondary">← Retour à l'accueil</a></div>
    </section>
  `;
  res.send(page("Mentions Légales", content, proConnected));
});

router.get("/confidentialite", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const content = `
    <section class="card" style="max-width: 800px; margin: 40px auto; padding: 40px; line-height: 1.8; text-align: justify;">
      <h1 style="font-size: 26px; color: #111827; margin-bottom: 30px; font-weight: bold; text-align: center;">Politique de Confidentialité des Données Personnelles</h1>
      <p style="margin-bottom: 16px; color: #374151;">La présente politique de confidentialité est fondée sur l'article 415 figurant au livre cinquième du code du numérique relatif à la Protection des Données à caractère personnelle.</p>
      <p style="margin-bottom: 16px; color: #374151;">Elle mentionne la preuve de l'accomplissement des formalités préalables auprès de l'Autorité de Protection des Données Personnelles (APDP) et vous aide à comprendre quelles informations nous collectons et traitons dans notre structure <strong>ADK SERVICES</strong>, les données personnelles, les finalités visées ainsi que la politique de management mise en place aux fins de respecter la législation en vigueur en matière de protection des données personnelles et de la vie privée en République du Bénin.</p>
      <p style="margin-bottom: 24px; color: #374151; font-weight: 500;">Veuillez lire attentivement cette Politique de confidentialité qui nous engage.</p>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">1. Responsable du traitement</h2>
      <p style="margin-bottom: 16px; color: #374151;">Le responsable du traitement de vos Données Personnelles est la structure <strong>ADK SERVICES</strong>, éditrice de la plateforme TrouveMoi.<br>Adresse email : <strong>contact@trouvemoi.bj</strong></p>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">2. Formalités préalables</h2>
      <p style="margin-bottom: 16px; color: #374151;">Le traitement est poursuivi conformément au Récépissé n° <span style="font-style: italic; border-bottom: 1px dashed #6b7280; padding: 0 4px;">[Numéro en cours d'attribution]</span> délivré par l'Autorité de Protection des données Personnelles (APDP).</p>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">3. Les données personnelles objet du traitement</h2>
      <p style="margin-bottom: 16px; color: #374151;">Les données traitées sont : Nom, prénom, numéro de téléphone, adresse mail, NPI, photo d'identité, carte d'identité, photo d'identité KYC et adresse géographique (ville et quartier).</p>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">4. Les opérations effectuées</h2>
      <p style="margin-bottom: 16px; color: #374151;">ADK SERVICES ne collecte des informations personnelles relatives des clients et des professionnels de métiers que pour le besoin exclusif de services proposés par elle-même. Les informations recueillies font l'objet des opérations suivantes (traitement électronique) destiné à l'atteinte des finalités ci-dessous mentionnées. Les données sont conservées dans des infrastructures sécurisées.</p>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">5. La/les finalité(s) du/des traitement(s)</h2>
      <p style="margin-bottom: 8px; color: #374151;">Les informations sont collectées pour :</p>
      <ol style="margin-left: 20px; color: #374151; margin-bottom: 16px;"><li>La mise en relation entre les clients et les professionnels</li><li>La vérification d'identité des professionnels (KYC) pour éviter les arnaques</li><li>La gestion des paiements et des abonnements</li><li>L'envoi de notifications par SMS</li></ol>
      <p style="margin-bottom: 16px; color: #374151;">Il convient de rappeler que chaque traitement correspond à une finalité précise et unique. Dans l'hypothèse où un seul et même traitement pourrait servir plusieurs finalités, votre consentement sera recueilli distinctement pour chacune d'elles.</p>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">6. Destinataires des Données personnelles communication et transfert</h2>
      <p style="margin-bottom: 8px; color: #374151;">Les destinataires de ces données sont les services internes suivants :</p>
      <ol style="margin-left: 20px; color: #374151; margin-bottom: 16px;"><li>Direction des traitements de données : ADK SERVICES</li><li>Secrétariat Administratif : Support Client TrouveMoi</li><li>Service Informatique : Administrateur Technique</li></ol>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">7. Durée du traitement, conservation et stockage</h2>
      <p style="margin-bottom: 16px; color: #374151;">Les Données Personnelles sont traitées par nos soins pendant (toute la durée de vie du compte de l'utilisateur, et supprimées immédiatement en cas de demande de suppression par l'utilisateur).<br>Pour plus d'informations concernant les durées de conservation, vous pouvez nous contacter à l'adresse mail suivante : <strong>contact@trouvemoi.bj</strong>.<br>Après la durée ci-dessus mentionnée, vos données sont supprimées.</p>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">8. Les droits des personnes concernées à propos des traitements</h2>
      <p style="margin-bottom: 8px; color: #374151;">La loi vous donne sur vos données personnelles les droits suivants :</p>
      <ol style="margin-left: 20px; color: #374151; margin-bottom: 16px;"><li>Droit d'accès aux informations collectées ;</li><li>Droit d'interrogation ;</li><li>Droit de modification ;</li><li>Droit de rectification ;</li><li>Droit à la portabilité ;</li><li>Droit d'opposition au traitement ;</li><li>Droit de suppression de données ;</li><li>Droit à l'oubli ;</li><li>Droit à réparation.</li></ol>
      <p style="margin-bottom: 16px; color: #374151;">Vous pouvez consulter la définition de ces droits à l'adresse de l'APDP. Vous pouvez exercer vos droits en écrivant à ADK SERVICES par e-mail à l'adresse suivante :<br>- email : <strong>contact@trouvemoi.bj</strong></p>
      <p style="margin-bottom: 16px; color: #374151;">Nous garantissons une réponse à vos demandes dans un délai de 30 jours à compter de la date de réception de la demande.</p>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">9. Plaintes</h2>
      <p style="margin-bottom: 8px; color: #374151;">Vous avez le droit de déposer une plainte auprès de l'Autorité de Protection des Données Personnelles :</p>
      <ol style="margin-left: 20px; color: #374151; margin-bottom: 16px;"><li>La plainte est déposée au siège de l'institution Rue 6.076 Aïdjèdo Cotonou</li><li>Adressée (mail uniquement) à l'adresse : contact@apdp.bj</li></ol>
      <p style="margin-bottom: 16px; color: #374151;">Ceci est sans préjudice d'un recours devant un tribunal compétent.</p>
      <h2 style="font-size: 18px; color: #111827; margin-top: 24px; margin-bottom: 12px; font-weight: bold;">10. Pour en savoir plus</h2>
      <p style="margin-bottom: 16px; color: #374151;">Si vous avez d'autres questions ou commentaires concernant le traitement de vos données personnelles, n'hésitez pas à contacter le Délégué à la Protection des Données Personnelles par e-mail à : <strong>contact@trouvemoi.bj</strong></p>
      <p style="font-size: 14px; color: #6b7280; margin-top: 30px;">Date de dernière mise à jour : 31/10/2026</p>
      <div style="margin-top: 40px; text-align: center;" class="no-print"><button onclick="window.print()" class="button no-print" style="background: #2563eb; margin-bottom: 10px;">🖨️ Imprimer cette page</button><br><a href="/" class="button secondary">← Retour à l'accueil</a></div>
    </section>
  `;
  res.send(page("Politique de Confidentialité", content, proConnected));
});
  // ==========================================
  // 6. BLOG
  // ==========================================
  router.get("/blog", async (req, res) => {
    try {
      const proConnected = await getConnectedPro(req);
      const articles = (await pool.query(`SELECT * FROM blog_posts WHERE published = true ORDER BY created_at DESC`)).rows;
      const list = articles.map(a => `<article class="card" style="margin-bottom:20px;"><h2 style="font-size:20px;"><a href="/blog/${a.slug}" style="text-decoration:none; color:#1e40af;">${escapeHtml(a.title)}</a></h2><p class="muted" style="font-size:13px;">Publié le ${new Date(a.created_at).toLocaleDateString("fr-FR")}</p><p style="margin-top:10px; color:#4b5563;">${escapeHtml(a.content).slice(0, 200)}...</p></article>`).join("");
      res.send(page("Blog", `<h1 style="text-align:center; margin-bottom:30px;">Le Blog de TrouveMoi</h1><div style="max-width:800px; margin:0 auto;">${list || '<p style="text-align:center; color:#6b7280; font-style:italic;">Aucun article pour le moment.</p>'}</div>`, proConnected));
    } catch (error) {
      res.status(500).send(page("Erreur", "<h2>Le blog est indisponible.</h2>", null));
    }
  });

  router.get("/blog/:slug", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    const article = (await pool.query(`SELECT * FROM blog_posts WHERE slug = $1 AND published = true`, [req.params.slug])).rows[0];
    if (!article) return res.redirect(303, "/blog");
    res.send(page(article.title, `<article class="card" style="max-width:800px; margin:40px auto;"><h1 style="font-size:28px;">${escapeHtml(article.title)}</h1><p class="muted" style="font-size:13px; margin-bottom:20px;">Publié le ${new Date(article.created_at).toLocaleDateString("fr-FR")}</p><div style="line-height:1.8; color:#374151;">${escapeHtml(article.content).replace(/\n/g, "<br>")}</div><p style="margin-top:30px;"><a href="/blog" style="color:#2563eb;">← Retour au blog</a></p></article>`, proConnected));
  });
// ==========================================
// 7. FAVORIS ET COMPTE CLIENT
// ==========================================

// A. Ajouter/Retirer un favori
router.post("/api/favorite/:id", async (req, res) => {
  try {
    const visitorId = getOrCreateVisitorId(req, res);
    const proId = Number(req.params.id);
    if (!Number.isSafeInteger(proId) || proId < 1) return res.json({ ok: false });

    const check = await pool.query("SELECT 1 FROM client_favorites WHERE visitor_id = $1 AND pro_id = $2", [visitorId, proId]);
    if (check.rows.length) {
      await pool.query("DELETE FROM client_favorites WHERE visitor_id = $1 AND pro_id = $2", [visitorId, proId]);
      res.json({ ok: true, isFav: false });
    } else {
      await pool.query("INSERT INTO client_favorites (visitor_id, pro_id) VALUES ($1, $2)", [visitorId, proId]);
      res.json({ ok: true, isFav: true });
    }
  } catch (e) { res.json({ ok: false }); }
});

// B. Page Mes Favoris
router.get("/mes-favoris", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const visitorId = getOrCreateVisitorId(req, res);
  
  const result = await pool.query(`
    SELECT p.*, 
    (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count, 
    (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating 
    FROM professional_applications p 
    JOIN client_favorites cf ON p.id = cf.pro_id 
    WHERE cf.visitor_id = $1 AND p.status = 'approved'
    ORDER BY cf.created_at DESC
  `, [visitorId]);

  const cards = result.rows.map(person => {
    const displayName = getDisplayName(person);
    return `
      <article class="pro-card" style="border-left: 4px solid #ef4444;">
        <div class="favorite-btn active" onclick="toggleFav(event, ${person.id}).then(() => location.reload())" style="top: 12px; right: 12px; width: 30px; height: 30px;">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="#ef4444" stroke="#ef4444" stroke-width="2"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"></path></svg>
        </div>
        <div class="pro-card-top">
          <div>
            <div class="pro-name">${escapeHtml(displayName)} ${renderKycBadge(person)}</div>
            <div class="pro-meta">${escapeHtml(person.profession)}</div>
            <div class="pro-meta">📍 ${escapeHtml(person.city)}</div>
          </div>
        </div>
        <div class="pro-actions" style="margin-top: 12px; gap: 4px;">
          <a href="/pro/${person.id}" class="button pro-profile-link" style="padding: 6px; font-size: 11px;">Voir le profil →</a>
        </div>
      </article>
    `;
  }).join("");

  res.send(page("Mes Favoris", `
    <div style="text-align: center; margin-bottom: 30px;">
      <h1>❤️ Mes Favoris</h1>
      <div class="alert alert-info" style="text-align:center; margin-bottom:20px;">
  💡 <strong>Astuce :</strong> Créez un compte gratuit pour retrouver vos favoris sur tous vos appareils. 
  <a href="/mon-compte" style="font-weight:bold; text-decoration:underline;">Créer un compte</a>
</div>
      <a href="/" style="color: #6b7280; font-size: 14px;">← Retour à l'accueil</a>
    </div>
    <div class="pros-grid">
      ${cards || `<div class="card"><p style="text-align:center;">Vous n'avez pas encore de favoris. Cliquez sur le cœur d'un professionnel pour le sauvegarder ici.</p></div>`}
    </div>
  `, proConnected));
});

// C. Page Mon Compte (Portail avec Connexion / Inscription)
router.get("/mon-compte", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const visitorId = getOrCreateVisitorId(req, res);
  
  const clientResult = await pool.query(`SELECT * FROM client_codes WHERE visitor_id = $1`, [visitorId]);
  const client = clientResult.rows[0];
  const isConnected = client && client.phone;

  const favorites = await pool.query(`SELECT COUNT(*) FROM client_favorites WHERE visitor_id = $1`, [visitorId]);
  const count = Number(favorites.rows[0]?.count || 0);

  let content = "";

  if (isConnected) {
    const code = await getOrCreateClientCode(visitorId);
    content = `
      <h2 style="text-align:center;">Bonjour ${escapeHtml(client.full_name)}</h2>
      <p style="font-size:14px; color:#4b5563; text-align:center;">Votre code de récupération secret :</p>
      <div class="pro-code-box" style="margin: 20px 0;">
        <div style="font-size:12px; text-transform:uppercase; letter-spacing:1px; opacity:0.85;">Votre code</div>
        <div class="pro-code-value" style="font-size:36px; letter-spacing: 5px;">${escapeHtml(code || "Indisponible")}</div>
      </div>
      <p style="font-size:14px; text-align:center;"><strong>${count}</strong> favori(s) enregistré(s).</p>
      <div style="text-align:center; margin:16px 0;"><a class="button" href="/mes-favoris">❤️ Voir mes favoris</a></div>
      <hr style="border:none; border-top:1px solid #e5e7eb; margin:24px 0;">
      <div style="text-align:center;"><a href="/mon-compte/deconnexion" style="color:#ef4444; font-size:13px;">Se déconnecter de cet appareil</a></div>
    `;
  } else {
    content = `
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px;">
        
        <!-- CONNEXION -->
        <div style="background:#f8fafc; padding:20px; border-radius:12px; border:1px solid #e2e8f0;">
          <h2 style="font-size:18px; text-align:center; margin-bottom:15px;">🔑 Se connecter</h2>
          <form action="/mon-compte/connexion-code" method="POST">
            <label>Téléphone</label>
            <input name="phone" type="tel" required pattern="01[0-9]{8}" placeholder="0100000000" style="text-align:center;">
            <label>Mot de passe</label>
            <input name="password" type="password" required placeholder="Votre mot de passe">
            <button type="submit" style="width:100%; margin-top:10px;">Se connecter</button>
          </form>
        </div>

        <!-- INSCRIPTION -->
        <div style="background:#eff6ff; padding:20px; border-radius:12px; border:1px solid #bfdbfe;">
          <h2 style="font-size:18px; text-align:center; margin-bottom:15px;">✨ Créer un compte</h2>
          <form action="/mon-compte/enregistrer" method="POST">
            <label>Nom complet</label>
            <input name="full_name" required maxlength="150" placeholder="Ex: Jean Dupont">
            <label>Téléphone</label>
            <input name="phone" type="tel" required pattern="01[0-9]{8}" placeholder="0100000000">
            <label>Mot de passe</label>
            <input name="password" type="password" required minlength="6" placeholder="Au moins 6 caractères">
            <label>Confirmer le mot de passe</label>
            <input name="password_confirm" type="password" required minlength="6" placeholder="Retapez le mot de passe">
            <button type="submit" class="success" style="width:100%; margin-top:10px;">Créer mon compte</button>
          </form>
        </div>
        
      </div>
    `;
  }

  res.send(page("Mon compte", `<section class="card" style="max-width: 800px; margin: 40px auto;">${content}</section>`, proConnected));
});

// D. Créer un compte client (avec mot de passe sécurisé)
router.post("/mon-compte/enregistrer", async (req, res) => {
  const visitorId = getOrCreateVisitorId(req, res);
  const fullName = String(req.body.full_name || "").trim().slice(0, 150);
  const phone = cleanBeninPhone(req.body.phone);
  const password = String(req.body.password || "");
  const passwordConfirm = String(req.body.password_confirm || "");

  if (!fullName || !phone || password.length < 6) return res.redirect(303, "/mon-compte");
  if (password !== passwordConfirm) return res.status(400).send(page("Erreur", "<h2>Les mots de passe ne correspondent pas.</h2><a href='/mon-compte'>Retour</a>", null));

  try {
    // Sécurité maximale avec bcrypt (12 tours = très sécurisé)
    const passwordHash = await bcrypt.hash(password, 12);

    // On vérifie si le numéro existe déjà
    const existing = await pool.query(`SELECT id FROM client_codes WHERE phone = $1`, [phone]);
    if (existing.rows.length) return res.status(400).send(page("Erreur", "<h2>Ce numéro a déjà un compte.</h2><a href='/mon-compte'>Se connecter</a>", null));

    const code = await getOrCreateClientCode(visitorId);
    await pool.query(`UPDATE client_codes SET full_name = $1, phone = $2, password_hash = $3 WHERE visitor_id = $4`, [fullName, phone, passwordHash, visitorId]);
    res.redirect(303, "/mon-compte");
  } catch (error) { res.redirect(303, "/mon-compte"); }
});

// E. Se connecter avec téléphone + mot de passe (Sécurisé)
router.post("/mon-compte/connexion-code", async (req, res) => {
  const phone = cleanBeninPhone(req.body.phone);
  const password = String(req.body.password || "");
  const visitorId = getOrCreateVisitorId(req, res);

  if (!phone || !password) return res.redirect(303, "/mon-compte");

  try {
    const result = await pool.query(`SELECT id, visitor_id, password_hash FROM client_codes WHERE phone = $1`, [phone]);
    if (!result.rows.length) return res.status(404).send(page("Erreur", "<h2>Numéro ou mot de passe incorrect.</h2><a href='/mon-compte'>Retour</a>", null));
    
    const client = result.rows[0];
    if (!client.password_hash) return res.status(400).send(page("Erreur", "<h2>Ce compte n'a pas encore de mot de passe.</h2><a href='/mon-compte'>Retour</a>", null));

    const match = await bcrypt.compare(password, client.password_hash);
    
    if (!match) return res.status(401).send(page("Erreur", "<h2>Numéro ou mot de passe incorrect.</h2><a href='/mon-compte'>Retour</a>", null));

    // On fusionne proprement : l'ancien visiteur prend le nouveau cookie
    if (client.visitor_id !== visitorId) {
        // On supprime l'ancien profil visiteur temporaire s'il existe
        await pool.query(`DELETE FROM client_codes WHERE visitor_id = $1 AND phone IS NULL`, [visitorId]);
        // On lie le compte au nouvel appareil
        await pool.query(`UPDATE client_codes SET visitor_id = $1 WHERE id = $2`, [visitorId, client.id]);
    }
    
    res.redirect(303, "/mon-compte");
  } catch (error) { res.redirect(303, "/mon-compte"); }
});
// F. Réinitialiser le code par SMS
router.post("/mon-compte/reinitialiser", async (req, res) => {
  const phone = cleanBeninPhone(req.body.phone);
  if (!phone) return res.redirect(303, "/mon-compte");
  
  // Note: On ne fait pas le vrai SMS ici (Termii n'est pas configuré), 
  // on affiche juste un message pour l'instant.
  res.send(page("SMS", `<section class="card" style="max-width: 500px; margin: 40px auto; text-align:center;"><h1>📩 SMS envoyé</h1><p>Si un compte est associé à ce numéro, vous recevrez votre code.</p><a href="/mon-compte" class="button">Retour</a></section>`, null));
});
  // ==========================================
// PAGE POUR LAISSER UN AVIS
// ==========================================
router.get("/pro/:id/avis", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/");

  const result = await pool.query(`SELECT id, full_name, company_name, profession FROM professional_applications WHERE id = $1 AND status = 'approved'`, [id]);
  if (!result.rows.length) return res.redirect(303, "/");
  const person = result.rows[0];
  const displayName = person.company_name?.trim() || person.full_name || "";

  res.send(page("Laisser un avis", `
    <section class="card" style="max-width: 600px; margin: 40px auto;">
      <h1 style="text-align:center;">Laisser un avis</h1>
      <div class="alert alert-info" style="text-align:center;">
        ⭐ Avis sur <strong>${escapeHtml(displayName)}</strong> (${escapeHtml(person.profession)}).
      </div>
      <form action="/pro/${person.id}/avis" method="POST">
        <label>Votre nom *</label>
        <input name="author_name" required maxlength="100">
        
        <label>Note *</label>
        <div class="star-rating-input">
          <input type="radio" id="s5" name="rating" value="5" required><label for="s5">★</label>
          <input type="radio" id="s4" name="rating" value="4"><label for="s4">★</label>
          <input type="radio" id="s3" name="rating" value="3"><label for="s3">★</label>
          <input type="radio" id="s2" name="rating" value="2"><label for="s2">★</label>
          <input type="radio" id="s1" name="rating" value="1"><label for="s1">★</label>
        </div>
        
        <label>Commentaire</label>
        <textarea name="comment" rows="4" maxlength="3000"></textarea>
        
        <div style="text-align:center; margin-top:20px;">
          <button type="submit">Envoyer</button>
          <a class="button secondary" href="/pro/${person.id}">Annuler</a>
        </div>
      </form>
    </section>
  `, proConnected));
});
  // ==========================================
// ENREGISTREMENT D'UN AVIS (POST)
// ==========================================
router.post("/pro/:id/avis", async (req, res) => {
  try {
    const proId = Number(req.params.id);
    const visitorId = getOrCreateVisitorId(req, res);
    if (!Number.isSafeInteger(proId) || proId < 1) return res.redirect(303, "/");
    
    const check = await pool.query(`SELECT id FROM professional_applications WHERE id = $1 AND status = 'approved'`, [proId]);
    if (!check.rows.length) return res.redirect(303, "/");

    // On vérifie que le client a bien contacté le pro (via Appel/WhatsApp) ces 30 derniers jours
    const contactProof = await pool.query(`
      SELECT 1 FROM contact_events
       WHERE pro_id = $1 AND visitor_id = $2 AND created_at >= NOW() - INTERVAL '30 days'
       UNION ALL
      SELECT 1 FROM pro_stats
       WHERE pro_id = $1 AND last_visitor_id = $2
         AND (phone_clicks > 0 OR wa_clicks > 0)
         AND date >= CURRENT_DATE - INTERVAL '30 days'
       LIMIT 1
    `, [proId, visitorId]);
    
    if (contactProof.rows.length === 0) {
      return res.status(403).send(page("Preuve de contact requise", `<section class="card" style="max-width: 600px; margin: 40px auto; text-align: center;"><h1 style="color:#ef4444;">🔒 Preuve de contact requise</h1><p>Pour garantir l'authenticité des avis, seuls les clients ayant contacté ce professionnel via TrouveMoi (Appel ou WhatsApp) dans les 30 derniers jours peuvent laisser un avis.</p><a class="button" href="/pro/${proId}" style="margin-top:20px;">Retour au profil</a></section>`, null));
    }

    const ratingNum = Number(req.body.rating);
    if (!Number.isInteger(ratingNum) || ratingNum < 1 || ratingNum > 5) {
      return res.status(400).send(page("Erreur", "<h2>Note invalide (1 a 5).</h2>", null));
    }
    const author = String(req.body.author_name || "").trim().slice(0, 100);
    if (!author) return res.status(400).send(page("Erreur", "<h2>Nom requis.</h2>", null));
    const comment = String(req.body.comment || "").slice(0, 3000);

    const alreadyReviewed = await pool.query(`SELECT id FROM reviews WHERE pro_id = $1 AND visitor_id = $2 LIMIT 1`, [proId, visitorId]);
    if (alreadyReviewed.rows.length) {
      return res.status(409).send(page("Avis deja depose", `<section class="card" style="max-width: 600px; margin: 40px auto; text-align:center;"><h1>✅ Avis deja enregistre</h1><p>Vous avez deja laisse un avis sur ce professionnel. Merci !</p><a class="button" href="/pro/${proId}">Retour au profil</a></section>`, null));
    }

    try {
      await pool.query(`INSERT INTO reviews (pro_id, author_name, rating, comment, status, visitor_id) VALUES ($1, $2, $3, $4, 'pending', $5)`, [proId, author, ratingNum, comment, visitorId]);
    } catch (insertError) {
      if (insertError.code === "23505") {
        return res.status(409).send(page("Avis deja depose", `<section class="card" style="max-width: 600px; margin: 40px auto; text-align:center;"><h1>✅ Avis deja enregistre</h1><a class="button" href="/pro/${proId}">Retour au profil</a></section>`, null));
      }
      throw insertError;
    }

    res.send(page("Succes", `<section class='card' style='text-align:center; max-width: 500px; margin: 40px auto;'><h1>Merci !</h1><p>Votre avis sera examine par notre equipe avant publication.</p><a class='button' href='/pro/${proId}'>Retour au profil</a></section>`, null));
  } catch (e) { 
    res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); 
  }
});
  // ==========================================
// TRACKING DES CLICS (Appels & WhatsApp)
// ==========================================
router.post("/api/track/:id/:type", async (req, res) => {
  try {
    const id = Number(req.params.id);
    const type = req.params.type;
    const visitorId = getOrCreateVisitorId(req, res);
    if (!Number.isSafeInteger(id) || id < 1) return res.json({ ok: false });
    
    let col = "";
    if (type === "phone") col = "phone_clicks";
    else if (type === "wa") col = "wa_clicks";
    else return res.json({ ok: false });

    // 1. Mise à jour des stats
    await pool.query(`INSERT INTO pro_stats (pro_id, date, ${col}, last_visitor_id) VALUES ($1, CURRENT_DATE, 1, $2) ON CONFLICT (pro_id, date) DO UPDATE SET ${col} = pro_stats.${col} + 1, last_visitor_id = $2`, [id, visitorId]);

    // 2. Enregistrement de la preuve de contact (pour les avis)
    await pool.query(`INSERT INTO contact_events (pro_id, visitor_id, type) VALUES ($1, $2, $3)`, [id, visitorId, type]);

    res.json({ ok: true });
  } catch (e) { 
    console.error("Erreur tracking :", e.message);
    res.json({ ok: false }); 
  }
});
  // ==========================================
// ROUTES AJOUTÉES POUR RÉPARER LES BUGS
// ==========================================

// 1. Déconnexion du compte client
router.get("/mon-compte/deconnexion", (req, res) => {
  res.append("Set-Cookie", `tm_visitor_id=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
  res.redirect(303, "/mon-compte");
});

// 2. API pour remplir la liste des quartiers (formulaire pro)
router.get("/api/neighborhoods", async (req, res) => {
  try {
    const city = String(req.query.city || "").trim();
    if (!city) return res.json({ neighborhoods: [] });
    
    // On cherche les quartiers existants en base pour cette ville
    const result = await pool.query(
      `SELECT DISTINCT neighborhood FROM professional_applications WHERE city = $1 AND neighborhood IS NOT NULL AND neighborhood != '' ORDER BY neighborhood ASC LIMIT 50`, 
      [city]
    );
    
    const neighborhoods = result.rows.map(r => r.neighborhood);
    res.json({ neighborhoods });
  } catch (e) {
    res.json({ neighborhoods: [] });
  }
});

// 3. Formulaire de demande de retrait (Espace Pro)
router.post("/mon-espace-pro/demander-retrait", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  if (!proConnected) return res.redirect(303, "/mon-espace-pro");

  const amount = Number(req.body.amount);
  const phoneNumber = cleanBeninPhone(req.body.phone_number);

  // Sécurité : on vérifie que le montant est valide et qu'il y a assez d'argent
  if (!phoneNumber || isNaN(amount) || amount < 1000) {
    return res.status(400).send(page("Erreur", "<h2>Montant ou numéro invalide (minimum 1000 FCFA).</h2>", proConnected));
  }

  if (amount > Number(proConnected.pro.referral_balance)) {
    return res.status(400).send(page("Erreur", "<h2>Solde insuffisant.</h2>", proConnected));
  }

  try {
    // 1. On déduit l'argent du solde du pro (pour éviter qu'il ne le dépense deux fois)
    await pool.query(`UPDATE professional_applications SET referral_balance = referral_balance - $1 WHERE id = $2`, [amount, proConnected.pro.id]);
    
    // 2. On enregistre la demande pour que l'admin la valide
    await pool.query(`INSERT INTO withdrawal_requests (pro_id, amount, phone_number, status) VALUES ($1, $2, $3, 'pending')`, [proConnected.pro.id, amount, phoneNumber]);
    
    res.redirect(303, "/mon-espace-pro");
  } catch (e) {
    res.status(500).send(page("Erreur", "<h2>Erreur lors de la demande de retrait.</h2>", proConnected));
  }
});
  // ==========================================
// 4. PAGE DE PAIEMENT (Kkiapay)
// ==========================================
router.get("/paiement/:trackingCode", async (req, res) => {
  const proConnected = await getConnectedPro(req);
  const trackingCode = String(req.params.trackingCode || "").trim();
  
  // On vérifie que le dossier existe bien
  const result = await pool.query(`SELECT id, full_name, payment_status FROM professional_applications WHERE tracking_code = $1`, [trackingCode]);
  if (!result.rows.length) return res.redirect(303, "/");
  
  const dossier = result.rows[0];
  if (dossier.payment_status === 'paid') {
    return res.send(page("Déjà payé", `<section class="card" style="text-align:center;"><h1>✅ Déjà payé</h1><p>Votre dossier est déjà réglé.</p><a href="/" class="button">Retour à l'accueil</a></section>`, proConnected));
  }

  res.send(page("Paiement", `
    <section class="card" style="max-width: 500px; margin: 40px auto; text-align: center;">
      <h1>💳 Finalisez votre inscription</h1>
      <p>Bonjour <strong>${escapeHtml(dossier.full_name)}</strong>,</p>
      <p style="margin-bottom: 20px;">Pour valider l'étude de votre dossier, veuillez régler les frais d'inscription de <strong>1500 FCFA</strong>.</p>
      
      <button onclick="payer()" style="padding: 16px; background: #10b981; color: white; font-size: 18px; width: 100%; border-radius: 8px;">
        Payer 1500 FCFA
      </button>
      
      <p style="font-size: 12px; color: #6b7280; margin-top: 20px;">Paiement sécurisé via Mobile Money (MTN / Moov).</p>
    </section>
    
    <script src="https://cdn.kkiapay.me/k.js"></script>
    <script>
      function payer() {
        openKkiapayWidget({ 
          amount: 1500, 
          api_key: "${process.env.KKIAPAY_PUBLIC_KEY}", 
          sandbox: ${process.env.KKIAPAY_SANDBOX === "true"}, 
          callback: "${APP_URL}/paiement/verifier?tracking=${trackingCode}", 
          data: "${trackingCode}" 
        });
      }
      
      addSuccessListener(function(response) {
        if (response && response.transactionId) {
          window.location.href = "/paiement/verifier?tracking=${trackingCode}&transaction_id=" + response.transactionId;
        }
      });
    </script>
  `, proConnected));
});

// Vérification du paiement après retour de Kkiapay
router.get("/paiement/verifier", async (req, res) => {
  const trackingCode = String(req.query.tracking || "").trim();
  const transactionId = String(req.query.transaction_id || "").trim();
  const proConnected = await getConnectedPro(req);

  if (!trackingCode || !transactionId) return res.redirect(303, "/");

  try {
    // On appelle la fonction de vérification de ton serveur.js
    const verification = await verifyKkiapayTransaction(transactionId);
    
    if (verification.success) {
      const dossier = await pool.query(`SELECT id FROM professional_applications WHERE tracking_code = $1`, [trackingCode]);
      if (dossier.rows.length) {
         await settlePayment({
           dossierId: dossier.rows[0].id,
           transactionId: transactionId,
           amount: verification.amount,
           method: 'kkiapay',
           source: 'redirect'
         });
         return res.send(page("Succès", `<section class="card" style="text-align:center;"><h1>🎉 Paiement réussi !</h1><p>Votre dossier est maintenant en cours d'examen par notre équipe.</p><a href="/" class="button">Retour à l'accueil</a></section>`, proConnected));
      }
    }
    res.send(page("Erreur", `<section class="card" style="text-align:center;"><h1>❌ Paiement non confirmé</h1><p>Si vous avez été débité, contactez-nous.</p><a href="/contact" class="button">Contact</a></section>`, proConnected));
  } catch (e) {
    res.redirect(303, "/");
  }
});
  // Fonction pour créer ou récupérer le code d'un client
async function getOrCreateClientCode(visitorId) {
  if (!visitorId) return null;
  let result = await pool.query(`SELECT code FROM client_codes WHERE visitor_id = $1`, [visitorId]);
  if (result.rows.length) return result.rows[0].code;
  
  // Si le visiteur n'a pas de code, on lui en crée un
  const newCode = crypto.randomBytes(4).toString("hex").toUpperCase();
  await pool.query(`INSERT INTO client_codes (visitor_id, code) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [visitorId, newCode]);
  return newCode;
}
  return router;
};
