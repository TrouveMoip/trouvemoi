const express = require('express');

module.exports = function(pool, page, getConnectedPro, getOrCreateVisitorId, escapeHtml, renderStars, renderKycBadge, getDisplayName, APP_URL) {
  const router = express.Router();

  // --- FONCTION DE PAGINATION ---
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
  // 1. PAGE D'ACCUEIL (Bannière + Pros + Agences)
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

      const query = `SELECT p.id, p.full_name, p.company_name, p.phone, p.phone_public, p.city, p.neighborhood, p.profession, p.service_description, p.type_lieu, p.latitude, p.longitude, p.kyc_verified, (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count, (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating, EXISTS(SELECT 1 FROM client_favorites cf WHERE cf.pro_id = p.id AND cf.visitor_id = $3) AS is_favorite FROM professional_applications p WHERE p.status = 'approved' ORDER BY p.created_at DESC LIMIT $1 OFFSET $2`;
      const result = await pool.query(query, [limit, offset, visitorId]);

      // Agences récentes
      const agenciesAccueil = await pool.query(`SELECT a.id, a.name, a.address, p.company_name AS parent_name FROM agencies a JOIN professional_applications p ON a.parent_pro_id = p.id WHERE a.status = 'approved' ORDER BY a.created_at DESC LIMIT 3`);
      let agenciesAccueilHtml = "";
      if (agenciesAccueil.rows.length > 0) {
        agenciesAccueilHtml = `
          <h2 style="text-align: center; margin: 40px 0 20px 0;">🏢 Nos nouvelles agences</h2>
          <div class="pros-grid">
            ${agenciesAccueil.rows.map(ag => `
              <article class="pro-card" style="border-left: 4px solid #8b5cf6;">
                <div class="pro-name">${escapeHtml(ag.name)}</div>
                <div class="pro-meta" style="color: #8b5cf6; font-weight: 700; font-size: 11px;">Réseau : ${escapeHtml(ag.parent_name || "Indépendant")}</div>
                <div class="pro-meta">📍 ${escapeHtml(ag.address)}</div>
                <div class="pro-actions" style="margin-top: 12px;"><a href="/agence/${ag.id}" class="button pro-profile-link" style="padding: 8px; font-size: 13px; background:#8b5cf6; color:white;">Voir l'agence →</a></div>
              </article>`).join("")}
          </div>`;
      }

      const palettes = ["#d97706", "#dc2626", "#7c3aed", "#0891b2", "#db2777", "#2563eb", "#059669", "#ca8a04"];
      const prosCards = result.rows.map((person) => {
        const displayName = getDisplayName(person);
        const reviewsCount = Number(person.reviews_count || 0);
        const avgRating = Number(person.avg_rating || 0);
        const isTopPro = avgRating >= 4.5 && reviewsCount >= 10;
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

        <div class="alert alert-danger" style="text-align: center;"><strong>⚠️ ATTENTION :</strong> Ne payez jamais un professionnel avant de l'avoir rencontré.</div>
        ${agenciesAccueilHtml}
        <h2 style="text-align: center; margin: 40px 0 20px 0;">Derniers professionnels inscrits</h2>
        <div class="pros-grid">${prosCards}</div>
        ${renderPagination(currentPage, totalPages, "/")}
        <script>
          const prosGeo = ${JSON.stringify(result.rows.map(p => ({ id: p.id, lat: p.latitude, lon: p.longitude })).filter(p => p.lat && p.lon))};
          if (prosGeo.length > 0 && navigator.geolocation) {
            navigator.geolocation.getCurrentPosition((pos) => {
              const cLat = pos.coords.latitude, cLon = pos.coords.longitude;
              prosGeo.forEach(p => {
                const R = 6371; const dLat = (p.lat - cLat) * Math.PI / 180; const dLon = (p.lon - cLon) * Math.PI / 180;
                const a = Math.sin(dLat/2) * Math.sin(dLat/2) + Math.cos(cLat * Math.PI / 180) * Math.cos(p.lat * Math.PI / 180) * Math.sin(dLon/2) * Math.sin(dLon/2);
                const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a)); const distance = (R * c).toFixed(1);
                const el = document.getElementById('dist-' + p.id); if (el) el.innerHTML = '📍 ' + distance + ' km';
              });
            });
          }
        </script>
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

        // Agences
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
  // 3. PAGE PROFIL PUBLIC (Avec galerie et avis)
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
      
      const reviewsResult = await pool.query(`SELECT author_name, rating, comment, pro_response, created_at FROM reviews WHERE pro_id = $1 AND status = 'approved' ORDER BY created_at DESC LIMIT 5`, [id]);
      const galerieData = [{ url: person.photo_galerie_1, desc: person.photo_galerie_1_desc }, { url: person.photo_galerie_2, desc: person.photo_galerie_2_desc }, { url: person.photo_galerie_3, desc: person.photo_galerie_3_desc }].filter(item => item.url);

      let rawPhone = (person.phone || "").replace(/\D/g, ""); if (rawPhone.startsWith("00229")) rawPhone = rawPhone.substring(5); if (rawPhone.startsWith("229")) rawPhone = rawPhone.substring(3);
      const phoneClean = rawPhone; const whatsappNumber = /^\d{8,10}$/.test(rawPhone) ? "229" + rawPhone : null;
      
      let contactButtons = person.phone_public && phoneClean ? `<a class="button" href="tel:+229${escapeHtml(phoneClean)}" style="background: #e0e7ff; color: #1e3a8a;">📞 Appeler</a>${whatsappNumber ? `<a class="button whatsapp" href="https://wa.me/${whatsappNumber}" target="_blank">💬 WhatsApp</a>` : ""}` : `<a class="button" href="/contact?pro=${person.id}">📩 Contacter</a>`;

      const content = `
        <div style="max-width: 800px; margin: 0 auto;">
          <div class="card" style="padding: 32px 24px; text-align:center;">
            <div style="margin-bottom:12px;"><a href="#" onclick="toggleFav(event, ${person.id})" class="button secondary" style="padding:8px 16px;">${person.is_favorite ? '❤️ Retirer des favoris' : '🤍 Ajouter aux favoris'}</a></div>
            <h1>${escapeHtml(displayName)} ${renderKycBadge(person, "lg")}</h1>
            <div style="color: #2563eb; font-weight: 700; text-transform: uppercase;">${escapeHtml(person.profession)}</div>
            <div style="color: #6b7280; margin-top: 8px;">📍 ${escapeHtml(person.city)}</div>
            <div style="font-size: 22px; color: #f59e0b; margin-top: 12px;">${renderStars(Number(person.avg_rating || 0))} <span style="font-size:15px; color:#6b7280;">(${person.reviews_count} avis)</span></div>
          </div>
          <div class="card"><h2>À propos</h2><p>${escapeHtml(person.service_description)}</p><div style="margin-top: 24px; display:flex; gap:12px; flex-wrap:wrap;">${contactButtons}</div></div>
          ${galerieData.length > 0 ? `<div class="card"><h2>📸 Galerie</h2><div style="display:flex; gap:10px;">${galerieData.map(item => `<img src="${escapeHtml(item.url)}" style="width:100px;height:100px;object-fit:cover;border-radius:8px;">`).join("")}</div></div>` : ""}
          <div class="card"><h2>Avis (${person.reviews_count})</h2>${reviewsResult.rows.map(r => `<div style="border-bottom:1px solid #e5e7eb; padding-bottom:10px; margin-bottom:10px;"><strong>${escapeHtml(r.author_name)}</strong> - ${renderStars(r.rating)}<br><p>${escapeHtml(r.comment)}</p></div>`).join("")}<a href="/pro/${person.id}/avis" class="button warning" style="width:100%; margin-top:10px;">⭐ Laisser un avis</a></div>
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
        contactButtons = `<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 16px;"><a class="button" href="tel:+229${escapeHtml(cleanPhone)}" onclick="fetch('/api/track-agency/${agency.id}/phone', {method:'POST'})" style="margin: 0; background: #e0e7ff; color: #1e3a8a;">📞 Appeler</a>${waNumber ? `<a class="button whatsapp" href="https://wa.me/${waNumber}" onclick="fetch('/api/track-agency/${agency.id}/wa', {method:'POST'})" target="_blank" style="margin: 0;">💬 WhatsApp</a>` : ""}</div>`;
      }

      const galerieData = [{ url: agency.photo_1, desc: agency.photo_1_desc }, { url: agency.photo_2, desc: agency.photo_2_desc }, { url: agency.photo_3, desc: agency.photo_3_desc }].filter(i => i.url);
      res.send(page(agency.name, `<div style="max-width: 800px; margin: 0 auto;"><div class="card" style="text-align:center;"><span class="badge" style="background:#8b5cf6; color:white;">🏢 Agence officielle</span><h1>${escapeHtml(agency.name)} ${renderKycBadge(agency, "lg")}</h1><div style="color: #2563eb; font-weight: bold;">Réseau : ${escapeHtml(parentName)}</div><div style="margin-top:20px; background:#eff6ff; padding:20px; border-radius:12px;"><p>${escapeHtml(agency.address)}</p>${agency.latitude ? `<a href="https://www.google.com/maps/search/?api=1&query=${agency.latitude},${agency.longitude}" target="_blank" class="button" style="background:#2563eb; width:100%; margin-top:10px;">🗺️ Itinéraire</a>` : ""}</div>${contactButtons}</div>${galerieData.length > 0 ? `<div class="card"><h2>📸 Photos</h2><div style="display:flex; gap:10px;">${galerieData.map(i => `<img src="${escapeHtml(i.url)}" style="width:100px;height:100px;object-fit:cover;border-radius:8px;">`).join("")}</div></div>` : ""}<div style="text-align:center; margin-top:24px;"><a href="/pro/${agency.parent_pro_id}" class="button secondary">← Profil de ${escapeHtml(parentName)}</a></div></div>`, proConnected, { title: agency.name }));
      pool.query(`INSERT INTO agency_stats (agency_id, date, views, last_visitor_id) VALUES ($1, CURRENT_DATE, 1, $2) ON CONFLICT (agency_id, date) DO UPDATE SET views = CASE WHEN agency_stats.last_visitor_id = $2 THEN agency_stats.views ELSE agency_stats.views + 1 END, last_visitor_id = $2`, [id, getOrCreateVisitorId(req, res)]).catch(() => {});
    } catch (e) { res.status(500).send(page("Erreur", "<h2>Erreur.</h2>", null)); }
  });

  // ==========================================
  // 5. PAGES STATIQUES & BLOG
  // ==========================================
  router.get("/a-propos", async (req, res) => res.send(page("À propos", "<h1>À propos</h1>", await getConnectedPro(req))));
  router.get("/partenariats", async (req, res) => res.send(page("Partenariats", "<h1>Partenariats</h1>", await getConnectedPro(req))));
  router.get("/conditions", async (req, res) => res.send(page("Conditions", "<h1>Conditions</h1>", await getConnectedPro(req))));
  router.get("/mentions-legales", async (req, res) => res.send(page("Mentions Légales", "<h1>Mentions Légales</h1>", await getConnectedPro(req))));
  router.get("/confidentialite", async (req, res) => res.send(page("Confidentialité", "<h1>Confidentialité</h1>", await getConnectedPro(req))));

  router.get("/blog", async (req, res) => {
    const articles = (await pool.query(`SELECT * FROM blog_posts WHERE published = true ORDER BY created_at DESC`)).rows;
    const list = articles.map(a => `<article class="card"><h2><a href="/blog/${a.slug}" style="text-decoration:none; color:#1e40af;">${escapeHtml(a.title)}</a></h2><p style="font-size:13px; color:#6b7280;">Publié le ${new Date(a.created_at).toLocaleDateString("fr-FR")}</p><p>${escapeHtml(a.content).slice(0, 200)}...</p></article>`).join("");
    res.send(page("Blog", `<h1 style="text-align:center;">Le Blog de TrouveMoi</h1><div style="max-width:800px; margin:0 auto;">${list}</div>`, await getConnectedPro(req)));
  });

  router.get("/blog/:slug", async (req, res) => {
    const article = (await pool.query(`SELECT * FROM blog_posts WHERE slug = $1 AND published = true`, [req.params.slug])).rows[0];
    if (!article) return res.redirect(303, "/blog");
    res.send(page(article.title, `<article class="card" style="max-width:800px; margin:40px auto;"><h1>${escapeHtml(article.title)}</h1><p>${escapeHtml(article.content).replace(/\n/g, "<br>")}</p></article>`, await getConnectedPro(req)));
  });

  return router;
};
