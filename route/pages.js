const express = require('express');

module.exports = function(pool, page, getConnectedPro, getOrCreateVisitorId, escapeHtml, renderStars, renderKycBadge, getDisplayName) {
  const router = express.Router();

  // Fonction pour la pagination
  function renderPagination(currentPage, totalPages, baseUrl, queryParams = {}) {
    if (totalPages <= 1) return "";
    const buildUrl = (pageNum) => {
      const params = new URLSearchParams(queryParams);
      params.set("page", pageNum);
      return `${baseUrl}?${params.toString()}`;
    };
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
  // LA VRAIE PAGE D'ACCUEIL
  // ==========================================
  router.get("/", async (req, res) => {
    try {
      const proConnected = await getConnectedPro(req);
      const visitorId = getOrCreateVisitorId(req, res);
      const rawRef = typeof req.query.ref === "string" ? req.query.ref.trim().toLowerCase() : "";
      const refCode = /^[a-z0-9]{7}$/.test(rawRef) ? rawRef : null;
      
      if (refCode) {
        res.append("Set-Cookie", `tm_ref=${refCode}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 24 * 60 * 60}`);
      }

      const currentPage = Math.max(1, parseInt(req.query.page) || 1);
      const limit = 6; const offset = (currentPage - 1) * limit;

      const totalAllProsResult = await pool.query("SELECT COUNT(*) FROM professional_applications WHERE status = 'approved'");
      const totalAllPros = parseInt(totalAllProsResult.rows[0].count);
      const totalPages = Math.ceil(totalAllPros / limit);

      const query = `SELECT p.id, p.full_name, p.company_name, p.phone, p.phone_public, p.city, p.neighborhood, p.profession, p.service_description, p.type_lieu, p.latitude, p.longitude, p.kyc_verified, 
        (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count, 
        (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating,
        EXISTS(SELECT 1 FROM client_favorites cf WHERE cf.pro_id = p.id AND cf.visitor_id = $3) AS is_favorite
        FROM professional_applications p WHERE p.status = 'approved' ORDER BY p.created_at DESC LIMIT $1 OFFSET $2`;
      const result = await pool.query(query, [limit, offset, visitorId]);

      // Récupérer les agences récentes
      const agenciesAccueil = await pool.query(`SELECT a.id, a.name, a.address, p.company_name AS parent_name FROM agencies a JOIN professional_applications p ON a.parent_pro_id = p.id WHERE a.status = 'approved' ORDER BY a.created_at DESC LIMIT 3`);
      
      let agenciesAccueilHtml = "";
      if (agenciesAccueil.rows.length > 0) {
        agenciesAccueilHtml = `
          <h2 style="text-align: center; margin: 40px 0 20px 0;">🏢 Nos nouvelles agences</h2>
          <div class="pros-grid">
            ${agenciesAccueil.rows.map(ag => `
              <article class="pro-card" style="border-left: 4px solid #8b5cf6;">
                <div class="pro-card-top">
                  <div>
                    <div class="pro-name">${escapeHtml(ag.name)}</div>
                    <div class="pro-meta" style="color: #8b5cf6; font-weight: 700; font-size: 11px; text-transform: uppercase;">Réseau : ${escapeHtml(ag.parent_name || "Indépendant")}</div>
                    <div class="pro-meta">📍 ${escapeHtml(ag.address)}</div>
                  </div>
                  <div style="text-align: right;"><span class="badge" style="background:#8b5cf6; color:white;">Agence</span></div>
                </div>
                <div class="pro-actions" style="margin-top: 12px;">
                  <a href="/agence/${ag.id}" class="button pro-profile-link" style="padding: 8px; font-size: 13px; background:#8b5cf6; color:white;">Voir l'agence →</a>
                </div>
              </article>
            `).join("")}
          </div>`;
      }

      const palettes = ["#d97706", "#dc2626", "#7c3aed", "#0891b2", "#db2777", "#2563eb", "#059669", "#ca8a04"];
      const prosCards = result.rows.map((person) => {
        const displayName = person.company_name?.trim() || person.full_name || "";
        const reviewsCount = Number(person.reviews_count || 0);
        const avgRating = Number(person.avg_rating || 0);
        const isTopPro = avgRating >= 4.5 && reviewsCount >= 10;
        
        let hash = 0; const key = String(person.profession);
        for (let i = 0; i < key.length; i++) { hash = ((hash << 5) - hash) + key.charCodeAt(i); hash = hash & hash; }
        const borderColor = palettes[Math.abs(hash) % palettes.length];
        
        let ratingHtml = reviewsCount > 0 
          ? `<div style="font-size: 13px; color: #ed8936; font-weight: 600;">${renderStars(avgRating)} <span style="color: #718096; font-weight: 400; font-size: 11px;">(${reviewsCount})</span></div>`
          : `<div style="font-size: 11px; color: #a0aec0; font-style: italic;">Pas encore d'avis</div>`;

        const typeBadge = person.type_lieu === 'fixe' ? `<span class="badge-local">🏠 Local</span>` : `<span class="badge-ambulant">🚗 Ambulant</span>`;

        let rawPhone = (person.phone || "").replace(/\D/g, "");
        if (rawPhone.startsWith("00229")) rawPhone = rawPhone.substring(5);
        if (rawPhone.startsWith("229")) rawPhone = rawPhone.substring(3);
        const cleanPhone = rawPhone;
        const waNumber = /^\d{8,10}$/.test(rawPhone) ? "229" + rawPhone : null;

        let actionButtons = "";
        if (person.phone_public && cleanPhone) {
          actionButtons = `
            <a href="tel:${escapeHtml("+229" + cleanPhone)}" class="button" style="background:#e0e7ff; color:#1e3a8a;">📞 Appeler</a>
            ${waNumber ? `<a href="https://wa.me/${waNumber}?text=${encodeURIComponent("Bonjour, je vous contacte via TrouveMoi.")}" target="_blank" class="button whatsapp">💬 WhatsApp</a>` : ""}
          `;
        } else {
          actionButtons = `<a href="/contact?pro=${person.id}" class="button" style="background:#e0e7ff; color:#1e3a8a; grid-column: span 2;">📩 Contacter</a>`;
        }

        return `
          <article class="pro-card" style="border-left: 4px solid ${borderColor};">
            <div class="favorite-btn ${person.is_favorite ? 'active' : ''}" onclick="toggleFav(event, ${person.id})" title="Ajouter aux favoris" style="top: 12px; right: 12px; width: 30px; height: 30px;">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="${person.is_favorite ? '#ef4444' : 'none'}" stroke="${person.is_favorite ? '#ef4444' : '#6b7280'}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"></path></svg>
            </div>
            <div class="pro-card-top">
              <div>
                <div class="pro-name">${escapeHtml(displayName)} ${renderKycBadge(person)}</div>
                <div class="pro-meta" style="color: ${borderColor}; font-weight: 700; font-size: 11px; text-transform: uppercase;">${escapeHtml(person.profession)}</div>
                <div class="pro-meta">📍 ${escapeHtml(person.city)}</div>
              </div>
              <div style="text-align: right; display: flex; flex-direction: column; gap: 4px; align-items: flex-end; margin-right: 20px;">
                ${isTopPro ? `<span class="top-pro-badge" style="font-size: 9px;">⭐ Top</span>` : ""}
                ${typeBadge}
              </div>
            </div>
            <div class="pro-desc">${escapeHtml(person.service_description || "")}</div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; margin-top: 4px;">
              ${ratingHtml}
            </div>
            <div class="pro-actions" style="gap: 4px;">
              ${actionButtons}
              <a href="/pro/${encodeURIComponent(person.id)}" class="button pro-profile-link" style="padding: 6px; font-size: 11px;">Voir le profil →</a>
            </div>
          </article>
        `;
      }).join("");

      const content = `
      <div style="position: relative; background: white; border: 1px solid #e5e7eb; border-radius: 24px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.05); margin-bottom: 40px;">
        <div style="display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; max-width: 1100px; margin: 0 auto; padding: 40px 20px; gap: 40px;">
          <div style="flex: 1 1 400px; text-align: left;">
            <div style="display: inline-block; background: #eff6ff; border: 1px solid #bfdbfe; padding: 6px 16px; border-radius: 20px; color: #1e40af; font-size: 13px; font-weight: 700; text-transform: uppercase; margin-bottom: 20px;">
              Déjà ${totalAllPros} pros vérifiés
            </div>
            <h1 style="font-size: 38px; font-weight: 800; color: #1e3a8a; margin-bottom: 16px; line-height: 1.2;">
              Trouvez le professionnel<br><span style="color: #f59e0b;">qu'il vous faut près de chez vous.</span>
            </h1>
            <p style="font-size: 17px; color: #4b5563; margin-bottom: 30px;">Des professionnels vérifiés au Bénin, à portée de clic.</p>
            <a href="/recherche" class="button" style="background: #f59e0b; color: white; font-size: 18px; padding: 16px 40px; font-weight: 800; border-radius: 50px; display: inline-block;">🔍 Rechercher un pro</a>
          </div>
          <div style="flex: 1 1 400px; position: relative; display: flex; justify-content: center; align-items: center; min-height: 350px;">
            <img src="https://res.cloudinary.com/gxm35ndf/image/upload/f_auto,q_auto,w_600/v1793214672/ali-mkumbwa-PxlKOcj0a3Q-unsplash_1.jpg" alt="Menuisier" style="width: 85%; height: 320px; object-fit: cover; border-radius: 24px; position: relative; z-index: 1; margin-left: auto;">
            <img src="https://res.cloudinary.com/gxm35ndf/image/upload/f_auto,q_auto,w_500/v1793214724/ali-mkumbwa-1SAFRlUY0lk-unsplash.jpg" alt="Couturier" style="width: 55%; height: 220px; object-fit: cover; border-radius: 20px; position: absolute; bottom: 0px; left: 0px; border: 4px solid white; z-index: 2;">
          </div>
        </div>
      </div>
      
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; max-width: 800px; margin: 50px auto; padding: 0 20px;">
        <a href="/devenir-professionnel" style="background: #2563eb; color: white; padding: 24px; border-radius: 16px; text-decoration: none; text-align: center; font-weight: 700; font-size: 16px;">
          <span style="font-size: 36px; margin-bottom: 12px; display:block;">👤</span>Devenir professionnel
        </a>
        <a href="/emplois" style="background: #10b981; color: white; padding: 24px; border-radius: 16px; text-decoration: none; text-align: center; font-weight: 700; font-size: 16px;">
          <span style="font-size: 36px; margin-bottom: 12px; display:block;">💼</span>Offres d'emploi
        </a>
      </div>

      <div class="alert alert-animated" style="text-align: center; margin-bottom: 24px;"><strong>⚠️ ATTENTION :</strong> Ne payez jamais un professionnel avant de l'avoir rencontré.</div>
      
      ${agenciesAccueilHtml}

      <h2 style="text-align: center; margin: 40px 0 20px 0;">Derniers professionnels inscrits</h2>
      <div class="pros-grid">${prosCards || `<p style="text-align:center;">Aucun professionnel.</p>`}</div>
      ${renderPagination(currentPage, totalPages, "/")}
      `;
      
      res.send(page("Accueil", content, proConnected));
    } catch (error) { 
      console.error(error);
      res.status(500).send(page("Erreur", `<h2>Erreur technique</h2><pre style="background:#f4f4f4; padding:10px; border-radius:8px; white-space:pre-wrap;">${error.message}</pre>`, null));
    }
  });

  // --- PAGES STATIQUES ---
  router.get("/a-propos", async (req, res) => res.send(page("À propos", "<h1>À propos</h1>", await getConnectedPro(req))));
  router.get("/partenariats", async (req, res) => res.send(page("Partenariats", "<h1>Partenariats</h1>", await getConnectedPro(req))));
  router.get("/conditions", async (req, res) => res.send(page("Conditions", "<h1>Conditions</h1>", await getConnectedPro(req))));
  router.get("/mentions-legales", async (req, res) => res.send(page("Mentions Légales", "<h1>Mentions Légales</h1>", await getConnectedPro(req))));
  router.get("/confidentialite", async (req, res) => res.send(page("Confidentialité", "<h1>Confidentialité</h1>", await getConnectedPro(req))));

// PAGE DE RECHERCHE
router.get("/recherche", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const visitorId = getOrCreateVisitorId(req, res);
    const profession = String(req.query.profession || "").trim().slice(0, 150);
    const city = String(req.query.city || "").trim().slice(0, 100);
    const category = String(req.query.category || "").trim().slice(0, 100);
    const neighborhood = String(req.query.neighborhood || "").trim().slice(0, 150);
    const sort = String(req.query.sort || "pertinence").trim();
    const hasLat = req.query.lat !== "" && req.query.lat != null;
    const hasLng = req.query.lng !== "" && req.query.lng != null;
    const lat = hasLat ? Number(req.query.lat) : NaN;
    const lng = hasLng ? Number(req.query.lng) : NaN;
    const hasCoords = Number.isFinite(lat) && Number.isFinite(lng) && Math.abs(lat) <= 90 && Math.abs(lng) <= 180;
    
    const isSearching = profession !== "" || city !== "" || category !== "" || neighborhood !== "";
    
    const currentPage = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 12; const offset = (currentPage - 1) * limit;

    let result = { rows: [] }; let totalPros = 0; let totalPages = 0;
    let prosSection = ""; let paginationHtml = ""; let agencesSearchHtml = "";

    if (isSearching) {
      let whereClause = ` WHERE p.status = 'approved'`; const values = [];
      if (profession) { values.push(`%${profession}%`); whereClause += ` AND (p.profession ILIKE $${values.length} OR p.company_name ILIKE $${values.length} OR p.full_name ILIKE $${values.length})`; }
      if (city) { values.push(`%${city}%`); whereClause += ` AND p.city ILIKE $${values.length}`; }
      if (neighborhood) { values.push(`%${neighborhood}%`); whereClause += ` AND p.neighborhood ILIKE $${values.length}`; }
      if (category) { values.push(category); whereClause += ` AND (p.profession_category = $${values.length} OR p.profession IN (SELECT name FROM professions WHERE category = $${values.length}))`; }

      const countResult = await pool.query(`SELECT COUNT(*) FROM professional_applications p ${whereClause}`, values);
      totalPros = parseInt(countResult.rows[0].count);
      totalPages = Math.ceil(totalPros / limit);

      let orderBy = "p.created_at DESC";
      if (sort === "rating") orderBy = "avg_rating DESC, reviews_count DESC, p.created_at DESC";
      else if (sort === "distance" && hasCoords) orderBy = `(6371 * acos(LEAST(1, cos(radians(${lat})) * cos(radians(p.latitude)) * cos(radians(p.longitude) - radians(${lng})) + sin(radians(${lat})) * sin(radians(p.latitude))))) ASC NULLS LAST`;

      const queryValues = [...values, visitorId, limit, offset];
      const query = `
        SELECT p.id, p.full_name, p.company_name, p.phone, p.phone_public, p.city, p.profession, p.service_description, p.latitude, p.longitude, p.kyc_verified, 
        (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count, 
        (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating,
        EXISTS(SELECT 1 FROM client_favorites cf WHERE cf.pro_id = p.id AND cf.visitor_id = $${queryValues.length - 2}) AS is_favorite
        FROM professional_applications p ${whereClause} ORDER BY ${orderBy} LIMIT $${queryValues.length - 1} OFFSET $${queryValues.length}`;
      result = await pool.query(query, queryValues);

      const cards = result.rows.map(p => `
        <article class="pro-card">
          <div class="pro-name">${escapeHtml(p.company_name || p.full_name)} ${renderKycBadge(p)}</div>
          <div class="pro-meta" style="color: #2563eb; font-weight: bold;">${escapeHtml(p.profession)}</div>
          <div class="pro-meta">📍 ${escapeHtml(p.city)}</div>
          <div class="pro-actions" style="margin-top:10px;">
            <a href="/pro/${p.id}" class="button" style="grid-column: span 2; background: #f3f4f6; color: #374151;">Voir le profil</a>
          </div>
        </article>`).join("");
      
      prosSection = `<div class="pros-grid">${cards || "<p>Aucun professionnel trouvé.</p>"}</div>`;
    }

    res.send(page("Recherche", `
      <div class="card" style="background: #f8fafc; max-width: 900px; margin: 0 auto 30px auto;">
       <form action="/recherche" method="GET" style="display: flex; flex-wrap: wrap; gap: 12px;">
  <input id="profession" name="profession" list="professions-list" value="${escapeHtml(profession)}" placeholder="Métiers ou nom (ex: Maçon, nom de société...)" autocomplete="off" style="flex: 1 1 200px; border: 1px solid #cbd5e0; margin: 0; padding: 16px; font-size: 16px; border-radius: 12px; font-weight: 500;">
  <input id="city" name="city" list="cities-list" value="${escapeHtml(city)}" placeholder="Villes (ex: Cotonou...)" autocomplete="off" style="flex: 1 1 200px; border: 1px solid #cbd5e0; margin: 0; padding: 16px; font-size: 16px; border-radius: 12px; font-weight: 500;">
  <input name="neighborhood" value="${escapeHtml(req.query.neighborhood || "")}" placeholder="Quartier (ex: Akpakpa)" style="flex: 1 1 200px; border: 1px solid #cbd5e0; margin: 0; padding: 16px; font-size: 16px; border-radius: 12px; font-weight: 500;">
  
  <select id="sort-select" name="sort" style="flex: 0 0 150px; border: 1px solid #cbd5e0; margin: 0; padding: 16px; font-size: 14px; border-radius: 12px; background: white;">
    <option value="pertinence" ${sort === 'pertinence' ? 'selected' : ''}>Plus récents</option>
    <option value="rating" ${sort === 'rating' ? 'selected' : ''}>Mieux notés</option>
    <option value="distance" ${sort === 'distance' ? 'selected' : ''}>Plus proches</option>
  </select>

  <button type="button" onclick="useMyPosition()" class="button secondary" style="flex: 0 0 170px; margin: 0; padding: 16px; border-radius: 12px; font-size: 14px;">📍 Autour de moi</button>
  <button type="submit" style="flex: 0 0 120px; border-radius: 12px; padding: 16px; margin: 0; background: #f59e0b; font-size: 16px; font-weight: 800; color: white; box-shadow: 0 4px 12px rgba(245,158,11,0.3);">🔍 Filtrer</button>

  <input type="hidden" name="lat" id="lat-input" value="${hasCoords ? lat : ""}">
  <input type="hidden" name="lng" id="lng-input" value="${hasCoords ? lng : ""}">
  
  ${category ? `<input type="hidden" name="category" value="${escapeHtml(category)}"><div style="width: 100%; font-size: 14px; color: #1e40af; margin-top: 8px;">Filtre actif : Catégorie <strong>${escapeHtml(category)}</strong> <a href="/recherche" style="color: #ef4444; margin-left: 10px;">(Effacer)</a></div>` : ""}
</form>
      </div>
     ${isSearching ? `<h2 style="text-align: center;">Résultats (${totalPros})</h2>${prosSection}` : `<p style="text-align:center;">Entrez un métier ou une ville pour commencer.</p>`}
     <script>
  function useMyPosition() {
    if (!navigator.geolocation) { alert("La géolocalisation n'est pas disponible."); return; }
    navigator.geolocation.getCurrentPosition(function (position) {
      document.getElementById('lat-input').value = position.coords.latitude;
      document.getElementById('lng-input').value = position.coords.longitude;
      document.getElementById('sort-select').value = 'distance';
      document.querySelector('form[action="/recherche"]').submit();
    }, function () { alert("Impossible de vous localiser."); });
  }
</script>
    `, proConnected));
  } catch (error) { res.status(500).send(page("Erreur", "Erreur serveur", null)); }
});

  // ==========================================
// PAGE PROFIL PUBLIC
// ==========================================
router.get("/pro/:id", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.redirect(303, "/");

    const visitorId = getOrCreateVisitorId(req, res);
    const result = await pool.query(`
      SELECT p.*, (SELECT COUNT(*) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS reviews_count, (SELECT COALESCE(AVG(rating), 0) FROM reviews r WHERE r.pro_id = p.id AND r.status = 'approved') AS avg_rating,
      EXISTS(SELECT 1 FROM client_favorites cf WHERE cf.pro_id = p.id AND cf.visitor_id = $2) AS is_favorite
      FROM professional_applications p WHERE p.id = $1 AND p.status = 'approved'`, [id, visitorId]);
    if (!result.rows.length) return res.redirect(303, "/");
    const person = result.rows[0];

    const displayName = person.company_name?.trim() || person.full_name || "";
    const phoneClean = (person.phone || "").replace(/\D/g, "");
    
    res.send(page(displayName, `
      <div class="card" style="max-width: 800px; margin: 0 auto;">
        <h1 style="color: #111827;">${escapeHtml(displayName)} ${renderKycBadge(person, "lg")}</h1>
        <div style="color: #2563eb; font-size: 16px; font-weight: 700; text-transform: uppercase;">${escapeHtml(person.profession)}</div>
        <div style="color: #6b7280; margin-top: 8px;">📍 ${escapeHtml(person.city)}</div>
        <div style="font-size: 22px; color: #f59e0b; margin-top: 12px; font-weight: 700;">${renderStars(Number(person.avg_rating || 0))} <span style="font-size: 15px; color: #6b7280;">(${person.reviews_count} avis)</span></div>
        
        <div style="margin-top: 24px; border-top: 1px solid #e5e7eb; padding-top: 16px;">
          <p>${escapeHtml(person.service_description || "")}</p>
        </div>

        <div style="margin-top: 24px;">
           <a class="button" href="tel:+229${escapeHtml(phoneClean)}" style="width: 100%; font-size: 18px; padding: 16px;">📞 Appeler</a>
        </div>
        <div style="text-align: center; margin-top: 24px;">
          <a href="/" style="color: #6b7280;">← Retour à l'accueil</a>
        </div>
      </div>
    `, proConnected));
  } catch (error) { res.status(500).send(page("Erreur", "Erreur serveur", null)); }
});
  return router;
};
