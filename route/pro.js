const express = require('express');

module.exports = function(pool, page, getConnectedPro, escapeHtml, upload, uploadToCloudinary, clearRateLimit, takeRateLimit, setProCookie, clearProCookie, generateUniqueProCode, logAdminAction, OFFER_DURATION_DAYS) {
  const router = express.Router();

  router.post("/login", async (req, res) => {
    const ip = req.ip || "unknown";
    const ipKey = `pro_login:ip:${ip}`;
    if (!(await takeRateLimit(ipKey, 30, 15 * 60 * 1000))) return res.status(429).send(page("Trop de tentatives", "<h1>⏳ Trop de tentatives</h1>", null));
    const code = String(req.body.pro_code || "").trim().toUpperCase();
    if (!/^TM\d{5,8}$/.test(code)) return res.status(400).send(page("Erreur", "<h2>Code invalide.</h2>", null));
    const codeKey = `pro_login:code:${code}`;
    if (!(await takeRateLimit(codeKey, 3, 15 * 60 * 1000))) return res.status(429).send(page("Trop de tentatives", "<h1>⏳ Trop de tentatives sur ce code</h1>", null));
    try {
      const result = await pool.query(`SELECT id FROM professional_applications WHERE pro_code = $1 AND status = 'approved'`, [code]);
      if (!result.rows.length) return res.status(401).send(page("Erreur", "<h2>Code incorrect.</h2>", null));
      await clearRateLimit(codeKey); setProCookie(res, code); res.redirect(303, "/mon-espace-pro");
    } catch (error) { res.redirect(303, "/mon-espace-pro"); }
  });

  router.post("/logout", (req, res) => { clearProCookie(res); res.redirect(303, "/mon-espace-pro"); });

  router.get("/", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.send(page("Espace pro", `<section class="card" style="max-width: 500px; margin: 40px auto;"><h1 style="text-align: center;">Espace pro</h1><form action="/mon-espace-pro/login" method="POST"><label>Code pro</label><input name="pro_code" required><button type="submit" style="width: 100%;">Se connecter</button></form></section>`, null));

    const statsRes = await pool.query(`SELECT SUM(views) as v, SUM(phone_clicks) as p, SUM(wa_clicks) as w FROM pro_stats WHERE pro_id = $1 AND date >= CURRENT_DATE - INTERVAL '30 days'`, [proConnected.pro.id]);
    const stats = { views: Number(statsRes.rows[0]?.v || 0), phone: Number(statsRes.rows[0]?.p || 0), wa: Number(statsRes.rows[0]?.w || 0) };

    res.send(page("Espace pro", `
      <div class="card" style="background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; padding:20px; border-radius:12px; margin-bottom:20px;">
        <h2 style="color:white; margin:0;">Bonjour ${escapeHtml(proConnected.pro.company_name || proConnected.pro.full_name)} 👋</h2>
        <p style="margin-top:10px; font-size:24px; font-weight:bold;">Code : ${escapeHtml(proConnected.code)}</p>
      </div>
      <div style="display:flex; gap:10px; margin-bottom:20px; flex-wrap:wrap;">
        <a class="button" href="/mon-espace-pro/agences">📋 Mes agences</a>
        <a class="button" href="/mon-espace-pro/agences/nouvelle" style="background: #8b5cf6;">🏢 Ajouter une agence</a>
        <a class="button" href="/publier-emploi">📢 Publier une offre</a>
        <a class="button" href="/mon-espace-pro/modifier-profil">✏️ Profil</a>
        <a class="button" href="/mon-espace-pro/modifier-photo">📷 Photo</a>
        <a class="button" href="/mon-espace-pro/modifier-galerie">📸 Galerie</a>
        <form action="/mon-espace-pro/logout" method="POST" style="margin-left:auto;"><button class="danger" type="submit">Déconnexion</button></form>
      </div>
      <div class="card"><h2>📊 Statistiques (30j)</h2><p>Vues : ${stats.views} | Appels : ${stats.phone} | WhatsApp : ${stats.wa}</p></div>
    `, proConnected));
  });

  router.get("/modifier-profil", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    res.send(page("Modifier Profil", `<section class="card" style="max-width: 600px; margin: 40px auto;"><h1>✏️ Modifier mon profil</h1><form action="/mon-espace-pro/modifier-profil" method="POST"><label>Nom de l'entreprise</label><input name="company_name" value="${escapeHtml(proConnected.pro.company_name || '')}"><label>Téléphone</label><input name="phone" value="${escapeHtml(proConnected.pro.phone)}"><button type="submit" style="width:100%;">Enregistrer</button></form></section>`, proConnected));
  });

  router.post("/modifier-profil", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    await pool.query(`UPDATE professional_applications SET company_name = $1, phone = $2 WHERE id = $3`, [req.body.company_name, req.body.phone, proConnected.pro.id]);
    res.redirect(303, "/mon-espace-pro");
  });

  // (Les routes pour modifier-photo et modifier-galerie iraient ici avec la logique uploadToCloudinary)

  return router;
};
