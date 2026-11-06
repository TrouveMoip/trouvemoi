const express = require('express');

module.exports = function(pool, page, getConnectedPro, escapeHtml, cleanBeninPhone, JOB_CONTRACT_TYPES, logAdminAction) {
  const router = express.Router();

  router.get("/emplois", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    const result = await pool.query(`SELECT * FROM job_offers WHERE status = 'approved' ORDER BY created_at DESC LIMIT 10`);
    const jobs = result.rows.map((job) => `<article class="card"><h2>${escapeHtml(job.job_title)}</h2><p>${escapeHtml(job.company_name)} - ${escapeHtml(job.city)}</p></article>`).join("");
    res.send(page("Emploi", `<h1>Offres d'emploi</h1>${jobs || "<p>Aucune offre.</p>"}`, proConnected));
  });

  router.get("/publier-emploi", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    res.send(page("Publier", `<section class="card" style="max-width: 700px; margin: 0 auto;"><h1>Nouvelle offre</h1><form action="/offres-emploi" method="POST"><label>Entreprise *</label><input name="company_name" value="${escapeHtml(proConnected.pro.company_name || '')}" required><label>Poste *</label><input name="job_title" required><label>Description *</label><textarea name="description" required></textarea><button type="submit" style="width:100%;">Soumettre</button></form></section>`, proConnected));
  });

  router.post("/offres-emploi", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    await pool.query(`INSERT INTO job_offers (company_name, job_title, city, contract_type, description, status, pro_id, expires_at) VALUES ($1,$2,$3,$4,$5,'pending',$6, NOW() + INTERVAL '15 days')`, [req.body.company_name, req.body.job_title, req.body.city || 'Cotonou', 'CDI', req.body.description, proConnected.pro.id]);
    res.send(page("Succes", "<h1>Soumise !</h1><a href='/mon-espace-pro' class='button'>Retour</a>", proConnected));
  });

  return router;
};
