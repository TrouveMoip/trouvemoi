const express = require('express');

module.exports = function(pool, page, getConnectedPro, escapeHtml, cleanBeninPhone, JOB_CONTRACT_TYPES, logAdminAction, OFFER_DURATION_DAYS) {
  const router = express.Router();

  router.get("/publier-emploi", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    res.send(page("Publier", `<section class="card" style="max-width: 700px; margin: 0 auto;"><h1>Nouvelle offre</h1><form action="/offres-emploi" method="POST"><label>Entreprise *</label><input name="company_name" required><label>Poste *</label><input name="job_title" required><label>Description *</label><textarea name="description" required></textarea><button type="submit">Soumettre</button></form></section>`, proConnected));
  });

  router.post("/offres-emploi", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (!proConnected) return res.redirect(303, "/mon-espace-pro");
    await pool.query(`INSERT INTO job_offers (company_name, job_title, city, contract_type, description, status, pro_id, expires_at) VALUES ($1,$2,$3,$4,$5,'pending',$6, NOW() + INTERVAL '15 days')`, [req.body.company_name, req.body.job_title, req.body.city || 'Cotonou', 'CDI', req.body.description, proConnected.pro.id]);
    res.send(page("Succes", "<h1>Soumise !</h1><a href='/mon-espace-pro' class='button'>Retour</a>", proConnected));
  });

  router.post("/mon-espace-pro/offre/:id/close", async (req, res) => { 
    const proConnected = await getConnectedPro(req); 
    if (proConnected) await pool.query(`UPDATE job_offers SET status = 'closed' WHERE id = $1 AND pro_id = $2`, [Number(req.params.id), proConnected.pro.id]); 
    res.redirect(303, "/mon-espace-pro"); 
  });

  router.post("/mon-espace-pro/offre/:id/reopen", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (proConnected) await pool.query(`UPDATE job_offers SET status = 'approved', expires_at = NOW() + INTERVAL '15 days' WHERE id = $1 AND pro_id = $2 AND status = 'closed'`, [Number(req.params.id), proConnected.pro.id]);
    res.redirect(303, "/mon-espace-pro");
  });

  router.post("/mon-espace-pro/offre/:id/supprimer", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    if (proConnected) await pool.query(`DELETE FROM job_offers WHERE id = $1 AND pro_id = $2`, [Number(req.params.id), proConnected.pro.id]);
    res.redirect(303, "/mon-espace-pro");
  });

  return router;
};
