const express = require('express');

// On exporte une fonction qui prend "pool", "page", etc., en paramètres
module.exports = function(pool, page, getConnectedPro, takeRateLimit) {
  const router = express.Router();

  // La route GET /contact
  router.get('/', async (req, res) => {
    const proConnected = await getConnectedPro(req);
    const proId = req.query.pro ? Number(req.query.pro) : null;
    const reportId = req.query.report ? Number(req.query.report) : null;
    const success = req.query.success === "1";
    
    let contextHtml = "";
    if (proId) {
      const proResult = await pool.query(`SELECT full_name, company_name FROM professional_applications WHERE id = $1`, [proId]);
      if (proResult.rows.length) {
        contextHtml = `<div class="alert alert-info">Vous contactez : <strong>${proResult.rows[0].company_name || proResult.rows[0].full_name}</strong></div>`;
      }
    } else if (reportId) {
      contextHtml = `<div class="alert alert-danger">⚠️ Vous signalez le professionnel #${reportId}.</div>`;
    }

    res.send(page("Contact", `
      <section class="card" style="max-width: 600px; margin: 40px auto;">
        <h1 style="text-align:center;">Contactez-nous</h1>
        ${success ? `<div class="alert alert-success">✅ Votre message a bien été envoyé. Nous vous répondrons rapidement.</div>` : ""}
        ${contextHtml}
        <form action="/contact" method="POST">
          <input type="hidden" name="pro_id" value="${proId || ""}">
          <input type="hidden" name="report_id" value="${reportId || ""}">
          <label>Votre nom *</label>
          <input name="name" required maxlength="100">
          <label>Votre email *</label>
          <input name="email" type="email" required maxlength="254">
          <label>Votre téléphone (optionnel)</label>
          <input name="phone" type="tel" maxlength="30">
          <label>Message *</label>
          <textarea name="message" required rows="5" maxlength="3000"></textarea>
          <button type="submit" style="width:100%; margin-top:10px;">Envoyer le message</button>
        </form>
      </section>
    `, proConnected));
  });

  // La route POST /contact
  router.post('/', async (req, res) => {
    const ip = req.ip || "unknown";
    if (!(await takeRateLimit(`contact:${ip}`, 5, 60 * 60 * 1000))) return res.status(429).send(page("Trop de tentatives", "<section class='card'><h1>⏳ Trop de tentatives</h1><p>Patientez 1 heure.</p></section>", null));

    const name = String(req.body.name || "").trim().slice(0, 100);
    const email = String(req.body.email || "").trim().slice(0, 254);
    const phone = String(req.body.phone || "").trim().slice(0, 30);
    const message = String(req.body.message || "").trim().slice(0, 3000);
    const proId = req.body.pro_id ? Number(req.body.pro_id) : null;
    const reportId = req.body.report_id ? Number(req.body.report_id) : null;

    if (!name || !email || !message) return res.redirect(303, "/contact");

    try {
      await pool.query(
        `INSERT INTO contact_messages (name, email, phone, message, pro_id, report_id) VALUES ($1, $2, $3, $4, $5, $6)`,
        [name, email, phone || null, message, proId || null, reportId || null]
      );
      res.redirect(303, "/contact?success=1");
    } catch (e) { res.redirect(303, "/contact"); }
  });

  return router;
};
