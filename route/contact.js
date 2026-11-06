const express = require('express');

module.exports = function(pool, page, getConnectedPro, takeRateLimit, escapeHtml) {
  const router = express.Router();

  router.get("/", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    res.send(page("Contact", `<section class="card" style="max-width: 600px; margin: 40px auto;"><h1 style="text-align:center;">Contactez-nous</h1><form action="/contact" method="POST"><label>Votre nom *</label><input name="name" required maxlength="100"><label>Votre email *</label><input name="email" type="email" required maxlength="254"><label>Votre téléphone (optionnel)</label><input name="phone" type="tel" maxlength="30"><label>Message *</label><textarea name="message" required rows="5" maxlength="3000"></textarea><button type="submit" style="width:100%; margin-top:10px;">Envoyer le message</button></form></section>`, proConnected));
  });

  router.post("/", async (req, res) => {
    const ip = req.ip || "unknown";
    if (!(await takeRateLimit(`contact:${ip}`, 5, 60 * 60 * 1000))) return res.status(429).send(page("Trop de tentatives", "<h1>⏳ Trop de tentatives</h1>", null));

    const name = String(req.body.name || "").trim().slice(0, 100);
    const email = String(req.body.email || "").trim().slice(0, 254);
    const phone = String(req.body.phone || "").trim().slice(0, 30);
    const message = String(req.body.message || "").trim().slice(0, 3000);

    if (!name || !email || !message) return res.redirect(303, "/contact");

    try {
      await pool.query(
        `INSERT INTO contact_messages (name, email, phone, message) VALUES ($1, $2, $3, $4)`,
        [name, email, phone || null, message]
      );
      res.redirect(303, "/contact?success=1");
    } catch (e) { 
      console.error("ERREUR CONTACT:", e.message);
      res.redirect(303, "/contact"); 
    }
  });

  return router;
};
