const express = require('express');

module.exports = function(pool, page, getConnectedPro) {
  const router = express.Router();

  // Route pour À propos
  router.get('/a-propos', async (req, res) => {
    const proConnected = await getConnectedPro(req);
    res.send(page("À propos", `<section class="card" style="max-width: 800px; margin: 40px auto;"><h1>À propos de TrouveMoi</h1><p>TrouveMoi est la première plateforme béninoise qui met en relation directe les clients avec des professionnels vérifiés de leur quartier.</p><p>Notre mission est de valoriser le savoir-faire local tout en garantissant aux clients des prestations de qualité, en toute confiance.</p></section>`, proConnected));
  });

  // Route pour Partenariats
  router.get('/partenariats', async (req, res) => {
    const proConnected = await getConnectedPro(req);
    res.send(page("Partenariats", `<section class="card" style="max-width: 800px; margin: 40px auto;"><h1>Partenariats</h1><p>Vous souhaitez collaborer avec TrouveMoi ? Contactez-nous à contact@trouvemoi.bj.</p></section>`, proConnected));
  });

  return router;
};
