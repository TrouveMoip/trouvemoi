const express = require('express');

module.exports = function(pool, page, getConnectedPro, escapeHtml) {
  const router = express.Router();

  router.get("/a-propos", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    res.send(page("À propos", `<section class="card" style="max-width: 800px; margin: 40px auto;"><h1>À propos de TrouveMoi</h1><p>TrouveMoi est la première plateforme béninoise qui met en relation directe les clients avec des professionnels vérifiés de leur quartier.</p><p>Notre mission est de valoriser le savoir-faire local tout en garantissant aux clients des prestations de qualité, en toute confiance.</p></section>`, proConnected));
  });

  router.get("/partenariats", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    res.send(page("Partenariats", `<section class="card" style="max-width: 800px; margin: 40px auto;"><h1>Partenariats</h1><p>Vous souhaitez collaborer avec TrouveMoi ? Contactez-nous à contact@trouvemoi.bj.</p></section>`, proConnected));
  });

  router.get("/conditions", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    const content = `
      <section class="card" style="max-width: 800px; margin: 40px auto; padding: 30px;">
        <h1 style="font-size: 28px; color: #1e3a8a; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; margin-bottom: 20px;">Conditions Générales d'Utilisation (CGU)</h1>
        <p><em>Dernière mise à jour : ${new Date().toLocaleDateString("fr-FR")}</em></p>
        <p>Les présentes Conditions Générales d'Utilisation (CGU) ont pour objet de définir les modalités d'accès et d'utilisation de la plateforme TrouveMoi.</p>
        <div style="margin-top: 40px; text-align: center;">
          <button onclick="window.print()" class="button no-print" style="background: #2563eb; margin-bottom: 10px;">🖨️ Imprimer cette page</button>
          <br><a href="/" class="button secondary">← Retour à l'accueil</a>
        </div>
      </section>
    `;
    res.send(page("Conditions Générales", content, proConnected));
  });

  router.get("/mentions-legales", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    const content = `
      <section class="card" style="max-width: 800px; margin: 40px auto; padding: 40px;">
        <h1 style="font-size: 26px; color: #111827; margin-bottom: 30px; font-weight: bold;">Mentions légales</h1>
        <p>Conformément à la loi 2017-20 portant code du numérique en République du Bénin, le site a fait l'objet d'une déclaration auprès de l'APDP.</p>
        <div style="margin-top: 40px; text-align: center;" class="no-print">
          <button onclick="window.print()" class="button no-print" style="background: #2563eb; margin-bottom: 10px;">🖨️ Imprimer cette page</button>
          <br><a href="/" class="button secondary">← Retour à l'accueil</a>
        </div>
      </section>
    `;
    res.send(page("Mentions Légales", content, proConnected));
  });

  router.get("/confidentialite", async (req, res) => {
    const proConnected = await getConnectedPro(req);
    const content = `
      <section class="card" style="max-width: 800px; margin: 40px auto; padding: 40px;">
        <h1 style="font-size: 26px; color: #111827; margin-bottom: 10px; font-weight: bold;">Politique de Confidentialité</h1>
        <p style="color: #6b7280; font-size: 14px; margin-bottom: 30px;">Dernière mise à jour : ${new Date().toLocaleDateString("fr-FR")}</p>
        <p>Comment nous collectons, utilisons et protégeons vos données sur TrouveMoi.</p>
        <div style="margin-top: 40px; text-align: center;" class="no-print">
          <button onclick="window.print()" class="button no-print" style="background: #2563eb; margin-bottom: 10px;">🖨️ Imprimer cette page</button>
          <br><a href="/" class="button secondary">← Retour à l'accueil</a>
        </div>
      </section>
    `;
    res.send(page("Politique de Confidentialité", content, proConnected));
  });

// PAGE D'ACCUEIL
router.get("/", async (req, res) => {
  try {
    const proConnected = await getConnectedPro(req);
    
    // On récupère les 6 derniers pros approuvés
    const result = await pool.query("SELECT * FROM professional_applications WHERE status = 'approved' ORDER BY created_at DESC LIMIT 6");
    
    let cards = result.rows.map(p => `
      <div class="pro-card">
        <div class="pro-name">${escapeHtml(p.company_name || p.full_name)}</div>
        <div class="pro-meta" style="color: #2563eb; font-weight: bold; text-transform: uppercase;">${escapeHtml(p.profession)}</div>
        <div class="pro-meta">📍 ${escapeHtml(p.city)}</div>
        <a href="/pro/${p.id}" class="button" style="margin-top: 10px; width: 100%;">Voir le profil</a>
      </div>
    `).join("");

    res.send(page("Accueil", `
      <div class="card" style="text-align: center; background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; padding: 40px; border-radius: 16px; margin-bottom: 30px;">
        <h1 style="color: white; font-size: 32px; margin-bottom: 10px;">Trouvez le professionnel qu'il vous faut</h1>
        <p style="font-size: 16px; margin-bottom: 20px; opacity: 0.9;">Des professionnels vérifiés au Bénin, à portée de clic.</p>
        <a href="/recherche" class="button" style="background: #f59e0b; font-size: 16px; padding: 14px 28px; font-weight: bold;">🔍 Rechercher un pro</a>
      </div>
      
      <h2 style="text-align: center; margin-bottom: 20px;">Derniers professionnels inscrits</h2>
      <div class="pros-grid">
        ${cards || `<div class="card"><p style="text-align:center;">Aucun professionnel pour le moment.</p></div>`}
      </div>
    `, proConnected));
    
  } catch (e) {
    console.error(e);
    res.status(500).send("Erreur serveur");
  }
});
  return router;
};
