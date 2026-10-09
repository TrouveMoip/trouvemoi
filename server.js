const express = require("express");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

// Connexion à la base de données PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Page d'accueil
app.get("/", (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <title>TrouveMoi - Trouvez le bon professionnel</title>

  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: Arial, sans-serif;
      background: #f3f6fb;
      color: #1d2939;
    }

    header {
      background: #075e54;
      color: white;
      padding: 22px 16px;
      text-align: center;
    }

    header h1 {
      margin: 0;
      font-size: 30px;
    }

    header p {
      margin-bottom: 0;
    }

    main {
      max-width: 850px;
      margin: 35px auto;
      padding: 0 16px;
    }

    .card {
      background: white;
      padding: 25px;
      border-radius: 12px;
      box-shadow: 0 3px 15px rgba(0, 0, 0, 0.07);
    }

    h2 {
      color: #075e54;
    }

    input, select, button {
      width: 100%;
      padding: 13px;
      margin: 8px 0;
      border-radius: 7px;
      font-size: 16px;
    }

    input, select {
      border: 1px solid #ccd5df;
      background: white;
    }

    button {
      border: none;
      background: #075e54;
      color: white;
      font-weight: bold;
      cursor: pointer;
    }

    button:hover {
      background: #064b43;
    }

    .services {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
      margin-top: 25px;
    }

    .service {
      background: #e8f5f1;
      padding: 18px 10px;
      text-align: center;
      border-radius: 8px;
    }

    footer {
      text-align: center;
      padding: 25px;
      color: #667085;
    }
  </style>
</head>

<body>

  <header>
    <h1>TrouveMoi</h1>
    <p>Trouvez le bon professionnel près de chez vous.</p>
  </header>

  <main>
    <section class="card">
      <h2>Quel professionnel recherchez-vous ?</h2>

      <p>
        Recherchez un artisan ou un prestataire de services au Bénin.
      </p>

      <form id="searchForm">
        <input
          type="text"
          id="service"
          placeholder="Ex. : plombier, mécanicien, électricien"
          required
        >

        <select id="city">
          <option value="">Toutes les villes</option>
          <option value="Cotonou">Cotonou</option>
          <option value="Abomey-Calavi">Abomey-Calavi</option>
        </select>

        <button type="submit">Rechercher</button>
      </form>

      <p id="message"></p>
    </section>

    <section class="services">
      <div class="service">Plombier</div>
      <div class="service">Électricien</div>
      <div class="service">Mécanicien</div>
      <div class="service">Maçon</div>
      <div class="service">Réparateur de téléphones</div>
      <div class="service">Soudeur</div>
    </section>
  </main>

  <footer>
    TrouveMoi - La plateforme qui vous rapproche des professionnels.
  </footer>

  <script>
    document
      .getElementById("searchForm")
      .addEventListener("submit", function(event) {
        event.preventDefault();

        const service = document
          .getElementById("service")
          .value.trim();

        const city = document.getElementById("city").value;
        const message = document.getElementById("message");

        message.textContent =
          "Votre recherche de " + service +
          (city ? " à " + city : "") +
          " a été enregistrée. L'annuaire des professionnels sera bientôt disponible.";
      });
  </script>

</body>
</html>
  `);
});

// Vérifier que le serveur fonctionne
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    application: "TrouveMoi"
  });
});

// Vérifier la connexion à PostgreSQL
app.get("/health/database", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.status(200).json({
      status: "ok",
      database: "connected",
      application: "TrouveMoi"
    });
  } catch (error) {
    console.error(
      "Erreur de connexion à PostgreSQL:",
      error.message
    );

    res.status(503).json({
      status: "error",
      database: "unavailable"
    });
  }
});

// Démarrer le serveur
app.listen(PORT, "0.0.0.0", () => {
  console.log("TrouveMoi est lancé sur le port " + PORT);
});
