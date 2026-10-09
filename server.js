const express = require("express");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

// Connexion à PostgreSQL
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
      background: #f4f7fb;
      color: #222;
    }

    header {
      background: #087443;
      color: white;
      padding: 25px 15px;
      text-align: center;
    }

    header h1 {
      margin: 0 0 10px;
      font-size: 32px;
    }

    header p {
      margin: 0;
      font-size: 16px;
    }

    main {
      max-width: 900px;
      margin: 30px auto;
      padding: 0 15px;
    }

    .search-box {
      background: white;
      padding: 25px;
      border-radius: 12px;
      box-shadow: 0 3px 12px rgba(0, 0, 0, 0.08);
    }

    h2 {
      color: #087443;
    }

    form {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 20px;
    }

    input, select, button {
      padding: 13px;
      font-size: 16px;
      border-radius: 6px;
    }

    input, select {
      flex: 1;
      min-width: 180px;
      border: 1px solid #ccc;
    }

    button {
      background: #087443;
      color: white;
      border: none;
      cursor: pointer;
    }

    button:hover {
      background: #065c35;
    }

    .services {
      margin-top: 30px;
    }

    .service-list {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 15px;
    }

    .service {
      background: white;
      padding: 20px 10px;
      text-align: center;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
    }

    #message {
      margin-top: 15px;
      color: #087443;
    }

    footer {
      margin-top: 40px;
      background: #173b2b;
      color: white;
      text-align: center;
      padding: 20px 10px;
    }
  </style>
</head>
<body>

  <header>
    <h1>TrouveMoi</h1>
    <p>Trouvez le bon professionnel près de chez vous.</p>
  </header>

  <main>
    <section class="search-box">
      <h2>Quel professionnel recherchez-vous ?</h2>
      <p>Recherchez un artisan ou un prestataire de services au Bénin.</p>

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
      <h2>Services recherchés</h2>

      <div class="service-list">
        <div class="service">Plombier</div>
        <div class="service">Électricien</div>
        <div class="service">Mécanicien</div>
        <div class="service">Maçon</div>
        <div class="service">Réparateur de téléphones</div>
        <div class="service">Soudeur</div>
      </div>
    </section>
  </main>

  <footer>
    TrouveMoi - La plateforme qui vous rapproche des professionnels.
  </footer>

  <script>
    document.getElementById("searchForm").addEventListener("submit", function(event) {
      event.preventDefault();

      const service = document.getElementById("service").value.trim();
      const city = document.getElementById("city").value;
      const message = document.getElementById("message");

      if (service) {
        message.textContent =
          "Votre recherche : " + service +
          (city ? " à " + city : "") +
          ". Le répertoire des professionnels sera bientôt disponible.";
      }
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
    console.error("Erreur PostgreSQL:", error.message);

    res.status(503).json({
      status: "error",
      database: "unavailable"
    });
  }
});

// Créer la table des candidatures et démarrer le serveur
async function startServer() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS professional_applications (
        id BIGSERIAL PRIMARY KEY,
        full_name VARCHAR(150) NOT NULL,
        npi VARCHAR(100) NOT NULL,
        phone VARCHAR(30) NOT NULL,
        city VARCHAR(100) NOT NULL,
        neighborhood VARCHAR(150),
        profession VARCHAR(150) NOT NULL,
        experience TEXT,
        service_description TEXT NOT NULL,
        service_area VARCHAR(200),
        availability VARCHAR(200),
        identity_document_path TEXT,
        portrait_path TEXT,
        full_body_photo_path TEXT,
        work_photo_path TEXT,
        portfolio_photo_path TEXT,
        status VARCHAR(30) NOT NULL DEFAULT 'pending'
          CHECK (
            status IN (
              'pending',
              'under_review',
              'approved',
              'rejected',
              'corrections_requested'
            )
          ),
        admin_notes TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    console.log("Table des candidatures prête.");

    app.listen(PORT, "0.0.0.0", () => {
      console.log("TrouveMoi est lancé sur le port " + PORT);
    });
  } catch (error) {
    console.error("Erreur au démarrage de TrouveMoi:", error.message);
    process.exit(1);
  }
}

startServer();
