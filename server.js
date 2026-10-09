const express = require("express");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error("Erreur : DATABASE_URL n'est pas configuree.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

pool.on("error", (error) => {
  console.error("Erreur de connexion a la base de donnees :", error.message);
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get("/", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="fr">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>TrouveMoi - Trouvez un professionnel</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          margin: 0;
          background: #f4f7fb;
          color: #222;
        }
        header {
          background: #087f5b;
          color: white;
          padding: 25px 15px;
          text-align: center;
        }
        main {
          max-width: 850px;
          margin: 30px auto;
          padding: 20px;
        }
        .card {
          background: white;
          padding: 25px;
          border-radius: 12px;
          box-shadow: 0 3px 12px rgba(0,0,0,0.08);
        }
        input, button {
          box-sizing: border-box;
          width: 100%;
          padding: 13px;
          margin: 8px 0;
          border-radius: 6px;
          font-size: 16px;
        }
        input {
          border: 1px solid #ccc;
        }
        button, .link-button {
          background: #087f5b;
          color: white;
          border: none;
          cursor: pointer;
          text-decoration: none;
          display: inline-block;
          text-align: center;
        }
        .link-button {
          box-sizing: border-box;
          width: 100%;
          padding: 13px;
          border-radius: 6px;
          margin-top: 12px;
        }
        footer {
          text-align: center;
          padding: 20px;
          color: #666;
        }
      </style>
    </head>
    <body>
      <header>
        <h1>TrouveMoi</h1>
        <p>Trouvez facilement un professionnel pres de chez vous.</p>
      </header>

      <main>
        <section class="card">
          <h2>Rechercher un professionnel</h2>

          <form action="/" method="GET">
            <input
              type="text"
              name="profession"
              placeholder="Quel professionnel recherchez-vous ?"
            >

            <input
              type="text"
              name="city"
              placeholder="Dans quelle ville ?"
            >

            <button type="submit">Rechercher</button>
          </form>

          <a class="link-button" href="/devenir-professionnel">
            Devenir professionnel
          </a>
        </section>

        <section class="card" style="margin-top: 20px;">
          <h2>Vous proposez des services ?</h2>
          <p>
            Inscrivez votre candidature pour rejoindre la plateforme
            TrouveMoi.
          </p>
          <a class="link-button" href="/devenir-professionnel">
            Soumettre ma candidature
          </a>
        </section>
      </main>

      <footer>
        TrouveMoi - Mise en relation entre clients et professionnels au Benin.
      </footer>
    </body>
    </html>
  `);
});

app.get("/devenir-professionnel", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="fr">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Devenir professionnel - TrouveMoi</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          background: #f4f7fb;
          margin: 0;
          padding: 20px;
          color: #222;
        }
        main {
          max-width: 650px;
          margin: 20px auto;
          background: white;
          padding: 25px;
          border-radius: 12px;
          box-shadow: 0 3px 12px rgba(0,0,0,0.08);
        }
        input, textarea, select, button {
          box-sizing: border-box;
          display: block;
          width: 100%;
          padding: 12px;
          margin: 8px 0 16px;
          font-size: 16px;
          border-radius: 6px;
        }
        input, textarea, select {
          border: 1px solid #ccc;
        }
        button {
          background: #087f5b;
          color: white;
          border: none;
          cursor: pointer;
        }
        a {
          color: #087f5b;
        }
      </style>
    </head>
    <body>
      <main>
        <h1>Devenir professionnel sur TrouveMoi</h1>
        <p>Remplissez le formulaire pour soumettre votre candidature.</p>

        <form action="/candidatures" method="POST">
          <label for="full_name">Nom et prenoms *</label>
          <input id="full_name" name="full_name" required maxlength="150">

          <label for="phone">Telephone *</label>
          <input id="phone" name="phone" type="tel" required maxlength="30">

          <label for="city">Ville *</label>
          <input id="city" name="city" required maxlength="100">

          <label for="neighborhood">Quartier</label>
          <input id="neighborhood" name="neighborhood" maxlength="150">

          <label for="profession">Profession ou service propose *</label>
          <input id="profession" name="profession" required maxlength="150">

          <label for="experience">Experience</label>
          <select id="experience" name="experience">
            <option value="">Selectionnez une option</option>
            <option value="Debutant">Debutant</option>
            <option value="Moins de 2 ans">Moins de 2 ans</option>
            <option value="2 a 5 ans">2 a 5 ans</option>
            <option value="Plus de 5 ans">Plus de 5 ans</option>
          </select>

          <label for="service_description">Description de vos services *</label>
          <textarea
            id="service_description"
            name="service_description"
            rows="5"
            required
            maxlength="3000"
          ></textarea>

          <label for="service_area">Zones d'intervention</label>
          <input id="service_area" name="service_area" maxlength="300">

          <label for="availability">Disponibilite</label>
          <select id="availability" name="availability">
            <option value="">Selectionnez une option</option>
            <option value="Disponible immediatement">Disponible immediatement</option>
            <option value="Sur rendez-vous">Sur rendez-vous</option>
            <option value="A temps partiel">A temps partiel</option>
          </select>

          <button type="submit">Envoyer ma candidature</button>
        </form>

        <p><a href="/">Retour a l'accueil</a></p>
      </main>
    </body>
    </html>
  `);
});

app.post("/candidatures", async (req, res) => {
  const {
    full_name,
    phone,
    city,
    neighborhood,
    profession,
    experience,
    service_description,
    service_area,
    availability
  } = req.body;

  if (
    !full_name ||
    !phone ||
    !city ||
    !profession ||
    !service_description
  ) {
    return res.status(400).send(`
      <h2>Informations manquantes</h2>
      <p>Veuillez remplir tous les champs obligatoires.</p>
      <a href="/devenir-professionnel">Retour au formulaire</a>
    `);
  }

  try {
    const query = `
      INSERT INTO professional_applications (
        full_name,
        phone,
        city,
        neighborhood,
        profession,
        experience,
        service_description,
        service_area,
        availability,
        npi,
        status
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, 'pending')
      RETURNING id
    `;

    const values = [
      full_name.trim(),
      phone.trim(),
      city.trim(),
      neighborhood || null,
      profession.trim(),
      experience || null,
      service_description.trim(),
      service_area || null,
      availability || null
    ];

    const result = await pool.query(query, values);

    res.status(201).send(`
      <!DOCTYPE html>
      <html lang="fr">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Candidature envoyee - TrouveMoi</title>
      </head>
      <body style="font-family:Arial,sans-serif;padding:30px;text-align:center;">
        <h1>Candidature envoyee avec succes !</h1>
        <p>Votre candidature a bien ete enregistree.</p>
        <p>Reference de candidature : ${result.rows[0].id}</p>
        <p>Elle devra etre examinee avant toute publication de votre profil.</p>
        <a href="/">Retour a l'accueil</a>
      </body>
      </html>
    `);
  } catch (error) {
    console.error("Erreur lors de l'enregistrement :", error.message);

    res.status(500).send(`
      <h2>Impossible d'enregistrer la candidature</h2>
      <p>Une erreur technique est survenue. Veuillez reessayer plus tard.</p>
      <a href="/devenir-professionnel">Retour au formulaire</a>
    `);
  }
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    application: "TrouveMoi"
  });
});

app.get("/health/database", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      database: "connected",
      application: "TrouveMoi"
    });
  } catch (error) {
    console.error("Verification de la base impossible :", error.message);

    res.status(500).json({
      status: "error",
      database: "disconnected",
      application: "TrouveMoi"
    });
  }
});

async function startServer() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS professional_applications (
        id SERIAL PRIMARY KEY,
        full_name VARCHAR(150) NOT NULL,
        phone VARCHAR(30) NOT NULL,
        city VARCHAR(100) NOT NULL,
        neighborhood VARCHAR(150),
        profession VARCHAR(150) NOT NULL,
        experience VARCHAR(100),
        service_description TEXT NOT NULL,
        service_area VARCHAR(300),
        availability VARCHAR(100),
        npi VARCHAR(100),
        status VARCHAR(30) NOT NULL DEFAULT 'pending',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      ALTER TABLE professional_applications
      ALTER COLUMN npi DROP NOT NULL
    `);

    console.log("Table des candidatures prete.");

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`TrouveMoi demarre sur le port ${PORT}.`);
    });
  } catch (error) {
    console.error("Erreur au demarrage :", error);
    process.exit(1);
  }
}

startServer();
