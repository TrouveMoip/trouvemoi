const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

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
  console.error("Erreur de base de donnees :", error.message);
});

app.use(express.urlencoded({ extended: true, limit: "20kb" }));
app.use(express.json({ limit: "20kb" }));
app.disable("x-powered-by");

const SESSION_COOKIE = "tm_admin_session";
const SESSION_DURATION = 4 * 60 * 60 * 1000;

const ALLOWED_STATUSES = [
  "pending",
  "under_review",
  "approved",
  "rejected",
  "corrections_requested"
];

const STATUS_LABELS = {
  pending: "En attente",
  under_review: "En cours d'examen",
  approved: "Approuvee",
  rejected: "Refusee",
  corrections_requested: "Corrections demandees"
};

const JOB_STATUSES = ["pending", "approved", "rejected"];

const JOB_STATUS_LABELS = {
  pending: "En attente",
  approved: "Approuvee",
  rejected: "Refusee"
};

const JOB_CONTRACT_TYPES = [
  "CDI",
  "CDD",
  "Stage",
  "Interim",
  "Freelance",
  "Apprentissage",
  "Autre"
];

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => {
    const entities = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    };

    return entities[character];
  });
}

function safeEqual(first, second) {
  const firstBuffer = Buffer.from(String(first));
  const secondBuffer = Buffer.from(String(second));

  if (firstBuffer.length !== secondBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(firstBuffer, secondBuffer);
}

function createSessionToken(payload) {
  const secret = process.env.ADMIN_SESSION_SECRET;

  if (!secret || secret.length < 32) {
    throw new Error(
      "ADMIN_SESSION_SECRET doit contenir au moins 32 caracteres."
    );
  }

  const encodedPayload = Buffer
    .from(JSON.stringify(payload))
    .toString("base64url");

  const signature = crypto
    .createHmac("sha256", secret)
    .update(encodedPayload)
    .digest("base64url");

  return `${encodedPayload}.${signature}`;
}

function verifySessionToken(token) {
  try {
    if (!token || !process.env.ADMIN_SESSION_SECRET) {
      return null;
    }

    const parts = token.split(".");

    if (parts.length !== 2) {
      return null;
    }

    const [encodedPayload, signature] = parts;

    const expectedSignature = crypto
      .createHmac("sha256", process.env.ADMIN_SESSION_SECRET)
      .update(encodedPayload)
      .digest("base64url");

    if (!safeEqual(signature, expectedSignature)) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(encodedPayload, "base64url").toString("utf8")
    );

    if (
      payload.expiresAt <= Date.now() ||
      typeof payload.csrf !== "string"
    ) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function readCookie(req, name) {
  const cookieHeader = req.headers.cookie || "";

  for (const item of cookieHeader.split(";")) {
    const separator = item.indexOf("=");

    if (separator === -1) {
      continue;
    }

    const key = item.slice(0, separator).trim();
    const value = item.slice(separator + 1).trim();

    if (key === name) {
      return value;
    }
  }

  return null;
}

function setSessionCookie(res, token) {
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_DURATION / 1000}`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
  );
}

function requireAdmin(req, res, next) {
  const token = readCookie(req, SESSION_COOKIE);
  const session = verifySessionToken(token);

  if (!session) {
    clearSessionCookie(res);
    return res.redirect(303, "/admin");
  }

  req.adminSession = session;
  next();
}

function verifyCsrf(req, res, next) {
  const submittedToken = req.body.csrfToken;
  const sessionToken = req.adminSession?.csrf;

  if (
    typeof submittedToken !== "string" ||
    typeof sessionToken !== "string" ||
    !safeEqual(submittedToken, sessionToken)
  ) {
    return res.status(403).send(
      page(
        "Requete refusee",
        "<h1>Requete refusee</h1><p>Veuillez actualiser la page et reessayer.</p>"
      )
    );
  }

  next();
}

function page(title, content) {
  return `
    <!DOCTYPE html>
    <html lang="fr">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${escapeHtml(title)} - TrouveMoi</title>

      <style>
        * {
          box-sizing: border-box;
        }

        body {
          font-family: Arial, sans-serif;
          margin: 0;
          padding: 20px;
          background: #f4f7fb;
          color: #222;
        }

        header {
          background: #087f5b;
          color: white;
          padding: 22px;
          text-align: center;
          border-radius: 10px;
        }

        main {
          max-width: 1000px;
          margin: 24px auto;
        }

        .card {
          background: white;
          padding: 22px;
          margin-bottom: 18px;
          border-radius: 10px;
          box-shadow: 0 3px 12px rgba(0,0,0,0.07);
        }

        input,
        textarea,
        select,
        button {
          width: 100%;
          padding: 12px;
          margin: 8px 0 14px;
          border-radius: 6px;
          font-size: 16px;
        }

        input,
        textarea,
        select {
          border: 1px solid #ccc;
          background: white;
        }

        button,
        .button {
          display: inline-block;
          border: none;
          background: #087f5b;
          color: white;
          padding: 12px 16px;
          border-radius: 6px;
          cursor: pointer;
          text-decoration: none;
          text-align: center;
        }

        .danger {
          background: #b42318;
        }

        .secondary {
          background: #475467;
        }

        .muted {
          color: #667085;
        }

        .actions {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
        }

        .actions form {
          flex: 1 1 150px;
        }

        .actions button {
          margin: 0;
        }

        a {
          color: #087f5b;
        }

        .contact-buttons {
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
          margin-top: 16px;
        }

        .contact-buttons .button {
          flex: 1 1 180px;
        }

        .whatsapp {
          background: #128c7e;
        }

        .email {
          background: #475467;
        }

        @media (max-width: 600px) {
          body {
            padding: 12px;
          }

          .card {
            padding: 16px;
          }
        }
      </style>
    </head>

    <body>
      <header>
        <h1>
          <a href="/" style="color:white;text-decoration:none">
            TrouveMoi
          </a>
        </h1>

        <p>La plateforme de mise en relation au Benin</p>

        <nav>
          <a href="/" style="color:white;margin:0 8px">
            Professionnels
          </a>

          <a href="/emplois" style="color:white;margin:0 8px">
            Emploi
          </a>

          <a href="/publier-emploi" style="color:white;margin:0 8px">
            Publier une offre
          </a>
        </nav>
      </header>

      <main>
        ${content}
      </main>
    </body>
    </html>
  `;
}

function normalizePhone(value) {
  return String(value || "").trim().replace(/[()\s.-]/g, "");
}

function validPhone(value) {
  return /^\+?[0-9]{8,15}$/.test(value);
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)
    && value.length <= 254;
}

function jobContactButtons(job) {
  const buttons = [];

  if (job.contact_phone) {
    buttons.push(`
      <a
        class="button"
        href="tel:${escapeHtml(normalizePhone(job.contact_phone))}"
      >
        Appeler le recruteur
      </a>
    `);
  }

  if (job.contact_whatsapp) {
    const whatsapp = normalizePhone(job.contact_whatsapp)
      .replace(/^\+/, "");

    buttons.push(`
      <a
        class="button whatsapp"
        href="https://wa.me/${escapeHtml(whatsapp)}?text=${encodeURIComponent(
          "Bonjour, j'ai consulte votre offre d'emploi sur TrouveMoi et je souhaite obtenir plus d'informations."
        )}"
        target="_blank"
        rel="noopener noreferrer"
      >
        Contacter sur WhatsApp
      </a>
    `);
  }

  if (job.contact_email) {
    buttons.push(`
      <a
        class="button email"
        href="mailto:${escapeHtml(job.contact_email)}?subject=${encodeURIComponent(
          "Candidature - " + job.job_title
        )}"
      >
        Envoyer un e-mail
      </a>
    `);
  }

  return buttons.length
    ? `<div class="contact-buttons">${buttons.join("")}</div>`
    : "";
}

/* PAGE D'ACCUEIL ET RECHERCHE DES PROFESSIONNELS */

app.get("/", async (req, res) => {
  try {
    const profession = String(req.query.profession || "")
      .trim()
      .slice(0, 150);

    const city = String(req.query.city || "")
      .trim()
      .slice(0, 100);

    let query = `
      SELECT
        id,
        full_name,
        city,
        neighborhood,
        profession,
        experience,
        service_description,
        service_area,
        availability
      FROM professional_applications
      WHERE status = 'approved'
    `;

    const values = [];

    if (profession) {
      values.push(`%${profession}%`);
      query += ` AND profession ILIKE $${values.length}`;
    }

    if (city) {
      values.push(`%${city}%`);
      query += ` AND city ILIKE $${values.length}`;
    }

    query += " ORDER BY created_at DESC LIMIT 50";

    const result = await pool.query(query, values);

    const professionals = result.rows.map((person) => `
      <article class="card">
        <h2>${escapeHtml(person.profession)}</h2>

        <p>
          <strong>Professionnel :</strong>
          ${escapeHtml(person.full_name)}
        </p>

        <p>
          <strong>Ville :</strong>
          ${escapeHtml(person.city)}
        </p>

        ${person.neighborhood
          ? `<p><strong>Quartier :</strong> ${escapeHtml(person.neighborhood)}</p>`
          : ""}

        ${person.experience
          ? `<p><strong>Experience :</strong> ${escapeHtml(person.experience)}</p>`
          : ""}

        <p>${escapeHtml(person.service_description)}</p>

        ${person.service_area
          ? `<p><strong>Zone d'intervention :</strong> ${escapeHtml(person.service_area)}</p>`
          : ""}

        ${person.availability
          ? `<p><strong>Disponibilite :</strong> ${escapeHtml(person.availability)}</p>`
          : ""}
      </article>
    `).join("");

    const content = `
      <section class="card">
        <h2>Rechercher un professionnel</h2>

        <form action="/" method="GET">
          <label for="profession">Metier ou service</label>

          <input
            id="profession"
            name="profession"
            value="${escapeHtml(profession)}"
            placeholder="Exemple : plombier"
          >

          <label for="city">Ville</label>

          <input
            id="city"
            name="city"
            value="${escapeHtml(city)}"
            placeholder="Exemple : Cotonou"
          >

          <button type="submit">Rechercher</button>
        </form>

        <a class="button" href="/devenir-professionnel">
          Devenir professionnel
        </a>

        <a class="button" href="/emplois">
          Consulter les offres d'emploi
        </a>
      </section>

      <h2>Professionnels disponibles</h2>

      ${professionals || `
        <section class="card">
          <p>
            Aucun professionnel approuve ne correspond a votre recherche.
          </p>
        </section>
      `}

      <p>
        <a href="/devenir-professionnel">Proposer mes services</a>
      </p>
    `;

    res.send(page("Accueil", content));
  } catch (error) {
    console.error("Erreur sur la page d'accueil :", error.message);

    res.status(500).send(
      page("Erreur", "<h2>Une erreur technique est survenue.</h2>")
    );
  }
});

/* FORMULAIRE PROFESSIONNEL */

app.get("/devenir-professionnel", (req, res) => {
  const content = `
    <section class="card">
      <h1>Devenir professionnel sur TrouveMoi</h1>

      <p>
        Remplissez le formulaire pour soumettre votre candidature.
      </p>

      <form action="/candidatures" method="POST">
        <label for="full_name">Nom et prenoms *</label>
        <input
          id="full_name"
          name="full_name"
          required
          maxlength="150"
        >

        <label for="phone">Telephone *</label>
        <input
          id="phone"
          name="phone"
          type="tel"
          required
          maxlength="30"
        >

        <label for="city">Ville *</label>
        <input
          id="city"
          name="city"
          required
          maxlength="100"
        >

        <label for="neighborhood">Quartier</label>
        <input
          id="neighborhood"
          name="neighborhood"
          maxlength="150"
        >

        <label for="profession">Profession ou service propose *</label>
        <input
          id="profession"
          name="profession"
          required
          maxlength="150"
        >

        <label for="experience">Experience</label>

        <select id="experience" name="experience">
          <option value="">Selectionnez une option</option>
          <option value="Debutant">Debutant</option>
          <option value="Moins de 2 ans">Moins de 2 ans</option>
          <option value="2 a 5 ans">2 a 5 ans</option>
          <option value="Plus de 5 ans">Plus de 5 ans</option>
        </select>

        <label for="service_description">
          Description des services *
        </label>

        <textarea
          id="service_description"
          name="service_description"
          rows="5"
          required
          maxlength="3000"
        ></textarea>

        <label for="service_area">Zones d'intervention</label>
        <input
          id="service_area"
          name="service_area"
          maxlength="300"
        >

        <label for="availability">Disponibilite</label>

        <select id="availability" name="availability">
          <option value="">Selectionnez une option</option>
          <option value="Disponible immediatement">
            Disponible immediatement
          </option>
          <option value="Sur rendez-vous">Sur rendez-vous</option>
          <option value="A temps partiel">A temps partiel</option>
        </select>

        <button type="submit">Envoyer ma candidature</button>
      </form>

      <p><a href="/">Retour a l'accueil</a></p>
    </section>
  `;

  res.send(page("Devenir professionnel", content));
});

/* ENREGISTREMENT DES CANDIDATURES PROFESSIONNELLES */

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
    typeof full_name !== "string" ||
    typeof phone !== "string" ||
    typeof city !== "string" ||
    typeof profession !== "string" ||
    typeof service_description !== "string" ||
    !full_name.trim() ||
    !phone.trim() ||
    !city.trim() ||
    !profession.trim() ||
    !service_description.trim()
  ) {
    return res.status(400).send(
      page(
        "Informations manquantes",
        '<section class="card"><h2>Informations manquantes</h2><a href="/devenir-professionnel">Retour au formulaire</a></section>'
      )
    );
  }

  try {
    const result = await pool.query(`
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
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL,'pending')
      RETURNING id
    `, [
      full_name.trim().slice(0, 150),
      phone.trim().slice(0, 30),
      city.trim().slice(0, 100),
      typeof neighborhood === "string"
        ? neighborhood.trim().slice(0, 150) || null
        : null,
      profession.trim().slice(0, 150),
      typeof experience === "string"
        ? experience.slice(0, 100) || null
        : null,
      service_description.trim().slice(0, 3000),
      typeof service_area === "string"
        ? service_area.trim().slice(0, 300) || null
        : null,
      typeof availability === "string"
        ? availability.slice(0, 100) || null
        : null
    ]);

    res.status(201).send(
      page(
        "Candidature envoyee",
        `
          <section class="card">
            <h1>Candidature envoyee avec succes !</h1>
            <p>Votre candidature a bien ete enregistree.</p>
            <p>Reference : ${escapeHtml(result.rows[0].id)}</p>
            <p>Votre profil ne sera visible qu'apres approbation.</p>
            <a class="button" href="/">Retour a l'accueil</a>
          </section>
        `
      )
    );
  } catch (error) {
    console.error(
      "Erreur lors de l'enregistrement :",
      error.message
    );

    res.status(500).send(
      page(
        "Erreur",
        "<section class='card'><h2>Impossible d'enregistrer la candidature.</h2><p>Veuillez reessayer plus tard.</p></section>"
      )
    );
  }
});

/* PAGE DE RECHERCHE DES EMPLOIS */

app.get("/emplois", async (req, res) => {
  try {
    const keyword = String(req.query.keyword || "")
      .trim()
      .slice(0, 150);

    const city = String(req.query.city || "")
      .trim()
      .slice(0, 100);

    const contract = String(req.query.contract || "")
      .trim()
      .slice(0, 50);

    let query = `
      SELECT
        id,
        company_name,
        job_title,
        city,
        contract_type,
        salary,
        description,
        qualifications,
        contact_phone,
        contact_whatsapp,
        contact_email,
        deadline,
        created_at
      FROM job_offers
      WHERE status = 'approved'
        AND (deadline IS NULL OR deadline >= CURRENT_DATE)
    `;

    const values = [];

    if (keyword) {
      values.push(`%${keyword}%`);

      query += `
        AND (
          job_title ILIKE $${values.length}
          OR company_name ILIKE $${values.length}
          OR description ILIKE $${values.length}
        )
      `;
    }

    if (city) {
      values.push(`%${city}%`);
      query += ` AND city ILIKE $${values.length}`;
    }

    if (contract && JOB_CONTRACT_TYPES.includes(contract)) {
      values.push(contract);
      query += ` AND contract_type = $${values.length}`;
    }

    query += " ORDER BY created_at DESC LIMIT 100";

    const result = await pool.query(query, values);

    const jobs = result.rows.map((job) => `
      <article class="card">
        <h2>${escapeHtml(job.job_title)}</h2>

        <p>
          <strong>Entreprise :</strong>
          ${escapeHtml(job.company_name)}
        </p>

        <p>
          <strong>Ville :</strong>
          ${escapeHtml(job.city)}
        </p>

        <p>
          <strong>Contrat :</strong>
          ${escapeHtml(job.contract_type)}
        </p>

        ${job.salary
          ? `<p><strong>Salaire :</strong> ${escapeHtml(job.salary)}</p>`
          : ""}

        <p>
          ${escapeHtml(job.description).replace(/\n/g, "<br>")}
        </p>

        ${job.qualifications
          ? `<p><strong>Profil recherche :</strong> ${escapeHtml(job.qualifications).replace(/\n/g, "<br>")}</p>`
          : ""}

        ${job.deadline
          ? `<p><strong>Date limite :</strong> ${escapeHtml(job.deadline)}</p>`
          : ""}

        ${jobContactButtons(job)}
      </article>
    `).join("");

    const contractOptions = JOB_CONTRACT_TYPES.map((type) => `
      <option
        value="${escapeHtml(type)}"
        ${contract === type ? "selected" : ""}
      >
        ${escapeHtml(type)}
      </option>
    `).join("");

    res.send(
      page(
        "Offres d'emploi",
        `
          <section class="card">
            <h1>Rechercher un emploi</h1>

            <form action="/emplois" method="GET">
              <label for="keyword">
                Metier, poste ou entreprise
              </label>

              <input
                id="keyword"
                name="keyword"
                value="${escapeHtml(keyword)}"
                placeholder="Ex. : commercial"
              >

              <label for="city">Ville</label>

              <input
                id="city"
                name="city"
                value="${escapeHtml(city)}"
                placeholder="Ex. : Cotonou"
              >

              <label for="contract">Type de contrat</label>

              <select id="contract" name="contract">
                <option value="">Tous les contrats</option>
                ${contractOptions}
              </select>

              <button type="submit">Rechercher</button>
            </form>

            <a class="button" href="/publier-emploi">
              Publier gratuitement une offre
            </a>
          </section>

          <h2>Offres disponibles (${result.rows.length})</h2>

          ${jobs || `
            <section class="card">
              <p>
                Aucune offre ne correspond a votre recherche pour le moment.
              </p>
            </section>
          `}
        `
      )
    );
  } catch (error) {
    console.error(
      "Erreur lors de la recherche d'emplois :",
      error.message
    );

    res.status(500).send(
      page(
        "Erreur",
        "<section class='card'><h2>Impossible de charger les offres d'emploi.</h2></section>"
      )
    );
  }
});

/* FORMULAIRE DE PUBLICATION D'EMPLOI */

app.get("/publier-emploi", (req, res) => {
  const contractOptions = JOB_CONTRACT_TYPES.map((type) => `
    <option value="${escapeHtml(type)}">
      ${escapeHtml(type)}
    </option>
  `).join("");

  res.send(
    page(
      "Publier une offre d'emploi",
      `
        <section class="card">
          <h1>Publier gratuitement une offre d'emploi</h1>

          <p>
            La publication est gratuite. Votre offre sera verifiee
            par l'administration avant d'etre visible.
          </p>

          <form action="/offres-emploi" method="POST">
            <label for="company_name">
              Nom de l'entreprise ou du recruteur *
            </label>

            <input
              id="company_name"
              name="company_name"
              required
              maxlength="200"
            >

            <label for="job_title">Intitule du poste *</label>

            <input
              id="job_title"
              name="job_title"
              required
              maxlength="200"
            >

            <label for="city">Ville *</label>

            <input
              id="city"
              name="city"
              required
              maxlength="100"
            >

            <label for="contract_type">Type de contrat *</label>

            <select id="contract_type" name="contract_type" required>
              <option value="">Choisir</option>
              ${contractOptions}
            </select>

            <label for="salary">Salaire (facultatif)</label>

            <input
              id="salary"
              name="salary"
              maxlength="100"
              placeholder="Ex. : 100 000 FCFA/mois"
            >

            <label for="description">
              Description du poste *
            </label>

            <textarea
              id="description"
              name="description"
              required
              maxlength="8000"
              rows="6"
            ></textarea>

            <label for="qualifications">
              Qualifications et competences recherchees
            </label>

            <textarea
              id="qualifications"
              name="qualifications"
              maxlength="4000"
              rows="4"
            ></textarea>

            <fieldset style="border:1px solid #ddd;border-radius:8px;padding:14px">
              <legend>
                Moyens de contact (au moins un obligatoire) *
              </legend>

              <p>
                Cochez un ou plusieurs moyens de contact.
                Remplissez le champ correspondant a chaque moyen choisi.
              </p>

              <label>
                <input
                  style="width:auto"
                  type="checkbox"
                  id="use_phone"
                  name="use_phone"
                  value="yes"
                >
                Appel direct
              </label>

              <label for="contact_phone">
                Numero de telephone
              </label>

              <input
                id="contact_phone"
                name="contact_phone"
                type="tel"
                maxlength="30"
                placeholder="+229..."
              >

              <label>
                <input
                  style="width:auto"
                  type="checkbox"
                  id="use_whatsapp"
                  name="use_whatsapp"
                  value="yes"
                >
                WhatsApp
              </label>

              <label for="contact_whatsapp">
                Numero WhatsApp
              </label>

              <input
                id="contact_whatsapp"
                name="contact_whatsapp"
                type="tel"
                maxlength="30"
                placeholder="+229..."
              >

              <label>
                <input
                  style="width:auto"
                  type="checkbox"
                  id="use_email"
                  name="use_email"
                  value="yes"
                >
                E-mail
              </label>

              <label for="contact_email">
                Adresse e-mail
              </label>

              <input
                id="contact_email"
                name="contact_email"
                type="email"
                maxlength="254"
                placeholder="recrutement@entreprise.com"
              >
            </fieldset>

            <label for="deadline">
              Date limite de candidature (facultatif)
            </label>

            <input
              id="deadline"
              name="deadline"
              type="date"
            >

            <button type="submit">
              Soumettre l'offre gratuitement
            </button>
          </form>

          <p>
            <a href="/emplois">Retour aux offres d'emploi</a>
          </p>
        </section>

        <script>
          const form = document.querySelector('form');

          form.addEventListener('submit', function(event) {
            const methods = [
              ['use_phone', 'contact_phone'],
              ['use_whatsapp', 'contact_whatsapp'],
              ['use_email', 'contact_email']
            ];

            const selected = methods.filter(
              ([check]) => document.getElementById(check).checked
            );

            if (!selected.length) {
              event.preventDefault();
              alert('Choisissez au moins un moyen de contact.');
              return;
            }

            const missing = selected.find(
              ([check, field]) =>
                !document.getElementById(field).value.trim()
            );

            if (missing) {
              event.preventDefault();

              alert(
                'Veuillez renseigner les coordonnees de chaque moyen de contact selectionne.'
              );
            }
          });
        </script>
      `
    )
  );
});

/* ENREGISTREMENT DES OFFRES : EN ATTENTE DE VALIDATION */

app.post("/offres-emploi", async (req, res) => {
  const {
    company_name,
    job_title,
    city,
    contract_type,
    salary,
    description,
    qualifications,
    contact_phone,
    contact_whatsapp,
    contact_email,
    deadline,
    use_phone,
    use_whatsapp,
    use_email
  } = req.body;

  const company = typeof company_name === "string"
    ? company_name.trim()
    : "";

  const title = typeof job_title === "string"
    ? job_title.trim()
    : "";

  const jobCity = typeof city === "string"
    ? city.trim()
    : "";

  const contract = typeof contract_type === "string"
    ? contract_type.trim()
    : "";

  const jobDescription = typeof description === "string"
    ? description.trim()
    : "";

  const phone =
    use_phone === "yes" && typeof contact_phone === "string"
      ? normalizePhone(contact_phone)
      : null;

  const whatsapp =
    use_whatsapp === "yes" && typeof contact_whatsapp === "string"
      ? normalizePhone(contact_whatsapp)
      : null;

  const email =
    use_email === "yes" && typeof contact_email === "string"
      ? contact_email.trim()
      : null;

  const jobDeadline =
    typeof deadline === "string" && deadline.trim()
      ? deadline.trim()
      : null;

  if (
    !company ||
    !title ||
    !jobCity ||
    !jobDescription ||
    !JOB_CONTRACT_TYPES.includes(contract)
  ) {
    return res.status(400).send(
      page(
        "Informations manquantes",
        `
          <section class="card">
            <h2>Informations obligatoires manquantes ou invalides.</h2>
            <a href="/publier-emploi">Retour au formulaire</a>
          </section>
        `
      )
    );
  }

  if (
    company.length > 200 ||
    title.length > 200 ||
    jobCity.length > 100 ||
    jobDescription.length > 8000
  ) {
    return res.status(400).send(
      page(
        "Informations trop longues",
        `
          <section class="card">
            <h2>Certains champs depassent la longueur autorisee.</h2>
            <a href="/publier-emploi">Retour au formulaire</a>
          </section>
        `
      )
    );
  }

  if (!phone && !whatsapp && !email) {
    return res.status(400).send(
      page(
        "Contact obligatoire",
        `
          <section class="card">
            <h2>
              Choisissez au moins un moyen de contact et renseignez ses coordonnees.
            </h2>
            <a href="/publier-emploi">Retour au formulaire</a>
          </section>
        `
      )
    );
  }

  if (phone && !validPhone(phone)) {
    return res.status(400).send(
      page(
        "Telephone invalide",
        `
          <section class="card">
            <h2>
              Le numero de telephone est invalide.
              Utilisez l'indicatif international, par exemple +229XXXXXXXX.
            </h2>
            <a href="/publier-emploi">Retour au formulaire</a>
          </section>
        `
      )
    );
  }

  if (whatsapp && !validPhone(whatsapp)) {
    return res.status(400).send(
      page(
        "WhatsApp invalide",
        `
          <section class="card">
            <h2>
              Le numero WhatsApp est invalide.
              Utilisez l'indicatif international, par exemple +229XXXXXXXX.
            </h2>
            <a href="/publier-emploi">Retour au formulaire</a>
          </section>
        `
      )
    );
  }

  if (email && !validEmail(email)) {
    return res.status(400).send(
      page(
        "E-mail invalide",
        `
          <section class="card">
            <h2>L'adresse e-mail est invalide.</h2>
            <a href="/publier-emploi">Retour au formulaire</a>
          </section>
        `
      )
    );
  }

  if (jobDeadline && !/^\d{4}-\d{2}-\d{2}$/.test(jobDeadline)) {
    return res.status(400).send(
      page(
        "Date invalide",
        `
          <section class="card">
            <h2>La date limite est invalide.</h2>
            <a href="/publier-emploi">Retour au formulaire</a>
          </section>
        `
      )
    );
  }

  try {
    await pool.query(`
      INSERT INTO job_offers (
        company_name,
        job_title,
        city,
        contract_type,
        salary,
        description,
        qualifications,
        contact_phone,
        contact_whatsapp,
        contact_email,
        deadline,
        status
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending')
    `, [
      company.slice(0, 200),
      title.slice(0, 200),
      jobCity.slice(0, 100),
      contract,
      typeof salary === "string"
        ? salary.trim().slice(0, 100) || null
        : null,
      jobDescription.slice(0, 8000),
      typeof qualifications === "string"
        ? qualifications.trim().slice(0, 4000) || null
        : null,
      phone,
      whatsapp,
      email,
      jobDeadline
    ]);

    res.status(201).send(
      page(
        "Offre soumise",
        `
          <section class="card">
            <h1>Votre offre a bien ete soumise</h1>

            <p>
              Merci ! Votre offre est en attente de verification
              par l'administration. Elle ne sera visible qu'apres approbation.
            </p>

            <a class="button" href="/emplois">
              Consulter les offres d'emploi
            </a>
          </section>
        `
      )
    );
  } catch (error) {
    console.error(
      "Erreur lors de l'enregistrement de l'offre :",
      error.message
    );

    res.status(500).send(
      page(
        "Erreur",
        `
          <section class="card">
            <h2>Impossible d'enregistrer l'offre pour le moment.</h2>
            <p>Veuillez reessayer plus tard.</p>
          </section>
        `
      )
    );
  }
});

/* CONNEXION ADMINISTRATEUR */

const loginAttempts = new Map();

app.get("/admin", (req, res) => {
  const session = verifySessionToken(
    readCookie(req, SESSION_COOKIE)
  );

  if (session) {
    return res.redirect(303, "/admin/candidatures");
  }

  const content = `
    <section class="card">
      <h1>Administration TrouveMoi</h1>

      <p>
        Connectez-vous pour gerer les candidatures et les offres d'emploi.
      </p>

      <form action="/admin/login" method="POST">
        <label for="password">Mot de passe administrateur</label>

        <input
          id="password"
          name="password"
          type="password"
          required
          maxlength="300"
          autocomplete="current-password"
        >

        <button type="submit">Se connecter</button>
      </form>

      <p><a href="/">Retour au site</a></p>
    </section>
  `;

  res.setHeader("Cache-Control", "no-store");
  res.send(page("Connexion administrateur", content));
});

app.post("/admin/login", (req, res) => {
  const now = Date.now();
  const address = req.ip || "unknown";
  const record = loginAttempts.get(address);

  if (record && now - record.startedAt > 15 * 60 * 1000) {
    loginAttempts.delete(address);
  }

  const current = loginAttempts.get(address);

  if (current && current.count >= 5) {
    return res.status(429).send(
      page(
        "Trop de tentatives",
        `
          <h2>Trop de tentatives de connexion.</h2>
          <p>Veuillez patienter 15 minutes avant de reessayer.</p>
        `
      )
    );
  }

  const configuredPassword = process.env.ADMIN_PASSWORD;
  const submittedPassword = req.body.password;

  if (
    !configuredPassword ||
    typeof submittedPassword !== "string" ||
    !safeEqual(submittedPassword, configuredPassword)
  ) {
    if (current) {
      current.count += 1;
    } else {
      loginAttempts.set(address, {
        count: 1,
        startedAt: now
      });
    }

    return res.status(401).send(
      page(
        "Connexion refusee",
        `
          <section class="card">
            <h2>Identifiants incorrects.</h2>
            <p><a href="/admin">Reessayer</a></p>
          </section>
        `
      )
    );
  }

  loginAttempts.delete(address);

  if (
    !process.env.ADMIN_SESSION_SECRET ||
    process.env.ADMIN_SESSION_SECRET.length < 32
  ) {
    console.error(
      "ADMIN_SESSION_SECRET est absente ou trop courte."
    );

    return res.status(500).send(
      page(
        "Configuration incomplete",
        `
          <h2>
            La configuration securisee de l'administration est incomplete.
          </h2>
        `
      )
    );
  }

  const session = {
    expiresAt: Date.now() + SESSION_DURATION,
    csrf: crypto.randomBytes(32).toString("hex")
  };

  setSessionCookie(res, createSessionToken(session));
  res.setHeader("Cache-Control", "no-store");

  res.redirect(303, "/admin/candidatures");
});

/* TABLEAU DE BORD ADMINISTRATEUR : CANDIDATURES PROFESSIONNELLES */

app.get(
  "/admin/candidatures",
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          id,
          full_name,
          phone,
          city,
          neighborhood,
          profession,
          experience,
          service_description,
          service_area,
          availability,
          status,
          created_at
        FROM professional_applications
        ORDER BY
          CASE WHEN status = 'pending' THEN 0 ELSE 1 END,
          created_at DESC
        LIMIT 200
      `);

      const applications = result.rows.map((candidate) => {
        const statusOptions = ALLOWED_STATUSES.map((status) => `
          <option
            value="${status}"
            ${candidate.status === status ? "selected" : ""}
          >
            ${STATUS_LABELS[status]}
          </option>
        `).join("");

        return `
          <article class="card">
            <h2>${escapeHtml(candidate.full_name)}</h2>

            <p>
              <strong>Reference :</strong>
              ${escapeHtml(candidate.id)}
            </p>

            <p>
              <strong>Telephone prive :</strong>
              ${escapeHtml(candidate.phone)}
            </p>

            <p>
              <strong>Ville :</strong>
              ${escapeHtml(candidate.city)}
            </p>

            <p>
              <strong>Quartier :</strong>
              ${escapeHtml(candidate.neighborhood || "Non renseigne")}
            </p>

            <p>
              <strong>Profession :</strong>
              ${escapeHtml(candidate.profession)}
            </p>

            <p>
              <strong>Experience :</strong>
              ${escapeHtml(candidate.experience || "Non renseignee")}
            </p>

            <p>
              <strong>Description :</strong>
              ${escapeHtml(candidate.service_description)}
            </p>

            <p>
              <strong>Zone :</strong>
              ${escapeHtml(candidate.service_area || "Non renseignee")}
            </p>

            <p>
              <strong>Disponibilite :</strong>
              ${escapeHtml(candidate.availability || "Non renseignee")}
            </p>

            <p>
              <strong>Statut actuel :</strong>
              ${escapeHtml(STATUS_LABELS[candidate.status] || candidate.status)}
            </p>

            <p class="muted">
              Reçue le : ${escapeHtml(candidate.created_at)}
            </p>

            <form
              action="/admin/candidatures/${encodeURIComponent(candidate.id)}/status"
              method="POST"
            >
              <input
                type="hidden"
                name="csrfToken"
                value="${escapeHtml(req.adminSession.csrf)}"
              >

              <label for="status-${escapeHtml(candidate.id)}">
                Changer le statut
              </label>

              <select
                id="status-${escapeHtml(candidate.id)}"
                name="status"
              >
                ${statusOptions}
              </select>

              <button type="submit">
                Enregistrer le statut
              </button>
            </form>
          </article>
        `;
      }).join("");

      res.setHeader("Cache-Control", "no-store");

      res.send(
        page(
          "Administration",
          `
            <section class="card">
              <h1>Tableau de bord administrateur</h1>

              <p>
                Candidatures professionnelles affichees :
                ${result.rows.length}
              </p>

              <div class="actions">
                <a class="button" href="/admin/emplois">
                  Gerer les offres d'emploi
                </a>

                <a class="button secondary" href="/emplois">
                  Voir les offres publiques
                </a>
              </div>

              <form action="/admin/logout" method="POST">
                <input
                  type="hidden"
                  name="csrfToken"
                  value="${escapeHtml(req.adminSession.csrf)}"
                >

                <button class="secondary" type="submit">
                  Se deconnecter
                </button>
              </form>

              <a href="/">Voir le site public</a>
            </section>

            ${applications || `
              <section class="card">
                <p>Aucune candidature pour le moment.</p>
              </section>
            `}
          `
        )
      );
    } catch (error) {
      console.error(
        "Erreur du tableau de bord :",
        error.message
      );

      res.status(500).send(
        page(
          "Erreur",
          "<h2>Impossible de charger les candidatures.</h2>"
        )
      );
    }
  }
);

/* GESTION ADMINISTRATEUR DES OFFRES D'EMPLOI */

app.get("/admin/emplois", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        id,
        company_name,
        job_title,
        city,
        contract_type,
        salary,
        description,
        qualifications,
        contact_phone,
        contact_whatsapp,
        contact_email,
        deadline,
        status,
        created_at
      FROM job_offers
      ORDER BY
        CASE WHEN status = 'pending' THEN 0 ELSE 1 END,
        created_at DESC
      LIMIT 200
    `);

    const offers = result.rows.map((job) => {
      const statusOptions = JOB_STATUSES.map((status) => `
        <option
          value="${status}"
          ${job.status === status ? "selected" : ""}
        >
          ${JOB_STATUS_LABELS[status]}
        </option>
      `).join("");

      return `
        <article class="card">
          <h2>${escapeHtml(job.job_title)}</h2>

          <p>
            <strong>Entreprise/recruteur :</strong>
            ${escapeHtml(job.company_name)}
          </p>

          <p>
            <strong>Ville :</strong>
            ${escapeHtml(job.city)}
          </p>

          <p>
            <strong>Contrat :</strong>
            ${escapeHtml(job.contract_type)}
          </p>

          ${job.salary
            ? `<p><strong>Salaire :</strong> ${escapeHtml(job.salary)}</p>`
            : ""}

          <p>
            <strong>Description :</strong>
            ${escapeHtml(job.description).replace(/\n/g, "<br>")}
          </p>

          ${job.qualifications
            ? `<p><strong>Qualifications :</strong> ${escapeHtml(job.qualifications).replace(/\n/g, "<br>")}</p>`
            : ""}

          <p>
            <strong>Contact telephone :</strong>
            ${escapeHtml(job.contact_phone || "Non fourni")}
          </p>

          <p>
            <strong>Contact WhatsApp :</strong>
            ${escapeHtml(job.contact_whatsapp || "Non fourni")}
          </p>

          <p>
            <strong>Contact e-mail :</strong>
            ${escapeHtml(job.contact_email || "Non fourni")}
          </p>

          <p>
            <strong>Date limite :</strong>
            ${escapeHtml(job.deadline || "Non renseignee")}
          </p>

          <p>
            <strong>Statut :</strong>
            ${escapeHtml(JOB_STATUS_LABELS[job.status] || job.status)}
          </p>

          <form
            action="/admin/emplois/${encodeURIComponent(job.id)}/status"
            method="POST"
          >
            <input
              type="hidden"
              name="csrfToken"
              value="${escapeHtml(req.adminSession.csrf)}"
            >

            <label for="job-status-${escapeHtml(job.id)}">
              Statut de l'offre
            </label>

            <select
              id="job-status-${escapeHtml(job.id)}"
              name="status"
            >
              ${statusOptions}
            </select>

            <button type="submit">
              Enregistrer le statut
            </button>
          </form>
        </article>
      `;
    }).join("");

    res.setHeader("Cache-Control", "no-store");

    res.send(
      page(
        "Gestion des offres",
        `
          <section class="card">
            <h1>Gestion des offres d'emploi</h1>

            <p>Offres affichees : ${result.rows.length}</p>

            <a class="button" href="/admin/candidatures">
              Retour aux candidatures professionnelles
            </a>
          </section>

          ${offers || `
            <section class="card">
              <p>Aucune offre soumise pour le moment.</p>
            </section>
          `}
        `
      )
    );
  } catch (error) {
    console.error(
      "Erreur de gestion des offres :",
      error.message
    );

    res.status(500).send(
      page(
        "Erreur",
        "<h2>Impossible de charger les offres.</h2>"
      )
    );
  }
});

app.post(
  "/admin/emplois/:id/status",
  requireAdmin,
  verifyCsrf,
  async (req, res) => {
    const id = Number(req.params.id);
    const status = req.body.status;

    if (!Number.isSafeInteger(id) || id < 1) {
      return res.status(400).send(
        page(
          "Reference invalide",
          "<h2>Reference d'offre invalide.</h2>"
        )
      );
    }

    if (!JOB_STATUSES.includes(status)) {
      return res.status(400).send(
        page(
          "Statut invalide",
          "<h2>Statut non autorise.</h2>"
        )
      );
    }

    try {
      const result = await pool.query(
        `
          UPDATE job_offers
          SET status = $1
          WHERE id = $2
          RETURNING id
        `,
        [status, id]
      );

      if (!result.rowCount) {
        return res.status(404).send(
          page(
            "Offre introuvable",
            "<h2>Cette offre n'existe pas.</h2>"
          )
        );
      }

      res.redirect(303, "/admin/emplois");
    } catch (error) {
      console.error(
        "Erreur de mise a jour de l'offre :",
        error.message
      );

      res.status(500).send(
        page(
          "Erreur",
          "<h2>Impossible de modifier le statut de l'offre.</h2>"
        )
      );
    }
  }
);

/* CHANGER LE STATUT D'UNE CANDIDATURE PROFESSIONNELLE */

app.post(
  "/admin/candidatures/:id/status",
  requireAdmin,
  verifyCsrf,
  async (req, res) => {
    const id = Number(req.params.id);
    const status = req.body.status;

    if (!Number.isSafeInteger(id) || id < 1) {
      return res.status(400).send(
        page(
          "Reference invalide",
          "<h2>Reference de candidature invalide.</h2>"
        )
      );
    }

    if (!ALLOWED_STATUSES.includes(status)) {
      return res.status(400).send(
        page(
          "Statut invalide",
          "<h2>Statut non autorise.</h2>"
        )
      );
    }

    try {
      const result = await pool.query(
        `
          UPDATE professional_applications
          SET status = $1
          WHERE id = $2
          RETURNING id
        `,
        [status, id]
      );

      if (!result.rowCount) {
        return res.status(404).send(
          page(
            "Candidature introuvable",
            "<h2>Cette candidature n'existe pas.</h2>"
          )
        );
      }

      res.redirect(303, "/admin/candidatures");
    } catch (error) {
      console.error(
        "Erreur de mise a jour :",
        error.message
      );

      res.status(500).send(
        page(
          "Erreur",
          "<h2>Impossible de modifier le statut.</h2>"
        )
      );
    }
  }
);

/* DECONNEXION */

app.post(
  "/admin/logout",
  requireAdmin,
  verifyCsrf,
  (req, res) => {
    clearSessionCookie(res);
    res.setHeader("Cache-Control", "no-store");
    res.redirect(303, "/admin");
  }
);

/* VERIFICATION DU SERVEUR */

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
    console.error(
      "Verification de la base impossible :",
      error.message
    );

    res.status(500).json({
      status: "error",
      database: "disconnected",
      application: "TrouveMoi"
    });
  }
});

/* DEMARRAGE */

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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS job_offers (
        id SERIAL PRIMARY KEY,
        company_name VARCHAR(200) NOT NULL,
        job_title VARCHAR(200) NOT NULL,
        city VARCHAR(100) NOT NULL,
        contract_type VARCHAR(50) NOT NULL,
        salary VARCHAR(100),
        description TEXT NOT NULL,
        qualifications TEXT,
        contact_phone VARCHAR(30),
        contact_whatsapp VARCHAR(30),
        contact_email VARCHAR(254),
        deadline DATE,
        status VARCHAR(20) NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending', 'approved', 'rejected')),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CHECK (
          contact_phone IS NOT NULL
          OR contact_whatsapp IS NOT NULL
          OR contact_email IS NOT NULL
        )
      )
    `);

    console.log(
      "Tables des candidatures et des offres d'emploi pretes."
    );

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`TrouveMoi demarre sur le port ${PORT}.`);
    });
  } catch (error) {
    console.error("Erreur au demarrage :", error);
    process.exit(1);
  }
}

startServer();
