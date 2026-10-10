const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error("Erreur : DATABASE_URL n'est pas configuree.");
  process.exit(1);
}

/* CONFIGURATION CLOUDINARY */

if (
  !process.env.CLOUDINARY_CLOUD_NAME ||
  !process.env.CLOUDINARY_API_KEY ||
  !process.env.CLOUDINARY_API_SECRET
) {
  console.error(
    "Erreur : les variables Cloudinary ne sont pas configurees."
  );
  process.exit(1);
}

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

/* CONFIGURATION MULTER */

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024,
    files: 3
  },
  fileFilter: (req, file, cb) => {
    const allowed = [
      "image/jpeg",
      "image/jpg",
      "image/png",
      "image/webp"
    ];

    if (!allowed.includes(file.mimetype)) {
      return cb(
        new Error("Format non autorise. Utilisez JPG, PNG ou WEBP.")
      );
    }

    cb(null, true);
  }
});

/* FONCTION D'UPLOAD CLOUDINARY */

function uploadToCloudinary(buffer, folder, publicId) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      {
        folder: folder,
        public_id: publicId,
        resource_type: "image",
        transformation: [
          { width: 800, height: 800, crop: "limit" },
          { quality: "auto" },
          { fetch_format: "auto" }
        ]
      },
      (error, result) => {
        if (error) {
          return reject(error);
        }
        resolve(result);
      }
    );
    stream.end(buffer);
  });
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

        input[type="file"] {
          padding: 10px;
          background: #f9fafb;
          border: 2px dashed #ccc;
          cursor: pointer;
        }

        input[type="file"]:hover {
          border-color: #087f5b;
          background: #f0fdf9;
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

        .photos-grid {
          display: flex;
          flex-wrap: wrap;
          gap: 12px;
          margin: 12px 0;
        }

        .photos-grid img {
          max-width: 180px;
          max-height: 180px;
          border-radius: 8px;
          border: 2px solid #e5e7eb;
          object-fit: cover;
        }

        .photo-profil {
          border: 3px solid #087f5b !important;
        }

        .photo-identite {
          border: 3px solid #b42318 !important;
        }

        .photo-activite {
          border: 3px solid #475467 !important;
        }

        .photo-label {
          font-size: 12px;
          color: #667085;
          text-align: center;
          margin-top: 4px;
        }

        .photo-block {
          display: flex;
          flex-direction: column;
          align-items: center;
        }

        .help-text {
          font-size: 13px;
          color: #667085;
          margin-top: -8px;
          margin-bottom: 12px;
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
        availability,
        photo_profil_url,
        photo_activite_url
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

        <div class="photos-grid">
          ${person.photo_profil_url
            ? `
              <div class="photo-block">
                <img
                  src="${escapeHtml(person.photo_profil_url)}"
                  alt="Photo de profil"
                  class="photo-profil"
                >
                <div class="photo-label">Profil</div>
              </div>
            `
            : ""
          }

          ${person.photo_activite_url
            ? `
              <div class="photo-block">
                <img
                  src="${escapeHtml(person.photo_activite_url)}"
                  alt="Photo d'activite"
                  class="photo-activite"
                >
                <div class="photo-label">Activite</div>
              </div>
            `
            : ""
          }
        </div>

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

      <form
        action="/candidatures"
        method="POST"
        enctype="multipart/form-data"
      >
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

        <hr style="margin:24px 0;border:none;border-top:1px solid #e5e7eb">

        <h3>Photos obligatoires</h3>

        <p class="help-text">
          Formats acceptes : JPG, PNG, WEBP. Taille max : 5 Mo par photo.
        </p>

        <label for="photo_profil">
          Photo de profil * (visible publiquement)
        </label>
        <input
          id="photo_profil"
          name="photo_profil"
          type="file"
          accept="image/jpeg,image/jpg,image/png,image/webp"
          required
        >

        <label for="photo_identite">
          Photo d'identite * (privee, visible uniquement par l'administration)
        </label>
        <input
          id="photo_identite"
          name="photo_identite"
          type="file"
          accept="image/jpeg,image/jpg,image/png,image/webp"
          required
        >

        <label for="photo_activite">
          Photo d'activite (optionnelle, visible publiquement)
        </label>
        <input
          id="photo_activite"
          name="photo_activite"
          type="file"
          accept="image/jpeg,image/jpg,image/png,image/webp"
        >

        <button type="submit">Envoyer ma candidature</button>
      </form>

      <p><a href="/">Retour a l'accueil</a></p>
    </section>
  `;

  res.send(page("Devenir professionnel", content));
});

/* ENREGISTREMENT DES CANDIDATURES PROFESSIONNELLES */

app.post(
  "/candidatures",
  upload.fields([
    { name: "photo_profil", maxCount: 1 },
    { name: "photo_identite", maxCount: 1 },
    { name: "photo_activite", maxCount: 1 }
  ]),
  async (req, res) => {
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

    const files = req.files || {};
    const photoProfil = files.photo_profil?.[0];
    const photoIdentite = files.photo_identite?.[0];
    const photoActivite = files.photo_activite?.[0];

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

    if (!photoProfil || !photoIdentite) {
      return res.status(400).send(
        page(
          "Photos obligatoires",
          `
            <section class="card">
              <h2>Photos obligatoires manquantes</h2>
              <p>
                La photo de profil et la photo d'identite sont obligatoires.
              </p>
              <a href="/devenir-professionnel">Retour au formulaire</a>
            </section>
          `
        )
      );
    }

    let photoProfilUrl = null;
    let photoIdentiteUrl = null;
    let photoActiviteUrl = null;

    try {
      const timestamp = Date.now();

      const profilResult = await uploadToCloudinary(
        photoProfil.buffer,
        "trouvemoi/profils",
        `profil_${timestamp}`
      );
      photoProfilUrl = profilResult.secure_url;

      const identiteResult = await uploadToCloudinary(
        photoIdentite.buffer,
        "trouvemoi/identites",
        `identite_${timestamp}`
      );
      photoIdentiteUrl = identiteResult.secure_url;

      if (photoActivite) {
        const activiteResult = await uploadToCloudinary(
          photoActivite.buffer,
          "trouvemoi/activites",
          `activite_${timestamp}`
        );
        photoActiviteUrl = activiteResult.secure_url;
      }
    } catch (uploadError) {
      console.error(
        "Erreur d'upload Cloudinary :",
        uploadError.message
      );

      return res.status(500).send(
        page(
          "Erreur d'upload",
          `
            <section class="card">
              <h2>Impossible de televerser les photos.</h2>
              <p>Veuillez reessayer avec des images plus petites.</p>
              <a href="/devenir-professionnel">Retour au formulaire</a>
            </section>
          `
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
          photo_profil_url,
          photo_identite_url,
          photo_activite_url,
          status
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL,$10,$11,$12,'pending')
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
          : null,
        photoProfilUrl,
        photoIdentiteUrl,
        photoActiviteUrl
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
  }
);

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
              <option
