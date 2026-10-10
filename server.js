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
      <meta name="description" content="TrouveMoi - La plateforme de mise en relation entre clients et professionnels au Benin.">
      <title>${escapeHtml(title)} - TrouveMoi</title>

      <style>
        * {
          box-sizing: border-box;
          margin: 0;
          padding: 0;
        }

        body {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
          padding: 0;
          background: #f4f7fb;
          color: #222;
          line-height: 1.6;
          min-height: 100vh;
          display: flex;
          flex-direction: column;
        }

        header {
          background: linear-gradient(135deg, #087f5b 0%, #0a9d70 100%);
          color: white;
          padding: 18px 20px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.1);
          position: sticky;
          top: 0;
          z-index: 100;
        }

        .header-content {
          max-width: 1100px;
          margin: 0 auto;
          display: flex;
          flex-wrap: wrap;
          justify-content: space-between;
          align-items: center;
          gap: 12px;
        }

        .logo {
          font-size: 26px;
          font-weight: 800;
          color: white;
          text-decoration: none;
          letter-spacing: -0.5px;
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .logo::before {
          content: "🔍";
          font-size: 24px;
        }

        .tagline {
          font-size: 13px;
          opacity: 0.9;
          margin-top: 2px;
        }

        nav {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
        }

        nav a {
          color: white;
          text-decoration: none;
          padding: 8px 14px;
          border-radius: 6px;
          font-size: 14px;
          font-weight: 500;
          transition: background 0.2s;
        }

        nav a:hover {
          background: rgba(255,255,255,0.15);
        }

        main {
          max-width: 1100px;
          width: 100%;
          margin: 0 auto;
          padding: 24px 20px;
          flex: 1;
        }

        .card {
          background: white;
          padding: 24px;
          margin-bottom: 20px;
          border-radius: 12px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.06);
          transition: box-shadow 0.2s;
        }

        .card:hover {
          box-shadow: 0 4px 16px rgba(0,0,0,0.08);
        }

        h1 {
          font-size: 28px;
          margin-bottom: 16px;
          color: #087f5b;
          line-height: 1.3;
        }

        h2 {
          font-size: 22px;
          margin-bottom: 14px;
          color: #1a1a1a;
          line-height: 1.3;
        }

        h3 {
          font-size: 18px;
          margin-bottom: 10px;
          color: #1a1a1a;
        }

        p {
          margin-bottom: 12px;
        }

        label {
          display: block;
          margin-top: 8px;
          margin-bottom: 4px;
          font-weight: 600;
          font-size: 14px;
          color: #333;
        }

        input,
        textarea,
        select {
          width: 100%;
          padding: 12px 14px;
          margin-bottom: 14px;
          border: 1px solid #ddd;
          border-radius: 8px;
          font-size: 15px;
          font-family: inherit;
          background: white;
          transition: border-color 0.2s, box-shadow 0.2s;
        }

        input:focus,
        textarea:focus,
        select:focus {
          outline: none;
          border-color: #087f5b;
          box-shadow: 0 0 0 3px rgba(8,127,91,0.1);
        }

        textarea {
          resize: vertical;
          min-height: 100px;
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

        input[type="checkbox"] {
          width: auto;
          margin-right: 8px;
        }

        button,
        .button {
          display: inline-block;
          border: none;
          background: #087f5b;
          color: white;
          padding: 12px 20px;
          border-radius: 8px;
          cursor: pointer;
          text-decoration: none;
          text-align: center;
          font-size: 15px;
          font-weight: 600;
          transition: background 0.2s, transform 0.1s;
          margin-right: 8px;
          margin-bottom: 8px;
        }

        button:hover,
        .button:hover {
          background: #0a6b4d;
          transform: translateY(-1px);
        }

        .danger {
          background: #b42318;
        }

        .danger:hover {
          background: #9a1d13;
        }

        .secondary {
          background: #475467;
        }

        .secondary:hover {
          background: #344054;
        }

        .muted {
          color: #667085;
          font-size: 14px;
        }

        .contact-buttons {
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
          margin-top: 16px;
        }

        .contact-buttons .button {
          flex: 1 1 140px;
          margin: 0;
        }

        .whatsapp {
          background: #25d366;
        }

        .whatsapp:hover {
          background: #1da851;
        }

        .email {
          background: #475467;
        }

        .email:hover {
          background: #344054;
        }

        .share {
          background: #4267b2;
        }

        .share:hover {
          background: #365899;
        }

        .photos-grid {
          display: flex;
          flex-wrap: wrap;
          gap: 12px;
          margin: 16px 0;
        }

        .photos-grid img {
          max-width: 280px;
          max-height: 280px;
          border-radius: 10px;
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
          font-weight: 600;
        }

        .photo-block {
          display: flex;
          flex-direction: column;
          align-items: center;
        }

        .help-text {
          font-size: 13px;
          color: #667085;
          margin-bottom: 12px;
          font-style: italic;
        }

        .hidden {
          display: none !important;
        }

        .actions {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
          margin: 12px 0;
        }

        /* STATS DASHBOARD */

        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 16px;
          margin-bottom: 24px;
        }

        .stat-card {
          background: white;
          padding: 24px;
          border-radius: 12px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.06);
          border-left: 4px solid #087f5b;
          transition: transform 0.2s, box-shadow 0.2s;
        }

        .stat-card:hover {
          transform: translateY(-2px);
          box-shadow: 0 6px 20px rgba(0,0,0,0.1);
        }

        .stat-card.warning {
          border-left-color: #f59e0b;
        }

        .stat-card.danger {
          border-left-color: #b42318;
        }

        .stat-card.info {
          border-left-color: #3b82f6;
        }

        .stat-icon {
          font-size: 32px;
          margin-bottom: 8px;
        }

        .stat-number {
          font-size: 36px;
          font-weight: 800;
          color: #1a1a1a;
          line-height: 1;
          margin-bottom: 6px;
        }

        .stat-label {
          font-size: 14px;
          color: #667085;
          font-weight: 500;
        }

        .stat-link {
          display: inline-block;
          margin-top: 10px;
          font-size: 13px;
          color: #087f5b;
          text-decoration: none;
          font-weight: 600;
        }

        .stat-link:hover {
          text-decoration: underline;
        }

        footer {
          background: #1a1a1a;
          color: #ccc;
          padding: 32px 20px 20px;
          margin-top: 40px;
        }

        .footer-content {
          max-width: 1100px;
          margin: 0 auto;
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 24px;
        }

        .footer-col h4 {
          color: white;
          margin-bottom: 12px;
          font-size: 15px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .footer-col a {
          display: block;
          color: #aaa;
          text-decoration: none;
          padding: 4px 0;
          font-size: 14px;
        }

        .footer-col a:hover {
          color: #0a9d70;
        }

        .footer-bottom {
          max-width: 1100px;
          margin: 24px auto 0;
          padding-top: 20px;
          border-top: 1px solid #333;
          text-align: center;
          font-size: 13px;
          color: #888;
        }

        @media (max-width: 600px) {
          header {
            padding: 14px 16px;
          }

          .header-content {
            flex-direction: column;
            text-align: center;
          }

          .logo {
            font-size: 22px;
          }

          nav {
            justify-content: center;
          }

          nav a {
            padding: 6px 10px;
            font-size: 13px;
          }

          main {
            padding: 16px 12px;
          }

          .card {
            padding: 16px;
          }

          h1 {
            font-size: 22px;
          }

          h2 {
            font-size: 18px;
          }

          .photos-grid img {
            max-width: 100%;
          }

          .contact-buttons .button {
            flex: 1 1 100%;
          }

          .stat-number {
            font-size: 28px;
          }
        }
      </style>
    </head>

    <body>
      <header>
        <div class="header-content">
          <div>
            <a href="/" class="logo">TrouveMoi</a>
            <div class="tagline">Trouvez le bon professionnel au Benin</div>
          </div>

          <nav>
            <a href="/">Professionnels</a>
            <a href="/emplois">Emploi</a>
            <a href="/publier-emploi">Publier une offre</a>
            <a href="/contact">Contact</a>
          </nav>
        </div>
      </header>

      <main>
        ${content}
      </main>

      <footer>
        <div class="footer-content">
          <div class="footer-col">
            <h4>TrouveMoi</h4>
            <p style="color:#aaa;font-size:14px">
              La plateforme beninoise de mise en relation entre clients et professionnels.
            </p>
          </div>

          <div class="footer-col">
            <h4>Navigation</h4>
            <a href="/">Professionnels</a>
            <a href="/emplois">Offres d'emploi</a>
            <a href="/devenir-professionnel">Devenir professionnel</a>
            <a href="/publier-emploi">Publier une offre</a>
          </div>

          <div class="footer-col">
            <h4>Informations</h4>
            <a href="/a-propos">A propos</a>
            <a href="/contact">Contact</a>
            <a href="/conditions">Conditions d'utilisation</a>
            <a href="/confidentialite">Politique de confidentialite</a>
          </div>

          <div class="footer-col">
            <h4>Contact</h4>
            <a href="/contact">Nous ecrire</a>
            <a href="mailto:contact@trouvemoi.bj">contact@trouvemoi.bj</a>
          </div>
        </div>

        <div class="footer-bottom">
          &copy; ${new Date().getFullYear()} TrouveMoi. Tous droits reserves.
        </div>
      </footer>
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

    const neighborhood = String(req.query.neighborhood || "")
      .trim()
      .slice(0, 150);

    const citiesResult = await pool.query(
      "SELECT id, name FROM cities ORDER BY display_order ASC"
    );

    const professionsResult = await pool.query(
      "SELECT id, name, category FROM professions ORDER BY display_order ASC"
    );

    let query = `
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
      values.push(city);
      query += ` AND city = $${values.length}`;
    }

    if (neighborhood) {
      values.push(neighborhood);
      query += ` AND neighborhood = $${values.length}`;
    }

    query += " ORDER BY created_at DESC LIMIT 50";

    const result = await pool.query(query, values);

    const cityOptions = citiesResult.rows.map((c) => `
      <option
        value="${escapeHtml(c.name)}"
        ${city === c.name ? "selected" : ""}
      >
        ${escapeHtml(c.name)}
      </option>
    `).join("");

    let neighborhoodOptions = "";

    if (city) {
      const cityResult = await pool.query(
        "SELECT id FROM cities WHERE name = $1",
        [city]
      );

      if (cityResult.rows.length) {
        const neighborhoodsResult = await pool.query(
          `SELECT name FROM neighborhoods
           WHERE city_id = $1
           ORDER BY name ASC`,
          [cityResult.rows[0].id]
        );

        neighborhoodOptions = neighborhoodsResult.rows.map((n) => `
          <option
            value="${escapeHtml(n.name)}"
            ${neighborhood === n.name ? "selected" : ""}
          >
            ${escapeHtml(n.name)}
          </option>
        `).join("");
      }
    }

    const professionsByCategory = {};

    for (const p of professionsResult.rows) {
      const cat = p.category || "Autres";

      if (!professionsByCategory[cat]) {
        professionsByCategory[cat] = [];
      }

      professionsByCategory[cat].push(p.name);
    }

    const professionOptions = Object.entries(professionsByCategory)
      .map(([category, names]) => {
        const options = names.map((name) => `
          <option
            value="${escapeHtml(name)}"
            ${profession === name ? "selected" : ""}
          >
            ${escapeHtml(name)}
          </option>
        `).join("");

        return `
          <optgroup label="${escapeHtml(category)}">
            ${options}
          </optgroup>
        `;
      }).join("");

    const professionals = result.rows.map((person) => {
      const phoneClean = normalizePhone(person.phone || "");
      const whatsappNumber = phoneClean.replace(/^\+/, "");

      const shareText = encodeURIComponent(
        "Decouvrez " + person.full_name + " (" + person.profession + ") sur TrouveMoi"
      );

      const shareUrl = encodeURIComponent(
        "https://trouvemoi-4mk0.onrender.com/"
      );

      const contactButtons = `
        <div class="contact-buttons">
          ${phoneClean
            ? `
              <a
                class="button"
                href="tel:${escapeHtml(phoneClean)}"
              >
                📞 Appeler
              </a>

              <a
                class="button whatsapp"
                href="https://wa.me/${escapeHtml(whatsappNumber)}?text=${encodeURIComponent(
                  "Bonjour, je vous contacte via TrouveMoi pour votre service de " + person.profession + "."
                )}"
                target="_blank"
                rel="noopener noreferrer"
              >
                💬 WhatsApp
              </a>
            `
            : ""
          }

          <a
            class="button share"
            href="https://wa.me/?text=${shareText}%20-%20${shareUrl}"
            target="_blank"
            rel="noopener noreferrer"
          >
            📤 Partager
          </a>
        </div>
      `;

      return `
        <article class="card">
          <h2>${escapeHtml(person.profession)}</h2>

          ${person.photo_activite_url
            ? `
              <div class="photos-grid">
                <div class="photo-block">
                  <img
                    src="${escapeHtml(person.photo_activite_url)}"
                    alt="Photo d'activite"
                    class="photo-activite"
                  >
                  <div class="photo-label">Activite</div>
                </div>
              </div>
            `
            : ""
          }

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

          ${contactButtons}
        </article>
      `;
    }).join("");

    const content = `
      <section class="card">
        <h1>Rechercher un professionnel</h1>

        <form action="/" method="GET">
          <label for="profession">Metier ou service</label>

          <select id="profession" name="profession">
            <option value="">Tous les metiers</option>
            ${professionOptions}
          </select>

          <label for="city">Ville</label>

          <select id="city" name="city">
            <option value="">Toutes les villes</option>
            ${cityOptions}
          </select>

          ${city && neighborhoodOptions
            ? `
              <label for="neighborhood">Quartier</label>

              <select id="neighborhood" name="neighborhood">
                <option value="">Tous les quartiers</option>
                ${neighborhoodOptions}
              </select>
            `
            : ""
          }

          <button type="submit">Rechercher</button>
        </form>

        <a class="button" href="/devenir-professionnel">
          Devenir professionnel
        </a>

        <a class="button secondary" href="/emplois">
          Consulter les offres d'emploi
        </a>
      </section>

      <h2>Professionnels disponibles (${result.rows.length})</h2>

      ${professionals || `
        <section class="card">
          <p>
            Aucun professionnel approuve ne correspond a votre recherche.
          </p>
        </section>
      `}

      <p style="text-align:center;margin-top:24px">
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

app.get("/devenir-professionnel", async (req, res) => {
  try {
    const citiesResult = await pool.query(
      "SELECT id, name FROM cities ORDER BY display_order ASC"
    );

    const professionsResult = await pool.query(
      "SELECT id, name, category FROM professions ORDER BY display_order ASC"
    );

    const cityOptions = citiesResult.rows.map((c) => `
      <option value="${escapeHtml(c.name)}">
        ${escapeHtml(c.name)}
      </option>
    `).join("");

    const professionsByCategory = {};

    for (const p of professionsResult.rows) {
      const cat = p.category || "Autres";

      if (!professionsByCategory[cat]) {
        professionsByCategory[cat] = [];
      }

      professionsByCategory[cat].push(p.name);
    }

    const professionOptions = Object.entries(professionsByCategory)
      .map(([category, names]) => {
        const options = names.map((name) => `
          <option value="${escapeHtml(name)}">
            ${escapeHtml(name)}
          </option>
        `).join("");

        return `
          <optgroup label="${escapeHtml(category)}">
            ${options}
          </optgroup>
        `;
      }).join("");

    const content = `
      <section class="card">
        <h1>Devenir professionnel sur TrouveMoi</h1>

        <p>
          Remplissez le formulaire pour soumettre votre candidature.
          Votre profil sera examine par notre equipe avant publication.
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
            placeholder="+229..."
          >

          <label for="city">Ville *</label>

          <select id="city" name="city" required>
            <option value="">Choisissez votre ville</option>
            ${cityOptions}
          </select>

          <label for="neighborhood">Quartier</label>

          <select id="neighborhood" name="neighborhood">
            <option value="">Choisissez d'abord une ville</option>
          </select>

          <div id="neighborhood-other-block" class="hidden">
            <label for="neighborhood_other">
              Precisez votre quartier
            </label>
            <input
              id="neighborhood_other"
              name="neighborhood_other"
              maxlength="150"
              placeholder="Ex. : mon quartier"
            >
          </div>

          <label for="profession">Profession ou service propose *</label>

          <select id="profession" name="profession" required>
            <option value="">Choisissez un metier</option>
            ${professionOptions}
            <option value="__AUTRE__">Autre (precisez)</option>
          </select>

          <div id="profession-other-block" class="hidden">
            <label for="profession_other">
              Precisez votre metier ou service *
            </label>
            <input
              id="profession_other"
              name="profession_other"
              maxlength="150"
              placeholder="Ex. : reparateur de drones"
            >
          </div>

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
            placeholder="Decrivez vos services, votre savoir-faire, vos specialites..."
          ></textarea>

          <label for="service_area">Zones d'intervention</label>
          <input
            id="service_area"
            name="service_area"
            maxlength="300"
            placeholder="Ex. : Cotonou et environs"
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

          <h3>Photos</h3>

          <p class="help-text">
            Formats acceptes : JPG, PNG, WEBP. Taille max : 5 Mo par photo.
          </p>

          <label for="photo_profil">
            Photo de profil * (privee, visible par l'administration)
          </label>
          <input
            id="photo_profil"
            name="photo_profil"
            type="file"
            accept="image/jpeg,image/jpg,image/png,image/webp"
            required
          >

          <label for="photo_identite">
            Photo d'identite * (privee, visible par l'administration)
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

      <script>
        const citySelect = document.getElementById('city');
        const neighborhoodSelect = document.getElementById('neighborhood');
        const neighborhoodOtherBlock = document.getElementById('neighborhood-other-block');
        const professionSelect = document.getElementById('profession');
        const professionOtherBlock = document.getElementById('profession-other-block');

        citySelect.addEventListener('change', async function() {
          const city = citySelect.value;

          neighborhoodSelect.innerHTML = '';

          if (!city) {
            neighborhoodSelect.innerHTML =
              '<option value="">Choisissez d\\'abord une ville</option>';
            neighborhoodOtherBlock.classList.add('hidden');
            return;
          }

          neighborhoodSelect.innerHTML =
            '<option value="">Chargement...</option>';

          try {
            const response = await fetch(
              '/api/neighborhoods?city=' + encodeURIComponent(city)
            );

            const data = await response.json();

            neighborhoodSelect.innerHTML =
              '<option value="">Choisissez un quartier</option>';

            for (const n of data.neighborhoods) {
              const opt = document.createElement('option');
              opt.value = n;
              opt.textContent = n;
              neighborhoodSelect.appendChild(opt);
            }

            const otherOpt = document.createElement('option');
            otherOpt.value = '__AUTRE__';
            otherOpt.textContent = 'Autre (precisez)';
            neighborhoodSelect.appendChild(otherOpt);

            neighborhoodOtherBlock.classList.remove('hidden');
          } catch (e) {
            neighborhoodSelect.innerHTML =
              '<option value="">Erreur de chargement</option>';
          }
        });

        neighborhoodSelect.addEventListener('change', function() {
          if (neighborhoodSelect.value === '__AUTRE__') {
            neighborhoodOtherBlock.classList.remove('hidden');
          }
        });

        professionSelect.addEventListener('change', function() {
          if (professionSelect.value === '__AUTRE__') {
            professionOtherBlock.classList.remove('hidden');
          } else {
            professionOtherBlock.classList.add('hidden');
          }
        });
      </script>
    `;

    res.send(page("Devenir professionnel", content));
  } catch (error) {
    console.error(
      "Erreur sur le formulaire professionnel :",
      error.message
    );

    res.status(500).send(
      page("Erreur", "<h2>Une erreur technique est survenue.</h2>")
    );
  }
});

/* API QUARTIERS (pour le chargement dynamique) */

app.get("/api/neighborhoods", async (req, res) => {
  try {
    const city = String(req.query.city || "").trim();

    if (!city) {
      return res.json({ neighborhoods: [] });
    }

    const cityResult = await pool.query(
      "SELECT id FROM cities WHERE name = $1",
      [city]
    );

    if (!cityResult.rows.length) {
      return res.json({ neighborhoods: [] });
    }

    const neighborhoodsResult = await pool.query(
      `SELECT name FROM neighborhoods
       WHERE city_id = $1
       ORDER BY name ASC`,
      [cityResult.rows[0].id]
    );

    res.json({
      neighborhoods: neighborhoodsResult.rows.map((n) => n.name)
    });
  } catch (error) {
    console.error("Erreur API quartiers :", error.message);
    res.status(500).json({ neighborhoods: [] });
  }
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
      neighborhood_other,
      profession,
      profession_other,
      experience,
      service_description,
      service_area,
      availability
    } = req.body;

    const files = req.files || {};
    const photoProfil = files.photo_profil?.[0];
    const photoIdentite = files.photo_identite?.[0];
    const photoActivite = files.photo_activite?.[0];

    let finalNeighborhood = null;

    if (neighborhood === "__AUTRE__") {
      finalNeighborhood =
        typeof neighborhood_other === "string"
          ? neighborhood_other.trim().slice(0, 150) || null
          : null;
    } else if (typeof neighborhood === "string" && neighborhood.trim()) {
      finalNeighborhood = neighborhood.trim().slice(0, 150);
    }

    let finalProfession = null;

    if (profession === "__AUTRE__") {
      finalProfession =
        typeof profession_other === "string"
          ? profession_other.trim().slice(0, 150) || null
          : null;
    } else if (typeof profession === "string" && profession.trim()) {
      finalProfession = profession.trim().slice(0, 150);
    }

    if (
      typeof full_name !== "string" ||
      typeof phone !== "string" ||
      typeof city !== "string" ||
      typeof service_description !== "string" ||
      !full_name.trim() ||
      !phone.trim() ||
      !city.trim() ||
      !finalProfession ||
      !service_description.trim()
    ) {
      return res.status(400).send(
        page(
          "Informations manquantes",
          `
            <section class="card">
              <h2>Informations manquantes ou invalides</h2>
              <p>
                Verifiez que vous avez bien rempli le nom, le telephone,
                la ville, le metier et la description.
              </p>
              <a href="/devenir-professionnel">Retour au formulaire</a>
            </section>
          `
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
        finalNeighborhood,
        finalProfession,
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

/* ENREGISTREMENT DES OFFRES */

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

/* CONNEXION ADMINISTRATEUR */

const loginAttempts = new Map();

app.get("/admin", (req, res) => {
  const session = verifySessionToken(
    readCookie(req, SESSION_COOKIE)
  );

  if (session) {
    return res.redirect(303, "/admin/dashboard");
  }

  const content = `
    <section class="card">
      <h1>Administration TrouveMoi</h1>

      <p>
        Connectez-vous pour gerer les candidatures, les offres d'emploi
        et les messages recus.
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

  res.redirect(303, "/admin/dashboard");
});

/* FONCTION : MENU ADMIN */

function adminMenu(current) {
  const links = [
    { href: "/admin/dashboard", label: "📊 Tableau de bord" },
    { href: "/admin/candidatures", label: "📋 Candidatures" },
    { href: "/admin/emplois", label: "💼 Offres d'emploi" },
    { href: "/admin/messages", label: "📩 Messages" }
  ];

  return `
    <section class="card">
      <div class="actions">
        ${links.map((link) => `
          <a
            class="button ${current === link.href ? "" : "secondary"}"
            href="${link.href}"
          >
            ${link.label}
          </a>
        `).join("")}

        <a class="button secondary" href="/" target="_blank">
          🌐 Voir le site
        </a>
      </div>

      <form
        action="/admin/logout"
        method="POST"
        style="display:inline"
      >
        <input
          type="hidden"
          name="csrfToken"
          value="__CSRF__"
        >

        <button class="danger" type="submit">
          Se deconnecter
        </button>
      </form>
    </section>
  `;
}

/* TABLEAU DE BORD ADMINISTRATEUR */

app.get("/admin/dashboard", requireAdmin, async (req, res) => {
  try {
    const prosApproved = await pool.query(
      "SELECT COUNT(*) FROM professional_applications WHERE status = 'approved'"
    );

    const prosPending = await pool.query(
      "SELECT COUNT(*) FROM professional_applications WHERE status = 'pending'"
    );

    const jobsApproved = await pool.query(
      "SELECT COUNT(*) FROM job_offers WHERE status = 'approved'"
    );

    const jobsPending = await pool.query(
      "SELECT COUNT(*) FROM job_offers WHERE status = 'pending'"
    );

    const messagesUnread = await pool.query(
      "SELECT COUNT(*) FROM contact_messages WHERE is_read = false"
    );

    const messagesTotal = await pool.query(
      "SELECT COUNT(*) FROM contact_messages"
    );

    const stats = {
      prosApproved: Number(prosApproved.rows[0].count),
      prosPending: Number(prosPending.rows[0].count),
      jobsApproved: Number(jobsApproved.rows[0].count),
      jobsPending: Number(jobsPending.rows[0].count),
      messagesUnread: Number(messagesUnread.rows[0].count),
      messagesTotal: Number(messagesTotal.rows[0].count)
    };

    const menuHtml = adminMenu("/admin/dashboard")
      .replace("__CSRF__", escapeHtml(req.adminSession.csrf));

    res.setHeader("Cache-Control", "no-store");

    res.send(
      page(
        "Tableau de bord",
        `
          <section class="card">
            <h1>Tableau de bord</h1>
            <p class="muted">
              Bienvenue dans votre espace d'administration.
              Voici un apercu de l'activite de TrouveMoi.
            </p>
          </section>

          ${menuHtml}

          <div class="stats-grid">
            <div class="stat-card">
              <div class="stat-icon">👥</div>
              <div class="stat-number">${stats.prosApproved}</div>
              <div class="stat-label">Pros approuves</div>
              <a class="stat-link" href="/admin/candidatures">
                Voir les candidatures →
              </a>
            </div>

            <div class="stat-card warning">
              <div class="stat-icon">⏳</div>
              <div class="stat-number">${stats.prosPending}</div>
              <div class="stat-label">Candidatures en attente</div>
              <a class="stat-link" href="/admin/candidatures">
                Traiter maintenant →
              </a>
            </div>

            <div class="stat-card info">
              <div class="stat-icon">💼</div>
              <div class="stat-number">${stats.jobsApproved}</div>
              <div class="stat-label">Offres publiees</div>
              <a class="stat-link" href="/admin/emplois">
                Voir les offres →
              </a>
            </div>

            <div class="stat-card warning">
              <div class="stat-icon">📝</div>
              <div class="stat-number">${stats.jobsPending}</div>
              <div class="stat-label">Offres en attente</div>
              <a class="stat-link" href="/admin/emplois">
                Traiter maintenant →
              </a>
            </div>

            <div class="stat-card ${stats.messagesUnread > 0 ? "danger" : ""}">
              <div class="stat-icon">📩</div>
              <div class="stat-number">${stats.messagesUnread}</div>
              <div class="stat-label">Messages non lus</div>
              <a class="stat-link" href="/admin/messages">
                Lire les messages →
              </a>
            </div>

            <div class="stat-card">
              <div class="stat-icon">📬</div>
              <div class="stat-number">${stats.messagesTotal}</div>
              <div class="stat-label">Messages au total</div>
              <a class="stat-link" href="/admin/messages">
                Voir l'historique →
              </a>
            </div>
          </div>

          <section class="card">
            <h3>Actions rapides</h3>

            <div class="actions">
              <a class="button" href="/admin/candidatures">
                Gerer les candidatures
              </a>

              <a class="button" href="/admin/emplois">
                Gerer les offres d'emploi
              </a>

              <a class="button" href="/admin/messages">
                Voir les messages
              </a>
            </div>
          </section>
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
        "<h2>Impossible de charger le tableau de bord.</h2>"
      )
    );
  }
});

/* ADMIN : CANDIDATURES PROFESSIONNELLES */

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
          created_at,
          photo_profil_url,
          photo_identite_url,
          photo_activite_url
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

        const photos = `
          <div class="photos-grid">
            ${candidate.photo_profil_url
              ? `
                <div class="photo-block">
                  <img
                    src="${escapeHtml(candidate.photo_profil_url)}"
                    alt="Photo de profil"
                    class="photo-profil"
                  >
                  <div class="photo-label">Profil (privee)</div>
                </div>
              `
              : ""
            }

            ${candidate.photo_identite_url
              ? `
                <div class="photo-block">
                  <img
                    src="${escapeHtml(candidate.photo_identite_url)}"
                    alt="Photo d'identite"
                    class="photo-identite"
                  >
                  <div class="photo-label">Identite (privee)</div>
                </div>
              `
              : ""
            }

            ${candidate.photo_activite_url
              ? `
                <div class="photo-block">
                  <img
                    src="${escapeHtml(candidate.photo_activite_url)}"
                    alt="Photo d'activite"
                    class="photo-activite"
                  >
                  <div class="photo-label">Activite (publique)</div>
                </div>
              `
              : ""
            }
          </div>
        `;

        return `
          <article class="card">
            <h2>${escapeHtml(candidate.full_name)}</h2>

            ${photos}

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
              Recue le : ${escapeHtml(candidate.created_at)}
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

      const menuHtml = adminMenu("/admin/candidatures")
        .replace("__CSRF__", escapeHtml(req.adminSession.csrf));

      res.setHeader("Cache-Control", "no-store");

      res.send(
        page(
          "Candidatures",
          `
            <section class="card">
              <h1>Candidatures professionnelles</h1>
              <p>
                Total affiche : ${result.rows.length} candidature(s)
              </p>
            </section>

            ${menuHtml}

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

/* ADMIN : OFFRES D'EMPLOI */

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

    const menuHtml = adminMenu("/admin/emplois")
      .replace("__CSRF__", escapeHtml(req.adminSession.csrf));

    res.setHeader("Cache-Control", "no-store");

    res.send(
      page(
        "Offres d'emploi",
        `
          <section class="card">
            <h1>Gestion des offres d'emploi</h1>
            <p>Total affiche : ${result.rows.length} offre(s)</p>
          </section>

          ${menuHtml}

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

/* CHANGER LE STATUT D'UNE CANDIDATURE */

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

/* ADMIN : MESSAGES DE CONTACT (avec boutons Repondre) */

app.get("/admin/messages", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        id,
        name,
        email,
        phone,
        subject,
        message,
        is_read,
        created_at
      FROM contact_messages
      ORDER BY
        CASE WHEN is_read = false THEN 0 ELSE 1 END,
        created_at DESC
      LIMIT 200
    `);

    const messages = result.rows.map((msg) => {
      const replyEmail = msg.email
        ? `
          <a
            class="button email"
            href="mailto:${escapeHtml(msg.email)}?subject=${encodeURIComponent(
              "Re: " + (msg.subject || "Votre message sur TrouveMoi")
            )}"
          >
            ✉️ Repondre par email
          </a>
        `
        : "";

      const replyWhatsapp = msg.phone
        ? `
          <a
            class="button whatsapp"
            href="https://wa.me/${escapeHtml(
              normalizePhone(msg.phone).replace(/^\+/, "")
            )}?text=${encodeURIComponent(
              "Bonjour " + msg.name + ", suite a votre message sur TrouveMoi concernant : " + (msg.subject || "votre demande")
            )}"
            target="_blank"
            rel="noopener noreferrer"
          >
            💬 Repondre par WhatsApp
          </a>
        `
        : "";

      return `
        <article class="card">
          <h2>
            ${msg.is_read ? "📖" : "📩"}
            ${escapeHtml(msg.subject || "Sans objet")}
          </h2>

          <p>
            <strong>De :</strong>
            ${escapeHtml(msg.name)}
          </p>

          <p>
            <strong>E-mail :</strong>
            ${escapeHtml(msg.email || "Non renseigne")}
          </p>

          <p>
            <strong>Telephone :</strong>
            ${escapeHtml(msg.phone || "Non renseigne")}
          </p>

          <p>
            <strong>Message :</strong>
          </p>

          <p style="background:#f9fafb;padding:12px;border-radius:8px">
            ${escapeHtml(msg.message).replace(/\n/g, "<br>")}
          </p>

          <p class="muted">
            Recu le : ${escapeHtml(msg.created_at)}
          </p>

          <div class="actions">
            ${replyEmail}
            ${replyWhatsapp}

            ${!msg.is_read
              ? `
                <form
                  action="/admin/messages/${encodeURIComponent(msg.id)}/read"
                  method="POST"
                  style="display:inline"
                >
                  <input
                    type="hidden"
                    name="csrfToken"
                    value="${escapeHtml(req.adminSession.csrf)}"
                  >

                  <button class="secondary" type="submit">
                    ✅ Marquer comme lu
                  </button>
                </form>
              `
              : ""
            }

            <form
              action="/admin/messages/${encodeURIComponent(msg.id)}/delete"
              method="POST"
              style="display:inline"
            >
              <input
                type="hidden"
                name="csrfToken"
                value="${escapeHtml(req.adminSession.csrf)}"
              >

              <button class="danger" type="submit">
                🗑️ Supprimer
              </button>
            </form>
          </div>
        </article>
      `;
    }).join("");

    const menuHtml = adminMenu("/admin/messages")
      .replace("__CSRF__", escapeHtml(req.adminSession.csrf));

    res.setHeader("Cache-Control", "no-store");

    res.send(
      page(
        "Messages",
        `
          <section class="card">
            <h1>Messages recus</h1>
            <p>Total : ${result.rows.length} message(s)</p>
          </section>

          ${menuHtml}

          ${messages || `
            <section class="card">
              <p>Aucun message pour le moment.</p>
            </section>
          `}
        `
      )
    );
  } catch (error) {
    console.error(
      "Erreur de chargement des messages :",
      error.message
    );

    res.status(500).send(
      page(
        "Erreur",
        "<h2>Impossible de charger les messages.</h2>"
      )
    );
  }
});

app.post(
  "/admin/messages/:id/read",
  requireAdmin,
  verifyCsrf,
  async (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id < 1) {
      return res.redirect(303, "/admin/messages");
    }

    try {
      await pool.query(
        "UPDATE contact_messages SET is_read = true WHERE id = $1",
        [id]
      );
    } catch (error) {
      console.error("Erreur marquage lu :", error.message);
    }

    res.redirect(303, "/admin/messages");
  }
);

app.post(
  "/admin/messages/:id/delete",
  requireAdmin,
  verifyCsrf,
  async (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id < 1) {
      return res.redirect(303, "/admin/messages");
    }

    try {
      await pool.query(
        "DELETE FROM contact_messages WHERE id = $1",
        [id]
      );
    } catch (error) {
      console.error("Erreur suppression message :", error.message);
    }

    res.redirect(303, "/admin/messages");
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

/* PAGES STATIQUES */

app.get("/a-propos", (req, res) => {
  const content = `
    <section class="card">
      <h1>A propos de TrouveMoi</h1>

      <p>
        <strong>TrouveMoi</strong> est la plateforme beninoise de mise en relation
        entre les clients et les professionnels qualifiés.
      </p>

      <h2>Notre mission</h2>

      <p>
        Nous voulons simplifier la recherche de professionnels de confiance
        au Benin. Trop souvent, trouver un plombier, un electricien ou un
        couturier fiable prend du temps et passe par le bouche-a-oreille.
      </p>

      <p>
        TrouveMoi centralise les professionnels de votre ville, verifie leur
        identite et vous permet de les contacter en un clic.
      </p>

      <h2>Nos services</h2>

      <ul style="margin-left:20px;margin-bottom:16px">
        <li>Annuaire de professionnels verifies</li>
        <li>Recherche par ville, quartier et metier</li>
        <li>Contact direct par telephone ou WhatsApp</li>
        <li>Offres d'emploi publiees par les entreprises</li>
      </ul>

      <h2>Notre engagement</h2>

      <p>
        Chaque professionnel inscrit sur TrouveMoi est verifie par notre equipe
        (photo d'identite et informations verifiees) avant publication. Nous
        nous engageons a fournir une plateforme de qualite et a proteger vos
        donnees personnelles.
      </p>

      <p style="margin-top:24px">
        <a class="button" href="/contact">Nous contacter</a>
        <a class="button secondary" href="/">Voir les professionnels</a>
      </p>
    </section>
  `;

  res.send(page("A propos", content));
});

app.get("/conditions", (req, res) => {
  const content = `
    <section class="card">
      <h1>Conditions d'utilisation</h1>

      <p class="muted">
        Derniere mise a jour : ${new Date().toLocaleDateString("fr-FR")}
      </p>

      <h2>1. Acceptation des conditions</h2>
      <p>
        En utilisant TrouveMoi, vous acceptez sans reserve les presentes
        conditions d'utilisation.
      </p>

      <h2>2. Nature du service</h2>
      <p>
        TrouveMoi est une plateforme de mise en relation. Nous ne fournissons
        pas directement de services professionnels.
      </p>

      <h2>3. Inscription des professionnels</h2>
      <p>
        Les professionnels doivent fournir des informations exactes et a jour.
        Toute fausse declaration entraine le rejet de la candidature.
      </p>

      <h2>4. Responsabilites</h2>
      <p>
        TrouveMoi ne peut etre tenu responsable de la qualite des services
        fournis par les professionnels references.
      </p>

      <h2>5. Utilisation interdite</h2>
      <p>Il est interdit de :</p>
      <ul style="margin-left:20px;margin-bottom:16px">
        <li>Publier de fausses informations</li>
        <li>Usurper l'identite d'autrui</li>
        <li>Utiliser la plateforme a des fins illicites</li>
      </ul>

      <h2>6. Contact</h2>
      <p>
        Pour toute question : <a href="/contact">formulaire de contact</a>
      </p>
    </section>
  `;

  res.send(page("Conditions d'utilisation", content));
});

app.get("/confidentialite", (req, res) => {
  const content = `
    <section class="card">
      <h1>Politique de confidentialite</h1>

      <p class="muted">
        Derniere mise a jour : ${new Date().toLocaleDateString("fr-FR")}
      </p>

      <h2>1. Donnees collectees</h2>
      <p>Nous collectons :</p>
      <ul style="margin-left:20px;margin-bottom:16px">
        <li>Pros : nom, telephone, ville, quartier, metier, description, photos</li>
        <li>Offres : entreprise, contacts, description du poste</li>
        <li>Contact : nom, email, telephone, message</li>
      </ul>

      <h2>2. Utilisation des donnees</h2>
      <p>Vos donnees sont utilisees pour :</p>
      <ul style="margin-left:20px;margin-bottom:16px">
        <li>Mettre en relation les clients et les professionnels</li>
        <li>Afficher les profils approuves</li>
        <li>Vous contacter en cas de besoin</li>
      </ul>

      <h2>3. Protection des photos d'identite</h2>
      <p>
        Les photos d'identite sont <strong>strictement privees</strong>.
        Elles ne sont visibles que par l'administration.
      </p>

      <h2>4. Partage des donnees</h2>
      <p>
        Nous ne vendons ni ne partageons vos donnees avec des tiers.
      </p>

      <h2>5. Vos droits</h2>
      <p>
        Vous pouvez demander l'acces, la modification ou la suppression de
        vos donnees via le <a href="/contact">formulaire de contact</a>.
      </p>

      <h2>6. Cookies</h2>
      <p>
        Nous utilisons uniquement des cookies techniques necessaires
        au fonctionnement de l'administration.
      </p>
    </section>
  `;

  res.send(page("Politique de confidentialite", content));
});

app.get("/contact", (req, res) => {
  const content = `
    <section class="card">
      <h1>Nous contacter</h1>

      <p>
        Une question, une suggestion, un probleme ? Ecrivez-nous.
      </p>

      <form action="/contact" method="POST">
        <label for="name">Votre nom *</label>
        <input
          id="name"
          name="name"
          required
          maxlength="150"
        >

        <label for="email">Votre e-mail</label>
        <input
          id="email"
          name="email"
          type="email"
          maxlength="254"
          placeholder="vous@exemple.com"
        >

        <label for="phone">Votre telephone</label>
        <input
          id="phone"
          name="phone"
          type="tel"
          maxlength="30"
          placeholder="+229..."
        >

        <label for="subject">Sujet *</label>
        <input
          id="subject"
          name="subject"
          required
          maxlength="200"
        >

        <label for="message">Votre message *</label>
        <textarea
          id="message"
          name="message"
          required
          maxlength="5000"
          rows="6"
        ></textarea>

        <p class="help-text">
          Au moins un moyen de contact (email ou telephone) est requis.
        </p>

        <button type="submit">Envoyer le message</button>
      </form>
    </section>
  `;

  res.send(page("Contact", content));
});

app.post("/contact", async (req, res) => {
  const {
    name,
    email,
    phone,
    subject,
    message
  } = req.body;

  const cleanName = typeof name === "string"
    ? name.trim().slice(0, 150)
    : "";

  const cleanEmail = typeof email === "string"
    ? email.trim().slice(0, 254)
    : "";

  const cleanPhone = typeof phone === "string"
    ? normalizePhone(phone).slice(0, 30)
    : "";

  const cleanSubject = typeof subject === "string"
    ? subject.trim().slice(0, 200)
    : "";

  const cleanMessage = typeof message === "string"
    ? message.trim().slice(0, 5000)
    : "";

  if (
    !cleanName ||
    !cleanSubject ||
    !cleanMessage ||
    (!cleanEmail && !cleanPhone)
  ) {
    return res.status(400).send(
      page(
        "Informations manquantes",
        `
          <section class="card">
            <h2>Informations manquantes</h2>
            <p>
              Le nom, le sujet, le message et au moins un moyen de contact
              sont obligatoires.
            </p>
            <a href="/contact">Retour au formulaire</a>
          </section>
        `
      )
    );
  }

  if (cleanEmail && !validEmail(cleanEmail)) {
    return res.status(400).send(
      page(
        "E-mail invalide",
        `
          <section class="card">
            <h2>L'adresse e-mail est invalide.</h2>
            <a href="/contact">Retour au formulaire</a>
          </section>
        `
      )
    );
  }

  if (cleanPhone && !validPhone(cleanPhone)) {
    return res.status(400).send(
      page(
        "Telephone invalide",
        `
          <section class="card">
            <h2>Le numero de telephone est invalide.</h2>
            <a href="/contact">Retour au formulaire</a>
          </section>
        `
      )
    );
  }

  try {
    await pool.query(`
      INSERT INTO contact_messages (
        name,
        email,
        phone,
        subject,
        message,
        is_read
      )
      VALUES ($1, $2, $3, $4, $5, false)
    `, [
      cleanName,
      cleanEmail || null,
      cleanPhone || null,
      cleanSubject,
      cleanMessage
    ]);

    res.status(201).send(
      page(
        "Message envoye",
        `
          <section class="card">
            <h1>Message envoye avec succes !</h1>
            <p>
              Merci pour votre message. Nous vous repondrons dans les plus
              brefs delais.
            </p>
            <a class="button" href="/">Retour a l'accueil</a>
          </section>
        `
      )
    );
  } catch (error) {
    console.error(
      "Erreur lors de l'enregistrement du message :",
      error.message
    );

    res.status(500).send(
      page(
        "Erreur",
        `
          <section class="card">
            <h2>Impossible d'envoyer le message.</h2>
            <p>Veuillez reessayer plus tard.</p>
          </section>
        `
      )
    );
  }
});

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
        photo_profil_url TEXT,
        photo_identite_url TEXT,
        photo_activite_url TEXT,
        status VARCHAR(30) NOT NULL DEFAULT 'pending',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      ALTER TABLE professional_applications
      ALTER COLUMN npi DROP NOT NULL
    `);

    await pool.query(`
      ALTER TABLE professional_applications
      ADD COLUMN IF NOT EXISTS photo_profil_url TEXT
    `);

    await pool.query(`
      ALTER TABLE professional_applications
      ADD COLUMN IF NOT EXISTS photo_identite_url TEXT
    `);

    await pool.query(`
      ALTER TABLE professional_applications
      ADD COLUMN IF NOT EXISTS photo_activite_url TEXT
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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS cities (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL UNIQUE,
        display_order INTEGER NOT NULL DEFAULT 0
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS neighborhoods (
        id SERIAL PRIMARY KEY,
        city_id INTEGER NOT NULL REFERENCES cities(id) ON DELETE CASCADE,
        name VARCHAR(150) NOT NULL,
        UNIQUE (city_id, name)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS professions (
        id SERIAL PRIMARY KEY,
        name VARCHAR(150) NOT NULL UNIQUE,
        category VARCHAR(100),
        display_order INTEGER NOT NULL DEFAULT 0
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS contact_messages (
        id SERIAL PRIMARY KEY,
        name VARCHAR(150) NOT NULL,
        email VARCHAR(254),
        phone VARCHAR(30),
        subject VARCHAR(200) NOT NULL,
        message TEXT NOT NULL,
        is_read BOOLEAN NOT NULL DEFAULT false,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    const citiesData = [
      ["Cotonou", 1],
      ["Abomey-Calavi", 2],
      ["Porto-Novo", 3],
      ["Parakou", 4],
      ["Bohicon", 5],
      ["Natitingou", 6],
      ["Ouidah", 7]
    ];

    for (const [name, order] of citiesData) {
      await pool.query(
        `INSERT INTO cities (name, display_order)
         VALUES ($1, $2)
         ON CONFLICT (name) DO NOTHING`,
        [name, order]
      );
    }

    const neighborhoodsData = {
      "Cotonou": [
        "Akpakpa", "Cadjèhoun", "Fidjrossè", "Ganhi",
        "Godomey", "Gbégamey", "Haie Vive", "Jéricho",
        "Ladji", "Missèbo", "Saint-Michel", "Sainte-Rita",
        "Sèmè-Podji", "Tokpa", "Vèdoko", "Zogbo",
        "Zone des Ambassades", "Dantokpa", "Agla",
        "Aïdjèdo", "Sikècodji"
      ],
      "Abomey-Calavi": [
        "Calavi centre", "Godomey", "Akassato", "Zinvié",
        "Togba", "Tankpè", "Hêvié", "Ouèdo",
        "Cocotomey", "Kpota"
      ],
      "Porto-Novo": [
        "Djègan-Kpèvi", "Ouando", "Akonaboè", "Djassin",
        "Houinmè", "Sèmè", "Tokpota", "Zounvié",
        "Avakpa", "Atinkanmey"
      ],
      "Parakou": [
        "Zongo", "Dépôt", "Guéma", "Kpébié",
        "Madina", "Tourou", "Albarika", "Baparapé",
        "Titirou"
      ],
      "Bohicon": [
        "Bohicon centre", "Agbangnizoun", "Sèdjè",
        "Djidja", "Ouèssè", "Kpassè"
      ],
      "Natitingou": [
        "Natitingou centre", "Kanté", "Perma",
        "Kouandé", "Tchoumi-Tchoumi", "Yokossi"
      ],
      "Ouidah": [
        "Ouidah centre", "Pahou", "Gbéna", "Sè",
        "Kpomassè", "Avlékété", "Djègbadji"
      ]
    };

    for (const [cityName, neighborhoods] of Object.entries(neighborhoodsData)) {
      const cityResult = await pool.query(
        "SELECT id FROM cities WHERE name = $1",
        [cityName]
      );

      if (!cityResult.rows.length) {
        continue;
      }

      const cityId = cityResult.rows[0].id;

      for (const neighborhood of neighborhoods) {
        await pool.query(
          `INSERT INTO neighborhoods (city_id, name)
           VALUES ($1, $2)
           ON CONFLICT (city_id, name) DO NOTHING`,
          [cityId, neighborhood]
        );
      }
    }

    const professionsData = [
      ["Maçon", "Bâtiment"],
      ["Plombier", "Bâtiment"],
      ["Électricien", "Bâtiment"],
      ["Carreleur", "Bâtiment"],
      ["Peintre en bâtiment", "Bâtiment"],
      ["Menuisier bois", "Bâtiment"],
      ["Menuisier aluminium", "Bâtiment"],
      ["Soudeur", "Bâtiment"],
      ["Ferrailleur", "Bâtiment"],
      ["Charpentier", "Bâtiment"],
      ["Étanchéiste (toiture)", "Bâtiment"],
      ["Vitrier", "Bâtiment"],

      ["Femme de ménage", "Maison"],
      ["Repassage à domicile", "Maison"],
      ["Cuisinier", "Maison"],
      ["Cuisinière", "Maison"],
      ["Gardien", "Maison"],
      ["Vigile", "Maison"],
      ["Nounou", "Maison"],
      ["Garde d'enfants", "Maison"],
      ["Jardinier", "Maison"],
      ["Désinsectisation", "Maison"],
      ["Dératisation", "Maison"],
      ["Plombier-déboucheur", "Maison"],

      ["Coiffeur", "Beauté"],
      ["Coiffeuse", "Beauté"],
      ["Tresseuse", "Beauté"],
      ["Barbier", "Beauté"],
      ["Esthéticienne", "Beauté"],
      ["Maquilleuse", "Beauté"],
      ["Manucure", "Beauté"],
      ["Pédicure", "Beauté"],
      ["Masseur", "Beauté"],
      ["Masseuse", "Beauté"],
      ["Tatoueur", "Beauté"],

      ["Couturier", "Couture"],
      ["Couturière", "Couture"],
      ["Tailleur", "Couture"],
      ["Brodeur", "Couture"],
      ["Retoucheur", "Couture"],
      ["Styliste modéliste", "Couture"],
      ["Cordonnier", "Couture"],

      ["Mécanicien auto", "Automobile"],
      ["Mécanicien moto", "Automobile"],
      ["Électricien auto", "Automobile"],
      ["Carrossier", "Automobile"],
      ["Tôlier", "Automobile"],
      ["Vulcanisateur", "Automobile"],
      ["Chauffeur de taxi", "Transport"],
      ["Chauffeur de moto-taxi", "Transport"],
      ["Chauffeur personnel", "Transport"],
      ["Déménageur", "Transport"],

      ["Traiteur", "Restauration"],
      ["Pâtissier", "Restauration"],
      ["Boulanger", "Restauration"],
      ["Vendeur de nourriture", "Restauration"],
      ["Boucher", "Restauration"],
      ["Poissonnier", "Restauration"],
      ["Barista", "Restauration"],

      ["Développeur web", "Informatique"],
      ["Développeur mobile", "Informatique"],
      ["Informaticien", "Informatique"],
      ["Réparateur de téléphone", "Informatique"],
      ["Réparateur d'ordinateur", "Informatique"],
      ["Graphiste", "Informatique"],
      ["Community manager", "Informatique"],
      ["Photographe", "Informatique"],
      ["Vidéaste", "Informatique"],
      ["Ingénieur réseau", "Informatique"],

      ["Professeur de Maths", "Éducation"],
      ["Professeur de Français", "Éducation"],
      ["Professeur d'Anglais", "Éducation"],
      ["Enseignant primaire", "Éducation"],
      ["Formateur informatique", "Éducation"],
      ["Coach scolaire", "Éducation"],

      ["Infirmier à domicile", "Santé"],
      ["Infirmière à domicile", "Santé"],
      ["Sage-femme", "Santé"],
      ["Kinésithérapeute", "Santé"],
      ["Aide-soignant", "Santé"],
      ["Pharmacien", "Santé"],
      ["Opticien", "Santé"],

      ["Comptable", "Professionnel"],
      ["Fiscaliste", "Professionnel"],
      ["Juriste", "Professionnel"],
      ["Avocat", "Professionnel"],
      ["Notaire", "Professionnel"],
      ["Traducteur", "Professionnel"],
      ["Rédacteur de contenu", "Professionnel"],
      ["Secrétaire", "Professionnel"],
      ["Assistant administratif", "Professionnel"],
      ["Consultant", "Professionnel"],

      ["Wedding planner", "Événementiel"],
      ["Décorateur événementiel", "Événementiel"],
      ["DJ", "Événementiel"],
      ["Animateur", "Événementiel"],
      ["MC", "Événementiel"],
      ["Serveur événementiel", "Événementiel"],
      ["Sécurité événementielle", "Événementiel"],
      ["Sonorisation", "Événementiel"],

      ["Agent immobilier", "Immobilier"],
      ["Courtier", "Immobilier"],
      ["Serrurier", "Divers"],
      ["Climatisation", "Divers"],
      ["Froid", "Divers"],
      ["Réparation électroménager", "Divers"],
      ["Antenniste", "Divers"],
      ["Forgeron", "Divers"],
      ["Puisatier", "Divers"],
      ["Agriculteur", "Agriculture"],
      ["Maraîcher", "Agriculture"],
      ["Éleveur", "Agriculture"],
      ["Pêcheur", "Agriculture"],
      ["Apiculteur", "Agriculture"],
      ["Prothésiste dentaire", "Santé"]
    ];

    let orderCounter = 0;

    for (const [name, category] of professionsData) {
      orderCounter += 1;

      await pool.query(
        `INSERT INTO professions (name, category, display_order)
         VALUES ($1, $2, $3)
         ON CONFLICT (name) DO NOTHING`,
        [name, category, orderCounter]
      );
    }

    console.log(
      "Toutes les tables sont pretes (pros, offres, villes, quartiers, metiers, messages)."
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
