const CACHE_NAME = 'trouvemoi-v2'; // On change la version pour effacer l'ancien cache
const ASSETS_TO_CACHE = [
  '/manifest.json'
];

// 1. Installation
self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS_TO_CACHE);
    })
  );
});

// 2. Activation : on nettoie les vieux caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cache) => {
          if (cache !== CACHE_NAME) {
            return caches.delete(cache);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// 3. Interception
self.addEventListener('fetch', (event) => {
  // On ignore tout ce qui n'est pas du GET (ex: les formulaires POST)
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);

  // SÉCURITÉ : On ne met JAMAIS en cache les pages privées ou dynamiques
  const NEVER_CACHE = [
    '/mon-espace-pro', '/admin', '/paiement', '/api', '/webhooks', '/cron',
    '/pro/', '/contact', '/devenir-professionnel', '/candidatures',
    '/soutenir', '/don', '/emplois', '/mes-favoris', '/mon-compte'
  ];
  
  if (NEVER_CACHE.some(p => url.pathname === p || url.pathname.startsWith(p + '/'))) {
    return; // Laisse le réseau gérer ces pages normalement
  }

  // On ne met en cache QUE les fichiers statiques (images, css, js)
  const CACHEABLE_EXT = /\.(css|js|png|jpg|jpeg|webp|svg|woff2?|ico)$/i;
  if (!CACHEABLE_EXT.test(url.pathname)) {
    return; // Si c'est une page HTML normale, on ne la cache pas
  }

  // Stratégie : Cache d'abord pour les images, sinon réseau
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) return cachedResponse;
      
      return fetch(event.request).then((response) => {
        if (response && response.status === 200) {
          const responseClone = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseClone);
          });
        }
        return response;
      }).catch(() => {
        // Si erreur et pas en cache, on affiche une erreur simple
        return new Response("Hors ligne", { status: 503, statusText: "Hors ligne" });
      });
    })
  );
});
