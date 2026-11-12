const CACHE_NAME = 'trouvemoi-v4';
const ASSETS_TO_CACHE = ['/manifest.json'];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS_TO_CACHE)));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(cacheNames.map((cache) => { 
        if (cache !== CACHE_NAME) return caches.delete(cache); 
      }));
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  // On ne touche qu'aux requêtes GET
  if (event.request.method !== 'GET') return;
  
  const url = new URL(event.request.url);
  
  // SÉCURITÉ : On ne cache JAMAIS les pages privées ou dynamiques
  const NEVER_CACHE = [
    '/mon-espace-pro', '/admin', '/paiement', '/api', '/webhooks', 
    '/cron', '/pro/', '/contact', '/devenir-professionnel', 
    '/candidatures', '/soutenir', '/don', '/emplois', '/mes-favoris', 
    '/mon-compte', '/suivi'
  ];
  
  if (NEVER_CACHE.some(p => url.pathname === p || url.pathname.startsWith(p + '/'))) return;

  // On ne cache QUE les images et les fichiers de style (CSS)
  const CACHEABLE_EXT = /\.(css|png|jpg|jpeg|webp|svg|woff2?|ico)$/i;
  if (!CACHEABLE_EXT.test(url.pathname)) return;

  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      
      return fetch(event.request).then((response) => {
        // On ne met en cache que si la réponse est valide (status 200)
        if (response && response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        }
        return response;
      }).catch(() => {
        // En cas de perte de connexion, on affiche le cache s'il existe
        return caches.match(event.request);
      });
    })
  );
});
