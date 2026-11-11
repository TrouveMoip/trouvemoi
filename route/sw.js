const CACHE_NAME = 'trouvemoi-v3';
const ASSETS_TO_CACHE = ['/manifest.json'];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS_TO_CACHE)));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(cacheNames.map((cache) => { if (cache !== CACHE_NAME) return caches.delete(cache); }));
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  
  // SÉCURITÉ : On ne cache JAMAIS les pages privées
  const NEVER_CACHE = ['/mon-espace-pro', '/admin', '/paiement', '/api', '/webhooks', '/cron', '/pro/', '/contact', '/devenir-professionnel', '/candidatures', '/soutenir', '/don', '/emplois', '/mes-favoris', '/mon-compte'];
  if (NEVER_CACHE.some(p => url.pathname === p || url.pathname.startsWith(p + '/'))) return;

  // On ne cache QUE les images et le CSS
  const CACHEABLE_EXT = /\.(css|png|jpg|jpeg|webp|svg|woff2?|ico)$/i;
  if (!CACHEABLE_EXT.test(url.pathname)) return;

  event.respondWith(
    caches.match(event.request).then((cached) => {
      return cached || fetch(event.request).then((response) => {
        if (response && response.status === 200) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        }
        return response;
      });
    })
  );
});
