const CACHE_NAME = 'trouvemoi-v1';
const ASSETS_TO_CACHE = [
  '/',
  '/manifest.json'
];

// 1. Installation : on met en cache les pages de base
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

// 3. Interception : on sert le cache si pas de réseau
self.addEventListener('fetch', (event) => {
  // On ne met en cache que les requêtes GET (pages web, images)
  if (event.request.method !== 'GET') return;

  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      // Si on a la page en cache, on l'affiche
      if (cachedResponse) {
        return cachedResponse;
      }
      // Sinon, on va sur internet
      return fetch(event.request).then((response) => {
        // Si la réponse est bonne, on la met en cache pour la prochaine fois
        if (response && response.status === 200) {
          const responseClone = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseClone);
          });
        }
        return response;
      }).catch(() => {
        // Si pas de réseau et pas en cache, on affiche une page d'erreur basique
        return new Response("<h1>Vous êtes hors ligne</h1><p>Veuillez vérifier votre connexion internet.</p>", {
          headers: { 'Content-Type': 'text/html' }
        });
      });
    })
  );
});
