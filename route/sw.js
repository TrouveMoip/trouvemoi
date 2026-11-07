const CACHE_NAME = 'trouvemoi-v1';
const urlsToCache = [
  '/',
  '/manifest.json'
];

// Installation du Service Worker
self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
  );
});

// Activation
self.addEventListener('activate', event => {
  event.waitUntil(clients.claim());
});

// Interception des requêtes (pour le mode hors-ligne basique)
self.addEventListener('fetch', event => {
  // On ne met en cache que les requêtes GET (pages web)
  if (event.request.method !== 'GET') return;
  
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // Si on a la page en cache, on la renvoie, sinon on va sur internet
        return response || fetch(event.request);
      })
  );
});
