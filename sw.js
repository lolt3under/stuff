const CACHE_NAME = 'xer0x-v1';
const ASSETS = [
  '/',
  'https://bear-images.sfo2.cdn.digitaloceanspaces.com/xer0x/gladgers-hacker-gers-guardians-of-galaxy.gif',
  'https://xer0x.in/blog/',
  'https://bear-images.sfo2.cdn.digitaloceanspaces.com/xer0x/xer0x-anderson-e8270d03-public.txt',
  'https://bear-images.sfo2.cdn.digitaloceanspaces.com/xer0x/twitter.webp',
  'https://bear-images.sfo2.cdn.digitaloceanspaces.com/xer0x/linkedin.webp',
  'https://bear-images.sfo2.cdn.digitaloceanspaces.com/xer0x/signal-logo-ultramarine.webp',
  'https://bear-images.sfo2.cdn.digitaloceanspaces.com/xer0x/mail_icon_130883.webp',
  'https://bear-images.sfo2.cdn.digitaloceanspaces.com/xer0x/comiccodeligatures-regular.otf'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(ASSETS))
      .then(() => self.skipWaiting()) // Force activation of new service worker
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          // Delete old caches
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => self.clients.claim()) // Take control of all clients immediately
  );
});

self.addEventListener('fetch', event => {
  // Only handle GET requests
  if (event.request.method !== 'GET') {
    return;
  }

  event.respondWith(
    caches.match(event.request)
      .then(response => {
        if (response) {
          return response;
        }
        
        // Clone the request because it can only be used once
        const fetchRequest = event.request.clone();
        
        return fetch(fetchRequest).then(response => {
          // Check if we received a valid response
          if (!response || response.status !== 200 || response.type !== 'basic') {
            return response;
          }

          // Clone the response because it can only be used once
          const responseToCache = response.clone();

          caches.open(CACHE_NAME)
            .then(cache => {
              cache.put(event.request, responseToCache);
            });

          return response;
        }).catch(() => {
          // If fetch fails, try to return a cached fallback
          if (event.request.destination === 'document') {
            return caches.match('/');
          }
        });
      })
  );
});