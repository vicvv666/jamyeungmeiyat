// Jymy Web PWA service worker — bump version to force re-cache
const CACHE = 'jymy-v83';
const ASSETS = ['/', '/index.html', '/manifest.json'];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.delete('/index.html')).then(() => caches.open(CACHE))
    .then(c => c.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  // Network-first for HTML navigations and /, /index.html
  if (
    e.request.method === 'GET' &&
    (e.request.mode === 'navigate' ||
      e.request.url.endsWith('index.html') ||
      new URL(e.request.url).pathname === '/' ||
      new URL(e.request.url).pathname === '/index.html')
  ) {
    e.respondWith(
      fetch(e.request, { cache: 'no-cache' })
        .then(r => {
          const clone = r.clone();
          if (r.ok) caches.open(CACHE).then(c => c.put(e.request, clone));
          return r;
        })
        .catch(() => caches.match(e.request).then(r => r || caches.match('/index.html')))
    );
    return;
  }
  // Cache-first for static assets
  e.respondWith(
    caches.match(e.request).then(
      r => r || fetch(e.request).then(resp => {
        const c = resp.clone();
        if (resp.ok) caches.open(CACHE).then(cache => cache.put(e.request, c));
        return resp;
      })
    )
  );
});
