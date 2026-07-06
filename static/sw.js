// Jymy Web PWA service worker — bump version to force re-cache
// v84: ensure new icon-192/512 + cover images re-fetched (cover image must match APK launcher)
const CACHE = 'jymy-v84';
const ASSETS = ['/', '/index.html', '/manifest.json'];
// Critical brand assets — always bypass cache and re-fetch from network
const NETWORK_FIRST = ['/icon-192.png','/icon-512.png','/cover.webp','/cover-480.webp','/og-cover.webp','/manifest.json','/sw.js'];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.delete('/index.html')).then(() => caches.open(CACHE))
    .then(c => c.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k))))
    // Explicitly purge any cached icon/cover from ALL caches (force re-fetch)
    .then(() => Promise.all([caches.open(CACHE)]).then(caches => Promise.all(
      NETWORK_FIRST.map(url => caches[0].delete(url).catch(() => true))
    )))
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
  // Network-first for brand icons/cover (always re-fetch latest)
  if (e.request.method === 'GET') {
    const url = new URL(e.request.url);
    if (NETWORK_FIRST.includes(url.pathname) || NETWORK_FIRST.some(p => url.pathname.endsWith(p))) {
      e.respondWith(
        fetch(e.request, { cache: 'no-cache' })
          .then(r => {
            const clone = r.clone();
            if (r.ok) caches.open(CACHE).then(c => c.put(e.request, clone));
            return r;
          })
          .catch(() => caches.match(e.request))
      );
      return;
    }
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
