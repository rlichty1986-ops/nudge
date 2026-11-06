// Nudge service worker: shows push notifications and keeps the app usable offline.
const CACHE = 'nudge-v2';
const SHELL = ['/', '/index.html', '/manifest.webmanifest', '/icon-192.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).catch(() => {}));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k !== CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});

// Network first for the page, fall back to cache when offline.
self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== location.origin || req.url.includes('/api/')) return;
  e.respondWith((async () => {
    try {
      const res = await fetch(req);
      if (res.ok && (req.mode === 'navigate' || SHELL.includes(new URL(req.url).pathname))) {
        const copy = res.clone(); caches.open(CACHE).then(c => c.put(req.mode === 'navigate' ? '/' : req, copy));
      }
      return res;
    } catch {
      return (await caches.match(req)) || (req.mode === 'navigate' ? caches.match('/') : Response.error());
    }
  })());
});

self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch { d = { title: 'Nudge', body: e.data ? e.data.text() : '' }; }
  e.waitUntil(self.registration.showNotification(d.title || 'Nudge', {
    body: d.body || '',
    tag: d.tag || undefined,
    renotify: !!d.tag,
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    vibrate: [120, 60, 120],
    data: { url: '/' }
  }));
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const w of wins) if ('focus' in w) return w.focus();
    return self.clients.openWindow('/');
  })());
});
