/* سرویس‌ورکر پرتال راه کنکور
 *
 * فقط پوسته‌ی اپ را کش می‌کند: HTML، JS، CSS، فونت و آیکون.
 * هیچ درخواست API ای کش نمی‌شود — داده‌ی دانش‌آموز باید همیشه تازه باشد،
 * و کش‌کردنش یعنی نمره و برنامه‌ی کهنه نشان دادن.
 */
const VERSION = 'rk-20260917-193239';
const SHELL = './';

self.addEventListener('install', event => {
  event.waitUntil(caches.open(VERSION).then(c => c.add(SHELL)).catch(() => {}));
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== VERSION).map(k => caches.delete(k)))).then(() => self.clients.claim())
  );
});

// پنل می‌تواند بگوید نسخه‌ی تازه را همین حالا فعال کن
self.addEventListener('message', event => {
  if (event.data === 'rk-skip-waiting') self.skipWaiting();
});

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // API روی دامنه‌ی دیگری است

  // ناوبری: اول شبکه، اگر نبود همان پوسته‌ی کش‌شده
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then(res => {
          const copy = res.clone();
          caches.open(VERSION).then(c => c.put(SHELL, copy)).catch(() => {});
          return res;
        })
        .catch(() => caches.match(SHELL).then(r => r || Response.error()))
    );
    return;
  }

  // دارایی‌ها: اول کش، در پس‌زمینه تازه شود
  event.respondWith(
    caches.match(req).then(hit => {
      const net = fetch(req)
        .then(res => {
          if (res && res.status === 200) {
            const copy = res.clone();
            caches.open(VERSION).then(c => c.put(req, copy)).catch(() => {});
          }
          return res;
        })
        .catch(() => hit);
      return hit || net;
    })
  );
});
