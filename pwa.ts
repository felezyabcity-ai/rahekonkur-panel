/**
 * ثبت سرویس‌ورکر و اطلاع نسخه‌ی تازه.
 *
 * کش پوسته یعنی کاربر ممکن است نسخه‌ی قبلی را ببیند؛ برای همین وقتی نسخه‌ی
 * تازه‌ای آماده شد یک نوار پایین صفحه نشان می‌دهیم تا خودش یک کلیک به‌روز کند.
 */
export function registerPWA() {
  if (!('serviceWorker' in navigator)) return;
  if (location.protocol !== 'https:' && location.hostname !== 'localhost') return;

  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register('./sw.js')
      .then(reg => {
        // هر بار که پنل باز می‌شود، ببین نسخه‌ی تازه‌ای هست یا نه
        reg.update().catch(() => {});
        reg.addEventListener('updatefound', () => {
          const sw = reg.installing;
          if (!sw) return;
          sw.addEventListener('statechange', () => {
            if (sw.state === 'installed' && navigator.serviceWorker.controller) {
              showUpdateBar(() => {
                sw.postMessage('rk-skip-waiting');
              });
            }
          });
        });
      })
      .catch(() => {});

    let reloading = false;
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (reloading) return;
      reloading = true;
      location.reload();
    });
  });
}

function showUpdateBar(onUpdate: () => void) {
  if (document.getElementById('rk-update-bar')) return;
  const bar = document.createElement('div');
  bar.id = 'rk-update-bar';
  bar.setAttribute('dir', 'rtl');
  bar.style.cssText =
    'position:fixed;inset-inline:0;bottom:0;z-index:60;display:flex;gap:12px;align-items:center;justify-content:center;' +
    'padding:10px 14px;background:#0f172a;color:#fff;font-family:inherit;font-size:13px;font-weight:700';

  const text = document.createElement('span');
  text.textContent = 'نسخه‌ی تازه‌ی پنل آماده است.';

  const btn = document.createElement('button');
  btn.type = 'button';
  btn.textContent = 'به‌روزرسانی';
  btn.style.cssText = 'background:#e8456b;color:#fff;border:0;border-radius:10px;padding:6px 14px;font-weight:700;cursor:pointer';
  btn.onclick = () => {
    btn.disabled = true;
    btn.textContent = 'در حال به‌روزرسانی…';
    onUpdate();
  };

  const later = document.createElement('button');
  later.type = 'button';
  later.textContent = 'بعداً';
  later.style.cssText = 'background:transparent;color:#94a3b8;border:0;font-weight:700;cursor:pointer';
  later.onclick = () => bar.remove();

  bar.append(text, btn, later);
  document.body.appendChild(bar);
}
