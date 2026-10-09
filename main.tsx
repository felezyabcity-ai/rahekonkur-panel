import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import { registerPWA } from './pwa';
import './index.css';
import { tokenStorage } from './api';

// ورود مدیر از پیشخوان وردپرس: توکن در بخش # آدرس می‌آید (به سرور فرستاده نمی‌شود) و فوراً پاک می‌شود.
(() => {
  try {
    const hash = new URLSearchParams(window.location.hash.replace(/^#/, ''));
    const token = hash.get('rk_token');
    if (token) {
      tokenStorage.remove();
      tokenStorage.set(token);
      const tab = hash.get('tab');
      if (tab) sessionStorage.setItem('rk_admin_tab', tab);
      history.replaceState(null, '', window.location.pathname + window.location.search);
    }
  } catch {}
})();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

registerPWA();
