import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { AuthScreen } from './components/AuthScreen';
import { StudentPortal } from './components/StudentPortal';
import { MentorPortal } from './components/MentorPortal';
import { AdminDashboard } from './components/AdminDashboard';
import { SalesPortal } from './components/SalesPortal';
import { api, tokenStorage, onAuthError } from './api';

export type Role = 'student' | 'mentor' | 'sales' | 'sales_manager' | 'mentor_manager' | 'admin';

export default function App() {
  const [token, setToken] = useState<string | null>(() => tokenStorage.get());
  const [currentUser, setCurrentUser] = useState<any | null>(() => tokenStorage.getUser());
  const [role, setRole] = useState<Role | null>(() => {
    const user = tokenStorage.getUser();
    return user ? detectRole(user) : null;
  });
  const [isLoading, setIsLoading] = useState<boolean>(() => {
    // اگر توکن از قبل ذخیره شده، ابتدا وضعیت اعتبارسنجی را بررسی می‌کنیم
    return !!tokenStorage.get();
  });

  function detectRole(user: any): Role {
    if (!user) return 'student';
    const roleVal = user.role || (Array.isArray(user.roles) ? user.roles[0] : '');
    const r = String(roleVal).toLowerCase();
    if (r.includes('admin')) return 'admin';
    if (r.includes('sales_manager')) return 'sales_manager';
    if (r.includes('mentor_manager')) return 'mentor_manager';
    if (r.includes('sales')) return 'sales';
    if (r.includes('mentor') || r.includes('teacher') || r.includes('advisor')) return 'mentor';
    return 'student';
  }

  // بررسی نشست کاربری با me() در هنگام بالا آمدن برنامه
  useEffect(() => {
    const checkSession = async () => {
      const savedToken = tokenStorage.get();
      if (!savedToken) {
        setIsLoading(false);
        return;
      }

      try {
        setIsLoading(true);
        const res = await api.auth.me();
        const user = res?.user;
        if (user) {
          tokenStorage.setUser(user);
          setCurrentUser(user);
          setRole(detectRole(user));
          setToken(savedToken);
        } else {
          // اگر کاربر برنگشت ولی توکن بود، از اطلاعات محلی استفاده کن
          const localUser = tokenStorage.getUser();
          if (localUser) {
            setCurrentUser(localUser);
            setRole(detectRole(localUser));
          } else {
            tokenStorage.remove();
            setCurrentUser(null);
            setRole(null);
            setToken(null);
          }
        }
      } catch (err) {
        console.warn('Session verification failed, attempting cached user:', err);
        // اگر خطای شبکه بود ولی کاربر ذخیره شده بود
        const cachedUser = tokenStorage.getUser();
        if (cachedUser) {
          setCurrentUser(cachedUser);
          setRole(detectRole(cachedUser));
        } else {
          tokenStorage.remove();
          setCurrentUser(null);
          setRole(null);
          setToken(null);
        }
      } finally {
        setIsLoading(false);
      }
    };

    checkSession();

    // گوش دادن به خطاهای اعتبارسنجی ۴۰۱/۴۰۳
    const unsubscribe = onAuthError(() => {
      tokenStorage.remove();
      setCurrentUser(null);
      setRole(null);
      setToken(null);
    });

    return () => unsubscribe();
  }, []);

  const handleAuthSuccess = (user: any, newToken: string) => {
    tokenStorage.set(newToken);
    tokenStorage.setUser(user);
    setToken(newToken);
    setCurrentUser(user);
    setRole(detectRole(user));
  };

  const handleLogout = async () => {
    try {
      await api.auth.logout();
    } catch (e) {
      console.warn('Logout error:', e);
    } finally {
      tokenStorage.remove();
      setToken(null);
      setCurrentUser(null);
      setRole(null);
    }
  };

  // حالت در حال بررسی نشست
  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center font-['Vazirmatn',sans-serif]" dir="rtl">
        <div className="text-center space-y-4 p-8">
          <div className="w-12 h-12 border-3 border-orange-500 border-t-transparent rounded-full animate-spin mx-auto" />
          <div className="space-y-1">
            <h3 className="text-base font-black text-slate-900">سامانه جامع راه کنکور</h3>
            <p className="text-xs text-slate-500">در حال بررسی نشست کاربری و هدایت به پنل...</p>
          </div>
        </div>
      </div>
    );
  }

  // اگر توکن یا کاربر وجود ندارد: مستقیماً صفحه‌ی ورود و ثبت‌نام
  if (!token || !currentUser || !role) {
    return (
      <div className="min-h-screen bg-slate-50 flex flex-col font-['Vazirmatn',sans-serif]" dir="rtl">
        <AuthScreen onSuccess={handleAuthSuccess} />
      </div>
    );
  }

  // اگر کاربر لاگین کرده است: هدایت مستقیم بر اساس نقش
  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 flex flex-col font-['Vazirmatn',sans-serif]" dir="rtl">
      {/* هدر پرتال متناسب با کاربر لاگین‌شده */}
      <Navbar user={currentUser} role={role} onLogout={handleLogout} />

      {/* نمایش اختصاصی پرتال بر اساس نقش */}
      <main className="flex-1 pb-12">
        {role === 'student' && <StudentPortal currentUser={currentUser} />}
        {role === 'mentor' && <MentorPortal currentUser={currentUser} />}
        {role === 'sales' && <SalesPortal currentUser={currentUser} />}
        {(role === 'sales_manager' || role === 'mentor_manager') && <AdminDashboard kind={role} />}
        {role === 'admin' && <AdminDashboard currentUser={currentUser} />}
      </main>

      {/* فوتر رسمی سامانه */}
      <footer className="bg-white border-t border-slate-200 py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="font-extrabold text-slate-900">پرتال راه کنکور</span>
            <span>·</span>
            <span>سامانه پایش ساعات مطالعه و برنامه‌ریزی تحصیلی</span>
          </div>
          <div className="text-slate-400 text-[11px]">
            panel.rahekonkur.ir · نسخه‌ی ۱۶
          </div>
        </div>
      </footer>
    </div>
  );
}
