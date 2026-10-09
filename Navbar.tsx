import React from 'react';
import { LogOut, User as UserIcon, Shield, GraduationCap, UserCheck, Phone } from 'lucide-react';

interface NavbarProps {
  user: any;
  role: 'student' | 'mentor' | 'sales' | 'admin';
  onLogout: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ user, role, onLogout }) => {
  const getRoleBadge = () => {
    switch (role) {
      case 'student':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-amber-50 text-amber-800 border border-amber-200">
            <GraduationCap className="w-3.5 h-3.5" />
            <span>دانش‌آموز</span>
          </span>
        );
      case 'mentor':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-50 text-emerald-800 border border-emerald-200">
            <UserCheck className="w-3.5 h-3.5" />
            <span>مشاور تحصیلی</span>
          </span>
        );
      case 'sales':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-sky-50 text-sky-800 border border-sky-200">
            <Phone className="w-3.5 h-3.5" />
            <span>مشاور فروش</span>
          </span>
        );
      case 'admin':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-indigo-50 text-indigo-800 border border-indigo-200">
            <Shield className="w-3.5 h-3.5" />
            <span>مدیر سامانه</span>
          </span>
        );
      default:
        return null;
    }
  };

  return (
    <header className="bg-white border-b border-slate-200 sticky top-0 z-40 shadow-xs">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* سمت راست: نام و برند راه کنکور */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-amber-500 to-orange-600 flex items-center justify-center text-white font-black text-lg shadow-sm">
              RK
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-slate-900 text-lg tracking-tight">راه کنکور</span>
                {getRoleBadge()}
              </div>
              <p className="text-xs text-slate-500 hidden sm:block">
                سامانه پایش و برنامه‌ریزی مطالعه
              </p>
            </div>
          </div>

          {/* سمت چپ: اطلاعات کاربر و دکمه خروج */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 text-right">
              <div className="w-8 h-8 rounded-full bg-slate-100 flex items-center justify-center text-slate-600">
                <UserIcon className="w-4 h-4" />
              </div>
              <div className="hidden sm:block">
                <div className="text-xs font-bold text-slate-900 leading-tight">
                  {user?.name || user?.display_name || user?.username || 'کاربر گرامی'}
                </div>
                {user?.mobile && (
                  <div className="text-[11px] font-mono text-slate-500" dir="ltr">
                    {user.mobile}
                  </div>
                )}
              </div>
            </div>

            <button
              type="button"
              onClick={onLogout}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-slate-600 hover:text-red-600 hover:bg-red-50 rounded-xl border border-slate-200 transition-colors"
              title="خروج از حساب کاربری"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span className="hidden xs:inline">خروج</span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
