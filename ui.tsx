import React from 'react';
import { AlertCircle, CheckCircle2, RefreshCw } from 'lucide-react';

export const Card: React.FC<{ title?: React.ReactNode; icon?: React.ReactNode; action?: React.ReactNode; className?: string; children: React.ReactNode }> = ({
  title,
  icon,
  action,
  className = '',
  children,
}) => (
  <section className={`bg-white border border-slate-200 rounded-2xl p-4 sm:p-5 shadow-xs ${className}`}>
    {(title || action) && (
      <div className="flex items-center justify-between gap-3 mb-4">
        <h2 className="flex items-center gap-2 text-sm sm:text-base font-black text-slate-900">
          {icon && <span className="text-orange-600">{icon}</span>}
          {title}
        </h2>
        {action}
      </div>
    )}
    {children}
  </section>
);

export const Stat: React.FC<{ label: string; value: React.ReactNode; hint?: React.ReactNode; tone?: 'orange' | 'emerald' | 'slate' | 'sky' }> = ({
  label,
  value,
  hint,
  tone = 'slate',
}) => {
  const tones = {
    orange: 'text-orange-600',
    emerald: 'text-emerald-600',
    slate: 'text-slate-900',
    sky: 'text-sky-700',
  };
  return (
    <div className="bg-slate-50 border border-slate-200 rounded-xl p-3 sm:p-4 text-center min-w-0">
      <div className="text-[11px] sm:text-xs font-bold text-slate-500 mb-1">{label}</div>
      <div className={`text-base sm:text-xl font-black ${tones[tone]} break-words`}>{value}</div>
      {hint && <div className="text-[11px] text-slate-400 mt-1">{hint}</div>}
    </div>
  );
};

export const Alert: React.FC<{ kind: 'error' | 'success'; children: React.ReactNode; onClose?: () => void }> = ({ kind, children, onClose }) => (
  <div
    role={kind === 'error' ? 'alert' : 'status'}
    className={`flex items-start gap-2 p-3 rounded-xl text-xs font-bold border ${
      kind === 'error' ? 'bg-red-50 border-red-200 text-red-700' : 'bg-emerald-50 border-emerald-200 text-emerald-700'
    }`}
  >
    {kind === 'error' ? <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" /> : <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />}
    <span className="flex-1">{children}</span>
    {onClose && (
      <button type="button" onClick={onClose} className="text-[11px] opacity-70 hover:opacity-100">
        بستن
      </button>
    )}
  </div>
);

export const Empty: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="text-center text-xs text-slate-500 bg-slate-50 border border-dashed border-slate-200 rounded-xl p-5">{children}</div>
);

export const Spinner: React.FC<{ label?: string }> = ({ label = 'در حال بارگذاری...' }) => (
  <div className="flex items-center justify-center gap-2 py-16 text-sm text-slate-500">
    <RefreshCw className="w-4 h-4 animate-spin" />
    <span>{label}</span>
  </div>
);

export const Button: React.FC<
  React.ButtonHTMLAttributes<HTMLButtonElement> & { loading?: boolean; variant?: 'primary' | 'dark' | 'ghost' | 'danger' | 'success'; size?: 'md' | 'sm' }
> = ({ loading, variant = 'primary', size = 'md', className = '', children, disabled, ...rest }) => {
  const variants = {
    primary: 'bg-orange-600 hover:bg-orange-700 text-white',
    dark: 'bg-slate-900 hover:bg-slate-800 text-white',
    ghost: 'bg-white hover:bg-slate-50 text-slate-700 border border-slate-200',
    danger: 'bg-white hover:bg-red-50 text-red-600 border border-red-200',
    success: 'bg-emerald-600 hover:bg-emerald-700 text-white',
  };
  return (
    <button
      {...rest}
      disabled={disabled || loading}
      className={`inline-flex items-center justify-center gap-2 rounded-xl font-bold transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
        size === 'sm' ? 'px-3 py-1.5 text-xs' : 'px-4 py-2.5 text-xs sm:text-sm'
      } ${variants[variant]} ${className}`}
    >
      {loading && <RefreshCw className="w-4 h-4 animate-spin" />}
      {children}
    </button>
  );
};

export const inputCls =
  'w-full px-3 py-2.5 border border-slate-300 rounded-xl text-sm bg-white focus:border-orange-500 focus:ring-2 focus:ring-orange-100 outline-none';

export const Label: React.FC<{ children: React.ReactNode; required?: boolean; htmlFor?: string }> = ({ children, required, htmlFor }) => (
  <label htmlFor={htmlFor} className="block text-xs font-bold text-slate-700 mb-1.5">
    {children} {required && <span className="text-red-500">*</span>}
  </label>
);

/** نوار ساده‌ی ۱۴ روز اخیر؛ فقط داده‌ی واقعی. */
export const DaysBars: React.FC<{ days: { date: string; minutes: number }[]; label: (d: string) => string; title: (d: { date: string; minutes: number }) => string }> = ({
  days,
  label,
  title,
}) => {
  const max = Math.max(60, ...days.map(d => d.minutes));
  return (
    <div className="flex items-end gap-1 sm:gap-1.5" dir="ltr">
      {days.map(d => (
        <div key={d.date} className="flex-1 flex flex-col items-center gap-1 min-w-0" title={title(d)}>
          <div className="w-full h-28 flex items-end">
            <div
              className={`w-full rounded-t-md ${d.minutes > 0 ? 'bg-orange-500' : 'bg-slate-100'}`}
              style={{ height: `${Math.max(3, Math.round((d.minutes / max) * 100))}%` }}
            />
          </div>
          <div className="text-[9px] sm:text-[10px] text-slate-400 w-full text-center">{label(d.date)}</div>
        </div>
      ))}
    </div>
  );
};
