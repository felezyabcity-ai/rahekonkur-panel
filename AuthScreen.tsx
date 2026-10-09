import React, { useEffect, useRef, useState } from 'react';
import { KeyRound, Smartphone, UserPlus, ArrowRight, RefreshCw, CheckCircle2 } from 'lucide-react';
import { api, normalizeMobile } from '../api';
import { Alert, Button, Label, inputCls } from './ui';

interface AuthScreenProps {
  onSuccess: (user: any, token: string) => void;
}

type Mode = 'login' | 'register';
type OtpStep = 'mobile' | 'code';

const validMobile = (m: string) => m.startsWith('09') && m.length === 11;

export const AuthScreen: React.FC<AuthScreenProps> = ({ onSuccess }) => {
  const [mode, setMode] = useState<Mode>('login');
  const [method, setMethod] = useState<'password' | 'otp'>('otp');
  const [otpStep, setOtpStep] = useState<OtpStep>('mobile');

  const [mobile, setMobile] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [timer, setTimer] = useState(0);

  // ثبت‌نام: بعد از تأیید شماره
  const [verifiedMobile, setVerifiedMobile] = useState('');
  const [name, setName] = useState('');
  const [grade, setGrade] = useState('');
  const [field, setField] = useState('');
  const [regPassword, setRegPassword] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [info, setInfo] = useState('');
  const sending = useRef(false); // setLoading همگام نیست؛ جلوی دابل‌کلیک و دو پیامک را می‌گیرد

  useEffect(() => {
    if (timer <= 0) return;
    const t = setTimeout(() => setTimer(v => v - 1), 1000);
    return () => clearTimeout(t);
  }, [timer]);

  const reset = (next: Mode) => {
    setMode(next);
    setOtpStep('mobile');
    setCode('');
    setError('');
    setInfo('');
    setVerifiedMobile('');
  };

  const finish = (res: any) => {
    if (res?.token && res?.user) {
      onSuccess(res.user, res.token);
      return true;
    }
    return false;
  };

  const handlePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    const m = normalizeMobile(mobile);
    if (!validMobile(m)) return setError('شماره موبایل باید ۱۱ رقم و با ۰۹ شروع شود.');
    if (!password) return setError('رمز عبور را وارد کنید.');
    try {
      setLoading(true);
      const res = await api.auth.login(m, password);
      if (!finish(res)) throw new Error('پاسخ سرور نامعتبر است.');
    } catch (err: any) {
      setError(err.message || 'ورود انجام نشد.');
    } finally {
      setLoading(false);
    }
  };

  const requestOtp = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (sending.current) return;
    setError('');
    const m = normalizeMobile(mobile);
    if (!validMobile(m)) return setError('شماره موبایل باید ۱۱ رقم و با ۰۹ شروع شود.');
    sending.current = true;
    try {
      setLoading(true);
      const res = await api.auth.requestOtp(m);
      setInfo(res?.message || 'کد تأیید پیامک شد.');
      setOtpStep('code');
      setCode('');
      setTimer(120);
    } catch (err: any) {
      setError(err.message || 'ارسال کد انجام نشد. دوباره تلاش کنید.');
    } finally {
      setLoading(false);
      sending.current = false;
    }
  };

  const verifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    const m = normalizeMobile(mobile);
    const c = normalizeMobile(code);
    if (c.length < 4) return setError('کد تأیید را کامل وارد کنید.');
    try {
      setLoading(true);
      const res = await api.auth.verifyOtp(m, c);
      if (finish(res)) return;
      // حالت سوم: کد درست است ولی این شماره هنوز حساب ندارد
      if (res?.verified && res.registered === false) {
        setVerifiedMobile(m);
        setMode('register');
        setInfo('شماره‌ی شما تأیید شد. برای ساخت حساب، فرم زیر را کامل کنید.');
        return;
      }
      throw new Error('کد تأیید درست نیست یا منقضی شده است.');
    } catch (err: any) {
      setError(err.message || 'کد تأیید درست نیست یا منقضی شده است.');
    } finally {
      setLoading(false);
    }
  };

  const register = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!name.trim()) return setError('نام و نام خانوادگی را وارد کنید.');
    if (!grade) return setError('پایه‌ی تحصیلی را انتخاب کنید.');
    if (regPassword && regPassword.length < 6) return setError('رمز عبور حداقل ۶ کاراکتر باشد (یا خالی بگذارید).');
    try {
      setLoading(true);
      const res = await api.auth.register({
        name: name.trim(),
        mobile: verifiedMobile,
        grade,
        field: field || undefined,
        password: regPassword || undefined,
      });
      if (!finish(res)) throw new Error('ثبت‌نام انجام نشد. پاسخ سرور نامعتبر است.');
    } catch (err: any) {
      setError(err.message || 'ثبت‌نام انجام نشد.');
    } finally {
      setLoading(false);
    }
  };

  const tabCls = (active: boolean) =>
    `flex-1 py-2.5 rounded-xl font-bold text-xs sm:text-sm transition-all ${active ? 'bg-white text-orange-600 shadow-xs' : 'text-slate-600 hover:text-slate-900'}`;

  const otpForms = (
    <>
      {otpStep === 'mobile' ? (
        <form onSubmit={requestOtp} className="space-y-4">
          <div>
            <Label htmlFor="auth-mobile" required>
              شماره موبایل
            </Label>
            <input
              id="auth-mobile"
              type="tel"
              dir="ltr"
              inputMode="numeric"
              autoComplete="tel"
              value={mobile}
              onChange={e => {
                setMobile(e.target.value);
                setError('');
              }}
              placeholder="09xxxxxxxxx"
              className={`${inputCls} font-mono text-left`}
              required
            />
            <p className="text-[11px] text-slate-500 mt-1.5">کد تأیید یک‌بار مصرف به این شماره پیامک می‌شود.</p>
          </div>
          <Button type="submit" loading={loading} className="w-full py-3">
            دریافت کد تأیید
          </Button>
        </form>
      ) : (
        <form onSubmit={verifyOtp} className="space-y-4">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-slate-700">
              کد ارسال‌شده به <span className="font-mono text-orange-600">{normalizeMobile(mobile)}</span>
            </span>
            <button
              type="button"
              onClick={() => {
                setOtpStep('mobile');
                setError('');
              }}
              className="text-slate-500 hover:text-slate-800 flex items-center gap-1"
            >
              تغییر شماره <ArrowRight className="w-3 h-3" />
            </button>
          </div>
          <input
            type="text"
            dir="ltr"
            inputMode="numeric"
            autoComplete="one-time-code"
            autoFocus
            maxLength={8}
            value={code}
            onChange={e => {
              setCode(e.target.value);
              setError('');
            }}
            placeholder="کد تأیید"
            className={`${inputCls} text-center text-xl tracking-[0.5em] font-mono`}
          />
          <Button type="submit" loading={loading} className="w-full py-3">
            تأیید کد
          </Button>
          <div className="text-xs text-center">
            {timer > 0 ? (
              <span className="text-slate-500">ارسال دوباره تا {timer} ثانیه‌ی دیگر</span>
            ) : (
              <button type="button" disabled={loading} onClick={() => requestOtp()} className="text-orange-600 font-bold inline-flex items-center gap-1">
                <RefreshCw className="w-3.5 h-3.5" /> ارسال دوباره‌ی کد
              </button>
            )}
          </div>
        </form>
      )}
    </>
  );

  return (
    <div className="min-h-screen flex items-center justify-center p-4" dir="rtl">
      <div className="bg-white border border-slate-200 rounded-3xl p-5 sm:p-8 max-w-md w-full shadow-lg">
        <div className="text-center mb-5">
          <div className="w-12 h-12 mx-auto rounded-2xl bg-gradient-to-br from-amber-500 to-orange-600 flex items-center justify-center text-white font-black text-lg mb-2">
            RK
          </div>
          <div className="text-2xl font-black text-slate-900">راه کنکور</div>
          <div className="text-xs text-slate-500 mt-1">پرتال دانش‌آموز و مشاور</div>
        </div>

        <div className="space-y-2 mb-4">
          {error && <Alert kind="error">{error}</Alert>}
          {info && !error && <Alert kind="success">{info}</Alert>}
        </div>

        <div className="flex bg-slate-100 p-1 rounded-2xl mb-5">
          <button type="button" onClick={() => reset('login')} className={tabCls(mode === 'login')}>
            ورود
          </button>
          <button type="button" onClick={() => reset('register')} className={tabCls(mode === 'register')}>
            ثبت‌نام دانش‌آموز
          </button>
        </div>

        {mode === 'login' && (
          <>
            <div className="flex justify-center gap-6 mb-5 text-xs font-bold border-b border-slate-100 pb-3">
              {(
                [
                  ['otp', 'با کد پیامکی', <Smartphone key="i" className="w-3.5 h-3.5" />],
                  ['password', 'با رمز عبور', <KeyRound key="i" className="w-3.5 h-3.5" />],
                ] as const
              ).map(([key, label, icon]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => {
                    setMethod(key);
                    setError('');
                  }}
                  className={`pb-1 border-b-2 flex items-center gap-1.5 ${
                    method === key ? 'border-orange-500 text-orange-600' : 'border-transparent text-slate-500 hover:text-slate-800'
                  }`}
                >
                  {icon}
                  {label}
                </button>
              ))}
            </div>

            {method === 'password' ? (
              <form onSubmit={handlePassword} className="space-y-4">
                <div>
                  <Label htmlFor="login-mobile" required>
                    شماره موبایل
                  </Label>
                  <input
                    id="login-mobile"
                    type="tel"
                    dir="ltr"
                    inputMode="numeric"
                    autoComplete="username"
                    value={mobile}
                    onChange={e => setMobile(e.target.value)}
                    placeholder="09xxxxxxxxx"
                    className={`${inputCls} font-mono text-left`}
                    required
                  />
                </div>
                <div>
                  <Label htmlFor="login-pass" required>
                    رمز عبور
                  </Label>
                  <input
                    id="login-pass"
                    type="password"
                    dir="ltr"
                    autoComplete="current-password"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    className={inputCls}
                    required
                  />
                  <p className="text-[11px] text-slate-500 mt-1.5">رمز را ندارید؟ از «با کد پیامکی» وارد شوید.</p>
                </div>
                <Button type="submit" loading={loading} className="w-full py-3">
                  ورود
                </Button>
              </form>
            ) : (
              otpForms
            )}
          </>
        )}

        {mode === 'register' && !verifiedMobile && (
          <>
            <p className="text-xs text-slate-600 mb-4 leading-6">قدم اول: شماره موبایل خود را با کد پیامکی تأیید کنید.</p>
            {otpForms}
          </>
        )}

        {mode === 'register' && verifiedMobile && (
          <form onSubmit={register} className="space-y-4">
            <div className="flex items-center gap-2 text-xs bg-emerald-50 border border-emerald-200 rounded-xl p-3 text-emerald-800 font-bold">
              <CheckCircle2 className="w-4 h-4" />
              <span>
                شماره‌ی تأییدشده: <span className="font-mono">{verifiedMobile}</span>
              </span>
            </div>
            <div>
              <Label htmlFor="reg-name" required>
                نام و نام خانوادگی
              </Label>
              <input id="reg-name" type="text" autoComplete="name" value={name} onChange={e => setName(e.target.value)} className={inputCls} required />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label htmlFor="reg-grade" required>
                  پایه
                </Label>
                <select id="reg-grade" value={grade} onChange={e => setGrade(e.target.value)} className={inputCls} required>
                  <option value="">انتخاب کنید</option>
                  <option value="دهم">دهم</option>
                  <option value="یازدهم">یازدهم</option>
                  <option value="دوازدهم">دوازدهم</option>
                  <option value="فارغ‌التحصیل">فارغ‌التحصیل</option>
                </select>
              </div>
              <div>
                <Label htmlFor="reg-field">رشته</Label>
                <select id="reg-field" value={field} onChange={e => setField(e.target.value)} className={inputCls}>
                  <option value="">انتخاب کنید</option>
                  <option value="تجربی">تجربی</option>
                  <option value="ریاضی">ریاضی</option>
                  <option value="انسانی">انسانی</option>
                  <option value="هنر">هنر</option>
                  <option value="زبان">زبان</option>
                </select>
              </div>
            </div>
            <div>
              <Label htmlFor="reg-pass">رمز عبور (اختیاری)</Label>
              <input
                id="reg-pass"
                type="password"
                dir="ltr"
                autoComplete="new-password"
                value={regPassword}
                onChange={e => setRegPassword(e.target.value)}
                className={inputCls}
              />
              <p className="text-[11px] text-slate-500 mt-1.5">اگر خالی بماند، همیشه با کد پیامکی وارد می‌شوید.</p>
            </div>
            <Button type="submit" loading={loading} variant="success" className="w-full py-3">
              <UserPlus className="w-4 h-4" /> ساخت حساب و ورود
            </Button>
          </form>
        )}
      </div>
    </div>
  );
};
