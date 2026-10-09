import React, { useState } from 'react';
import { Lock } from 'lucide-react';
import { api, tokenStorage } from '../api';
import { Alert, Button, Card, Label, inputCls } from './ui';

/** تغییر رمز؛ برای حساب‌هایی که مدیر ساخته (must_change_password) پیش از همه نمایش داده می‌شود. */
export const PasswordCard: React.FC<{ forced?: boolean; onDone?: () => void }> = ({ forced, onDone }) => {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [repeat, setRepeat] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [ok, setOk] = useState('');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setOk('');
    if (next.length < 8) return setError('رمز جدید باید حداقل ۸ کاراکتر باشد.');
    if (next !== repeat) return setError('تکرار رمز جدید یکسان نیست.');
    try {
      setLoading(true);
      const res = await api.auth.changePassword(current, next);
      if (res?.token) tokenStorage.set(res.token);
      const user = tokenStorage.getUser();
      if (user) tokenStorage.setUser({ ...user, must_change_password: false });
      setCurrent('');
      setNext('');
      setRepeat('');
      setOk('رمز عبور تغییر کرد. از دستگاه‌های دیگر خارج شدید.');
      onDone?.();
    } catch (err: any) {
      setError(err.message || 'تغییر رمز انجام نشد.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card title="تغییر رمز عبور" icon={<Lock className="w-4 h-4" />} className={forced ? 'border-amber-300 ring-2 ring-amber-100' : ''}>
      {forced && (
        <p className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded-xl p-3 mb-4 leading-6">
          این حساب با رمز موقت ساخته شده است. برای امنیت، قبل از ادامه رمز خود را عوض کنید.
        </p>
      )}
      <form onSubmit={submit} className="grid sm:grid-cols-3 gap-3 items-end">
        <div>
          <Label htmlFor="pw-cur" required>
            رمز فعلی
          </Label>
          <input id="pw-cur" type="password" dir="ltr" autoComplete="current-password" value={current} onChange={e => setCurrent(e.target.value)} className={inputCls} required />
        </div>
        <div>
          <Label htmlFor="pw-new" required>
            رمز جدید
          </Label>
          <input id="pw-new" type="password" dir="ltr" autoComplete="new-password" value={next} onChange={e => setNext(e.target.value)} className={inputCls} required />
        </div>
        <div>
          <Label htmlFor="pw-rep" required>
            تکرار رمز جدید
          </Label>
          <input id="pw-rep" type="password" dir="ltr" autoComplete="new-password" value={repeat} onChange={e => setRepeat(e.target.value)} className={inputCls} required />
        </div>
        <p className="sm:col-span-2 text-[11px] text-slate-500">حداقل ۸ کاراکتر و فقط عدد نباشد.</p>
        <Button type="submit" loading={loading} variant="dark">
          ذخیره‌ی رمز جدید
        </Button>
      </form>
      <div className="mt-3 space-y-2">
        {error && <Alert kind="error">{error}</Alert>}
        {ok && <Alert kind="success">{ok}</Alert>}
      </div>
    </Card>
  );
};
