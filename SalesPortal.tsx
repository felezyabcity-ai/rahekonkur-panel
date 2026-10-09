import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { BadgeCheck, Clock3, Lock, MessageSquare, Receipt, RefreshCw, Search, UserCheck, UserPlus, Wallet, XCircle } from 'lucide-react';
import { MentorOption, Payment, PaymentStatus, PlanCatalogItem, SalesSummary, adminApi, normalizeMobile, salesApi } from '../api';
import { addDaysIso, fa, jDate, jShort, latinDigits, toman, todayIso } from '../lib/format';
import { currentJMonth, jMonthRange } from '../lib/jalali';
import { Alert, Button, Card, Empty, Label, Spinner, Stat, inputCls } from './ui';
import { PasswordCard } from './Security';
import { Tickets } from './Tickets';
import { UnreadDot, UnreadPopup, useOpenTicketsRequest, useUnread } from './Unread';

const GRADES = ['دهم', 'یازدهم', 'دوازدهم', 'فارغ‌التحصیل'];
const FIELDS = ['تجربی', 'ریاضی', 'انسانی', 'هنر', 'زبان'];

const STATUS_LABEL: Record<string, string> = {
  pending: 'در انتظار تأیید مدیر',
  approved: 'تأیید شده',
  rejected: 'رد شده',
};

const STATUS_CLS: Record<string, string> = {
  pending: 'bg-amber-50 text-amber-800 border-amber-200',
  approved: 'bg-emerald-50 text-emerald-800 border-emerald-200',
  rejected: 'bg-slate-100 text-slate-600 border-slate-200',
};

export const StatusBadge: React.FC<{ status: string }> = ({ status }) => (
  <span className={`shrink-0 text-[10px] font-bold border rounded-full px-2 py-0.5 ${STATUS_CLS[status] || STATUS_CLS.rejected}`}>
    {STATUS_LABEL[status] || status}
  </span>
);

const money = (v: string) => parseInt(latinDigits(v).replace(/[^\d]/g, ''), 10) || 0;

/* ------------------------------------------------------------------ ریشه */

type Tab = 'register' | 'payments' | 'report' | 'chat';

const TABS: { key: Tab; label: string; icon: React.ReactNode }[] = [
  { key: 'register', label: 'ثبت‌نام دانش‌آموز', icon: <UserPlus className="w-4 h-4" /> },
  { key: 'payments', label: 'فیش‌ها', icon: <Receipt className="w-4 h-4" /> },
  { key: 'report', label: 'کارنامه‌ی من', icon: <Wallet className="w-4 h-4" /> },
  { key: 'chat', label: 'پیام‌ها', icon: <MessageSquare className="w-4 h-4" /> },
];

export const SalesPortal: React.FC<{ currentUser?: any; admin?: boolean; embedded?: boolean }> = ({ currentUser, admin, embedded }) => {
  const [tab, setTab] = useState<Tab>('register');
  const [mustChange, setMustChange] = useState<boolean>(!admin && !!currentUser?.must_change_password);
  const unread = useUnread();
  useOpenTicketsRequest(() => setTab('chat'));
  const [showPw, setShowPw] = useState(false);
  const [mentors, setMentors] = useState<MentorOption[]>([]);
  const [plans, setPlans] = useState<PlanCatalogItem[]>([]);
  const [payments, setPayments] = useState<Payment[] | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const loadPayments = useCallback(async () => {
    try {
      setLoading(true);
      setError('');
      const r = await salesApi.payments();
      setPayments(r.payments);
    } catch (err: any) {
      setError(err.message || 'فیش‌ها بارگذاری نشد.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    salesApi
      .mentors()
      .then(r => setMentors(r.mentors))
      .catch(() => {});
    salesApi
      .plans()
      .then(r => setPlans(r.plans))
      .catch(() => {});
    loadPayments();
  }, [loadPayments]);

  const tabs = admin ? TABS.filter(t => t.key !== 'report' && t.key !== 'chat') : TABS;

  // حسابی که مدیر ساخته با رمز موقت وارد می‌شود؛ تا رمز را عوض نکند هیچ‌جای دیگری باز نمی‌شود.
  if (mustChange) {
    return (
      <div className="max-w-xl mx-auto px-4 py-8 space-y-4">
        <div className="bg-white border border-slate-200 rounded-2xl p-4">
          <div className="font-black text-lg text-slate-900">خوش آمدید</div>
          <div className="text-xs text-slate-500">این حساب را مدیر برای شما ساخته و رمزش موقت است. برای شروع کار، اول یک رمز تازه بگذارید.</div>
        </div>
        <PasswordCard forced onDone={() => setMustChange(false)} />
      </div>
    );
  }

  return (
    <div className={embedded ? 'space-y-5' : 'max-w-5xl mx-auto px-4 py-5 space-y-5'}>
      {!embedded && (
        <div className="bg-white border border-slate-200 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="font-black text-lg text-slate-900">میز فروش</div>
            <div className="text-xs text-slate-500">دانش‌آموز را ثبت‌نام کن و فیشش را همین‌جا ثبت کن؛ تأیید مالی با مدیر است.</div>
          </div>
          <Button size="sm" variant="ghost" onClick={() => setShowPw(v => !v)}>
            <Lock className="w-4 h-4" /> تغییر رمز
          </Button>
        </div>
      )}

      {showPw && !embedded && <PasswordCard onDone={() => setShowPw(false)} />}

      <nav className={`grid gap-1 bg-white border border-slate-200 rounded-2xl p-1 ${tabs.length === 4 ? 'grid-cols-2 sm:grid-cols-4' : tabs.length === 3 ? 'grid-cols-3' : 'grid-cols-2'}`} aria-label="بخش‌های فروش">
        {tabs.map(t => (
          <button
            key={t.key}
            type="button"
            onClick={() => setTab(t.key)}
            className={`flex items-center justify-center gap-1.5 px-2 py-2 rounded-xl text-[11px] sm:text-sm font-bold ${
              tab === t.key ? 'bg-orange-50 text-orange-700' : 'text-slate-600 hover:bg-slate-50'
            }`}
          >
            {t.icon}
            {t.label}
            {t.key === 'chat' && <UnreadDot count={unread.count} />}
          </button>
        ))}
      </nav>

      {error && (
        <Alert kind="error" onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      {tab === 'register' && <RegisterForm mentors={mentors} plans={plans} onDone={loadPayments} />}
      {tab === 'payments' && <PaymentsTab payments={payments} plans={plans} mentors={mentors} loading={loading} admin={admin} onReload={loadPayments} />}
      {tab === 'report' && <ReportTab />}
      {tab === 'chat' && <Tickets viewer="sales" onSeen={unread.refresh} />}
      {!admin && <UnreadPopup count={unread.count} items={unread.items} />}
    </div>
  );
};

/* ------------------------------------------------------- ثبت‌نام دانش‌آموز */

const RegisterForm: React.FC<{ mentors: MentorOption[]; plans: PlanCatalogItem[]; onDone: () => void }> = ({ mentors, plans, onDone }) => {
  const [name, setName] = useState('');
  const [mobile, setMobile] = useState('');
  const [grade, setGrade] = useState('');
  const [field, setField] = useState('');
  const [mentor, setMentor] = useState('');
  const [plan, setPlan] = useState('');
  const [price, setPrice] = useState('');
  const [months, setMonths] = useState('1');
  const [startOffset, setStartOffset] = useState(0);
  const [ref, setRef] = useState('');
  const [amount, setAmount] = useState('');
  const [paidOffset, setPaidOffset] = useState(0);
  const [note, setNote] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState('');

  const priceNum = money(price);
  const amountNum = amount ? money(amount) : priceNum;

  const pickPlan = (value: string) => {
    setPlan(value);
    const found = plans.find(p => p.name === value);
    const untouched = !price || plans.some(p => String(p.price) === latinDigits(price));
    if (found && untouched) setPrice(String(found.price));
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!name.trim()) return setError('نام دانش‌آموز را وارد کن.');
    if (normalizeMobile(mobile).length !== 11) return setError('موبایل دانش‌آموز درست نیست.');
    if (!grade) return setError('پایه را انتخاب کن.');
    if (!plan) return setError('طرح را انتخاب کن.');
    if (priceNum <= 0) return setError('مبلغ طرح را وارد کن.');
    if (ref.trim() && amountNum <= 0) return setError('مبلغ فیش را وارد کن.');
    if (!confirm(`ثبت‌نام ${name} در «${plan}» برای ${months} ماه با مبلغ ${toman(priceNum)}؟`)) return;
    try {
      setSaving(true);
      const res = await salesApi.registerStudent({
        name: name.trim(),
        mobile: normalizeMobile(mobile),
        grade,
        field: field || undefined,
        mentor_id: mentor ? Number(mentor) : 0,
        plan_name: plan,
        price: priceNum,
        months: Number(months),
        start_date: addDaysIso(todayIso(), startOffset),
        ref: ref.trim() || undefined,
        amount: ref.trim() ? amountNum : undefined,
        paid_at: ref.trim() ? addDaysIso(todayIso(), -paidOffset) : undefined,
        note: note.trim() || undefined,
      });
      setDone(
        `${res.account_created ? 'حساب دانش‌آموز ساخته شد' : 'طرح به پرونده‌ی موجود اضافه شد'}.` +
          (res.payment
            ? ' فیش ثبت شد و برای تأیید مدیر رفت؛ سهم شما بعد از تأیید مدیر حساب می‌شود.'
            : ' فیشی ثبت نشد — هر وقت رسید، از تب «فیش‌ها» اضافه‌اش کن.')
      );
      onDone();
    } catch (err: any) {
      setError(err.message || 'ثبت‌نام انجام نشد.');
    } finally {
      setSaving(false);
    }
  };

  if (done) {
    return (
      <Card title="ثبت‌نام انجام شد" icon={<BadgeCheck className="w-4 h-4" />}>
        <Alert kind="success">{done}</Alert>
        <div className="mt-3">
          <Button
            variant="ghost"
            onClick={() => {
              setDone('');
              setName('');
              setMobile('');
              setGrade('');
              setField('');
              setPlan('');
              setPrice('');
              setRef('');
              setAmount('');
              setNote('');
            }}
          >
            ثبت‌نام بعدی
          </Button>
        </div>
      </Card>
    );
  }

  return (
    <Card title="ثبت‌نام دانش‌آموز تازه" icon={<UserPlus className="w-4 h-4" />}>
      <form onSubmit={submit} className="space-y-4">
        <div className="grid sm:grid-cols-2 gap-3">
          <div>
            <Label htmlFor="rg-name" required>
              نام و نام خانوادگی
            </Label>
            <input id="rg-name" value={name} onChange={e => setName(e.target.value)} className={inputCls} />
          </div>
          <div>
            <Label htmlFor="rg-mobile" required>
              موبایل دانش‌آموز
            </Label>
            <input id="rg-mobile" value={mobile} onChange={e => setMobile(e.target.value)} dir="ltr" inputMode="numeric" className={`${inputCls} font-mono`} />
            <div className="text-[11px] text-slate-500 mt-1">با همین شماره و کد پیامکی وارد پنل می‌شود.</div>
          </div>
          <div>
            <Label htmlFor="rg-grade" required>
              پایه
            </Label>
            <select id="rg-grade" value={grade} onChange={e => setGrade(e.target.value)} className={inputCls}>
              <option value="">انتخاب کنید</option>
              {GRADES.map(g => (
                <option key={g}>{g}</option>
              ))}
            </select>
          </div>
          <div>
            <Label htmlFor="rg-field">رشته</Label>
            <select id="rg-field" value={field} onChange={e => setField(e.target.value)} className={inputCls}>
              <option value="">انتخاب کنید</option>
              {FIELDS.map(g => (
                <option key={g}>{g}</option>
              ))}
            </select>
          </div>
          <div>
            <Label htmlFor="rg-plan" required>
              طرح
            </Label>
            <select id="rg-plan" value={plan} onChange={e => pickPlan(e.target.value)} className={inputCls}>
              <option value="">انتخاب کنید</option>
              {plans.map(p => (
                <option key={p.name} value={p.name}>
                  {p.name} — {toman(p.price)} / ماهانه
                </option>
              ))}
            </select>
          </div>
          <div>
            <Label htmlFor="rg-mentor">مشاور تحصیلی</Label>
            <select id="rg-mentor" value={mentor} onChange={e => setMentor(e.target.value)} className={inputCls}>
              <option value="">بعداً وصل شود</option>
              {mentors.map(m => (
                <option key={m.mentor_id} value={m.mentor_id}>
                  {m.name}
                  {m.specialty ? ` (${m.specialty})` : ''} — {fa(m.active_students)} دانش‌آموز
                </option>
              ))}
            </select>
          </div>
          <div>
            <Label htmlFor="rg-price" required>
              مبلغ کل طرح (تومان)
            </Label>
            <input id="rg-price" value={price} onChange={e => setPrice(e.target.value)} inputMode="numeric" dir="ltr" className={`${inputCls} font-mono`} />
            {priceNum > 0 && (
              <div className="text-[11px] text-slate-500 mt-1">
                {toman(priceNum)} · ماهانه {toman(priceNum / Number(months))}
              </div>
            )}
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <Label htmlFor="rg-months" required>
                مدت
              </Label>
              <select id="rg-months" value={months} onChange={e => setMonths(e.target.value)} className={inputCls}>
                {[1, 2, 3, 4, 6, 9, 12].map(m => (
                  <option key={m} value={m}>
                    {fa(m)} ماه
                  </option>
                ))}
              </select>
            </div>
            <div>
              <Label htmlFor="rg-start">شروع</Label>
              <select id="rg-start" value={startOffset} onChange={e => setStartOffset(Number(e.target.value))} className={inputCls}>
                {[0, 1, 2, 3, 7].map(d => (
                  <option key={d} value={d}>
                    {d === 0 ? 'امروز' : jShort(addDaysIso(todayIso(), d))}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        <div className="bg-orange-50/50 border border-orange-200 rounded-xl p-3 space-y-3">
          <div className="text-sm font-black text-slate-900 flex items-center gap-2">
            <Receipt className="w-4 h-4 text-orange-600" /> فیش واریزی
            <span className="text-[11px] font-normal text-slate-500">اگر هنوز فیش نگرفته‌ای خالی بگذار</span>
          </div>
          <div className="grid sm:grid-cols-3 gap-3">
            <div>
              <Label htmlFor="rg-ref">شماره پیگیری</Label>
              <input id="rg-ref" value={ref} onChange={e => setRef(e.target.value)} dir="ltr" className={`${inputCls} font-mono`} />
            </div>
            <div>
              <Label htmlFor="rg-amount">مبلغ واریزی</Label>
              <input
                id="rg-amount"
                value={amount}
                onChange={e => setAmount(e.target.value)}
                inputMode="numeric"
                dir="ltr"
                placeholder={priceNum ? String(priceNum) : ''}
                className={`${inputCls} font-mono`}
              />
            </div>
            <div>
              <Label htmlFor="rg-paid">تاریخ واریز</Label>
              <select id="rg-paid" value={paidOffset} onChange={e => setPaidOffset(Number(e.target.value))} className={inputCls}>
                {[0, 1, 2, 3, 7].map(d => (
                  <option key={d} value={d}>
                    {d === 0 ? 'امروز' : jShort(addDaysIso(todayIso(), -d))}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <Label htmlFor="rg-note">یادداشت برای مدیر</Label>
            <input id="rg-note" value={note} onChange={e => setNote(e.target.value)} className={inputCls} />
          </div>
        </div>

        {error && <Alert kind="error">{error}</Alert>}
        <Button type="submit" loading={saving}>
          ثبت‌نام و ارسال فیش برای مدیر
        </Button>
      </form>
    </Card>
  );
};

/* ------------------------------------------------------------- فیش‌ها */

const PaymentsTab: React.FC<{
  payments: Payment[] | null;
  plans: PlanCatalogItem[];
  mentors: MentorOption[];
  loading: boolean;
  admin?: boolean;
  onReload: () => void;
}> = ({ payments, plans, mentors, loading, admin, onReload }) => {
  const [filter, setFilter] = useState<PaymentStatus | 'all'>('all');
  const [q, setQ] = useState('');
  const [adding, setAdding] = useState(false);

  const rows = useMemo(() => {
    const all = payments || [];
    const needle = latinDigits(q.trim());
    return all.filter(p => {
      if (filter !== 'all' && p.status !== filter) return false;
      if (!needle) return true;
      return p.student_name.includes(q.trim()) || p.mobile.includes(needle) || p.ref.includes(needle);
    });
  }, [payments, filter, q]);

  return (
    <Card
      title={admin ? 'همه‌ی فیش‌ها' : 'فیش‌های ثبت‌شده‌ی من'}
      icon={<Receipt className="w-4 h-4" />}
      action={
        <div className="flex items-center gap-2">
          <Button size="sm" variant="ghost" onClick={() => setAdding(v => !v)}>
            {adding ? 'بستن' : 'فیش برای دانش‌آموز موجود'}
          </Button>
          <button type="button" onClick={onReload} className="p-2 text-slate-400 hover:text-slate-700" aria-label="به‌روزرسانی">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      }
    >
      {adding && (
        <div className="mb-4">
          <StandalonePaymentForm
            plans={plans}
            onDone={() => {
              setAdding(false);
              onReload();
            }}
          />
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 mb-3">
        {(
          [
            { key: 'all', label: 'همه' },
            { key: 'pending', label: 'در انتظار تأیید' },
            { key: 'approved', label: 'تأیید شده' },
            { key: 'rejected', label: 'رد شده' },
          ] as { key: PaymentStatus | 'all'; label: string }[]
        ).map(f => (
          <button
            key={f.key}
            type="button"
            onClick={() => setFilter(f.key)}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold border ${
              filter === f.key ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-600 border-slate-200'
            }`}
          >
            {f.label}
          </button>
        ))}
        <div className="relative flex-1 min-w-40">
          <Search className="w-4 h-4 text-slate-400 absolute right-3 top-1/2 -translate-y-1/2" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="نام، موبایل یا شماره پیگیری" className={`${inputCls} pr-9 py-2`} aria-label="جستجو در فیش‌ها" />
        </div>
      </div>

      {!payments && loading && <Spinner />}
      {payments && rows.length === 0 && <Empty>فیشی با این فیلتر نیست.</Empty>}
      <ul className="space-y-2">
        {rows.map(p => (
          <PaymentRow key={p.id} p={p} admin={admin} mentors={mentors} onChanged={onReload} />
        ))}
      </ul>
    </Card>
  );
};

export const PaymentRow: React.FC<{ p: Payment; admin?: boolean; mentors?: MentorOption[]; onChanged: () => void }> = ({ p, admin, mentors, onChanged }) => {
  const [busy, setBusy] = useState('');
  const [err, setErr] = useState('');
  const [needsMentor, setNeedsMentor] = useState(false);

  const decide = async (decision: 'approved' | 'rejected') => {
    if (decision === 'rejected' && !confirm(`فیش ${p.ref} رد شود؟ طرحی که با همین فیش ساخته شده هم بسته می‌شود.`)) return;
    try {
      setBusy(decision);
      setErr('');
      const res = await adminApi.decidePayment(p.id, { decision });
      // تأیید مالی انجام شد ولی دانش‌آموز هنوز مشاور تحصیلی ندارد
      if (res.payment?.needs_mentor) {
        setNeedsMentor(true);
        return;
      }
      onChanged();
    } catch (e: any) {
      setErr(e.message || 'انجام نشد.');
    } finally {
      setBusy('');
    }
  };

  return (
    <li className="border border-slate-200 rounded-xl p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-bold text-sm text-slate-900">{p.student_name || `دانش‌آموز #${fa(p.student_id)}`}</span>
            <StatusBadge status={p.status} />
          </div>
          <div className="text-[11px] text-slate-500 mt-1 flex flex-wrap gap-x-3 gap-y-1">
            <span className="font-mono" dir="ltr">
              {p.mobile}
            </span>
            <span>
              پیگیری:{' '}
              <span className="font-mono" dir="ltr">
                {p.ref}
              </span>
            </span>
            <span>واریز: {jDate(p.paid_at)}</span>
            <span>ثبت: {p.created_name}</span>
            {p.decided_name && <span>تصمیم: {p.decided_name}</span>}
          </div>
          {p.note && <div className="text-[11px] text-slate-600 mt-1 whitespace-pre-line">{p.note}</div>}
        </div>
        <div className="flex items-center gap-2">
          <span className="font-black text-sm whitespace-nowrap">{toman(p.amount)}</span>
          {admin && p.status !== 'approved' && (
            <Button size="sm" variant="success" loading={busy === 'approved'} onClick={() => decide('approved')}>
              <BadgeCheck className="w-4 h-4" /> تأیید
            </Button>
          )}
          {admin && p.status !== 'rejected' && (
            <Button size="sm" variant="danger" loading={busy === 'rejected'} onClick={() => decide('rejected')}>
              <XCircle className="w-4 h-4" /> رد
            </Button>
          )}
        </div>
      </div>
      {needsMentor && (
        <AssignMentorInline
          studentId={p.student_id}
          studentName={p.student_name}
          mentors={mentors || []}
          onDone={() => {
            setNeedsMentor(false);
            onChanged();
          }}
          onSkip={() => {
            setNeedsMentor(false);
            onChanged();
          }}
        />
      )}
      {err && <div className="text-[11px] text-red-600 mt-2">{err}</div>}
    </li>
  );
};

/** بعد از تأیید فیش، وصل کردن دانش‌آموزِ بی‌مشاور به یک مشاور تحصیلی. */
export const AssignMentorInline: React.FC<{
  studentId: number;
  studentName: string;
  mentors: MentorOption[];
  onDone: () => void;
  onSkip?: () => void;
}> = ({ studentId, studentName, mentors, onDone, onSkip }) => {
  const [mentor, setMentor] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const save = async () => {
    if (!mentor) return setErr('یک مشاور انتخاب کن.');
    try {
      setBusy(true);
      setErr('');
      await adminApi.assignMentor(studentId, Number(mentor));
      onDone();
    } catch (e: any) {
      setErr(e.message || 'اتصال انجام نشد.');
      setBusy(false);
    }
  };

  return (
    <div className="mt-3 bg-amber-50 border border-amber-200 rounded-xl p-3 space-y-2">
      <div className="text-xs font-bold text-amber-900 flex items-center gap-2">
        <UserCheck className="w-4 h-4" />
        فیش تأیید شد؛ {studentName || 'این دانش‌آموز'} هنوز مشاور تحصیلی ندارد.
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <select value={mentor} onChange={e => setMentor(e.target.value)} className={`${inputCls} w-auto py-2`} aria-label="مشاور تحصیلی">
          <option value="">انتخاب مشاور</option>
          {mentors.map(m => (
            <option key={m.mentor_id} value={m.mentor_id}>
              {m.name}
              {m.specialty ? ` (${m.specialty})` : ''} — {fa(m.active_students)} دانش‌آموز
            </option>
          ))}
        </select>
        <Button size="sm" loading={busy} onClick={save}>
          اتصال
        </Button>
        {onSkip && (
          <Button size="sm" variant="ghost" onClick={onSkip}>
            بعداً
          </Button>
        )}
      </div>
      {err && <div className="text-[11px] text-red-600">{err}</div>}
    </div>
  );
};

const StandalonePaymentForm: React.FC<{ plans: PlanCatalogItem[]; onDone: () => void }> = ({ plans, onDone }) => {
  const [mobile, setMobile] = useState('');
  const [amount, setAmount] = useState('');
  const [ref, setRef] = useState('');
  const [paidOffset, setPaidOffset] = useState(0);
  const [withPlan, setWithPlan] = useState(false);
  const [plan, setPlan] = useState('');
  const [months, setMonths] = useState('1');
  const [note, setNote] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (normalizeMobile(mobile).length !== 11) return setError('موبایل دانش‌آموز درست نیست.');
    if (money(amount) <= 0) return setError('مبلغ را وارد کن.');
    if (!ref.trim()) return setError('شماره پیگیری لازم است.');
    if (withPlan && !plan) return setError('طرح را انتخاب کن.');
    try {
      setSaving(true);
      await salesApi.addPayment({
        mobile: normalizeMobile(mobile),
        amount: money(amount),
        ref: ref.trim(),
        paid_at: addDaysIso(todayIso(), -paidOffset),
        note: note.trim() || undefined,
        plan_name: withPlan ? plan : undefined,
        months: withPlan ? Number(months) : undefined,
        start_date: withPlan ? todayIso() : undefined,
      });
      onDone();
    } catch (err: any) {
      setError(err.message || 'فیش ثبت نشد.');
      setSaving(false);
    }
  };

  return (
    <form onSubmit={submit} className="bg-slate-50 border border-slate-200 rounded-xl p-3 space-y-3">
      <div className="text-sm font-black text-slate-900">فیش برای دانش‌آموزی که از قبل پرونده دارد (تمدید یا قسط)</div>
      <div className="grid sm:grid-cols-4 gap-3">
        <div>
          <Label htmlFor="sp-mobile" required>
            موبایل
          </Label>
          <input id="sp-mobile" value={mobile} onChange={e => setMobile(e.target.value)} dir="ltr" inputMode="numeric" className={`${inputCls} font-mono`} />
        </div>
        <div>
          <Label htmlFor="sp-amount" required>
            مبلغ
          </Label>
          <input id="sp-amount" value={amount} onChange={e => setAmount(e.target.value)} dir="ltr" inputMode="numeric" className={`${inputCls} font-mono`} />
        </div>
        <div>
          <Label htmlFor="sp-ref" required>
            شماره پیگیری
          </Label>
          <input id="sp-ref" value={ref} onChange={e => setRef(e.target.value)} dir="ltr" className={`${inputCls} font-mono`} />
        </div>
        <div>
          <Label htmlFor="sp-paid">تاریخ واریز</Label>
          <select id="sp-paid" value={paidOffset} onChange={e => setPaidOffset(Number(e.target.value))} className={inputCls}>
            {[0, 1, 2, 3, 7].map(d => (
              <option key={d} value={d}>
                {d === 0 ? 'امروز' : jShort(addDaysIso(todayIso(), -d))}
              </option>
            ))}
          </select>
        </div>
      </div>
      <label className="flex items-center gap-2 text-xs font-bold text-slate-700">
        <input type="checkbox" checked={withPlan} onChange={e => setWithPlan(e.target.checked)} />
        طرح تازه هم برای این دانش‌آموز ثبت شود (تمدید)
      </label>
      {withPlan && (
        <div className="grid sm:grid-cols-2 gap-3">
          <div>
            <Label htmlFor="sp-plan" required>
              طرح
            </Label>
            <select id="sp-plan" value={plan} onChange={e => setPlan(e.target.value)} className={inputCls}>
              <option value="">انتخاب کنید</option>
              {plans.map(p => (
                <option key={p.name} value={p.name}>
                  {p.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <Label htmlFor="sp-months">مدت</Label>
            <select id="sp-months" value={months} onChange={e => setMonths(e.target.value)} className={inputCls}>
              {[1, 2, 3, 4, 6, 9, 12].map(m => (
                <option key={m} value={m}>
                  {fa(m)} ماه
                </option>
              ))}
            </select>
          </div>
        </div>
      )}
      <div>
        <Label htmlFor="sp-note">یادداشت</Label>
        <input id="sp-note" value={note} onChange={e => setNote(e.target.value)} className={inputCls} />
      </div>
      {error && <Alert kind="error">{error}</Alert>}
      <Button type="submit" loading={saving} size="sm">
        ثبت فیش
      </Button>
    </form>
  );
};

/* ------------------------------------------------------------- کارنامه */

const ReportTab: React.FC = () => {
  const [data, setData] = useState<SalesSummary | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    const r = jMonthRange(currentJMonth());
    salesApi
      .summary({ from: r.from, to: r.to })
      .then(setData)
      .catch((e: any) => setError(e.message || 'کارنامه بارگذاری نشد.'));
  }, []);

  if (error) return <Alert kind="error">{error}</Alert>;
  if (!data) return <Spinner />;

  const s = data.summary;
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Stat label="فیش تأییدشده" value={toman(s.approved_amount)} hint={`${fa(s.approved_count)} فیش`} tone="emerald" />
        <Stat label="در انتظار تأیید" value={toman(s.pending_amount)} hint={`${fa(s.pending_count)} فیش`} tone="orange" />
        <Stat label="درصد شما" value={`${fa(data.percent)}٪`} />
        <Stat label="سهم این ماه" value={toman(data.payout)} tone="sky" />
      </div>
      <Card title="فیش‌های این ماه" icon={<Clock3 className="w-4 h-4" />}>
        {data.payments.length === 0 ? (
          <Empty>هنوز فیشی ثبت نکرده‌اید.</Empty>
        ) : (
          <ul className="space-y-2">
            {data.payments.map(p => (
              <PaymentRow key={p.id} p={p} onChanged={() => {}} />
            ))}
          </ul>
        )}
        <p className="text-[11px] text-slate-500 mt-3">سهم فقط از فیش‌هایی حساب می‌شود که مدیر تأیید کرده باشد. مبنای ماه، تاریخ واریز است نه تاریخ ثبت.</p>
      </Card>
    </div>
  );
};
