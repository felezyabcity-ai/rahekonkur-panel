import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  BarChart3,
  ChevronLeft,
  ChevronRight,
  Database,
  ExternalLink,
  Hourglass,
  MessageSquare,
  Phone,
  Receipt,
  RefreshCw,
  Shield,
  UserPlus,
  Lock,
  UserCheck,
  Users,
  Wallet,
} from 'lucide-react';
import { AdminDashboardData, MentorOption, Settlement, adminApi, salesApi } from '../api';
import { fa, jShort, toman } from '../lib/format';
import { JMonth, currentJMonth, jMonthLabel, jMonthRange, pad, shiftJMonth } from '../lib/jalali';
import { Alert, Button, Card, Empty, Label, Spinner, Stat, inputCls } from './ui';
import { AssignMentorInline, SalesPortal } from './SalesPortal';
import { Tickets } from './Tickets';
import { UnreadDot, UnreadPopup, useOpenTicketsRequest, useUnread } from './Unread';
import { PasswordCard } from './Security';

const WP = 'https://rahekonkur.ir/wp-admin/admin.php?page=';

type Tab = 'overview' | 'money' | 'payments' | 'tickets' | 'staff';

const TABS: { key: Tab; label: string; icon: React.ReactNode }[] = [
  { key: 'overview', label: 'خلاصه', icon: <BarChart3 className="w-4 h-4" /> },
  { key: 'money', label: 'حق‌الزحمه', icon: <Wallet className="w-4 h-4" /> },
  { key: 'payments', label: 'فیش‌ها و ثبت‌نام', icon: <Receipt className="w-4 h-4" /> },
  { key: 'tickets', label: 'گفت‌وگوها', icon: <MessageSquare className="w-4 h-4" /> },
  { key: 'staff', label: 'کارکنان', icon: <Users className="w-4 h-4" /> },
];

export const AdminDashboard: React.FC<{ currentUser?: any; kind?: 'admin' | 'sales_manager' | 'mentor_manager' }> = ({ kind = 'admin' }) => {
  // تب‌ها بر اساس نقش. این فقط راحتی رابط است — بستن واقعی سمت سرور انجام شده.
  const tabs = useMemo(
    () =>
      TABS.filter(t => {
        if (kind === 'admin') return true;
        if (kind === 'sales_manager') return t.key !== 'money';
        return t.key === 'overview' || t.key === 'tickets';
      }),
    [kind]
  );
  const unread = useUnread();
  const [tab, setTab] = useState<Tab>(() => {
    try {
      const t = sessionStorage.getItem('rk_admin_tab');
      sessionStorage.removeItem('rk_admin_tab');
      if (t && TABS.some(x => x.key === t)) return t as Tab;
    } catch {}
    return 'overview';
  });
  const [month, setMonth] = useState<JMonth>(currentJMonth());
  const [data, setData] = useState<AdminDashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      setLoading(true);
      setError('');
      const r = jMonthRange(month);
      setData(await adminApi.dashboard(r.from, r.to));
    } catch (err: any) {
      setError(err.message || 'داشبورد بارگذاری نشد.');
    } finally {
      setLoading(false);
    }
  }, [month]);

  useEffect(() => {
    load();
  }, [load]);

  const isCurrent = (() => {
    const c = currentJMonth();
    return c.jy === month.jy && c.jm === month.jm;
  })();

  return (
    <div className="max-w-7xl mx-auto px-4 py-5 space-y-5">
      <div className="bg-white border border-slate-200 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="font-black text-lg text-slate-900">داشبورد مدیر</div>
          <div className="text-xs text-slate-500">همه‌ی اعداد از داده‌ی ثبت‌شده‌ی سامانه است</div>
        </div>
        {tab !== 'payments' && tab !== 'staff' && tab !== 'tickets' && (
          <div className="flex items-center gap-2">
            <button type="button" onClick={() => setMonth(m => shiftJMonth(m, -1))} className="p-2 rounded-lg border border-slate-200 hover:bg-slate-50" aria-label="ماه قبل">
              <ChevronRight className="w-4 h-4" />
            </button>
            <div className="text-center min-w-28">
              <div className="text-sm font-black">{jMonthLabel(month)}</div>
              {!isCurrent && (
                <button type="button" onClick={() => setMonth(currentJMonth())} className="text-[11px] text-orange-600 font-bold">
                  ماه جاری
                </button>
              )}
            </div>
            <button type="button" onClick={() => setMonth(m => shiftJMonth(m, 1))} className="p-2 rounded-lg border border-slate-200 hover:bg-slate-50" aria-label="ماه بعد">
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button type="button" onClick={load} className="p-2 text-slate-400 hover:text-slate-700" aria-label="به‌روزرسانی">
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        )}
      </div>

      <nav className="grid grid-cols-3 sm:grid-cols-5 gap-1 bg-white border border-slate-200 rounded-2xl p-1" aria-label="بخش‌های داشبورد">
        {tabs.map(t => (
          <button
            key={t.key}
            type="button"
            onClick={() => setTab(t.key)}
            className={`flex flex-col sm:flex-row items-center justify-center gap-1 sm:gap-1.5 px-1 py-2 rounded-xl text-[11px] sm:text-sm font-bold ${
              tab === t.key ? 'bg-orange-50 text-orange-700' : 'text-slate-600 hover:bg-slate-50'
            }`}
          >
            {t.icon}
            {t.label}
            {t.key === 'tickets' && <UnreadDot count={unread.count} />}
          </button>
        ))}
      </nav>

      {error && <Alert kind="error">{error}</Alert>}

      {tab === 'payments' && <SalesPortal admin embedded />}
      {tab === 'tickets' && <Tickets viewer="admin" onSeen={unread.refresh} />}
      <UnreadPopup count={unread.count} items={unread.items} />
      {tab === 'staff' && <StaffTab data={data} onChanged={load} />}
      {(tab === 'overview' || tab === 'money') && !data && !error && <Spinner />}
      {tab === 'overview' && data && <Overview data={data} onGo={setTab} onChanged={load} />}
      {tab === 'money' && data && kind === 'admin' && <MoneyTab data={data} month={month} onChanged={load} />}
    </div>
  );
};

/* ------------------------------------------------------------------ خلاصه */

const StudentTable: React.FC<{ rows: AdminDashboardData['students']['expiring']; extra: (r: any) => React.ReactNode; extraLabel: string }> = ({ rows, extra, extraLabel }) => (
  <div className="overflow-x-auto -mx-1">
    <table className="w-full text-xs">
      <thead>
        <tr className="text-slate-500 text-right">
          <th className="font-bold p-2">دانش‌آموز</th>
          <th className="font-bold p-2">موبایل</th>
          <th className="font-bold p-2">مشاور</th>
          <th className="font-bold p-2">طرح</th>
          <th className="font-bold p-2">{extraLabel}</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-slate-100">
        {rows.map(r => (
          <tr key={r.student_id}>
            <td className="p-2 font-bold whitespace-nowrap">
              {r.name}
              {r.grade && <span className="font-normal text-slate-400"> · {r.grade}</span>}
            </td>
            <td className="p-2">
              {r.mobile && (
                <a href={`tel:${r.mobile}`} className="font-mono text-emerald-700" dir="ltr">
                  {r.mobile}
                </a>
              )}
            </td>
            <td className="p-2 whitespace-nowrap">{r.mentor_name || <span className="text-red-600">ندارد</span>}</td>
            <td className="p-2 whitespace-nowrap">{r.plan_name || '—'}</td>
            <td className="p-2 whitespace-nowrap">{extra(r)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

const NoMentorCard: React.FC<{ rows: AdminDashboardData['students']['no_mentor']; onChanged: () => void }> = ({ rows, onChanged }) => {
  const [mentors, setMentors] = useState<MentorOption[]>([]);
  useEffect(() => {
    salesApi
      .mentors()
      .then(r => setMentors(r.mentors))
      .catch(() => {});
  }, []);
  return (
    <Card title="دانش‌آموزان بدون مشاور تحصیلی" icon={<UserCheck className="w-4 h-4" />}>
      <ul className="space-y-3">
        {rows.map(r => (
          <li key={r.student_id} className="border border-slate-200 rounded-xl p-3">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="font-bold">{r.name}</span>
              {r.grade && <span className="text-slate-400">· {r.grade}</span>}
              {r.mobile && (
                <a href={`tel:${r.mobile}`} className="font-mono text-xs text-emerald-700" dir="ltr">
                  {r.mobile}
                </a>
              )}
              {r.plan_name && <span className="text-xs text-slate-500">· {r.plan_name}</span>}
            </div>
            <AssignMentorInline studentId={r.student_id} studentName={r.name} mentors={mentors} onDone={onChanged} />
          </li>
        ))}
      </ul>
      <p className="text-[11px] text-slate-500 mt-3">تا وقتی مشاور وصل نشده، برنامه‌ی هفتگی و تکلیفی برای این دانش‌آموز نوشته نمی‌شود.</p>
    </Card>
  );
};

const Overview: React.FC<{ data: AdminDashboardData; onGo: (t: Tab) => void; onChanged: () => void }> = ({ data, onGo, onChanged }) => {
  const s = data.students;
  const totalPayout = data.mentors.reduce((a, m) => a + (m.payout || 0), 0) + data.sales.reduce((a, m) => a + m.payout, 0);
  const unsetMentors = data.mentors.filter(m => m.percent === null).length;
  const pay = data.payments || { pending: 0, pending_amount: 0, approved_amount: 0 };
  const tk = data.tickets || { total: 0, overdue: 0, rows: [] };
  const approvedCount = data.sales.reduce((a, x) => a + x.approved_count, 0);
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Stat label="دانش‌آموز با طرح فعال" value={fa(s.active)} hint={`از ${fa(s.total)} پرونده`} tone="emerald" />
        <Stat label="فیش تأییدشده‌ی این ماه" value={toman(pay.approved_amount)} hint={`${fa(approvedCount)} فیش`} tone="orange" />
        <Stat label="در انتظار تأیید شما" value={fa(pay.pending)} hint={toman(pay.pending_amount)} />
        <Stat label="حق‌الزحمه‌ی این ماه" value={toman(totalPayout)} hint={unsetMentors ? `${fa(unsetMentors)} مشاور بدون درصد` : 'همه‌ی درصدها تعیین شده'} tone="sky" />
      </div>

      {(pay.pending > 0 || tk.total > 0 || data.sales.length === 0 || s.no_mentor.length > 0) && (
        <Card title="نیاز به اقدام" icon={<AlertTriangle className="w-4 h-4" />}>
          <ul className="space-y-2 text-sm">
            {data.sales.length === 0 && (
              <li>
                هنوز هیچ مشاور فروشی تعریف نشده.{' '}
                <button type="button" onClick={() => onGo('staff')} className="text-orange-600 font-bold">
                  افزودن مشاور فروش
                </button>
              </li>
            )}
            {tk.total > 0 && (
              <li>
                {fa(tk.total)} گفت‌وگوی بی‌جواب
                {tk.overdue > 0 && <span className="text-red-600 font-bold"> ({fa(tk.overdue)} تا بیش از ۲۴ ساعت)</span>}.{' '}
                <button type="button" onClick={() => onGo('tickets')} className="text-orange-600 font-bold">
                  دیدن گفت‌وگوها
                </button>
              </li>
            )}
            {pay.pending > 0 && (
              <li>
                {fa(pay.pending)} فیش در انتظار تأیید شما ({toman(pay.pending_amount)}).{' '}
                <button type="button" onClick={() => onGo('payments')} className="text-orange-600 font-bold">
                  بررسی فیش‌ها
                </button>
              </li>
            )}
            {s.no_mentor.length > 0 && <li>{fa(s.no_mentor.length)} دانش‌آموز هنوز مشاور تحصیلی ندارد — پایین همین صفحه وصلشان کن.</li>}
          </ul>
        </Card>
      )}

      {s.no_mentor.length > 0 && <NoMentorCard rows={s.no_mentor} onChanged={onChanged} />}

      <Card title="طرح‌های رو به پایان (۱۰ روز آینده) و تازه تمام‌شده" icon={<Hourglass className="w-4 h-4" />}>
        {s.expiring.length === 0 ? (
          <Empty>طرحی نزدیک پایان نیست.</Empty>
        ) : (
          <StudentTable
            rows={s.expiring}
            extraLabel="پایان"
            extra={r => (
              <span className={r.days_left < 0 ? 'text-red-600 font-bold' : r.days_left <= 3 ? 'text-amber-700 font-bold' : ''}>
                {jShort(r.plan_end)} · {r.days_left < 0 ? `${fa(-r.days_left)} روز گذشته` : r.days_left === 0 ? 'امروز' : `${fa(r.days_left)} روز مانده`}
              </span>
            )}
          />
        )}
      </Card>

      <Card title="دانش‌آموزان کم‌کار (۳ روز یا بیشتر بدون ثبت مطالعه)" icon={<AlertTriangle className="w-4 h-4" />}>
        {s.inactive.length === 0 ? (
          <Empty>همه‌ی دانش‌آموزان در سه روز اخیر مطالعه ثبت کرده‌اند.</Empty>
        ) : (
          <StudentTable
            rows={s.inactive}
            extraLabel="آخرین ثبت"
            extra={r => (r.idle_days === null ? <span className="text-red-600">هیچ ثبتی ندارد</span> : `${fa(r.idle_days)} روز پیش`)}
          />
        )}
      </Card>

    </div>
  );
};

/* ------------------------------------------------------------- حق‌الزحمه */

const PercentCell: React.FC<{ userId: number; value: number | null; placeholder?: string; onSaved: () => void }> = ({ userId, value, placeholder, onSaved }) => {
  const [v, setV] = useState(value === null ? '' : String(value));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  useEffect(() => setV(value === null ? '' : String(value)), [value]);
  const dirty = v !== (value === null ? '' : String(value));
  const save = async () => {
    try {
      setBusy(true);
      setErr('');
      await adminApi.setShare({ user_id: userId, percent: v });
      onSaved();
    } catch (e: any) {
      setErr(e.message || 'ذخیره نشد');
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="flex items-center gap-1">
      <input
        value={v}
        onChange={e => setV(e.target.value)}
        onKeyDown={e => e.key === 'Enter' && dirty && save()}
        inputMode="decimal"
        placeholder={placeholder || '—'}
        className="w-16 px-2 py-1 border border-slate-300 rounded-lg text-center text-xs"
        aria-label="درصد"
      />
      <span className="text-slate-400">٪</span>
      {dirty && (
        <button type="button" onClick={save} disabled={busy} className="text-[11px] font-bold text-white bg-slate-900 rounded-md px-2 py-1">
          ذخیره
        </button>
      )}
      {err && <span className="text-[10px] text-red-600">{err}</span>}
    </div>
  );
};

/** بستن ماه: عکس گرفتن از سهم‌ها و قفل‌کردنشان تا بعداً با تغییر درصد جابه‌جا نشوند. */
const SettlementCard: React.FC<{ period: string; month: JMonth; data: AdminDashboardData; onChanged: () => void }> = ({ period, month, data, onChanged }) => {
  const [rows, setRows] = useState<Settlement[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState('');

  const load = useCallback(async () => {
    try {
      const r = await adminApi.settlements(period);
      setRows(r.rows);
    } catch {
      setRows([]);
    }
  }, [period]);

  useEffect(() => {
    setDone('');
    setError('');
    load();
  }, [load]);

  const close = async () => {
    const live = data.mentors.reduce((a, m) => a + (m.payout || 0), 0) + data.sales.reduce((a, m) => a + m.payout, 0);
    if (!confirm(`سهم‌های ${jMonthLabel(month)} با جمع ${toman(live)} قفل شود؟ بعد از این، تغییر درصدها روی این ماه اثری ندارد.`)) return;
    try {
      setBusy(true);
      setError('');
      const r = await adminApi.closeSettlement({ period, ...jMonthRange(month) });
      setRows(r.rows);
      setDone('ماه بسته شد.');
    } catch (e: any) {
      setError(e.message || 'بستن ماه انجام نشد.');
    } finally {
      setBusy(false);
    }
  };

  const reopen = async () => {
    if (!confirm('قفل این ماه برداشته شود؟ عددها دوباره لحظه‌ای حساب می‌شوند.')) return;
    try {
      setBusy(true);
      setError('');
      await adminApi.reopenSettlement(period);
      setRows([]);
      setDone('');
      onChanged();
    } catch (e: any) {
      setError(e.message || 'باز کردن انجام نشد.');
    } finally {
      setBusy(false);
    }
  };

  const togglePaid = async (row: Settlement) => {
    try {
      const r = await adminApi.markPaid(row.id, row.status !== 'paid');
      setRows(r.rows);
    } catch (e: any) {
      setError(e.message || 'ثبت پرداخت انجام نشد.');
    }
  };

  const locked = (rows?.length || 0) > 0;
  const total = (rows || []).reduce((a, r) => a + r.payout, 0);
  const paid = (rows || []).filter(r => r.status === 'paid').reduce((a, r) => a + r.payout, 0);

  return (
    <Card
      title={`تسویه‌ی ${jMonthLabel(month)}`}
      icon={<Lock className="w-4 h-4" />}
      action={
        locked ? (
          <Button size="sm" variant="ghost" loading={busy} onClick={reopen}>
            باز کردن قفل
          </Button>
        ) : (
          <Button size="sm" variant="dark" loading={busy} onClick={close}>
            بستن ماه و قفل سهم‌ها
          </Button>
        )
      }
    >
      {error && <Alert kind="error">{error}</Alert>}
      {done && !error && <Alert kind="success">{done}</Alert>}

      {!locked && (
        <p className="text-xs text-slate-600 leading-6">
          این ماه هنوز بسته نشده و عددهای پایین لحظه‌ای‌اند — با تغییر هر درصدی جابه‌جا می‌شوند. بعد از تعیین تکلیف همه‌ی فیش‌های ماه، قفلشان کن تا سند پرداخت داشته باشی.
        </p>
      )}

      {locked && rows && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-4">
            <Stat label="جمع سهم قفل‌شده" value={toman(total)} tone="sky" />
            <Stat label="پرداخت‌شده" value={toman(paid)} tone="emerald" />
            <Stat label="مانده" value={toman(total - paid)} tone="orange" />
          </div>
          <div className="overflow-x-auto -mx-1">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-slate-500 text-right">
                  <th className="font-bold p-2">نفر</th>
                  <th className="font-bold p-2">نقش</th>
                  <th className="font-bold p-2">مبنا</th>
                  <th className="font-bold p-2">درصد</th>
                  <th className="font-bold p-2">سهم</th>
                  <th className="font-bold p-2">وضعیت</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {rows.map(r => (
                  <tr key={r.id}>
                    <td className="p-2 font-bold whitespace-nowrap">
                      {r.name}
                      {r.detail && <div className="font-normal text-[11px] text-slate-400">{r.detail}</div>}
                    </td>
                    <td className="p-2 whitespace-nowrap">{r.role === 'sales' ? 'فروش' : 'تحصیلی'}</td>
                    <td className="p-2 whitespace-nowrap">{toman(r.base_amount)}</td>
                    <td className="p-2">{fa(r.percent)}٪</td>
                    <td className="p-2 whitespace-nowrap font-black">{toman(r.payout)}</td>
                    <td className="p-2 whitespace-nowrap">
                      <Button size="sm" variant={r.status === 'paid' ? 'ghost' : 'success'} onClick={() => togglePaid(r)}>
                        {r.status === 'paid' ? `پرداخت شد · ${jShort(r.paid_at)}` : 'ثبت پرداخت'}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-[11px] text-slate-500 mt-3">
            این عددها عکسِ لحظه‌ی بستن ماه‌اند و دیگر تغییر نمی‌کنند. ماهی که در آن پرداخت ثبت شده باز نمی‌شود.
          </p>
        </>
      )}
    </Card>
  );
};

const MoneyTab: React.FC<{ data: AdminDashboardData; month: JMonth; onChanged: () => void }> = ({ data, month, onChanged }) => {
  const mentorTotal = data.mentors.reduce((a, m) => a + (m.payout || 0), 0);
  const salesTotal = data.sales.reduce((a, m) => a + m.payout, 0);
  const period = `${month.jy}-${pad(month.jm)}`;
  return (
    <div className="space-y-5">
      <SettlementCard period={period} month={month} data={data} onChanged={onChanged} />
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
        <Stat label="سهم مشاوران تحصیلی" value={toman(mentorTotal)} tone="sky" />
        <Stat label="سهم مشاوران فروش" value={toman(salesTotal)} tone="orange" />
        <Stat label="فیش تأییدشده‌ی این ماه" value={toman(data.payments?.approved_amount || 0)} hint={`${fa(data.sales.reduce((a, x) => a + x.approved_count, 0))} فیش`} tone="emerald" />
      </div>

      <Card title="مشاوران تحصیلی" icon={<Users className="w-4 h-4" />}>
        {data.mentors.length === 0 ? (
          <Empty>مشاوری ثبت نشده است.</Empty>
        ) : (
          <div className="overflow-x-auto -mx-1">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-slate-500 text-right">
                  <th className="font-bold p-2">مشاور</th>
                  <th className="font-bold p-2">دانش‌آموز فعال</th>
                  <th className="font-bold p-2">با طرح پرداختی</th>
                  <th className="font-bold p-2">وصول ناقص</th>
                  <th className="font-bold p-2">مبنای ماهانه</th>
                  <th className="font-bold p-2">درصد</th>
                  <th className="font-bold p-2">حق‌الزحمه</th>
                  <th className="font-bold p-2">عمل به برنامه</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {data.mentors.map(m => (
                  <tr key={m.user_id || m.name}>
                    <td className="p-2 font-bold whitespace-nowrap">{m.name}</td>
                    <td className="p-2">{fa(m.active_students)}</td>
                    <td className="p-2">{fa(m.paying_students)}</td>
                    <td className="p-2">{m.partial_students ? <span className="text-amber-700 font-bold">{fa(m.partial_students)}</span> : '—'}</td>
                    <td className="p-2 whitespace-nowrap">{toman(m.base_amount)}</td>
                    <td className="p-2">{m.user_id ? <PercentCell userId={m.user_id} value={m.percent} placeholder="تعیین نشده" onSaved={onChanged} /> : '—'}</td>
                    <td className="p-2 whitespace-nowrap font-black">{m.payout === null ? <span className="text-amber-700 font-bold">درصد تعیین نشده</span> : toman(m.payout)}</td>
                    <td className="p-2">{m.week_rate === null ? '—' : `${fa(m.week_rate)}٪`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="text-[11px] text-slate-500 mt-3 leading-6">
          مبنای ماهانه = برای هر دانش‌آموز، مبلغ ماهانه‌ی طرح فعالش ضرب در نسبت پولی که واقعاً وصول شده. اگر نصف طرح پرداخت شده، نصف مبنا. دانش‌آموزی که هیچ فیشی
          برایش ثبت نشده (قبل از راه‌افتادن این بخش) کامل حساب می‌شود. ستون «وصول ناقص» تعداد دانش‌آموزهایی است که طرحشان تسویه نشده. درصد را بنویس و «ذخیره» را بزن.
        </p>
      </Card>

      <Card title="مشاوران فروش" icon={<Phone className="w-4 h-4" />}>
        {data.sales.length === 0 ? (
          <Empty>مشاور فروشی تعریف نشده است.</Empty>
        ) : (
          <div className="overflow-x-auto -mx-1">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-slate-500 text-right">
                  <th className="font-bold p-2">مشاور فروش</th>
                  <th className="font-bold p-2">فیش تأییدشده</th>
                  <th className="font-bold p-2">مبلغ تأییدشده</th>
                  <th className="font-bold p-2">در انتظار</th>
                  <th className="font-bold p-2">درصد</th>
                  <th className="font-bold p-2">سهم</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {data.sales.map(s => (
                  <tr key={s.user_id}>
                    <td className="p-2 font-bold whitespace-nowrap">
                      {s.name}
                      {s.paused && <span className="mr-1 text-[10px] text-slate-500">(غیرفعال)</span>}
                    </td>
                    <td className="p-2">{fa(s.approved_count)}</td>
                    <td className="p-2 whitespace-nowrap">{toman(s.approved_amount)}</td>
                    <td className="p-2 whitespace-nowrap">
                      {s.pending_count > 0 ? (
                        <span className="text-amber-700 font-bold">
                          {fa(s.pending_count)} فیش · {toman(s.pending_amount)}
                        </span>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td className="p-2">
                      <PercentCell userId={s.user_id} value={s.percent} onSaved={onChanged} />
                    </td>
                    <td className="p-2 whitespace-nowrap font-black">{toman(s.payout)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="text-[11px] text-slate-500 mt-3">
          سهم = درصد × مبلغ فیش‌هایی که خودِ او ثبت کرده و شما تأیید کرده‌اید. فیش در انتظار تأیید هیچ سهمی نمی‌سازد. مبنای ماه، تاریخ واریز است. پیش‌فرض ۱۵٪ است.
        </p>
      </Card>
    </div>
  );
};

/* ------------------------------------------------------------------ کارکنان */

const StaffTab: React.FC<{ data: AdminDashboardData | null; onChanged: () => void }> = ({ data, onChanged }) => {
  const [name, setName] = useState('');
  const [mobile, setMobile] = useState('');
  const [percent, setPercent] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [created, setCreated] = useState<{ mobile: string; password: string; name: string } | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    try {
      setSaving(true);
      const r = await adminApi.createSales({ name: name.trim(), mobile, percent: percent.trim() || undefined });
      setCreated({ mobile: r.mobile, password: r.password, name: name.trim() });
      setName('');
      setMobile('');
      setPercent('');
      onChanged();
    } catch (err: any) {
      setError(err.message || 'ساخت حساب انجام نشد.');
    } finally {
      setSaving(false);
    }
  };

  const togglePause = async (userId: number, paused: boolean) => {
    try {
      await adminApi.setShare({ user_id: userId, paused });
      onChanged();
    } catch (err: any) {
      setError(err.message || 'انجام نشد.');
    }
  };

  return (
    <div className="space-y-5">
      <Card title="افزودن مشاور فروش" icon={<UserPlus className="w-4 h-4" />}>
        <form onSubmit={submit} className="grid sm:grid-cols-4 gap-3 items-end">
          <div>
            <Label htmlFor="st-name" required>
              نام و نام خانوادگی
            </Label>
            <input id="st-name" value={name} onChange={e => setName(e.target.value)} className={inputCls} />
          </div>
          <div>
            <Label htmlFor="st-mobile" required>
              موبایل
            </Label>
            <input id="st-mobile" value={mobile} onChange={e => setMobile(e.target.value)} dir="ltr" inputMode="numeric" className={`${inputCls} font-mono`} />
          </div>
          <div>
            <Label htmlFor="st-pct">درصد (خالی = ۱۵)</Label>
            <input id="st-pct" value={percent} onChange={e => setPercent(e.target.value)} inputMode="decimal" className={inputCls} />
          </div>
          <Button type="submit" loading={saving} variant="dark">
            ساخت حساب
          </Button>
        </form>
        {error && (
          <div className="mt-3">
            <Alert kind="error">{error}</Alert>
          </div>
        )}
        {created && (
          <div className="mt-3 bg-emerald-50 border border-emerald-200 rounded-xl p-3 text-sm space-y-1">
            <div className="font-bold text-emerald-900">حساب {created.name} ساخته شد. این رمز فقط همین یک بار نمایش داده می‌شود:</div>
            <div>
              موبایل: <span className="font-mono" dir="ltr">{created.mobile}</span> · رمز موقت:{' '}
              <span className="font-mono bg-white border rounded px-2 py-0.5" dir="ltr">
                {created.password}
              </span>
            </div>
            <div className="text-xs text-emerald-800">در اولین ورود باید رمز را عوض کند. با کد پیامکی هم می‌تواند وارد شود. از همین حالا می‌تواند دانش‌آموز ثبت‌نام کند و فیش بفرستد.</div>
          </div>
        )}
      </Card>

      <Card title="مشاوران فروش" icon={<Phone className="w-4 h-4" />}>
        {!data || data.sales.length === 0 ? (
          <Empty>هنوز کسی اضافه نشده است.</Empty>
        ) : (
          <ul className="divide-y divide-slate-100">
            {data.sales.map(s => (
              <li key={s.user_id} className="py-2 flex flex-wrap items-center justify-between gap-2 text-sm">
                <div>
                  <span className="font-bold">{s.name}</span>{' '}
                  <span className="font-mono text-xs text-slate-500" dir="ltr">
                    {s.mobile}
                  </span>
                  <span className="text-xs text-slate-500"> · {fa(s.approved_count)} فیش تأییدشده</span>
                </div>
                <Button size="sm" variant={s.paused ? 'success' : 'ghost'} onClick={() => togglePause(s.user_id, !s.paused)}>
                  {s.paused ? 'فعال کردن دوباره' : 'غیرفعال کردن (مرخصی)'}
                </Button>
              </li>
            ))}
          </ul>
        )}
        <p className="text-[11px] text-slate-500 mt-2">
          حساب مشاور فروش را شما یا مدیر فروش می‌سازید؛ ثبت‌نام عمومی وجود ندارد. غیرفعال کردن، حساب را حذف نمی‌کند ولی تا فعال‌سازی دوباره نه می‌تواند دانش‌آموز ثبت‌نام کند نه فیش بفرستد.
        </p>
      </Card>

      <Card title="مشاوران تحصیلی و تنظیمات" icon={<Shield className="w-4 h-4" />}>
        <ul className="grid sm:grid-cols-2 gap-3 text-sm">
          {[
            { href: `${WP}rkspb_data&t=mentors`, title: 'افزودن مشاور تحصیلی', icon: <UserPlus className="w-4 h-4" /> },
            { href: `${WP}rkspb_apps`, title: 'درخواست‌های همکاری', icon: <Users className="w-4 h-4" /> },
            { href: `${WP}rkspb_data&t=students`, title: 'مدیریت داده‌ها (ویرایش/حذف)', icon: <Database className="w-4 h-4" /> },
            { href: `${WP}rkspb_sms`, title: 'تنظیمات پیامک', icon: <MessageSquare className="w-4 h-4" /> },
          ].map(l => (
            <li key={l.href}>
              <a href={l.href} target="_blank" rel="noopener" className="flex items-center gap-2 border border-slate-200 hover:border-orange-300 rounded-xl p-3">
                <span className="text-orange-600">{l.icon}</span>
                <span className="font-bold">{l.title}</span>
                <ExternalLink className="w-3 h-3 text-slate-400" />
              </a>
            </li>
          ))}
        </ul>
      </Card>

      <PasswordCard />
    </div>
  );
};

