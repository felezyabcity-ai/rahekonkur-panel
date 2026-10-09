import React, { useCallback, useEffect, useRef, useState } from 'react';
import { BarChart3, BookOpen, CalendarDays, CheckCircle2, Circle, ClipboardList, Clock, MessageSquare, Pause, Play, Plus, Receipt, Settings, Trash2, User, UserCheck } from 'lucide-react';
import { api, StudentOverview, Task } from '../api';
import { daysUntil, fa, formatMinutes, isoDaysAgo, jDate, jShort, jDay, latinDigits, todayIso, toman } from '../lib/format';
import { Alert, Button, Card, DaysBars, Empty, Label, Spinner, Stat, inputCls } from './ui';
import { PasswordCard } from './Security';
import { Tickets } from './Tickets';
import { UnreadDot, UnreadPopup, useOpenTicketsRequest, useUnread } from './Unread';
import { SubjectField } from './fields';
import { StudentWeek } from './StudentWeek';

type Tab = 'home' | 'week' | 'log' | 'tasks' | 'mentor' | 'support' | 'account';

const TABS: { key: Tab; label: string; icon: React.ReactNode }[] = [
  { key: 'home', label: 'خلاصه', icon: <BarChart3 className="w-4 h-4" /> },
  { key: 'week', label: 'برنامه', icon: <CalendarDays className="w-4 h-4" /> },
  { key: 'log', label: 'ثبت مطالعه', icon: <Plus className="w-4 h-4" /> },
  { key: 'tasks', label: 'تکالیف', icon: <ClipboardList className="w-4 h-4" /> },
  { key: 'mentor', label: 'مشاور', icon: <UserCheck className="w-4 h-4" /> },
  { key: 'support', label: 'گفت‌وگو', icon: <MessageSquare className="w-4 h-4" /> },
];

/* کرونومتر در localStorage نگه داشته می‌شود تا با رفرش صفر نشود */
type TimerState = { start: number | null; base: number };
const TIMER_KEY = 'rksp_timer';
function readTimer(): TimerState {
  try {
    const t = JSON.parse(localStorage.getItem(TIMER_KEY) || 'null');
    if (t && typeof t.base === 'number') {
      // کرونومتری که بیش از ۱۶ ساعت روشن مانده، فراموش‌شده حساب می‌شود
      if (t.start && Date.now() - t.start > 16 * 3600 * 1000) return { start: null, base: 0 };
      return { start: typeof t.start === 'number' ? t.start : null, base: t.base };
    }
  } catch {}
  return { start: null, base: 0 };
}
function writeTimer(t: TimerState | null) {
  try {
    if (t && (t.start || t.base)) localStorage.setItem(TIMER_KEY, JSON.stringify(t));
    else localStorage.removeItem(TIMER_KEY);
  } catch {}
}
const timerSeconds = (t: TimerState) => t.base + (t.start ? Math.floor((Date.now() - t.start) / 1000) : 0);

export const StudentPortal: React.FC<{ currentUser: any }> = ({ currentUser }) => {
  const [data, setData] = useState<StudentOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [tab, setTab] = useState<Tab>('home');
  const unread = useUnread();
  useOpenTicketsRequest(() => setTab('support'));
  const [mustChange, setMustChange] = useState<boolean>(!!currentUser?.must_change_password);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      setLoadError('');
      setData(await api.student.overview());
    } catch (err: any) {
      setLoadError(err.message || 'اطلاعات بارگذاری نشد.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (loading && !data) return <Spinner />;
  if (loadError && !data) {
    return (
      <div className="max-w-xl mx-auto px-4 py-10 space-y-3">
        <Alert kind="error">{loadError}</Alert>
        <Button variant="ghost" onClick={load}>
          تلاش دوباره
        </Button>
      </div>
    );
  }
  if (!data) return null;

  const pending = data.tasks.filter(t => !t.done);

  return (
    <div className="max-w-5xl mx-auto px-4 py-5 space-y-5">
      {mustChange && <PasswordCard forced onDone={() => setMustChange(false)} />}

      <div className="bg-gradient-to-l from-orange-500 to-amber-500 rounded-2xl p-4 sm:p-5 text-white relative">
        <button
          type="button"
          onClick={() => setTab(tab === 'account' ? 'home' : 'account')}
          className="absolute left-3 top-3 inline-flex items-center gap-1 text-[11px] font-bold bg-white/20 hover:bg-white/30 rounded-lg px-2 py-1"
        >
          <Settings className="w-3.5 h-3.5" /> حساب و رمز
        </button>
        <div className="text-lg sm:text-xl font-black pl-24">{data.student.name ? `سلام ${data.student.name}` : 'سلام'}</div>
        <div className="text-xs sm:text-sm text-amber-50 mt-1 flex flex-wrap gap-x-3 gap-y-1">
          {data.student.grade && <span>پایه‌ی {data.student.grade}</span>}
          {data.student.field && <span>رشته‌ی {data.student.field}</span>}
          {data.mentor?.name ? <span>مشاور: {data.mentor.name}</span> : <span>هنوز مشاوری به شما متصل نشده است</span>}
        </div>
      </div>

      <nav className="grid grid-cols-3 sm:grid-cols-6 gap-1 bg-white border border-slate-200 rounded-2xl p-1" aria-label="بخش‌های پرتال">
        {TABS.map(t => (
          <button
            key={t.key}
            type="button"
            onClick={() => setTab(t.key)}
            className={`relative flex flex-col sm:flex-row items-center justify-center gap-1 sm:gap-1.5 px-1 sm:px-3 py-2 rounded-xl text-[11px] sm:text-sm font-bold whitespace-nowrap ${
              tab === t.key ? 'bg-orange-50 text-orange-700' : 'text-slate-600 hover:bg-slate-50'
            }`}
          >
            {t.icon}
            {t.label}
            {t.key === 'support' && <UnreadDot count={unread.count} />}
            {t.key === 'tasks' && pending.length > 0 && (
              <span className="absolute top-0.5 left-1 sm:static bg-orange-600 text-white text-[10px] rounded-full px-1.5 min-w-5">{fa(pending.length)}</span>
            )}
          </button>
        ))}
      </nav>

      {tab === 'home' && <HomeTab data={data} onGo={setTab} onRefresh={load} />}
      {tab === 'week' && <StudentWeek onLogged={load} />}
      {tab === 'log' && <LogTab data={data} onData={setData} />}
      {tab === 'tasks' && <TasksTab tasks={data.tasks} onData={setData} />}
      {tab === 'mentor' && <MentorTab data={data} />}
      {tab === 'support' && <Tickets viewer="student" onSeen={unread.refresh} />}
      <UnreadPopup count={unread.count} items={unread.items} />
        {tab === 'account' && (
        <div className="space-y-5">
          <Card title="اطلاعات من" icon={<User className="w-4 h-4" />}>
            <dl className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm">
              <Info label="نام" value={data.student.name} />
              <Info label="موبایل" value={data.student.mobile} ltr />
              <Info label="پایه" value={data.student.grade} />
              <Info label="رشته" value={data.student.field} />
            </dl>
            <p className="text-[11px] text-slate-500 mt-3">برای اصلاح این اطلاعات به مشاور یا پشتیبانی راه کنکور پیام بدهید.</p>
          </Card>
          {!mustChange && <PasswordCard />}
        </div>
      )}
    </div>
  );
};

const Info: React.FC<{ label: string; value?: string; ltr?: boolean }> = ({ label, value, ltr }) => (
  <div className="bg-slate-50 rounded-xl p-3 min-w-0">
    <dt className="text-[11px] text-slate-500">{label}</dt>
    <dd className={`font-bold text-slate-900 mt-0.5 truncate ${ltr ? 'font-mono' : ''}`} dir={ltr ? 'ltr' : undefined}>
      {value || '—'}
    </dd>
  </div>
);

/* ------------------------------------------------------------------ خلاصه */

const HomeTab: React.FC<{ data: StudentOverview; onGo: (t: Tab) => void; onRefresh: () => void }> = ({ data, onGo, onRefresh }) => {
  const { totals, study } = data;
  const hasAny = totals.sessions > 0;
  const pending = data.tasks.filter(t => !t.done);
  const maxSubject = Math.max(1, ...study.subjects.map(s => s.minutes));

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Stat label="امروز" value={formatMinutes(totals.today_minutes)} tone="orange" />
        <Stat label="۷ روز اخیر" value={formatMinutes(totals.week_minutes)} />
        <Stat label="روزهای پشت‌سرهم" value={`${fa(study.streak_days)} روز`} tone="emerald" />
        <Stat label="کل مطالعه‌ی ثبت‌شده" value={formatMinutes(totals.total_minutes)} />
      </div>

      <StudentWeek compact onLogged={onRefresh} onOpenFull={() => onGo('week')} />

      {!hasAny ? (
        <Card>
          <Empty>
            هنوز ساعت مطالعه‌ای ثبت نکرده‌اید. هر روز بعد از درس خواندن، زمانش را ثبت کنید تا شما و مشاورتان روند پیشرفت را ببینید.
            <div className="mt-3">
              <Button onClick={() => onGo('log')}>
                <Plus className="w-4 h-4" /> ثبت اولین مطالعه
              </Button>
            </div>
          </Empty>
        </Card>
      ) : (
        <div className="grid lg:grid-cols-2 gap-5">
          <Card title="۱۴ روز اخیر" icon={<Clock className="w-4 h-4" />}>
            <DaysBars days={study.days} label={d => jDay(d)} title={d => `${jDate(d.date)}: ${formatMinutes(d.minutes)}`} />
          </Card>
          <Card title="به تفکیک درس" icon={<BookOpen className="w-4 h-4" />}>
            <ul className="space-y-3">
              {study.subjects.map(s => (
                <li key={s.subject}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="font-bold text-slate-800">{s.subject}</span>
                    <span className="text-slate-500">
                      {formatMinutes(s.minutes)}
                      {s.tests > 0 && ` · ${fa(s.tests)} تست`}
                    </span>
                  </div>
                  <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                    <div className="h-full bg-orange-500 rounded-full" style={{ width: `${(s.minutes / maxSubject) * 100}%` }} />
                  </div>
                </li>
              ))}
            </ul>
          </Card>
        </div>
      )}

      <Card
        title="تکالیف انجام‌نشده"
        icon={<ClipboardList className="w-4 h-4" />}
        action={
          data.tasks.length > 0 && (
            <button type="button" onClick={() => onGo('tasks')} className="text-xs font-bold text-orange-600">
              همه‌ی تکالیف
            </button>
          )
        }
      >
        {pending.length === 0 ? (
          <Empty>{data.tasks.length === 0 ? 'مشاور هنوز تکلیفی برایتان ثبت نکرده است.' : 'همه‌ی تکالیف انجام شده‌اند.'}</Empty>
        ) : (
          <ul className="divide-y divide-slate-100">
            {pending.slice(0, 5).map(t => (
              <li key={t.id} className="py-2 flex items-center justify-between gap-3 text-sm">
                <span className="font-bold text-slate-800 truncate">{t.title}</span>
                <DueBadge date={t.due_date} />
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
};

const DueBadge: React.FC<{ date: string; done?: boolean }> = ({ date, done }) => {
  if (!date) return null;
  const d = daysUntil(date);
  let cls = 'bg-slate-100 text-slate-600';
  let txt = `مهلت ${jShort(date)}`;
  if (!done && d !== null) {
    if (d < 0) {
      cls = 'bg-red-50 text-red-700';
      txt = `مهلت گذشته (${jShort(date)})`;
    } else if (d === 0) {
      cls = 'bg-amber-50 text-amber-800';
      txt = 'مهلت: امروز';
    } else if (d <= 2) {
      cls = 'bg-amber-50 text-amber-800';
      txt = `${fa(d)} روز مانده`;
    }
  }
  return <span className={`shrink-0 text-[11px] font-bold px-2 py-0.5 rounded-full ${cls}`}>{txt}</span>;
};

/* ------------------------------------------------------------- ثبت مطالعه */

const LogTab: React.FC<{ data: StudentOverview; onData: (d: StudentOverview) => void }> = ({ data, onData }) => {
  const [subject, setSubject] = useState('');
  const [hours, setHours] = useState('');
  const [mins, setMins] = useState('');
  const [tests, setTests] = useState('');
  const [topic, setTopic] = useState('');
  const [day, setDay] = useState(0);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [ok, setOk] = useState('');
  const [deleting, setDeleting] = useState<number | null>(null);

  const [formKey, setFormKey] = useState(0);

  // کرونومتر: زمان واقعی را در فیلدها می‌گذارد و با رفرش یا بستن صفحه از دست نمی‌رود
  const saved = useRef(readTimer());
  const startedAt = useRef<number | null>(saved.current.start);
  const base = useRef(saved.current.base);
  const [running, setRunning] = useState(!!saved.current.start);
  const [seconds, setSeconds] = useState(timerSeconds(saved.current));
  useEffect(() => {
    if (!running) return;
    const tick = () => {
      if (startedAt.current) setSeconds(base.current + Math.floor((Date.now() - startedAt.current) / 1000));
    };
    tick();
    const i = setInterval(tick, 1000);
    return () => clearInterval(i);
  }, [running]);

  const toggleTimer = () => {
    if (running) {
      base.current = seconds;
      startedAt.current = null;
      setRunning(false);
      writeTimer({ start: null, base: seconds });
      const total = Math.max(1, Math.round(seconds / 60));
      setHours(String(Math.floor(total / 60) || ''));
      setMins(String(total % 60));
    } else {
      startedAt.current = Date.now();
      setRunning(true);
      writeTimer({ start: startedAt.current, base: base.current });
    }
  };
  const resetTimer = () => {
    setRunning(false);
    startedAt.current = null;
    base.current = 0;
    setSeconds(0);
    writeTimer(null);
  };
  const clock = [Math.floor(seconds / 3600), Math.floor((seconds % 3600) / 60), seconds % 60].map(n => String(n).padStart(2, '0')).join(':');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setOk('');
    const total = (parseInt(latinDigits(hours), 10) || 0) * 60 + (parseInt(latinDigits(mins), 10) || 0);
    if (!subject.trim()) return setError('درس را انتخاب کنید.');
    if (total < 1) return setError('مدت مطالعه را وارد کنید.');
    if (total > 16 * 60) return setError('مدت یک ثبت نمی‌تواند بیش از ۱۶ ساعت باشد.');
    try {
      setSaving(true);
      const res = await api.student.logStudy({
        subject: subject.trim(),
        minutes: total,
        tests: parseInt(latinDigits(tests), 10) || 0,
        topic: topic.trim() || undefined,
        date: day === 0 ? todayIso() : isoDaysAgo(day),
      });
      onData(res);
      setOk(`${formatMinutes(total)} ${subject} ثبت شد.`);
      setHours('');
      setMins('');
      setTests('');
      setTopic('');
      setSubject('');
      setFormKey(k => k + 1);
      resetTimer();
    } catch (err: any) {
      setError(err.message || 'ثبت انجام نشد.');
    } finally {
      setSaving(false);
    }
  };

  const remove = async (id: number) => {
    if (!confirm('این ثبت حذف شود؟')) return;
    try {
      setDeleting(id);
      onData(await api.student.deleteLog(id));
    } catch (err: any) {
      setError(err.message || 'حذف انجام نشد.');
    } finally {
      setDeleting(null);
    }
  };

  if (!data.can_log) {
    return <Alert kind="error">ثبت ساعت مطالعه در حال حاضر فعال نیست. به پشتیبانی راه کنکور اطلاع دهید.</Alert>;
  }

  return (
    <div className="grid lg:grid-cols-5 gap-5">
      <Card title="ثبت ساعت مطالعه" icon={<Plus className="w-4 h-4" />} className="lg:col-span-3">
        <div className="flex items-center justify-between gap-3 bg-slate-900 text-white rounded-xl p-3 mb-4">
          <div>
            <div className="text-[11px] text-slate-300">کرونومتر (اختیاری)</div>
            <div className="font-mono text-2xl font-black tracking-wider" dir="ltr">
              {clock}
            </div>
          </div>
          <div className="flex gap-2">
            <button type="button" onClick={toggleTimer} className="inline-flex items-center gap-1 bg-orange-600 hover:bg-orange-500 rounded-lg px-3 py-2 text-xs font-bold">
              {running ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
              {running ? 'توقف و انتقال به فرم' : seconds ? 'ادامه' : 'شروع'}
            </button>
            {seconds > 0 && !running && (
              <button type="button" onClick={resetTimer} className="text-xs text-slate-300 hover:text-white px-2">
                صفر
              </button>
            )}
          </div>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <div className="grid sm:grid-cols-2 gap-3">
            <SubjectField key={formKey} id="log-subject" value={subject} onChange={setSubject} required />
            <div>
              <Label htmlFor="log-day">روز</Label>
              <select id="log-day" value={day} onChange={e => setDay(Number(e.target.value))} className={inputCls}>
                <option value={0}>امروز</option>
                <option value={1}>دیروز</option>
                <option value={2}>پریروز</option>
              </select>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <Label htmlFor="log-h">ساعت</Label>
              <input id="log-h" inputMode="numeric" value={hours} onChange={e => setHours(e.target.value)} className={`${inputCls} text-center`} />
            </div>
            <div>
              <Label htmlFor="log-m">دقیقه</Label>
              <input id="log-m" inputMode="numeric" value={mins} onChange={e => setMins(e.target.value)} className={`${inputCls} text-center`} />
            </div>
            <div>
              <Label htmlFor="log-t">تعداد تست</Label>
              <input id="log-t" inputMode="numeric" value={tests} onChange={e => setTests(e.target.value)} className={`${inputCls} text-center`} />
            </div>
          </div>
          <div>
            <Label htmlFor="log-topic">مبحث (اختیاری)</Label>
            <input id="log-topic" type="text" value={topic} onChange={e => setTopic(e.target.value)} className={inputCls} />
          </div>
          {error && <Alert kind="error">{error}</Alert>}
          {ok && <Alert kind="success">{ok}</Alert>}
          <Button type="submit" loading={saving} className="w-full py-3" disabled={running}>
            ثبت مطالعه
          </Button>
          {running && <p className="text-[11px] text-center text-slate-500">برای ثبت، اول کرونومتر را متوقف کنید.</p>}
        </form>
      </Card>

      <Card title="ثبت‌های اخیر" icon={<Clock className="w-4 h-4" />} className="lg:col-span-2">
        {data.study.logs.length === 0 ? (
          <Empty>هنوز ثبتی ندارید.</Empty>
        ) : (
          <ul className="divide-y divide-slate-100 -my-2">
            {data.study.logs.map(l => (
              <li key={l.id} className="py-2.5 flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <div className="text-sm font-bold text-slate-800 truncate">
                    {l.subject || 'بدون درس'}
                    {l.topic && <span className="font-normal text-slate-500"> · {l.topic}</span>}
                  </div>
                  <div className="text-[11px] text-slate-500">
                    {jDate(l.date)} · {formatMinutes(l.minutes)}
                    {l.tests > 0 && ` · ${fa(l.tests)} تست`}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => remove(l.id)}
                  disabled={deleting === l.id}
                  className="p-2 text-slate-400 hover:text-red-600 disabled:opacity-40"
                  aria-label="حذف این ثبت"
                  title="حذف"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
};

/* ------------------------------------------------------------------ تکالیف */

const TasksTab: React.FC<{ tasks: Task[]; onData: (d: StudentOverview) => void }> = ({ tasks, onData }) => {
  const [busy, setBusy] = useState<number | null>(null);
  const [error, setError] = useState('');

  const toggle = async (t: Task) => {
    setError('');
    try {
      setBusy(t.id);
      onData(await api.student.setTaskDone(t.id, !t.done));
    } catch (err: any) {
      setError(err.message || 'وضعیت تکلیف ذخیره نشد.');
    } finally {
      setBusy(null);
    }
  };

  const pending = tasks.filter(t => !t.done);
  const done = tasks.filter(t => t.done);

  return (
    <Card title="تکالیف مشاور" icon={<ClipboardList className="w-4 h-4" />}>
      {error && (
        <div className="mb-3">
          <Alert kind="error">{error}</Alert>
        </div>
      )}
      {tasks.length === 0 ? (
        <Empty>مشاور هنوز تکلیفی برایتان ثبت نکرده است.</Empty>
      ) : (
        <ul className="space-y-2">
          {[...pending, ...done].map(t => (
            <li key={t.id} className={`border rounded-xl p-3 flex items-start gap-3 ${t.done ? 'bg-slate-50 border-slate-200' : 'bg-white border-orange-200'}`}>
              <button
                type="button"
                onClick={() => toggle(t)}
                disabled={busy === t.id}
                className="mt-0.5 shrink-0 disabled:opacity-40"
                aria-label={t.done ? 'برگرداندن به انجام‌نشده' : 'علامت انجام شد'}
              >
                {t.done ? <CheckCircle2 className="w-6 h-6 text-emerald-600" /> : <Circle className="w-6 h-6 text-slate-300 hover:text-orange-500" />}
              </button>
              <div className="flex-1 min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`text-sm font-bold ${t.done ? 'text-slate-500 line-through' : 'text-slate-900'}`}>{t.title}</span>
                  <DueBadge date={t.due_date} done={t.done} />
                </div>
                {t.description && <p className="text-xs text-slate-600 mt-1 whitespace-pre-line">{t.description}</p>}
                <div className="text-[11px] text-slate-400 mt-1">
                  {t.created_at && `ثبت: ${jDate(t.created_at)}`}
                  {t.done && t.done_at && ` · انجام: ${jDate(t.done_at)}`}
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
};

const PlanCountdown: React.FC<{ end: string; daysLeft: number | null }> = ({ end, daysLeft }) => {
  if (!end || daysLeft === null) return null;
  const expired = daysLeft < 0;
  const soon = !expired && daysLeft <= 7;
  return (
    <div
      className={`mt-3 rounded-xl border p-3 text-sm font-bold ${
        expired ? 'bg-red-50 border-red-200 text-red-700' : soon ? 'bg-amber-50 border-amber-200 text-amber-800' : 'bg-emerald-50 border-emerald-200 text-emerald-800'
      }`}
    >
      {expired
        ? `طرح شما ${fa(-daysLeft)} روز پیش تمام شده — برای تمدید با مشاورتان تماس بگیرید.`
        : daysLeft === 0
          ? 'امروز آخرین روز طرح شماست.'
          : `${fa(daysLeft)} روز تا پایان طرح مانده است.`}
    </div>
  );
};

/* ------------------------------------------------------------------- مشاور */

const MentorTab: React.FC<{ data: StudentOverview }> = ({ data }) => (
  <div className="space-y-5">
    <div className="grid sm:grid-cols-2 gap-5">
      <Card title="مشاور من" icon={<UserCheck className="w-4 h-4" />}>
        {data.mentor ? (
          <dl className="grid grid-cols-2 gap-3 text-sm">
            <Info label="نام" value={data.mentor.name} />
            <Info label="موبایل" value={data.mentor.mobile} ltr />
            {data.mentor.specialty && <Info label="تخصص" value={data.mentor.specialty} />}
          </dl>
        ) : (
          <Empty>هنوز مشاوری به شما متصل نشده است. بعد از ثبت‌نام در طرح، مشاورتان اینجا نمایش داده می‌شود.</Empty>
        )}
      </Card>
      <Card title="طرح من" icon={<BookOpen className="w-4 h-4" />}>
        {data.plan ? (
          <>
            <dl className="grid grid-cols-2 gap-3 text-sm">
              {data.plan.name && <Info label="طرح" value={data.plan.name} />}
              {data.plan.start && <Info label="شروع" value={jDate(data.plan.start)} />}
              {data.plan.end && <Info label="پایان" value={jDate(data.plan.end)} />}
            </dl>
            {!!data.plan.price && (
              <div className="mt-3 text-xs text-slate-600 bg-slate-50 border border-slate-200 rounded-xl p-3">
                پرداخت‌شده: <b className="text-slate-900">{toman(data.plan.paid || 0)}</b> از {toman(data.plan.price)}
                {!!data.plan.due && <span className="text-amber-700 font-bold"> · مانده {toman(data.plan.due)}</span>}
              </div>
            )}
            <PlanCountdown end={data.plan.end} daysLeft={data.plan.days_left ?? daysUntil(data.plan.end)} />
          </>
        ) : (
          <Empty>اطلاعات طرح برای حساب شما ثبت نشده است.</Empty>
        )}
      </Card>
    </div>

    {data.payments && data.payments.length > 0 && (
      <Card title="پرداخت‌های من" icon={<Receipt className="w-4 h-4" />}>
        <ul className="divide-y divide-slate-100">
          {data.payments.map(p => (
            <li key={p.id} className="py-2 flex flex-wrap items-center justify-between gap-2 text-sm">
              <div className="text-slate-700">
                {jDate(p.paid_at)}
                <span className="text-[11px] text-slate-400 mr-2">
                  پیگیری:{' '}
                  <span className="font-mono" dir="ltr">
                    {p.ref}
                  </span>
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="font-black">{toman(p.amount)}</span>
                <span
                  className={`text-[10px] font-bold border rounded-full px-2 py-0.5 ${
                    p.status === 'approved'
                      ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                      : p.status === 'pending'
                        ? 'bg-amber-50 text-amber-800 border-amber-200'
                        : 'bg-slate-100 text-slate-600 border-slate-200'
                  }`}
                >
                  {p.status === 'approved' ? 'تأیید شده' : p.status === 'pending' ? 'در حال بررسی' : 'رد شده'}
                </span>
              </div>
            </li>
          ))}
        </ul>
        <p className="text-[11px] text-slate-500 mt-2">اگر فیشی را فرستاده‌اید و اینجا نیست، به مشاور فروشتان بگویید ثبتش کند.</p>
      </Card>
    )}
    <Card title="پیام‌ها و تحلیل‌های مشاور" icon={<MessageSquare className="w-4 h-4" />}>
      {data.notes.length === 0 ? (
        <Empty>مشاور هنوز پیامی برایتان ننوشته است.</Empty>
      ) : (
        <ul className="space-y-3">
          {data.notes.map(n => (
            <li key={n.id} className="bg-slate-50 border border-slate-200 rounded-xl p-3">
              <p className="text-sm text-slate-800 whitespace-pre-line leading-7">{n.note}</p>
              {n.created_at && <div className="text-[11px] text-slate-400 mt-1">{jDate(n.created_at)}</div>}
            </li>
          ))}
        </ul>
      )}
    </Card>
  </div>
);
