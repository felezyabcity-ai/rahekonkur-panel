import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, BookOpen, CheckCircle2, Circle, ClipboardList, Clock, Lock, MessageSquare, Pencil, Phone, RefreshCw, Search, Send, Trash2, Users } from 'lucide-react';
import { api, MentorStudentDetail, StudentCard, Task, Note } from '../api';
import { daysSince, daysUntil, fa, formatMinutes, isoDaysAgo, jDate, jShort, jDay } from '../lib/format';
import { WeekPlanner } from './WeekPlanner';

const isoDaysAhead = (n: number) => isoDaysAgo(-n);
const DUE_OPTIONS = [
  { days: 0, label: 'امروز' },
  { days: 1, label: 'فردا' },
  { days: 2, label: 'پس‌فردا' },
  { days: 3, label: '۳ روز' },
  { days: 5, label: '۵ روز' },
  { days: 7, label: 'یک هفته' },
  { days: 10, label: '۱۰ روز' },
  { days: 14, label: 'دو هفته' },
  { days: 30, label: 'یک ماه' },
];
import { Alert, Button, Card, DaysBars, Empty, Label, Spinner, Stat, inputCls } from './ui';
import { PasswordCard } from './Security';
import { Tickets } from './Tickets';
import { UnreadDot, UnreadPopup, useOpenTicketsRequest, useUnread } from './Unread';

export const MentorPortal: React.FC<{ currentUser: any }> = ({ currentUser }) => {
  const [students, setStudents] = useState<StudentCard[]>([]);
  const [loading, setLoading] = useState(true);
  const [listError, setListError] = useState('');
  const [selected, setSelected] = useState<number | null>(null);
  const [query, setQuery] = useState('');
  const [mustChange, setMustChange] = useState<boolean>(!!currentUser?.must_change_password);
  const [showPassword, setShowPassword] = useState(false);
  const [view, setView] = useState<'students' | 'tickets'>('students');
  const unread = useUnread();
  useOpenTicketsRequest(() => setView('tickets'));

  const loadList = useCallback(async (keep?: number | null) => {
    try {
      setLoading(true);
      setListError('');
      const res = await api.mentor.students();
      const list = res?.students || [];
      setStudents(list);
      setSelected(prev => {
        const want = keep ?? prev;
        if (want && list.some(s => s.student_id === want)) return want;
        return list.length ? list[0].student_id : null;
      });
    } catch (err: any) {
      setListError(err.message || 'فهرست دانش‌آموزان بارگذاری نشد.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadList();
  }, [loadList]);

  const filtered = useMemo(() => {
    const q = query.trim();
    if (!q) return students;
    return students.filter(s => s.name.includes(q) || s.mobile.includes(q));
  }, [students, query]);

  return (
    <div className="max-w-7xl mx-auto px-4 py-5 space-y-5">
      {mustChange && <PasswordCard forced onDone={() => setMustChange(false)} />}

      <div className="bg-white border border-slate-200 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="font-black text-slate-900 text-lg truncate">{currentUser?.name}</div>
          <div className="text-xs text-slate-500 mt-0.5">
            مشاور تحصیلی
            {currentUser?.specialty && ` · ${currentUser.specialty}`}
          </div>
        </div>
        {!mustChange && (
          <Button variant="ghost" onClick={() => setShowPassword(v => !v)}>
            <Lock className="w-4 h-4" /> تغییر رمز
          </Button>
        )}
      </div>
      {showPassword && !mustChange && <PasswordCard onDone={() => setShowPassword(false)} />}

      <nav className="grid grid-cols-2 gap-1 bg-white border border-slate-200 rounded-2xl p-1" aria-label="بخش‌ها">
        <button
          type="button"
          onClick={() => setView('students')}
          className={`px-3 py-2 rounded-xl text-sm font-bold ${view === 'students' ? 'bg-emerald-50 text-emerald-700' : 'text-slate-600 hover:bg-slate-50'}`}
        >
          دانش‌آموزان من
        </button>
        <button
          type="button"
          onClick={() => setView('tickets')}
          className={`flex items-center justify-center gap-2 px-3 py-2 rounded-xl text-sm font-bold ${view === 'tickets' ? 'bg-emerald-50 text-emerald-700' : 'text-slate-600 hover:bg-slate-50'}`}
        >
          گفت‌وگوها
          <UnreadDot count={unread.count} />
        </button>
      </nav>

      {view === 'tickets' && <Tickets viewer="mentor" onSeen={unread.refresh} />}
      <UnreadPopup count={unread.count} items={unread.items} />

      {view === 'students' && (
      <div className="grid lg:grid-cols-12 gap-5 items-start">
        <aside className="lg:col-span-4 xl:col-span-3 lg:sticky lg:top-20">
          <Card
            title="دانش‌آموزان من"
            icon={<Users className="w-4 h-4" />}
            action={
              <button type="button" onClick={() => loadList(selected)} className="p-1.5 text-slate-400 hover:text-slate-700" title="به‌روزرسانی" aria-label="به‌روزرسانی فهرست">
                <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              </button>
            }
          >
            {listError && <Alert kind="error">{listError}</Alert>}
            {!listError && loading && students.length === 0 && <Spinner />}
            {!loading && !listError && students.length === 0 && (
              <Empty>هنوز دانش‌آموزی به شما متصل نشده است. مدیر از پیشخوان وردپرس دانش‌آموز را به شما وصل می‌کند.</Empty>
            )}
            {students.length > 4 && (
              <div className="relative mb-3">
                <Search className="w-4 h-4 absolute right-3 top-3 text-slate-400" />
                <input value={query} onChange={e => setQuery(e.target.value)} placeholder="جستجوی نام یا موبایل" className={`${inputCls} pr-9`} />
              </div>
            )}
            <ul className="space-y-2 max-h-[60vh] overflow-y-auto">
              {filtered.map(s => {
                const active = s.student_id === selected;
                return (
                  <li key={s.student_id}>
                    <button
                      type="button"
                      onClick={() => setSelected(s.student_id)}
                      className={`w-full text-right border rounded-xl p-3 transition-colors ${
                        active ? 'border-orange-400 bg-orange-50/60' : 'border-slate-200 hover:border-orange-200'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-bold text-sm text-slate-900 truncate">{s.name || 'بدون نام'}</span>
                        {s.tasks_pending > 0 && (
                          <span className="shrink-0 text-[10px] font-bold bg-orange-100 text-orange-800 rounded-full px-2 py-0.5">
                            {fa(s.tasks_pending)} تکلیف باز
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-500 mt-1 flex flex-wrap gap-x-2">
                        {[s.grade, s.field].filter(Boolean).join(' · ')}
                        <span>هفته: {formatMinutes(s.study.week_minutes)}</span>
                        {s.week && s.week.rate !== null && <span>برنامه: {fa(s.week.rate)}٪</span>}
                      </div>
                      <InactiveBadge lastAt={s.study.last_at} />
                    </button>
                  </li>
                );
              })}
            </ul>
          </Card>
        </aside>

        <main className="lg:col-span-8 xl:col-span-9 min-w-0">
          {selected ? (
            <StudentDetail key={selected} studentId={selected} onChanged={() => loadList(selected)} />
          ) : (
            !loading && <Card>
              <Empty>دانش‌آموزی برای نمایش انتخاب نشده است.</Empty>
            </Card>
          )}
        </main>
      </div>
      )}
    </div>
  );
};

/** هشدار دانش‌آموز کم‌کار: ۲ روز یا بیشتر بدون ثبت مطالعه */
const InactiveBadge: React.FC<{ lastAt: string }> = ({ lastAt }) => {
  const days = lastAt ? daysSince(lastAt) : null;
  if (days !== null && days < 2) return null;
  return (
    <div className="mt-1.5 inline-flex items-center gap-1 text-[10px] font-bold text-red-700 bg-red-50 border border-red-200 rounded-full px-2 py-0.5">
      <AlertTriangle className="w-3 h-3" />
      {days === null ? 'هنوز مطالعه‌ای ثبت نکرده' : `${fa(days)} روز بدون ثبت مطالعه`}
    </div>
  );
};

/* ------------------------------------------------------ جزئیات دانش‌آموز */

const StudentDetail: React.FC<{ studentId: number; onChanged: () => void }> = ({ studentId, onChanged }) => {
  const [detail, setDetail] = useState<MentorStudentDetail | null>(null);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      setError('');
      setDetail(await api.mentor.student(studentId));
    } catch (err: any) {
      setError(err.message || 'اطلاعات دانش‌آموز بارگذاری نشد.');
    }
  }, [studentId]);

  useEffect(() => {
    load();
  }, [load]);

  if (error && !detail) {
    return (
      <div className="space-y-3">
        <Alert kind="error">{error}</Alert>
        <Button variant="ghost" onClick={load}>
          تلاش دوباره
        </Button>
      </div>
    );
  }
  if (!detail) return <Spinner />;

  const { student: s, study, tasks, notes } = detail;
  const doneRate = s.tasks_total ? Math.round((s.tasks_done / s.tasks_total) * 100) : null;
  const planLeft = s.plan_end ? daysUntil(s.plan_end) : null;
  const maxSubject = Math.max(1, ...study.subjects.map(x => x.minutes));

  return (
    <div className="space-y-5">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h2 className="text-lg font-black text-slate-900">{s.name || 'بدون نام'}</h2>
            <div className="text-xs text-slate-500 mt-1 flex flex-wrap gap-x-3 gap-y-1">
              {s.grade && <span>پایه: {s.grade}</span>}
              {s.field && <span>رشته: {s.field}</span>}
              {s.city && <span>شهر: {s.city}</span>}
              {s.study.last_at ? <span>آخرین ثبت مطالعه: {jDate(s.study.last_at)}</span> : <span>هنوز مطالعه‌ای ثبت نکرده</span>}
            </div>
          </div>
          {s.mobile && (
            <a href={`tel:${s.mobile}`} className="inline-flex items-center gap-1.5 text-sm font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-xl px-3 py-2">
              <Phone className="w-4 h-4" />
              <span className="font-mono" dir="ltr">
                {s.mobile}
              </span>
            </a>
          )}
        </div>
        {(s.plan_name || s.plan_end) && (
          <div className="mt-3 text-xs bg-slate-50 border border-slate-200 rounded-xl p-3 flex flex-wrap gap-x-4 gap-y-1">
            {s.plan_name && <span className="font-bold text-slate-800">طرح: {s.plan_name}</span>}
            {s.plan_start && <span>شروع: {jDate(s.plan_start)}</span>}
            {s.plan_end && <span>پایان: {jDate(s.plan_end)}</span>}
            {planLeft !== null && (
              <span className={planLeft < 0 ? 'text-red-600 font-bold' : planLeft <= 7 ? 'text-amber-700 font-bold' : ''}>
                {planLeft < 0 ? 'منقضی شده' : `${fa(planLeft)} روز مانده`}
              </span>
            )}
          </div>
        )}
      </Card>

      <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
        <Stat label="امروز" value={formatMinutes(s.study.today_minutes)} tone="orange" />
        <Stat label="۷ روز اخیر" value={formatMinutes(s.study.week_minutes)} />
        <Stat
          label="عمل به برنامه‌ی این هفته"
          value={s.week && s.week.rate !== null ? `${fa(s.week.rate)}٪` : '—'}
          hint={s.week && s.week.items ? `${fa(s.week.due_done_items)} از ${fa(s.week.due_items)} مورد سررسید` : 'برنامه‌ای چیده نشده'}
          tone="emerald"
        />
        <Stat
          label="تکالیف انجام‌شده"
          value={s.tasks_total ? `${fa(s.tasks_done)} از ${fa(s.tasks_total)}` : '—'}
          hint={doneRate !== null ? `${fa(doneRate)}٪` : 'تکلیفی ثبت نشده'}
          tone="sky"
        />
      </div>

      <WeekPlanner
        studentId={s.student_id}
        onChanged={() => {
          load();
          onChanged();
        }}
      />

      <div className="grid xl:grid-cols-2 gap-5">
        <Card title="مطالعه‌ی ۱۴ روز اخیر" icon={<Clock className="w-4 h-4" />}>
          {s.study.sessions === 0 ? (
            <Empty>این دانش‌آموز هنوز ساعت مطالعه ثبت نکرده است.</Empty>
          ) : (
            <>
              <DaysBars days={study.days} label={d => jDay(d)} title={d => `${jDate(d.date)}: ${formatMinutes(d.minutes)}`} />
              <div className="text-[11px] text-slate-500 mt-2">
                کل ثبت‌شده: {formatMinutes(s.study.total_minutes)}
                {s.study.total_tests > 0 && ` · ${fa(s.study.total_tests)} تست`}
              </div>
            </>
          )}
        </Card>
        <Card title="به تفکیک درس" icon={<BookOpen className="w-4 h-4" />}>
          {study.subjects.length === 0 ? (
            <Empty>داده‌ای برای نمایش نیست.</Empty>
          ) : (
            <ul className="space-y-3">
              {study.subjects.map(x => (
                <li key={x.subject}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="font-bold text-slate-800">{x.subject}</span>
                    <span className="text-slate-500">
                      {formatMinutes(x.minutes)}
                      {x.tests > 0 && ` · ${fa(x.tests)} تست`}
                    </span>
                  </div>
                  <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                    <div className="h-full bg-orange-500 rounded-full" style={{ width: `${(x.minutes / maxSubject) * 100}%` }} />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      {study.logs.length > 0 && (
        <Card title="آخرین ثبت‌های مطالعه" icon={<Clock className="w-4 h-4" />}>
          <div className="overflow-x-auto -mx-1">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-slate-500 text-right">
                  <th className="font-bold p-2">تاریخ</th>
                  <th className="font-bold p-2">درس</th>
                  <th className="font-bold p-2">مبحث</th>
                  <th className="font-bold p-2">مدت</th>
                  <th className="font-bold p-2">تست</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {study.logs.slice(0, 10).map(l => (
                  <tr key={l.id}>
                    <td className="p-2 whitespace-nowrap">{jDate(l.date)}</td>
                    <td className="p-2 font-bold">{l.subject}</td>
                    <td className="p-2 text-slate-600">{l.topic || '—'}</td>
                    <td className="p-2 whitespace-nowrap">{formatMinutes(l.minutes)}</td>
                    <td className="p-2">{l.tests ? fa(l.tests) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      <div className="grid xl:grid-cols-2 gap-5 items-start">
        <TasksBox studentId={s.student_id} tasks={tasks} onTasks={t => {
          setDetail({ ...detail, tasks: t });
          load();
          onChanged();
        }} />
        <NotesBox studentId={s.student_id} notes={notes} onNotes={n => setDetail({ ...detail, notes: n })} />
      </div>
    </div>
  );
};

/* ------------------------------------------------------------------ تکالیف */

const TasksBox: React.FC<{ studentId: number; tasks: MentorStudentDetail['tasks']; onTasks: (t: MentorStudentDetail['tasks']) => void }> = ({
  studentId,
  tasks,
  onTasks,
}) => {
  const [title, setTitle] = useState('');
  const [desc, setDesc] = useState('');
  const [due, setDue] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [ok, setOk] = useState('');
  const [deleting, setDeleting] = useState<number | null>(null);
  const [editing, setEditing] = useState<number | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setOk('');
    if (!title.trim()) return setError('عنوان تکلیف را بنویسید.');
    try {
      setSaving(true);
      const res = await api.mentor.createTask({ student_id: studentId, title: title.trim(), description: desc.trim(), due_date: due || undefined });
      onTasks(res.tasks);
      setTitle('');
      setDesc('');
      setDue('');
      setOk('تکلیف ثبت شد و در پنل دانش‌آموز نمایش داده می‌شود.');
    } catch (err: any) {
      setError(err.message || 'ثبت تکلیف انجام نشد.');
    } finally {
      setSaving(false);
    }
  };

  const remove = async (id: number) => {
    if (!confirm('این تکلیف حذف شود؟')) return;
    setError('');
    try {
      setDeleting(id);
      const res = await api.mentor.deleteTask(id);
      onTasks(res.tasks);
    } catch (err: any) {
      setError(err.message || 'حذف انجام نشد.');
    } finally {
      setDeleting(null);
    }
  };

  const sorted = [...tasks.filter(t => !t.done), ...tasks.filter(t => t.done)];

  return (
    <Card title="تکالیف" icon={<ClipboardList className="w-4 h-4" />}>
      <form onSubmit={submit} className="space-y-3 bg-slate-50 border border-slate-200 rounded-xl p-3 mb-4">
        <div>
          <Label htmlFor="task-title" required>
            تکلیف جدید
          </Label>
          <input id="task-title" type="text" value={title} onChange={e => setTitle(e.target.value)} className={inputCls} placeholder="عنوان تکلیف" />
        </div>
        <textarea value={desc} onChange={e => setDesc(e.target.value)} rows={2} className={inputCls} placeholder="توضیحات (اختیاری)" aria-label="توضیحات تکلیف" />
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex-1 min-w-40">
            <Label htmlFor="task-due">مهلت (اختیاری)</Label>
            <select id="task-due" value={due} onChange={e => setDue(e.target.value)} className={inputCls}>
              <option value="">بدون مهلت</option>
              {DUE_OPTIONS.map(o => {
                const iso = isoDaysAhead(o.days);
                return (
                  <option key={o.days} value={iso}>
                    {o.label} — {jDate(iso)}
                  </option>
                );
              })}
            </select>
          </div>
          <Button type="submit" loading={saving} variant="dark">
            <Send className="w-4 h-4" /> ثبت تکلیف
          </Button>
        </div>
        {error && <Alert kind="error">{error}</Alert>}
        {ok && <Alert kind="success">{ok}</Alert>}
      </form>

      {sorted.length === 0 ? (
        <Empty>هنوز تکلیفی برای این دانش‌آموز ثبت نشده است.</Empty>
      ) : (
        <ul className="space-y-2">
          {sorted.map(t => {
            const d = t.due_date ? daysUntil(t.due_date) : null;
            const late = !t.done && d !== null && d < 0;
            if (editing === t.id) {
              return (
                <li key={t.id}>
                  <TaskEditForm
                    task={t}
                    onCancel={() => setEditing(null)}
                    onSave={async body => {
                      const res = await api.mentor.updateTask(t.id, body);
                      onTasks(res.tasks);
                      setEditing(null);
                    }}
                  />
                </li>
              );
            }
            return (
              <li key={t.id} className="border border-slate-200 rounded-xl p-3 flex items-start gap-2">
                {t.done ? <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" /> : <Circle className="w-5 h-5 text-slate-300 shrink-0 mt-0.5" />}
                <div className="flex-1 min-w-0">
                  <div className={`text-sm font-bold ${t.done ? 'text-slate-500' : 'text-slate-900'}`}>{t.title}</div>
                  {t.description && <p className="text-xs text-slate-600 mt-0.5 whitespace-pre-line">{t.description}</p>}
                  <div className="text-[11px] mt-1 flex flex-wrap gap-x-2 text-slate-400">
                    {t.done ? (
                      <span className="text-emerald-700 font-bold">انجام شد{t.done_at && ` · ${jDate(t.done_at)}`}</span>
                    ) : (
                      <span className={late ? 'text-red-600 font-bold' : 'text-amber-700 font-bold'}>{late ? 'مهلت گذشته' : 'انجام نشده'}</span>
                    )}
                    {t.due_date && <span>مهلت: {jShort(t.due_date)}</span>}
                    {t.created_at && <span>ثبت: {jShort(t.created_at)}</span>}
                  </div>
                </div>
                <button type="button" onClick={() => setEditing(t.id)} className="p-1.5 text-slate-400 hover:text-slate-700" title="ویرایش تکلیف" aria-label="ویرایش تکلیف">
                  <Pencil className="w-4 h-4" />
                </button>
                <button
                  type="button"
                  onClick={() => remove(t.id)}
                  disabled={deleting === t.id}
                  className="p-1.5 text-slate-400 hover:text-red-600 disabled:opacity-40"
                  title="حذف تکلیف"
                  aria-label="حذف تکلیف"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
};

const DueSelect: React.FC<{ id: string; value: string; onChange: (v: string) => void }> = ({ id, value, onChange }) => {
  const options = DUE_OPTIONS.map(o => ({ ...o, iso: isoDaysAhead(o.days) }));
  const known = !value || options.some(o => o.iso === value);
  return (
    <select id={id} value={value} onChange={e => onChange(e.target.value)} className={inputCls}>
      <option value="">بدون مهلت</option>
      {!known && <option value={value}>مهلت فعلی — {jDate(value)}</option>}
      {options.map(o => (
        <option key={o.days} value={o.iso}>
          {o.label} — {jDate(o.iso)}
        </option>
      ))}
    </select>
  );
};

const TaskEditForm: React.FC<{ task: Task; onSave: (b: { title: string; description: string; due_date: string }) => Promise<void>; onCancel: () => void }> = ({
  task,
  onSave,
  onCancel,
}) => {
  const [title, setTitle] = useState(task.title);
  const [desc, setDesc] = useState(task.description);
  const [due, setDue] = useState(task.due_date);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return setError('عنوان تکلیف را بنویسید.');
    try {
      setSaving(true);
      setError('');
      await onSave({ title: title.trim(), description: desc.trim(), due_date: due });
    } catch (err: any) {
      setError(err.message || 'ذخیره نشد.');
      setSaving(false);
    }
  };
  return (
    <form onSubmit={submit} className="border border-orange-200 bg-orange-50/40 rounded-xl p-3 space-y-2">
      <input value={title} onChange={e => setTitle(e.target.value)} className={inputCls} aria-label="عنوان تکلیف" />
      <textarea value={desc} onChange={e => setDesc(e.target.value)} rows={2} className={inputCls} aria-label="توضیحات" placeholder="توضیحات" />
      <DueSelect id={`due-edit-${task.id}`} value={due} onChange={setDue} />
      {error && <Alert kind="error">{error}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" size="sm" variant="dark" loading={saving}>
          ذخیره
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={onCancel}>
          انصراف
        </Button>
      </div>
    </form>
  );
};

const NoteEditForm: React.FC<{ note: Note; onSave: (b: { note: string; visibility: 'public' | 'private' }) => Promise<void>; onCancel: () => void }> = ({
  note,
  onSave,
  onCancel,
}) => {
  const [text, setText] = useState(note.note);
  const [vis, setVis] = useState<'public' | 'private'>(note.private ? 'private' : 'public');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!text.trim()) return setError('متن یادداشت خالی است.');
    try {
      setSaving(true);
      setError('');
      await onSave({ note: text.trim(), visibility: vis });
    } catch (err: any) {
      setError(err.message || 'ذخیره نشد.');
      setSaving(false);
    }
  };
  return (
    <form onSubmit={submit} className="border border-orange-200 bg-orange-50/40 rounded-xl p-3 space-y-2">
      <textarea value={text} onChange={e => setText(e.target.value)} rows={3} className={inputCls} aria-label="متن یادداشت برای ویرایش" />
      <div className="flex flex-wrap gap-4 text-xs">
        <label className="flex items-center gap-1.5 cursor-pointer">
          <input type="radio" name={`vis-${note.id}`} checked={vis === 'public'} onChange={() => setVis('public')} className="accent-orange-600" />
          دانش‌آموز هم ببیند
        </label>
        <label className="flex items-center gap-1.5 cursor-pointer">
          <input type="radio" name={`vis-${note.id}`} checked={vis === 'private'} onChange={() => setVis('private')} className="accent-orange-600" />
          محرمانه
        </label>
      </div>
      {error && <Alert kind="error">{error}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" size="sm" variant="dark" loading={saving}>
          ذخیره
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={onCancel}>
          انصراف
        </Button>
      </div>
    </form>
  );
};

/* -------------------------------------------------------------- یادداشت‌ها */

const NotesBox: React.FC<{ studentId: number; notes: MentorStudentDetail['notes']; onNotes: (n: MentorStudentDetail['notes']) => void }> = ({
  studentId,
  notes,
  onNotes,
}) => {
  const [text, setText] = useState('');
  const [visibility, setVisibility] = useState<'public' | 'private'>('public');
  const [editing, setEditing] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [ok, setOk] = useState('');
  const [deleting, setDeleting] = useState<number | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setOk('');
    if (!text.trim()) return setError('متن یادداشت خالی است.');
    try {
      setSaving(true);
      const res = await api.mentor.createNote({ student_id: studentId, note: text.trim(), visibility });
      onNotes(res.notes);
      setText('');
      setOk(visibility === 'public' ? 'یادداشت ثبت شد و دانش‌آموز آن را می‌بیند.' : 'یادداشت محرمانه ثبت شد (فقط شما می‌بینید).');
    } catch (err: any) {
      setError(err.message || 'ثبت یادداشت انجام نشد.');
    } finally {
      setSaving(false);
    }
  };

  const remove = async (id: number) => {
    if (!confirm('این یادداشت حذف شود؟')) return;
    setError('');
    try {
      setDeleting(id);
      const res = await api.mentor.deleteNote(id);
      onNotes(res.notes);
    } catch (err: any) {
      setError(err.message || 'حذف انجام نشد.');
    } finally {
      setDeleting(null);
    }
  };

  return (
    <Card title="یادداشت‌ها و تحلیل عملکرد" icon={<MessageSquare className="w-4 h-4" />}>
      <form onSubmit={submit} className="space-y-3 bg-slate-50 border border-slate-200 rounded-xl p-3 mb-4">
        <textarea value={text} onChange={e => setText(e.target.value)} rows={3} className={inputCls} placeholder="تحلیل هفته، توصیه یا نکته‌ی تماس تلفنی..." aria-label="متن یادداشت" />
        <fieldset className="flex flex-wrap gap-4 text-xs">
          <legend className="sr-only">چه کسی ببیند</legend>
          <label className="flex items-center gap-1.5 cursor-pointer">
            <input type="radio" name="note-vis" checked={visibility === 'public'} onChange={() => setVisibility('public')} className="accent-orange-600" />
            دانش‌آموز هم ببیند
          </label>
          <label className="flex items-center gap-1.5 cursor-pointer">
            <input type="radio" name="note-vis" checked={visibility === 'private'} onChange={() => setVisibility('private')} className="accent-orange-600" />
            محرمانه (فقط خودم)
          </label>
        </fieldset>
        {error && <Alert kind="error">{error}</Alert>}
        {ok && <Alert kind="success">{ok}</Alert>}
        <Button type="submit" loading={saving} variant="dark">
          <Send className="w-4 h-4" /> ثبت یادداشت
        </Button>
      </form>

      {notes.length === 0 ? (
        <Empty>هنوز یادداشتی ثبت نشده است.</Empty>
      ) : (
        <ul className="space-y-2">
          {notes.map(n =>
            editing === n.id ? (
              <li key={n.id}>
                <NoteEditForm
                  note={n}
                  onCancel={() => setEditing(null)}
                  onSave={async body => {
                    const res = await api.mentor.updateNote(n.id, body);
                    onNotes(res.notes);
                    setEditing(null);
                  }}
                />
              </li>
            ) : (
            <li key={n.id} className={`border rounded-xl p-3 ${n.private ? 'border-slate-300 bg-slate-50' : 'border-emerald-200 bg-emerald-50/40'}`}>
              <div className="flex items-start justify-between gap-2">
                <p className="text-sm text-slate-800 whitespace-pre-line leading-7 flex-1">{n.note}</p>
                <button type="button" onClick={() => setEditing(n.id)} className="p-1.5 text-slate-400 hover:text-slate-700" title="ویرایش یادداشت" aria-label="ویرایش یادداشت">
                  <Pencil className="w-4 h-4" />
                </button>
                <button
                  type="button"
                  onClick={() => remove(n.id)}
                  disabled={deleting === n.id}
                  className="p-1.5 text-slate-400 hover:text-red-600 disabled:opacity-40"
                  title="حذف یادداشت"
                  aria-label="حذف یادداشت"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
              <div className="text-[11px] text-slate-500 mt-1">
                {n.private ? 'محرمانه' : 'قابل مشاهده برای دانش‌آموز'}
                {n.created_at && ` · ${jDate(n.created_at)}`}
              </div>
            </li>
            )
          )}
        </ul>
      )}
    </Card>
  );
};
