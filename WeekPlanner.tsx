import React, { useCallback, useEffect, useState } from 'react';
import { CalendarDays, CheckCircle2, ChevronLeft, ChevronRight, Circle, Copy, Pencil, Plus, Trash2 } from 'lucide-react';
import { api, Week, WeekItem, WeekItemInput } from '../api';
import { WEEKDAYS, addDaysIso, fa, formatMinutes, jDate, jShort } from '../lib/format';
import { Alert, Button, Card, Label, Spinner, inputCls } from './ui';
import { DurationFields, SubjectField, splitMinutes, toInt } from './fields';

export const weekTitle = (w: Week) => `${jShort(w.start)} تا ${jShort(w.end)}`;

export const WeekStatsRow: React.FC<{ w: Week }> = ({ w }) => (
  <div className="grid grid-cols-3 gap-2 text-center">
    <div className="bg-slate-50 rounded-xl p-2">
      <div className="text-[11px] text-slate-500">عمل به برنامه</div>
      <div className="font-black text-emerald-600">{w.stats.rate === null ? '—' : `${fa(w.stats.rate)}٪`}</div>
      <div className="text-[10px] text-slate-400">
        {w.stats.due_items ? `${fa(w.stats.due_done_items)} از ${fa(w.stats.due_items)} مورد تا امروز` : 'هنوز موردی سررسید نشده'}
      </div>
    </div>
    <div className="bg-slate-50 rounded-xl p-2">
      <div className="text-[11px] text-slate-500">برنامه‌ریزی‌شده</div>
      <div className="font-black text-slate-900 text-sm">{formatMinutes(w.stats.planned_minutes)}</div>
      <div className="text-[10px] text-slate-400">{fa(w.stats.items)} مورد</div>
    </div>
    <div className="bg-slate-50 rounded-xl p-2">
      <div className="text-[11px] text-slate-500">انجام‌شده</div>
      <div className="font-black text-orange-600 text-sm">{formatMinutes(w.stats.done_minutes)}</div>
      <div className="text-[10px] text-slate-400">{fa(w.stats.done_items)} مورد</div>
    </div>
  </div>
);

export const WeekNav: React.FC<{ w: Week; onGo: (start?: string) => void; busy?: boolean }> = ({ w, onGo, busy }) => {
  const isThisWeek = w.today >= w.start && w.today <= w.end;
  return (
    <div className="flex items-center justify-between gap-2">
      <button type="button" disabled={busy} onClick={() => onGo(addDaysIso(w.start, -7))} className="p-2 rounded-lg border border-slate-200 hover:bg-slate-50" aria-label="هفته‌ی قبل">
        <ChevronRight className="w-4 h-4" />
      </button>
      <div className="text-center">
        <div className="text-sm font-black text-slate-900">{weekTitle(w)}</div>
        {isThisWeek ? (
          <div className="text-[11px] text-emerald-700 font-bold">این هفته</div>
        ) : (
          <button type="button" onClick={() => onGo(undefined)} className="text-[11px] text-orange-600 font-bold">
            برگشت به این هفته
          </button>
        )}
      </div>
      <button type="button" disabled={busy} onClick={() => onGo(addDaysIso(w.start, 7))} className="p-2 rounded-lg border border-slate-200 hover:bg-slate-50" aria-label="هفته‌ی بعد">
        <ChevronLeft className="w-4 h-4" />
      </button>
    </div>
  );
};

export const itemSummary = (i: WeekItem) =>
  [i.minutes ? formatMinutes(i.minutes) : '', i.tests ? `${fa(i.tests)} تست` : ''].filter(Boolean).join(' · ');

/* -------------------------------------------------- فرم افزودن/ویرایش مورد */

const ItemForm: React.FC<{
  date: string;
  initial?: WeekItem;
  onSave: (v: WeekItemInput) => Promise<void>;
  onCancel: () => void;
}> = ({ date, initial, onSave, onCancel }) => {
  const [subject, setSubject] = useState(initial?.subject || '');
  const [topic, setTopic] = useState(initial?.topic || '');
  const [h0, m0] = splitMinutes(initial?.minutes || 0);
  const [hours, setHours] = useState(h0);
  const [mins, setMins] = useState(m0);
  const [tests, setTests] = useState(initial?.tests ? String(initial.tests) : '');
  const [note, setNote] = useState(initial?.note || '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const idp = `wi-${initial?.id || date}`;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    const minutes = toInt(hours) * 60 + toInt(mins);
    if (!subject.trim()) return setError('درس را انتخاب کنید.');
    if (!minutes && !toInt(tests)) return setError('مدت یا تعداد تست را مشخص کنید.');
    try {
      setSaving(true);
      await onSave({ date, subject: subject.trim(), topic: topic.trim(), minutes, tests: toInt(tests), note: note.trim() });
    } catch (err: any) {
      setError(err.message || 'ذخیره نشد.');
      setSaving(false);
    }
  };

  return (
    <form onSubmit={submit} className="bg-orange-50/50 border border-orange-200 rounded-xl p-3 space-y-3 mt-2">
      <div className="grid sm:grid-cols-2 gap-3">
        <SubjectField id={`${idp}-s`} value={subject} onChange={setSubject} required />
        <div>
          <Label htmlFor={`${idp}-t`}>مبحث</Label>
          <input id={`${idp}-t`} value={topic} onChange={e => setTopic(e.target.value)} className={inputCls} placeholder="مثلاً فصل ۲ – ژنتیک" />
        </div>
      </div>
      <div className="grid grid-cols-3 gap-3">
        <DurationFields idPrefix={idp} hours={hours} minutes={mins} onHours={setHours} onMinutes={setMins} />
        <div>
          <Label htmlFor={`${idp}-n`}>تعداد تست</Label>
          <input id={`${idp}-n`} inputMode="numeric" value={tests} onChange={e => setTests(e.target.value)} className={`${inputCls} text-center`} />
        </div>
      </div>
      <div>
        <Label htmlFor={`${idp}-note`}>توضیح کوتاه (اختیاری)</Label>
        <input id={`${idp}-note`} value={note} onChange={e => setNote(e.target.value)} className={inputCls} maxLength={255} />
      </div>
      {error && <Alert kind="error">{error}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" loading={saving} variant="dark">
          {initial ? 'ذخیره‌ی تغییرات' : 'افزودن به برنامه'}
        </Button>
        <Button type="button" variant="ghost" onClick={onCancel}>
          انصراف
        </Button>
      </div>
    </form>
  );
};

/* ----------------------------------------------------------- برنامه‌ریز مشاور */

export const WeekPlanner: React.FC<{ studentId: number; onChanged?: () => void }> = ({ studentId, onChanged }) => {
  const [week, setWeek] = useState<Week | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [adding, setAdding] = useState<string | null>(null);
  const [editing, setEditing] = useState<number | null>(null);

  const load = useCallback(
    async (start?: string) => {
      try {
        setBusy(true);
        setError('');
        setWeek(await api.mentor.week(studentId, start));
        setAdding(null);
        setEditing(null);
      } catch (err: any) {
        setError(err.message || 'برنامه بارگذاری نشد.');
      } finally {
        setBusy(false);
      }
    },
    [studentId]
  );

  useEffect(() => {
    load();
  }, [load]);

  const apply = (w: Week) => {
    setWeek(w);
    setAdding(null);
    setEditing(null);
    onChanged?.();
  };

  const copyLast = async () => {
    if (!week) return;
    const append = week.stats.items > 0;
    if (append && !confirm('این هفته برنامه دارد. موارد هفته‌ی قبل هم به آن اضافه شود؟')) return;
    try {
      setBusy(true);
      setError('');
      apply(await api.mentor.copyWeek(studentId, week.start, append));
    } catch (err: any) {
      setError(err.message || 'کپی انجام نشد.');
    } finally {
      setBusy(false);
    }
  };

  const remove = async (item: WeekItem) => {
    const msg = item.done ? 'دانش‌آموز این مورد را انجام داده. فقط از برنامه حذف شود؟ (ساعت ثبت‌شده‌اش می‌ماند)' : 'این مورد از برنامه حذف شود؟';
    if (!confirm(msg)) return;
    try {
      setError('');
      apply(await api.mentor.deleteWeekItem(item.id));
    } catch (err: any) {
      setError(err.message || 'حذف انجام نشد.');
    }
  };

  if (!week) {
    return (
      <Card title="برنامه‌ی هفتگی" icon={<CalendarDays className="w-4 h-4" />}>
        {error ? <Alert kind="error">{error}</Alert> : <Spinner />}
      </Card>
    );
  }

  return (
    <Card
      title="برنامه‌ی هفتگی"
      icon={<CalendarDays className="w-4 h-4" />}
      action={
        <Button type="button" variant="ghost" size="sm" onClick={copyLast} disabled={busy}>
          <Copy className="w-3.5 h-3.5" /> کپی از هفته‌ی قبل
        </Button>
      }
    >
      <div className="space-y-3">
        <WeekNav w={week} onGo={load} busy={busy} />
        <WeekStatsRow w={week} />
        {error && <Alert kind="error">{error}</Alert>}

        <ul className="space-y-2">
          {week.days.map((day, idx) => {
            const isToday = day.date === week.today;
            const past = day.date < week.today;
            return (
              <li key={day.date} className={`border rounded-xl p-3 ${isToday ? 'border-orange-300 bg-orange-50/30' : 'border-slate-200'}`}>
                <div className="flex items-center justify-between gap-2">
                  <div className="text-sm font-black text-slate-900">
                    {WEEKDAYS[idx]} <span className="font-normal text-xs text-slate-500">{jDate(day.date)}</span>
                    {isToday && <span className="mr-2 text-[10px] bg-orange-600 text-white rounded-full px-2 py-0.5">امروز</span>}
                  </div>
                  {adding !== day.date && (
                    <button
                      type="button"
                      onClick={() => {
                        setAdding(day.date);
                        setEditing(null);
                      }}
                      className="inline-flex items-center gap-1 text-xs font-bold text-orange-600 hover:text-orange-700"
                    >
                      <Plus className="w-3.5 h-3.5" /> افزودن
                    </button>
                  )}
                </div>

                {day.items.length > 0 && (
                  <ul className="mt-2 space-y-1.5">
                    {day.items.map(item =>
                      editing === item.id ? (
                        <li key={item.id}>
                          <ItemForm
                            date={day.date}
                            initial={item}
                            onCancel={() => setEditing(null)}
                            onSave={async v => apply(await api.mentor.updateWeekItem(item.id, v))}
                          />
                        </li>
                      ) : (
                        <li key={item.id} className="flex items-start gap-2 bg-white border border-slate-100 rounded-lg p-2">
                          {item.done ? (
                            <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0" />
                          ) : (
                            <Circle className={`w-5 h-5 shrink-0 ${past ? 'text-red-400' : 'text-slate-300'}`} />
                          )}
                          <div className="flex-1 min-w-0">
                            <div className="text-sm font-bold text-slate-900">
                              {item.subject}
                              {item.topic && <span className="font-normal text-slate-500"> · {item.topic}</span>}
                            </div>
                            <div className="text-[11px] text-slate-500">
                              برنامه: {itemSummary(item)}
                              {item.done && (
                                <span className="text-emerald-700 font-bold">
                                  {' '}
                                  · انجام: {formatMinutes(item.done_minutes)}
                                  {item.done_tests > 0 && ` · ${fa(item.done_tests)} تست`}
                                </span>
                              )}
                              {!item.done && past && <span className="text-red-600 font-bold"> · انجام نشد</span>}
                            </div>
                            {item.note && <div className="text-[11px] text-slate-400 mt-0.5">{item.note}</div>}
                          </div>
                          <button type="button" onClick={() => { setEditing(item.id); setAdding(null); }} className="p-1 text-slate-400 hover:text-slate-700" aria-label="ویرایش" title="ویرایش">
                            <Pencil className="w-4 h-4" />
                          </button>
                          <button type="button" onClick={() => remove(item)} className="p-1 text-slate-400 hover:text-red-600" aria-label="حذف" title="حذف">
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </li>
                      )
                    )}
                  </ul>
                )}

                {adding === day.date && (
                  <ItemForm
                    date={day.date}
                    onCancel={() => setAdding(null)}
                    onSave={async v => apply(await api.mentor.addWeekItem(studentId, v))}
                  />
                )}
              </li>
            );
          })}
        </ul>
      </div>
    </Card>
  );
};
