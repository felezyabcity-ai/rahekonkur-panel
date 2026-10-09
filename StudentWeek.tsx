import React, { useCallback, useEffect, useState } from 'react';
import { CalendarDays, CheckCircle2, Circle } from 'lucide-react';
import { api, Week, WeekItem } from '../api';
import { WEEKDAYS, fa, formatMinutes, jDate } from '../lib/format';
import { Alert, Button, Card, Empty, Label, Spinner, inputCls } from './ui';
import { DurationFields, splitMinutes, toInt } from './fields';
import { WeekNav, WeekStatsRow, itemSummary } from './WeekPlanner';

/** تأیید انجام یک مورد: مدت واقعی و تعداد تست را می‌پرسد (پیش‌فرض همان برنامه). */
const DoneForm: React.FC<{ item: WeekItem; onSave: (minutes: number, tests: number) => Promise<void>; onCancel: () => void }> = ({ item, onSave, onCancel }) => {
  const [h0, m0] = splitMinutes(item.minutes);
  const [hours, setHours] = useState(h0);
  const [mins, setMins] = useState(m0 || (item.minutes ? '0' : ''));
  const [tests, setTests] = useState(item.tests ? String(item.tests) : '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const idp = `done-${item.id}`;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    const minutes = toInt(hours) * 60 + toInt(mins);
    if (minutes > 16 * 60) return setError('مدت نمی‌تواند بیش از ۱۶ ساعت باشد.');
    if (!minutes && !toInt(tests)) return setError('مدت مطالعه یا تعداد تست را وارد کنید.');
    try {
      setSaving(true);
      await onSave(minutes, toInt(tests));
    } catch (err: any) {
      setError(err.message || 'ثبت نشد.');
      setSaving(false);
    }
  };

  return (
    <form onSubmit={submit} className="mt-2 bg-emerald-50/60 border border-emerald-200 rounded-xl p-3 space-y-3">
      <p className="text-xs text-emerald-900 font-bold">واقعاً چقدر خواندی؟ همین در ساعت مطالعه‌ات هم ثبت می‌شود.</p>
      <div className="grid grid-cols-3 gap-3">
        <DurationFields idPrefix={idp} hours={hours} minutes={mins} onHours={setHours} onMinutes={setMins} />
        <div>
          <Label htmlFor={`${idp}-t`}>تست</Label>
          <input id={`${idp}-t`} inputMode="numeric" value={tests} onChange={e => setTests(e.target.value)} className={`${inputCls} text-center`} />
        </div>
      </div>
      {error && <Alert kind="error">{error}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" variant="success" loading={saving}>
          ثبت انجام
        </Button>
        <Button type="button" variant="ghost" onClick={onCancel}>
          انصراف
        </Button>
      </div>
    </form>
  );
};

const ItemRow: React.FC<{ item: WeekItem; today: string; onChange: (w: Week) => void }> = ({ item, today, onChange }) => {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const future = item.date > today;
  const missed = !item.done && item.date < today;

  const undo = async () => {
    if (!confirm('علامت انجام برداشته شود؟ ساعتی که با آن ثبت شده هم حذف می‌شود.')) return;
    try {
      setBusy(true);
      setError('');
      const res = await api.student.setWeekItem(item.id, { done: false });
      onChange(res.week);
    } catch (err: any) {
      setError(err.message || 'انجام نشد.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <li className={`border rounded-xl p-3 ${item.done ? 'bg-emerald-50/40 border-emerald-200' : missed ? 'border-red-200' : 'border-slate-200 bg-white'}`}>
      <div className="flex items-start gap-3">
        <button
          type="button"
          disabled={busy || future}
          onClick={() => (item.done ? undo() : setOpen(v => !v))}
          className="shrink-0 disabled:opacity-40"
          aria-label={item.done ? 'برداشتن علامت انجام' : 'علامت انجام'}
          title={future ? 'روزش هنوز نرسیده' : undefined}
        >
          {item.done ? <CheckCircle2 className="w-7 h-7 text-emerald-600" /> : <Circle className="w-7 h-7 text-slate-300 hover:text-emerald-500" />}
        </button>
        <div className="flex-1 min-w-0">
          <div className={`text-sm font-bold ${item.done ? 'text-emerald-900' : 'text-slate-900'}`}>
            {item.subject}
            {item.topic && <span className="font-normal text-slate-500"> · {item.topic}</span>}
          </div>
          <div className="text-[11px] text-slate-500 mt-0.5">
            {itemSummary(item)}
            {item.done && (
              <span className="text-emerald-700 font-bold">
                {' '}
                · خواندی: {formatMinutes(item.done_minutes)}
                {item.done_tests > 0 && ` · ${fa(item.done_tests)} تست`}
              </span>
            )}
            {missed && <span className="text-red-600 font-bold"> · انجام نشده</span>}
          </div>
          {item.note && <div className="text-[11px] text-slate-500 mt-1 bg-slate-50 rounded-lg px-2 py-1">{item.note}</div>}
        </div>
      </div>
      {error && (
        <div className="mt-2">
          <Alert kind="error">{error}</Alert>
        </div>
      )}
      {open && !item.done && (
        <DoneForm
          item={item}
          onCancel={() => setOpen(false)}
          onSave={async (minutes, tests) => {
            const res = await api.student.setWeekItem(item.id, { done: true, minutes, tests });
            setOpen(false);
            onChange(res.week);
          }}
        />
      )}
    </li>
  );
};

/**
 * برنامه‌ی هفتگی دانش‌آموز.
 * compact: فقط برنامه‌ی امروز (برای صفحه‌ی خلاصه).
 */
export const StudentWeek: React.FC<{ compact?: boolean; onLogged?: () => void; onOpenFull?: () => void }> = ({ compact, onLogged, onOpenFull }) => {
  const [week, setWeek] = useState<Week | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async (start?: string) => {
    try {
      setBusy(true);
      setError('');
      setWeek(await api.student.week(start));
    } catch (err: any) {
      setError(err.message || 'برنامه بارگذاری نشد.');
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const changed = (w: Week) => {
    setWeek(w);
    onLogged?.();
  };

  if (!week) {
    return (
      <Card title={compact ? 'برنامه‌ی امروز' : 'برنامه‌ی هفتگی'} icon={<CalendarDays className="w-4 h-4" />}>
        {error ? <Alert kind="error">{error}</Alert> : <Spinner />}
      </Card>
    );
  }

  if (compact) {
    const today = week.days.find(d => d.date === week.today);
    const items = today?.items || [];
    const done = items.filter(i => i.done).length;
    return (
      <Card
        title="برنامه‌ی امروز"
        icon={<CalendarDays className="w-4 h-4" />}
        action={
          onOpenFull && (
            <button type="button" onClick={onOpenFull} className="text-xs font-bold text-orange-600">
              کل هفته
            </button>
          )
        }
      >
        {items.length === 0 ? (
          <Empty>{week.stats.items ? 'برای امروز برنامه‌ای نداری.' : 'مشاور هنوز برنامه‌ی این هفته را نچیده است.'}</Empty>
        ) : (
          <>
            <div className="text-xs text-slate-500 mb-2">
              {fa(done)} از {fa(items.length)} مورد انجام شده
            </div>
            <ul className="space-y-2">
              {items.map(i => (
                <ItemRow key={i.id} item={i} today={week.today} onChange={changed} />
              ))}
            </ul>
          </>
        )}
      </Card>
    );
  }

  return (
    <Card title="برنامه‌ی هفتگی" icon={<CalendarDays className="w-4 h-4" />}>
      <div className="space-y-3">
        <WeekNav w={week} onGo={load} busy={busy} />
        {week.stats.items > 0 && <WeekStatsRow w={week} />}
        {error && <Alert kind="error">{error}</Alert>}
        {week.stats.items === 0 ? (
          <Empty>برای این هفته برنامه‌ای ثبت نشده است. مشاورت برنامه را اینجا می‌چیند.</Empty>
        ) : (
          <ul className="space-y-3">
            {week.days.map((day, idx) => (
              <li key={day.date}>
                <div className={`text-sm font-black mb-1.5 ${day.date === week.today ? 'text-orange-700' : 'text-slate-800'}`}>
                  {WEEKDAYS[idx]} <span className="font-normal text-xs text-slate-500">{jDate(day.date)}</span>
                  {day.date === week.today && <span className="mr-2 text-[10px] bg-orange-600 text-white rounded-full px-2 py-0.5">امروز</span>}
                </div>
                {day.items.length === 0 ? (
                  <div className="text-[11px] text-slate-400 pr-1">بدون برنامه</div>
                ) : (
                  <ul className="space-y-2">
                    {day.items.map(i => (
                      <ItemRow key={i.id} item={i} today={week.today} onChange={changed} />
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
};
