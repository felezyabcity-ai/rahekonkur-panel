import React, { useCallback, useEffect, useRef, useState } from 'react';
import { CheckCircle2, MessageSquare, Plus, RefreshCw, Send, ShieldAlert } from 'lucide-react';
import { Ticket, TicketMessage, ticketsApi } from '../api';
import { fa, jShort } from '../lib/format';
import { Alert, Button, Card, Empty, Label, Spinner, inputCls } from './ui';

const ROLE_LABEL: Record<string, string> = {
  student: 'دانش‌آموز',
  mentor: 'مشاور',
  admin: 'مدیریت',
  sales: 'مشاور فروش',
};

const timeOf = (iso: string) => {
  const t = (iso || '').slice(11, 16);
  return `${jShort(iso)}${t ? ' · ' + fa(t) : ''}`;
};

export const Tickets: React.FC<{ viewer: 'student' | 'mentor' | 'admin' | 'sales'; onSeen?: () => void }> = ({ viewer, onSeen }) => {
  const [list, setList] = useState<Ticket[] | null>(null);
  const [open, setOpen] = useState<Ticket | null>(null);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      setError('');
      const r = await ticketsApi.list();
      setList(r.tickets);
    } catch (e: any) {
      setError(e.message || 'گفت‌وگوها بارگذاری نشد.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (open) {
    return (
      <Thread
        viewer={viewer}
        ticket={open}
        onSeen={onSeen}
        onBack={() => {
          setOpen(null);
          load();
          onSeen?.();
        }}
      />
    );
  }

  return (
    <div className="space-y-4">
      {error && <Alert kind="error" onClose={() => setError('')}>{error}</Alert>}

      {!creating && (
        <Button onClick={() => setCreating(true)}>
          <Plus className="w-4 h-4" /> {viewer === 'student' ? 'گفت‌وگوی تازه' : viewer === 'admin' ? 'پیام به همکار' : 'پیام به مدیریت'}
        </Button>
      )}

      {creating && (
        <NewTicket
          viewer={viewer}
          onCancel={() => setCreating(false)}
          onDone={t => {
            setCreating(false);
            setOpen(t);
          }}
        />
      )}

      <Card
        title={viewer === 'student' ? 'گفت‌وگوهای من' : 'گفت‌وگوها'}
        icon={<MessageSquare className="w-4 h-4" />}
        action={
          <button type="button" onClick={load} className="p-2 text-slate-400 hover:text-slate-700" aria-label="به‌روزرسانی">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        }
      >
        {!list && loading && <Spinner />}
        {list && list.length === 0 && (
          <Empty>
            {viewer === 'student' ? 'هنوز گفت‌وگویی باز نکرده‌اید. اگر سؤالی دارید یا مشاورتان جواب نمی‌دهد، از همین‌جا بنویسید.' : 'گفت‌وگویی نیست.'}
          </Empty>
        )}
        <ul className="space-y-2">
          {(list || []).map(t => (
            <li key={t.id}>
              <button
                type="button"
                onClick={() => setOpen(t)}
                className="w-full text-right border border-slate-200 rounded-xl p-3 hover:bg-slate-50"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-bold text-sm text-slate-900">{t.subject}</span>
                  <span className={`text-[10px] font-bold border rounded-full px-2 py-0.5 ${t.kind === 'staff' ? 'bg-slate-100 text-slate-700 border-slate-200' : t.target === 'admin' ? 'bg-sky-50 text-sky-800 border-sky-200' : 'bg-violet-50 text-violet-800 border-violet-200'}`}>
                    {t.kind === 'staff' ? `${t.opener} ← ${t.to_name}` : t.target === 'admin' ? 'با پشتیبانی' : 'با مشاور'}
                  </span>
                  {t.status === 'closed' && <span className="text-[10px] font-bold border rounded-full px-2 py-0.5 bg-slate-100 text-slate-600 border-slate-200">بسته</span>}
                  {t.waiting && t.status === 'open' && (
                    <span className={`text-[10px] font-bold border rounded-full px-2 py-0.5 ${t.waiting_hours >= 24 ? 'bg-red-50 text-red-700 border-red-200' : 'bg-amber-50 text-amber-800 border-amber-200'}`}>
                      {viewer === 'student' ? 'منتظر جواب' : `بی‌جواب · ${fa(t.waiting_hours)} ساعت`}
                    </span>
                  )}
                </div>
                <div className="text-[11px] text-slate-500 mt-1 flex flex-wrap gap-x-3">
                  {viewer !== 'student' && t.kind === 'student' && <span>{t.student}</span>}
                  <span>آخرین پیام: {timeOf(t.last_at)}</span>
                </div>
              </button>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
};

const NewTicket: React.FC<{ viewer: string; onCancel: () => void; onDone: (t: Ticket) => void }> = ({ viewer, onCancel, onDone }) => {
  const [target, setTarget] = useState<'mentor' | 'admin'>('mentor');
  const [to, setTo] = useState('');
  const [people, setPeople] = useState<{ user_id: number; name: string; role: string }[]>([]);

  useEffect(() => {
    if (viewer !== 'admin') return;
    ticketsApi
      .recipients()
      .then(r => setPeople(r.recipients))
      .catch(() => {});
  }, [viewer]);
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!subject.trim()) return setError('یک موضوع کوتاه بنویس.');
    if (!body.trim()) return setError('متن پیام خالی است.');
    if (viewer === 'admin' && !to) return setError('گیرنده را انتخاب کن.');
    try {
      setSaving(true);
      const r = await ticketsApi.create(
        viewer === 'student'
          ? { kind: 'student', target, subject: subject.trim(), body: body.trim() }
          : { kind: 'staff', to_user_id: viewer === 'admin' ? Number(to) : 0, subject: subject.trim(), body: body.trim() }
      );
      onDone(r.ticket);
    } catch (e: any) {
      setError(e.message || 'ارسال نشد.');
      setSaving(false);
    }
  };

  return (
    <Card title="گفت‌وگوی تازه" icon={<Plus className="w-4 h-4" />}>
      <form onSubmit={submit} className="space-y-3">
        {viewer === 'admin' && (
          <div>
            <Label htmlFor="tk-to" required>
              گیرنده
            </Label>
            <select id="tk-to" value={to} onChange={e => setTo(e.target.value)} className={inputCls}>
              <option value="">انتخاب کنید</option>
              {people.map(p => (
                <option key={p.user_id} value={p.user_id}>
                  {p.name} — {p.role}
                </option>
              ))}
            </select>
          </div>
        )}
        {viewer !== 'student' && viewer !== 'admin' && (
          <div className="text-xs text-slate-600 bg-slate-50 border border-slate-200 rounded-xl p-3">این پیام به مدیریت موسسه می‌رسد.</div>
        )}
        {viewer === 'student' && (
        <div>
          <Label htmlFor="tk-target" required>
            با چه کسی؟
          </Label>
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              onClick={() => setTarget('mentor')}
              className={`border rounded-xl p-3 text-right ${target === 'mentor' ? 'border-violet-400 bg-violet-50' : 'border-slate-200'}`}
            >
              <div className="font-bold text-sm">مشاور تحصیلی‌ام</div>
              <div className="text-[11px] text-slate-500 mt-1">سؤال درسی، برنامه، تکلیف</div>
            </button>
            <button
              type="button"
              onClick={() => setTarget('admin')}
              className={`border rounded-xl p-3 text-right ${target === 'admin' ? 'border-sky-400 bg-sky-50' : 'border-slate-200'}`}
            >
              <div className="font-bold text-sm">پشتیبانی موسسه</div>
              <div className="text-[11px] text-slate-500 mt-1">اگر مشاور جواب نمی‌دهد یا مشکل دیگری هست</div>
            </button>
          </div>
        </div>
        )}
        <div>
          <Label htmlFor="tk-subject" required>
            موضوع
          </Label>
          <input id="tk-subject" value={subject} onChange={e => setSubject(e.target.value)} className={inputCls} placeholder="مثلاً: سؤال درباره‌ی برنامه‌ی این هفته" />
        </div>
        <div>
          <Label htmlFor="tk-body" required>
            پیام
          </Label>
          <textarea id="tk-body" value={body} onChange={e => setBody(e.target.value)} rows={5} className={inputCls} />
        </div>
        {viewer === 'student' && (
        <div className="text-[11px] text-slate-500 bg-slate-50 border border-slate-200 rounded-xl p-3 flex gap-2">
          <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5 text-slate-400" />
          <span>
            گفت‌وگوی با مشاور را مدیر موسسه هم می‌بیند. اگر می‌خواهی چیزی را فقط با موسسه در میان بگذاری، «پشتیبانی موسسه» را انتخاب کن — آن را مشاورت نمی‌بیند.
          </span>
        </div>
        )}
        {error && <Alert kind="error">{error}</Alert>}
        <div className="flex gap-2">
          <Button type="submit" loading={saving}>
            <Send className="w-4 h-4" /> ارسال
          </Button>
          <Button type="button" variant="ghost" onClick={onCancel}>
            انصراف
          </Button>
        </div>
      </form>
    </Card>
  );
};

const Thread: React.FC<{ viewer: string; ticket: Ticket; onBack: () => void; onSeen?: () => void }> = ({ viewer, ticket, onBack, onSeen }) => {
  const [data, setData] = useState<Ticket>(ticket);
  const [body, setBody] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    ticketsApi
      .get(ticket.id)
      .then(r => {
        setData(r.ticket);
        onSeen?.();
      })
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ticket.id]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: 'nearest' });
  }, [data.messages]);

  const send = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!body.trim()) return;
    try {
      setSending(true);
      setError('');
      const r = await ticketsApi.reply(ticket.id, body.trim());
      setData(r.ticket);
      setBody('');
    } catch (e: any) {
      setError(e.message || 'ارسال نشد.');
    } finally {
      setSending(false);
    }
  };

  const toggleClose = async () => {
    try {
      await ticketsApi.close(ticket.id, data.status === 'closed');
      const r = await ticketsApi.get(ticket.id);
      setData(r.ticket);
    } catch (e: any) {
      setError(e.message || 'انجام نشد.');
    }
  };

  const msgs: TicketMessage[] = data.messages || [];

  return (
    <Card
      title={data.subject}
      icon={<MessageSquare className="w-4 h-4" />}
      action={
        <div className="flex items-center gap-2">
          <Button size="sm" variant="ghost" onClick={toggleClose}>
            {data.status === 'closed' ? 'باز کردن دوباره' : 'بستن گفت‌وگو'}
          </Button>
          <Button size="sm" variant="ghost" onClick={onBack}>
            بازگشت
          </Button>
        </div>
      }
    >
      {viewer !== 'student' && data.kind === 'student' && (
        <div className="text-[11px] text-slate-500 mb-3">
          {data.student}
          {data.mobile && (
            <a href={`tel:${data.mobile}`} className="font-mono text-emerald-700 mr-2" dir="ltr">
              {data.mobile}
            </a>
          )}
        </div>
      )}

      <ul className="space-y-3 max-h-[420px] overflow-y-auto pl-1">
        {msgs.map(m => {
          const mine = m.role === viewer;
          return (
            <li key={m.id} className={`flex ${mine ? 'justify-start' : 'justify-end'}`}>
              <div
                className={`max-w-[85%] rounded-2xl px-3 py-2 border ${
                  mine ? 'bg-emerald-50 border-emerald-200' : m.role === 'admin' ? 'bg-sky-50 border-sky-200' : 'bg-white border-slate-200'
                }`}
              >
                <div className="text-[10px] text-slate-500 mb-1">
                  {ROLE_LABEL[m.role] || m.role}
                  {m.name ? ` · ${m.name}` : ''} · {timeOf(m.created_at)}
                </div>
                <div className="text-sm text-slate-800 whitespace-pre-line leading-6">{m.body}</div>
              </div>
            </li>
          );
        })}
        <div ref={endRef} />
      </ul>

      {data.status === 'closed' ? (
        <div className="mt-4 text-xs text-slate-500 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4" /> این گفت‌وگو بسته شده است.
        </div>
      ) : (
        <form onSubmit={send} className="mt-4 space-y-2">
          <textarea value={body} onChange={e => setBody(e.target.value)} rows={3} className={inputCls} placeholder="پاسخ شما…" aria-label="متن پیام" />
          {error && <Alert kind="error">{error}</Alert>}
          <Button type="submit" loading={sending} size="sm">
            <Send className="w-4 h-4" /> ارسال
          </Button>
        </form>
      )}
    </Card>
  );
};
