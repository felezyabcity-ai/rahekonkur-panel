import React, { useCallback, useEffect, useRef, useState } from 'react';
import { MessageSquare, X } from 'lucide-react';
import { UnreadItem, ticketsApi } from '../api';

const POLL_MS = 45000;
const OPEN_EVENT = 'rk-open-tickets';

/** هر جای پنل می‌تواند بخواهد تب گفت‌وگوها باز شود. */
export const requestOpenTickets = () => window.dispatchEvent(new CustomEvent(OPEN_EVENT));

export const useOpenTicketsRequest = (handler: () => void) => {
  useEffect(() => {
    const fn = () => handler();
    window.addEventListener(OPEN_EVENT, fn);
    return () => window.removeEventListener(OPEN_EVENT, fn);
  }, [handler]);
};

/**
 * شمارش خوانده‌نشده‌ها با نظرسنجی دوره‌ای.
 * وب‌سوکت نداریم و روی هاست اشتراکی هم نمی‌شود داشت؛ هر ۴۵ ثانیه کافی است.
 */
export const useUnread = () => {
  const [count, setCount] = useState(0);
  const [items, setItems] = useState<UnreadItem[]>([]);

  const refresh = useCallback(async () => {
    try {
      const r = await ticketsApi.unread();
      setCount(r.messages || 0);
      setItems(r.items || []);
    } catch {
      /* شبکه قطع بود، دفعه‌ی بعد */
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(() => {
      if (document.visibilityState === 'visible') refresh();
    }, POLL_MS);
    const onFocus = () => refresh();
    window.addEventListener('focus', onFocus);
    return () => {
      clearInterval(id);
      window.removeEventListener('focus', onFocus);
    };
  }, [refresh]);

  return { count, items, refresh };
};

/** پاپ‌آپ گوشه‌ی صفحه؛ فقط وقتی پیام تازه‌ای نسبت به دفعه‌ی قبل آمده باشد. */
export const UnreadPopup: React.FC<{ count: number; items: UnreadItem[] }> = ({ count, items }) => {
  const [show, setShow] = useState(false);
  const seen = useRef<number>(-1);
  const dismissed = useRef<number>(-1);

  useEffect(() => {
    if (seen.current === -1) {
      seen.current = count;
      return;
    }
    if (count > seen.current && count !== dismissed.current) {
      setShow(true);
    }
    seen.current = count;
  }, [count]);

  if (!show || !items.length) return null;

  const top = items[0];
  const more = items.length - 1;

  return (
    <div className="fixed bottom-4 left-4 z-50 w-[min(92vw,340px)] animate-in">
      <div className="bg-white border border-slate-200 shadow-lg rounded-2xl p-3">
        <div className="flex items-start gap-2">
          <span className="shrink-0 w-8 h-8 rounded-full bg-orange-50 text-orange-600 flex items-center justify-center">
            <MessageSquare className="w-4 h-4" />
          </span>
          <div className="min-w-0 flex-1">
            <div className="font-black text-sm text-slate-900">پیام تازه از {top.from}</div>
            <div className="text-xs text-slate-600 mt-0.5 truncate">{top.subject}</div>
            <div className="text-[11px] text-slate-500 mt-1 line-clamp-2">{top.preview}</div>
            {more > 0 && <div className="text-[11px] text-slate-400 mt-1">و {more} گفت‌وگوی دیگر</div>}
            <div className="flex gap-2 mt-2">
              <button
                type="button"
                onClick={() => {
                  setShow(false);
                  dismissed.current = count;
                  requestOpenTickets();
                }}
                className="px-3 py-1.5 rounded-lg bg-slate-900 text-white text-xs font-bold"
              >
                دیدن گفت‌وگو
              </button>
              <button
                type="button"
                onClick={() => {
                  setShow(false);
                  dismissed.current = count;
                }}
                className="px-3 py-1.5 rounded-lg text-slate-500 text-xs font-bold hover:bg-slate-50"
              >
                بعداً
              </button>
            </div>
          </div>
          <button
            type="button"
            onClick={() => {
              setShow(false);
              dismissed.current = count;
            }}
            className="p-1 text-slate-300 hover:text-slate-600"
            aria-label="بستن"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};

/** نشان عددی کنار عنوان تب. */
export const UnreadDot: React.FC<{ count: number }> = ({ count }) =>
  count > 0 ? (
    <span className="bg-orange-600 text-white text-[10px] rounded-full px-1.5 min-w-5 text-center">
      {String(count).replace(/\d/g, d => '۰۱۲۳۴۵۶۷۸۹'[Number(d)])}
    </span>
  ) : null;
