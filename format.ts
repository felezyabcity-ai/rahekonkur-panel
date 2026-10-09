// قالب‌بندی تاریخ و عدد برای نمایش فارسی. هیچ مقدار پیش‌فرضی نمی‌سازد.

const faDigits = (s: string | number) => String(s).replace(/\d/g, d => '۰۱۲۳۴۵۶۷۸۹'[Number(d)]);

export const fa = faDigits;

/** «۲ ساعت و ۱۵ دقیقه» — برای صفر، «۰ دقیقه». */
export function formatMinutes(total: number): string {
  const m = Math.max(0, Math.round(total || 0));
  const h = Math.floor(m / 60);
  const r = m % 60;
  if (h === 0) return `${faDigits(r)} دقیقه`;
  if (r === 0) return `${faDigits(h)} ساعت`;
  return `${faDigits(h)} ساعت و ${faDigits(r)} دقیقه`;
}

/** «۲٫۵» ساعت برای نمودارها */
export function hoursShort(total: number): string {
  const h = Math.round(((total || 0) / 60) * 10) / 10;
  return faDigits(String(h).replace('.', '٫'));
}

function parseDate(value: string): Date | null {
  if (!value || value.startsWith('0000')) return null;
  // «2026-09-16» یا «2026-09-16 14:37:38» — به وقت محلی تفسیر می‌شود
  const m = value.match(/^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2}))?/);
  if (!m) return null;
  return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4] || 12), Number(m[5] || 0));
}

const dateFmt = new Intl.DateTimeFormat('fa-IR-u-ca-persian', { year: 'numeric', month: 'long', day: 'numeric' });
const shortFmt = new Intl.DateTimeFormat('fa-IR-u-ca-persian', { month: 'short', day: 'numeric' });
const dayFmt = new Intl.DateTimeFormat('fa-IR-u-ca-persian', { day: 'numeric' });

export function jDate(value: string): string {
  const d = parseDate(value);
  return d ? dateFmt.format(d) : '';
}

export function jShort(value: string): string {
  const d = parseDate(value);
  return d ? shortFmt.format(d) : '';
}

/** فقط روزِ ماه (برای زیر نمودار) */
export function jDay(value: string): string {
  const d = parseDate(value);
  return d ? dayFmt.format(d) : '';
}

/** تعداد روز از امروز تا تاریخ (منفی یعنی گذشته). */
export function daysUntil(value: string): number | null {
  const d = parseDate(value);
  if (!d) return null;
  const today = new Date();
  today.setHours(12, 0, 0, 0);
  d.setHours(12, 0, 0, 0);
  return Math.round((d.getTime() - today.getTime()) / 86400000);
}

export function todayIso(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

export function isoDaysAgo(n: number): string {
  const d = new Date();
  d.setDate(d.getDate() - n);
  const p = (x: number) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** ارقام فارسی/عربی ورودی را لاتین می‌کند. */
export function latinDigits(s: string): string {
  return String(s || '')
    .replace(/[۰-۹]/g, d => String('۰۱۲۳۴۵۶۷۸۹'.indexOf(d)))
    .replace(/[٠-٩]/g, d => String('٠١٢٣٤٥٦٧٨٩'.indexOf(d)));
}

const moneyFmt = new Intl.NumberFormat('fa-IR');
/** «۴٬۵۰۰٬۰۰۰ تومان» */
export const toman = (n: number | null | undefined) => (n === null || n === undefined ? '—' : `${moneyFmt.format(Math.round(n))} تومان`);
export const faNum = (n: number) => moneyFmt.format(n);

export const WEEKDAYS = ['شنبه', 'یکشنبه', 'دوشنبه', 'سه‌شنبه', 'چهارشنبه', 'پنجشنبه', 'جمعه'];

/** تاریخ ISO به‌علاوه‌ی n روز (بدون وابستگی به منطقه‌ی زمانی) */
export function addDaysIso(iso: string, n: number): string {
  const [y, m, d] = iso.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d + n, 12));
  return dt.toISOString().slice(0, 10);
}

/** «۲ روز پیش» و مانند آن برای آخرین فعالیت؛ null اگر تاریخی نباشد */
export function daysSince(value: string): number | null {
  const d = daysUntil(value);
  return d === null ? null : -d;
}

export const SUBJECTS = [
  'زیست‌شناسی',
  'شیمی',
  'فیزیک',
  'ریاضی',
  'ادبیات فارسی',
  'عربی',
  'دین و زندگی',
  'زبان انگلیسی',
  'آزمون جامع',
  'سایر',
];
