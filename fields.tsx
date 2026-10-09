import React, { useEffect, useState } from 'react';
import { SUBJECTS, latinDigits } from '../lib/format';
import { inputCls, Label } from './ui';

const OTHER = 'سایر';

/** انتخاب درس؛ با «سایر» یک فیلد متنی برای نام دلخواه باز می‌شود. مقدار نهایی همیشه متن درس است. */
export const SubjectField: React.FC<{ id: string; value: string; onChange: (v: string) => void; required?: boolean; label?: string }> = ({
  id,
  value,
  onChange,
  required,
  label = 'درس',
}) => {
  const known = SUBJECTS.includes(value) && value !== OTHER;
  const [custom, setCustom] = useState(!!value && !known);

  useEffect(() => {
    // بعد از خالی شدن فرم، والد با تغییر key این فیلد را از نو می‌سازد
    if (value && !SUBJECTS.includes(value)) setCustom(true);
  }, [value]);

  return (
    <div>
      <Label htmlFor={id} required={required}>
        {label}
      </Label>
      <select
        id={id}
        value={custom ? OTHER : value}
        onChange={e => {
          if (e.target.value === OTHER) {
            setCustom(true);
            onChange('');
          } else {
            setCustom(false);
            onChange(e.target.value);
          }
        }}
        className={inputCls}
      >
        <option value="">انتخاب کنید</option>
        {SUBJECTS.map(s => (
          <option key={s} value={s}>
            {s === OTHER ? 'سایر (نام درس را بنویسید)' : s}
          </option>
        ))}
      </select>
      {custom && (
        <input
          aria-label="نام درس"
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder="نام درس"
          maxLength={50}
          className={`${inputCls} mt-2`}
          autoFocus
        />
      )}
    </div>
  );
};

export const toInt = (v: string) => parseInt(latinDigits(v), 10) || 0;

/** ساعت + دقیقه → دقیقه */
export const DurationFields: React.FC<{ idPrefix: string; hours: string; minutes: string; onHours: (v: string) => void; onMinutes: (v: string) => void }> = ({
  idPrefix,
  hours,
  minutes,
  onHours,
  onMinutes,
}) => (
  <>
    <div>
      <Label htmlFor={`${idPrefix}-h`}>ساعت</Label>
      <input id={`${idPrefix}-h`} inputMode="numeric" value={hours} onChange={e => onHours(e.target.value)} className={`${inputCls} text-center`} />
    </div>
    <div>
      <Label htmlFor={`${idPrefix}-m`}>دقیقه</Label>
      <input id={`${idPrefix}-m`} inputMode="numeric" value={minutes} onChange={e => onMinutes(e.target.value)} className={`${inputCls} text-center`} />
    </div>
  </>
);

export const splitMinutes = (total: number): [string, string] => {
  if (!total) return ['', ''];
  const h = Math.floor(total / 60);
  return [h ? String(h) : '', String(total % 60)];
};
