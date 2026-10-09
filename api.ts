// src/api.ts
// Real API Client for Rahe Konkur Student Portal (WordPress REST API)

export class ApiError extends Error {

  status: number;
  code?: string;
  data?: any;

  constructor(message: string, status: number, code?: string, data?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.data = data;
  }
}

export const BASE = (import.meta as any).env?.VITE_API_BASE || 'https://rahekonkur.ir/wp-json';
export const API_BASE = BASE;
const TOKEN_KEY = 'rksp_token';

const USER_KEY = 'rksp_user';

export const tokenStorage = {
  get: (): string | null => {
    try {
      return localStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  },
  set: (token: string) => {
    try {
      localStorage.setItem(TOKEN_KEY, token);
    } catch {}
  },
  remove: () => {
    try {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(USER_KEY);
      localStorage.removeItem('rksp_active_student');
      localStorage.removeItem('rksp_active_mentor');
    } catch {}
  },
  getUser: (): any | null => {
    try {
      const raw = localStorage.getItem(USER_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  },
  setUser: (user: any) => {
    try {
      localStorage.setItem(USER_KEY, JSON.stringify(user));
    } catch {}
  },
};

// Global authentication error handlers (triggered on 401 or 403)
type AuthErrorListener = () => void;
let authErrorListeners: AuthErrorListener[] = [];

export const onAuthError = (callback: AuthErrorListener) => {
  authErrorListeners.push(callback);
  return () => {
    authErrorListeners = authErrorListeners.filter(l => l !== callback);
  };
};

function handleAuthFailure() {
  tokenStorage.remove();
  authErrorListeners.forEach(cb => {
    try {
      cb();
    } catch (e) {
      console.error('Auth error listener failure:', e);
    }
  });
}

// Convert Persian and Arabic digits to Latin, and normalize to 09xxxxxxxxx
export function normalizeMobile(phone: string): string {
  if (!phone) return '';
  const persianDigits = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹'];
  const arabicDigits = ['٠', '١', '٢', '٣', '٤', '٥', '٦', '٧', '٨', '٩'];
  let clean = String(phone).trim();
  for (let i = 0; i < 10; i++) {
    clean = clean.split(persianDigits[i]).join(String(i));
    clean = clean.split(arabicDigits[i]).join(String(i));
  }
  // Remove any non-digits
  clean = clean.replace(/\D/g, '');
  // Normalize international prefix
  if (clean.startsWith('0098')) {
    clean = '0' + clean.slice(4);
  } else if (clean.startsWith('98') && clean.length === 12) {
    clean = '0' + clean.slice(2);
  } else if (!clean.startsWith('0') && clean.length === 10) {
    clean = '0' + clean;
  }
  return clean;
}

export async function apiRequest<T = any>(
  endpoint: string,
  options: {
    method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    body?: any;
    params?: Record<string, any>;
    headers?: Record<string, string>;
  } = {}
): Promise<T> {
  const method = options.method || 'GET';
  let url = `${BASE}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;

  if (options.params) {
    const searchParams = new URLSearchParams();
    Object.entries(options.params).forEach(([key, val]) => {
      if (val !== undefined && val !== null) {
        searchParams.append(key, String(val));
      }
    });
    const qs = searchParams.toString();
    if (qs) {
      url += (url.includes('?') ? '&' : '?') + qs;
    }
  }

  const token = tokenStorage.get();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  };

  const config: RequestInit = {
    method,
    headers,
  };

  if (options.body && method !== 'GET') {
    config.body = JSON.stringify(options.body);
  }

  let res: Response;
  try {
    res = await fetch(url, config);
  } catch (err: any) {
    throw new ApiError(
      err?.message || 'خطا در برقراری ارتباط با سرور. لطفاً اتصال اینترنت خود را بررسی کنید.',
      0,
      'NETWORK_ERROR'
    );
  }

  // فقط خطای واقعیِ احراز هویت کاربر را بیرون می‌کند. ۴۰۳ ِ «این دانش‌آموز به شما متصل نیست»
  // یا «این بخش مخصوص مشاوران است» نباید نشست را پاک کند.
  if (res.status === 401 || res.status === 403) {
    let errorData: any = null;
    try {
      errorData = await res.clone().json();
    } catch {}
    // وردپرس برای «وارد نشده» ۴۰۱ و برای «وارد شده ولی مجاز نیست» ۴۰۳ برمی‌گرداند.
    const isAuthFailure = res.status === 401;
    if (!isAuthFailure) {
      throw new ApiError(errorData?.message || 'اجازه‌ی این کار را ندارید.', res.status, errorData?.code || 'FORBIDDEN', errorData);
    }
    // ۴۰۱ ِ فرم ورود (رمز یا کد اشتباه) هم نباید رفتار «نشست منقضی شد» بگیرد
    if (!token || endpoint.includes('/login') || endpoint.includes('/otp/') || endpoint.includes('/change-password')) {
      throw new ApiError(errorData?.message || 'اطلاعات ورود درست نیست.', res.status, errorData?.code || 'UNAUTHORIZED', errorData);
    }
    handleAuthFailure();
    throw new ApiError(
      errorData?.message || 'نشست کاربری شما منقضی شده است. لطفاً مجدداً وارد شوید.',
      res.status,
      errorData?.code || 'UNAUTHORIZED',
      errorData
    );
  }

  if (!res.ok) {
    let errorData: any = null;
    try {
      errorData = await res.json();
    } catch {}
    throw new ApiError(
      errorData?.message || `خطای سرور (${res.status})`,
      res.status,
      errorData?.code || 'SERVER_ERROR',
      errorData
    );
  }

  const contentType = res.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    return (await res.json()) as T;
  }

  return (await res.text()) as unknown as T;
}


// اندپوینت‌های واقعی سامانه راه کنکور — همه روی پل (rkspb/v1)
export const api = {
  auth: {
    login: (mobile: string, password: string) =>
      apiRequest<AuthResponse>('/rkspb/v1/login', {
        method: 'POST',
        body: { mobile: normalizeMobile(mobile), password },
      }),
    requestOtp: (mobile: string) =>
      apiRequest<{ sent?: boolean; success?: boolean; message?: string }>('/rkspb/v1/otp/request', {
        method: 'POST',
        body: { mobile: normalizeMobile(mobile) },
      }),
    verifyOtp: (mobile: string, code: string) =>
      apiRequest<AuthResponse & { verified?: boolean; registered?: boolean }>('/rkspb/v1/otp/verify', {
        method: 'POST',
        body: { mobile: normalizeMobile(mobile), code: normalizeMobile(code) },
      }),
    register: (body: { name: string; mobile: string; password?: string; grade?: string; field?: string }) =>
      apiRequest<AuthResponse>('/rkspb/v1/register', {
        method: 'POST',
        body: { ...body, mobile: normalizeMobile(body.mobile) },
      }),
    me: () => apiRequest<{ user: any }>('/rkspb/v1/me'),
    changePassword: (current_password: string, new_password: string) =>
      apiRequest<{ ok: boolean; token: string }>('/rkspb/v1/change-password', {
        method: 'POST',
        body: { current_password, new_password },
      }),
    logout: () => apiRequest<{ ok: boolean }>('/rkspb/v1/logout', { method: 'POST' }),
  },

  student: {
    overview: () => apiRequest<StudentOverview>('/rkspb/v1/student/overview'),
    logStudy: (body: { subject: string; minutes: number; tests?: number; topic?: string; date?: string }) =>
      apiRequest<StudentOverview>('/rkspb/v1/student/study-log', { method: 'POST', body }),
    deleteLog: (id: number) =>
      apiRequest<StudentOverview>(`/rkspb/v1/student/study-log/${id}/delete`, { method: 'POST' }),
    setTaskDone: (id: number, done: boolean) =>
      apiRequest<StudentOverview>(`/rkspb/v1/student/tasks/${id}`, { method: 'POST', body: { done } }),
    week: (start?: string) => apiRequest<Week>('/rkspb/v1/student/week', { params: { start } }),
    setWeekItem: (id: number, body: { done: boolean; minutes?: number; tests?: number }) =>
      apiRequest<{ ok: boolean; week: Week }>(`/rkspb/v1/student/week/items/${id}`, { method: 'POST', body }),
  },

  mentor: {
    students: () => apiRequest<{ students: StudentCard[] }>('/rkspb/v1/mentor/students'),
    student: (id: number) => apiRequest<MentorStudentDetail>(`/rkspb/v1/mentor/students/${id}`),
    createTask: (body: { student_id: number; title: string; description?: string; due_date?: string }) =>
      apiRequest<{ ok: boolean; tasks: Task[] }>('/rkspb/v1/mentor/tasks', { method: 'POST', body }),
    deleteTask: (id: number) =>
      apiRequest<{ ok: boolean; tasks: Task[] }>(`/rkspb/v1/mentor/tasks/${id}/delete`, { method: 'POST' }),
    createNote: (body: { student_id: number; note: string; visibility: 'public' | 'private' }) =>
      apiRequest<{ ok: boolean; notes: Note[] }>('/rkspb/v1/mentor/notes', { method: 'POST', body }),
    deleteNote: (id: number) =>
      apiRequest<{ ok: boolean; notes: Note[] }>(`/rkspb/v1/mentor/notes/${id}/delete`, { method: 'POST' }),
    updateTask: (id: number, body: { title: string; description?: string; due_date?: string }) =>
      apiRequest<{ ok: boolean; tasks: Task[] }>(`/rkspb/v1/mentor/tasks/${id}`, { method: 'POST', body }),
    updateNote: (id: number, body: { note: string; visibility?: 'public' | 'private' }) =>
      apiRequest<{ ok: boolean; notes: Note[] }>(`/rkspb/v1/mentor/notes/${id}`, { method: 'POST', body }),
    week: (studentId: number, start?: string) => apiRequest<Week>(`/rkspb/v1/mentor/students/${studentId}/week`, { params: { start } }),
    addWeekItem: (studentId: number, body: WeekItemInput) =>
      apiRequest<Week>(`/rkspb/v1/mentor/students/${studentId}/week/items`, { method: 'POST', body }),
    updateWeekItem: (id: number, body: Partial<WeekItemInput>) =>
      apiRequest<Week>(`/rkspb/v1/mentor/week/items/${id}`, { method: 'POST', body }),
    deleteWeekItem: (id: number) => apiRequest<Week>(`/rkspb/v1/mentor/week/items/${id}/delete`, { method: 'POST' }),
    copyWeek: (studentId: number, start: string, append = false) =>
      apiRequest<Week>(`/rkspb/v1/mentor/students/${studentId}/week/copy`, { method: 'POST', body: { start, append } }),
  },
};

export const salesApi = {
  mentors: () => apiRequest<{ mentors: MentorOption[]; sales: { user_id: number; name: string }[] }>('/rkspb/v1/sales/mentors'),
  plans: () => apiRequest<{ plans: PlanCatalogItem[] }>('/rkspb/v1/plans/catalog'),
  registerStudent: (body: {
    name: string;
    mobile: string;
    grade: string;
    field?: string;
    mentor_id?: number;
    plan_name: string;
    price: number;
    months: number;
    start_date?: string;
    ref?: string;
    amount?: number;
    paid_at?: string;
    note?: string;
  }) =>
    apiRequest<{ ok: boolean; student_id: number; account_created: boolean; plan_id: number; payment: Payment | null }>('/rkspb/v1/sales/register-student', {
      method: 'POST',
      body,
    }),
  payments: (params?: { status?: string; student_id?: number }) =>
    apiRequest<{ payments: Payment[]; pending: number }>('/rkspb/v1/payments', { params }),
  addPayment: (body: { mobile: string; amount: number; ref: string; paid_at: string; note?: string; plan_name?: string; months?: number; start_date?: string }) =>
    apiRequest<{ ok: boolean; payment: Payment }>('/rkspb/v1/payments', { method: 'POST', body }),
  summary: (params: { from: string; to: string }) => apiRequest<SalesSummary>('/rkspb/v1/sales/summary', { params }),
};

export const adminApi = {
  dashboard: (from: string, to: string) => apiRequest<AdminDashboardData>('/rkspb/v1/admin/dashboard', { params: { from, to } }),
  setShare: (body: { user_id: number; percent?: string; paused?: boolean }) =>
    apiRequest<{ ok: boolean }>('/rkspb/v1/admin/share', { method: 'POST', body }),
  createSales: (body: { name: string; mobile: string; percent?: string }) =>
    apiRequest<{ ok: boolean; user_id: number; mobile: string; password: string }>('/rkspb/v1/admin/sales-users', { method: 'POST', body }),
  decidePayment: (id: number, body: { decision: 'approved' | 'rejected'; note?: string }) =>
    apiRequest<{ ok: boolean; payment: Payment & { needs_mentor?: boolean } }>(`/rkspb/v1/payments/${id}/decide`, { method: 'POST', body }),
  settlements: (period: string) => apiRequest<{ period: string; rows: Settlement[] }>('/rkspb/v1/admin/settlements', { params: { period } }),
  closeSettlement: (body: { period: string; from: string; to: string }) =>
    apiRequest<{ ok: boolean; period: string; count: number; rows: Settlement[] }>('/rkspb/v1/admin/settlements/close', { method: 'POST', body }),
  markPaid: (id: number, paid: boolean) =>
    apiRequest<{ ok: boolean; rows: Settlement[] }>(`/rkspb/v1/admin/settlements/${id}/paid`, { method: 'POST', body: { paid } }),
  reopenSettlement: (period: string) =>
    apiRequest<{ ok: boolean; period: string }>('/rkspb/v1/admin/settlements/reopen', { method: 'POST', body: { period } }),
  assignMentor: (studentId: number, mentorId: number) =>
    apiRequest<{ ok: boolean; student_id: number; mentor_id: number }>(`/rkspb/v1/students/${studentId}/mentor`, { method: 'POST', body: { mentor_id: mentorId } }),
  deletePayment: (id: number) => apiRequest<{ ok: boolean }>(`/rkspb/v1/payments/${id}/delete`, { method: 'POST' }),
};

export interface TicketMessage {
  id: number;
  role: 'student' | 'mentor' | 'admin';
  name: string;
  body: string;
  created_at: string;
}

export interface Ticket {
  id: number;
  student_id: number;
  student: string;
  mobile: string;
  target: 'mentor' | 'admin';
  kind: 'student' | 'staff';
  opener: string;
  to_user_id: number;
  to_name: string;
  subject: string;
  status: 'open' | 'closed';
  created_at: string;
  last_at: string;
  last_role: string;
  waiting: boolean;
  waiting_hours: number;
  messages?: TicketMessage[];
}

export interface UnreadItem {
  ticket_id: number;
  subject: string;
  kind: string;
  student: string;
  from: string;
  role: string;
  preview: string;
  at: string;
  count: number;
}

export const ticketsApi = {
  unread: () => apiRequest<{ count: number; messages: number; items: UnreadItem[] }>('/rkspb/v1/tickets/unread'),
  markRead: (id: number) => apiRequest<{ ok: boolean }>(`/rkspb/v1/tickets/${id}/read`, { method: 'POST' }),
  list: () => apiRequest<{ role: string; tickets: Ticket[]; waiting: number }>('/rkspb/v1/tickets'),
  get: (id: number) => apiRequest<{ role: string; ticket: Ticket }>(`/rkspb/v1/tickets/${id}`),
  recipients: () => apiRequest<{ recipients: { user_id: number; name: string; role: string }[] }>('/rkspb/v1/tickets/recipients'),
  create: (body: { kind?: 'student' | 'staff'; target?: 'mentor' | 'admin'; to_user_id?: number; subject: string; body: string }) =>
    apiRequest<{ ok: boolean; ticket: Ticket }>('/rkspb/v1/tickets', { method: 'POST', body }),
  reply: (id: number, body: string) => apiRequest<{ ok: boolean; ticket: Ticket }>(`/rkspb/v1/tickets/${id}/reply`, { method: 'POST', body: { body } }),
  close: (id: number, reopen = false) => apiRequest<{ ok: boolean }>(`/rkspb/v1/tickets/${id}/close`, { method: 'POST', body: { reopen } }),
};

export type PaymentStatus = 'pending' | 'approved' | 'rejected';

export interface Settlement {
  id: number;
  period: string;
  user_id: number;
  role: 'mentor' | 'sales';
  name: string;
  base_amount: number;
  percent: number;
  payout: number;
  detail: string;
  status: 'locked' | 'paid';
  locked_at: string;
  locked_name: string;
  paid_at: string;
  note: string;
}

export interface Payment {
  id: number;
  student_id: number;
  student_name: string;
  mobile: string;
  plan_id: number;
  amount: number;
  ref: string;
  paid_at: string;
  status: PaymentStatus;
  note: string;
  created_by: number;
  created_name: string;
  created_at: string;
  decided_by: number;
  decided_name: string;
  decided_at: string;
}

export interface PlanCatalogItem {
  name: string;
  price: number;
  track: string;
}

export interface SalesSummary {
  from: string;
  to: string;
  percent: number;
  payout: number;
  summary: { approved_count: number; approved_amount: number; pending_count: number; pending_amount: number };
  payments: Payment[];
}

export interface MentorOption {
  mentor_id: number;
  name: string;
  specialty: string;
  active_students: number;
}

export interface AdminStudentRow {
  student_id: number;
  name: string;
  mobile: string;
  grade: string;
  mentor_name: string;
  plan_name: string;
  plan_end: string;
  last_at: string;
  days_left?: number;
  idle_days?: number | null;
}

export interface AdminDashboardData {
  from: string;
  to: string;
  today: string;
  students: {
    total: number;
    active: number;
    new: number;
    expiring: AdminStudentRow[];
    inactive: AdminStudentRow[];
    no_mentor: AdminStudentRow[];
  };
  mentors: {
    user_id: number;
    name: string;
    active_students: number;
    paying_students: number;
    partial_students?: number;
    base_amount: number;
    percent: number | null;
    payout: number | null;
    week_rate: number | null;
  }[];
  sales: {
    user_id: number;
    name: string;
    mobile: string;
    paused: boolean;
    approved_count: number;
    approved_amount: number;
    pending_count: number;
    pending_amount: number;
    percent: number;
    payout: number;
  }[];
  payments?: { pending: number; pending_amount: number; approved_amount: number };
  tickets?: { total: number; overdue: number; rows: Ticket[] };
}

export interface AuthResponse {
  token: string;
  user: any;
  message?: string;
}

export interface Task {
  id: number;
  title: string;
  description: string;
  due_date: string;
  done: boolean;
  done_at: string;
  created_at: string;
}

export interface Note {
  id: number;
  note: string;
  private: boolean;
  created_at: string;
}

export interface StudyTotals {
  total_minutes: number;
  week_minutes: number;
  today_minutes: number;
  last_at: string;
  sessions: number;
  total_tests: number;
}

export interface StudyDetail {
  subjects: { subject: string; minutes: number; tests: number; sessions: number }[];
  days: { date: string; minutes: number }[];
  logs: { id: number; date: string; subject: string; topic: string; minutes: number; tests: number }[];
  streak_days: number;
}

export interface WeekItemInput {
  date: string;
  subject: string;
  topic?: string;
  minutes: number;
  tests: number;
  note?: string;
}

export interface WeekItem {
  id: number;
  date: string;
  subject: string;
  topic: string;
  minutes: number;
  tests: number;
  note: string;
  done: boolean;
  done_minutes: number;
  done_tests: number;
  done_at: string;
}

export interface WeekStats {
  items: number;
  done_items: number;
  due_items: number;
  due_done_items: number;
  rate: number | null;
  planned_minutes: number;
  done_minutes: number;
}

export interface Week {
  start: string;
  end: string;
  today: string;
  days: { date: string; items: WeekItem[] }[];
  stats: WeekStats;
}

export interface StudentCard {
  student_id: number;
  name: string;
  mobile: string;
  grade: string;
  field: string;
  city: string;
  plan_name: string;
  plan_start: string;
  plan_end: string;
  tasks_total: number;
  tasks_done: number;
  tasks_pending: number;
  study: StudyTotals;
  week: WeekStats | null;
}

export interface MentorStudentDetail {
  student: StudentCard;
  tasks: Task[];
  notes: Note[];
  study: StudyDetail;
}

export interface StudentOverview {
  ok?: boolean;
  student: { student_id: number; name: string; mobile: string; grade: string; field: string; city: string };
  mentor: { name: string; mobile: string; specialty: string } | null;
  plan: { name: string; start: string; end: string; status?: string; days_left: number | null; expired?: boolean; plan_id?: number; price?: number; paid?: number; due?: number } | null;
  payments?: { id: number; amount: number; ref: string; paid_at: string; status: PaymentStatus }[];
  tasks: Task[];
  notes: Note[];
  totals: StudyTotals;
  study: StudyDetail;
  can_log: boolean;
}
