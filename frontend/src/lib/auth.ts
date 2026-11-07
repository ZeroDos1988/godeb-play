import { api } from "@/lib/api.ts";

export type LoginResponse = {
  "2fa_required": boolean;
  enrollment_required: boolean;
};

export type Enrollment = {
  secret: string;
  otpauth_url: string;
  qr_code: string;
  backup_codes: string[];
};

export type SessionResponse = {
  ok: boolean;
  username: string;
};

function post<T>(path: string, body?: unknown): Promise<T> {
  return api<T>(path, {
    method: "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export const authApi = {
  me: () => api<{ username: string }>("/api/auth/me"),
  identify: (username: string) => post<{ ok: boolean }>("/api/auth/identify", { username }),
  login: (username: string, password: string) =>
    post<LoginResponse>("/api/auth/login", { username, password }),
  enroll: () => post<Enrollment>("/api/auth/2fa/enroll"),
  verify: (code: string) => post<SessionResponse>("/api/auth/2fa/verify", { code }),
  authenticate: (code: string) =>
    post<SessionResponse>("/api/auth/2fa/authenticate", { code }),
  logout: () => post<{ ok: boolean }>("/api/auth/logout"),
};
