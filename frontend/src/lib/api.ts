export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export const STEP_UP_HEADER = "X-GoDeb-TOTP";
export const PASSWORD_HEADER = "X-GoDeb-Password";

export type StepUpCredentials = {
  code: string;
  password?: string;
};

export type StepUpRequest = {
  critical: boolean;
  passwordRequired: boolean;
  error?: string;
  remaining?: number;
};

type StepUpBody = {
  error?: string;
  step_up_required?: boolean;
  critical?: boolean;
  password_required?: boolean;
  remaining?: number;
};

// StepUpPrompt asks the user for a TOTP (and for critical actions the
// account password); null means cancelled.
export type StepUpPrompt = (request: StepUpRequest) => Promise<StepUpCredentials | null>;

let stepUpPrompt: StepUpPrompt | null = null;
let pendingPrompt: Promise<StepUpCredentials | null> | null = null;

// setStepUpPrompt installs the dialog that confirms admin actions and returns
// a function that removes it again.
export function setStepUpPrompt(prompt: StepUpPrompt): () => void {
  stepUpPrompt = prompt;
  return () => {
    if (stepUpPrompt === prompt) {
      stepUpPrompt = null;
    }
  };
}

function ask(request: StepUpRequest): Promise<StepUpCredentials | null> {
  if (!stepUpPrompt) {
    return Promise.resolve(null);
  }
  // Concurrent requests share one dialog.
  pendingPrompt ??= stepUpPrompt(request).finally(() => {
    pendingPrompt = null;
  });
  return pendingPrompt;
}

// send performs the request and, when the daemon asks for a second factor,
// prompts for a code (and password when critical) and repeats the request
// until it is accepted, the user cancels or the session ends.
async function send(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  let response = await fetch(path, { ...init, headers });
  let retried = false;
  while (response.status === 403) {
    let body: StepUpBody;
    try {
      body = (await response.clone().json()) as StepUpBody;
    } catch {
      return response;
    }
    if (!body.step_up_required) {
      return response;
    }
    const critical = Boolean(body.critical);
    const credentials = await ask({
      critical,
      passwordRequired: critical || Boolean(body.password_required),
      error: retried ? body.error : undefined,
      remaining: body.remaining,
    });
    if (credentials === null) {
      return response;
    }
    headers.set(STEP_UP_HEADER, credentials.code);
    if (credentials.password) {
      headers.set(PASSWORD_HEADER, credentials.password);
    } else {
      headers.delete(PASSWORD_HEADER);
    }
    response = await fetch(path, { ...init, headers });
    retried = true;
  }
  return response;
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  if (init?.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await send(path, { ...init, headers });
  await ensureOk(response);
  return (await response.json()) as T;
}

export async function apiBlob(path: string): Promise<Blob> {
  const response = await send(path);
  await ensureOk(response);
  return response.blob();
}

export const UNAUTHORIZED_EVENT = "godeb:unauthorized";

async function ensureOk(response: Response): Promise<void> {
  if (!response.ok) {
    if (response.status === 401 && !new URL(response.url).pathname.startsWith("/api/auth/")) {
      window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
    }
    let message = `Anfrage fehlgeschlagen (${response.status})`;
    try {
      const body = (await response.json()) as { error?: string };
      if (body.error) {
        message = body.error;
      }
    } catch {
      // The daemon answered without a JSON body.
    }
    throw new ApiError(response.status, message);
  }
}
