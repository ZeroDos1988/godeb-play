import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api.ts";

type AsyncState<T> = {
  data: T | null;
  error: string;
  loading: boolean;
  reload: () => void;
};

export function useAsync<T>(load: () => Promise<T>): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);

  const reload = useCallback(() => {
    setNonce((current) => current + 1);
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    load()
      .then((value) => {
        if (!cancelled) {
          setData(value);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Unbekannter Fehler");
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [load, nonce]);

  return { data, error, loading, reload };
}

export function useGet<T>(path: string): AsyncState<T> {
  const load = useCallback(() => api<T>(path), [path]);
  return useAsync(load);
}
