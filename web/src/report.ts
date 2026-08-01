import { useEffect, useState } from "react";
import type { ReportV1 } from "./types";
import { parseReport } from "./validate";

type ReportState =
  | { state: "loading" }
  | { state: "ready"; report: ReportV1 }
  | { state: "error"; error: Error };

export function useReport(): ReportState {
  const [result, setResult] = useState<ReportState>({ state: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    const url = `${import.meta.env.BASE_URL}data/report.json`;
    fetch(url, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`Unable to load ${url} (HTTP ${response.status})`);
        }
        return response.json() as Promise<unknown>;
      })
      .then((value) => setResult({ state: "ready", report: parseReport(value) }))
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setResult({
          state: "error",
          error: error instanceof Error ? error : new Error(String(error)),
        });
      });
    return () => controller.abort();
  }, []);

  return result;
}

