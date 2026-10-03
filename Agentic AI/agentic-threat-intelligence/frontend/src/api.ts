import type { AuditEvent, BlocklistEntry, Investigation, SystemStatus } from "./types";

const BASE = "/api/v1";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options?.headers },
    ...options,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: "Request failed" }));
    const detail = body.detail;
    const message = Array.isArray(detail)
      ? detail.map((item) => item?.msg ?? JSON.stringify(item)).join("; ")
      : typeof detail === "string" ? detail : `Request failed (${response.status})`;
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}

export const api = {
  list: () => request<Investigation[]>("/investigations"),
  get: (id: string) => request<Investigation>(`/investigations/${id}`),
  create: (indicator: string, title = "", screenshotDataUrl: string | null = null, autoCapture = true) =>
    request<Investigation>("/investigations", {
      method: "POST",
      body: JSON.stringify({ indicator, title, screenshot_data_url: screenshotDataUrl, auto_capture: autoCapture }),
    }),
  decide: (id: string, decision: "approve" | "reject" | "override_monitor", comment = "") =>
    request<Investigation>(`/investigations/${id}/decision`, {
      method: "POST",
      body: JSON.stringify({ decision, comment }),
    }),
  audit: () => request<AuditEvent[]>("/audit"),
  blocklist: () => request<BlocklistEntry[]>("/blocklist"),
  removeBlock: (id: string) => request<BlocklistEntry>(`/blocklist/${id}`, { method: "DELETE" }),
  systemStatus: () => request<SystemStatus>("/system/status"),
};
