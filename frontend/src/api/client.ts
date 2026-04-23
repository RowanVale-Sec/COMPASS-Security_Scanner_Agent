// Thin API client. Tokens are passed through untouched and never stored.
// The consumer is expected to discard the credentials object as soon as the
// scan is submitted so they can be garbage-collected.

export interface AzureCredentials {
  provider: "azure";
  api_key: string;
  endpoint: string;
  deployment: string;
  api_version?: string;
  embedding_deployment?: string;
}

export interface ClaudeCredentials {
  provider: "claude";
  api_key: string;
  model?: string;
  max_tokens?: number;
}

export type Credentials = AzureCredentials | ClaudeCredentials;

export interface ScanSubmission {
  github_url: string;
  github_pat?: string;
  provider: "azure" | "claude";
  credentials: Credentials;
}

export interface ScanCreateResponse {
  job_id: string;
  events_url: string;
  download_url: string;
}

export async function submitScan(body: ScanSubmission): Promise<ScanCreateResponse> {
  const response = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const text = await response.text();
    let detail = text;
    try {
      detail = JSON.parse(text).error ?? detail;
    } catch {
      /* ignore */
    }
    throw new Error(`Scan rejected (HTTP ${response.status}): ${detail}`);
  }
  return response.json();
}

export function downloadBundleUrl(jobId: string): string {
  return `/api/download/${encodeURIComponent(jobId)}`;
}
