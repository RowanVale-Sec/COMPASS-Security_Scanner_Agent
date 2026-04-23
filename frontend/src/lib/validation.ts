// Client-side mirror of the server-side URL validator. Server is authoritative
// — this exists only to give the user instant feedback and block obviously
// wrong inputs before they leave the browser.

const GITHUB_URL_RE =
  /^https:\/\/github\.com\/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,38}[A-Za-z0-9])?\/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99}[A-Za-z0-9])?(?:\.git)?\/?$/;

const GITHUB_PAT_RE = /^(?:ghp_|github_pat_)[A-Za-z0-9_]{10,240}$/;

const AZURE_ENDPOINT_RE =
  /^https:\/\/[A-Za-z0-9][A-Za-z0-9-]{0,62}\.openai\.azure\.com\/?$/;

const AZURE_KEY_RE = /^[A-Fa-f0-9]{32,64}$/;

const AZURE_DEPLOYMENT_RE = /^[A-Za-z0-9_-]{1,64}$/;

const CLAUDE_KEY_RE = /^sk-ant-[A-Za-z0-9_-]{20,300}$/;

export const CLAUDE_MODELS = [
  "claude-opus-4-7",
  "claude-sonnet-4-6",
  "claude-haiku-4-5",
  "claude-opus-4-6",
  "claude-sonnet-4-5",
] as const;

export type ClaudeModel = (typeof CLAUDE_MODELS)[number];

export function validateGithubUrl(v: string): string | null {
  const trimmed = v.trim();
  if (!trimmed) return "Required";
  if (trimmed.length > 250) return "Too long";
  if (!GITHUB_URL_RE.test(trimmed)) return "Must look like https://github.com/<owner>/<repo>";
  return null;
}

export function validateGithubPat(v: string): string | null {
  if (!v) return null; // optional
  if (!GITHUB_PAT_RE.test(v)) return "Must start with ghp_ or github_pat_";
  return null;
}

export function validateAzureKey(v: string): string | null {
  if (!AZURE_KEY_RE.test(v)) return "Expected 32–64 hex characters";
  return null;
}

export function validateAzureEndpoint(v: string): string | null {
  if (!AZURE_ENDPOINT_RE.test(v)) return "Expected https://<name>.openai.azure.com/";
  return null;
}

export function validateAzureDeployment(v: string): string | null {
  if (!AZURE_DEPLOYMENT_RE.test(v)) return "Invalid deployment name";
  return null;
}

export function validateClaudeKey(v: string): string | null {
  if (!CLAUDE_KEY_RE.test(v)) return "Expected key starting with sk-ant-";
  return null;
}
