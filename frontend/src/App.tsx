import { useEffect, useRef, useState } from "react";
import {
  Credentials,
  downloadBundleUrl,
  ScanCreateResponse,
  submitScan,
} from "./api/client";
import { subscribeToEvents } from "./lib/sse";
import {
  CLAUDE_MODELS,
  ClaudeModel,
  validateAzureDeployment,
  validateAzureEndpoint,
  validateAzureKey,
  validateClaudeKey,
  validateGithubPat,
  validateGithubUrl,
} from "./lib/validation";

type Provider = "azure" | "claude";
type StageStatus = "pending" | "started" | "completed" | "failed";

const STAGES: { id: string; label: string }[] = [
  { id: "clone", label: "Clone repository" },
  { id: "scanner", label: "Security scan" },
  { id: "inventory", label: "Build inventory" },
  { id: "threat_model", label: "Threat model" },
  { id: "executive_summary", label: "Executive summary" },
];

function initialStages(): Record<string, StageStatus> {
  return Object.fromEntries(STAGES.map((s) => [s.id, "pending"])) as Record<string, StageStatus>;
}

export function App() {
  const [githubUrl, setGithubUrl] = useState("");
  const [githubPat, setGithubPat] = useState("");
  const [provider, setProvider] = useState<Provider>("claude");

  // Claude
  const [claudeKey, setClaudeKey] = useState("");
  const [claudeModel, setClaudeModel] = useState<ClaudeModel>("claude-sonnet-4-6");

  // Azure
  const [azureKey, setAzureKey] = useState("");
  const [azureEndpoint, setAzureEndpoint] = useState("");
  const [azureDeployment, setAzureDeployment] = useState("");

  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [job, setJob] = useState<ScanCreateResponse | null>(null);
  const [stages, setStages] = useState<Record<string, StageStatus>>(initialStages());
  const [pipelineError, setPipelineError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const abortRef = useRef<AbortController | null>(null);

  // Any previous run: cancel its SSE subscription when unmounting or restarting.
  useEffect(
    () => () => {
      abortRef.current?.abort();
    },
    [],
  );

  const urlError = githubUrl ? validateGithubUrl(githubUrl) : null;
  const patError = validateGithubPat(githubPat);
  const providerError =
    provider === "azure"
      ? validateAzureKey(azureKey) || validateAzureEndpoint(azureEndpoint) || validateAzureDeployment(azureDeployment)
      : validateClaudeKey(claudeKey);
  const formValid = !!githubUrl && !urlError && !patError && !providerError && !submitting;

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitError(null);
    setPipelineError(null);
    setDone(false);
    setStages(initialStages());

    const credentials: Credentials =
      provider === "claude"
        ? { provider: "claude", api_key: claudeKey, model: claudeModel }
        : {
            provider: "azure",
            api_key: azureKey,
            endpoint: azureEndpoint,
            deployment: azureDeployment,
          };

    setSubmitting(true);
    try {
      const resp = await submitScan({
        github_url: githubUrl.trim(),
        github_pat: githubPat || undefined,
        provider,
        credentials,
      });
      setJob(resp);

      // Clear tokens from state as soon as the request is on the wire. The
      // gateway has them; the browser process doesn't need them anymore.
      setGithubPat("");
      setClaudeKey("");
      setAzureKey("");

      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;

      for await (const evt of subscribeToEvents(resp.events_url, ac.signal)) {
        if (evt.event === "stage") {
          const data = evt.data as { stage: string; status: string };
          setStages((prev) => ({ ...prev, [data.stage]: data.status as StageStatus }));
        } else if (evt.event === "complete") {
          setDone(true);
          return;
        } else if (evt.event === "error") {
          const data = evt.data as { message: string };
          setPipelineError(data.message);
          return;
        }
      }
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  }

  function onReset() {
    abortRef.current?.abort();
    setJob(null);
    setStages(initialStages());
    setPipelineError(null);
    setDone(false);
  }

  return (
    <main className="container">
      <header>
        <h1>COMPASS</h1>
        <p className="tagline">GitHub repo → security scan → threat model</p>
      </header>

      {!job ? (
        <form onSubmit={onSubmit} autoComplete="off" spellCheck={false}>
          <fieldset disabled={submitting}>
            <label>
              GitHub repository URL
              <input
                type="url"
                name="github_url"
                inputMode="url"
                autoComplete="off"
                placeholder="https://github.com/<owner>/<repo>"
                value={githubUrl}
                onChange={(e) => setGithubUrl(e.target.value)}
                required
              />
              {urlError && <span className="field-error">{urlError}</span>}
            </label>

            <label>
              GitHub personal access token <span className="muted">(optional — needed for private repos)</span>
              <input
                type="password"
                name="github_pat"
                autoComplete="off"
                spellCheck={false}
                placeholder="ghp_… or github_pat_…"
                value={githubPat}
                onChange={(e) => setGithubPat(e.target.value)}
              />
              {patError && <span className="field-error">{patError}</span>}
            </label>

            <fieldset className="provider-fieldset">
              <legend>LLM provider</legend>
              <label className="radio">
                <input
                  type="radio"
                  name="provider"
                  value="claude"
                  checked={provider === "claude"}
                  onChange={() => setProvider("claude")}
                />
                Anthropic Claude
              </label>
              <label className="radio">
                <input
                  type="radio"
                  name="provider"
                  value="azure"
                  checked={provider === "azure"}
                  onChange={() => setProvider("azure")}
                />
                Azure OpenAI
              </label>
            </fieldset>

            {provider === "claude" ? (
              <>
                <label>
                  Claude API key
                  <input
                    type="password"
                    name="claude_key"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="sk-ant-…"
                    value={claudeKey}
                    onChange={(e) => setClaudeKey(e.target.value)}
                    required
                  />
                </label>
                <label>
                  Model
                  <select value={claudeModel} onChange={(e) => setClaudeModel(e.target.value as ClaudeModel)}>
                    {CLAUDE_MODELS.map((m) => (
                      <option key={m} value={m}>
                        {m}
                      </option>
                    ))}
                  </select>
                </label>
              </>
            ) : (
              <>
                <label>
                  Azure endpoint
                  <input
                    type="url"
                    name="azure_endpoint"
                    autoComplete="off"
                    placeholder="https://<name>.openai.azure.com/"
                    value={azureEndpoint}
                    onChange={(e) => setAzureEndpoint(e.target.value)}
                    required
                  />
                </label>
                <label>
                  Deployment name
                  <input
                    type="text"
                    name="azure_deployment"
                    autoComplete="off"
                    placeholder="gpt-4o"
                    value={azureDeployment}
                    onChange={(e) => setAzureDeployment(e.target.value)}
                    required
                  />
                </label>
                <label>
                  Azure API key
                  <input
                    type="password"
                    name="azure_key"
                    autoComplete="off"
                    spellCheck={false}
                    value={azureKey}
                    onChange={(e) => setAzureKey(e.target.value)}
                    required
                  />
                </label>
              </>
            )}

            {providerError && <span className="field-error">{providerError}</span>}
            {submitError && <span className="field-error">{submitError}</span>}

            <button type="submit" disabled={!formValid}>
              {submitting ? "Starting…" : "Run security scan"}
            </button>
          </fieldset>
        </form>
      ) : (
        <section className="progress">
          <h2>Scan in progress</h2>
          <ol className="stages">
            {STAGES.map((stage) => {
              const status = stages[stage.id];
              return (
                <li key={stage.id} className={`stage stage-${status}`}>
                  <span className="stage-indicator" aria-hidden="true" />
                  <span className="stage-label">{stage.label}</span>
                  <span className="stage-status">{status}</span>
                </li>
              );
            })}
          </ol>

          {pipelineError && <p className="error">❌ {pipelineError}</p>}

          {done && (
            <div className="download-area">
              <p>✅ Threat model ready.</p>
              <a
                className="download-button"
                href={downloadBundleUrl(job.job_id)}
                download={`compass-threat-model-${job.job_id}.json`}
              >
                Download JSON bundle
              </a>
            </div>
          )}

          <button type="button" className="secondary" onClick={onReset}>
            Start another scan
          </button>
        </section>
      )}

      <footer>
        <small>
          Tokens are sent directly to the backend with your scan and are never
          stored or written to disk. Refresh the page to clear all token fields.
        </small>
      </footer>
    </main>
  );
}
