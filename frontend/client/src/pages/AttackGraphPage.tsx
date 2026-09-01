/* Attack Graph — exploit path simulation across control failures. */
import { useState } from "react";
import { Network, AlertTriangle, ShieldCheck, FileText } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type AttackPath = {
  path_id: string;
  steps: string[];
  entry_point: string;
  target: string;
  severity: string;
  feasibility: string;
  exploited_controls: string[];
  mitigation: string;
};

type AttackGraphResult = {
  graph_id: string;
  total_paths: number;
  critical_paths: number;
  entry_points: string[];
  high_value_targets: string[];
  paths: AttackPath[];
  limitations: string[];
};

const SEV_TONE: Record<string, string> = {
  CRITICAL: "danger",
  HIGH: "danger",
  MEDIUM: "warn",
  LOW: "neutral",
};

function SectionLabel({ children }: { children: React.ReactNode }) {
  return <div className="section-label">{children}</div>;
}

function Metric({ label, value, note, tone = "neutral" }: { label: string; value: string; note: string; tone?: string }) {
  return (
    <div className={`metric metric-${tone}`}>
      <SectionLabel>{label}</SectionLabel>
      <strong>{value}</strong>
      <span>{note}</span>
    </div>
  );
}

export default function AttackGraphPage() {
  const [failedControls, setFailedControls] = useState("NET-001, NET-003");
  const [assets, setAssets] = useState("firewall-01, switch-core, db-primary");
  const [result, setResult] = useState<AttackGraphResult | null>(null);
  const [running, setRunning] = useState(false);
  const [toast, setToast] = useState("");
  const [selected, setSelected] = useState<AttackPath | null>(null);

  const run = async () => {
    if (!failedControls.trim()) return setToast("At least one failed control is required");
    setRunning(true);
    try {
      const res = await fetch(`${API_BASE}/api/attack-graph/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          failed_controls: failedControls.split(",").map(s => s.trim()).filter(Boolean),
          assets: assets.split(",").map(s => s.trim()).filter(Boolean),
        }),
      });
      if (!res.ok) throw new Error(`Graph returned ${res.status}`);
      const data = await res.json() as AttackGraphResult;
      setResult(data);
      setSelected(data.paths[0] ?? null);
      setToast(`Graph generated · ${data.total_paths} paths · ${data.critical_paths} critical`);
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "start the local API"}`);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="content-scroll">
      <div className="content-inner">
        <div className="page-intro">
          <div>
            <SectionLabel>ATTACK GRAPH / EXPLOIT PATH SIMULATION</SectionLabel>
            <h1>Follow the failure path.</h1>
            <p>Given a set of failed controls, enumerate plausible exploit paths an adversary could traverse. Results are hypothetical predictions — not confirmed attacks — and require human review before any remediation decision.</p>
          </div>
          <div className="intro-action">
            <span className="queue-readout"><Network size={14} /> SIMULATION</span>
          </div>
        </div>

        <div className="queue-banner" style={{ marginBottom: 24 }}>
          <div className="queue-icon"><AlertTriangle size={22} /></div>
          <div>
            <strong>Hypothetical — not confirmed attacks.</strong>
            <span>Attack paths are theoretical explorations based on control failures. They do not represent confirmed vulnerabilities and require human review before any action is taken.</span>
          </div>
          <span className="proof-tag">REVIEW ONLY</span>
        </div>

        <div className="website-scan-form">
          <div className="form-row">
            <label>Failed Controls (comma-separated)</label>
            <input type="text" value={failedControls} onChange={e => setFailedControls(e.target.value)} style={{ flex: 2 }} />
            <label>Assets in Scope</label>
            <input type="text" value={assets} onChange={e => setAssets(e.target.value)} style={{ flex: 2 }} />
            <button className="button button-primary" type="button" onClick={run} disabled={running}>
              <Network size={15} /> {running ? "Generating…" : "Generate Graph"}
            </button>
          </div>
        </div>

        {toast && (
          <div className="queue-banner" style={{ marginBottom: 16 }}>
            <div className="queue-icon"><AlertTriangle size={18} /></div>
            <span>{toast}</span>
          </div>
        )}

        {result && (
          <>
            <div className="scan-summary">
              <Metric label="TOTAL PATHS" value={result.total_paths.toString()} note="plausible exploit paths" tone={result.total_paths > 0 ? "warn" : "verified"} />
              <Metric label="CRITICAL PATHS" value={result.critical_paths.toString()} note="high-priority paths" tone={result.critical_paths > 0 ? "danger" : "verified"} />
              <Metric label="ENTRY POINTS" value={result.entry_points.length.toString()} note="identified entry surfaces" tone="neutral" />
              <Metric label="HIGH-VALUE TARGETS" value={result.high_value_targets.length.toString()} note="assets at risk" tone={result.high_value_targets.length > 0 ? "warn" : "verified"} />
            </div>

            <div className="two-column">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <SectionLabel>ATTACK PATHS / {result.graph_id}</SectionLabel>
                    <h2>Predicted exploit trajectories</h2>
                  </div>
                  <span className="count-badge">{result.paths.length.toString().padStart(2, "0")}</span>
                </div>
                <div className="findings-table">
                  <div className="table-head"><span>PATH / ENTRY</span><span>TARGET</span><span>SEVERITY</span><span>FEASIBILITY</span></div>
                  {result.paths.length === 0
                    ? <div className="empty-state"><ShieldCheck size={22} /><strong>No paths found</strong><span>No plausible attack paths for the given failures.</span></div>
                    : result.paths.map(p => (
                      <button
                        type="button"
                        key={p.path_id}
                        className={`finding-row ${selected?.path_id === p.path_id ? "finding-selected" : ""}`}
                        onClick={() => setSelected(p)}
                      >
                        <span className="finding-main">
                          <span className={`finding-symbol symbol-${SEV_TONE[p.severity] ?? "neutral"}`}>
                            {p.severity === "CRITICAL" || p.severity === "HIGH" ? "!" : "~"}
                          </span>
                          <span>
                            <strong>{p.entry_point}</strong>
                            <small>{p.steps.length} steps · {p.exploited_controls.join(", ")}</small>
                          </span>
                        </span>
                        <span className="vendor-label">{p.target}</span>
                        <span className={`severity severity-${p.severity.toLowerCase()}`}>{p.severity}</span>
                        <span className="vendor-label">{p.feasibility}</span>
                      </button>
                    ))
                  }
                </div>
              </section>

              <aside className="evidence-panel">
                <div className="evidence-top">
                  <SectionLabel>SELECTED PATH</SectionLabel>
                  <span className="proof-tag"><Network size={12} /> HYPOTHETICAL</span>
                </div>
                {selected ? (
                  <>
                    <div className="evidence-id">{selected.path_id} · {selected.severity}</div>
                    <h2>{selected.entry_point} → {selected.target}</h2>
                    <div className="evidence-block">
                      <SectionLabel>ATTACK STEPS</SectionLabel>
                      {selected.steps.map((step, i) => (
                        <div key={i} className="evidence-line">
                          <code>{String(i + 1).padStart(2, "0")}</code><span>{step}</span>
                        </div>
                      ))}
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>EXPLOITED CONTROLS</SectionLabel>
                      {selected.exploited_controls.map(c => (
                        <div key={c} className="evidence-line"><code>CTL</code><span>{c}</span></div>
                      ))}
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>MITIGATION PREVIEW</SectionLabel>
                      <p className="muted-copy">{selected.mitigation}</p>
                    </div>
                    <div className="evidence-footer">
                      <span>graph/{result.graph_id}</span>
                      <span>Feasibility: {selected.feasibility}</span>
                    </div>
                  </>
                ) : (
                  <div className="empty-state"><FileText size={22} /><strong>Select a path</strong><span>Attack path details will appear here</span></div>
                )}
              </aside>
            </div>

            {result.limitations.length > 0 && (
              <div className="queue-banner" style={{ marginTop: 24 }}>
                <div className="queue-icon"><FileText size={18} /></div>
                <div><strong>Graph limitations</strong><span>{result.limitations.join(" · ")}</span></div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
