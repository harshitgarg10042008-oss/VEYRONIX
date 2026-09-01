/* Counterfactual — test hypothetical rule changes against existing evidence. */
import { useState } from "react";
import { Play, AlertTriangle, FileText, ShieldCheck } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type CounterfactualFinding = {
  control_id: string;
  original_status: string;
  hypothetical_status: string;
  status_changed: boolean;
  original_severity: string;
  hypothetical_severity: string;
  delta_description: string;
};

type CounterfactualResult = {
  scenario_id: string;
  hypothesis: string;
  evaluated_at: string;
  total_controls: number;
  changed_count: number;
  improved_count: number;
  degraded_count: number;
  original_score: number;
  hypothetical_score: number;
  score_delta: number;
  findings: CounterfactualFinding[];
  verdict: string;
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

export default function CounterfactualPage() {
  const [auditId, setAuditId] = useState("");
  const [hypothesis, setHypothesis] = useState("");
  const [modifiedControls, setModifiedControls] = useState("");
  const [result, setResult] = useState<CounterfactualResult | null>(null);
  const [running, setRunning] = useState(false);
  const [toast, setToast] = useState("");
  const [selected, setSelected] = useState<CounterfactualFinding | null>(null);

  const run = async () => {
    if (!auditId.trim() || !hypothesis.trim()) return setToast("Audit ID and hypothesis required");
    setRunning(true);
    try {
      const res = await fetch(`${API_BASE}/api/counterfactual/evaluate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          audit_id: auditId,
          hypothesis,
          modified_controls: modifiedControls.split(",").map(s => s.trim()).filter(Boolean),
        }),
      });
      if (!res.ok) throw new Error(`Evaluation returned ${res.status}`);
      const data = await res.json() as CounterfactualResult;
      setResult(data);
      setSelected(data.findings.find(f => f.status_changed) ?? data.findings[0] ?? null);
      setToast(`Counterfactual complete · ${data.changed_count} controls changed`);
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
            <SectionLabel>COUNTERFACTUALS / HYPOTHETICAL RULE TESTING</SectionLabel>
            <h1>What if the rule were different?</h1>
            <p>Test a hypothesis against an existing audit's evidence without rerunning the audit. Understand how a policy change would have changed verdicts — before proposing it to the rule committee.</p>
          </div>
          <div className="intro-action">
            <span className="queue-readout"><Play size={14} /> HYPOTHETICAL</span>
          </div>
        </div>

        <div className="website-scan-form">
          <div className="form-row">
            <label>Audit ID</label>
            <input type="text" placeholder="Existing audit ID" value={auditId} onChange={e => setAuditId(e.target.value)} />
            <label>Modified Controls (comma-separated, leave blank for all)</label>
            <input type="text" placeholder="NET-001, NET-003" value={modifiedControls} onChange={e => setModifiedControls(e.target.value)} />
          </div>
          <div className="form-row">
            <label>Hypothesis</label>
            <input
              type="text"
              placeholder="If telnet were allowed on management-only VLANs, would NET-001 still fail?"
              value={hypothesis}
              onChange={e => setHypothesis(e.target.value)}
              style={{ flex: 3 }}
            />
            <button className="button button-primary" type="button" onClick={run} disabled={running}>
              <Play size={15} /> {running ? "Evaluating…" : "Test Hypothesis"}
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
              <Metric
                label="SCORE DELTA"
                value={result.score_delta >= 0 ? `+${result.score_delta.toFixed(1)}` : result.score_delta.toFixed(1)}
                note={`${result.original_score.toFixed(0)} → ${result.hypothetical_score.toFixed(0)}`}
                tone={result.score_delta >= 0 ? "verified" : "danger"}
              />
              <Metric label="CONTROLS CHANGED" value={result.changed_count.toString()} note="verdict changed under hypothesis" tone={result.changed_count > 0 ? "warn" : "verified"} />
              <Metric label="IMPROVED" value={result.improved_count.toString()} note="FAIL → PASS under hypothesis" tone="verified" />
              <Metric label="DEGRADED" value={result.degraded_count.toString()} note="PASS → FAIL under hypothesis" tone="danger" />
            </div>

            <div className="two-column">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <SectionLabel>HYPOTHETICAL FINDINGS / {result.scenario_id}</SectionLabel>
                    <h2>{result.verdict}</h2>
                  </div>
                  <span className="count-badge">{result.findings.length.toString().padStart(2, "0")}</span>
                </div>
                <div className="findings-table">
                  <div className="table-head"><span>CONTROL</span><span>ORIGINAL</span><span>HYPOTHETICAL</span><span>CHANGED?</span></div>
                  {result.findings.map(f => (
                    <button
                      type="button"
                      key={f.control_id}
                      className={`finding-row ${selected?.control_id === f.control_id ? "finding-selected" : ""}`}
                      onClick={() => setSelected(f)}
                    >
                      <span className="finding-main">
                        <span className={`finding-symbol symbol-${f.status_changed ? (f.degraded_count > 0 ? "fail" : "pass") : "unknown"}`}>
                          {f.status_changed ? "↔" : "="}
                        </span>
                        <span>
                          <strong>{f.control_id}</strong>
                          <small>{f.delta_description}</small>
                        </span>
                      </span>
                      <span className={`status-pill status-${f.original_status === "FAIL" ? "fail" : "pass"}`}><span className="status-dot" />{f.original_status}</span>
                      <span className={`status-pill status-${f.hypothetical_status === "FAIL" ? "fail" : "pass"}`}><span className="status-dot" />{f.hypothetical_status}</span>
                      <span className={`status-pill ${f.status_changed ? "status-warn" : "status-pass"}`}><span className="status-dot" />{f.status_changed ? "CHANGED" : "SAME"}</span>
                    </button>
                  ))}
                </div>
              </section>

              <aside className="evidence-panel">
                <div className="evidence-top">
                  <SectionLabel>SELECTED FINDING</SectionLabel>
                  <span className="proof-tag"><ShieldCheck size={12} /> HYPOTHETICAL</span>
                </div>
                {selected ? (
                  <>
                    <div className="evidence-id">{selected.control_id}</div>
                    <h2>{selected.delta_description || (selected.status_changed ? "Verdict changed under hypothesis" : "No change under hypothesis")}</h2>
                    <div className="evidence-block">
                      <SectionLabel>VERDICT COMPARISON</SectionLabel>
                      <div className="evidence-state">
                        <span className={`status-pill status-${selected.original_status === "FAIL" ? "fail" : "pass"}`}><span className="status-dot" />Original: {selected.original_status}</span>
                        <span className={`status-pill status-${selected.hypothetical_status === "FAIL" ? "fail" : "pass"}`}><span className="status-dot" />Hypothetical: {selected.hypothetical_status}</span>
                      </div>
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>HYPOTHESIS</SectionLabel>
                      <p className="muted-copy" style={{ fontStyle: "italic" }}>"{result.hypothesis}"</p>
                    </div>
                    <div className="evidence-footer">
                      <span>scenario/{result.scenario_id}</span>
                      <span>Not a rule change — evaluation only</span>
                    </div>
                  </>
                ) : (
                  <div className="empty-state"><FileText size={22} /><strong>Select a finding</strong><span>Details will appear here</span></div>
                )}
              </aside>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
