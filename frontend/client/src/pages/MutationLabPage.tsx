/* Mutation Lab — rule robustness testing via config mutations. */
import { useState } from "react";
import { Zap, AlertTriangle, ShieldCheck, FileText } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type MutationOutcome = {
  mutation_id: string;
  mutation_type: string;
  mutation_description: string;
  original_status: string;
  mutated_status: string;
  status_changed: boolean;
  control_id: string;
  confidence_delta: number;
  mutation_line: number;
};

type MutationLabResult = {
  lab_id: string;
  control_id: string;
  total_mutations: number;
  status_change_count: number;
  no_change_count: number;
  robustness_score: number;
  outcomes: MutationOutcome[];
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

export default function MutationLabPage() {
  const [configText, setConfigText] = useState("version 17.9\nhostname Router1\nline vty 0 4\n transport input telnet\nlogging host 10.0.0.20\n");
  const [controlId, setControlId] = useState("NET-001");
  const [vendor, setVendor] = useState("cisco_ios");
  const [result, setResult] = useState<MutationLabResult | null>(null);
  const [running, setRunning] = useState(false);
  const [toast, setToast] = useState("");
  const [selected, setSelected] = useState<MutationOutcome | null>(null);

  const run = async () => {
    if (!configText.trim() || !controlId.trim()) return setToast("Config text and control ID are required");
    setRunning(true);
    try {
      const res = await fetch(`${API_BASE}/api/mutation-lab/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ config_text: configText, control_id: controlId, vendor }),
      });
      if (!res.ok) throw new Error(`Lab returned ${res.status}`);
      const data = await res.json() as MutationLabResult;
      setResult(data);
      setSelected(data.outcomes[0] ?? null);
      setToast(`Lab complete · Robustness ${(data.robustness_score * 100).toFixed(0)}%`);
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
            <SectionLabel>MUTATION LAB / RULE ROBUSTNESS</SectionLabel>
            <h1>Does the rule hold under variation?</h1>
            <p>Systematically mutate a configuration and measure how a control responds. A robust rule should detect true failures even under minor syntactic variation. Weak rules are surfaced here before they reach production.</p>
          </div>
          <div className="intro-action">
            <span className="queue-readout"><Zap size={14} /> ROBUSTNESS TEST</span>
          </div>
        </div>

        <div className="website-scan-form">
          <div className="form-row">
            <label>Control ID</label>
            <input type="text" value={controlId} onChange={e => setControlId(e.target.value)} placeholder="NET-001" />
            <label>Vendor</label>
            <select value={vendor} onChange={e => setVendor(e.target.value)}>
              <option value="cisco_ios">Cisco IOS</option>
              <option value="cisco_nxos">Cisco NX-OS</option>
              <option value="juniper">Juniper</option>
              <option value="paloalto">Palo Alto</option>
            </select>
            <button className="button button-primary" type="button" onClick={run} disabled={running}>
              <Zap size={15} /> {running ? "Running…" : "Run Mutation Lab"}
            </button>
          </div>
          <div className="form-row" style={{ flexDirection: "column", alignItems: "stretch" }}>
            <label>Configuration Text</label>
            <textarea
              rows={6}
              value={configText}
              onChange={e => setConfigText(e.target.value)}
              style={{ fontFamily: "monospace", fontSize: 12, padding: 10, border: "1px solid var(--line)", background: "var(--surface)", color: "var(--ink)", resize: "vertical", borderRadius: 4 }}
            />
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
                label="ROBUSTNESS SCORE"
                value={`${(result.robustness_score * 100).toFixed(0)}%`}
                note={result.verdict}
                tone={result.robustness_score >= 0.8 ? "verified" : result.robustness_score >= 0.5 ? "warn" : "danger"}
              />
              <Metric label="TOTAL MUTATIONS" value={result.total_mutations.toString()} note="variants tested" tone="neutral" />
              <Metric label="STATUS CHANGES" value={result.status_change_count.toString()} note="mutations that changed verdict" tone={result.status_change_count > 0 ? "danger" : "verified"} />
              <Metric label="STABLE" value={result.no_change_count.toString()} note="mutations with no verdict change" tone="neutral" />
            </div>

            <div className="two-column">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <SectionLabel>MUTATION OUTCOMES / {result.lab_id}</SectionLabel>
                    <h2>Variant-by-variant results</h2>
                  </div>
                  <span className="count-badge">{result.outcomes.length.toString().padStart(2, "0")}</span>
                </div>
                <div className="findings-table">
                  <div className="table-head"><span>MUTATION</span><span>ORIGINAL</span><span>MUTATED</span><span>CHANGED?</span></div>
                  {result.outcomes.map(o => (
                    <button
                      type="button"
                      key={o.mutation_id}
                      className={`finding-row ${selected?.mutation_id === o.mutation_id ? "finding-selected" : ""}`}
                      onClick={() => setSelected(o)}
                    >
                      <span className="finding-main">
                        <span className={`finding-symbol symbol-${o.status_changed ? "fail" : "pass"}`}>
                          {o.status_changed ? "!" : "✓"}
                        </span>
                        <span>
                          <strong>{o.mutation_type.replace(/_/g, " ")}</strong>
                          <small>{o.mutation_description}</small>
                        </span>
                      </span>
                      <span className="vendor-label">{o.original_status}</span>
                      <span className={`status-pill status-${o.mutated_status === "FAIL" ? "fail" : "pass"}`}>
                        <span className="status-dot" />{o.mutated_status}
                      </span>
                      <span className={`status-pill ${o.status_changed ? "status-fail" : "status-pass"}`}>
                        <span className="status-dot" />{o.status_changed ? "CHANGED" : "STABLE"}
                      </span>
                    </button>
                  ))}
                </div>
              </section>

              <aside className="evidence-panel">
                <div className="evidence-top">
                  <SectionLabel>SELECTED MUTATION</SectionLabel>
                  <span className="proof-tag"><ShieldCheck size={12} /> ROBUSTNESS</span>
                </div>
                {selected ? (
                  <>
                    <div className="evidence-id">{selected.control_id} · {selected.mutation_type.replace(/_/g, " ").toUpperCase()}</div>
                    <h2>{selected.mutation_description}</h2>
                    <div className="evidence-block">
                      <SectionLabel>VERDICT COMPARISON</SectionLabel>
                      <div className="evidence-state">
                        <span className="status-pill status-pass"><span className="status-dot" />Before: {selected.original_status}</span>
                        <span className="status-pill status-fail"><span className="status-dot" />After: {selected.mutated_status}</span>
                      </div>
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>MUTATION DETAILS</SectionLabel>
                      <div className="evidence-line"><code>LINE</code><span>Mutation at line {selected.mutation_line}</span></div>
                      <div className="evidence-line"><code>ΔCONF</code><span>Confidence delta: {(selected.confidence_delta * 100).toFixed(1)}%</span></div>
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>INTERPRETATION</SectionLabel>
                      <p className="muted-copy">
                        {selected.status_changed
                          ? "This mutation changed the verdict. The rule may be fragile to this class of syntactic variation — review the control definition."
                          : "This mutation did not change the verdict. The rule is stable against this variation class."
                        }
                      </p>
                    </div>
                    <div className="evidence-footer">
                      <span>lab/{result.lab_id}</span>
                      <span>Robustness testing, not production audit</span>
                    </div>
                  </>
                ) : (
                  <div className="empty-state"><FileText size={22} /><strong>Select a mutation</strong><span>Details will appear here</span></div>
                )}
              </aside>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
