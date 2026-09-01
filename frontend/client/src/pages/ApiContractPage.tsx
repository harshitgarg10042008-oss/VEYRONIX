/* API Contract — verify API schema compliance vs runtime behavior. */
import { useState } from "react";
import { Network, AlertTriangle, ShieldCheck, FileText } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type ContractViolation = {
  violation_id: string;
  endpoint: string;
  method: string;
  violation_type: string;
  schema_expectation: string;
  runtime_observation: string;
  severity: string;
  suggested_fix: string;
};

type ContractResult = {
  contract_id: string;
  spec_source: string;
  checked_at: string;
  total_endpoints: number;
  compliant_count: number;
  violation_count: number;
  critical_count: number;
  coverage_pct: number;
  violations: ContractViolation[];
  verdict: string;
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

export default function ApiContractPage() {
  const [specUrl, setSpecUrl] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [result, setResult] = useState<ContractResult | null>(null);
  const [running, setRunning] = useState(false);
  const [toast, setToast] = useState("");
  const [selected, setSelected] = useState<ContractViolation | null>(null);

  const run = async () => {
    if (!specUrl.trim()) return setToast("OpenAPI spec URL or path is required");
    setRunning(true);
    try {
      const res = await fetch(`${API_BASE}/api/api-contract/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ spec_url: specUrl, target_url: targetUrl }),
      });
      if (!res.ok) throw new Error(`Contract check returned ${res.status}`);
      const data = await res.json() as ContractResult;
      setResult(data);
      setSelected(data.violations[0] ?? null);
      setToast(`Contract check complete · ${data.violation_count} violations`);
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
            <SectionLabel>API CONTRACTS / SCHEMA VS RUNTIME</SectionLabel>
            <h1>Does the runtime match the spec?</h1>
            <p>Verify that a live API implementation conforms to its declared OpenAPI schema. Schema drift is a silent risk — fields added, removed, or changed without spec updates create undefined behavior.</p>
          </div>
          <div className="intro-action">
            <span className="queue-readout"><Network size={14} /> CONTRACT CHECK</span>
          </div>
        </div>

        <div className="website-scan-form">
          <div className="form-row">
            <label>OpenAPI Spec URL / Path</label>
            <input type="text" placeholder="http://localhost:8000/openapi.json" value={specUrl} onChange={e => setSpecUrl(e.target.value)} style={{ flex: 2 }} />
            <label>API Target URL (optional)</label>
            <input type="text" placeholder="http://localhost:8000" value={targetUrl} onChange={e => setTargetUrl(e.target.value)} />
            <button className="button button-primary" type="button" onClick={run} disabled={running}>
              <Network size={15} /> {running ? "Checking…" : "Check Contract"}
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
              <Metric label="VERDICT" value={result.verdict} note={result.spec_source} tone={result.violation_count > 0 ? "danger" : "verified"} />
              <Metric label="ENDPOINTS" value={result.total_endpoints.toString()} note={`${result.coverage_pct.toFixed(0)}% covered`} tone="neutral" />
              <Metric label="COMPLIANT" value={result.compliant_count.toString()} note="schema-conformant" tone="verified" />
              <Metric label="VIOLATIONS" value={result.violation_count.toString()} note={`${result.critical_count} critical`} tone={result.violation_count > 0 ? "danger" : "verified"} />
            </div>

            <div className="two-column">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <SectionLabel>VIOLATIONS / {result.contract_id}</SectionLabel>
                    <h2>Schema conformance failures</h2>
                  </div>
                  <span className="count-badge">{result.violations.length.toString().padStart(2, "0")}</span>
                </div>
                <div className="findings-table">
                  <div className="table-head"><span>ENDPOINT</span><span>METHOD</span><span>TYPE</span><span>SEVERITY</span></div>
                  {result.violations.length === 0
                    ? <div className="empty-state"><ShieldCheck size={22} /><strong>No violations</strong><span>All endpoints conform to the declared schema.</span></div>
                    : result.violations.map(v => (
                      <button
                        type="button"
                        key={v.violation_id}
                        className={`finding-row ${selected?.violation_id === v.violation_id ? "finding-selected" : ""}`}
                        onClick={() => setSelected(v)}
                      >
                        <span className="finding-main">
                          <span className={`finding-symbol symbol-${SEV_TONE[v.severity] ?? "neutral"}`}>!</span>
                          <span>
                            <strong>{v.endpoint}</strong>
                            <small>{v.violation_type.replace(/_/g, " ")}</small>
                          </span>
                        </span>
                        <span className="vendor-label">{v.method}</span>
                        <span className="vendor-label">{v.violation_type.replace(/_/g, " ")}</span>
                        <span className={`severity severity-${v.severity.toLowerCase()}`}>{v.severity}</span>
                      </button>
                    ))
                  }
                </div>
              </section>

              <aside className="evidence-panel">
                <div className="evidence-top">
                  <SectionLabel>SELECTED VIOLATION</SectionLabel>
                  <span className="proof-tag"><Network size={12} /> CONTRACT</span>
                </div>
                {selected ? (
                  <>
                    <div className="evidence-id">{selected.method} {selected.endpoint}</div>
                    <h2>{selected.violation_type.replace(/_/g, " ")}</h2>
                    <div className="evidence-block">
                      <SectionLabel>SCHEMA EXPECTATION</SectionLabel>
                      <div style={{ fontFamily: "monospace", fontSize: 12, background: "var(--surface)", padding: "8px 10px", borderRadius: 4, border: "1px solid var(--line)", wordBreak: "break-all" }}>
                        {selected.schema_expectation}
                      </div>
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>RUNTIME OBSERVATION</SectionLabel>
                      <div style={{ fontFamily: "monospace", fontSize: 12, background: "var(--surface)", padding: "8px 10px", borderRadius: 4, border: "1px solid var(--line)", wordBreak: "break-all", color: "var(--red)" }}>
                        {selected.runtime_observation}
                      </div>
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>SUGGESTED FIX</SectionLabel>
                      <p className="muted-copy">{selected.suggested_fix}</p>
                    </div>
                    <div className="evidence-footer">
                      <span>contract/{result.contract_id}</span>
                      <span>Schema drift requires human review</span>
                    </div>
                  </>
                ) : (
                  <div className="empty-state"><FileText size={22} /><strong>Select a violation</strong><span>Details will appear here</span></div>
                )}
              </aside>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
