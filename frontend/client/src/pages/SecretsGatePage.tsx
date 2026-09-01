/* Secrets Gate — verify redaction quality of evidence excerpts. */
import { useState } from "react";
import { ShieldCheck, AlertTriangle, LockKeyhole, FileText } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type RedactionViolation = {
  violation_id: string;
  line_number: number;
  pattern_matched: string;
  risk_level: string;
  excerpt_redacted: string;
  category: string;
};

type SecretsGateResult = {
  gate_id: string;
  assessed_at: string;
  total_lines: number;
  redacted_lines: number;
  violation_count: number;
  high_risk_count: number;
  gate_status: "PASS" | "FAIL" | "WARN";
  violations: RedactionViolation[];
  limitations: string;
};

const RISK_TONE: Record<string, string> = {
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

export default function SecretsGatePage() {
  const [configText, setConfigText] = useState("version 17.9\nhostname Router1\nenable secret 5 $1$mERr$123abc\nusername admin password cisco123\nsnmp-server community public RO\n");
  const [result, setResult] = useState<SecretsGateResult | null>(null);
  const [running, setRunning] = useState(false);
  const [toast, setToast] = useState("");
  const [selected, setSelected] = useState<RedactionViolation | null>(null);

  const run = async () => {
    if (!configText.trim()) return setToast("Configuration text is required");
    setRunning(true);
    try {
      const res = await fetch(`${API_BASE}/api/secrets-gate/assess`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ config_text: configText }),
      });
      if (!res.ok) throw new Error(`Gate returned ${res.status}`);
      const data = await res.json() as SecretsGateResult;
      setResult(data);
      setSelected(data.violations[0] ?? null);
      setToast(`Gate ${data.gate_status} · ${data.violation_count} violation(s)`);
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
            <SectionLabel>SECRETS GATE / REDACTION VERIFICATION</SectionLabel>
            <h1>Is the evidence properly redacted?</h1>
            <p>Verify that evidence excerpts do not leak credentials, secrets, SNMP community strings, or other sensitive values. Evidence must be reviewed through this gate before export or sharing.</p>
          </div>
          <div className="intro-action">
            <span className="queue-readout"><LockKeyhole size={14} /> REDACTION CHECK</span>
          </div>
        </div>

        <div className="queue-banner" style={{ marginBottom: 24 }}>
          <div className="queue-icon"><LockKeyhole size={22} /></div>
          <div>
            <strong>Never export unredacted evidence.</strong>
            <span>This gate checks for patterns commonly associated with secrets. It is not exhaustive — manual review is required before any evidence leaves the local workbench.</span>
          </div>
          <span className="proof-tag">REVIEW REQUIRED</span>
        </div>

        <div className="website-scan-form">
          <div className="form-row" style={{ flexDirection: "column", alignItems: "stretch" }}>
            <label>Configuration / Evidence Text</label>
            <textarea
              rows={7}
              value={configText}
              onChange={e => setConfigText(e.target.value)}
              style={{ fontFamily: "monospace", fontSize: 12, padding: 10, border: "1px solid var(--line)", background: "var(--surface)", color: "var(--ink)", resize: "vertical", borderRadius: 4 }}
            />
          </div>
          <div className="form-row">
            <button className="button button-primary" type="button" onClick={run} disabled={running}>
              <ShieldCheck size={15} /> {running ? "Checking…" : "Run Secrets Gate"}
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
                label="GATE STATUS"
                value={result.gate_status}
                note={result.violation_count > 0 ? "redaction failures detected" : "no violations detected"}
                tone={result.gate_status === "PASS" ? "verified" : result.gate_status === "WARN" ? "warn" : "danger"}
              />
              <Metric label="TOTAL LINES" value={result.total_lines.toString()} note="lines assessed" tone="neutral" />
              <Metric label="REDACTED LINES" value={result.redacted_lines.toString()} note="already redacted" tone="verified" />
              <Metric label="VIOLATIONS" value={result.violation_count.toString()} note={`${result.high_risk_count} high-risk`} tone={result.violation_count > 0 ? "danger" : "verified"} />
            </div>

            <div className="two-column">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <SectionLabel>REDACTION VIOLATIONS / {result.gate_id}</SectionLabel>
                    <h2>Secrets requiring redaction</h2>
                  </div>
                  <span className="count-badge">{result.violations.length.toString().padStart(2, "0")}</span>
                </div>
                <div className="findings-table">
                  <div className="table-head"><span>VIOLATION / LINE</span><span>CATEGORY</span><span>PATTERN</span><span>RISK</span></div>
                  {result.violations.length === 0
                    ? <div className="empty-state"><ShieldCheck size={22} /><strong>No violations</strong><span>No unredacted secrets detected in this excerpt.</span></div>
                    : result.violations.map(v => (
                      <button
                        type="button"
                        key={v.violation_id}
                        className={`finding-row ${selected?.violation_id === v.violation_id ? "finding-selected" : ""}`}
                        onClick={() => setSelected(v)}
                      >
                        <span className="finding-main">
                          <span className={`finding-symbol symbol-${RISK_TONE[v.risk_level] ?? "neutral"}`}>!</span>
                          <span>
                            <strong>Line {v.line_number}</strong>
                            <small>{v.excerpt_redacted}</small>
                          </span>
                        </span>
                        <span className="vendor-label">{v.category}</span>
                        <code style={{ fontSize: 10 }}>{v.pattern_matched}</code>
                        <span className={`severity severity-${v.risk_level.toLowerCase()}`}>{v.risk_level}</span>
                      </button>
                    ))
                  }
                </div>
              </section>

              <aside className="evidence-panel">
                <div className="evidence-top">
                  <SectionLabel>SELECTED VIOLATION</SectionLabel>
                  <span className="proof-tag"><LockKeyhole size={12} /> SECRETS GATE</span>
                </div>
                {selected ? (
                  <>
                    <div className="evidence-id">Line {selected.line_number} · {selected.category}</div>
                    <h2>{selected.risk_level} risk — redaction required</h2>
                    <div className="evidence-block">
                      <SectionLabel>REDACTED EXCERPT</SectionLabel>
                      <div style={{ fontFamily: "monospace", fontSize: 12, background: "var(--surface)", padding: "8px 10px", borderRadius: 4, border: "1px solid var(--line)", wordBreak: "break-all" }}>
                        {selected.excerpt_redacted}
                      </div>
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>MATCHED PATTERN</SectionLabel>
                      <code style={{ display: "block", padding: "6px 10px", background: "var(--surface)", borderRadius: 4 }}>{selected.pattern_matched}</code>
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>REQUIRED ACTION</SectionLabel>
                      <p className="muted-copy">Replace the matched value with a redaction marker (e.g., <code>[REDACTED]</code>) before exporting or sharing this evidence artifact.</p>
                    </div>
                    <div className="evidence-footer">
                      <span>gate/{result.gate_id}</span>
                      <span>Gate is not exhaustive — manual review required</span>
                    </div>
                  </>
                ) : (
                  <div className="empty-state"><FileText size={22} /><strong>Select a violation</strong><span>Details will appear here</span></div>
                )}
              </aside>
            </div>

            <div className="queue-banner" style={{ marginTop: 24 }}>
              <div className="queue-icon"><FileText size={18} /></div>
              <div><strong>Limitations</strong><span>{result.limitations}</span></div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
