/* Threat Model — compile code to STRIDE threat model findings. */
import { useState } from "react";
import { AlertTriangle, FileText, ShieldCheck, Layers3 } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type StrideThreat = {
  threat_id: string;
  stride_category: string;
  title: string;
  description: string;
  affected_component: string;
  severity: string;
  mitigation: string;
  status: "OPEN" | "MITIGATED" | "ACCEPTED" | "UNKNOWN";
};

type ThreatModelResult = {
  model_id: string;
  component_name: string;
  analyzed_at: string;
  total_threats: number;
  open_count: number;
  mitigated_count: number;
  critical_count: number;
  threats: StrideThreat[];
  stride_summary: Record<string, number>;
};

const STRIDE_ICONS: Record<string, string> = {
  Spoofing: "S",
  Tampering: "T",
  Repudiation: "R",
  "Information Disclosure": "I",
  "Denial of Service": "D",
  "Elevation of Privilege": "E",
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

export default function ThreatModelPage() {
  const [componentName, setComponentName] = useState("");
  const [description, setDescription] = useState("");
  const [result, setResult] = useState<ThreatModelResult | null>(null);
  const [running, setRunning] = useState(false);
  const [toast, setToast] = useState("");
  const [selected, setSelected] = useState<StrideThreat | null>(null);
  const [strideFilter, setStrideFilter] = useState("ALL");

  const run = async () => {
    if (!componentName.trim() || !description.trim()) return setToast("Component name and description required");
    setRunning(true);
    try {
      const res = await fetch(`${API_BASE}/api/threat-model/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ component_name: componentName, description }),
      });
      if (!res.ok) throw new Error(`Model returned ${res.status}`);
      const data = await res.json() as ThreatModelResult;
      setResult(data);
      setSelected(data.threats[0] ?? null);
      setToast(`Threat model complete · ${data.total_threats} threats identified`);
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "start the local API"}`);
    } finally {
      setRunning(false);
    }
  };

  const visibleThreats = result?.threats.filter(t => strideFilter === "ALL" || t.stride_category === strideFilter) ?? [];

  return (
    <div className="content-scroll">
      <div className="content-inner">
        <div className="page-intro">
          <div>
            <SectionLabel>THREAT MODELS / STRIDE ANALYSIS</SectionLabel>
            <h1>Model threats. Don't assume safety.</h1>
            <p>Generate a STRIDE threat model for a described component or architecture. Results are hypothetical threat enumerations — not confirmed vulnerabilities — and require human review and validation.</p>
          </div>
          <div className="intro-action">
            <span className="queue-readout"><Layers3 size={14} /> STRIDE</span>
          </div>
        </div>

        <div className="website-scan-form">
          <div className="form-row">
            <label>Component Name</label>
            <input type="text" placeholder="ConfigSentinel API Gateway" value={componentName} onChange={e => setComponentName(e.target.value)} />
          </div>
          <div className="form-row" style={{ flexDirection: "column", alignItems: "stretch" }}>
            <label>Component Description</label>
            <textarea
              rows={4}
              placeholder="Describe the component, its inputs, outputs, trust boundaries, and interactions with other systems…"
              value={description}
              onChange={e => setDescription(e.target.value)}
              style={{ fontFamily: "inherit", fontSize: 13, padding: 10, border: "1px solid var(--line)", background: "var(--surface)", color: "var(--ink)", resize: "vertical", borderRadius: 4 }}
            />
          </div>
          <div className="form-row">
            <button className="button button-primary" type="button" onClick={run} disabled={running}>
              <AlertTriangle size={15} /> {running ? "Modeling…" : "Generate Threat Model"}
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
              <Metric label="TOTAL THREATS" value={result.total_threats.toString()} note="STRIDE enumeration" tone={result.critical_count > 0 ? "danger" : "warn"} />
              <Metric label="CRITICAL" value={result.critical_count.toString()} note="immediate review required" tone={result.critical_count > 0 ? "danger" : "verified"} />
              <Metric label="OPEN" value={result.open_count.toString()} note="unmitigated threats" tone={result.open_count > 0 ? "warn" : "verified"} />
              <Metric label="MITIGATED" value={result.mitigated_count.toString()} note="addressed threats" tone="verified" />
            </div>

            {/* STRIDE category summary */}
            <div style={{ display: "flex", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
              <button type="button" className={`button ${strideFilter === "ALL" ? "button-primary" : "button-secondary"}`} onClick={() => setStrideFilter("ALL")}>All</button>
              {Object.entries(STRIDE_ICONS).map(([cat, abbr]) => (
                <button key={cat} type="button" className={`button ${strideFilter === cat ? "button-primary" : "button-secondary"}`} onClick={() => setStrideFilter(cat)}>
                  <strong>{abbr}</strong> {cat} {result.stride_summary[cat] ? `(${result.stride_summary[cat]})` : ""}
                </button>
              ))}
            </div>

            <div className="two-column">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <SectionLabel>THREATS / {result.model_id}</SectionLabel>
                    <h2>{result.component_name}</h2>
                  </div>
                  <span className="count-badge">{visibleThreats.length.toString().padStart(2, "0")}</span>
                </div>
                <div className="findings-table">
                  <div className="table-head"><span>THREAT / COMPONENT</span><span>STRIDE</span><span>SEVERITY</span><span>STATUS</span></div>
                  {visibleThreats.length === 0
                    ? <div className="empty-state"><ShieldCheck size={22} /><strong>No threats in this category</strong><span>Select a different STRIDE filter.</span></div>
                    : visibleThreats.map(t => (
                      <button
                        type="button"
                        key={t.threat_id}
                        className={`finding-row ${selected?.threat_id === t.threat_id ? "finding-selected" : ""}`}
                        onClick={() => setSelected(t)}
                      >
                        <span className="finding-main">
                          <span className={`finding-symbol symbol-${SEV_TONE[t.severity] ?? "neutral"}`}>
                            {STRIDE_ICONS[t.stride_category] ?? "?"}
                          </span>
                          <span>
                            <strong>{t.title}</strong>
                            <small>{t.affected_component}</small>
                          </span>
                        </span>
                        <span className="vendor-label">{t.stride_category}</span>
                        <span className={`severity severity-${t.severity.toLowerCase()}`}>{t.severity}</span>
                        <span className={`status-pill status-${t.status === "MITIGATED" ? "pass" : t.status === "OPEN" ? "fail" : "unknown"}`}>
                          <span className="status-dot" />{t.status}
                        </span>
                      </button>
                    ))
                  }
                </div>
              </section>

              <aside className="evidence-panel">
                <div className="evidence-top">
                  <SectionLabel>SELECTED THREAT</SectionLabel>
                  <span className="proof-tag"><AlertTriangle size={12} /> STRIDE</span>
                </div>
                {selected ? (
                  <>
                    <div className="evidence-id">{selected.stride_category} · {selected.severity}</div>
                    <h2>{selected.title}</h2>
                    <div className="evidence-block">
                      <SectionLabel>DESCRIPTION</SectionLabel>
                      <p className="muted-copy">{selected.description}</p>
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>AFFECTED COMPONENT</SectionLabel>
                      <div className="evidence-line"><code>COMP</code><span>{selected.affected_component}</span></div>
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>MITIGATION</SectionLabel>
                      <p className="muted-copy">{selected.mitigation}</p>
                    </div>
                    <div className="evidence-footer">
                      <span>model/{result.model_id}</span>
                      <span>Hypothetical — requires human validation</span>
                    </div>
                  </>
                ) : (
                  <div className="empty-state"><FileText size={22} /><strong>Select a threat</strong><span>Details will appear here</span></div>
                )}
              </aside>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
