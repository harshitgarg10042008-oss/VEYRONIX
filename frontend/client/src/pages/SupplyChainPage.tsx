/* Supply Chain — SBOM inspection and dependency evidence review. */
import { useState } from "react";
import { FileText, AlertTriangle, ShieldCheck, Package } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type ComponentRisk = {
  component_id: string;
  name: string;
  version: string;
  license: string;
  risk_level: string;
  known_cves: string[];
  supplier: string;
  attestation_status: "ATTESTED" | "UNATTESTED" | "DISPUTED";
};

type SupplyChainResult = {
  sbom_id: string;
  project_name: string;
  analyzed_at: string;
  total_components: number;
  attested_count: number;
  unattested_count: number;
  high_risk_count: number;
  cve_count: number;
  components: ComponentRisk[];
  overall_risk: string;
};

const RISK_TONE: Record<string, string> = {
  HIGH: "danger",
  MEDIUM: "warn",
  LOW: "neutral",
};

const ATTEST_TONE: Record<string, string> = {
  ATTESTED: "verified",
  UNATTESTED: "warn",
  DISPUTED: "danger",
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

export default function SupplyChainPage() {
  const [sbomJson, setSbomJson] = useState('{\n  "project_name": "veyronix-backend",\n  "components": [\n    {"name": "fastapi", "version": "0.104.0", "supplier": "Sebastián Ramírez"},\n    {"name": "cryptography", "version": "41.0.3", "supplier": "PyCA"}\n  ]\n}');
  const [result, setResult] = useState<SupplyChainResult | null>(null);
  const [running, setRunning] = useState(false);
  const [toast, setToast] = useState("");
  const [selected, setSelected] = useState<ComponentRisk | null>(null);

  const run = async () => {
    let parsed: object;
    try { parsed = JSON.parse(sbomJson); } catch { return setToast("Invalid SBOM JSON"); }
    setRunning(true);
    try {
      const res = await fetch(`${API_BASE}/api/supply-chain/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sbom: parsed }),
      });
      if (!res.ok) throw new Error(`Analysis returned ${res.status}`);
      const data = await res.json() as SupplyChainResult;
      setResult(data);
      setSelected(data.components[0] ?? null);
      setToast(`SBOM analysis complete · ${data.total_components} components · ${data.high_risk_count} high-risk`);
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
            <SectionLabel>SUPPLY CHAIN / SBOM EVIDENCE</SectionLabel>
            <h1>Inspect what you depend on.</h1>
            <p>Analyze a Software Bill of Materials for known vulnerabilities, unattested components, and high-risk dependencies. Evidence is sourced from the SBOM — not inferred.</p>
          </div>
          <div className="intro-action">
            <span className="queue-readout"><Package size={14} /> SBOM ANALYSIS</span>
          </div>
        </div>

        <div className="website-scan-form">
          <div className="form-row" style={{ flexDirection: "column", alignItems: "stretch" }}>
            <label>SBOM JSON</label>
            <textarea
              rows={8}
              value={sbomJson}
              onChange={e => setSbomJson(e.target.value)}
              style={{ fontFamily: "monospace", fontSize: 12, padding: 10, border: "1px solid var(--line)", background: "var(--surface)", color: "var(--ink)", resize: "vertical", borderRadius: 4 }}
            />
          </div>
          <div className="form-row">
            <button className="button button-primary" type="button" onClick={run} disabled={running}>
              <FileText size={15} /> {running ? "Analyzing…" : "Analyze SBOM"}
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
              <Metric label="OVERALL RISK" value={result.overall_risk} note={result.project_name} tone={RISK_TONE[result.overall_risk] ?? "neutral"} />
              <Metric label="TOTAL COMPONENTS" value={result.total_components.toString()} note="from SBOM" tone="neutral" />
              <Metric label="HIGH-RISK" value={result.high_risk_count.toString()} note="require attention" tone={result.high_risk_count > 0 ? "danger" : "verified"} />
              <Metric label="UNATTESTED" value={result.unattested_count.toString()} note="no supply chain proof" tone={result.unattested_count > 0 ? "warn" : "verified"} />
            </div>

            <div className="two-column">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <SectionLabel>COMPONENTS / {result.sbom_id}</SectionLabel>
                    <h2>SBOM component evidence</h2>
                  </div>
                  <span className="count-badge">{result.components.length.toString().padStart(2, "0")}</span>
                </div>
                <div className="findings-table">
                  <div className="table-head"><span>COMPONENT</span><span>VERSION</span><span>RISK</span><span>ATTESTED?</span></div>
                  {result.components.map(c => (
                    <button
                      type="button"
                      key={c.component_id}
                      className={`finding-row ${selected?.component_id === c.component_id ? "finding-selected" : ""}`}
                      onClick={() => setSelected(c)}
                    >
                      <span className="finding-main">
                        <span className={`finding-symbol symbol-${RISK_TONE[c.risk_level] ?? "neutral"}`}>
                          {c.risk_level === "HIGH" ? "!" : c.known_cves.length > 0 ? "~" : "✓"}
                        </span>
                        <span>
                          <strong>{c.name}</strong>
                          <small>{c.supplier} · {c.license}</small>
                          {c.known_cves.length > 0 && <code style={{ color: "var(--red)", fontSize: 10 }}>{c.known_cves.join(", ")}</code>}
                        </span>
                      </span>
                      <span className="vendor-label">{c.version}</span>
                      <span className={`severity severity-${c.risk_level.toLowerCase()}`}>{c.risk_level}</span>
                      <span className={`status-pill status-${ATTEST_TONE[c.attestation_status] ?? "neutral"}`}>
                        <span className="status-dot" />{c.attestation_status}
                      </span>
                    </button>
                  ))}
                </div>
              </section>

              <aside className="evidence-panel">
                <div className="evidence-top">
                  <SectionLabel>SELECTED COMPONENT</SectionLabel>
                  <span className="proof-tag"><ShieldCheck size={12} /> SUPPLY CHAIN</span>
                </div>
                {selected ? (
                  <>
                    <div className="evidence-id">{selected.name} v{selected.version}</div>
                    <h2>{selected.risk_level} risk · {selected.attestation_status}</h2>
                    <div className="evidence-block">
                      <SectionLabel>COMPONENT DETAILS</SectionLabel>
                      <div className="evidence-line"><code>SUP</code><span>Supplier: {selected.supplier}</span></div>
                      <div className="evidence-line"><code>LIC</code><span>License: {selected.license}</span></div>
                    </div>
                    {selected.known_cves.length > 0 && (
                      <div className="evidence-block">
                        <SectionLabel>KNOWN CVEs</SectionLabel>
                        {selected.known_cves.map(cve => (
                          <div key={cve} className="evidence-line"><code>CVE</code><span style={{ color: "var(--red)", fontWeight: 600 }}>{cve}</span></div>
                        ))}
                      </div>
                    )}
                    <div className="evidence-block">
                      <SectionLabel>ATTESTATION STATUS</SectionLabel>
                      <span className={`status-pill status-${ATTEST_TONE[selected.attestation_status] ?? "neutral"}`}>
                        <span className="status-dot" />{selected.attestation_status}
                      </span>
                    </div>
                    <div className="evidence-footer">
                      <span>sbom/{result.sbom_id}</span>
                      <span>Analysis at {new Date(result.analyzed_at).toLocaleString()}</span>
                    </div>
                  </>
                ) : (
                  <div className="empty-state"><FileText size={22} /><strong>Select a component</strong><span>Details will appear here</span></div>
                )}
              </aside>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
