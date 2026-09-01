/* Regulatory Evidence Automation — export machine-readable OSCAL evidence packages. */
import { useState } from "react";
import { FileText, AlertTriangle, Download, ShieldCheck } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type MappedControl = {
  control_id: string;
  title: string;
  catalog: string;
  finding_status: string;
  evidence_count: number;
  assessment_date: string;
  responsible_role: string;
  implementation_statement: string;
  review_required: boolean;
};

type RegulatoryExport = {
  export_id: string;
  generated_at: string;
  catalog: string;
  profile_version: string;
  audit_id: string;
  total_controls: number;
  mapped_count: number;
  unmapped_count: number;
  review_required_count: number;
  controls: MappedControl[];
  format: string;
  limitations: string;
  disclaimer: string;
};

const CATALOG_OPTIONS = [
  { value: "nist-800-53-r5", label: "NIST SP 800-53 Rev 5" },
  { value: "nist-csf-2", label: "NIST CSF 2.0" },
  { value: "cis-controls-v8", label: "CIS Controls v8" },
  { value: "iso-27001-2022", label: "ISO/IEC 27001:2022" },
  { value: "pci-dss-v4", label: "PCI DSS v4.0" },
  { value: "soc2-trust", label: "SOC 2 Trust Services" },
];

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

export default function RegulatoryPage() {
  const [auditId, setAuditId] = useState("");
  const [catalog, setCatalog] = useState("nist-800-53-r5");
  const [format, setFormat] = useState("oscal-json");
  const [result, setResult] = useState<RegulatoryExport | null>(null);
  const [exporting, setExporting] = useState(false);
  const [toast, setToast] = useState("");
  const [selected, setSelected] = useState<MappedControl | null>(null);
  const [reviewFilter, setReviewFilter] = useState(false);

  const doExport = async () => {
    if (!auditId.trim()) return setToast("Audit ID is required");
    setExporting(true);
    try {
      const res = await fetch(`${API_BASE}/api/regulatory/export`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ audit_id: auditId, catalog, format }),
      });
      if (!res.ok) throw new Error(`Export returned ${res.status}`);
      const data = await res.json() as RegulatoryExport;
      setResult(data);
      setSelected(data.controls[0] ?? null);
      setToast(`Export generated · ${data.mapped_count}/${data.total_controls} controls mapped`);
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "start the local API"}`);
    } finally {
      setExporting(false);
    }
  };

  const downloadExport = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `regulatory-export-${result.export_id}.${format === "oscal-json" ? "json" : "xml"}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const visible = result?.controls.filter(c => !reviewFilter || c.review_required) ?? [];

  const statusTone = (status: string) => {
    if (status === "PASS") return "verified";
    if (status === "FAIL") return "danger";
    if (status === "UNKNOWN") return "neutral";
    return "warn";
  };

  return (
    <div className="content-scroll">
      <div className="content-inner">
        <div className="page-intro">
          <div>
            <SectionLabel>REGULATORY EVIDENCE / OSCAL EXPORT</SectionLabel>
            <h1>Map evidence to control catalogs.</h1>
            <p>Export machine-readable evidence packages mapped to regulatory control frameworks. Results state "supports assessment against" — not "certified compliant." Certification requires an independent, authorized assessment body.</p>
          </div>
          <div className="intro-action">
            <span className="queue-readout"><FileText size={14} /> OSCAL EXPORT</span>
          </div>
        </div>

        <div className="queue-banner" style={{ marginBottom: 24 }}>
          <div className="queue-icon"><AlertTriangle size={22} /></div>
          <div>
            <strong>Supports assessment — not a certification.</strong>
            <span>This export maps observed control evidence to a framework catalog. It does not constitute legal compliance certification. An authorized, independent assessment is required for formal certification claims.</span>
          </div>
          <span className="proof-tag">REVIEW REQUIRED</span>
        </div>

        <div className="website-scan-form">
          <div className="form-row">
            <label>Audit ID</label>
            <input type="text" placeholder="audit-uuid" value={auditId} onChange={e => setAuditId(e.target.value)} />
            <label>Control Catalog</label>
            <select value={catalog} onChange={e => setCatalog(e.target.value)}>
              {CATALOG_OPTIONS.map(c => <option key={c.value} value={c.value}>{c.label}</option>)}
            </select>
            <label>Export Format</label>
            <select value={format} onChange={e => setFormat(e.target.value)}>
              <option value="oscal-json">OSCAL JSON</option>
              <option value="oscal-xml">OSCAL XML</option>
              <option value="csv">CSV Summary</option>
              <option value="markdown">Markdown Report</option>
            </select>
            <button className="button button-primary" type="button" onClick={doExport} disabled={exporting}>
              <FileText size={15} /> {exporting ? "Generating…" : "Generate Export"}
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
              <Metric label="CATALOG" value={CATALOG_OPTIONS.find(c => c.value === result.catalog)?.label ?? result.catalog} note={result.profile_version} tone="neutral" />
              <Metric label="CONTROLS MAPPED" value={result.mapped_count.toString()} note={`of ${result.total_controls} total`} tone={result.mapped_count === result.total_controls ? "verified" : "warn"} />
              <Metric label="UNMAPPED" value={result.unmapped_count.toString()} note="require manual assessment" tone={result.unmapped_count > 0 ? "warn" : "verified"} />
              <Metric label="NEEDS REVIEW" value={result.review_required_count.toString()} note="contradictory or insufficient" tone={result.review_required_count > 0 ? "danger" : "verified"} />
            </div>

            {/* Download + filter bar */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <button
                  type="button"
                  className={`button ${reviewFilter ? "button-primary" : "button-secondary"}`}
                  onClick={() => setReviewFilter(!reviewFilter)}
                >
                  {reviewFilter ? "Show All" : "Show Review Required Only"}
                </button>
              </div>
              <button className="button button-secondary" type="button" onClick={downloadExport}>
                <Download size={15} /> Download {format.toUpperCase()}
              </button>
            </div>

            <div className="two-column">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <SectionLabel>MAPPED CONTROLS / {result.export_id}</SectionLabel>
                    <h2>Evidence-to-control mapping</h2>
                  </div>
                  <span className="count-badge">{visible.length.toString().padStart(2, "0")}</span>
                </div>
                <div className="findings-table">
                  <div className="table-head"><span>CONTROL / CATALOG</span><span>STATUS</span><span>EVIDENCE</span><span>REVIEW?</span></div>
                  {visible.length === 0
                    ? <div className="empty-state"><ShieldCheck size={22} /><strong>No controls match filter</strong><span>Remove filter or generate an export.</span></div>
                    : visible.map(c => (
                      <button
                        type="button"
                        key={c.control_id}
                        className={`finding-row ${selected?.control_id === c.control_id ? "finding-selected" : ""}`}
                        onClick={() => setSelected(c)}
                      >
                        <span className="finding-main">
                          <span className={`finding-symbol symbol-${statusTone(c.finding_status)}`}>
                            {c.finding_status === "PASS" ? "✓" : c.finding_status === "FAIL" ? "!" : "?"}
                          </span>
                          <span>
                            <strong>{c.control_id}</strong>
                            <small>{c.title}</small>
                          </span>
                        </span>
                        <span className={`status-pill status-${statusTone(c.finding_status)}`}><span className="status-dot" />{c.finding_status}</span>
                        <span className="vendor-label">{c.evidence_count} refs</span>
                        <span className={`status-pill ${c.review_required ? "status-fail" : "status-pass"}`}>
                          <span className="status-dot" />{c.review_required ? "REVIEW" : "OK"}
                        </span>
                      </button>
                    ))
                  }
                </div>
              </section>

              <aside className="evidence-panel">
                <div className="evidence-top">
                  <SectionLabel>SELECTED CONTROL</SectionLabel>
                  <span className="proof-tag"><FileText size={12} /> OSCAL</span>
                </div>
                {selected ? (
                  <>
                    <div className="evidence-id">{selected.control_id} · {selected.catalog}</div>
                    <h2>{selected.title}</h2>
                    <div className="evidence-block">
                      <SectionLabel>FINDING STATUS</SectionLabel>
                      <span className={`status-pill status-${statusTone(selected.finding_status)}`}>
                        <span className="status-dot" />{selected.finding_status}
                      </span>
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>IMPLEMENTATION STATEMENT</SectionLabel>
                      <p className="muted-copy">{selected.implementation_statement}</p>
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>ASSESSMENT METADATA</SectionLabel>
                      <div className="evidence-line"><code>DATE</code><span>{new Date(selected.assessment_date).toLocaleDateString()}</span></div>
                      <div className="evidence-line"><code>ROLE</code><span>{selected.responsible_role}</span></div>
                      <div className="evidence-line"><code>EVID</code><span>{selected.evidence_count} evidence reference(s)</span></div>
                    </div>
                    {selected.review_required && (
                      <div className="evidence-block">
                        <SectionLabel>ASSESSOR REVIEW QUEUE</SectionLabel>
                        <p className="muted-copy" style={{ color: "var(--red)" }}>
                          This control has contradictory or insufficient evidence. It must be reviewed by an assessor before the export is submitted to a certification authority.
                        </p>
                      </div>
                    )}
                    <div className="evidence-footer">
                      <span>export/{result.export_id}</span>
                      <span>Supports assessment — not a certification</span>
                    </div>
                  </>
                ) : (
                  <div className="empty-state"><FileText size={22} /><strong>Select a control</strong><span>Mapping details will appear here</span></div>
                )}
              </aside>
            </div>

            {/* Disclaimer */}
            <div className="queue-banner" style={{ marginTop: 24, borderColor: "var(--line-strong)" }}>
              <div className="queue-icon"><AlertTriangle size={18} /></div>
              <div>
                <strong>Disclaimer</strong>
                <span>{result.disclaimer}</span>
              </div>
            </div>

            {result.limitations && (
              <div className="queue-banner" style={{ marginTop: 12 }}>
                <div className="queue-icon"><FileText size={18} /></div>
                <div><strong>Limitations</strong><span>{result.limitations}</span></div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
