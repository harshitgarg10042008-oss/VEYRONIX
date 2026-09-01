/* Evidence Exchange — sign and share verified findings across workspaces. */
import { useState } from "react";
import { Download, Upload, ShieldCheck, FileText, AlertTriangle } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type ExchangePackage = {
  package_id: string;
  audit_id: string;
  created_at: string;
  created_by: string;
  signature: string;
  finding_count: number;
  recipient: string | null;
  expiry: string;
  download_url: string;
};

type ImportResult = {
  import_id: string;
  package_id: string;
  audit_id: string;
  imported_at: string;
  finding_count: number;
  signature_valid: boolean;
  status: "ACCEPTED" | "REJECTED" | "QUARANTINE";
  rejection_reason: string | null;
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

export default function ExchangePage() {
  const [tab, setTab] = useState<"export" | "import">("export");
  const [auditId, setAuditId] = useState("");
  const [recipient, setRecipient] = useState("");
  const [ttlHours, setTtlHours] = useState(24);
  const [exportResult, setExportResult] = useState<ExchangePackage | null>(null);
  const [importJson, setImportJson] = useState("");
  const [importResult, setImportResult] = useState<ImportResult | null>(null);
  const [processing, setProcessing] = useState(false);
  const [toast, setToast] = useState("");

  const doExport = async () => {
    if (!auditId.trim()) return setToast("Audit ID is required");
    setProcessing(true);
    try {
      const res = await fetch(`${API_BASE}/api/exchange/export`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ audit_id: auditId, recipient, ttl_hours: ttlHours }),
      });
      if (!res.ok) throw new Error(`Export returned ${res.status}`);
      const data = await res.json() as ExchangePackage;
      setExportResult(data);
      setImportJson(JSON.stringify(data, null, 2));
      setToast(`Package created · ${data.package_id}`);
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "start the local API"}`);
    } finally {
      setProcessing(false);
    }
  };

  const doImport = async () => {
    let parsed: object;
    try { parsed = JSON.parse(importJson); } catch { return setToast("Invalid package JSON"); }
    setProcessing(true);
    try {
      const res = await fetch(`${API_BASE}/api/exchange/import`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ package: parsed }),
      });
      if (!res.ok) throw new Error(`Import returned ${res.status}`);
      const data = await res.json() as ImportResult;
      setImportResult(data);
      setToast(`Import ${data.status} · ${data.finding_count} findings · signature ${data.signature_valid ? "valid" : "INVALID"}`);
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "unknown"}`);
    } finally {
      setProcessing(false);
    }
  };

  return (
    <div className="content-scroll">
      <div className="content-inner">
        <div className="page-intro">
          <div>
            <SectionLabel>EVIDENCE EXCHANGE / SIGNED FINDINGS SHARING</SectionLabel>
            <h1>Share evidence, not trust.</h1>
            <p>Export signed audit packages for sharing with other operators or workspaces. Each package is cryptographically sealed and time-limited. Importers verify the seal before accepting any findings.</p>
          </div>
          <div className="intro-action">
            <span className="queue-readout"><ShieldCheck size={14} /> SIGNED EXCHANGE</span>
          </div>
        </div>

        <div className="queue-banner" style={{ marginBottom: 24 }}>
          <div className="queue-icon"><AlertTriangle size={22} /></div>
          <div>
            <strong>Signature verification is mandatory on import.</strong>
            <span>Imported findings are quarantined until the package signature is verified. An invalid signature results in automatic rejection.</span>
          </div>
          <span className="proof-tag">TAMPER-EVIDENT</span>
        </div>

        {/* Tab selector */}
        <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
          <button type="button" className={`button ${tab === "export" ? "button-primary" : "button-secondary"}`} onClick={() => setTab("export")}>
            <Download size={15} /> Export Package
          </button>
          <button type="button" className={`button ${tab === "import" ? "button-primary" : "button-secondary"}`} onClick={() => setTab("import")}>
            <Upload size={15} /> Import Package
          </button>
        </div>

        {tab === "export" && (
          <>
            <div className="website-scan-form">
              <div className="form-row">
                <label>Audit ID</label>
                <input type="text" placeholder="audit-uuid" value={auditId} onChange={e => setAuditId(e.target.value)} />
                <label>Recipient (optional)</label>
                <input type="text" placeholder="ops-team@corp" value={recipient} onChange={e => setRecipient(e.target.value)} />
                <label>TTL (hours)</label>
                <input type="number" min={1} max={168} value={ttlHours} onChange={e => setTtlHours(parseInt(e.target.value) || 24)} style={{ width: 70 }} />
                <button className="button button-primary" type="button" onClick={doExport} disabled={processing}>
                  <Download size={15} /> {processing ? "Exporting…" : "Create Package"}
                </button>
              </div>
            </div>

            {exportResult && (
              <div className="two-column" style={{ marginTop: 24 }}>
                <section className="panel">
                  <div className="panel-head">
                    <div><SectionLabel>EXCHANGE PACKAGE</SectionLabel><h2>Signed evidence artifact</h2></div>
                    <span className="proof-tag"><ShieldCheck size={12} /> SIGNED</span>
                  </div>
                  <div style={{ padding: "0 16px 16px" }}>
                    <div className="scan-summary" style={{ marginBottom: 16, marginTop: 0 }}>
                      <Metric label="FINDINGS" value={exportResult.finding_count.toString()} note="sealed in package" tone="neutral" />
                      <Metric label="EXPIRES" value={new Date(exportResult.expiry).toLocaleDateString()} note={new Date(exportResult.expiry).toLocaleTimeString()} tone="neutral" />
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>PACKAGE ID</SectionLabel>
                      <code style={{ wordBreak: "break-all", display: "block" }}>{exportResult.package_id}</code>
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>SIGNATURE (truncated)</SectionLabel>
                      <code style={{ wordBreak: "break-all", display: "block", fontSize: 10 }}>{exportResult.signature.slice(0, 64)}…</code>
                    </div>
                  </div>
                </section>
                <aside className="evidence-panel">
                  <div className="evidence-top"><SectionLabel>PACKAGE JSON</SectionLabel><span className="proof-tag">EXPORT</span></div>
                  <textarea
                    readOnly
                    rows={18}
                    value={importJson}
                    style={{ width: "100%", fontFamily: "monospace", fontSize: 10, padding: 10, border: "1px solid var(--line)", background: "var(--surface)", color: "var(--muted)", resize: "none", borderRadius: 4 }}
                  />
                </aside>
              </div>
            )}
          </>
        )}

        {tab === "import" && (
          <>
            <div className="website-scan-form">
              <div className="form-row" style={{ flexDirection: "column", alignItems: "stretch" }}>
                <label>Package JSON</label>
                <textarea
                  rows={10}
                  placeholder={`Paste the exchange package JSON here…`}
                  value={importJson}
                  onChange={e => setImportJson(e.target.value)}
                  style={{ fontFamily: "monospace", fontSize: 12, padding: 10, border: "1px solid var(--line)", background: "var(--surface)", color: "var(--ink)", resize: "vertical", borderRadius: 4 }}
                />
                <button className="button button-primary" type="button" onClick={doImport} disabled={processing} style={{ alignSelf: "flex-start", marginTop: 8 }}>
                  <Upload size={15} /> {processing ? "Importing…" : "Import & Verify"}
                </button>
              </div>
            </div>

            {importResult && (
              <div className="scan-summary" style={{ marginTop: 24 }}>
                <Metric
                  label="IMPORT STATUS"
                  value={importResult.status}
                  note={importResult.rejection_reason ?? "no rejection reason"}
                  tone={importResult.status === "ACCEPTED" ? "verified" : "danger"}
                />
                <Metric label="SIGNATURE" value={importResult.signature_valid ? "VALID" : "INVALID"} note="cryptographic verification" tone={importResult.signature_valid ? "verified" : "danger"} />
                <Metric label="FINDINGS" value={importResult.finding_count.toString()} note="in package" tone="neutral" />
                <Metric label="IMPORTED AT" value={new Date(importResult.imported_at).toLocaleTimeString()} note={new Date(importResult.imported_at).toLocaleDateString()} tone="neutral" />
              </div>
            )}
          </>
        )}

        {toast && (
          <div className="queue-banner" style={{ marginTop: 16 }}>
            <div className="queue-icon"><FileText size={18} /></div>
            <span>{toast}</span>
          </div>
        )}
      </div>
    </div>
  );
}
