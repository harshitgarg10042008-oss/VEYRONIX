/* Provenance Tracker — artifact origin and chain-of-custody verification. */
import { useState } from "react";
import { Fingerprint, ShieldCheck, AlertTriangle, FileText } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type ProvenanceLink = {
  link_id: string;
  step_number: number;
  actor_id: string;
  action: string;
  timestamp: string;
  artifact_hash: string;
  previous_hash: string | null;
  location: string;
};

type ProvenanceRecord = {
  artifact_id: string;
  artifact_type: string;
  origin: string;
  created_at: string;
  current_hash: string;
  chain_valid: boolean;
  chain_length: number;
  chain: ProvenanceLink[];
  limitations: string;
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

export default function ProvenancePage() {
  const [artifactId, setArtifactId] = useState("");
  const [record, setRecord] = useState<ProvenanceRecord | null>(null);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState("");
  const [selected, setSelected] = useState<ProvenanceLink | null>(null);

  const load = async () => {
    if (!artifactId.trim()) return setToast("Artifact ID is required");
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/provenance/${encodeURIComponent(artifactId)}`);
      if (!res.ok) throw new Error(`Provenance returned ${res.status}`);
      const data = await res.json() as ProvenanceRecord;
      setRecord(data);
      setSelected(data.chain[0] ?? null);
      setToast(`Provenance loaded · chain ${data.chain_valid ? "valid" : "INVALID"}`);
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "start the local API"}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="content-scroll">
      <div className="content-inner">
        <div className="page-intro">
          <div>
            <SectionLabel>PROVENANCE TRACKER / CHAIN OF CUSTODY</SectionLabel>
            <h1>Trace where every artifact came from.</h1>
            <p>Verify the full custody chain of an evidence artifact — who created it, who touched it, and whether each link in the chain is cryptographically consistent. A broken chain is a review-required finding.</p>
          </div>
          <div className="intro-action">
            <span className="queue-readout"><Fingerprint size={14} /> CHAIN AUDIT</span>
          </div>
        </div>

        <div className="website-scan-form">
          <div className="form-row">
            <label>Artifact ID</label>
            <input type="text" placeholder="audit-uuid or bundle-id" value={artifactId} onChange={e => setArtifactId(e.target.value)} style={{ flex: 2 }} />
            <button className="button button-primary" type="button" onClick={load} disabled={loading}>
              <Fingerprint size={15} /> {loading ? "Loading…" : "Load Provenance"}
            </button>
          </div>
        </div>

        {toast && (
          <div className="queue-banner" style={{ marginBottom: 16 }}>
            <div className="queue-icon"><AlertTriangle size={18} /></div>
            <span>{toast}</span>
          </div>
        )}

        {record && (
          <>
            <div className="scan-summary">
              <Metric
                label="CHAIN VALIDITY"
                value={record.chain_valid ? "VALID" : "INVALID"}
                note={`${record.chain_length} custody links`}
                tone={record.chain_valid ? "verified" : "danger"}
              />
              <Metric label="ARTIFACT TYPE" value={record.artifact_type} note={record.origin} tone="neutral" />
              <Metric label="CREATED" value={new Date(record.created_at).toLocaleDateString()} note={new Date(record.created_at).toLocaleTimeString()} tone="neutral" />
              <Metric label="CURRENT HASH" value={record.current_hash.slice(0, 12) + "…"} note="SHA-256 truncated" tone="neutral" />
            </div>

            {!record.chain_valid && (
              <div className="queue-banner" style={{ marginBottom: 24, borderColor: "var(--red)" }}>
                <div className="queue-icon"><AlertTriangle size={22} /></div>
                <div>
                  <strong>Chain integrity failure.</strong>
                  <span>One or more custody links have a hash mismatch. This artifact should not be trusted as authoritative evidence without manual investigation.</span>
                </div>
                <span className="proof-tag" style={{ color: "var(--red)" }}>INVALID CHAIN</span>
              </div>
            )}

            <div className="two-column">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <SectionLabel>CUSTODY CHAIN / {record.artifact_id}</SectionLabel>
                    <h2>Chronological custody links</h2>
                  </div>
                  <span className="count-badge">{record.chain.length.toString().padStart(2, "0")}</span>
                </div>
                <div className="findings-table">
                  <div className="table-head"><span>STEP / ACTOR</span><span>ACTION</span><span>LOCATION</span><span>TIME</span></div>
                  {record.chain.map(link => {
                    const hashOk = !link.previous_hash || link.previous_hash !== null;
                    return (
                      <button
                        type="button"
                        key={link.link_id}
                        className={`finding-row ${selected?.link_id === link.link_id ? "finding-selected" : ""}`}
                        onClick={() => setSelected(link)}
                      >
                        <span className="finding-main">
                          <span className="finding-symbol symbol-pass">{link.step_number}</span>
                          <span>
                            <strong>{link.actor_id}</strong>
                            <small>{link.artifact_hash.slice(0, 12)}…</small>
                          </span>
                        </span>
                        <span className="vendor-label">{link.action}</span>
                        <span className="vendor-label">{link.location}</span>
                        <span className="vendor-label">{new Date(link.timestamp).toLocaleTimeString()}</span>
                      </button>
                    );
                  })}
                </div>
              </section>

              <aside className="evidence-panel">
                <div className="evidence-top">
                  <SectionLabel>SELECTED LINK</SectionLabel>
                  <span className="proof-tag"><ShieldCheck size={12} /> PROVENANCE</span>
                </div>
                {selected ? (
                  <>
                    <div className="evidence-id">Step {selected.step_number} · {selected.action}</div>
                    <h2>{selected.actor_id}</h2>
                    <div className="evidence-block">
                      <SectionLabel>ARTIFACT HASH</SectionLabel>
                      <div style={{ fontFamily: "monospace", fontSize: 11, wordBreak: "break-all", background: "var(--surface)", padding: "6px 10px", borderRadius: 4, border: "1px solid var(--line)" }}>
                        {selected.artifact_hash}
                      </div>
                    </div>
                    {selected.previous_hash && (
                      <div className="evidence-block">
                        <SectionLabel>PREVIOUS HASH</SectionLabel>
                        <div style={{ fontFamily: "monospace", fontSize: 11, wordBreak: "break-all", background: "var(--surface)", padding: "6px 10px", borderRadius: 4, border: "1px solid var(--line)", color: "var(--muted)" }}>
                          {selected.previous_hash}
                        </div>
                      </div>
                    )}
                    <div className="evidence-block">
                      <SectionLabel>CUSTODY DETAILS</SectionLabel>
                      <div className="evidence-line"><code>LOC</code><span>{selected.location}</span></div>
                      <div className="evidence-line"><code>AT</code><span>{new Date(selected.timestamp).toLocaleString()}</span></div>
                    </div>
                    <div className="evidence-footer">
                      <span>link/{selected.link_id}</span>
                      <span>Chain audit, not authorization</span>
                    </div>
                  </>
                ) : (
                  <div className="empty-state"><FileText size={22} /><strong>Select a link</strong><span>Custody details will appear here</span></div>
                )}
              </aside>
            </div>

            <div className="queue-banner" style={{ marginTop: 24 }}>
              <div className="queue-icon"><FileText size={18} /></div>
              <div><strong>Limitations</strong><span>{record.limitations}</span></div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
