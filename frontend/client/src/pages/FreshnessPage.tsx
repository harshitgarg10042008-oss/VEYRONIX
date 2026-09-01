/* Evidence Freshness Page — certify data age, stale evidence detection. */
import { useState } from "react";
import { Clock3, AlertTriangle, CheckCircle, FileText } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type RecordFreshness = {
  record_id: string;
  record_type: string;
  collected_at: string;
  age_hours: number;
  freshness_status: "FRESH" | "STALE" | "CRITICAL" | "UNKNOWN";
  max_allowed_age_hours: number;
  expires_at: string;
  collector_id: string;
};
type FreshnessAssessment = {
  assessment_id: string;
  assessed_at: string;
  total_records: number;
  fresh_count: number;
  stale_count: number;
  critical_count: number;
  unknown_count: number;
  records: RecordFreshness[];
  overall_status: "FRESH" | "STALE" | "CRITICAL" | "UNKNOWN";
  limitations: string[];
};

const STATUS_TONE: Record<string, string> = {
  FRESH: "verified",
  STALE: "warn",
  CRITICAL: "danger",
  UNKNOWN: "neutral",
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

function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="empty-state">
      <Clock3 size={22} />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

export default function FreshnessPage() {
  const [targetId, setTargetId] = useState("");
  const [result, setResult] = useState<FreshnessAssessment | null>(null);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState("");
  const [selected, setSelected] = useState<RecordFreshness | null>(null);

  const assess = async () => {
    if (!targetId.trim()) return setToast("Target ID is required");
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/freshness/assess`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_id: targetId }),
      });
      if (!res.ok) throw new Error(`Assessment returned ${res.status}`);
      const data = await res.json() as FreshnessAssessment;
      setResult(data);
      setSelected(data.records[0] ?? null);
      setToast(`Assessment complete · ${data.overall_status}`);
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "start the local API"}`);
    } finally {
      setLoading(false);
    }
  };

  const statusBadge = (status: string) => (
    <span className={`status-pill status-${STATUS_TONE[status] ?? "neutral"}`}>
      <span className="status-dot" />{status}
    </span>
  );

  const ageBar = (record: RecordFreshness) => {
    const pct = Math.min(100, (record.age_hours / record.max_allowed_age_hours) * 100);
    const color = pct >= 100 ? "var(--red)" : pct >= 75 ? "var(--amber)" : "var(--teal)";
    return (
      <div style={{ height: 6, background: "var(--surface)", borderRadius: 3, overflow: "hidden", marginTop: 8 }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 3, transition: "width 0.4s" }} />
      </div>
    );
  };

  return (
    <div className="content-scroll">
      <div className="content-inner">
        <div className="page-intro">
          <div>
            <SectionLabel>EVIDENCE FRESHNESS / CERTIFICATION</SectionLabel>
            <h1>Stale evidence is absent evidence.</h1>
            <p>Certify when evidence was collected, how old it is, and whether it falls within the permitted freshness window. Old data does not become a pass by default.</p>
          </div>
          <div className="intro-action">
            <span className="queue-readout"><Clock3 size={14} /> FRESHNESS CHECK</span>
          </div>
        </div>

        <div className="website-scan-form">
          <div className="form-row">
            <label>Target ID</label>
            <input
              type="text"
              placeholder="audit-id or asset-id"
              value={targetId}
              onChange={e => setTargetId(e.target.value)}
              style={{ flex: 2 }}
            />
            <button className="button button-primary" type="button" onClick={assess} disabled={loading}>
              <Clock3 size={15} /> {loading ? "Assessing…" : "Check Freshness"}
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
                label="OVERALL STATUS"
                value={result.overall_status}
                note={`assessed at ${new Date(result.assessed_at).toLocaleTimeString()}`}
                tone={STATUS_TONE[result.overall_status] ?? "neutral"}
              />
              <Metric label="FRESH" value={result.fresh_count.toString()} note="within allowed window" tone="verified" />
              <Metric label="STALE" value={result.stale_count.toString()} note="past tolerance threshold" tone="warn" />
              <Metric label="CRITICAL" value={result.critical_count.toString()} note="dangerously old, review required" tone="danger" />
            </div>

            <div className="two-column">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <SectionLabel>EVIDENCE RECORDS / {result.assessment_id}</SectionLabel>
                    <h2>Freshness by record</h2>
                  </div>
                  <span className="count-badge">{result.records.length.toString().padStart(2, "0")}</span>
                </div>
                <div className="findings-table">
                  <div className="table-head"><span>RECORD / COLLECTOR</span><span>AGE</span><span>MAX ALLOWED</span><span>STATUS</span></div>
                  {result.records.length === 0
                    ? <EmptyState title="No records found" detail="No evidence records are associated with this target." />
                    : result.records.map(rec => (
                      <button
                        type="button"
                        key={rec.record_id}
                        className={`finding-row ${selected?.record_id === rec.record_id ? "finding-selected" : ""}`}
                        onClick={() => setSelected(rec)}
                      >
                        <span className="finding-main">
                          <span className={`finding-symbol symbol-${STATUS_TONE[rec.freshness_status] ?? "neutral"}`}>
                            {rec.freshness_status === "FRESH" ? "✓" : rec.freshness_status === "CRITICAL" ? "!" : "~"}
                          </span>
                          <span>
                            <strong>{rec.record_id}</strong>
                            <small>{rec.record_type} · {rec.collector_id}</small>
                            {ageBar(rec)}
                          </span>
                        </span>
                        <span className="vendor-label">{rec.age_hours.toFixed(1)}h old</span>
                        <span className="vendor-label">max {rec.max_allowed_age_hours}h</span>
                        {statusBadge(rec.freshness_status)}
                      </button>
                    ))
                  }
                </div>
              </section>

              <aside className="evidence-panel">
                <div className="evidence-top">
                  <SectionLabel>SELECTED RECORD</SectionLabel>
                  <span className="proof-tag"><CheckCircle size={12} /> FRESHNESS</span>
                </div>
                {selected ? (
                  <>
                    <div className="evidence-id">{selected.record_id} · {selected.record_type}</div>
                    <h2>{selected.freshness_status === "FRESH" ? "Evidence is within permitted window." : selected.freshness_status === "STALE" ? "Evidence has exceeded the tolerance threshold." : "Evidence is critically old — re-collection required."}</h2>
                    <div className="evidence-block">
                      <SectionLabel>FRESHNESS STATUS</SectionLabel>
                      {statusBadge(selected.freshness_status)}
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>AGE METRICS</SectionLabel>
                      <div className="evidence-state">
                        <span>Age: <strong>{selected.age_hours.toFixed(2)} hours</strong></span>
                        <span>Max allowed: <strong>{selected.max_allowed_age_hours} hours</strong></span>
                      </div>
                      {ageBar(selected)}
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>COLLECTION METADATA</SectionLabel>
                      <div className="evidence-line">
                        <code>COL</code><span>Collector: {selected.collector_id}</span>
                      </div>
                      <div className="evidence-line">
                        <code>AT</code><span>Collected: {new Date(selected.collected_at).toLocaleString()}</span>
                      </div>
                      <div className="evidence-line">
                        <code>EXP</code><span>Expires: {new Date(selected.expires_at).toLocaleString()}</span>
                      </div>
                    </div>
                    <div className="evidence-footer">
                      <span>assess/{result.assessment_id}</span>
                      <span>Stale evidence does not auto-pass</span>
                    </div>
                  </>
                ) : (
                  <EmptyState title="Select a record" detail="Freshness details will appear here." />
                )}
              </aside>
            </div>

            {result.limitations.length > 0 && (
              <div className="queue-banner" style={{ marginTop: 24 }}>
                <div className="queue-icon"><FileText size={18} /></div>
                <div>
                  <strong>Assessment limitations</strong>
                  <span>{result.limitations.join(" · ")}</span>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
