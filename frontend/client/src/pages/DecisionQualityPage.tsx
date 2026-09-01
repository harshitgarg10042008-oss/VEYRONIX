/* Decision Quality — analyze approval and review decision statistics. */
import { useState, useEffect } from "react";
import { Check, AlertTriangle, FileText, BarChart2 } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type ApprovalStat = {
  period: string;
  total_requests: number;
  approved: number;
  rejected: number;
  avg_review_time_hours: number;
  overdue_count: number;
  actor_id: string;
  role: string;
};

type DecisionQualityResult = {
  report_id: string;
  generated_at: string;
  period_days: number;
  total_decisions: number;
  approval_rate: number;
  rejection_rate: number;
  avg_review_time_hours: number;
  overdue_total: number;
  by_actor: ApprovalStat[];
  quality_score: number;
  observations: string[];
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

export default function DecisionQualityPage() {
  const [result, setResult] = useState<DecisionQualityResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [periodDays, setPeriodDays] = useState(30);
  const [toast, setToast] = useState("");

  const load = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/decision-quality/report?period_days=${periodDays}`);
      if (!res.ok) throw new Error(`Report returned ${res.status}`);
      const data = await res.json() as DecisionQualityResult;
      setResult(data);
      setToast(`Report loaded · Quality score ${(data.quality_score * 100).toFixed(0)}%`);
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "start the local API"}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  return (
    <div className="content-scroll">
      <div className="content-inner">
        <div className="page-intro">
          <div>
            <SectionLabel>DECISION QUALITY / APPROVAL ANALYTICS</SectionLabel>
            <h1>Are reviews happening on time?</h1>
            <p>Measure the quality of the human review loop. Track approval rates, review latency, and overdue decisions. A healthy approval process is a prerequisite for accountable security posture.</p>
          </div>
          <div className="intro-action">
            <div className="action-row">
              <select value={periodDays} onChange={e => setPeriodDays(Number(e.target.value))} className="button button-secondary" style={{ cursor: "pointer" }}>
                <option value={7}>Last 7 days</option>
                <option value={30}>Last 30 days</option>
                <option value={90}>Last 90 days</option>
              </select>
              <button className="button button-primary" type="button" onClick={load} disabled={loading}>
                <BarChart2 size={15} /> {loading ? "Loading…" : "Refresh"}
              </button>
            </div>
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
                label="QUALITY SCORE"
                value={`${(result.quality_score * 100).toFixed(0)}%`}
                note={`${result.period_days}-day window`}
                tone={result.quality_score >= 0.8 ? "verified" : result.quality_score >= 0.5 ? "warn" : "danger"}
              />
              <Metric label="TOTAL DECISIONS" value={result.total_decisions.toString()} note="all approval events" tone="neutral" />
              <Metric
                label="APPROVAL RATE"
                value={`${(result.approval_rate * 100).toFixed(0)}%`}
                note={`${(result.rejection_rate * 100).toFixed(0)}% rejected`}
                tone={result.approval_rate > 0.7 ? "neutral" : "warn"}
              />
              <Metric
                label="AVG REVIEW TIME"
                value={`${result.avg_review_time_hours.toFixed(1)}h`}
                note={`${result.overdue_total} overdue`}
                tone={result.overdue_total > 0 ? "danger" : "verified"}
              />
            </div>

            {/* Actor breakdown */}
            <section className="panel" style={{ marginBottom: 24 }}>
              <div className="panel-head">
                <div>
                  <SectionLabel>BY REVIEWER / {result.report_id}</SectionLabel>
                  <h2>Individual decision statistics</h2>
                </div>
                <span className="count-badge">{result.by_actor.length.toString().padStart(2, "0")}</span>
              </div>
              <div className="findings-table">
                <div className="table-head"><span>ACTOR / ROLE</span><span>REQUESTS</span><span>APPROVED</span><span>AVG TIME</span><span>OVERDUE</span></div>
                {result.by_actor.length === 0
                  ? <div className="empty-state"><Check size={22} /><strong>No decisions recorded</strong><span>No approval events in this period.</span></div>
                  : result.by_actor.map(a => (
                    <div className="finding-row" key={a.actor_id}>
                      <span className="finding-main">
                        <span className={`finding-symbol symbol-${a.overdue_count > 0 ? "fail" : "pass"}`}>
                          {a.overdue_count > 0 ? "!" : "✓"}
                        </span>
                        <span>
                          <strong>{a.actor_id}</strong>
                          <small>{a.role}</small>
                        </span>
                      </span>
                      <span className="vendor-label">{a.total_requests}</span>
                      <span className="vendor-label">{a.approved} / {a.total_requests}</span>
                      <span className="vendor-label">{a.avg_review_time_hours.toFixed(1)}h</span>
                      <span className={`status-pill status-${a.overdue_count > 0 ? "fail" : "pass"}`}>
                        <span className="status-dot" />{a.overdue_count > 0 ? `${a.overdue_count} overdue` : "on time"}
                      </span>
                    </div>
                  ))
                }
              </div>
            </section>

            {/* Observations */}
            {result.observations.length > 0 && (
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <SectionLabel>QUALITY OBSERVATIONS</SectionLabel>
                    <h2>Automated analysis notes</h2>
                  </div>
                  <span className="proof-tag"><FileText size={12} /> NON-AUTHORITATIVE</span>
                </div>
                <div style={{ padding: "0 16px 16px" }}>
                  {result.observations.map((obs, i) => (
                    <div key={i} className="evidence-line" style={{ marginBottom: 6 }}>
                      <code>{String(i + 1).padStart(2, "0")}</code>
                      <span>{obs}</span>
                    </div>
                  ))}
                  <p className="muted-copy" style={{ marginTop: 12 }}>
                    These observations are statistical summaries. They do not constitute authoritative verdicts and require human interpretation before any process change.
                  </p>
                </div>
              </section>
            )}
          </>
        )}
      </div>
    </div>
  );
}
