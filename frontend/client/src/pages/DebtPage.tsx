/* Technical Debt — track and triage security posture debt items. */
import { useState, useEffect } from "react";
import { AlertTriangle, FileText, Check, TrendingUp } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type DebtItem = {
  debt_id: string;
  control_id: string;
  title: string;
  category: string;
  severity: string;
  age_days: number;
  first_detected: string;
  last_confirmed: string;
  status: "OPEN" | "IN_PROGRESS" | "ACCEPTED" | "RESOLVED";
  estimated_effort_hours: number;
  rationale: string;
};

type DebtSummary = {
  report_id: string;
  generated_at: string;
  total_items: number;
  open_count: number;
  in_progress_count: number;
  critical_count: number;
  total_effort_hours: number;
  oldest_item_days: number;
  items: DebtItem[];
  debt_score: number;
};

const STATUS_TONE: Record<string, string> = {
  OPEN: "danger",
  IN_PROGRESS: "warn",
  ACCEPTED: "neutral",
  RESOLVED: "verified",
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

export default function DebtPage() {
  const [summary, setSummary] = useState<DebtSummary | null>(null);
  const [selected, setSelected] = useState<DebtItem | null>(null);
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState("");

  const load = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/technical-debt/report`);
      if (!res.ok) throw new Error(`Report returned ${res.status}`);
      const data = await res.json() as DebtSummary;
      setSummary(data);
      setSelected(data.items[0] ?? null);
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "start the local API"}`);
    } finally {
      setLoading(false);
    }
  };

  const updateStatus = async (debtId: string, newStatus: string) => {
    try {
      const res = await fetch(`${API_BASE}/api/technical-debt/${debtId}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      if (!res.ok) throw new Error(`Update returned ${res.status}`);
      setToast("Status updated");
      await load();
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "unknown"}`);
    }
  };

  useEffect(() => { load(); }, []);

  const visible = summary?.items.filter(i => statusFilter === "ALL" || i.status === statusFilter) ?? [];

  return (
    <div className="content-scroll">
      <div className="content-inner">
        <div className="page-intro">
          <div>
            <SectionLabel>TECHNICAL DEBT / POSTURE DEBT REGISTER</SectionLabel>
            <h1>Make debt visible. Make it manageable.</h1>
            <p>Track known security posture debt items — accepted risks, deferred remediations, and long-standing control failures — with age, effort estimates, and triage status.</p>
          </div>
          <div className="intro-action">
            <button className="button button-secondary" type="button" onClick={load} disabled={loading}>
              <TrendingUp size={15} /> {loading ? "Loading…" : "Refresh Report"}
            </button>
          </div>
        </div>

        {toast && (
          <div className="queue-banner" style={{ marginBottom: 16 }}>
            <div className="queue-icon"><AlertTriangle size={18} /></div>
            <span>{toast}</span>
          </div>
        )}

        {summary && (
          <>
            <div className="scan-summary">
              <Metric
                label="DEBT SCORE"
                value={`${(summary.debt_score * 100).toFixed(0)}%`}
                note="lower is better"
                tone={summary.debt_score > 0.5 ? "danger" : summary.debt_score > 0.2 ? "warn" : "verified"}
              />
              <Metric label="OPEN ITEMS" value={summary.open_count.toString()} note={`${summary.in_progress_count} in progress`} tone={summary.open_count > 0 ? "warn" : "verified"} />
              <Metric label="CRITICAL" value={summary.critical_count.toString()} note="highest priority" tone={summary.critical_count > 0 ? "danger" : "verified"} />
              <Metric label="TOTAL EFFORT" value={`${summary.total_effort_hours}h`} note={`oldest: ${summary.oldest_item_days} days`} tone="neutral" />
            </div>

            {/* Status filters */}
            <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
              {["ALL", "OPEN", "IN_PROGRESS", "ACCEPTED", "RESOLVED"].map(s => (
                <button key={s} type="button" className={`button ${statusFilter === s ? "button-primary" : "button-secondary"}`} onClick={() => setStatusFilter(s)}>
                  {s === "ALL" ? "All" : s.replace(/_/g, " ")}
                </button>
              ))}
            </div>

            <div className="two-column">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <SectionLabel>DEBT REGISTER / {summary.report_id}</SectionLabel>
                    <h2>Security posture debt items</h2>
                  </div>
                  <span className="count-badge">{visible.length.toString().padStart(2, "0")}</span>
                </div>
                <div className="findings-table">
                  <div className="table-head"><span>CONTROL / TITLE</span><span>AGE</span><span>EFFORT</span><span>STATUS</span></div>
                  {visible.length === 0
                    ? <div className="empty-state"><Check size={22} /><strong>No debt in this category</strong><span>All items have been triaged.</span></div>
                    : visible.map(item => (
                      <button
                        type="button"
                        key={item.debt_id}
                        className={`finding-row ${selected?.debt_id === item.debt_id ? "finding-selected" : ""}`}
                        onClick={() => setSelected(item)}
                      >
                        <span className="finding-main">
                          <span className={`finding-symbol symbol-${SEV_TONE[item.severity] ?? "neutral"}`}>
                            {item.severity === "CRITICAL" || item.severity === "HIGH" ? "!" : "~"}
                          </span>
                          <span>
                            <strong>{item.control_id}</strong>
                            <small>{item.title}</small>
                          </span>
                        </span>
                        <span className="vendor-label">{item.age_days}d</span>
                        <span className="vendor-label">{item.estimated_effort_hours}h</span>
                        <span className={`status-pill status-${STATUS_TONE[item.status] ?? "neutral"}`}>
                          <span className="status-dot" />{item.status.replace(/_/g, " ")}
                        </span>
                      </button>
                    ))
                  }
                </div>
              </section>

              <aside className="evidence-panel">
                <div className="evidence-top">
                  <SectionLabel>SELECTED DEBT ITEM</SectionLabel>
                  <span className="proof-tag"><AlertTriangle size={12} /> DEBT</span>
                </div>
                {selected ? (
                  <>
                    <div className="evidence-id">{selected.control_id} · {selected.severity}</div>
                    <h2>{selected.title}</h2>
                    <div className="evidence-block">
                      <SectionLabel>DEBT DETAILS</SectionLabel>
                      <div className="evidence-line"><code>AGE</code><span>{selected.age_days} days unresolved</span></div>
                      <div className="evidence-line"><code>EFF</code><span>Estimated {selected.estimated_effort_hours} hours to remediate</span></div>
                      <div className="evidence-line"><code>CAT</code><span>{selected.category}</span></div>
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>RATIONALE</SectionLabel>
                      <p className="muted-copy">{selected.rationale}</p>
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>TRIAGE ACTIONS</SectionLabel>
                      <div className="action-row">
                        {selected.status !== "IN_PROGRESS" && (
                          <button type="button" className="button button-secondary" onClick={() => updateStatus(selected.debt_id, "IN_PROGRESS")}>
                            Mark In Progress
                          </button>
                        )}
                        {selected.status !== "ACCEPTED" && (
                          <button type="button" className="button button-tertiary" onClick={() => updateStatus(selected.debt_id, "ACCEPTED")}>
                            Accept Risk
                          </button>
                        )}
                        {selected.status !== "RESOLVED" && (
                          <button type="button" className="button button-secondary" onClick={() => updateStatus(selected.debt_id, "RESOLVED")}>
                            Mark Resolved
                          </button>
                        )}
                      </div>
                    </div>
                    <div className="evidence-footer">
                      <span>debt/{selected.debt_id}</span>
                      <span>First detected: {new Date(selected.first_detected).toLocaleDateString()}</span>
                    </div>
                  </>
                ) : (
                  <div className="empty-state"><FileText size={22} /><strong>Select a debt item</strong><span>Details will appear here</span></div>
                )}
              </aside>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
