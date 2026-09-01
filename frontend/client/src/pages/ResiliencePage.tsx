/* Resilience Drills — schedule and track failover and recovery checks. */
import { useState, useEffect } from "react";
import { Activity, Play, AlertTriangle, Check, FileText } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type DrillResult = {
  drill_id: string;
  drill_type: string;
  target: string;
  started_at: string;
  completed_at: string | null;
  status: "SCHEDULED" | "RUNNING" | "PASSED" | "FAILED" | "ABORTED";
  rto_target_minutes: number;
  rto_actual_minutes: number | null;
  rpo_target_minutes: number;
  rpo_actual_minutes: number | null;
  observations: string[];
  passed_checks: string[];
  failed_checks: string[];
};

const STATUS_TONE: Record<string, string> = {
  PASSED: "verified",
  FAILED: "danger",
  RUNNING: "warn",
  SCHEDULED: "neutral",
  ABORTED: "safe",
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

export default function ResiliencePage() {
  const [drills, setDrills] = useState<DrillResult[]>([]);
  const [selected, setSelected] = useState<DrillResult | null>(null);
  const [newDrill, setNewDrill] = useState({ drill_type: "failover", target: "", rto_target_minutes: 30, rpo_target_minutes: 60 });
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState("");

  const loadDrills = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/resilience/drills`);
      if (!res.ok) throw new Error(`Drills returned ${res.status}`);
      const data = await res.json() as DrillResult[];
      setDrills(data);
      if (data.length > 0 && !selected) setSelected(data[0]);
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "start the local API"}`);
    } finally {
      setLoading(false);
    }
  };

  const scheduleDrill = async () => {
    if (!newDrill.target.trim()) return setToast("Target is required");
    try {
      const res = await fetch(`${API_BASE}/api/resilience/drills`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newDrill),
      });
      if (!res.ok) throw new Error(`Schedule returned ${res.status}`);
      setToast("Drill scheduled");
      await loadDrills();
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "unknown"}`);
    }
  };

  useEffect(() => { loadDrills(); }, []);

  const passed = drills.filter(d => d.status === "PASSED").length;
  const failed = drills.filter(d => d.status === "FAILED").length;
  const running = drills.filter(d => d.status === "RUNNING").length;

  return (
    <div className="content-scroll">
      <div className="content-inner">
        <div className="page-intro">
          <div>
            <SectionLabel>RESILIENCE DRILLS / FAILOVER CHECKS</SectionLabel>
            <h1>Test recovery before you need it.</h1>
            <p>Schedule and track controlled failover drills, RTO/RPO measurements, and recovery checks. Untested recovery is not a recovery plan.</p>
          </div>
          <div className="intro-action">
            <button className="button button-secondary" type="button" onClick={loadDrills} disabled={loading}>
              <Activity size={15} /> {loading ? "Loading…" : "Refresh"}
            </button>
          </div>
        </div>

        <div className="website-scan-form">
          <div className="form-row">
            <label>Drill Type</label>
            <select value={newDrill.drill_type} onChange={e => setNewDrill({ ...newDrill, drill_type: e.target.value })}>
              <option value="failover">Failover</option>
              <option value="recovery">Recovery</option>
              <option value="backup_restore">Backup Restore</option>
              <option value="network_partition">Network Partition</option>
            </select>
            <label>Target</label>
            <input type="text" placeholder="db-primary" value={newDrill.target} onChange={e => setNewDrill({ ...newDrill, target: e.target.value })} />
            <label>RTO (min)</label>
            <input type="number" min={1} value={newDrill.rto_target_minutes} onChange={e => setNewDrill({ ...newDrill, rto_target_minutes: parseInt(e.target.value) || 30 })} style={{ width: 70 }} />
            <label>RPO (min)</label>
            <input type="number" min={1} value={newDrill.rpo_target_minutes} onChange={e => setNewDrill({ ...newDrill, rpo_target_minutes: parseInt(e.target.value) || 60 })} style={{ width: 70 }} />
            <button className="button button-primary" type="button" onClick={scheduleDrill}>
              <Play size={15} /> Schedule Drill
            </button>
          </div>
        </div>

        {toast && (
          <div className="queue-banner" style={{ marginBottom: 16 }}>
            <div className="queue-icon"><AlertTriangle size={18} /></div>
            <span>{toast}</span>
          </div>
        )}

        <div className="scan-summary">
          <Metric label="TOTAL DRILLS" value={drills.length.toString()} note="scheduled and completed" tone="neutral" />
          <Metric label="PASSED" value={passed.toString()} note="within RTO/RPO targets" tone="verified" />
          <Metric label="FAILED" value={failed.toString()} note="missed targets" tone={failed > 0 ? "danger" : "neutral"} />
          <Metric label="RUNNING" value={running.toString()} note="currently in progress" tone={running > 0 ? "warn" : "neutral"} />
        </div>

        <div className="two-column">
          <section className="panel">
            <div className="panel-head">
              <div>
                <SectionLabel>DRILL HISTORY</SectionLabel>
                <h2>Scheduled and completed drills</h2>
              </div>
              <span className="count-badge">{drills.length.toString().padStart(2, "0")}</span>
            </div>
            <div className="findings-table">
              <div className="table-head"><span>DRILL / TARGET</span><span>TYPE</span><span>RTO</span><span>STATUS</span></div>
              {drills.length === 0
                ? <div className="empty-state"><Activity size={22} /><strong>No drills scheduled</strong><span>Use the form above to schedule the first resilience drill.</span></div>
                : drills.map(d => (
                  <button
                    type="button"
                    key={d.drill_id}
                    className={`finding-row ${selected?.drill_id === d.drill_id ? "finding-selected" : ""}`}
                    onClick={() => setSelected(d)}
                  >
                    <span className="finding-main">
                      <span className={`finding-symbol symbol-${STATUS_TONE[d.status] ?? "neutral"}`}>
                        {d.status === "PASSED" ? "✓" : d.status === "FAILED" ? "!" : "·"}
                      </span>
                      <span>
                        <strong>{d.target}</strong>
                        <small>{new Date(d.started_at).toLocaleString()}</small>
                      </span>
                    </span>
                    <span className="vendor-label">{d.drill_type.replace(/_/g, " ")}</span>
                    <span className="vendor-label">
                      {d.rto_actual_minutes !== null
                        ? `${d.rto_actual_minutes}/${d.rto_target_minutes}m`
                        : `target ${d.rto_target_minutes}m`}
                    </span>
                    <span className={`status-pill status-${STATUS_TONE[d.status] ?? "neutral"}`}>
                      <span className="status-dot" />{d.status}
                    </span>
                  </button>
                ))
              }
            </div>
          </section>

          <aside className="evidence-panel">
            <div className="evidence-top">
              <SectionLabel>SELECTED DRILL</SectionLabel>
              <span className="proof-tag"><Activity size={12} /> RESILIENCE</span>
            </div>
            {selected ? (
              <>
                <div className="evidence-id">{selected.drill_type.replace(/_/g, " ").toUpperCase()} · {selected.target}</div>
                <h2>{selected.status}</h2>
                <div className="evidence-block">
                  <SectionLabel>RTO / RPO METRICS</SectionLabel>
                  <div className="evidence-state">
                    <span>RTO Target: <strong>{selected.rto_target_minutes}m</strong></span>
                    <span>RTO Actual: <strong>{selected.rto_actual_minutes !== null ? `${selected.rto_actual_minutes}m` : "—"}</strong></span>
                  </div>
                  <div className="evidence-state" style={{ marginTop: 6 }}>
                    <span>RPO Target: <strong>{selected.rpo_target_minutes}m</strong></span>
                    <span>RPO Actual: <strong>{selected.rpo_actual_minutes !== null ? `${selected.rpo_actual_minutes}m` : "—"}</strong></span>
                  </div>
                </div>
                {selected.passed_checks.length > 0 && (
                  <div className="evidence-block">
                    <SectionLabel>PASSED CHECKS</SectionLabel>
                    {selected.passed_checks.map(c => (
                      <div key={c} className="evidence-line"><code><Check size={10} /></code><span>{c}</span></div>
                    ))}
                  </div>
                )}
                {selected.failed_checks.length > 0 && (
                  <div className="evidence-block">
                    <SectionLabel>FAILED CHECKS</SectionLabel>
                    {selected.failed_checks.map(c => (
                      <div key={c} className="evidence-line"><code style={{ color: "var(--red)" }}>!</code><span>{c}</span></div>
                    ))}
                  </div>
                )}
                {selected.observations.length > 0 && (
                  <div className="evidence-block">
                    <SectionLabel>OBSERVATIONS</SectionLabel>
                    {selected.observations.map((obs, i) => (
                      <p key={i} className="muted-copy" style={{ marginBottom: 4 }}>{obs}</p>
                    ))}
                  </div>
                )}
                <div className="evidence-footer">
                  <span>drill/{selected.drill_id}</span>
                  <span>Results require human review</span>
                </div>
              </>
            ) : (
              <div className="empty-state"><FileText size={22} /><strong>Select a drill</strong><span>Drill details will appear here</span></div>
            )}
          </aside>
        </div>
      </div>
    </div>
  );
}
