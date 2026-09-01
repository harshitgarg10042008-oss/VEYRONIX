/* Incident Timeline Page — post-incident state reconstruction, read-only. */
import { useState } from "react";
import { Clock3, AlertTriangle, FileText, Plus } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type TimelineEvent = {
  event_id: string;
  event_type: string;
  timestamp: string;
  actor_id: string;
  description: string;
  affected_controls: string[];
  affected_assets: string[];
  severity: string;
  metadata: Record<string, string>;
};

type TimelineResult = {
  timeline_id: string;
  incident_id: string;
  events: TimelineEvent[];
  total_events: number;
  start_time: string;
  end_time: string;
  affected_control_count: number;
  affected_asset_count: number;
};

const SEV_TONE: Record<string, string> = {
  CRITICAL: "danger",
  HIGH: "danger",
  MEDIUM: "warn",
  LOW: "neutral",
  INFO: "safe",
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

export default function TimelinePage() {
  const [incidentId, setIncidentId] = useState("");
  const [newEvent, setNewEvent] = useState({ description: "", event_type: "config_change", actor_id: "", severity: "MEDIUM" });
  const [timeline, setTimeline] = useState<TimelineResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState("");
  const [selected, setSelected] = useState<TimelineEvent | null>(null);

  const loadTimeline = async () => {
    if (!incidentId.trim()) return setToast("Incident ID is required");
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/timeline/${encodeURIComponent(incidentId)}`);
      if (!res.ok) throw new Error(`Timeline returned ${res.status}`);
      const data = await res.json() as TimelineResult;
      setTimeline(data);
      setSelected(data.events[0] ?? null);
      setToast(`Timeline loaded · ${data.total_events} events`);
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "start the local API"}`);
    } finally {
      setLoading(false);
    }
  };

  const addEvent = async () => {
    if (!incidentId.trim() || !newEvent.description.trim()) return setToast("Incident ID and description required");
    try {
      const res = await fetch(`${API_BASE}/api/timeline/${encodeURIComponent(incidentId)}/events`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newEvent),
      });
      if (!res.ok) throw new Error(`Add event returned ${res.status}`);
      setToast("Event recorded");
      await loadTimeline();
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "unknown"}`);
    }
  };

  return (
    <div className="content-scroll">
      <div className="content-inner">
        <div className="page-intro">
          <div>
            <SectionLabel>INCIDENT TIMELINE / POST-INCIDENT STATE</SectionLabel>
            <h1>Reconstruct what happened, when.</h1>
            <p>Build an immutable, chronological record of configuration events, findings changes, and actor decisions following a security incident. Evidence is preserved, not rewritten.</p>
          </div>
          <div className="intro-action">
            <span className="queue-readout"><Clock3 size={14} /> POST-INCIDENT</span>
          </div>
        </div>

        <div className="website-scan-form">
          <div className="form-row">
            <label>Incident ID</label>
            <input type="text" placeholder="INC-2024-001" value={incidentId} onChange={e => setIncidentId(e.target.value)} style={{ flex: 2 }} />
            <button className="button button-secondary" type="button" onClick={loadTimeline} disabled={loading}>
              <Clock3 size={15} /> {loading ? "Loading…" : "Load Timeline"}
            </button>
          </div>
          <div className="form-row" style={{ borderTop: "1px solid var(--line)", paddingTop: 16 }}>
            <label>Record Event</label>
            <select value={newEvent.event_type} onChange={e => setNewEvent({ ...newEvent, event_type: e.target.value })}>
              <option value="config_change">Config Change</option>
              <option value="finding_change">Finding Change</option>
              <option value="approval_event">Approval Event</option>
              <option value="remediation_applied">Remediation Applied</option>
              <option value="scan_completed">Scan Completed</option>
            </select>
            <input type="text" placeholder="Actor ID (e.g. ops-eng@corp)" value={newEvent.actor_id} onChange={e => setNewEvent({ ...newEvent, actor_id: e.target.value })} />
            <select value={newEvent.severity} onChange={e => setNewEvent({ ...newEvent, severity: e.target.value })}>
              {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div className="form-row">
            <input type="text" placeholder="Event description…" value={newEvent.description} onChange={e => setNewEvent({ ...newEvent, description: e.target.value })} style={{ flex: 3 }} />
            <button className="button button-primary" type="button" onClick={addEvent}>
              <Plus size={15} /> Record Event
            </button>
          </div>
        </div>

        {toast && (
          <div className="queue-banner" style={{ marginBottom: 16 }}>
            <div className="queue-icon"><AlertTriangle size={18} /></div>
            <span>{toast}</span>
          </div>
        )}

        {timeline && (
          <>
            <div className="scan-summary">
              <Metric label="TOTAL EVENTS" value={timeline.total_events.toString()} note="chronological record" tone="neutral" />
              <Metric label="AFFECTED CONTROLS" value={timeline.affected_control_count.toString()} note="controls in scope" tone="warn" />
              <Metric label="AFFECTED ASSETS" value={timeline.affected_asset_count.toString()} note="assets in scope" tone="neutral" />
              <Metric label="TIMELINE SPAN" value={`${Math.round((new Date(timeline.end_time).getTime() - new Date(timeline.start_time).getTime()) / 3600000)}h`} note={new Date(timeline.start_time).toLocaleDateString()} tone="neutral" />
            </div>

            <div className="two-column">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <SectionLabel>EVENTS / {timeline.timeline_id}</SectionLabel>
                    <h2>Chronological incident events</h2>
                  </div>
                  <span className="count-badge">{timeline.events.length.toString().padStart(2, "0")}</span>
                </div>
                <div className="findings-table">
                  <div className="table-head"><span>EVENT / ACTOR</span><span>TYPE</span><span>SEVERITY</span><span>TIME</span></div>
                  {timeline.events.length === 0
                    ? <EmptyState title="No events recorded" detail="Use the form above to record the first timeline event." />
                    : timeline.events.map(ev => (
                      <button
                        type="button"
                        key={ev.event_id}
                        className={`finding-row ${selected?.event_id === ev.event_id ? "finding-selected" : ""}`}
                        onClick={() => setSelected(ev)}
                      >
                        <span className="finding-main">
                          <span className={`finding-symbol symbol-${SEV_TONE[ev.severity] ?? "neutral"}`}>
                            {ev.severity === "CRITICAL" || ev.severity === "HIGH" ? "!" : "·"}
                          </span>
                          <span>
                            <strong>{ev.description}</strong>
                            <small>{ev.actor_id || "system"}</small>
                          </span>
                        </span>
                        <span className="vendor-label">{ev.event_type.replace(/_/g, " ")}</span>
                        <span className={`severity severity-${ev.severity.toLowerCase()}`}>{ev.severity}</span>
                        <span className="vendor-label">{new Date(ev.timestamp).toLocaleTimeString()}</span>
                      </button>
                    ))
                  }
                </div>
              </section>

              <aside className="evidence-panel">
                <div className="evidence-top">
                  <SectionLabel>SELECTED EVENT</SectionLabel>
                  <span className="proof-tag"><FileText size={12} /> TIMELINE</span>
                </div>
                {selected ? (
                  <>
                    <div className="evidence-id">{selected.event_id} · {selected.event_type.replace(/_/g, " ").toUpperCase()}</div>
                    <h2>{selected.description}</h2>
                    <div className="evidence-block">
                      <SectionLabel>EVENT DETAILS</SectionLabel>
                      <div className="evidence-line"><code>ACT</code><span>Actor: {selected.actor_id || "system"}</span></div>
                      <div className="evidence-line"><code>AT</code><span>Time: {new Date(selected.timestamp).toLocaleString()}</span></div>
                      <div className="evidence-line"><code>SEV</code><span>Severity: {selected.severity}</span></div>
                    </div>
                    {selected.affected_controls.length > 0 && (
                      <div className="evidence-block">
                        <SectionLabel>AFFECTED CONTROLS</SectionLabel>
                        {selected.affected_controls.map(c => (
                          <div key={c} className="evidence-line"><code>CTL</code><span>{c}</span></div>
                        ))}
                      </div>
                    )}
                    {selected.affected_assets.length > 0 && (
                      <div className="evidence-block">
                        <SectionLabel>AFFECTED ASSETS</SectionLabel>
                        {selected.affected_assets.map(a => (
                          <div key={a} className="evidence-line"><code>AST</code><span>{a}</span></div>
                        ))}
                      </div>
                    )}
                    <div className="evidence-footer">
                      <span>timeline/{timeline.timeline_id}</span>
                      <span>Immutable — evidence preserved as-recorded</span>
                    </div>
                  </>
                ) : (
                  <EmptyState title="Select an event" detail="Event details will appear here." />
                )}
              </aside>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
