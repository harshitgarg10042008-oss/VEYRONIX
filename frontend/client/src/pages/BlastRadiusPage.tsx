/* Blast Radius Page — pre-change impact simulation, read-only, review-only. */
import { useState } from "react";
import { AlertTriangle, Zap, ShieldCheck, FileText, Activity } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type ImpactLabel = "DIRECT" | "DEPENDENT" | "POSSIBLE" | "UNKNOWN";
type Impact = {
  target_id: string;
  target_type: string;
  impact_label: ImpactLabel;
  rationale: string;
  evidence_required: boolean;
};
type SimulationResult = {
  simulation_id: string;
  proposed_change_id: string;
  proposed_at: string;
  impacts: Impact[];
  total_affected: number;
  direct_impact_count: number;
  dependent_impact_count: number;
  possible_impact_count: number;
  unknown_impact_count: number;
  required_post_change_checks: string[];
  limitations: string[];
};

const LABEL_TONE: Record<ImpactLabel, string> = {
  DIRECT: "danger",
  DEPENDENT: "warn",
  POSSIBLE: "neutral",
  UNKNOWN: "safe",
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
      <AlertTriangle size={22} />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

export default function BlastRadiusPage() {
  const [changeDescription, setChangeDescription] = useState("");
  const [changeType, setChangeType] = useState("remediation");
  const [affectedControls, setAffectedControls] = useState("");
  const [affectedAssets, setAffectedAssets] = useState("");
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [simulating, setSimulating] = useState(false);
  const [toast, setToast] = useState("");
  const [selectedImpact, setSelectedImpact] = useState<Impact | null>(null);

  const runSimulation = async () => {
    if (!changeDescription.trim()) return setToast("Change description is required");
    setSimulating(true);
    try {
      const body = {
        change_description: changeDescription,
        change_type: changeType,
        affected_controls: affectedControls.split(",").map(s => s.trim()).filter(Boolean),
        affected_assets: affectedAssets.split(",").map(s => s.trim()).filter(Boolean),
      };
      const res = await fetch(`${API_BASE}/api/blast-radius/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`Simulation returned ${res.status}`);
      const data = await res.json() as SimulationResult;
      setResult(data);
      setSelectedImpact(data.impacts[0] ?? null);
      setToast(`Simulation complete · ${data.total_affected} impacted targets`);
    } catch (e) {
      setToast(`Simulation failed · ${e instanceof Error ? e.message : "start the local API"}`);
    } finally {
      setSimulating(false);
    }
  };

  const impactBadge = (label: ImpactLabel) => (
    <span className={`status-pill status-${LABEL_TONE[label]}`}>
      <span className="status-dot" />{label}
    </span>
  );

  return (
    <div className="content-scroll">
      <div className="content-inner">
        {/* Header */}
        <div className="page-intro">
          <div>
            <SectionLabel>BLAST RADIUS / PRE-CHANGE SIMULATION</SectionLabel>
            <h1>Assess before you change.</h1>
            <p>Predict which controls, assets, and trust boundaries are affected by a proposed configuration change. No device is touched. Results are review-only impact predictions.</p>
          </div>
          <div className="intro-action">
            <span className="queue-readout"><AlertTriangle size={14} /> SIMULATION ONLY</span>
          </div>
        </div>

        {/* Input form */}
        <div className="queue-banner" style={{ marginBottom: 24 }}>
          <div className="queue-icon"><Zap size={22} /></div>
          <div>
            <strong>No device connection.</strong>
            <span>This simulation predicts impact from a described change. No configuration is applied, no device is contacted, and no verdict is created.</span>
          </div>
          <span className="proof-tag">READ-ONLY</span>
        </div>

        <div className="website-scan-form">
          <div className="form-row">
            <label>Change Type</label>
            <select value={changeType} onChange={e => setChangeType(e.target.value)}>
              <option value="remediation">Remediation</option>
              <option value="config_update">Config Update</option>
              <option value="service_change">Service Change</option>
            </select>
            <label>Affected Controls (comma-separated)</label>
            <input type="text" placeholder="NET-001, NET-007" value={affectedControls} onChange={e => setAffectedControls(e.target.value)} />
            <label>Affected Assets (comma-separated)</label>
            <input type="text" placeholder="firewall-01, switch-core" value={affectedAssets} onChange={e => setAffectedAssets(e.target.value)} />
          </div>
          <div className="form-row">
            <label>Change Description</label>
            <input
              type="text"
              placeholder="Disable telnet on VTY lines, enable SSH-only transport"
              value={changeDescription}
              onChange={e => setChangeDescription(e.target.value)}
              style={{ flex: 3 }}
            />
            <button className="button button-primary" type="button" onClick={runSimulation} disabled={simulating}>
              <Zap size={15} /> {simulating ? "Simulating…" : "Simulate Blast Radius"}
            </button>
          </div>
        </div>

        {toast && (
          <div className="queue-banner" style={{ marginBottom: 16 }}>
            <div className="queue-icon"><Activity size={18} /></div>
            <span>{toast}</span>
          </div>
        )}

        {result && (
          <>
            <div className="scan-summary">
              <Metric label="TOTAL AFFECTED" value={result.total_affected.toString()} note="targets in impact radius" tone={result.total_affected > 0 ? "warn" : "verified"} />
              <Metric label="DIRECT" value={result.direct_impact_count.toString()} note="deterministic impact" tone={result.direct_impact_count > 0 ? "danger" : "verified"} />
              <Metric label="DEPENDENT" value={result.dependent_impact_count.toString()} note="downstream dependencies" tone={result.dependent_impact_count > 0 ? "warn" : "neutral"} />
              <Metric label="POSSIBLE" value={result.possible_impact_count.toString()} note="uncertain, needs review" tone="neutral" />
            </div>

            <div className="two-column">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <SectionLabel>IMPACT ANALYSIS / {result.simulation_id}</SectionLabel>
                    <h2>Predicted affected targets</h2>
                  </div>
                  <span className="count-badge">{result.impacts.length.toString().padStart(2, "0")}</span>
                </div>
                <div className="findings-table">
                  <div className="table-head"><span>TARGET</span><span>TYPE</span><span>IMPACT</span><span>VERIFY?</span></div>
                  {result.impacts.length === 0
                    ? <EmptyState title="No impacts predicted" detail="The proposed change has no deterministic blast radius against the current scope." />
                    : result.impacts.map(impact => (
                      <button
                        type="button"
                        key={`${impact.target_id}-${impact.target_type}`}
                        className={`finding-row ${selectedImpact?.target_id === impact.target_id ? "finding-selected" : ""}`}
                        onClick={() => setSelectedImpact(impact)}
                      >
                        <span className="finding-main">
                          <span className={`finding-symbol symbol-${LABEL_TONE[impact.impact_label]}`}>
                            {impact.impact_label === "DIRECT" ? "!" : impact.impact_label === "DEPENDENT" ? "↓" : "?"}
                          </span>
                          <span><strong>{impact.target_id}</strong><small>{impact.rationale}</small></span>
                        </span>
                        <span className="vendor-label">{impact.target_type}</span>
                        {impactBadge(impact.impact_label)}
                        <span className={`status-pill ${impact.evidence_required ? "status-fail" : "status-pass"}`}>
                          <span className="status-dot" />{impact.evidence_required ? "VERIFY" : "OPTIONAL"}
                        </span>
                      </button>
                    ))
                  }
                </div>
              </section>

              <aside className="evidence-panel">
                <div className="evidence-top">
                  <SectionLabel>SELECTED IMPACT</SectionLabel>
                  <span className="proof-tag"><ShieldCheck size={12} /> PREDICTION</span>
                </div>
                {selectedImpact ? (
                  <>
                    <div className="evidence-id">{selectedImpact.target_id} · {selectedImpact.target_type}</div>
                    <h2>{selectedImpact.rationale}</h2>
                    <div className="evidence-block">
                      <SectionLabel>IMPACT CLASSIFICATION</SectionLabel>
                      {impactBadge(selectedImpact.impact_label)}
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>POST-CHANGE VERIFICATION</SectionLabel>
                      <div className="evidence-state">
                        <span className={`status-pill ${selectedImpact.evidence_required ? "status-fail" : "status-pass"}`}>
                          <span className="status-dot" />
                          {selectedImpact.evidence_required ? "REQUIRED — collect evidence after change" : "OPTIONAL — low-risk target"}
                        </span>
                      </div>
                    </div>
                    {result.required_post_change_checks.length > 0 && (
                      <div className="evidence-block">
                        <SectionLabel>REQUIRED POST-CHANGE CHECKS</SectionLabel>
                        {result.required_post_change_checks.map(check => (
                          <div key={check} className="evidence-line">
                            <code>CHK</code><span>{check}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    <div className="evidence-footer">
                      <span>sim/{result.simulation_id}</span>
                      <span>Predictions require post-change evidence to confirm</span>
                    </div>
                  </>
                ) : (
                  <EmptyState title="Select a target" detail="Impact details will appear here." />
                )}
              </aside>
            </div>

            {result.limitations.length > 0 && (
              <div className="queue-banner" style={{ marginTop: 24, borderColor: "var(--line-strong)" }}>
                <div className="queue-icon"><FileText size={18} /></div>
                <div>
                  <strong>Simulation limitations</strong>
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
