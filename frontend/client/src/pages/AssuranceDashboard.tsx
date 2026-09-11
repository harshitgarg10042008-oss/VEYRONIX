/* Assurance Chain Dashboard — evidence-timeline viewer with cryptographic verification. */
import { useState } from "react";
import { Check, Clock, Fingerprint, Lock, Play, ShieldAlert, ShieldCheck, Activity, ChevronRight } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

function SectionLabel({ children }: { children: React.ReactNode }) {
  return <div className="section-label">{children}</div>;
}

function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="empty-state">
      <ShieldCheck size={22} />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

const STEP_ICONS = [Clock, Play, Lock, Check, ShieldCheck];
const STEP_LABELS = ["Baseline Audit", "Proposal", "Human Approval", "Post-Change Verification", "Final Outcome"];

export default function AssuranceDashboard() {
  const [loopId, setLoopId] = useState("");
  const [chain, setChain] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState(0);

  const fetchEvidenceChain = async () => {
    if (!loopId.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/verification-loops/${loopId.trim()}/evidence-chain`);
      if (!res.ok) {
        if (res.status === 404) {
          throw new Error("Verification loop not found. Create a loop from a baseline audit and paste its generated ID here.");
        }
        throw new Error(`API returned ${res.status} — try again or check the local API`);
      }
      const data = await res.json();
      setChain(data);
      setSelected(0);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const c = chain?.chain;

  const steps = c
    ? [
      {
        label: "Baseline Audit",
        icon: Clock,
        tone: "neutral",
        rows: [
          ["Audit ID", <code key="a">{c.baseline?.audit_id}</code>],
          ["Score", `${c.baseline?.score}/100`],
          ["Input SHA256", <code key="h">{c.baseline?.input_sha256?.slice(0, 16)}…</code>],
          ["Failed Controls", c.baseline?.failed_controls?.length ?? 0],
        ],
      },
      {
        label: "Proposal",
        icon: Play,
        tone: "neutral",
        rows: [
          ["Bundle ID", <code key="b">{c.proposal?.bundle_id}</code>],
          ["Remediations", c.proposal?.remediation_count ?? 0],
        ],
      },
      {
        label: "Human Approval",
        icon: Lock,
        tone: "warn",
        rows: [
          ["Actor ID", <code key="ac">{c.approval?.actor_id}</code>],
          ["Decision", <span key="dec" style={{ fontWeight: 700, color: c.approval?.decision === "APPROVED" ? "var(--status-pass)" : "var(--status-fail)" }}>{c.approval?.decision}</span>],
          ["Timestamp", c.approval?.timestamp ? new Date(c.approval.timestamp).toLocaleString() : "—"],
        ],
      },
      {
        label: "Post-Change Verification",
        icon: Check,
        tone: "neutral",
        rows: [
          ["Audit ID", <code key="pc">{c.post_change?.audit_id}</code>],
          ["Score", `${c.post_change?.score}/100`],
          ["Input SHA256", <code key="pch">{c.post_change?.input_sha256?.slice(0, 16)}…</code>],
          ["Failed Controls", c.post_change?.failed_controls?.length ?? 0],
        ],
      },
      {
        label: "Final Outcome",
        icon: ShieldCheck,
        tone: "verified",
        rows: [
          ["Status", <span key="vs" style={{ fontWeight: 700, color: "var(--status-pass)" }}>{c.outcome?.verification_status}</span>],
          ["Score Improvement", `+${c.outcome?.score_improvement ?? 0} pts`],
          ["Resolved Controls", c.outcome?.resolved_controls?.length ?? 0],
          ["New Failures", c.outcome?.new_failures?.length ?? 0],
        ],
      },
    ]
    : [];

  const activeStep = steps[selected];

  return (
    <>
      {/* Header */}
      <div className="page-intro">
        <div>
          <SectionLabel>ASSURANCE CHAIN / CRYPTOGRAPHIC TIMELINE</SectionLabel>
          <h1>Verify the evidence chain.</h1>
          <p>
            Inspect the cryptographic timeline linking a baseline audit, remediation proposal,
            human approval, and post-change verification into a single tamper-evident chain.
          </p>
        </div>
        <div className="intro-action">
          <span className="queue-readout">
            <ShieldCheck size={14} /> REVIEW-ONLY
          </span>
        </div>
      </div>

      {/* Search form */}
      <div className="website-scan-form">
        <div className="form-row">
          <label>Verification Loop ID</label>
          <input
            type="text"
            placeholder="e.g. loop_audit_abc123"
            value={loopId}
            onChange={(e) => setLoopId(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && fetchEvidenceChain()}
            style={{ flex: 3 }}
          />
          <button
            className="button button-primary"
            type="button"
            onClick={fetchEvidenceChain}
            disabled={loading}
          >
            <Activity size={15} /> {loading ? "Verifying…" : "Fetch Proof Chain"}
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="queue-banner" style={{ marginBottom: 16, borderColor: "var(--status-fail)" }}>
          <div className="queue-icon"><ShieldAlert size={18} /></div>
          <span>{error}</span>
        </div>
      )}

      {/* Empty / placeholder */}
      {!c && !error && !loading && (
        <EmptyState
          title="Enter a verification loop ID above"
          detail="The evidence chain will display here once fetched. Completed verification loops are created when you run a full audit → propose → approve → re-audit cycle."
        />
      )}

      {/* Chain steps */}
      {c && (
        <div className="two-column">
          {/* Step list */}
          <section className="panel">
            <div className="panel-head">
              <div>
                <SectionLabel>CHAIN STEPS / {loopId}</SectionLabel>
                <h2>Evidence timeline</h2>
              </div>
              <span className="count-badge">{steps.length.toString().padStart(2, "0")}</span>
            </div>
            <div className="findings-table">
              <div className="table-head">
                <span>STEP</span><span>LABEL</span><span>STATUS</span>
              </div>
              {steps.map((step, i) => {
                const Icon = step.icon;
                return (
                  <button
                    key={step.label}
                    type="button"
                    className={`finding-row ${selected === i ? "finding-selected" : ""}`}
                    onClick={() => setSelected(i)}
                  >
                    <span className="finding-main">
                      <span className={`finding-symbol symbol-${step.tone}`}>{i + 1}</span>
                      <span>
                        <strong>{step.label}</strong>
                        <small>{step.rows.length} fields</small>
                      </span>
                    </span>
                    <span className={`status-pill status-${step.tone}`}>
                      <span className="status-dot" />
                      <Icon size={12} />
                    </span>
                    <ChevronRight size={14} style={{ opacity: 0.4 }} />
                  </button>
                );
              })}
            </div>
          </section>

          {/* Step detail */}
          <aside className="evidence-panel">
            <div className="evidence-top">
              <SectionLabel>STEP DETAIL</SectionLabel>
              <span className="proof-tag"><ShieldCheck size={12} /> CRYPTOGRAPHIC</span>
            </div>
            {activeStep ? (
              <>
                <div className="evidence-id">
                  Step {selected + 1} · {activeStep.label}
                </div>
                {activeStep.rows.map(([label, value]) => (
                  <div className="evidence-block" key={String(label)}>
                    <SectionLabel>{String(label).toUpperCase()}</SectionLabel>
                    <div className="evidence-state">{value}</div>
                  </div>
                ))}
                <div className="evidence-footer">
                  <span>loop/{loopId}</span>
                  <span>All evidence is tamper-evident and review-only</span>
                </div>
              </>
            ) : (
              <EmptyState title="Select a step" detail="Details will appear here." />
            )}
          </aside>
        </div>
      )}
    </>
  );
}
