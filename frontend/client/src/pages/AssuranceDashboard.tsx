import { useState } from "react";
import { useLocation } from "wouter";
import { Check, Clock, Fingerprint, Lock, Play, ShieldAlert, ShieldCheck } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

export default function AssuranceDashboard() {
  const [, setLocation] = useLocation();
  const [loopId, setLoopId] = useState("");
  const [chain, setChain] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchEvidenceChain = async () => {
    if (!loopId.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/verification-loops/${loopId}/evidence-chain`);
      if (!res.ok) {
        throw new Error("Failed to fetch evidence chain");
      }
      const data = await res.json();
      setChain(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="layout-app">
      <nav className="sidebar">
        <div className="brand">
          <Fingerprint size={24} />
          <strong>ConfigSentinel AI</strong>
        </div>
        <button onClick={() => setLocation("/")} className="nav-item">
          Back to Overview
        </button>
      </nav>
      
      <main className="main-content" style={{ padding: "2rem", overflowY: "auto" }}>
        <header style={{ marginBottom: "2rem" }}>
          <h1 style={{ fontSize: "1.5rem", fontWeight: "600", marginBottom: "0.5rem" }}>Assurance Chain Dashboard</h1>
          <p style={{ color: "var(--text-muted)" }}>Verify the cryptographic timeline of configuration changes.</p>
        </header>

        <div style={{ display: "flex", gap: "1rem", marginBottom: "2rem" }}>
          <input
            type="text"
            placeholder="Enter Verification Loop ID (e.g. loop_audit_xyz)"
            value={loopId}
            onChange={(e) => setLoopId(e.target.value)}
            style={{ padding: "0.75rem", borderRadius: "6px", border: "1px solid var(--border)", width: "300px" }}
          />
          <button 
            onClick={fetchEvidenceChain}
            disabled={loading}
            style={{ padding: "0.75rem 1.5rem", borderRadius: "6px", background: "var(--accent-blue)", color: "white", fontWeight: "500", border: "none", cursor: "pointer" }}
          >
            {loading ? "Verifying..." : "Fetch Proof"}
          </button>
        </div>

        {error && (
          <div style={{ padding: "1rem", borderRadius: "6px", background: "#fef2f2", color: "#b91c1c", border: "1px solid #f87171", marginBottom: "2rem" }}>
            <ShieldAlert style={{ display: "inline", verticalAlign: "middle", marginRight: "0.5rem" }} size={20} />
            {error}
          </div>
        )}

        {chain && chain.chain && (
          <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
            <div style={{ padding: "1.5rem", borderRadius: "8px", border: "1px solid var(--border)", background: "var(--bg-surface)" }}>
              <h3 style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
                <Clock size={18} /> 1. Baseline Audit
              </h3>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                <div><strong>Audit ID:</strong> <code>{chain.chain.baseline.audit_id}</code></div>
                <div><strong>Score:</strong> {chain.chain.baseline.score}/100</div>
                <div><strong>Input SHA256:</strong> <code>{chain.chain.baseline.input_sha256.slice(0, 16)}...</code></div>
                <div><strong>Failed Controls:</strong> {chain.chain.baseline.failed_controls.length}</div>
              </div>
            </div>

            <div style={{ padding: "1.5rem", borderRadius: "8px", border: "1px solid var(--border)", background: "var(--bg-surface)" }}>
              <h3 style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
                <Play size={18} /> 2. Proposal
              </h3>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                <div><strong>Bundle ID:</strong> <code>{chain.chain.proposal.bundle_id}</code></div>
                <div><strong>Remediations:</strong> {chain.chain.proposal.remediation_count}</div>
              </div>
            </div>

            <div style={{ padding: "1.5rem", borderRadius: "8px", border: "1px solid var(--border)", background: "var(--bg-surface)" }}>
              <h3 style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
                <Lock size={18} /> 3. Human Approval
              </h3>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                <div><strong>Actor ID:</strong> <code>{chain.chain.approval.actor_id}</code></div>
                <div><strong>Decision:</strong> <span style={{ color: chain.chain.approval.decision === "APPROVED" ? "#15803d" : "#b91c1c", fontWeight: "bold" }}>{chain.chain.approval.decision}</span></div>
                <div><strong>Timestamp:</strong> {new Date(chain.chain.approval.timestamp).toLocaleString()}</div>
              </div>
            </div>

            <div style={{ padding: "1.5rem", borderRadius: "8px", border: "1px solid var(--border)", background: "var(--bg-surface)" }}>
              <h3 style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
                <Check size={18} /> 4. Post-Change Verification
              </h3>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                <div><strong>Audit ID:</strong> <code>{chain.chain.post_change.audit_id}</code></div>
                <div><strong>Score:</strong> {chain.chain.post_change.score}/100</div>
                <div><strong>Input SHA256:</strong> <code>{chain.chain.post_change.input_sha256.slice(0, 16)}...</code></div>
                <div><strong>Failed Controls:</strong> {chain.chain.post_change.failed_controls.length}</div>
              </div>
            </div>

            <div style={{ padding: "1.5rem", borderRadius: "8px", border: "1px solid var(--accent-green)", background: "var(--bg-surface)" }}>
              <h3 style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem", color: "var(--accent-green)" }}>
                <ShieldCheck size={18} /> 5. Final Outcome
              </h3>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                <div><strong>Verification Status:</strong> {chain.chain.outcome.verification_status}</div>
                <div><strong>Score Improvement:</strong> +{chain.chain.outcome.score_improvement} points</div>
                <div><strong>Resolved Controls:</strong> {chain.chain.outcome.resolved_controls.length}</div>
                <div><strong>New Failures:</strong> {chain.chain.outcome.new_failures.length}</div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
