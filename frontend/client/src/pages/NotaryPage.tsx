/* Notary Console — cryptographic evidence signing and verification. */
import { useState } from "react";
import { LockKeyhole, ShieldCheck, FileText, Check } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type NotarizedBundle = {
  bundle_id: string;
  audit_id: string;
  created_at: string;
  signature: string;
  payload_hash: string;
  algorithm: string;
  notary_version: string;
};

type VerificationResult = {
  bundle_id: string;
  valid: boolean;
  audit_id: string;
  verified_at: string;
  payload_hash: string;
  algorithm: string;
  failure_reason?: string;
};

function SectionLabel({ children }: { children: React.ReactNode }) {
  return <div className="section-label">{children}</div>;
}

export default function NotaryPage() {
  const [auditId, setAuditId] = useState("");
  const [bundleJson, setBundleJson] = useState("");
  const [signResult, setSignResult] = useState<NotarizedBundle | null>(null);
  const [verifyResult, setVerifyResult] = useState<VerificationResult | null>(null);
  const [signing, setSigning] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [toast, setToast] = useState("");
  const [tab, setTab] = useState<"sign" | "verify">("sign");

  const sign = async () => {
    if (!auditId.trim()) return setToast("Audit ID is required");
    setSigning(true);
    try {
      const res = await fetch(`${API_BASE}/api/notary/sign`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ audit_id: auditId }),
      });
      if (!res.ok) throw new Error(`Sign returned ${res.status}`);
      const data = await res.json() as NotarizedBundle;
      setSignResult(data);
      setBundleJson(JSON.stringify(data, null, 2));
      setToast(`Bundle signed · ${data.bundle_id}`);
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "start the local API"}`);
    } finally {
      setSigning(false);
    }
  };

  const verify = async () => {
    if (!bundleJson.trim()) return setToast("Paste a bundle JSON to verify");
    setVerifying(true);
    try {
      let parsed: NotarizedBundle;
      try { parsed = JSON.parse(bundleJson); } catch { throw new Error("Invalid JSON"); }
      const res = await fetch(`${API_BASE}/api/notary/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ bundle: parsed }),
      });
      if (!res.ok) throw new Error(`Verify returned ${res.status}`);
      const data = await res.json() as VerificationResult;
      setVerifyResult(data);
      setToast(data.valid ? "Bundle verified — signature is valid" : `Verification failed · ${data.failure_reason}`);
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "unknown"}`);
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="content-scroll">
      <div className="content-inner">
        <div className="page-intro">
          <div>
            <SectionLabel>NOTARY CONSOLE / CRYPTOGRAPHIC SIGNING</SectionLabel>
            <h1>Sign evidence. Prove it hasn't changed.</h1>
            <p>Notarize audit findings with a deterministic hash signature. Verifying a bundle confirms that evidence has not been modified since signing. The signature is not an approval — it is a tamper-evidence seal.</p>
          </div>
          <div className="intro-action">
            <span className="queue-readout"><LockKeyhole size={14} /> TAMPER-EVIDENT</span>
          </div>
        </div>

        <div className="queue-banner" style={{ marginBottom: 24 }}>
          <div className="queue-icon"><LockKeyhole size={22} /></div>
          <div>
            <strong>Signature ≠ approval.</strong>
            <span>A signed bundle proves integrity of evidence at time of signing. It does not authorize any configuration change or override a deterministic verdict.</span>
          </div>
          <span className="proof-tag">REVIEW ONLY</span>
        </div>

        {/* Tab selector */}
        <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
          <button type="button" className={`button ${tab === "sign" ? "button-primary" : "button-secondary"}`} onClick={() => setTab("sign")}>
            <LockKeyhole size={15} /> Sign Bundle
          </button>
          <button type="button" className={`button ${tab === "verify" ? "button-primary" : "button-secondary"}`} onClick={() => setTab("verify")}>
            <ShieldCheck size={15} /> Verify Bundle
          </button>
        </div>

        {tab === "sign" && (
          <div className="website-scan-form">
            <div className="form-row">
              <label>Audit ID to Notarize</label>
              <input type="text" placeholder="audit-uuid" value={auditId} onChange={e => setAuditId(e.target.value)} style={{ flex: 2 }} />
              <button className="button button-primary" type="button" onClick={sign} disabled={signing}>
                <LockKeyhole size={15} /> {signing ? "Signing…" : "Sign"}
              </button>
            </div>
          </div>
        )}

        {tab === "verify" && (
          <div className="website-scan-form">
            <div className="form-row" style={{ flexDirection: "column", alignItems: "stretch" }}>
              <label>Bundle JSON</label>
              <textarea
                rows={10}
                placeholder={`Paste the notarized bundle JSON here…\n{\n  "bundle_id": "…",\n  "signature": "…"\n}`}
                value={bundleJson}
                onChange={e => setBundleJson(e.target.value)}
                style={{ fontFamily: "monospace", fontSize: 12, padding: 10, border: "1px solid var(--line)", background: "var(--surface)", color: "var(--ink)", resize: "vertical", borderRadius: 4 }}
              />
              <button className="button button-primary" type="button" onClick={verify} disabled={verifying} style={{ alignSelf: "flex-start", marginTop: 8 }}>
                <ShieldCheck size={15} /> {verifying ? "Verifying…" : "Verify Signature"}
              </button>
            </div>
          </div>
        )}

        {toast && (
          <div className="queue-banner" style={{ marginBottom: 16 }}>
            <div className="queue-icon"><FileText size={18} /></div>
            <span>{toast}</span>
          </div>
        )}

        {tab === "sign" && signResult && (
          <div className="two-column" style={{ marginTop: 24 }}>
            <section className="panel">
              <div className="panel-head">
                <div>
                  <SectionLabel>NOTARIZED BUNDLE</SectionLabel>
                  <h2>Signed evidence artifact</h2>
                </div>
                <span className="proof-tag"><LockKeyhole size={12} /> SIGNED</span>
              </div>
              <div style={{ padding: "0 16px 16px" }}>
                <div className="evidence-block">
                  <SectionLabel>BUNDLE ID</SectionLabel>
                  <div className="evidence-line"><code>ID</code><span style={{ wordBreak: "break-all" }}>{signResult.bundle_id}</span></div>
                </div>
                <div className="evidence-block">
                  <SectionLabel>PAYLOAD HASH ({signResult.algorithm})</SectionLabel>
                  <div className="evidence-line"><code>SHA</code><span style={{ wordBreak: "break-all", fontFamily: "monospace", fontSize: 11 }}>{signResult.payload_hash}</span></div>
                </div>
                <div className="evidence-block">
                  <SectionLabel>SIGNATURE</SectionLabel>
                  <div style={{ wordBreak: "break-all", fontFamily: "monospace", fontSize: 11, background: "var(--surface)", padding: "8px 10px", borderRadius: 4, border: "1px solid var(--line)" }}>
                    {signResult.signature}
                  </div>
                </div>
                <div className="evidence-block">
                  <SectionLabel>METADATA</SectionLabel>
                  <div className="evidence-line"><code>AT</code><span>{new Date(signResult.created_at).toLocaleString()}</span></div>
                  <div className="evidence-line"><code>VER</code><span>Notary {signResult.notary_version}</span></div>
                </div>
              </div>
            </section>
            <aside className="evidence-panel">
              <div className="evidence-top"><SectionLabel>BUNDLE JSON</SectionLabel><span className="proof-tag">EXPORT</span></div>
              <div style={{ padding: "0 0 16px" }}>
                <textarea
                  readOnly
                  rows={18}
                  value={bundleJson}
                  style={{ width: "100%", fontFamily: "monospace", fontSize: 11, padding: 10, border: "1px solid var(--line)", background: "var(--surface)", color: "var(--muted)", resize: "none", borderRadius: 4 }}
                />
                <p className="muted-copy" style={{ marginTop: 8 }}>Copy and store this bundle. It can be used to verify evidence integrity at any future point.</p>
              </div>
            </aside>
          </div>
        )}

        {tab === "verify" && verifyResult && (
          <div className="scan-summary" style={{ marginTop: 24 }}>
            <div className={`metric metric-${verifyResult.valid ? "verified" : "danger"}`}>
              <SectionLabel>VERIFICATION RESULT</SectionLabel>
              <strong>{verifyResult.valid ? "VALID" : "INVALID"}</strong>
              <span>{verifyResult.valid ? "Signature matches payload hash" : verifyResult.failure_reason ?? "Signature mismatch"}</span>
            </div>
            <div className="metric metric-neutral">
              <SectionLabel>BUNDLE ID</SectionLabel>
              <strong style={{ fontSize: 11, wordBreak: "break-all" }}>{verifyResult.bundle_id}</strong>
              <span>{new Date(verifyResult.verified_at).toLocaleString()}</span>
            </div>
            <div className="metric metric-neutral">
              <SectionLabel>AUDIT ID</SectionLabel>
              <strong style={{ fontSize: 13 }}>{verifyResult.audit_id}</strong>
              <span>source audit reference</span>
            </div>
            {verifyResult.valid && (
              <div className="metric metric-verified">
                <SectionLabel>TAMPER STATUS</SectionLabel>
                <strong><Check size={20} /></strong>
                <span>Evidence has not been modified since signing</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
