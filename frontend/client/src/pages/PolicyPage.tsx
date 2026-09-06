/* Policy Page - Security and Usage Policies */
import { ShieldCheck, AlertTriangle, Users, Lock, FileCheck, Zap } from "lucide-react";

function SectionLabel({ children }: { children: React.ReactNode }) {
  return <div className="section-label">{children}</div>;
}

export default function PolicyPage() {
  return (
    <div className="content-inner">
      <div className="page-intro">
        <div>
          <SectionLabel>LEGAL / SECURITY POLICIES</SectionLabel>
          <h1>Security and usage policies.</h1>
          <p>ConfigSentinel operates under strict security principles. These policies govern how the application handles data, ensures integrity, and maintains security posture.</p>
        </div>
      </div>

      <div className="panel" style={{ padding: "32px" }}>
        <div className="evidence-block">
          <SectionLabel>CORE SECURITY PRINCIPLES</SectionLabel>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--teal-soft)", color: "var(--teal)" }}><ShieldCheck size={20} /></div>
            <div>
              <strong>Deterministic Verification</strong>
              <p className="muted-copy">All security assessments are deterministic and reproducible. ConfigSentinel does not use probabilistic scoring or AI-based guessing for security verdicts.</p>
            </div>
          </div>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--teal-soft)", color: "var(--teal)" }}><Lock size={20} /></div>
            <div>
              <strong>Evidence Integrity</strong>
              <p className="muted-copy">All evidence is cryptographically hashed and tamper-evident. The Notary Console provides verifiable signatures for all evidence bundles.</p>
            </div>
          </div>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--teal-soft)", color: "var(--teal)" }}><FileCheck size={20} /></div>
            <div>
              <strong>Proof-Carrying Code</strong>
              <p className="muted-copy">Remediation recommendations include proof of correctness. All control packs are deterministic and verifiable.</p>
            </div>
          </div>
        </div>

        <div className="evidence-block">
          <SectionLabel>DATA HANDLING POLICY</SectionLabel>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--teal-soft)", color: "var(--teal)" }}><Users size={20} /></div>
            <div>
              <strong>Local Processing Only</strong>
              <p className="muted-copy">All configuration analysis happens on your local machine. No configuration data, credentials, or sensitive information leaves your workstation.</p>
            </div>
          </div>
        </div>

        <div className="evidence-block">
          <SectionLabel>ACCESS CONTROL POLICY</SectionLabel>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--amber-soft)", color: "var(--amber)" }}><AlertTriangle size={20} /></div>
            <div>
              <strong>Role-Based Access</strong>
              <p className="muted-copy">ConfigSentinel supports operator and reviewer roles. Operators can run audits and view results. Reviewers can resolve unknown evidence and approve remediation.</p>
            </div>
          </div>
        </div>

        <div className="evidence-block">
          <SectionLabel>AUDIT TRAIL POLICY</SectionLabel>
          <p className="muted-copy">All actions within ConfigSentinel are logged locally. The Incident Timeline feature provides an immutable record of configuration changes, evidence modifications, and approval decisions.</p>
        </div>

        <div className="evidence-block">
          <SectionLabel>VULNERABILITY DISCLOSURE</SectionLabel>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--danger-soft)", color: "var(--danger)" }}><AlertTriangle size={20} /></div>
            <div>
              <strong>Responsible Disclosure</strong>
              <p className="muted-copy">If you discover a security vulnerability in ConfigSentinel, please report it through official Veyronix channels. We will investigate and address all reports promptly.</p>
            </div>
          </div>
        </div>

        <div className="evidence-block">
          <SectionLabel>CHANGE MANAGEMENT POLICY</SectionLabel>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--teal-soft)", color: "var(--teal)" }}><Zap size={20} /></div>
            <div>
              <strong>Blast Radius Assessment</strong>
              <p className="muted-copy">Before any configuration change is applied, use the Blast Radius feature to assess potential impact. This is a required step for production changes.</p>
            </div>
          </div>
        </div>

        <div className="evidence-block">
          <SectionLabel>EVIDENCE RETENTION POLICY</SectionLabel>
          <p className="muted-copy">Evidence is retained locally according to your organization's policies. ConfigSentinel does not automatically delete evidence, but provides tools for evidence lifecycle management through the Technical Debt and Evidence Freshness features.</p>
        </div>

        <div className="evidence-block">
          <SectionLabel>COMPLIANCE CERTIFICATION</SectionLabel>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--amber-soft)", color: "var(--amber)" }}><AlertTriangle size={20} /></div>
            <div>
              <strong>Supports Assessment Only</strong>
              <p className="muted-copy">The Regulatory Export feature supports compliance assessment but does not constitute certification. Formal certification requires an authorized, independent assessment body.</p>
            </div>
          </div>
        </div>

        <div className="evidence-block">
          <SectionLabel>POLICY UPDATES</SectionLabel>
          <p className="muted-copy">These policies may be updated periodically. Significant changes will be announced through the application and documented in the changelog.</p>
        </div>

        <div className="evidence-footer">
          <span>Last updated: January 2025</span>
          <span>Version 1.0</span>
        </div>
      </div>
    </div>
  );
}
