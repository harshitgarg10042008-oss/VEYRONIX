/* Privacy Policy Page */
import { ShieldCheck, Lock, Eye, Database, Trash2 } from "lucide-react";

function SectionLabel({ children }: { children: React.ReactNode }) {
  return <div className="section-label">{children}</div>;
}

export default function PrivacyPolicy() {
  return (
    <div className="content-inner">
      <div className="page-intro">
        <div>
          <SectionLabel>LEGAL / PRIVACY POLICY</SectionLabel>
          <h1>Your data stays yours.</h1>
          <p>ConfigSentinel operates entirely on your local machine. No data leaves your workstation without your explicit consent. This document explains our privacy practices.</p>
        </div>
      </div>

      <div className="panel" style={{ padding: "32px" }}>
        <div className="evidence-block">
          <SectionLabel>DATA COLLECTION</SectionLabel>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--teal-soft)", color: "var(--teal)" }}><Database size={20} /></div>
            <div>
              <strong>Local-Only Processing</strong>
              <p className="muted-copy">All configuration scans, evidence collection, and analysis happen entirely on your local machine. ConfigSentinel does not send any configuration data, credentials, or evidence to external servers.</p>
            </div>
          </div>
        </div>

        <div className="evidence-block">
          <SectionLabel>DATA STORAGE</SectionLabel>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--teal-soft)", color: "var(--teal)" }}><Lock size={20} /></div>
            <div>
              <strong>Local Filesystem Storage</strong>
              <p className="muted-copy">All audit results, evidence bundles, and configuration snapshots are stored in your local filesystem. You have full control over data retention and deletion.</p>
            </div>
          </div>
        </div>

        <div className="evidence-block">
          <SectionLabel>DATA SHARING</SectionLabel>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--amber-soft)", color: "var(--amber)" }}><Eye size={20} /></div>
            <div>
              <strong>No Automatic Sharing</strong>
              <p className="muted-copy">ConfigSentinel never automatically shares your data. Any evidence export or sharing operation requires explicit user action through the Evidence Exchange feature.</p>
            </div>
          </div>
        </div>

        <div className="evidence-block">
          <SectionLabel>DATA DELETION</SectionLabel>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--teal-soft)", color: "var(--teal)" }}><Trash2 size={20} /></div>
            <div>
              <strong>Complete Control</strong>
              <p className="muted-copy">You can delete all local data at any time by removing the ConfigSentinel data directory. No data is retained on external servers.</p>
            </div>
          </div>
        </div>

        <div className="evidence-block">
          <SectionLabel>THIRD-PARTY SERVICES</SectionLabel>
          <p className="muted-copy">ConfigSentinel does not use any third-party analytics, tracking, or data processing services. The application is self-contained and operates offline.</p>
        </div>

        <div className="evidence-block">
          <SectionLabel>ENCRYPTION</SectionLabel>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--teal-soft)", color: "var(--teal)" }}><ShieldCheck size={20} /></div>
            <div>
              <strong>Cryptographic Protection</strong>
              <p className="muted-copy">Evidence bundles are cryptographically signed using SHA-256 hashing. The Notary Console provides tamper-evident seals for all exported evidence.</p>
            </div>
          </div>
        </div>

        <div className="evidence-block">
          <SectionLabel>CHILDREN'S PRIVACY</SectionLabel>
          <p className="muted-copy">ConfigSentinel is not intended for use by children under the age of 13. We do not knowingly collect any personal information from children.</p>
        </div>

        <div className="evidence-block">
          <SectionLabel>CHANGES TO THIS POLICY</SectionLabel>
          <p className="muted-copy">We may update this privacy policy from time to time. Any changes will be posted on this page with a revised effective date.</p>
        </div>

        <div className="evidence-block">
          <SectionLabel>CONTACT</SectionLabel>
          <p className="muted-copy">For questions about this privacy policy or ConfigSentinel's privacy practices, contact the Veyronix team through the official channels.</p>
        </div>

        <div className="evidence-footer">
          <span>Last updated: January 2025</span>
          <span>Version 1.0</span>
        </div>
      </div>
    </div>
  );
}
