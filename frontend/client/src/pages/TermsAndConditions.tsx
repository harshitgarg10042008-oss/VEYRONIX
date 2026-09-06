/* Terms & Conditions Page */
import { FileText, AlertTriangle, CheckCircle, Scale } from "lucide-react";

function SectionLabel({ children }: { children: React.ReactNode }) {
  return <div className="section-label">{children}</div>;
}

export default function TermsAndConditions() {
  return (
    <div className="content-inner">
      <div className="page-intro">
        <div>
          <SectionLabel>LEGAL / TERMS & CONDITIONS</SectionLabel>
          <h1>Terms of Service.</h1>
          <p>By using ConfigSentinel, you agree to these terms. Please read them carefully before using the application.</p>
        </div>
      </div>

      <div className="panel" style={{ padding: "32px" }}>
        <div className="evidence-block">
          <SectionLabel>ACCEPTANCE OF TERMS</SectionLabel>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--teal-soft)", color: "var(--teal)" }}><CheckCircle size={20} /></div>
            <div>
              <strong>Agreement</strong>
              <p className="muted-copy">By accessing or using ConfigSentinel, you agree to be bound by these Terms and Conditions. If you do not agree to these terms, please do not use the application.</p>
            </div>
          </div>
        </div>

        <div className="evidence-block">
          <SectionLabel>LICENSE GRANT</SectionLabel>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--teal-soft)", color: "var(--teal)" }}><FileText size={20} /></div>
            <div>
              <strong>Usage License</strong>
              <p className="muted-copy">Veyronix grants you a personal, non-exclusive, non-transferable license to use ConfigSentinel for internal security auditing and configuration management purposes.</p>
            </div>
          </div>
        </div>

        <div className="evidence-block">
          <SectionLabel>USE RESTRICTIONS</SectionLabel>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--danger-soft)", color: "var(--danger)" }}><AlertTriangle size={20} /></div>
            <div>
              <strong>Prohibited Uses</strong>
              <p className="muted-copy">You may not use ConfigSentinel for: (a) illegal activities, (b) unauthorized access to systems, (c) reverse engineering the application, (d) redistributing or reselling the software without authorization.</p>
            </div>
          </div>
        </div>

        <div className="evidence-block">
          <SectionLabel>DISCLAIMER OF WARRANTIES</SectionLabel>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--amber-soft)", color: "var(--amber)" }}><AlertTriangle size={20} /></div>
            <div>
              <strong>As-Is Basis</strong>
              <p className="muted-copy">ConfigSentinel is provided "as is" without warranties of any kind, either express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement.</p>
            </div>
          </div>
        </div>

        <div className="evidence-block">
          <SectionLabel>LIMITATION OF LIABILITY</SectionLabel>
          <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
            <div className="queue-icon" style={{ background: "var(--amber-soft)", color: "var(--amber)" }}><Scale size={20} /></div>
            <div>
              <strong>No Liability</strong>
              <p className="muted-copy">In no event shall Veyronix be liable for any indirect, incidental, special, consequential, or punitive damages arising from your use of ConfigSentinel.</p>
            </div>
          </div>
        </div>

        <div className="evidence-block">
          <SectionLabel>INTELLECTUAL PROPERTY</SectionLabel>
          <p className="muted-copy">All content, features, and functionality of ConfigSentinel are owned by Veyronix and are protected by international copyright, trademark, and other intellectual property laws.</p>
        </div>

        <div className="evidence-block">
          <SectionLabel>USER RESPONSIBILITIES</SectionLabel>
          <p className="muted-copy">You are responsible for maintaining the confidentiality of your credentials and for all activities that occur under your account. You agree to notify us immediately of any unauthorized use.</p>
        </div>

        <div className="evidence-block">
          <SectionLabel>MODIFICATIONS TO TERMS</SectionLabel>
          <p className="muted-copy">Veyronix reserves the right to modify these terms at any time. Continued use of ConfigSentinel after such modifications constitutes acceptance of the revised terms.</p>
        </div>

        <div className="evidence-block">
          <SectionLabel>GOVERNING LAW</SectionLabel>
          <p className="muted-copy">These terms shall be governed by and construed in accordance with the laws of the jurisdiction in which Veyronix is established, without regard to its conflict of law provisions.</p>
        </div>

        <div className="evidence-block">
          <SectionLabel>TERMINATION</SectionLabel>
          <p className="muted-copy">Veyronix may terminate or suspend your access to ConfigSentinel at any time, with or without cause, with or without notice.</p>
        </div>

        <div className="evidence-footer">
          <span>Last updated: January 2025</span>
          <span>Version 1.0</span>
        </div>
      </div>
    </div>
  );
}
