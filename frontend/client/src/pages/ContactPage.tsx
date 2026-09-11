import { ArrowRight, Bug, Mail, MessageSquare, ShieldAlert } from "lucide-react";
import { useLocation } from "wouter";

function SectionLabel({ children }: { children: React.ReactNode }) {
  return <div className="section-label">{children}</div>;
}

export default function ContactPage() {
  const [, setLocation] = useLocation();
  return (
    <>
      <div className="page-intro">
        <div>
          <SectionLabel>SUPPORT / CONTACT</SectionLabel>
          <h1>Get the right handoff.</h1>
          <p>ConfigSentinel is a local review workbench. Use the path below to report a product issue, ask about an audit result, or disclose a security concern.</p>
        </div>
        <div className="intro-action"><span className="queue-readout"><MessageSquare size={14} /> HUMAN REVIEW</span></div>
      </div>
      <section className="panel contact-grid">
        <div className="contact-card"><div className="queue-icon"><Mail size={20} /></div><SectionLabel>PRODUCT QUESTIONS</SectionLabel><h2>Ask about a result</h2><p className="muted-copy">Include the audit filename, control ID, status, and the evidence shown in the panel. Do not include secrets or credentials.</p><a className="button button-primary" href="mailto:support@veyronix.example?subject=ConfigSentinel%20product%20question">Email product support <ArrowRight size={15} /></a></div>
        <div className="contact-card"><div className="queue-icon" style={{ background: "var(--danger-soft)", color: "var(--danger)" }}><Bug size={20} /></div><SectionLabel>BUG REPORT</SectionLabel><h2>Report broken behavior</h2><p className="muted-copy">Describe the route, the action you took, the expected result, and the browser console error. Attach a redacted reproduction if needed.</p><a className="button button-secondary" href="mailto:support@veyronix.example?subject=ConfigSentinel%20bug%20report">Send bug report <ArrowRight size={15} /></a></div>
        <div className="contact-card"><div className="queue-icon" style={{ background: "var(--amber-soft)", color: "var(--amber)" }}><ShieldAlert size={20} /></div><SectionLabel>SECURITY DISCLOSURE</SectionLabel><h2>Report a vulnerability</h2><p className="muted-copy">Do not post sensitive details in a public issue. Use the project security process and include impact, reproduction, and affected version.</p><button type="button" className="button button-secondary" onClick={() => setLocation("/policy")}>Open security policy <ArrowRight size={15} /></button></div>
      </section>
    </>
  );
}
