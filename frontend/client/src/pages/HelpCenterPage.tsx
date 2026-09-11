import { ArrowRight, CircleHelp, FileText, LifeBuoy, ShieldCheck } from "lucide-react";
import { useLocation } from "wouter";

function SectionLabel({ children }: { children: React.ReactNode }) {
  return <div className="section-label">{children}</div>;
}

const topics = [
  ["Start an audit", "Upload a supported configuration. The file is analyzed locally and the source filename stays attached to the report."],
  ["Understand findings", "FAIL means the rule found an issue. UNKNOWN means the engine needs more evidence; it is never treated as a pass."],
  ["Review a solution", "Open a finding to see evidence, remediation guidance, and the next review-only action. No live device is changed."],
  ["Use the Assurance Chain", "Create a verification loop from a baseline audit, then use its generated loop ID to fetch the proof timeline."],
];

export default function HelpCenterPage() {
  const [, setLocation] = useLocation();
  return (
    <>
      <div className="page-intro">
        <div>
          <SectionLabel>HELP CENTER / LOCAL OPERATIONS</SectionLabel>
          <h1>Know what to do next.</h1>
          <p>Short, practical guidance for running audits, resolving uncertainty, and keeping every decision evidence-bound.</p>
        </div>
        <div className="intro-action"><span className="queue-readout"><LifeBuoy size={14} /> OPERATOR SUPPORT</span></div>
      </div>
      <div className="two-column">
        <section className="panel">
          <div className="panel-head"><div><SectionLabel>COMMON TASKS</SectionLabel><h2>Workflow guide</h2></div><CircleHelp size={18} color="var(--accent)" /></div>
          <div className="help-topic-list">
            {topics.map(([title, detail]) => <div className="help-topic" key={title}><div className="queue-icon"><FileText size={18} /></div><div><strong>{title}</strong><p className="muted-copy">{detail}</p></div></div>)}
          </div>
        </section>
        <aside className="panel help-next-panel">
          <div className="panel-head"><div><SectionLabel>SAFE DEFAULT</SectionLabel><h2>Start with evidence</h2></div></div>
          <div className="help-next-content"><ShieldCheck size={24} color="var(--teal)" /><p className="muted-copy">Use the Overview to upload a configuration, select a finding, and follow its response plan. If the engine returns UNKNOWN, open Review Queue instead of assuming the control passed.</p><button type="button" className="button button-primary" onClick={() => setLocation("/operator-guide")}>Open operator guide <ArrowRight size={15} /></button><button type="button" className="button button-secondary" onClick={() => setLocation("/contact")}>Contact support <ArrowRight size={15} /></button></div>
        </aside>
      </div>
    </>
  );
}
