import { useMemo, useState } from "react";
import {
  Activity,
  Check,
  CheckCircle2,
  ClipboardCheck,
  Clock3,
  Download,
  FileCheck2,
  FileText,
  LockKeyhole,
  Play,
  RefreshCw,
  Server,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  UserCheck,
  Users,
} from "lucide-react";

type WorkflowKind =
  | "inventory"
  | "monitoring"
  | "audits"
  | "drift"
  | "review"
  | "remediation"
  | "settings"
  | "guide"
  | "controls";

type Row = { name: string; detail: string; status: string; tone: "pass" | "fail" | "unknown" | "neutral" };

const copy: Record<WorkflowKind, { label: string; title: string; intro: string; action: string; icon: typeof Server }> = {
  inventory: { label: "CORE / ASSET INVENTORY", title: "Know what is being assured.", intro: "A local inventory of configuration sources and their latest verified posture.", action: "Register asset", icon: Server },
  monitoring: { label: "CORE / CONTINUOUS MONITORING", title: "Watch posture without hiding uncertainty.", intro: "Review scheduled-check readiness and the last deterministic signal for every tracked asset.", action: "Run check", icon: Activity },
  audits: { label: "ASSURANCE / AUDITS", title: "Compare audits with evidence.", intro: "Run a repeatable audit, compare versions, and preserve the evidence needed for review.", action: "Run new audit", icon: ClipboardCheck },
  drift: { label: "ASSURANCE / DRIFT DETECTION", title: "See what changed before it becomes risk.", intro: "Compare redacted configuration snapshots and separate meaningful drift from harmless formatting changes.", action: "Compare snapshots", icon: RefreshCw },
  review: { label: "ASSURANCE / REVIEW QUEUE", title: "Resolve what the engine cannot prove.", intro: "Unknown and review-required findings stay visible until an operator records a decision.", action: "Start review", icon: UserCheck },
  remediation: { label: "ASSURANCE / REMEDIATION", title: "Fix safely, never silently.", intro: "Review proof-carrying change previews before a separate controlled process applies anything.", action: "Create preview", icon: TerminalSquare },
  settings: { label: "SYSTEM / SETTINGS", title: "Control the local workbench.", intro: "Inspect runtime mode, data retention, role boundaries, and export preferences.", action: "Save preferences", icon: Settings2 },
  guide: { label: "SYSTEM / OPERATOR GUIDE", title: "A judge-ready path through the product.", intro: "Use this sequence to demonstrate the complete audit-to-assurance workflow in under seven minutes.", action: "Start demo", icon: Play },
  controls: { label: "RESEARCH LAB / CONTROL PACKS", title: "Inspect the rules behind every verdict.", intro: "Control packs are deterministic and inspectable; research surfaces are explicitly separated from production assurance.", action: "Inspect pack", icon: FileCheck2 },
};

const rows: Record<WorkflowKind, Row[]> = {
  inventory: [
    { name: "edge-router-01", detail: "Cisco IOS XE · last audit 12 min ago", status: "HEALTHY", tone: "pass" },
    { name: "branch-fw-07", detail: "Generic firewall · review required", status: "REVIEW", tone: "unknown" },
    { name: "core-junos-02", detail: "Juniper Junos · drift detected", status: "DRIFT", tone: "fail" },
  ],
  monitoring: [
    { name: "Configuration freshness", detail: "3 of 3 sources within policy", status: "PASS", tone: "pass" },
    { name: "Unknown syntax budget", detail: "2 findings require operator review", status: "REVIEW", tone: "unknown" },
    { name: "Last scheduled check", detail: "Local scheduler readiness · 12 min ago", status: "READY", tone: "neutral" },
  ],
  audits: [
    { name: "AUD-2026-0911-7F2A", detail: "Cisco IOS XE · 18 controls · 6 evidence spans", status: "LATEST", tone: "pass" },
    { name: "AUD-2026-0911-44C1", detail: "Juniper Junos · compared with baseline", status: "DRIFT", tone: "fail" },
    { name: "AUD-2026-0910-0B8E", detail: "Generic firewall · awaiting review", status: "UNKNOWN", tone: "unknown" },
  ],
  drift: [
    { name: "edge-router-01", detail: "3 changed lines · management ACL affected", status: "ATTENTION", tone: "fail" },
    { name: "core-junos-02", detail: "1 parser-normalized change · evidence preserved", status: "REVIEW", tone: "unknown" },
    { name: "branch-fw-07", detail: "No material drift since last verified audit", status: "STABLE", tone: "pass" },
  ],
  review: [
    { name: "NET-ACL-004", detail: "Unsupported ACL syntax · line 84", status: "UNKNOWN", tone: "unknown" },
    { name: "NET-MGMT-007", detail: "Management exposure · source line 21", status: "FAIL", tone: "fail" },
    { name: "NET-LOG-002", detail: "Evidence complete · reviewer decision recorded", status: "RESOLVED", tone: "pass" },
  ],
  remediation: [
    { name: "PREVIEW-042", detail: "Disable plaintext management service · 3-line diff", status: "REVIEW ONLY", tone: "unknown" },
    { name: "PREVIEW-039", detail: "Add explicit logging control · rollback attached", status: "APPROVED", tone: "pass" },
    { name: "PREVIEW-031", detail: "Rejected by separation-of-duties policy", status: "BLOCKED", tone: "fail" },
  ],
  settings: [
    { name: "Runtime mode", detail: "Local demo · external inference disabled", status: "SAFE", tone: "pass" },
    { name: "Identity boundary", detail: "Operator session · reviewer switch available", status: "LOCAL", tone: "neutral" },
    { name: "Retention", detail: "Latest 20 audit snapshots in browser storage", status: "CONFIGURED", tone: "neutral" },
  ],
  guide: [
    { name: "01 · Run an audit", detail: "Use the bundled noncompliant Cisco fixture", status: "READY", tone: "pass" },
    { name: "02 · Inspect evidence", detail: "Open FAIL and UNKNOWN findings", status: "READY", tone: "pass" },
    { name: "03 · Verify assurance", detail: "Show preview, approval boundary, and chain", status: "READY", tone: "pass" },
  ],
  controls: [
    { name: "Network management", detail: "6 controls · CIS/NIST crosswalk", status: "18 EVALUATED", tone: "pass" },
    { name: "Logging and audit", detail: "4 controls · 1 unknown syntax case", status: "REVIEW", tone: "unknown" },
    { name: "Access control", detail: "8 controls · deterministic source evidence", status: "INSPECT", tone: "neutral" },
  ],
};

function toneClass(tone: Row["tone"]) {
  return tone === "pass" ? "status-pass" : tone === "fail" ? "status-fail" : tone === "unknown" ? "status-unknown" : "status-pill";
}

export default function PrimaryWorkflowPage({ kind }: { kind: WorkflowKind }) {
  const config = copy[kind];
  const Icon = config.icon;
  const [selected, setSelected] = useState(0);
  const [notice, setNotice] = useState("");
  const items = rows[kind];
  const selectedItem = items[selected];
  const summary = useMemo(() => ({
    total: items.length,
    pass: items.filter((item) => item.tone === "pass").length,
    review: items.filter((item) => item.tone === "unknown").length,
    fail: items.filter((item) => item.tone === "fail").length,
  }), [items]);

  const runAction = () => setNotice(`${config.action} queued in local review mode. No external system was changed.`);

  return (
    <>
      <div className="page-intro">
        <div>
          <div className="section-label">{config.label}</div>
          <h1>{config.title}</h1>
          <p>{config.intro}</p>
        </div>
        <div className="intro-action">
          <span className="queue-readout"><span className="signal signal-teal" /> LOCAL / DETERMINISTIC</span>
          <button className="button button-primary" type="button" onClick={runAction}><Icon size={15} /> {config.action}</button>
        </div>
      </div>

      <div className="metrics-grid">
        <div className="metric metric-safe"><span>READY / VERIFIED</span><strong>{summary.pass}</strong><small>evidence-backed records</small></div>
        <div className="metric metric-warn"><span>REVIEW REQUIRED</span><strong>{summary.review}</strong><small>unknowns stay visible</small></div>
        <div className="metric metric-danger"><span>ATTENTION</span><strong>{summary.fail}</strong><small>deterministic failures</small></div>
        <div className="metric"><span>RECORDS</span><strong>{summary.total}</strong><small>local workbench scope</small></div>
      </div>

      {notice && <div className="queue-banner" role="status"><div className="queue-icon"><CheckCircle2 size={18} /></div><span>{notice}</span></div>}

      <div className="two-column">
        <section className="panel">
          <div className="panel-head"><div><div className="section-label">WORKBENCH RECORDS</div><h2>{kind === "guide" ? "Demo sequence" : kind === "controls" ? "Inspectable control packs" : "Current records"}</h2></div><span className="count-badge">{String(items.length).padStart(2, "0")}</span></div>
          <div className="findings-table">
            <div className="table-head"><span>RECORD</span><span>STATE</span><span>OPEN</span></div>
            {items.map((item, index) => <button key={item.name} className={`finding-row ${selected === index ? "finding-selected" : ""}`} type="button" onClick={() => setSelected(index)}><span className="finding-main"><span className={`finding-symbol symbol-${item.tone}`}>{String(index + 1).padStart(2, "0")}</span><span><strong>{item.name}</strong><small>{item.detail}</small></span></span><span className={`status-pill ${toneClass(item.tone)}`}><span className="status-dot" />{item.status}</span><span>›</span></button>)}
          </div>
        </section>

        <aside className="evidence-panel">
          <div className="evidence-top"><div className="section-label">SELECTED RECORD</div><span className="proof-tag"><LockKeyhole size={12} /> REVIEWABLE</span></div>
          <div className="evidence-id">{selectedItem.name}</div>
          <h2>{selectedItem.status}</h2>
          <div className="evidence-block"><div className="section-label">DETAIL</div><div className="evidence-state">{selectedItem.detail}</div></div>
          <div className="evidence-block"><div className="section-label">SAFETY BOUNDARY</div><div className="evidence-state">Actions create a local review record only. The product never executes a generated command or changes a device.</div></div>
          <div className="evidence-block"><div className="section-label">NEXT STEP</div><div className="evidence-state">Open the primary audit to inspect source lines, expected state, observed state, and framework mapping.</div></div>
          <div className="evidence-footer"><span><Clock3 size={12} /> refreshed just now</span><span><ShieldCheck size={12} /> evidence-first</span></div>
        </aside>
      </div>

      <div className="queue-banner" style={{ marginTop: 16 }}><div className="queue-icon"><ShieldAlert size={18} /></div><div><strong>Operator note</strong><span>{kind === "guide" ? "Keep the demo focused on the deterministic audit → evidence → review → assurance chain. Research Lab surfaces are optional follow-up material." : "This screen is intentionally populated with a reproducible local fixture so the operator can understand the workflow before connecting an API."}</span></div></div>
    </>
  );
}
