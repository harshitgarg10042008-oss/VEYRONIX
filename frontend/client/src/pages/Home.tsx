/* VEYRONIX Operator's Blueprint: evidence-first, warm mineral surfaces, graphite structure, Signal Orange attention states, and explicit human approval. */
import { useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowUpRight,
  Check,
  ChevronDown,
  CircleHelp,
  ClipboardCheck,
  Clock3,
  Code2,
  Download,
  FileCheck2,
  FileText,
  Fingerprint,
  GitBranch,
  Layers3,
  LockKeyhole,
  Menu,
  Network,
  PanelRight,
  Play,
  Search,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  TerminalSquare,
  X,
  Zap,
} from "lucide-react";

const logo = "/veyronix-mark.png";

type FindingStatus = "FAIL" | "PASS" | "UNKNOWN";

type Finding = {
  id: string;
  title: string;
  vendor: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  status: FindingStatus;
  control: string;
  line: string;
  evidence: string;
  description: string;
  remediation: string;
};

const findings: Finding[] = [
  {
    id: "NET-MGMT-SSH-001",
    title: "Telnet accepted on VTY lines",
    vendor: "Cisco IOS",
    severity: "HIGH",
    status: "FAIL",
    control: "CIS-NET-01",
    line: "L3",
    evidence: "transport input telnet",
    description: "The management plane accepts a cleartext remote terminal protocol.",
    remediation: "transport input ssh",
  },
  {
    id: "NET-AUTH-AAA-002",
    title: "Centralized AAA not confirmed",
    vendor: "Cisco IOS",
    severity: "MEDIUM",
    status: "UNKNOWN",
    control: "NIST-IA-02",
    line: "L12",
    evidence: "aaa new-model",
    description: "The parser found a partial authentication context and needs operator review.",
    remediation: "Review authentication source before approval",
  },
  {
    id: "NET-LOG-001",
    title: "Remote logging is enabled",
    vendor: "Cisco IOS",
    severity: "LOW",
    status: "PASS",
    control: "CIS-NET-06",
    line: "L21",
    evidence: "logging host 10.0.0.20",
    description: "A remote logging destination is present in the submitted configuration.",
    remediation: "No action required",
  },
];

const navItems = [
  { label: "Overview", icon: Layers3 },
  { label: "Audits", icon: ClipboardCheck, count: "03" },
  { label: "Review queue", icon: CircleHelp, count: "02" },
  { label: "Control packs", icon: FileCheck2 },
  { label: "Remediation", icon: TerminalSquare },
];

function StatusPill({ status }: { status: FindingStatus }) {
  const styles = {
    FAIL: "status-pill status-fail",
    PASS: "status-pill status-pass",
    UNKNOWN: "status-pill status-unknown",
  };
  return <span className={styles[status]}>{status}</span>;
}

function Severity({ value }: { value: Finding["severity"] }) {
  return <span className={`severity severity-${value.toLowerCase()}`}>{value}</span>;
}

export default function Home() {
  const [activeNav, setActiveNav] = useState("Overview");
  const [selectedId, setSelectedId] = useState(findings[0].id);
  const [showFailures, setShowFailures] = useState(true);
  const [toast, setToast] = useState("Local workspace ready");
  const [running, setRunning] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  const selected = useMemo(
    () => findings.find((finding) => finding.id === selectedId) ?? findings[0],
    [selectedId],
  );
  const visibleFindings = showFailures ? findings : findings.filter((finding) => finding.status !== "FAIL");

  const runAudit = () => {
    setRunning(true);
    setToast("Parsing local fixture…");
    window.setTimeout(() => {
      setRunning(false);
      setToast("Audit complete · 1 high-risk finding requires review");
    }, 650);
  };

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-mark-wrap"><img src={logo} alt="VEYRONIX mark" className="brand-mark" /></div>
          <div>
            <div className="brand-name">VEYRONIX</div>
            <div className="brand-sub">OFFLINE SECURITY WORKBENCH</div>
          </div>
        </div>

        <div className="workspace-switcher">
          <div className="workspace-caption">WORKSPACE</div>
          <button className="workspace-button" onClick={() => setToast("Workspace switcher is local-demo only")}>
            <span className="workspace-dot" />
            <span>SIH / FIELD LAB</span>
            <ChevronDown size={14} />
          </button>
        </div>

        <nav className="nav-list" aria-label="Primary navigation">
          <div className="nav-section-label">WORKBENCH</div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeNav === item.label;
            return (
              <button
                key={item.label}
                className={`nav-item ${isActive ? "nav-item-active" : ""}`}
                onClick={() => {
                  setActiveNav(item.label);
                  setToast(`${item.label} view selected`);
                }}
              >
                <span className="nav-icon"><Icon size={16} strokeWidth={1.8} /></span>
                <span>{item.label}</span>
                {item.count && <span className="nav-count">{item.count}</span>}
              </button>
            );
          })}
          <div className="nav-section-label nav-section-spaced">SYSTEM</div>
          <button className="nav-item" onClick={() => setToast("Settings are available in the full local app")}> <span className="nav-icon"><Settings2 size={16} /></span><span>Settings</span></button>
          <button className="nav-item" onClick={() => setToast("Help: unknown is a review state, not a pass")}> <span className="nav-icon"><CircleHelp size={16} /></span><span>Operator guide</span></button>
        </nav>

        <div className="sidebar-foot">
          <div className="local-badge"><span className="local-led" /> OFFLINE MODE</div>
          <div className="sidebar-foot-row"><span>SDK</span><strong>0.3.0</strong></div>
          <div className="sidebar-foot-row"><span>POLICY</span><strong>v1.2</strong></div>
        </div>
      </aside>

      <section className="workbench">
        <header className="topbar">
          <div className="breadcrumb"><span className="breadcrumb-muted">WORKBENCH</span><span className="breadcrumb-slash">/</span><span>{activeNav.toUpperCase()}</span></div>
          <div className="topbar-actions">
            <div className="mode-note"><span className="mode-dot" /> LOCAL DEMO · LLM DISABLED</div>
            <button className="icon-button" aria-label="Search" onClick={() => setToast("Search is scoped to this local fixture")}><Search size={17} /></button>
            <button className="icon-button" aria-label="Notifications" onClick={() => setToast("No new local notifications")}><Zap size={17} /></button>
            <button className="avatar-button" onClick={() => setMenuOpen((open) => !open)} aria-label="Open operator menu">HG</button>
            {menuOpen && <div className="operator-menu"><strong>HARSHIT GARG</strong><span>operator · local</span><button onClick={() => { setMenuOpen(false); setToast("No cloud session is active"); }}>Session details <ArrowUpRight size={13} /></button></div>}
          </div>
        </header>

        <div className="content-scroll">
          <section className="hero-strip">
            <div className="hero-grid-lines" aria-hidden="true" />
            <div className="hero-route-marker" aria-hidden="true"><span>01</span><i /><span>04</span></div>
            <div className="hero-copy">
              <div className="eyebrow"><span className="eyebrow-line" /> 27 AUG 2026 · LOCAL AUDIT DESK</div>
              <h1>Configuration posture.<br /><em>Evidence attached.</em></h1>
              <p>Read-only compliance analysis for the configurations you control.</p>
              <div className="hero-inline-meta"><span><FileCheck2 size={12} /> 42 controls</span><span><Network size={12} /> 3 vendors</span><span><LockKeyhole size={12} /> no live device</span></div>
            </div>
            <div className="hero-meta">
              <div><span>AUDIT ID</span><strong className="mono">AUDIT_DFC92093</strong></div>
              <div><span>FRAMEWORKS</span><strong>CIS · NIST</strong></div>
              <div><span>NETWORK</span><strong><span className="online-dot" /> isolated</strong></div>
            </div>
          </section>

          <section className="section-heading-row">
            <div>
              <div className="section-kicker">01 / AUDIT HEALTH</div>
              <h2>Current posture</h2>
            </div>
            <div className="heading-actions">
              <button className="ghost-button" onClick={() => setToast("Filters are pinned to the demo fixture")}><SlidersHorizontal size={15} /> Filters <span className="filter-count">2</span></button>
              <button className="primary-button" onClick={runAudit} disabled={running}><Play size={14} fill="currentColor" /> {running ? "Running…" : "Run local audit"}</button>
            </div>
          </section>

          <section className="metrics-row" aria-label="Audit summary">
            <div className="metric-cell metric-emphasis"><div className="metric-label">COMPLIANCE SCORE <span className="info-dot">i</span></div><div className="metric-value">78<span className="metric-unit">/100</span></div><div className="metric-trend"><ArrowUpRight size={14} /> 6 pts since last run</div></div>
            <div className="metric-cell"><div className="metric-label">CONTROLS CHECKED</div><div className="metric-value small">42</div><div className="metric-note"><span className="bar-track"><span className="bar-fill" style={{ width: "72%" }} /></span><span>72% coverage</span></div></div>
            <div className="metric-cell"><div className="metric-label">REVIEW QUEUE</div><div className="metric-value small orange-value">02</div><div className="metric-note"><CircleHelp size={14} /> unknown syntax blocks</div></div>
            <div className="metric-cell"><div className="metric-label">SAFE REMEDIATIONS</div><div className="metric-value small">07</div><div className="metric-note"><LockKeyhole size={14} /> preview only</div></div>
          </section>

          <section className="main-grid">
            <div className="audit-panel ruled-panel">
              <div className="panel-head">
                <div><div className="panel-eyebrow">AUDIT / <span className="mono">AUDIT_DFC92093</span></div><h3>Findings requiring attention</h3></div>
                <div className="panel-tools"><button className={`toggle-button ${showFailures ? "toggle-on" : ""}`} onClick={() => setShowFailures((value) => !value)}><span className="toggle-knob" /> failures first</button><button className="dots-button" onClick={() => setToast("More audit actions are preview-only")}>•••</button></div>
              </div>
              <div className="finding-table-head"><span>CONTROL / EVIDENCE</span><span>VENDOR</span><span>SEVERITY</span><span>STATUS</span></div>
              <div className="finding-list">
                {visibleFindings.map((finding) => (
                  <button key={finding.id} className={`finding-row ${selected.id === finding.id ? "finding-row-selected" : ""}`} onClick={() => setSelectedId(finding.id)}>
                    <span className="finding-main"><span className="finding-status-mark">{finding.status === "PASS" ? <Check size={12} /> : finding.status === "UNKNOWN" ? "?" : "!"}</span><span><strong>{finding.id}</strong><small>{finding.title}</small><code><span>{finding.line}</span> {finding.evidence}</code></span></span>
                    <span className="vendor-label">{finding.vendor}</span><Severity value={finding.severity} /><StatusPill status={finding.status} />
                  </button>
                ))}
              </div>
              <div className="table-foot"><span><span className="table-foot-dot" /> Showing {visibleFindings.length} of 42 controls</span><button onClick={() => setToast("Full audit table is available in the local CLI export")}>Open full audit <ArrowUpRight size={13} /></button></div>
            </div>

            <aside className="evidence-panel">
              <div className="evidence-topline"><span className="panel-eyebrow">SELECTED FINDING</span><button className="close-detail" onClick={() => setToast("Finding stays pinned for review")}><PanelRight size={15} /></button></div>
              <div className="evidence-control">{selected.control} <span>·</span> {selected.id}</div>
              <h3>{selected.title}</h3>
              <p className="evidence-description">{selected.description}</p>
              <div className="evidence-rule" />
              <div className="evidence-label">SOURCE EVIDENCE <span className="mono">{selected.line}</span></div>
              <div className="code-snippet"><span className="code-line-number">{selected.line.replace("L", "")}</span><span><span className="syntax-command">{selected.evidence.split(" ")[0]}</span> {selected.evidence.split(" ").slice(1).join(" ")}</span></div>
              <div className="evidence-label evidence-label-spaced">FRAMEWORK MAPPING</div>
              <div className="mapping-row"><span className="mapping-chip">CIS Network</span><span className="mapping-status">verified</span><Fingerprint size={14} /></div>
              <div className="mapping-row"><span className="mapping-chip mapping-chip-blue">NIST 800-53</span><span className="mapping-status muted">crosswalk</span><GitBranch size={14} /></div>
              <div className="evidence-action-block"><div><span className="action-label">SAFE PREVIEW</span><span className="action-copy">{selected.remediation}</span></div><button className="preview-button" onClick={() => setToast("Remediation preview opened · no device execution")}>Preview <ArrowUpRight size={13} /></button></div>
              <div className="evidence-footer"><span><Clock3 size={13} /> captured 2m ago</span><span><FileText size={13} /> source hash locked</span></div>
            </aside>
          </section>

          <section className="lower-grid">
            <div className="topology-panel ruled-panel">
              <div className="panel-head"><div><div className="panel-eyebrow">NETWORK / NORMALIZED VIEW</div><h3>Topology signal</h3></div><button className="ghost-button compact" onClick={() => setToast("Topology is derived from local fixture metadata")}><Network size={14} /> inspect</button></div>
              <div className="topology-body"><div className="topology-canvas" aria-label="Normalized network topology diagram"><span className="topology-line line-a" /><span className="topology-line line-b" /><span className="topology-line line-c" /><span className="topology-node node-firewall"><ShieldCheck size={16} /></span><span className="topology-node node-cisco">C</span><span className="topology-node node-junos">J</span><span className="topology-node node-fw">F</span><span className="topology-alert">!</span></div><div className="topology-legend"><span><i className="legend-orange" /> 1 attention point</span><span><i className="legend-graphite" /> 3 normalized nodes</span><span><i className="legend-blue" /> 2 framework links</span></div></div>
            </div>
            <div className="queue-panel ruled-panel"><div className="panel-head"><div><div className="panel-eyebrow">LEARNING LOOP / 02 OPEN</div><h3>Unknown syntax queue</h3></div><button className="text-button" onClick={() => { setActiveNav("Review queue"); setToast("Review queue selected"); }}>Review all <ArrowUpRight size={13} /></button></div><div className="queue-item"><div className="queue-index">01</div><div><strong>aaa new-model</strong><small>partial auth context · Cisco IOS</small></div><span className="queue-state">PENDING</span></div><div className="queue-item"><div className="queue-index">02</div><div><strong>security ike proposal</strong><small>unmapped stanza · Junos</small></div><span className="queue-state">PENDING</span></div><div className="queue-foot"><Sparkles size={14} /> AI suggests. Operator approves. Control pack learns.</div></div>
          </section>

          <footer className="page-foot"><span>VEYRONIX · LOCAL SECURITY WORKBENCH</span><span>ALL OUTPUTS ARE EVIDENCE-BACKED · NO LIVE DEVICE CONNECTION</span><span className="mono">BUILD 0.3.0 / veyronix</span></footer>
        </div>
        <div className="toast"><span className="toast-mark"><Check size={12} /></span>{toast}</div>
      </section>
    </main>
  );
}
