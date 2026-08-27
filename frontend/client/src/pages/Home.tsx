/* VEYRONIX Operator's Blueprint: live deterministic audit evidence, quiet authority, and explicit human approval. */
import { useEffect, useMemo, useState, type ChangeEvent } from "react";
import { jsPDF } from "jspdf";
import {
  AlertTriangle, ArrowUpRight, Check, ChevronDown, CircleHelp, ClipboardCheck,
  Clock3, Download, FileCheck2, FileText, Fingerprint, GitBranch, Layers3,
  LockKeyhole, Network, PanelRight, Play, Search, Settings2, ShieldCheck,
  SlidersHorizontal, Sparkles, TerminalSquare, X, Zap,
} from "lucide-react";

const logo = "/veyronix-mark.png";
const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");
const DEMO_CONFIGURATION = "version 17.9\nline vty 0 4\n transport input telnet\nlogging host 10.0.0.20\n";

type FindingStatus = "FAIL" | "PASS" | "UNKNOWN" | "NOT_APPLICABLE" | "REVIEW_REQUIRED";
type SeverityValue = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
type Mapping = { framework_id: string; title: string; status: string; control_ids: string[]; confidence: number };
type Evidence = { start_line: number; end_line: number; excerpt: string; redacted: boolean };
type Finding = {
  finding_id: string; control_id: string; status: FindingStatus; severity: SeverityValue;
  confidence: number; evidence: Evidence[]; observed_state: string; expected_state: string;
  rationale: string; remediation_preview?: string | null; framework_mappings: Mapping[];
};
type AuditReport = {
  audit: { audit_id: string; vendor: string; parser_version: string; rule_pack_version: string; input_sha256: string; frameworks: string[] };
  summary: { finding_count: number; failed_count: number; unknown_count: number; evaluated_count: number; mapped_finding_count: number; status_counts: Record<string, number> };
  findings: Finding[];
};

const fallbackReport: AuditReport = {
  audit: { audit_id: "LOCAL_NOT_RUN", vendor: "cisco_ios", parser_version: "—", rule_pack_version: "—", input_sha256: "—", frameworks: ["cis-network", "nist-800-53"] },
  summary: { finding_count: 0, failed_count: 0, unknown_count: 0, evaluated_count: 0, mapped_finding_count: 0, status_counts: {} },
  findings: [],
};

type AuditHistoryEntry = { id: string; capturedAt: string; fileName: string; report: AuditReport };
const HISTORY_KEY = "veyronix.audit-history.v1";
const MAX_CONFIG_BYTES = 2 * 1024 * 1024;

function readHistory(): AuditHistoryEntry[] {
  try {
    const raw = window.localStorage.getItem(HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as AuditHistoryEntry[];
    return Array.isArray(parsed) ? parsed.slice(0, 20) : [];
  } catch { return []; }
}

function persistHistory(entries: AuditHistoryEntry[]) {
  window.localStorage.setItem(HISTORY_KEY, JSON.stringify(entries.slice(0, 20)));
}

const navItems = [
  { label: "Overview", icon: Layers3 }, { label: "Audits", icon: ClipboardCheck },
  { label: "Review queue", icon: CircleHelp }, { label: "Control packs", icon: FileCheck2 },
  { label: "Remediation", icon: TerminalSquare },
];

function StatusPill({ status }: { status: FindingStatus }) { return <span className={`status-pill status-${status.toLowerCase()}`}>{status}</span>; }
function Severity({ value }: { value: SeverityValue }) { return <span className={`severity severity-${value.toLowerCase()}`}>{value}</span>; }
function evidenceLine(finding: Finding) { const first = finding.evidence[0]; return first ? `L${first.start_line}` : "—"; }
function evidenceText(finding: Finding) { return finding.evidence.map((span) => span.excerpt).join(" · ") || "No evidence span recorded"; }
function frameworkText(finding: Finding) { return finding.framework_mappings.map((row) => row.framework_id).join(" · ") || "UNVERIFIED"; }

function FindingsTrend({ history, onSelect }: { history: AuditHistoryEntry[]; onSelect: (entry: AuditHistoryEntry) => void }) {
  const points = history.slice().reverse().map((entry, index, rows) => ({
    entry,
    x: rows.length === 1 ? 50 : 8 + (index / (rows.length - 1)) * 84,
    failures: entry.report.summary.failed_count,
    unknown: entry.report.summary.unknown_count,
  }));
  const max = Math.max(1, ...points.flatMap((point) => [point.failures, point.unknown]));
  const path = (key: "failures" | "unknown") => points.map((point, index) => `${index ? "L" : "M"}${point.x} ${86 - (point[key] / max) * 68}`).join(" ");
  return <div className="trend-panel ruled-panel"><div className="panel-head"><div><div className="panel-eyebrow">HISTORY / {history.length} SNAPSHOT{history.length === 1 ? "" : "S"}</div><h3>Finding trend</h3></div><div className="trend-legend"><span><i className="trend-fail" /> failures</span><span><i className="trend-unknown" /> unknown</span></div></div>{history.length === 0 ? <div className="empty-state">Run an audit or upload a configuration to build the local trend.</div> : <div className="trend-chart-wrap"><svg className="trend-chart" viewBox="0 0 100 100" role="img" aria-label="Interactive trend of failures and unknown findings over saved audits"><path d="M8 86 H92" className="trend-axis" /><path d="M8 18 V86" className="trend-axis" /><path d={path("failures")} className="trend-line trend-line-fail" /><path d={path("unknown")} className="trend-line trend-line-unknown" />{points.map((point) => <g key={point.entry.id} tabIndex={0} role="button" aria-label={`${point.entry.fileName}: ${point.failures} failures, ${point.unknown} unknown`} onClick={() => onSelect(point.entry)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") onSelect(point.entry); }}><circle cx={point.x} cy={86 - (point.failures / max) * 68} r="2.4" className="trend-point trend-point-fail" /><circle cx={point.x} cy={86 - (point.unknown / max) * 68} r="2.4" className="trend-point trend-point-unknown" /><title>{new Date(point.entry.capturedAt).toLocaleString()} · {point.failures} failures · {point.unknown} unknown</title></g>)}</svg><div className="trend-labels"><span>{new Date(points[0].entry.capturedAt).toLocaleDateString()}</span><span>Click a point to load snapshot</span><span>{new Date(points.at(-1)!.entry.capturedAt).toLocaleDateString()}</span></div></div>}</div>;
}

export default function Home() {
  const [activeNav, setActiveNav] = useState("Overview");
  const [report, setReport] = useState<AuditReport>(fallbackReport);
  const [selectedId, setSelectedId] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityValue | "ALL">("ALL");
  const [statusFilter, setStatusFilter] = useState<FindingStatus | "ALL">("ALL");
  const [frameworkFilter, setFrameworkFilter] = useState("ALL");
  const [showFilters, setShowFilters] = useState(false);
  const [toast, setToast] = useState("Connect a local audit API or run the bundled fixture");
  const [running, setRunning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [apiOnline, setApiOnline] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [history, setHistory] = useState<AuditHistoryEntry[]>(() => readHistory());
  const [selectedFileName, setSelectedFileName] = useState("bundled-fixture.conf");

  const loadReport = async (configText = DEMO_CONFIGURATION, fileName = "bundled-fixture.conf") => {
    setLoading(true);
    try {
      const health = await fetch(`${API_BASE}/api/health`);
      if (!health.ok) throw new Error("API unavailable");
      setApiOnline(true);
      const response = await fetch(`${API_BASE}/api/audit`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ config_text: configText, vendor: "cisco_ios", frameworks: ["cis-network", "nist-800-53"], project_id: fileName }) });
      if (!response.ok) throw new Error(`Audit returned ${response.status}`);
      const nextReport = (await response.json()) as AuditReport;
      const entry: AuditHistoryEntry = { id: `${nextReport.audit.audit_id}-${Date.now()}`, capturedAt: new Date().toISOString(), fileName, report: nextReport };
      const nextHistory = [entry, ...history.filter((item) => item.report.audit.audit_id !== nextReport.audit.audit_id)];
      setHistory(nextHistory); persistHistory(nextHistory);
      setReport(nextReport); setSelectedId(nextReport.findings[0]?.finding_id ?? ""); setSelectedFileName(fileName);
      setToast(`Live audit loaded · ${nextReport.summary.failed_count} failure(s) require review`);
    } catch {
      setApiOnline(false);
      setToast("API offline · start examples/api_server.py to load live results");
    } finally { setLoading(false); }
  };

  useEffect(() => { const latest = history[0]; if (latest) { setReport(latest.report); setSelectedId(latest.report.findings[0]?.finding_id ?? ""); setSelectedFileName(latest.fileName); setLoading(false); } else void loadReport(); }, []);

  const visibleFindings = useMemo(() => report.findings.filter((finding) => {
    const severityMatch = severityFilter === "ALL" || finding.severity === severityFilter;
    const statusMatch = statusFilter === "ALL" || finding.status === statusFilter;
    const frameworkMatch = frameworkFilter === "ALL" || finding.framework_mappings.some((row) => row.framework_id === frameworkFilter);
    return severityMatch && statusMatch && frameworkMatch;
  }), [report.findings, severityFilter, statusFilter, frameworkFilter]);
  const selected = useMemo(() => visibleFindings.find((finding) => finding.finding_id === selectedId) ?? visibleFindings[0] ?? report.findings[0], [visibleFindings, selectedId, report.findings]);
  const filterCount = [severityFilter !== "ALL", statusFilter !== "ALL", frameworkFilter !== "ALL"].filter(Boolean).length;

  const runAudit = async () => { setRunning(true); setToast("Submitting bundled configuration to local engine…"); await loadReport(); setRunning(false); };
  const handleFileUpload = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]; event.target.value = "";
    if (!file) return;
    if (file.size > MAX_CONFIG_BYTES) { setToast("Upload rejected · configuration must be 2 MB or smaller"); return; }
    if (!/\.(cfg|conf|config|txt)$/i.test(file.name)) { setToast("Upload rejected · use .cfg, .conf, .config, or .txt"); return; }
    setRunning(true); setToast(`Reading ${file.name}…`);
    try { const text = await file.text(); if (!text.trim()) throw new Error("empty"); await loadReport(text, file.name); }
    catch { setToast("Upload rejected · file is empty or could not be read"); }
    finally { setRunning(false); }
  };
  const selectHistory = (entry: AuditHistoryEntry) => { setReport(entry.report); setSelectedId(entry.report.findings[0]?.finding_id ?? ""); setSelectedFileName(entry.fileName); setToast(`Loaded history snapshot · ${entry.fileName}`); };
  const resetFilters = () => { setSeverityFilter("ALL"); setStatusFilter("ALL"); setFrameworkFilter("ALL"); };

  const exportPdf = () => {
    const pdf = new jsPDF({ unit: "pt", format: "a4" });
    const margin = 40; let y = 44;
    const write = (text: string, size = 10, color: [number, number, number] = [45, 48, 43]) => { pdf.setFontSize(size); pdf.setTextColor(...color); const lines = pdf.splitTextToSize(text, 515); pdf.text(lines, margin, y); y += lines.length * (size + 4) + 8; if (y > 760) { pdf.addPage(); y = 44; } };
    pdf.setFillColor(45, 48, 43); pdf.rect(0, 0, 595, 90, "F");
    pdf.setTextColor(244, 241, 232); pdf.setFontSize(20); pdf.text("VEYRONIX", margin, 42); pdf.setFontSize(9); pdf.text("LOCAL SECURITY WORKBENCH · EVIDENCE REPORT", margin, 62);
    y = 122; write("Posture report", 16); write(`Audit ${report.audit.audit_id} · Vendor ${report.audit.vendor} · Frameworks ${report.audit.frameworks.join(", ")}`); write(`Input SHA-256: ${report.audit.input_sha256}`); write(`Finding count: ${report.summary.finding_count} · Failures: ${report.summary.failed_count} · Unknown blocks: ${report.summary.unknown_count} · Evaluated: ${report.summary.evaluated_count}`);
    write(`Export filters: severity=${severityFilter}, status=${statusFilter}, framework=${frameworkFilter}`, 9, [106, 113, 103]);
    visibleFindings.forEach((finding, index) => { write(`${index + 1}. ${finding.control_id} · ${finding.status} · ${finding.severity}`, 11, finding.status === "FAIL" ? [196, 79, 38] : [45, 48, 43]); write(`Evidence: ${evidenceText(finding)} (${evidenceLine(finding)})`); write(`Observed: ${finding.observed_state || "—"} | Expected: ${finding.expected_state || "—"}`); write(`Framework mapping: ${frameworkText(finding)} | Confidence: ${(finding.confidence * 100).toFixed(0)}%`); });
    write("Safety note: this report is evidence for review. It does not authorize device changes. Remediation previews remain non-executable and require independent operator approval.", 9, [106, 113, 103]);
    pdf.save(`veyronix-${report.audit.audit_id || "posture"}.pdf`); setToast(`PDF exported · ${visibleFindings.length} visible finding(s)`);
  };

  return <main className="app-shell">
    <aside className="sidebar"><div className="brand-lockup"><div className="brand-mark-wrap"><img src={logo} alt="VEYRONIX mark" className="brand-mark" /></div><div><div className="brand-name">VEYRONIX</div><div className="brand-sub">OFFLINE SECURITY WORKBENCH</div></div></div>
      <div className="workspace-switcher"><div className="workspace-caption">WORKSPACE</div><button className="workspace-button" onClick={() => setToast("Workspace switcher is local-demo only")}><span className="workspace-dot" /><span>SIH / FIELD LAB</span><ChevronDown size={14} /></button></div>
      <nav className="nav-list" aria-label="Primary navigation"><div className="nav-section-label">WORKBENCH</div>{navItems.map((item) => { const Icon = item.icon; return <button key={item.label} className={`nav-item ${activeNav === item.label ? "nav-item-active" : ""}`} onClick={() => { setActiveNav(item.label); setToast(`${item.label} view selected`); }}><span className="nav-icon"><Icon size={16} strokeWidth={1.8} /></span><span>{item.label}</span>{item.label === "Review queue" && <span className="nav-count">{String(report.summary.unknown_count).padStart(2, "0")}</span>}</button>; })}<div className="nav-section-label nav-section-spaced">SYSTEM</div><button className="nav-item" onClick={() => setToast("Settings are available in the local API configuration")}> <span className="nav-icon"><Settings2 size={16} /></span><span>Settings</span></button><button className="nav-item" onClick={() => setToast("Unknown is a review state, not a pass")}> <span className="nav-icon"><CircleHelp size={16} /></span><span>Operator guide</span></button></nav>
      <div className="sidebar-foot"><div className="local-badge"><span className="local-led" /> {apiOnline ? "LOCAL API ONLINE" : "OFFLINE MODE"}</div><div className="sidebar-foot-row"><span>SDK</span><strong>0.3.0</strong></div><div className="sidebar-foot-row"><span>POLICY</span><strong>v1.2</strong></div></div>
    </aside>
    <section className="workbench"><header className="topbar"><div className="breadcrumb"><span className="breadcrumb-muted">WORKBENCH</span><span className="breadcrumb-slash">/</span><span>{activeNav.toUpperCase()}</span></div><div className="topbar-actions"><div className="mode-note"><span className="mode-dot" /> {apiOnline ? "LOCAL API · DETERMINISTIC" : "LOCAL DEMO · API OFFLINE"}</div><button className="icon-button" aria-label="Search" onClick={() => setToast("Search is scoped to the loaded audit") }><Search size={17} /></button><button className="icon-button" aria-label="Export PDF" onClick={exportPdf}><Download size={17} /></button><button className="avatar-button" onClick={() => setMenuOpen((open) => !open)} aria-label="Open operator menu">HG</button>{menuOpen && <div className="operator-menu"><strong>HARSHIT GARG</strong><span>operator · local</span><button onClick={() => { setMenuOpen(false); setToast("No cloud session is active"); }}>Session details <ArrowUpRight size={13} /></button></div>}</div></header>
      <div className="content-scroll"><section className="hero-strip"><div className="hero-grid-lines" aria-hidden="true" /><div className="hero-route-marker" aria-hidden="true"><span>01</span><i /><span>04</span></div><div className="hero-copy"><div className="eyebrow"><span className="eyebrow-line" /> LIVE AUDIT DESK · REDACTED INPUT</div><h1>Configuration posture.<br /><em>Evidence attached.</em></h1><p>Deterministic compliance results from the local engine, with source lines preserved.</p><div className="hero-inline-meta"><span><FileCheck2 size={12} /> {report.summary.evaluated_count} evaluated</span><span><Network size={12} /> {report.audit.vendor}</span><span><FileText size={12} /> {selectedFileName}</span><span><LockKeyhole size={12} /> no live device</span></div></div><div className="hero-meta"><div><span>AUDIT ID</span><strong className="mono">{report.audit.audit_id}</strong></div><div><span>FRAMEWORKS</span><strong>{report.audit.frameworks.join(" · ") || "—"}</strong></div><div><span>NETWORK</span><strong><span className="online-dot" /> isolated</strong></div></div></section>
        <section className="section-heading-row"><div><div className="section-kicker">01 / AUDIT HEALTH</div><h2>Current posture</h2></div><div className="heading-actions"><label className="upload-button ghost-button"><Download size={15} /> Upload config<input type="file" accept=".cfg,.conf,.config,.txt,text/plain" onChange={handleFileUpload} disabled={running} /></label><button className="ghost-button" onClick={() => setShowFilters((value) => !value)}><SlidersHorizontal size={15} /> Filters <span className="filter-count">{filterCount}</span></button><button className="ghost-button" onClick={exportPdf}><Download size={15} /> Export PDF</button><button className="primary-button" onClick={runAudit} disabled={running}><Play size={14} fill="currentColor" /> {running ? "Running…" : "Run local audit"}</button></div></section>
        {showFilters && <section className="filter-bar" aria-label="Finding filters"><label>SEVERITY<select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value as SeverityValue | "ALL")}><option value="ALL">All severities</option>{["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((value) => <option key={value} value={value}>{value}</option>)}</select></label><label>STATUS<select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value as FindingStatus | "ALL")}><option value="ALL">All statuses</option>{["FAIL", "UNKNOWN", "REVIEW_REQUIRED", "PASS", "NOT_APPLICABLE"].map((value) => <option key={value} value={value}>{value}</option>)}</select></label><label>FRAMEWORK<select value={frameworkFilter} onChange={(event) => setFrameworkFilter(event.target.value)}><option value="ALL">All mappings</option>{report.audit.frameworks.map((value) => <option key={value} value={value}>{value}</option>)}</select></label><button className="clear-filters" onClick={resetFilters}><X size={13} /> Reset</button></section>}
        <section className="metrics-row" aria-label="Audit summary"><div className="metric-cell metric-emphasis"><div className="metric-label">COMPLIANCE SCORE <span className="info-dot">i</span></div><div className="metric-value">{report.summary.finding_count ? Math.max(0, Math.round((report.summary.evaluated_count - report.summary.failed_count) / Math.max(1, report.summary.evaluated_count) * 100)) : "—"}<span className="metric-unit">/100</span></div><div className="metric-trend"><ArrowUpRight size={14} /> {loading ? "loading" : "live engine result"}</div></div><div className="metric-cell"><div className="metric-label">FINDINGS LOADED</div><div className="metric-value small">{report.summary.finding_count}</div><div className="metric-note"><span className="bar-track"><span className="bar-fill" style={{ width: `${report.summary.finding_count ? Math.min(100, report.summary.evaluated_count / report.summary.finding_count * 100) : 0}%` }} /></span><span>{report.summary.evaluated_count} evaluated</span></div></div><div className="metric-cell"><div className="metric-label">REVIEW QUEUE</div><div className="metric-value small orange-value">{String(report.summary.unknown_count).padStart(2, "0")}</div><div className="metric-note"><CircleHelp size={14} /> unknown blocks</div></div><div className="metric-cell"><div className="metric-label">SAFE PREVIEWS</div><div className="metric-value small">{report.findings.filter((finding) => finding.remediation_preview).length}</div><div className="metric-note"><LockKeyhole size={14} /> preview only</div></div></section>
        <section className="main-grid"><div className="audit-panel ruled-panel"><div className="panel-head"><div><div className="panel-eyebrow">AUDIT / <span className="mono">{report.audit.audit_id}</span></div><h3>Findings requiring attention</h3></div><div className="panel-tools"><span className="filter-summary">{visibleFindings.length} visible</span><button className="dots-button" onClick={() => setToast("Export uses the currently visible finding set")}>•••</button></div></div><div className="finding-table-head"><span>CONTROL / EVIDENCE</span><span>VENDOR</span><span>SEVERITY</span><span>STATUS</span></div><div className="finding-list">{loading && <div className="empty-state">Loading live audit report…</div>}{!loading && visibleFindings.length === 0 && <div className="empty-state">No findings match the active filters.</div>}{visibleFindings.map((finding) => <button key={finding.finding_id} className={`finding-row ${selected?.finding_id === finding.finding_id ? "finding-row-selected" : ""}`} onClick={() => setSelectedId(finding.finding_id)}><span className="finding-main"><span className="finding-status-mark">{finding.status === "PASS" ? <Check size={12} /> : finding.status === "UNKNOWN" ? "?" : "!"}</span><span><strong>{finding.control_id}</strong><small>{finding.observed_state || finding.rationale}</small><code><span>{evidenceLine(finding)}</span> {evidenceText(finding)}</code></span></span><span className="vendor-label">{report.audit.vendor}</span><Severity value={finding.severity} /><StatusPill status={finding.status} /></button>)}</div><div className="table-foot"><span><span className="table-foot-dot" /> Showing {visibleFindings.length} of {report.summary.finding_count} findings</span><button onClick={exportPdf}>Export visible report <Download size={13} /></button></div></div>
          <aside className="evidence-panel">{selected ? <><div className="evidence-topline"><span className="panel-eyebrow">SELECTED FINDING</span><button className="close-detail" onClick={() => setSelectedId("")}><PanelRight size={15} /></button></div><div className="evidence-control">{frameworkText(selected)} <span>·</span> {selected.control_id}</div><h3>{selected.observed_state || selected.rationale}</h3><p className="evidence-description">{selected.rationale || "Deterministic finding returned by the local engine."}</p><div className="evidence-rule" /><div className="evidence-label">SOURCE EVIDENCE <span className="mono">{evidenceLine(selected)}</span></div><div className="code-snippet"><span className="code-line-number">{selected.evidence[0]?.start_line ?? "—"}</span><span>{selected.evidence[0]?.excerpt || "No evidence span recorded"}</span></div><div className="evidence-label evidence-label-spaced">FRAMEWORK MAPPING</div>{selected.framework_mappings.map((mapping) => <div className="mapping-row" key={mapping.framework_id}><span className="mapping-chip">{mapping.framework_id}</span><span className="mapping-status">{mapping.status.toLowerCase()}</span><Fingerprint size={14} /></div>)}<div className="evidence-action-block"><div><span className="action-label">SAFE PREVIEW</span><span className="action-copy">{selected.remediation_preview || "No remediation preview authorized"}</span></div><button className="preview-button" onClick={() => setToast("Remediation preview opened · no device execution")}>Preview <ArrowUpRight size={13} /></button></div><div className="evidence-footer"><span><Clock3 size={13} /> live result</span><span><FileText size={13} /> source hash locked</span></div></> : <div className="empty-state">Select a finding to inspect evidence.</div>}</aside></section>
        <FindingsTrend history={history} onSelect={selectHistory} />
        <section className="lower-grid"><div className="topology-panel ruled-panel"><div className="panel-head"><div><div className="panel-eyebrow">NETWORK / NORMALIZED VIEW</div><h3>Topology signal</h3></div><button className="ghost-button compact" onClick={() => setToast("Topology is derived from normalized local metadata")}><Network size={14} /> inspect</button></div><div className="topology-body"><div className="topology-canvas" aria-label="Normalized network topology diagram"><span className="topology-line line-a" /><span className="topology-line line-b" /><span className="topology-line line-c" /><span className="topology-node node-firewall"><ShieldCheck size={16} /></span><span className="topology-node node-cisco">C</span><span className="topology-node node-junos">J</span><span className="topology-node node-fw">F</span><span className="topology-alert">!</span></div><div className="topology-legend"><span><i className="legend-orange" /> {report.summary.failed_count} attention point(s)</span><span><i className="legend-graphite" /> {report.summary.evaluated_count} evaluated</span><span><i className="legend-blue" /> {report.summary.mapped_finding_count} mapped</span></div></div></div><div className="queue-panel ruled-panel"><div className="panel-head"><div><div className="panel-eyebrow">LEARNING LOOP / {String(report.summary.unknown_count).padStart(2, "0")} OPEN</div><h3>Unknown syntax queue</h3></div><button className="text-button" onClick={() => { setStatusFilter("UNKNOWN"); setShowFilters(true); setActiveNav("Review queue"); }}>Review filtered <ArrowUpRight size={13} /></button></div>{report.findings.filter((finding) => finding.status === "UNKNOWN").slice(0, 3).map((finding, index) => <div className="queue-item" key={finding.finding_id}><div className="queue-index">{String(index + 1).padStart(2, "0")}</div><div><strong>{finding.control_id}</strong><small>{evidenceText(finding)}</small></div><span className="queue-state">PENDING</span></div>)}<div className="queue-foot"><Sparkles size={14} /> AI suggests. Operator approves. Control pack learns.</div></div></section><footer className="page-foot"><span>VEYRONIX · LOCAL SECURITY WORKBENCH</span><span>ALL OUTPUTS ARE EVIDENCE-BACKED · NO LIVE DEVICE CONNECTION</span><span className="mono">BUILD 0.3.0 / veyronix</span></footer></div><div className="toast"><span className="toast-mark"><Check size={12} /></span>{toast}</div></section>
  </main>;
}
