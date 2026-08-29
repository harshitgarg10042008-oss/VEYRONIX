/* Graphite Signal Console: route-backed evidence workbench with high-contrast themes and explicit review-only boundaries. */
import { useEffect, useMemo, useState, type ChangeEvent, type ReactNode } from "react";
import { jsPDF } from "jspdf";
import {
  AlertTriangle, ArrowRight, Check, ChevronDown, CircleHelp, ClipboardCheck,
  Clock3, Download, FileCheck2, FileText, Fingerprint, GitBranch, Layers3,
  LifeBuoy, LockKeyhole, Moon, Network, PanelRight, Play, Search, Settings2,
  ShieldCheck, SlidersHorizontal, Sparkles, Sun, TerminalSquare, Upload, X, Zap,
} from "lucide-react";
import { useLocation } from "wouter";
import { useTheme } from "../contexts/ThemeContext";

const logo = "/brand/configsentinel-mark-final.png";
const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");
const DEMO_CONFIGURATION = "version 17.9\nline vty 0 4\n transport input telnet\nlogging host 10.0.0.20\n";
const HISTORY_KEY = "veyronix.audit-history.v1";
const MAX_CONFIG_BYTES = 5 * 1024 * 1024;

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
  audit: { audit_id: string; vendor: string; parser_version: string; rule_pack_version: string; input_sha256: string; frameworks: string[]; framework_registry_version?: string };
  summary: { finding_count: number; failed_count: number; unknown_count: number; evaluated_count: number; mapped_finding_count: number; status_counts: Record<string, number> };
  findings: Finding[];
};
type ControlDefinition = { control_id: string; title: string; intent: string; severity: SeverityValue; framework_mappings: Record<string, string[]>; applicable_vendors: string[]; remediation: string };
type AuditHistoryEntry = { id: string; capturedAt: string; fileName: string; report: AuditReport };
type VendorDetection = { selected_vendor: string | null; confidence: number; ambiguous: boolean; reason: string; candidates: { vendor: string; confidence: number; parser_version: string }[] };
type ApprovalState = { resource_id: string; status: "NOT_REQUESTED" | "PENDING_REVIEW" | "APPROVED" | "REJECTED"; events: { event_id: string; actor_id: string; role: string; action: string; reason: string; created_at: string }[] };
type IconType = typeof Layers3;

const fallbackReport: AuditReport = {
  audit: { audit_id: "LOCAL_NOT_RUN", vendor: "auto", parser_version: "—", rule_pack_version: "—", input_sha256: "—", frameworks: ["cis-network", "nist-800-53"] },
  summary: { finding_count: 0, failed_count: 0, unknown_count: 0, evaluated_count: 0, mapped_finding_count: 0, status_counts: {} },
  findings: [],
};

const NAV_ITEMS: { label: string; path: string; icon: IconType; description: string }[] = [
  { label: "Overview", path: "/", icon: Layers3, description: "Posture at a glance" },
  { label: "Audits", path: "/audits", icon: ClipboardCheck, description: "Run and compare audits" },
  { label: "Review queue", path: "/review-queue", icon: CircleHelp, description: "Resolve unknown evidence" },
  { label: "Control packs", path: "/control-packs", icon: FileCheck2, description: "Inspect deterministic rules" },
  { label: "Remediation", path: "/remediation", icon: TerminalSquare, description: "Review proof-carrying fixes" },
];
const SYSTEM_ITEMS = [
  { label: "Settings", path: "/settings", icon: Settings2, description: "Local preferences" },
  { label: "Operator guide", path: "/operator-guide", icon: LifeBuoy, description: "Safe demo sequence" },
];

function readHistory(): AuditHistoryEntry[] {
  try {
    const raw = window.localStorage.getItem(HISTORY_KEY);
    const parsed = raw ? JSON.parse(raw) as AuditHistoryEntry[] : [];
    return Array.isArray(parsed) ? parsed.slice(0, 20) : [];
  } catch { return []; }
}
function persistHistory(entries: AuditHistoryEntry[]) { window.localStorage.setItem(HISTORY_KEY, JSON.stringify(entries.slice(0, 20))); }
function vendorLabel(vendor: string) { return vendor.replaceAll("_", " ").toUpperCase(); }
function postureScore(report: AuditReport) {
  const weights: Record<SeverityValue, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
  const applicable = report.findings.filter((finding) => finding.status !== "NOT_APPLICABLE");
  if (!applicable.length) return 0;
  const total = applicable.reduce((sum, finding) => sum + (weights[finding.severity] || 1), 0);
  const risk = applicable.reduce((sum, finding) => sum + ((finding.status === "FAIL" || finding.status === "UNKNOWN" || finding.status === "REVIEW_REQUIRED") ? (weights[finding.severity] || 1) : 0), 0);
  return Math.max(0, Math.round(((total - risk) / total) * 100));
}
function evidenceLine(finding: Finding) { const first = finding.evidence[0]; return first ? `L${first.start_line}` : "—"; }
function evidenceText(finding: Finding) { return finding.evidence.map((span) => span.excerpt).join(" · ") || "No evidence span recorded"; }
function frameworkText(finding: Finding) { return finding.framework_mappings?.map((row) => row.framework_id).join(" · ") || "UNVERIFIED"; }
function navLabel(path: string) { return [...NAV_ITEMS, ...SYSTEM_ITEMS].find((item) => item.path === path)?.label || "Overview"; }

function StatusPill({ status }: { status: FindingStatus }) { return <span className={`status-pill status-${status.toLowerCase()}`}><span className="status-dot" />{status.replace("_", " ")}</span>; }
function Severity({ value }: { value: SeverityValue }) { return <span className={`severity severity-${value.toLowerCase()}`}>{value}</span>; }
function SectionLabel({ children }: { children: ReactNode }) { return <div className="section-label">{children}</div>; }
function EmptyState({ title, detail, icon: Icon = FileText }: { title: string; detail: string; icon?: IconType }) { return <div className="empty-state"><Icon size={22} /><strong>{title}</strong><span>{detail}</span></div>; }

function FindingsTable({ findings, selectedId, onSelect, vendor }: { findings: Finding[]; selectedId: string; onSelect: (finding: Finding) => void; vendor: string }) {
  return <div className="findings-table">
    <div className="table-head"><span>CONTROL / EVIDENCE</span><span>VENDOR</span><span>SEVERITY</span><span>STATUS</span></div>
    {findings.length === 0 ? <EmptyState title="No findings match this view" detail="Change the filters or run a local audit to populate the evidence table." /> : findings.map((finding) => <button type="button" className={`finding-row ${finding.finding_id === selectedId ? "finding-selected" : ""}`} key={finding.finding_id} onClick={() => onSelect(finding)}>
      <span className="finding-main"><span className={`finding-symbol symbol-${finding.status.toLowerCase()}`}>{finding.status === "FAIL" ? "!" : finding.status === "PASS" ? "✓" : "?"}</span><span><strong>{finding.control_id}</strong><small>{finding.observed_state || finding.rationale}</small><code>{evidenceLine(finding)} <span>{frameworkText(finding)}</span></code></span></span>
      <span className="vendor-label">{vendorLabel(vendor)}</span>
      <Severity value={finding.severity} />
      <StatusPill status={finding.status} />
    </button>)}
  </div>;
}

function EvidencePanel({ finding }: { finding?: Finding }) {
  if (!finding) return <aside className="evidence-panel"><SectionLabel>SELECTED FINDING</SectionLabel><EmptyState title="Select a finding" detail="Evidence and remediation context will appear here." icon={Fingerprint} /></aside>;
  return <aside className="evidence-panel"><div className="evidence-top"><SectionLabel>SELECTED FINDING</SectionLabel><span className="proof-tag"><LockKeyhole size={12} /> REVIEW ONLY</span></div><div className="evidence-id">{finding.control_id} · {finding.severity}</div><h3>{finding.observed_state || finding.rationale}</h3><div className="evidence-block"><SectionLabel>AUTHORITATIVE STATE</SectionLabel><div className="evidence-state"><StatusPill status={finding.status} /><span>{finding.expected_state || "Expected state is defined by the active control."}</span></div></div><div className="evidence-block"><SectionLabel>SOURCE EVIDENCE</SectionLabel>{finding.evidence.length ? finding.evidence.map((span) => <div className="evidence-line" key={`${span.start_line}-${span.end_line}`}><code>L{span.start_line}–L{span.end_line}</code><span>{span.excerpt}</span></div>) : <div className="muted-copy">No source span recorded. This finding remains unresolved.</div>}</div><div className="evidence-block"><SectionLabel>WHY IT MATTERS</SectionLabel><p className="muted-copy">{finding.rationale}</p></div><div className="evidence-footer"><span><Fingerprint size={13} /> confidence {(finding.confidence * 100).toFixed(0)}%</span><span>{frameworkText(finding)}</span></div></aside>;
}

function TrendPanel({ history, onSelect }: { history: AuditHistoryEntry[]; onSelect: (entry: AuditHistoryEntry) => void }) {
  const points = history.slice().reverse(); const max = Math.max(1, ...points.flatMap((item) => [item.report.summary.failed_count, item.report.summary.unknown_count]));
  return <section className="panel trend-panel"><div className="panel-head"><div><SectionLabel>LOCAL HISTORY / {history.length} SNAPSHOTS</SectionLabel><h3>Assurance trend</h3></div><div className="legend"><span><i className="legend-fail" /> failures</span><span><i className="legend-unknown" /> unknown</span></div></div>{history.length === 0 ? <EmptyState title="No history yet" detail="Run an audit to build a local posture trend." icon={Clock3} /> : <div className="trend-wrap"><svg className="trend-svg" viewBox="0 0 100 100" role="img" aria-label="Failures and unknown findings across local audit history"><path className="chart-axis" d="M7 88H94M7 14V88" />{points.map((item, index) => { const x = points.length === 1 ? 50 : 8 + (index / (points.length - 1)) * 84; const failY = 86 - (item.report.summary.failed_count / max) * 68; const unknownY = 86 - (item.report.summary.unknown_count / max) * 68; return <g key={item.id} className="chart-point" tabIndex={0} role="button" aria-label={`${item.fileName}, ${item.report.summary.failed_count} failures, ${item.report.summary.unknown_count} unknown`} onClick={() => onSelect(item)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") onSelect(item); }}><circle cx={x} cy={failY} r="2.6" className="point-fail" /><circle cx={x} cy={unknownY} r="2.6" className="point-unknown" /><title>{item.fileName} · {item.report.summary.failed_count} failures · {item.report.summary.unknown_count} unknown</title></g>; })}</svg><div className="trend-foot"><span>{new Date(points[0].capturedAt).toLocaleDateString()}</span><span>Select a point to load an audit</span><span>{new Date(points.at(-1)!.capturedAt).toLocaleDateString()}</span></div></div>}</section>;
}

function HistoryPanel({ history, onSelect, onDelete, onExport }: { history: AuditHistoryEntry[]; onSelect: (entry: AuditHistoryEntry) => void; onDelete: (entry: AuditHistoryEntry) => void; onExport: (entry: AuditHistoryEntry) => void }) {
  return <section className="panel history-panel"><div className="panel-head"><div><SectionLabel>LOCAL STORAGE / LATEST 20</SectionLabel><h3>Audit snapshots</h3></div><span className="count-badge">{history.length.toString().padStart(2, "0")}</span></div>{history.length === 0 ? <EmptyState title="Nothing saved" detail="Completed audits appear here for comparison and export." icon={Clock3} /> : <div className="history-list">{history.map((entry) => <div className="history-row" key={entry.id}><button type="button" className="history-select" onClick={() => onSelect(entry)}><span className="history-time">{new Date(entry.capturedAt).toLocaleString()}</span><strong>{entry.fileName}</strong><small>{entry.report.audit.vendor} · {entry.report.summary.failed_count} failures · {entry.report.summary.unknown_count} unknown</small></button><button type="button" className="icon-action" aria-label={`Export ${entry.fileName}`} onClick={() => onExport(entry)}><Download size={14} /></button><button type="button" className="icon-action danger" aria-label={`Delete ${entry.fileName}`} onClick={() => onDelete(entry)}><X size={14} /></button></div>)}</div>}</section>;
}

function PageIntro({ eyebrow, title, detail, action }: { eyebrow: string; title: string; detail: string; action?: ReactNode }) { return <div className="page-intro"><div><SectionLabel>{eyebrow}</SectionLabel><h1>{title}</h1><p>{detail}</p></div>{action && <div className="intro-action">{action}</div>}</div>; }
function Metric({ label, value, note, tone = "neutral" }: { label: string; value: string; note: string; tone?: string }) { return <div className={`metric metric-${tone}`}><SectionLabel>{label}</SectionLabel><strong>{value}</strong><span>{note}</span></div>; }

export default function Home() {
  const [location, setLocation] = useLocation();
  const { theme, toggleTheme } = useTheme();
  const [report, setReport] = useState<AuditReport>(fallbackReport);
  const [selectedId, setSelectedId] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityValue | "ALL">("ALL");
  const [statusFilter, setStatusFilter] = useState<FindingStatus | "ALL">("ALL");
  const [frameworkFilter, setFrameworkFilter] = useState("ALL");
  const [showFilters, setShowFilters] = useState(false);
  const [toast, setToast] = useState("Offline-first workbench ready");
  const [running, setRunning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [apiOnline, setApiOnline] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [history, setHistory] = useState<AuditHistoryEntry[]>(() => readHistory());
  const [selectedFileName, setSelectedFileName] = useState("bundled-fixture.conf");
  const [controlPack, setControlPack] = useState<ControlDefinition[]>([]);
  const [controlPackVersion, setControlPackVersion] = useState("—");
  const [sdkVersion, setSdkVersion] = useState("—");
  const [detection, setDetection] = useState<VendorDetection | null>(null);
  const [approval, setApproval] = useState<ApprovalState | null>(null);

  const activeNav = navLabel(location);
  const loadReport = async (configText = DEMO_CONFIGURATION, fileName = "bundled-fixture.conf", vendor = "cisco_ios") => {
    setLoading(true);
    try {
      const health = await fetch(`${API_BASE}/api/health`); if (!health.ok) throw new Error("API unavailable"); setApiOnline(true);
      let selectedVendor = vendor;
      if (vendor === "auto") {
        const detectionResponse = await fetch(`${API_BASE}/api/detect`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ config_text: configText }) });
        if (!detectionResponse.ok) throw new Error(`Detection returned ${detectionResponse.status}`);
        const nextDetection = await detectionResponse.json() as VendorDetection; setDetection(nextDetection);
        if (!nextDetection.selected_vendor) throw new Error(nextDetection.reason);
        selectedVendor = nextDetection.selected_vendor;
      }
      const response = await fetch(`${API_BASE}/api/audit`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ config_text: configText, vendor: selectedVendor, frameworks: ["cis-network", "nist-800-53"], project_id: fileName }) });
      if (!response.ok) throw new Error(`Audit returned ${response.status}`);
      const nextReport = await response.json() as AuditReport; const entry = { id: `${nextReport.audit.audit_id}-${Date.now()}`, capturedAt: new Date().toISOString(), fileName, report: nextReport };
      const nextHistory = [entry, ...history.filter((item) => item.report.audit.audit_id !== nextReport.audit.audit_id)]; setHistory(nextHistory); persistHistory(nextHistory); setReport(nextReport); setSelectedId(nextReport.findings[0]?.finding_id || ""); setSelectedFileName(fileName); setToast(`Audit loaded · ${vendorLabel(nextReport.audit.vendor)} · ${nextReport.summary.failed_count} failure(s) require review`);
    } catch (error) { setApiOnline(false); setToast(`Audit unavailable · ${error instanceof Error ? error.message : "start the local backend"}`); } finally { setLoading(false); }
  };
  const refreshApproval = async (resourceId = report.audit.audit_id) => {
    if (!API_BASE || resourceId === "LOCAL_NOT_RUN") return;
    try {
      const response = await fetch(`${API_BASE}/api/approval/${encodeURIComponent(resourceId)}`);
      if (response.ok) setApproval(await response.json() as ApprovalState);
    } catch { setApproval(null); }
  };
  const requestApproval = async () => {
    if (!API_BASE || report.audit.audit_id === "LOCAL_NOT_RUN") return setToast("Approval unavailable · start the local API");
    try {
      const response = await fetch(`${API_BASE}/api/approval/request`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ resource_id: report.audit.audit_id, actor_id: "local-operator", role: "operator", reason: "Request review of remediation preview" }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || `Approval request returned ${response.status}`);
      setApproval(data as ApprovalState); setToast("Approval requested · waiting for independent review");
    } catch (error) { setToast(`Approval request failed · ${error instanceof Error ? error.message : "unknown error"}`); }
  };
  const decideApproval = async (approve: boolean) => {
    if (!API_BASE || report.audit.audit_id === "LOCAL_NOT_RUN") return setToast("Approval unavailable · start the local API");
    try {
      const response = await fetch(`${API_BASE}/api/approval/decision`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ resource_id: report.audit.audit_id, actor_id: "local-reviewer", role: "reviewer", approve, reason: approve ? "Independent review approved preview" : "Independent review rejected preview" }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || `Approval decision returned ${response.status}`);
      setApproval(data as ApprovalState); setToast(`Approval ${approve ? "approved" : "rejected"} by independent reviewer`);
    } catch (error) { setToast(`Approval decision failed · ${error instanceof Error ? error.message : "unknown error"}`); }
  };
  useEffect(() => {
    void refreshApproval();
  }, [report.audit.audit_id]);
  useEffect(() => {
    const latest = history[0];
    if (latest) { setReport(latest.report); setSelectedId(latest.report.findings[0]?.finding_id || ""); setSelectedFileName(latest.fileName); setLoading(false); }
    else void loadReport();
    void fetch(`${API_BASE}/api/control-pack`).then((response) => response.ok ? response.json() as Promise<{ version: string; controls: ControlDefinition[] }> : Promise.reject()).then((data) => { setControlPack(data.controls); setControlPackVersion(data.version); }).catch(() => setToast("Control-pack metadata unavailable · run the local API"));
    void fetch(`${API_BASE}/api/health`).then((response) => response.ok ? response.json() as Promise<{ status: string; version?: string }> : Promise.reject()).then((data) => { if (data.version) setSdkVersion(data.version); }).catch(() => { });
  }, []);
  const visibleFindings = useMemo(() => report.findings.filter((finding) => (severityFilter === "ALL" || finding.severity === severityFilter) && (statusFilter === "ALL" || finding.status === statusFilter) && (frameworkFilter === "ALL" || finding.framework_mappings?.some((row) => row.framework_id === frameworkFilter))), [report.findings, severityFilter, statusFilter, frameworkFilter]);
  const selected = useMemo(() => visibleFindings.find((finding) => finding.finding_id === selectedId) || visibleFindings[0] || report.findings[0], [visibleFindings, selectedId, report.findings]);
  const reviewFindings = report.findings.filter((finding) => finding.status === "UNKNOWN" || finding.status === "REVIEW_REQUIRED");
  const failedFindings = report.findings.filter((finding) => finding.status === "FAIL");
  const filterCount = [severityFilter !== "ALL", statusFilter !== "ALL", frameworkFilter !== "ALL"].filter(Boolean).length;
  const frameworkOptions = useMemo(() => Array.from(new Set(report.findings.flatMap((finding) => finding.framework_mappings?.map((mapping) => mapping.framework_id) || []))).sort(), [report.findings]);
  const vendorCount = controlPack.length ? new Set(controlPack.flatMap((control) => control.applicable_vendors)).size : 0;
  const score = postureScore(report);
  const navigate = (path: string) => { setLocation(path); setMenuOpen(false); };
  const runAudit = async () => { setRunning(true); setToast("Submitting bundled configuration to local engine…"); await loadReport(); setRunning(false); };
  const handleFileUpload = async (event: ChangeEvent<HTMLInputElement>) => { const file = event.target.files?.[0]; event.target.value = ""; if (!file) return; if (file.size > MAX_CONFIG_BYTES || !/\.(cfg|conf|config|txt)$/i.test(file.name)) { setToast("Upload rejected · use a supported UTF-8 file under 5 MiB"); return; } setRunning(true); try { const text = await file.text(); if (!text.trim() || text.includes("\u0000")) throw new Error("empty or contains NUL bytes"); await loadReport(text, file.name, "auto"); } catch (error) { setToast(`Upload rejected · ${error instanceof Error ? error.message : "file is unreadable"}`); } finally { setRunning(false); } };
  const selectHistory = (entry: AuditHistoryEntry) => { setReport(entry.report); setSelectedId(entry.report.findings[0]?.finding_id || ""); setSelectedFileName(entry.fileName); setToast(`Loaded snapshot · ${entry.fileName}`); };
  const deleteHistory = (entry: AuditHistoryEntry) => { const next = history.filter((item) => item.id !== entry.id); setHistory(next); persistHistory(next); if (entry.report.audit.audit_id === report.audit.audit_id) { if (next[0]) selectHistory(next[0]); else { setReport(fallbackReport); setSelectedId(""); } } setToast(`Deleted local snapshot · ${entry.fileName}`); };
  const clearHistory = () => { setHistory([]); persistHistory([]); setReport(fallbackReport); setSelectedId(""); setToast("Local audit history cleared"); };
  const exportReport = (source = report, name = selectedFileName) => { const pdf = new jsPDF({ unit: "pt", format: "a4" }); pdf.setFillColor(theme === "dark" ? 20 : 38, theme === "dark" ? 27 : 42, theme === "dark" ? 38 : 36); pdf.rect(0, 0, 595, 84, "F"); pdf.setTextColor(248, 245, 237); pdf.setFontSize(19); pdf.text("CONFIGSENTINEL AI", 40, 40); pdf.setFontSize(9); pdf.text("LOCAL EVIDENCE REPORT · REVIEW ONLY", 40, 60); let y = 120; const write = (text: string, size = 10) => { pdf.setTextColor(38, 42, 36); pdf.setFontSize(size); const lines = pdf.splitTextToSize(text, 515); pdf.text(lines, 40, y); y += lines.length * (size + 4) + 8; if (y > 760) { pdf.addPage(); y = 45; } }; write(`Source: ${name}`); write(`Audit ${source.audit.audit_id} · Vendor ${source.audit.vendor}`); write(`Findings ${source.summary.finding_count} · Failures ${source.summary.failed_count} · Unknown ${source.summary.unknown_count}`); write(`Input SHA-256: ${source.audit.input_sha256}`, 9); source.findings.forEach((finding, index) => { write(`${index + 1}. ${finding.control_id} · ${finding.status} · ${finding.severity}`, 11); write(`Evidence: ${evidenceText(finding)} (${evidenceLine(finding)})`, 9); }); write("Safety note: evidence for operator review; no device mutation is authorized.", 9); pdf.save(`configsentinel-${source.audit.audit_id || "report"}.pdf`); setToast("Evidence PDF exported"); };
  const resetFilters = () => { setSeverityFilter("ALL"); setStatusFilter("ALL"); setFrameworkFilter("ALL"); };
  const exportRemediation = () => {
    const failed = report.findings.filter((finding) => finding.status === "FAIL");
    const lines = ["# ConfigSentinel AI remediation preview", "# NON-EXECUTABLE — review, approve, and test independently", `# Audit: ${report.audit.audit_id}`, `# Vendor: ${report.audit.vendor}`, `# Source SHA-256: ${report.audit.input_sha256}`, ""];
    if (!failed.length) lines.push("# No deterministic failures require a remediation preview.");
    failed.forEach((finding) => { lines.push(`# ${finding.control_id} · ${finding.severity}`, `# Evidence: ${evidenceText(finding)} (${evidenceLine(finding)})`, `# Proposed intent: ${finding.remediation_preview || "Manual review required"}`, ""); });
    const blob = new Blob([lines.join("\\n")], { type: "text/plain;charset=utf-8" }); const url = URL.createObjectURL(blob); const anchor = document.createElement("a"); anchor.href = url; anchor.download = `configsentinel-${report.audit.audit_id || "report"}-remediation-preview.txt`; anchor.click(); URL.revokeObjectURL(url); setToast("Non-executable remediation preview exported");
  };

  const auditActions = <><label className="button button-secondary"><Upload size={15} /> Upload config<input type="file" accept=".cfg,.conf,.config,.txt" onChange={handleFileUpload} hidden /></label><button className="button button-primary" type="button" onClick={runAudit} disabled={running}><Play size={15} /> {running ? "Running…" : "Run local audit"}</button></>;
  const pageContent = () => {
    if (location === "/audits") return <><PageIntro eyebrow="AUDITS / LOCAL EXECUTION" title="Run, compare, explain." detail="Every audit stays on this machine. Upload a configuration, inspect the resulting evidence, and keep a reviewable local history." action={<div className="action-row">{auditActions}</div>} /><div className="audit-toolbar"><div><SectionLabel>ACTIVE SOURCE</SectionLabel><strong>{selectedFileName}</strong><span>{apiOnline ? "API connected · deterministic engine" : "API offline · local fixture only"}</span></div><div className="action-row"><button type="button" className="button button-secondary" onClick={() => setShowFilters((value) => !value)}><SlidersHorizontal size={15} /> Filters {filterCount ? `(${filterCount})` : ""}</button><button type="button" className="button button-secondary" onClick={() => exportReport()}><Download size={15} /> Export PDF</button></div></div>{showFilters && <FilterBar severity={severityFilter} setSeverity={setSeverityFilter} status={statusFilter} setStatus={setStatusFilter} framework={frameworkFilter} frameworkOptions={frameworkOptions} setFramework={setFrameworkFilter} reset={resetFilters} />}<div className="two-column"><section className="panel"><div className="panel-head"><div><SectionLabel>REPORT / {report.audit.audit_id}</SectionLabel><h3>Findings from the latest audit</h3></div><span className="count-badge">{visibleFindings.length.toString().padStart(2, "0")}</span></div><FindingsTable findings={visibleFindings} vendor={report.audit.vendor} selectedId={selected?.finding_id || ""} onSelect={(finding) => setSelectedId(finding.finding_id)} /></section><EvidencePanel finding={selected} /></div><div className="two-column lower"><HistoryPanel history={history} onSelect={selectHistory} onDelete={deleteHistory} onExport={(entry) => exportReport(entry.report, entry.fileName)} /><TrendPanel history={history} onSelect={selectHistory} /></div></>;
    if (location === "/review-queue") return <><PageIntro eyebrow="REVIEW QUEUE / EVIDENCE GAPS" title="Unknown is a decision." detail="Resolve uncertainty deliberately. These findings are not passes, and they never become authoritative without new evidence." action={<span className="queue-readout"><span className="signal signal-amber" /> {reviewFindings.length.toString().padStart(2, "0")} unresolved</span>} /><div className="queue-banner"><div className="queue-icon"><CircleHelp size={22} /></div><div><strong>Review before you trust the posture.</strong><span>Unknown blocks, parser gaps, and contested evidence remain visible until an operator provides a bounded explanation or reruns the deterministic audit.</span></div><button type="button" className="button button-secondary" onClick={() => navigate("/audits")}>Open audits <ArrowRight size={15} /></button></div><div className="two-column"><section className="panel"><div className="panel-head"><div><SectionLabel>UNRESOLVED FINDINGS</SectionLabel><h3>Evidence needing attention</h3></div><span className="count-badge">{reviewFindings.length.toString().padStart(2, "0")}</span></div><FindingsTable findings={reviewFindings} vendor={report.audit.vendor} selectedId={selected?.finding_id || ""} onSelect={(finding) => setSelectedId(finding.finding_id)} /></section><EvidencePanel finding={selected} /></div></>;
    if (location === "/control-packs") return <><PageIntro eyebrow="CONTROL PACKS / DETERMINISTIC" title="Rules with receipts." detail="Inspect the control surface behind every result. Version, vendor scope, framework mappings, and remediation intent stay explicit." action={<button type="button" className="button button-secondary" onClick={() => setToast("Custom policy packs are loaded through the CLI/API boundary")}> <GitBranch size={15} /> Policy boundary</button>} /><div className="control-summary"><Metric label="ACTIVE PACK" value={`v${controlPackVersion}`} note="backend-authoritative" tone="verified" /><Metric label="CONTROLS" value={controlPack.length.toString().padStart(2, "0")} note="deterministic definitions" /><Metric label="VENDORS" value={vendorCount.toString().padStart(2, "0")} note="from active control registry" /><Metric label="AI ROLE" value="OFF" note="non-authoritative only" tone="safe" /></div>{detection && <div className="queue-banner"><div className="queue-icon"><Fingerprint size={22} /></div><div><strong>Parser selection: {detection.selected_vendor ? vendorLabel(detection.selected_vendor) : "UNRESOLVED"}</strong><span>{(detection.confidence * 100).toFixed(0)}% confidence · {detection.reason}</span></div><span className="proof-tag">DETERMINISTIC</span></div>}<section className="panel control-list"><div className="panel-head"><div><SectionLabel>BUILT-IN / V{controlPackVersion}</SectionLabel><h3>Network assurance controls</h3></div><span className="proof-tag"><ShieldCheck size={12} /> hash-addressed</span></div>{controlPack.length === 0 ? <EmptyState title="Control metadata unavailable" detail="Start the local API to inspect the authoritative rule registry." icon={CircleHelp} /> : controlPack.map((control, index) => <div className="control-row" key={control.control_id}><span className="control-index">{String(index + 1).padStart(2, "0")}</span><span><strong>{control.title}</strong><small>{control.intent}</small></span><code>{control.control_id} · v{controlPackVersion}</code><span className="control-state"><span className="signal signal-teal" /> {control.severity}</span></div>)}</section></>;
    if (location === "/remediation") return <><PageIntro eyebrow="REMEDIATION / PROOF-CARRYING" title="Preview the change. Prove the boundary." detail="Remediation is a review artifact, never an autonomous action. Every suggestion is bound to source, evidence, preconditions, and rollback metadata." action={<span className="queue-readout"><LockKeyhole size={14} /> NON-EXECUTABLE</span>} /><div className="remediation-guard"><div className="guard-icon"><LockKeyhole size={21} /></div><div><strong>Operator approval is mandatory.</strong><span>ConfigSentinel AI can suggest a diff, but it cannot connect to a device, apply configuration, or turn an explanation into a verdict.</span></div><span className="proof-tag">SAFE PREVIEW</span></div><section className="panel remediation-list"><div className="panel-head"><div><SectionLabel>FAILED CONTROLS / {failedFindings.length}</SectionLabel><h3>Proof-carrying remediation previews</h3></div><div className="action-row"><span className="proof-tag">{approval?.status || "NOT_REQUESTED"}</span>{approval?.status === "NOT_REQUESTED" && <button type="button" className="button button-secondary" onClick={requestApproval}>Request review</button>}{approval?.status === "PENDING_REVIEW" && <><button type="button" className="button button-secondary" onClick={() => void decideApproval(true)}>Approve</button><button type="button" className="button button-danger" onClick={() => void decideApproval(false)}>Reject</button></>}<button type="button" className="button button-secondary" onClick={exportRemediation}> <Download size={15} /> Download preview</button></div></div>{failedFindings.length === 0 ? <EmptyState title="No failed controls" detail="Run an audit with a failing control to generate a review-only preview." icon={Check} /> : failedFindings.map((finding) => <div className="remediation-row" key={finding.finding_id}><span className="finding-symbol symbol-fail">!</span><span><strong>{finding.control_id}</strong><small>{finding.remediation_preview || "Review remediation intent after evidence inspection."}</small></span><span className="hash-chip"><Fingerprint size={12} /> source-bound</span><button type="button" className="button button-tertiary" onClick={() => { setSelectedId(finding.finding_id); navigate("/audits"); }}>Inspect <ArrowRight size={14} /></button></div>)}</section></>;
    if (location === "/settings") return <><PageIntro eyebrow="SYSTEM / SETTINGS" title="Make the console yours." detail="These settings affect only this browser session and local demo behavior. They never change the authoritative backend verdict engine." /><div className="settings-grid"><section className="settings-section"><SectionLabel>APPEARANCE</SectionLabel><h3>Theme preference</h3><p>Choose the contrast profile that is easiest for your eyes. Your preference is saved locally in this browser.</p><div className="theme-choice-row"><button type="button" className={`theme-choice ${theme === "light" ? "selected" : ""}`} onClick={() => theme === "dark" && toggleTheme?.()}><Sun size={18} /><span><strong>Light</strong><small>Paper and graphite</small></span>{theme === "light" && <Check size={16} />}</button><button type="button" className={`theme-choice ${theme === "dark" ? "selected" : ""}`} onClick={() => theme === "light" && toggleTheme?.()}><Moon size={18} /><span><strong>Dark</strong><small>Slate and signal</small></span>{theme === "dark" && <Check size={16} />}</button></div></section><section className="settings-section"><SectionLabel>LOCAL API</SectionLabel><h3>Connection boundary</h3><p>The dashboard talks only to the local FastAPI adapter. No cloud session or live device connection is configured.</p><div className="setting-line"><span>Endpoint</span><code>{API_BASE || "same-origin adapter"}</code></div><div className="setting-line"><span>Current state</span><strong className={apiOnline ? "text-teal" : "text-amber"}>{apiOnline ? "LOCAL API ONLINE" : "OFFLINE / FIXTURE MODE"}</strong></div></section><section className="settings-section"><SectionLabel>PRIVACY</SectionLabel><h3>Browser-local history</h3><p>Audit snapshots stay in localStorage and are limited to the latest 20 records. Clear them when the demonstration ends.</p><button type="button" className="button button-danger" onClick={clearHistory}><X size={15} /> Clear {history.length} saved snapshot(s)</button></section><section className="settings-section"><SectionLabel>SAFETY CONTRACT</SectionLabel><h3>What cannot happen here</h3><div className="safety-list"><span><Check size={14} /> No live device connections</span><span><Check size={14} /> No autonomous remediation</span><span><Check size={14} /> No verdict override by AI</span><span><Check size={14} /> No external submission</span></div></section></div></>;
    if (location === "/operator-guide") return <><PageIntro eyebrow="SYSTEM / OPERATOR GUIDE" title="A safe judging sequence." detail="Use this path to demonstrate the product clearly: show the evidence, acknowledge uncertainty, and never imply that a preview changes a device." /><div className="guide-grid"><div className="guide-rail"><div className="guide-step active"><span>01</span><div><strong>Run a local audit</strong><small>Start with the bundled fixture or upload a supported config.</small></div></div><div className="guide-step"><span>02</span><div><strong>Inspect the evidence</strong><small>Select a finding and show source lines, mapping, and confidence.</small></div></div><div className="guide-step"><span>03</span><div><strong>Explain unknowns</strong><small>Open Review Queue and show why uncertainty is not a pass.</small></div></div><div className="guide-step"><span>04</span><div><strong>Preview remediation</strong><small>Show proof-carrying metadata and the non-executable boundary.</small></div></div></div><section className="guide-callout"><Sparkles size={23} /><SectionLabel>THE ONE-LINE PITCH</SectionLabel><h2>“See the proof behind every finding.”</h2><p>ConfigSentinel AI is an offline-first evidence workbench for network assurance. The deterministic engine owns the verdict; AI, if enabled, can only explain or suggest.</p><button type="button" className="button button-primary" onClick={() => navigate("/")}>Return to overview <ArrowRight size={15} /></button></section></div></>;
    return <><div className="overview-hero"><div><SectionLabel>LIVE AUDIT DESK · REDACTED INPUT</SectionLabel><h1>Configuration posture.<br /><em>Evidence attached.</em></h1><p>See the proof behind every finding with a deterministic local audit path.</p><div className="hero-meta"><span><span className="signal signal-teal" /> {apiOnline ? "LOCAL API ONLINE" : "OFFLINE FIXTURE"}</span><span><LockKeyhole size={12} /> NO LIVE DEVICE</span><span><Fingerprint size={12} /> SHA-256 BOUND</span></div></div><div className="hero-score"><span>POSTURE SCORE</span><strong>{score}<small>/100</small></strong><div className="score-track"><i style={{ width: `${score}%` }} /></div><span>derived from current findings</span></div></div><div className="overview-actions"><div><SectionLabel>CURRENT WORKSPACE</SectionLabel><strong>{selectedFileName}</strong><span>{loading ? "Loading deterministic report…" : `${report.summary.finding_count} findings · ${report.summary.failed_count} failures · ${report.summary.unknown_count} unknown`}</span></div><div className="action-row">{auditActions}<button type="button" className="button button-secondary" onClick={() => navigate("/review-queue")}><CircleHelp size={15} /> Review queue {reviewFindings.length ? `(${reviewFindings.length})` : ""}</button></div></div><div className="metrics-grid"><Metric label="FAILURES" value={report.summary.failed_count.toString().padStart(2, "0")} note="require attention" tone={report.summary.failed_count ? "danger" : "safe"} /><Metric label="UNKNOWN" value={report.summary.unknown_count.toString().padStart(2, "0")} note="review before trust" tone="warn" /><Metric label="EVALUATED" value={report.summary.evaluated_count.toString().padStart(2, "0")} note="deterministic results" /><Metric label="SAVED AUDITS" value={history.length.toString().padStart(2, "0")} note="browser-local history" /></div><div className="two-column"><section className="panel"><div className="panel-head"><div><SectionLabel>POSTURE / LATEST REPORT</SectionLabel><h3>Findings requiring attention</h3></div><button type="button" className="button button-tertiary" onClick={() => navigate("/audits")}>Open audits <ArrowRight size={14} /></button></div><FindingsTable findings={visibleFindings.slice(0, 5)} vendor={report.audit.vendor} selectedId={selected?.finding_id || ""} onSelect={(finding) => setSelectedId(finding.finding_id)} /></section><EvidencePanel finding={selected} /></div><div className="two-column lower"><TrendPanel history={history} onSelect={selectHistory} /><HistoryPanel history={history} onSelect={selectHistory} onDelete={deleteHistory} onExport={(entry) => exportReport(entry.report, entry.fileName)} /></div></>;
  };

  return <main className="app-shell"><aside className="sidebar"><div className="brand-lockup"><div className="brand-mark-wrap"><img src={logo} alt="ConfigSentinel AI mark" className="brand-mark" /></div><div><div className="brand-name">CONFIGSENTINEL</div><div className="brand-sub">AI · OFFLINE SECURITY</div><div className="brand-team">BY VEYRONIX</div></div></div><div className="workspace-switcher"><SectionLabel>WORKSPACE</SectionLabel><button type="button" className="workspace-button" onClick={() => setToast("Workspace is local-demo only")}><span className="signal signal-teal" /> SIH / FIELD LAB <ChevronDown size={14} /></button></div><nav className="nav-list" aria-label="Workbench navigation"><SectionLabel>WORKBENCH</SectionLabel>{NAV_ITEMS.map((item) => <NavItem key={item.path} item={item} active={location === item.path} onClick={() => navigate(item.path)} count={item.path === "/review-queue" ? reviewFindings.length : undefined} />)}<div className="nav-spacer"><SectionLabel>SYSTEM</SectionLabel></div>{SYSTEM_ITEMS.map((item) => <NavItem key={item.path} item={item} active={location === item.path} onClick={() => navigate(item.path)} />)}</nav><div className="sidebar-foot"><div className="local-badge"><span className={`signal ${apiOnline ? "signal-teal" : "signal-amber"}`} /> {apiOnline ? "LOCAL API ONLINE" : "OFFLINE MODE"}</div><div className="sidebar-foot-row"><span>SDK</span><strong>{sdkVersion}</strong></div><div className="sidebar-foot-row"><span>THEME</span><strong>{theme.toUpperCase()}</strong></div></div></aside><section className="workbench"><header className="topbar"><div className="breadcrumb"><span className="breadcrumb-muted">WORKBENCH</span><span>/</span><strong>{activeNav.toUpperCase()}</strong></div><div className="topbar-actions"><span className="topbar-status"><span className={`signal ${apiOnline ? "signal-teal" : "signal-amber"}`} /> {apiOnline ? "DETERMINISTIC" : "LOCAL DEMO"}</span><button type="button" className="theme-toggle" onClick={() => toggleTheme?.()} aria-label={`Switch to ${theme === "light" ? "dark" : "light"} mode`}>{theme === "light" ? <Moon size={16} /> : <Sun size={16} />}<span>{theme === "light" ? "Dark" : "Light"}</span></button><button type="button" className="icon-button" aria-label="Search" onClick={() => setToast("Search is scoped to the active audit")}><Search size={17} /></button><button type="button" className="avatar-button" onClick={() => setMenuOpen((open) => !open)} aria-label="Open operator menu">HG</button>{menuOpen && <div className="operator-menu"><strong>HARSHIT GARG</strong><span>operator · local only</span><button type="button" onClick={() => { setMenuOpen(false); navigate("/settings"); }}>Open settings <ArrowRight size={13} /></button></div>}</div></header><div className="content-scroll"><div className="content-inner">{pageContent()}</div></div></section><div className="toast" role="status"><span className="toast-mark">{apiOnline ? <Check size={12} /> : <Zap size={12} />}</span>{toast}</div></main>;
}

function NavItem({ item, active, onClick, count }: { item: { label: string; path: string; icon: IconType; description: string }; active: boolean; onClick: () => void; count?: number }) { const Icon = item.icon; return <button type="button" className={`nav-item ${active ? "nav-item-active" : ""}`} onClick={onClick} title={item.description}><span className="nav-icon"><Icon size={16} strokeWidth={1.8} /></span><span className="nav-copy"><strong>{item.label}</strong><small>{item.description}</small></span>{count !== undefined && <span className="nav-count">{count.toString().padStart(2, "0")}</span>}</button>; }
function FilterBar({ severity, setSeverity, status, setStatus, framework, frameworkOptions, setFramework, reset }: { severity: SeverityValue | "ALL"; setSeverity: (value: SeverityValue | "ALL") => void; status: FindingStatus | "ALL"; setStatus: (value: FindingStatus | "ALL") => void; framework: string; frameworkOptions: string[]; setFramework: (value: string) => void; reset: () => void }) { return <div className="filter-bar"><label>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value as SeverityValue | "ALL")}><option value="ALL">All severities</option>{["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((value) => <option key={value} value={value}>{value}</option>)}</select></label><label>Status<select value={status} onChange={(event) => setStatus(event.target.value as FindingStatus | "ALL")}><option value="ALL">All statuses</option>{["FAIL", "PASS", "UNKNOWN", "REVIEW_REQUIRED"].map((value) => <option key={value} value={value}>{value}</option>)}</select></label><label>Framework<select value={framework} onChange={(event) => setFramework(event.target.value)}><option value="ALL">All frameworks</option>{frameworkOptions.map((value) => <option key={value} value={value}>{value.replaceAll("-", " ").toUpperCase()}</option>)}</select></label><button type="button" className="button button-tertiary" onClick={reset}>Reset</button></div>; }
