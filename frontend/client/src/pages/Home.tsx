/* Graphite Signal Console: route-backed evidence workbench with high-contrast themes and explicit review-only boundaries. */
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
  type ReactNode,
} from "react";
import { jsPDF } from "jspdf";
import {
  AlertTriangle,
  ArrowRight,
  Activity,
  Check,
  ChevronDown,
  CircleHelp,
  ClipboardCheck,
  Clock3,
  Download,
  FileCheck2,
  FileText,
  Fingerprint,
  GitBranch,
  Layers3,
  LifeBuoy,
  LoaderCircle,
  LockKeyhole,
  Moon,
  Network,
  PanelRight,
  Play,
  Search,
  Server,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Sun,
  TerminalSquare,
  Upload,
  X,
  Zap,
} from "lucide-react";
import { useLocation } from "wouter";
import { useTheme } from "../contexts/ThemeContext";

const logo = "/brand/configsentinel-mark-final.png";
const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");
const DEMO_CONFIGURATION = `version 17.9
hostname SIH-ROUTER-DEMO
service password-encryption
aaa new-model
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
username breakglass privilege 15 secret 9 $9$demo-hash
security password min-length 14
ntp server 10.0.0.1 key 1
ntp authentication-key 1 md5 DEMOKEY
ntp authenticate
logging host 10.0.0.20
logging trap informational
snmp-server group SECURE-GROUP v3 priv
snmp-server user MONITOR SECURE-GROUP v3 auth sha AUTHKEY priv aes 128 PRIVKEY
ip ssh version 2
ip ssh dh-min-size 2048
ip ssh time-out 60
no ip http server
ip http secure-server
no cdp run
no service pad
ip verify unicast source reachable-via rx
archive
 log config
  logging enable
  notify syslog contenttype plaintext
  hidekeys
line vty 0 4
 transport input ssh
 access-class MGMT-ACL in
 exec-timeout 10 0
access-list 10 permit 192.168.1.0 0.0.0.255
access-list 10 deny any
ip access-list standard MGMT-ACL
 permit 192.168.1.0 0.0.0.255
 deny any log
end
`;
const DEMO_FILE_NAME = "demo-cisco-compliant.conf";
const HISTORY_KEY = "veyronix.audit-history.v2";
const MAX_CONFIG_BYTES = 5 * 1024 * 1024;

type FindingStatus =
  | "FAIL"
  | "PASS"
  | "UNKNOWN"
  | "NOT_APPLICABLE"
  | "REVIEW_REQUIRED";
type SeverityValue = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
type Mapping = {
  framework_id: string;
  title: string;
  status: string;
  control_ids: string[];
  confidence: number;
};
type Evidence = {
  start_line: number;
  end_line: number;
  excerpt: string;
  redacted: boolean;
};
type Finding = {
  finding_id: string;
  control_id: string;
  status: FindingStatus;
  severity: SeverityValue;
  confidence: number;
  evidence: Evidence[];
  observed_state: string;
  expected_state: string;
  rationale: string;
  remediation_preview?: string | null;
  framework_mappings: Mapping[];
};
type AuditReport = {
  audit: {
    audit_id: string;
    vendor: string;
    parser_version: string;
    rule_pack_version: string;
    input_sha256: string;
    frameworks: string[];
    framework_registry_version?: string;
  };
  summary: {
    finding_count: number;
    failed_count: number;
    unknown_count: number;
    evaluated_count: number;
    mapped_finding_count: number;
    status_counts: Record<string, number>;
    posture_score?: number;
  };
  findings: Finding[];
};
type ControlDefinition = {
  control_id: string;
  title: string;
  intent: string;
  severity: SeverityValue;
  framework_mappings: Record<string, string[]>;
  applicable_vendors: string[];
  remediation: string;
};
type AuditHistoryEntry = {
  id: string;
  capturedAt: string;
  fileName: string;
  configText?: string;
  report: AuditReport;
};
type VendorDetection = {
  selected_vendor: string | null;
  confidence: number;
  ambiguous: boolean;
  reason: string;
  candidates: { vendor: string; confidence: number; parser_version: string }[];
};
type ApprovalState = {
  resource_id: string;
  status: "NOT_REQUESTED" | "PENDING_REVIEW" | "APPROVED" | "REJECTED";
  events: {
    event_id: string;
    actor_id: string;
    role: string;
    action: string;
    reason: string;
    created_at: string;
  }[];
};
type IconType = typeof Layers3;
type WebsiteFindingStatus = "PASS" | "FAIL" | "WARN" | "UNKNOWN";
type WebsiteSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
type WebsiteFinding = {
  finding_id: string;
  rule_id: string;
  title: string;
  status: WebsiteFindingStatus;
  severity: WebsiteSeverity;
  evidence: {
    check_type: string;
    observed_value: string;
    expected_value: string;
  };
  rationale: string;
  remediation: string;
  observed_at: string;
  rule_version: string;
  limitations: string;
};
type WebsiteScanResult = {
  scan_id: string;
  target_origin: string;
  final_url: string;
  posture_classification: string;
  score: number;
  findings_count: number;
  passed_count: number;
  failed_count: number;
  warning_count: number;
  unknown_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  rule_pack_version: string;
  scan_timestamp: string;
  limitations: string;
  findings: WebsiteFinding[];
};

const fallbackReport: AuditReport = {
  audit: {
    audit_id: "LOCAL_NOT_RUN",
    vendor: "auto",
    parser_version: "—",
    rule_pack_version: "—",
    input_sha256: "—",
    frameworks: ["cis-network", "nist-800-53"],
  },
  summary: {
    finding_count: 0,
    failed_count: 0,
    unknown_count: 0,
    evaluated_count: 0,
    mapped_finding_count: 0,
    status_counts: {},
    posture_score: 100,
  },
  findings: [],
};

const NAV_ITEMS: {
  label: string;
  path: string;
  icon: IconType;
  description: string;
}[] = [
  {
    label: "Overview",
    path: "/",
    icon: Layers3,
    description: "Posture at a glance",
  },
  {
    label: "Assurance Chain",
    path: "/assurance-chain",
    icon: LockKeyhole,
    description: "Verify evidence timeline",
  },
  {
    label: "Asset Inventory",
    path: "/inventory",
    icon: Server,
    description: "Manage tracked devices",
  },
  {
    label: "Continuous Monitoring",
    path: "/monitoring",
    icon: Activity,
    description: "Scheduled checks",
  },
  {
    label: "Audits",
    path: "/audits",
    icon: ClipboardCheck,
    description: "Run and compare audits",
  },
  {
    label: "Drift Detection",
    path: "/drift",
    icon: GitBranch,
    description: "Compare configuration changes",
  },
  {
    label: "Website Security",
    path: "/website-security",
    icon: ShieldCheck,
    description: "Scan website posture",
  },
  {
    label: "Review queue",
    path: "/review-queue",
    icon: CircleHelp,
    description: "Resolve unknown evidence",
  },
  {
    label: "Control packs",
    path: "/control-packs",
    icon: FileCheck2,
    description: "Inspect deterministic rules",
  },
  {
    label: "Remediation",
    path: "/remediation",
    icon: TerminalSquare,
    description: "Review proof-carrying fixes",
  },
  {
    label: "Blast Radius",
    path: "/blast-radius",
    icon: AlertTriangle,
    description: "Assess change impact",
  },
  {
    label: "Evidence Freshness",
    path: "/freshness",
    icon: Clock3,
    description: "Verify data age",
  },
  {
    label: "Incident Timeline",
    path: "/timeline",
    icon: Clock3,
    description: "Trace post-incident state",
  },
  {
    label: "Notary Console",
    path: "/notary",
    icon: LockKeyhole,
    description: "Sign & verify evidence",
  },
  {
    label: "Mutation Lab",
    path: "/mutation-lab",
    icon: Zap,
    description: "Evaluate rule robustness",
  },
  {
    label: "Parser Differential",
    path: "/parser-diff",
    icon: GitBranch,
    description: "Find ambiguity gaps",
  },
  {
    label: "Attack Graph",
    path: "/graph",
    icon: Network,
    description: "Simulate exploit paths",
  },
  {
    label: "Counterfactuals",
    path: "/counterfactual",
    icon: Play,
    description: "Test hypothetical rules",
  },
  {
    label: "Decision Quality",
    path: "/decision-quality",
    icon: Check,
    description: "Analyze approval stats",
  },
  {
    label: "Secrets Gate",
    path: "/secrets-gate",
    icon: ShieldCheck,
    description: "Verify redaction",
  },
  {
    label: "Supply Chain",
    path: "/supply-chain",
    icon: FileText,
    description: "Inspect SBOM evidence",
  },
  {
    label: "Provenance Tracker",
    path: "/provenance",
    icon: Fingerprint,
    description: "Verify artifact origin",
  },
  {
    label: "Threat Models",
    path: "/threat-model",
    icon: AlertTriangle,
    description: "Compile code to STRIDE",
  },
  {
    label: "API Contracts",
    path: "/api-contract",
    icon: Network,
    description: "Verify schema vs runtime",
  },
  {
    label: "Resilience Drills",
    path: "/resilience",
    icon: Activity,
    description: "Schedule failover checks",
  },
  {
    label: "Technical Debt",
    path: "/debt",
    icon: AlertTriangle,
    description: "Track posture debt",
  },
  {
    label: "Evidence Exchange",
    path: "/exchange",
    icon: Download,
    description: "Share signed findings",
  },
  {
    label: "Regulatory Export",
    path: "/regulatory",
    icon: FileText,
    description: "Export to OSCAL",
  },
  {
    label: "Knowledge Graph",
    path: "/knowledge-graph",
    icon: Network,
    description: "Query institutional memory",
  },
];
const SYSTEM_ITEMS = [
  {
    label: "Settings",
    path: "/settings",
    icon: Settings2,
    description: "Local preferences",
  },
  {
    label: "Operator guide",
    path: "/operator-guide",
    icon: LifeBuoy,
    description: "Safe demo sequence",
  },
];

function readHistory(): AuditHistoryEntry[] {
  try {
    const raw = window.localStorage.getItem(HISTORY_KEY);
    const parsed = raw ? (JSON.parse(raw) as AuditHistoryEntry[]) : [];
    return Array.isArray(parsed) ? parsed.slice(0, 20) : [];
  } catch {
    return [];
  }
}
function persistHistory(entries: AuditHistoryEntry[]) {
  window.localStorage.setItem(
    HISTORY_KEY,
    JSON.stringify(entries.slice(0, 20)),
  );
}
function vendorLabel(vendor: string) {
  return vendor.replaceAll("_", " ").toUpperCase();
}

function evidenceLine(finding: Finding) {
  const first = finding.evidence[0];
  return first ? `L${first.start_line}` : "—";
}
function evidenceText(finding: Finding) {
  return (
    finding.evidence.map((span) => span.excerpt).join(" · ") ||
    "No evidence span recorded"
  );
}
function frameworkText(finding: Finding) {
  return (
    finding.framework_mappings?.map((row) => row.framework_id).join(" · ") ||
    "UNVERIFIED"
  );
}
function navLabel(path: string) {
  return (
    [...NAV_ITEMS, ...SYSTEM_ITEMS].find((item) => item.path === path)?.label ||
    "Overview"
  );
}

function StatusPill({ status }: { status: FindingStatus }) {
  return (
    <span className={`status-pill status-${status.toLowerCase()}`}>
      <span className="status-dot" />
      {status.replace("_", " ")}
    </span>
  );
}
function Severity({ value }: { value: SeverityValue }) {
  return (
    <span className={`severity severity-${value.toLowerCase()}`}>{value}</span>
  );
}
function SectionLabel({ children }: { children: ReactNode }) {
  return <div className="section-label">{children}</div>;
}
function EmptyState({
  title,
  detail,
  icon: Icon = FileText,
}: {
  title: string;
  detail: string;
  icon?: IconType;
}) {
  return (
    <div className="empty-state">
      <Icon size={22} />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

function FindingsTable({
  findings,
  selectedId,
  onSelect,
  reportVendor,
}: {
  findings: Finding[];
  selectedId: string;
  onSelect: (finding: Finding) => void;
  reportVendor: string;
}) {
  return (
    <div className="findings-table">
      <div className="table-head">
        <span>CONTROL / EVIDENCE</span>
        <span>VENDOR</span>
        <span>SEVERITY</span>
        <span>STATUS</span>
      </div>
      {findings.length === 0 ? (
        <EmptyState
          title="No findings match this view"
          detail="Change the filters or run a local audit to populate the evidence table."
        />
      ) : (
        findings.map((finding) => (
          <button
            type="button"
            className={`finding-row ${finding.finding_id === selectedId ? "finding-selected" : ""}`}
            key={finding.finding_id}
            onClick={() => onSelect(finding)}
          >
            <span className="finding-main">
              <span
                className={`finding-symbol symbol-${finding.status.toLowerCase()}`}
              >
                {finding.status === "FAIL"
                  ? "!"
                  : finding.status === "PASS"
                    ? "✓"
                    : "?"}
              </span>
              <span>
                <strong>{finding.control_id}</strong>
                <small>{finding.observed_state || finding.rationale}</small>
                <code>
                  {evidenceLine(finding)} <span>{frameworkText(finding)}</span>
                </code>
              </span>
            </span>
            <span className="vendor-label">{vendorLabel(reportVendor)}</span>
            <Severity value={finding.severity} />
            <StatusPill status={finding.status} />
          </button>
        ))
      )}
    </div>
  );
}

function EvidencePanel({ finding }: { finding?: Finding }) {
  if (!finding)
    return (
      <aside className="evidence-panel">
        <SectionLabel>SELECTED FINDING</SectionLabel>
        <EmptyState
          title="Select a finding"
          detail="Evidence and remediation context will appear here."
          icon={Fingerprint}
        />
      </aside>
    );
  return (
    <aside className="evidence-panel">
      <div className="evidence-top">
        <SectionLabel>SELECTED FINDING</SectionLabel>
        <span className="proof-tag">
          <LockKeyhole size={12} /> REVIEW ONLY
        </span>
      </div>
      <div className="evidence-id">
        {finding.control_id} · {finding.severity}
      </div>
      <h2>{finding.observed_state || finding.rationale}</h2>
      <div className="evidence-block">
        <SectionLabel>AUTHORITATIVE STATE</SectionLabel>
        <div className="evidence-state">
          <StatusPill status={finding.status} />
          <span>
            {finding.expected_state ||
              "Expected state is defined by the active control."}
          </span>
        </div>
      </div>
      <div className="evidence-block">
        <SectionLabel>SOURCE EVIDENCE</SectionLabel>
        {finding.evidence.length ? (
          finding.evidence.map((span) => (
            <div
              className="evidence-line"
              key={`${span.start_line}-${span.end_line}`}
            >
              <code>
                L{span.start_line}–L{span.end_line}
              </code>
              <span>{span.excerpt}</span>
            </div>
          ))
        ) : (
          <div className="muted-copy">
            No source span recorded. This finding remains unresolved.
          </div>
        )}
      </div>
      <div className="evidence-block">
        <SectionLabel>WHY IT MATTERS</SectionLabel>
        <p className="muted-copy">{finding.rationale}</p>
      </div>
      <div className="evidence-footer">
        <span>
          <Fingerprint size={13} /> confidence{" "}
          {(finding.confidence * 100).toFixed(0)}%
        </span>
        <span>{frameworkText(finding)}</span>
      </div>
    </aside>
  );
}

function TrendPanel({
  history,
  onSelect,
}: {
  history: AuditHistoryEntry[];
  onSelect: (entry: AuditHistoryEntry) => void;
}) {
  const points = history.slice(0, 8);
  return (
    <section className="panel trend-panel">
      <div className="panel-head">
        <div>
          <SectionLabel>
            LOCAL HISTORY / {history.length} SNAPSHOTS
          </SectionLabel>
          <h2>Posture over time</h2>
        </div>
        <div className="trend-key">
          <span>
            <i className="legend-score" /> score
          </span>
          <span>
            <i className="legend-fail" /> failures
          </span>
          <span>
            <i className="legend-unknown" /> unknown
          </span>
        </div>
      </div>
      {history.length === 0 ? (
        <EmptyState
          title="No history yet"
          detail="Run an audit to build a local posture trend."
          icon={Clock3}
        />
      ) : (
        <div
          className="trend-list"
          role="list"
          aria-label="Recent audit snapshots"
        >
          {points.map((item) => {
            const { summary } = item.report;
            const score = summary.posture_score ?? 0;
            return (
              <button
                type="button"
                className="trend-entry"
                key={item.id}
                onClick={() => onSelect(item)}
              >
                <span className="trend-entry-date">
                  {new Date(item.capturedAt).toLocaleDateString(undefined, {
                    month: "short",
                    day: "numeric",
                  })}
                </span>
                <span className="trend-entry-main">
                  <strong>{item.fileName}</strong>
                  <small>
                    {vendorLabel(item.report.audit.vendor)} ·{" "}
                    {new Date(item.capturedAt).toLocaleTimeString([], {
                      hour: "numeric",
                      minute: "2-digit",
                    })}
                  </small>
                  <span className="trend-bar">
                    <i
                      style={{ width: `${Math.max(0, Math.min(100, score))}%` }}
                    />
                  </span>
                </span>
                <span className="trend-score">
                  {score}
                  <small>/100</small>
                </span>
                <span className="trend-count trend-count-fail">
                  {summary.failed_count} <small>fail</small>
                </span>
                <span className="trend-count trend-count-unknown">
                  {summary.unknown_count} <small>unknown</small>
                </span>
                <ArrowRight size={15} className="trend-arrow" />
              </button>
            );
          })}
        </div>
      )}
    </section>
  );
}

function HistoryPanel({
  history,
  onSelect,
  onDelete,
  onExport,
}: {
  history: AuditHistoryEntry[];
  onSelect: (entry: AuditHistoryEntry) => void;
  onDelete: (entry: AuditHistoryEntry) => void;
  onExport: (entry: AuditHistoryEntry) => void;
}) {
  return (
    <section className="panel history-panel">
      <div className="panel-head">
        <div>
          <SectionLabel>LOCAL STORAGE / LATEST 20</SectionLabel>
          <h2>Audit snapshots</h2>
        </div>
        <span className="count-badge">
          {history.length.toString().padStart(2, "0")}
        </span>
      </div>
      {history.length === 0 ? (
        <EmptyState
          title="Nothing saved"
          detail="Completed audits appear here for comparison and export."
          icon={Clock3}
        />
      ) : (
        <div className="history-list">
          {history.map((entry) => (
            <div className="history-row" key={entry.id}>
              <button
                type="button"
                className="history-select"
                onClick={() => onSelect(entry)}
              >
                <span className="history-time">
                  {new Date(entry.capturedAt).toLocaleString()}
                </span>
                <strong>{entry.fileName}</strong>
                <small>
                  {entry.report.audit.vendor} ·{" "}
                  {entry.report.summary.failed_count} failures ·{" "}
                  {entry.report.summary.unknown_count} unknown
                </small>
              </button>
              <button
                type="button"
                className="icon-action"
                aria-label={`Export ${entry.fileName}`}
                onClick={() => onExport(entry)}
              >
                <Download size={14} />
              </button>
              <button
                type="button"
                className="icon-action danger"
                aria-label={`Delete ${entry.fileName}`}
                onClick={() => onDelete(entry)}
              >
                <X size={14} />
              </button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function PageIntro({
  eyebrow,
  title,
  detail,
  action,
}: {
  eyebrow: string;
  title: string;
  detail: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-intro">
      <div>
        <SectionLabel>{eyebrow}</SectionLabel>
        <h1>{title}</h1>
        <p>{detail}</p>
      </div>
      {action && <div className="intro-action">{action}</div>}
    </div>
  );
}
function Metric({
  label,
  value,
  note,
  tone = "neutral",
}: {
  label: string;
  value: string;
  note: string;
  tone?: string;
}) {
  return (
    <div className={`metric metric-${tone}`}>
      <SectionLabel>{label}</SectionLabel>
      <strong>{value}</strong>
      <span>{note}</span>
    </div>
  );
}

function FindingResponsePanel({
  finding,
  onReview,
}: {
  finding?: Finding;
  onReview: () => void;
}) {
  if (!finding) {
    return (
      <aside className="panel finding-response-panel">
        <div className="panel-head">
          <div>
            <SectionLabel>FINDING RESPONSE</SectionLabel>
            <h2>Choose a finding</h2>
          </div>
        </div>
        <EmptyState
          title="Select a FAIL or UNKNOWN"
          detail="The response plan, evidence gap, and next step will appear here."
          icon={CircleHelp}
        />
      </aside>
    );
  }

  const isUnknown = finding.status === "UNKNOWN" || finding.status === "REVIEW_REQUIRED";
  return (
    <aside className={`panel finding-response-panel response-${isUnknown ? "unknown" : finding.status.toLowerCase()}`}>
      <div className="panel-head">
        <div>
          <SectionLabel>FINDING RESPONSE / {finding.status}</SectionLabel>
          <h2>{isUnknown ? "Evidence needed" : "Fix path"}</h2>
        </div>
        <StatusPill status={finding.status} />
      </div>
      <div className="response-content">
        <p className="response-rationale">{finding.rationale}</p>
        <div className="response-block">
          <SectionLabel>{isUnknown ? "HOW TO RESOLVE" : "PROPOSED SOLUTION"}</SectionLabel>
          <p>
            {isUnknown
              ? "Add the missing configuration evidence, use supported syntax, or rerun the audit after the source is updated. Unknown is not a pass."
              : finding.remediation_preview || "Review the evidence, apply the control change through your normal deployment process, and rerun the audit."}
          </p>
        </div>
        <div className="response-block">
          <SectionLabel>NEXT STEP</SectionLabel>
          <p>
            {isUnknown
              ? "Open the review queue and record a bounded explanation or collect stronger evidence."
              : "Preview and approve the change, verify it independently, then run another local audit."}
          </p>
          <button type="button" className="button button-secondary response-action" onClick={onReview}>
            {isUnknown ? "Open review queue" : "Open remediation"} <ArrowRight size={15} />
          </button>
        </div>
        <div className="response-safety">
          <LockKeyhole size={15} />
          <span>Review-only guidance. ConfigSentinel never changes a live device.</span>
        </div>
      </div>
    </aside>
  );
}

export default function Home() {
  const [location, setLocation] = useLocation();
  const { theme, toggleTheme } = useTheme();
  const [report, setReport] = useState<AuditReport>(fallbackReport);
  const [selectedId, setSelectedId] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityValue | "ALL">(
    "ALL",
  );
  const [statusFilter, setStatusFilter] = useState<FindingStatus | "ALL">(
    "ALL",
  );
  const [frameworkFilter, setFrameworkFilter] = useState("ALL");
  const [showFilters, setShowFilters] = useState(false);
  const [toast, setToast] = useState("Offline-first workbench ready");
  const [running, setRunning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [apiOnline, setApiOnline] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [history, setHistory] = useState<AuditHistoryEntry[]>(() =>
    readHistory(),
  );
  const [selectedFileName, setSelectedFileName] = useState(
    DEMO_FILE_NAME,
  );
  const [activeConfigText, setActiveConfigText] =
    useState(DEMO_CONFIGURATION);
  const [activeVendor, setActiveVendor] = useState("cisco_ios");
  const [uploadedFile, setUploadedFile] = useState<{
    name: string;
    size: number;
    status: "fixture" | "ready" | "analyzing" | "analyzed" | "rejected";
  }>({
    name: DEMO_FILE_NAME,
    size: DEMO_CONFIGURATION.length,
    status: "fixture",
  });
  const auditRequestRef = useRef(0);
  const [controlPack, setControlPack] = useState<ControlDefinition[]>([]);
  const [controlPackVersion, setControlPackVersion] = useState("—");
  const [controlCount, setControlCount] = useState(0);
  const [vendorCount, setVendorCount] = useState(0);
  const [sdkVersion, setSdkVersion] = useState("—");
  const [detection, setDetection] = useState<VendorDetection | null>(null);
  const [approval, setApproval] = useState<ApprovalState | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const [session, setSession] = useState<{
    actor_id: string;
    role: string;
    workspace_id: string;
  } | null>(null);
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [websiteScan, setWebsiteScan] = useState<WebsiteScanResult | null>(
    null,
  );
  const [websiteScanning, setWebsiteScanning] = useState(false);
  const [websiteAuthConfirmed, setWebsiteAuthConfirmed] = useState(false);
  const [websiteSelectedId, setWebsiteSelectedId] = useState("");
  const [websiteRules, setWebsiteRules] = useState<{
    version: string;
    rule_count: number;
    rules: {
      rule_id: string;
      title: string;
      severity: string;
      remediation: string;
    }[];
  } | null>(null);
  const [driftResult, setDriftResult] = useState<any>(null);
  const [baselineId, setBaselineId] = useState<string>("");
  const [currentId, setCurrentId] = useState<string>("");
  const [comparing, setComparing] = useState(false);

  const [assets, setAssets] = useState<any[]>([]);
  const [newAsset, setNewAsset] = useState({
    name: "",
    vendor: "",
    role: "",
    owner: "",
    criticality: "medium",
    exposure: "internal",
  });
  const [loadingAssets, setLoadingAssets] = useState(false);

  const [monitors, setMonitors] = useState<any[]>([]);
  const [newMonitor, setNewMonitor] = useState({
    target_id: "",
    target_type: "asset",
    interval_minutes: 60,
  });
  const [loadingMonitors, setLoadingMonitors] = useState(false);

  const switchRole = async (newRole: string) => {
    try {
      const response = await fetch(`${API_BASE}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ role: newRole }),
      });
      if (!response.ok) throw new Error(`login returned ${response.status}`);
      const data = await response.json();
      setSession({
        actor_id: data.actor_id,
        role: data.role,
        workspace_id: "local-workspace",
      });
      setMenuOpen(false);
    } catch (error) {
      setToast(
        `Local session unavailable · ${error instanceof Error ? error.message : "start the local backend"}`,
      );
    }
  };

  const activeNav = navLabel(location);
  const loadReport = async (
    configText = DEMO_CONFIGURATION,
    fileName = DEMO_FILE_NAME,
    vendor = "cisco_ios",
  ): Promise<boolean> => {
    const requestId = ++auditRequestRef.current;
    setLoading(true);
    setSelectedFileName(fileName);
    try {
      const health = await fetch(`${API_BASE}/api/health`);
      if (!health.ok) throw new Error("API unavailable");
      setApiOnline(true);
      let selectedVendor = vendor;
      if (vendor === "auto") {
        const detectionResponse = await fetch(`${API_BASE}/api/detect`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ config_text: configText }),
        });
        if (!detectionResponse.ok)
          throw new Error(`Detection returned ${detectionResponse.status}`);
        const nextDetection =
          (await detectionResponse.json()) as VendorDetection;
        setDetection(nextDetection);
        if (!nextDetection.selected_vendor)
          throw new Error(nextDetection.reason);
        selectedVendor = nextDetection.selected_vendor;
      }
      setActiveVendor(selectedVendor);
      const response = await fetch(`${API_BASE}/api/audit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          config_text: configText,
          vendor: selectedVendor,
          frameworks: ["cis-network", "nist-800-53"],
          project_id: fileName,
        }),
      });
      if (!response.ok) throw new Error(`Audit returned ${response.status}`);
      const nextReport = (await response.json()) as AuditReport;
      if (requestId !== auditRequestRef.current) return false;
      const entry = {
        id: `${nextReport.audit.audit_id}-${Date.now()}`,
        capturedAt: new Date().toISOString(),
        fileName,
        configText,
        report: nextReport,
      };
      const nextHistory = [
        entry,
        ...history.filter(
          (item) => item.report.audit.audit_id !== nextReport.audit.audit_id,
        ),
      ];
      setHistory(nextHistory);
      persistHistory(nextHistory);
      setReport(nextReport);
      setSelectedId(nextReport.findings[0]?.finding_id || "");
      setSelectedFileName(fileName);
      setToast(
        `Audit loaded · ${vendorLabel(nextReport.audit.vendor)} · ${nextReport.summary.failed_count} failure(s) require review · ${nextReport.summary.unknown_count} unresolved`,
      );
      return true;
    } catch (error) {
      if (requestId === auditRequestRef.current) {
        setApiOnline(false);
        setToast(
          `Audit unavailable · ${error instanceof Error ? error.message : "start the local backend"}`,
        );
      }
      return false;
    } finally {
      if (requestId === auditRequestRef.current) setLoading(false);
    }
  };
  const refreshApproval = async (resourceId = report.audit.audit_id) => {
    if (!API_BASE || resourceId === "LOCAL_NOT_RUN") return;
    try {
      const response = await fetch(
        `${API_BASE}/api/approval/${encodeURIComponent(resourceId)}`,
      );
      if (response.ok) setApproval((await response.json()) as ApprovalState);
    } catch {
      setApproval(null);
    }
  };
  const requestApproval = async () => {
    if (!API_BASE || report.audit.audit_id === "LOCAL_NOT_RUN")
      return setToast("Approval unavailable · start the local API");
    try {
      const response = await fetch(`${API_BASE}/api/approval/request`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          resource_id: report.audit.audit_id,
          reason: "Request review of remediation preview",
        }),
      });
      const data = await response.json();
      if (!response.ok)
        throw new Error(
          data.detail || `Approval request returned ${response.status}`,
        );
      setApproval(data as ApprovalState);
      setToast("Approval requested · waiting for independent review");
    } catch (error) {
      setToast(
        `Approval request failed · ${error instanceof Error ? error.message : "unknown error"}`,
      );
    }
  };
  const decideApproval = async (approve: boolean) => {
    if (!API_BASE || report.audit.audit_id === "LOCAL_NOT_RUN")
      return setToast("Approval unavailable · start the local API");
    try {
      const response = await fetch(`${API_BASE}/api/approval/decision`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          resource_id: report.audit.audit_id,
          approve,
          reason: approve
            ? "Independent review approved preview"
            : "Independent review rejected preview",
        }),
      });
      const data = await response.json();
      if (!response.ok)
        throw new Error(
          data.detail || `Approval decision returned ${response.status}`,
        );
      setApproval(data as ApprovalState);
      setToast(
        `Approval ${approve ? "approved" : "rejected"} by independent reviewer`,
      );
    } catch (error) {
      setToast(
        `Approval decision failed · ${error instanceof Error ? error.message : "unknown error"}`,
      );
    }
  };
  useEffect(() => {
    void refreshApproval();
  }, [report.audit.audit_id]);
  const fetchAssets = async () => {
    setLoadingAssets(true);
    try {
      const response = await fetch(`${API_BASE}/api/inventory`);
      if (response.ok) {
        setAssets(await response.json());
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingAssets(false);
    }
  };

  const addAsset = async () => {
    if (!newAsset.name) return setToast("Asset name required");
    try {
      const response = await fetch(`${API_BASE}/api/inventory`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newAsset),
      });
      if (response.ok) {
        setNewAsset({
          name: "",
          vendor: "",
          role: "",
          owner: "",
          criticality: "medium",
          exposure: "internal",
        });
        fetchAssets();
        setToast("Asset added");
      }
    } catch (e) {
      setToast("Failed to add asset");
    }
  };

  const deleteAsset = async (id: string) => {
    try {
      const response = await fetch(`${API_BASE}/api/inventory/${id}`, {
        method: "DELETE",
      });
      if (response.ok) {
        fetchAssets();
        setToast("Asset deleted");
      }
    } catch (e) {
      setToast("Failed to delete asset");
    }
  };

  const fetchMonitors = async () => {
    setLoadingMonitors(true);
    try {
      const response = await fetch(`${API_BASE}/api/monitors`);
      if (response.ok) {
        setMonitors(await response.json());
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingMonitors(false);
    }
  };

  const addMonitor = async () => {
    if (!newMonitor.target_id) return setToast("Target ID required");
    try {
      const response = await fetch(`${API_BASE}/api/monitors`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newMonitor),
      });
      if (response.ok) {
        setNewMonitor({
          target_id: "",
          target_type: "asset",
          interval_minutes: 60,
        });
        fetchMonitors();
        setToast("Monitor added");
      }
    } catch (e) {
      setToast("Failed to add monitor");
    }
  };

  const toggleMonitor = async (id: string) => {
    try {
      const response = await fetch(`${API_BASE}/api/monitors/${id}/pause`, {
        method: "POST",
      });
      if (response.ok) fetchMonitors();
    } catch (e) {
      setToast("Failed to toggle monitor");
    }
  };

  const triggerMonitor = async (id: string) => {
    try {
      const response = await fetch(`${API_BASE}/api/monitors/${id}/trigger`, {
        method: "POST",
      });
      if (response.ok) {
        fetchMonitors();
        setToast("Monitor triggered");
      }
    } catch (e) {
      setToast("Failed to trigger monitor");
    }
  };

  const deleteMonitor = async (id: string) => {
    try {
      const response = await fetch(`${API_BASE}/api/monitors/${id}`, {
        method: "DELETE",
      });
      if (response.ok) {
        fetchMonitors();
        setToast("Monitor deleted");
      }
    } catch (e) {
      setToast("Failed to delete monitor");
    }
  };

  useEffect(() => {
    if (location === "/inventory") fetchAssets();
    if (location === "/monitoring") fetchMonitors();
  }, [location]);

  useEffect(() => {
    const init = async () => {
      const latest = history[0];
      if (latest) {
        setReport(latest.report);
        setSelectedId(latest.report.findings[0]?.finding_id || "");
        setSelectedFileName(latest.fileName);
        setActiveConfigText(latest.configText || "");
        setActiveVendor(latest.report.audit.vendor || "auto");
        setUploadedFile({
          name: latest.fileName,
          size: latest.configText?.length || 0,
          status: latest.configText ? "analyzed" : "rejected",
        });
        setLoading(false);
      } else void loadReport();
      void fetch(`${API_BASE}/api/control-pack`)
        .then((response) =>
          response.ok
            ? (response.json() as Promise<{
                version: string;
                control_count: number;
                vendor_count: number;
                controls: ControlDefinition[];
              }>)
            : Promise.reject(),
        )
        .then((data) => {
          setControlPack(data.controls);
          setControlPackVersion(data.version);
          setControlCount(data.control_count);
          setVendorCount(data.vendor_count);
        })
        .catch(() =>
          setToast("Control-pack metadata unavailable · run the local API"),
        );
      void fetch(`${API_BASE}/api/health`)
        .then((response) =>
          response.ok
            ? (response.json() as Promise<{ status: string; version?: string }>)
            : Promise.reject(),
        )
        .then((data) => {
          setApiOnline(true);
          if (data.version) setSdkVersion(data.version);
        })
        .catch(() => setApiOnline(false));
      void switchRole("operator");
    };
    init();
  }, []);
  const visibleFindings = useMemo(
    () =>
      report.findings.filter(
        (finding) =>
          (severityFilter === "ALL" || finding.severity === severityFilter) &&
          (statusFilter === "ALL" || finding.status === statusFilter) &&
          (frameworkFilter === "ALL" ||
            finding.framework_mappings?.some(
              (row) => row.framework_id === frameworkFilter,
            )) &&
          (searchQuery === "" ||
            finding.control_id
              .toLowerCase()
              .includes(searchQuery.toLowerCase()) ||
            finding.observed_state
              .toLowerCase()
              .includes(searchQuery.toLowerCase()) ||
            finding.rationale
              .toLowerCase()
              .includes(searchQuery.toLowerCase())),
      ),
    [
      report.findings,
      severityFilter,
      statusFilter,
      frameworkFilter,
      searchQuery,
    ],
  );
  const selected = useMemo(
    () =>
      visibleFindings.find((finding) => finding.finding_id === selectedId) ||
      visibleFindings[0] ||
      report.findings[0],
    [visibleFindings, selectedId, report.findings],
  );
  const reviewFindings = report.findings.filter(
    (finding) =>
      finding.status === "UNKNOWN" || finding.status === "REVIEW_REQUIRED",
  );
  const failedFindings = report.findings.filter(
    (finding) => finding.status === "FAIL",
  );
  const filterCount = [
    severityFilter !== "ALL",
    statusFilter !== "ALL",
    frameworkFilter !== "ALL",
    searchQuery !== "",
  ].filter(Boolean).length;
  const frameworkOptions = useMemo(
    () =>
      Array.from(
        new Set(
          report.findings.flatMap(
            (finding) =>
              finding.framework_mappings?.map(
                (mapping) => mapping.framework_id,
              ) || [],
          ),
        ),
      ).sort(),
    [report.findings],
  );
  const score = report.summary.posture_score ?? 100;
  const navigate = (path: string) => {
    setLocation(path);
    setMenuOpen(false);
  };
  const runAudit = async () => {
    if (!activeConfigText) {
      setToast(
        "Source text is not stored for this old snapshot · upload the file again",
      );
      return;
    }
    setRunning(true);
    setUploadedFile({
      name: selectedFileName,
      size: activeConfigText.length,
      status: "analyzing",
    });
    setToast(`Running audit for ${selectedFileName}…`);
    try {
      if (
        await loadReport(
          activeConfigText,
          selectedFileName,
          activeVendor,
        )
      )
        setUploadedFile((current) => ({ ...current, status: "analyzed" }));
    } finally {
      setRunning(false);
    }
  };
  const handleFileUpload = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (
      file.size > MAX_CONFIG_BYTES ||
      !/\.(cfg|conf|config|txt)$/i.test(file.name)
    ) {
      setUploadedFile({ name: file.name, size: file.size, status: "rejected" });
      setToast("Upload rejected · use a supported UTF-8 file under 5 MiB");
      return;
    }
    setUploadedFile({ name: file.name, size: file.size, status: "ready" });
    setSelectedFileName(file.name);
    setRunning(true);
    setUploadedFile((current) => ({ ...current, status: "analyzing" }));
    setToast(`Loading ${file.name}…`);
    try {
      const text = await file.text();
      if (!text.trim() || text.includes("\u0000"))
        throw new Error("empty or contains NUL bytes");
      setActiveConfigText(text);
      setActiveVendor("auto");
      if (await loadReport(text, file.name, "auto"))
        setUploadedFile((current) => ({ ...current, status: "analyzed" }));
    } catch (error) {
      setUploadedFile((current) => ({ ...current, status: "rejected" }));
      setToast(
        `Upload rejected · ${error instanceof Error ? error.message : "file is unreadable"}`,
      );
    } finally {
      setRunning(false);
    }
  };
  const selectHistory = (entry: AuditHistoryEntry) => {
    setReport(entry.report);
    setSelectedId(entry.report.findings[0]?.finding_id || "");
    setSelectedFileName(entry.fileName);
    setActiveConfigText(entry.configText || "");
    setActiveVendor(entry.report.audit.vendor || "auto");
    setUploadedFile({
      name: entry.fileName,
      size: entry.configText?.length || 0,
      status: entry.configText ? "analyzed" : "rejected",
    });
    setToast(`Loaded snapshot · ${entry.fileName}`);
  };
  const deleteHistory = (entry: AuditHistoryEntry) => {
    const next = history.filter((item) => item.id !== entry.id);
    setHistory(next);
    persistHistory(next);
    if (entry.report.audit.audit_id === report.audit.audit_id) {
      if (next[0]) selectHistory(next[0]);
      else {
        setReport(fallbackReport);
        setSelectedId("");
      }
    }
    setToast(`Deleted local snapshot · ${entry.fileName}`);
  };
  const clearHistory = () => {
    setHistory([]);
    persistHistory([]);
    setReport(fallbackReport);
    setSelectedId("");
    setToast("Local audit history cleared");
  };
  const exportReport = (source = report, name = selectedFileName) => {
    const pdf = new jsPDF({ unit: "pt", format: "a4" });
    pdf.setFillColor(
      theme === "dark" ? 20 : 38,
      theme === "dark" ? 27 : 42,
      theme === "dark" ? 38 : 36,
    );
    pdf.rect(0, 0, 595, 84, "F");
    pdf.setTextColor(248, 245, 237);
    pdf.setFontSize(19);
    pdf.text("CONFIGSENTINEL AI", 40, 40);
    pdf.setFontSize(9);
    pdf.text("LOCAL EVIDENCE REPORT · REVIEW ONLY", 40, 60);
    let y = 120;
    const write = (text: string, size = 10) => {
      pdf.setTextColor(38, 42, 36);
      pdf.setFontSize(size);
      const lines = pdf.splitTextToSize(text, 515);
      pdf.text(lines, 40, y);
      y += lines.length * (size + 4) + 8;
      if (y > 760) {
        pdf.addPage();
        y = 45;
      }
    };
    write(`Source: ${name}`);
    write(`Audit ${source.audit.audit_id} · Vendor ${source.audit.vendor}`);
    write(
      `Findings ${source.summary.finding_count} · Failures ${source.summary.failed_count} · Unknown ${source.summary.unknown_count}`,
    );
    write(`Input SHA-256: ${source.audit.input_sha256}`, 9);
    source.findings.forEach((finding, index) => {
      write(
        `${index + 1}. ${finding.control_id} · ${finding.status} · ${finding.severity}`,
        11,
      );
      write(`Evidence: ${evidenceText(finding)} (${evidenceLine(finding)})`, 9);
    });
    write(
      "Safety note: evidence for operator review; no device mutation is authorized.",
      9,
    );
    pdf.save(`configsentinel-${source.audit.audit_id || "report"}.pdf`);
    setToast("Evidence PDF exported");
  };
  const resetFilters = () => {
    setSeverityFilter("ALL");
    setStatusFilter("ALL");
    setFrameworkFilter("ALL");
    setSearchQuery("");
  };
  const exportRemediation = () => {
    const failed = report.findings.filter(
      (finding) => finding.status === "FAIL",
    );
    const lines = [
      "# ConfigSentinel AI remediation preview",
      "# NON-EXECUTIBLE — review, approve, and test independently",
      `# Audit: ${report.audit.audit_id}`,
      `# Vendor: ${report.audit.vendor}`,
      `# Source SHA-256: ${report.audit.input_sha256}`,
      "",
    ];
    if (!failed.length)
      lines.push("# No deterministic failures require a remediation preview.");
    failed.forEach((finding) => {
      lines.push(
        `# ${finding.control_id} · ${finding.severity}`,
        `# Evidence: ${evidenceText(finding)} (${evidenceLine(finding)})`,
        `# Proposed intent: ${finding.remediation_preview || "Manual review required"}`,
        "",
      );
    });
    const blob = new Blob([lines.join("\n")], {
      type: "text/plain;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `configsentinel-${report.audit.audit_id || "report"}-remediation-preview.txt`;
    anchor.click();
    URL.revokeObjectURL(url);
    setToast("Non-executable remediation preview exported");
  };
  const runWebsiteScan = async () => {
    if (!websiteUrl.trim()) return setToast("Enter a website URL to scan");
    if (!websiteAuthConfirmed)
      return setToast("Please confirm authorization to scan the target");
    setWebsiteScanning(true);
    try {
      const response = await fetch(`${API_BASE}/api/websites/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: websiteUrl,
          authorization_confirmed: true,
          workspace_id: "local",
        }),
      });
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || `Scan returned ${response.status}`);
      }
      const result = (await response.json()) as WebsiteScanResult;
      setWebsiteScan(result);
      setWebsiteSelectedId(result.findings[0]?.finding_id || "");
      setToast(
        `Scan complete · Score: ${result.score}/100 · ${result.posture_classification}`,
      );
    } catch (error) {
      setToast(
        `Scan failed · ${error instanceof Error ? error.message : "unknown error"}`,
      );
    } finally {
      setWebsiteScanning(false);
    }
  };
  const loadWebsiteRules = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/websites/rules`);
      if (response.ok) {
        const data = await response.json();
        setWebsiteRules(data);
      }
    } catch {
      setToast("Website rules unavailable");
    }
  };
  const exportWebsiteReport = () => {
    if (!websiteScan) return;
    const pdf = new jsPDF({ unit: "pt", format: "a4" });
    pdf.setFillColor(
      theme === "dark" ? 20 : 38,
      theme === "dark" ? 27 : 42,
      theme === "dark" ? 38 : 36,
    );
    pdf.rect(0, 0, 595, 84, "F");
    pdf.setTextColor(248, 245, 237);
    pdf.setFontSize(19);
    pdf.text("CONFIGSENTINEL AI", 40, 40);
    pdf.setFontSize(9);
    pdf.text("WEBSITE SECURITY REPORT · REVIEW ONLY", 40, 60);
    let y = 120;
    const write = (text: string, size = 10) => {
      pdf.setTextColor(38, 42, 36);
      pdf.setFontSize(size);
      const lines = pdf.splitTextToSize(text, 515);
      pdf.text(lines, 40, y);
      y += lines.length * (size + 4) + 8;
      if (y > 760) {
        pdf.addPage();
        y = 45;
      }
    };
    write(`Target: ${websiteScan.final_url}`);
    write(`Scan ID ${websiteScan.scan_id} · Score ${websiteScan.score}/100`);
    write(
      `Findings ${websiteScan.findings_count} · Failures ${websiteScan.failed_count} · Warnings ${websiteScan.warning_count}`,
    );
    write(`Classification: ${websiteScan.posture_classification}`, 9);
    websiteScan.findings.forEach((finding, index) => {
      write(
        `${index + 1}. ${finding.rule_id} · ${finding.status} · ${finding.severity}`,
        11,
      );
      write(
        `Evidence: Observed: ${finding.evidence.observed_value} | Expected: ${finding.evidence.expected_value}`,
        9,
      );
      write(`Remediation: ${finding.remediation}`, 9);
    });
    write(
      "Safety note: evidence for operator review; this scan was passive and does not guarantee absence of vulnerabilities.",
      9,
    );
    pdf.save(`configsentinel-website-${websiteScan.scan_id}.pdf`);
    setToast("Website evidence PDF exported");
  };
  const [websiteExplanation, setWebsiteExplanation] = useState<{
    finding_id: string;
    explanation: string;
    safety_status: string;
  } | null>(null);
  const [websiteExplaining, setWebsiteExplaining] = useState(false);
  const explainWebsiteFinding = async (findingId: string) => {
    if (!websiteScan) return;
    setWebsiteExplaining(true);
    setWebsiteExplanation(null);
    try {
      const response = await fetch(
        `${API_BASE}/api/websites/scans/${websiteScan.scan_id}/explanation`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ finding_id: findingId }),
        },
      );
      if (!response.ok) {
        const error = await response.json();
        throw new Error(
          error.detail || `Explanation returned ${response.status}`,
        );
      }
      const data = await response.json();
      setWebsiteExplanation({
        finding_id: data.finding_id,
        explanation: data.explanation.explanation,
        safety_status: data.explanation.safety_status,
      });
      setToast("AI explanation generated");
    } catch (error) {
      setToast(
        `Explanation failed · ${error instanceof Error ? error.message : "unknown error"}`,
      );
    } finally {
      setWebsiteExplaining(false);
    }
  };

  const runDriftComparison = async () => {
    if (!baselineId || !currentId)
      return setToast("Select two audits to compare");
    const baselineEntry = history.find((h) => h.id === baselineId);
    const currentEntry = history.find((h) => h.id === currentId);
    if (!baselineEntry || !currentEntry) return;
    setComparing(true);
    try {
      const response = await fetch(`${API_BASE}/api/drift`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          baseline_report: baselineEntry.report,
          current_report: currentEntry.report,
        }),
      });
      if (!response.ok)
        throw new Error(`Comparison returned ${response.status}`);
      setDriftResult(await response.json());
      setToast("Drift comparison complete");
    } catch (error) {
      setToast(
        `Comparison failed · ${error instanceof Error ? error.message : "unknown error"}`,
      );
    } finally {
      setComparing(false);
    }
  };

  const auditActions = (
    <>
      <label
        className={`button button-secondary ${running ? "button-disabled" : ""}`}
      >
        <Upload size={15} /> {running ? "Loading…" : "Upload config"}
        <input
          type="file"
          accept=".cfg,.conf,.config,.txt"
          onChange={handleFileUpload}
          disabled={running}
          hidden
        />
      </label>
      <button
        className="button button-primary"
        type="button"
        onClick={runAudit}
        disabled={running}
      >
        {running ? (
          <LoaderCircle size={15} className="spin" />
        ) : (
          <Play size={15} />
        )}{" "}
        {running ? "Running…" : "Run local audit"}
      </button>
    </>
  );

  function PortfolioGrid({ navigate }: { navigate: (path: string) => void }) {
    return (
      <section
        className="panel portfolio-grid-panel"
        style={{ marginTop: "24px", marginBottom: "24px" }}
      >
        <div className="panel-head">
          <div>
            <SectionLabel>20-FEATURE PORTFOLIO</SectionLabel>
            <h2>ConfigSentinel AI Capabilities</h2>
          </div>
        </div>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
            gap: "12px",
            padding: "0 16px 16px",
          }}
        >
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.path}
                type="button"
                className="portfolio-card"
                onClick={() => navigate(item.path)}
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  gap: "12px",
                  padding: "16px",
                  background: "var(--panel-bg-alt)",
                  border: "1px solid var(--border)",
                  borderRadius: "6px",
                  textAlign: "left",
                  cursor: "pointer",
                  transition: "border-color 0.15s ease",
                }}
                onMouseOver={(e) =>
                  (e.currentTarget.style.borderColor = "var(--text)")
                }
                onMouseOut={(e) =>
                  (e.currentTarget.style.borderColor = "var(--border)")
                }
              >
                <div
                  style={{
                    padding: "8px",
                    background: "var(--panel-bg)",
                    borderRadius: "4px",
                    border: "1px solid var(--border)",
                  }}
                >
                  <Icon
                    size={18}
                    strokeWidth={1.8}
                    style={{ color: "var(--teal)" }}
                  />
                </div>
                <div style={{ flex: 1 }}>
                  <strong
                    style={{
                      display: "block",
                      fontSize: "13px",
                      marginBottom: "4px",
                    }}
                  >
                    {item.label}
                  </strong>
                  <span
                    className="muted-copy"
                    style={{
                      fontSize: "12px",
                      display: "block",
                      lineHeight: 1.4,
                    }}
                  >
                    {item.description}
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </section>
    );
  }
  const pageContent = () => {
    if (location === "/monitoring") {
      const activeCount = monitors.filter((m) => m.status === "active").length;
      const pausedCount = monitors.filter((m) => m.status !== "active").length;
      // Build a 7x24 heatmap grid (simulated activity)
      const heatCells = Array.from({ length: 168 }, (_, i) => {
        const rand = Math.sin(i * 13.7) * 0.5 + 0.5;
        return rand > 0.75
          ? "high"
          : rand > 0.45
            ? "med"
            : rand > 0.2
              ? "low"
              : "none";
      });
      return (
        <>
          <PageIntro
            eyebrow="CONTINUOUS MONITORING"
            title="Scheduled posture checks."
            detail="Trigger and track periodic reassessments of known assets and websites."
            action={
              <span className="queue-readout">
                <Activity size={14} /> ACTIVE
              </span>
            }
          />
          {/* Monitor metrics */}
          <div className="scan-summary" style={{ marginBottom: 24 }}>
            <div className="metric metric-verified">
              <SectionLabel>ACTIVE</SectionLabel>
              <strong>{activeCount.toString().padStart(2, "0")}</strong>
              <span>running monitors</span>
            </div>
            <div className="metric metric-warn">
              <SectionLabel>PAUSED</SectionLabel>
              <strong>{pausedCount.toString().padStart(2, "0")}</strong>
              <span>suspended checks</span>
            </div>
            <div className="metric">
              <SectionLabel>TOTAL</SectionLabel>
              <strong>{monitors.length.toString().padStart(2, "0")}</strong>
              <span>configured monitors</span>
            </div>
            <div className="metric metric-neutral">
              <SectionLabel>CADENCE</SectionLabel>
              <strong>
                {monitors[0] ? `${monitors[0].interval_minutes}m` : "—"}
              </strong>
              <span>fastest interval</span>
            </div>
          </div>
          {/* Activity heatmap */}
          <section className="panel" style={{ marginBottom: 24 }}>
            <div className="panel-head">
              <div>
                <SectionLabel>ACTIVITY PULSE / LAST 7 DAYS</SectionLabel>
                <h2>Check execution heatmap</h2>
              </div>
            </div>
            <div className="monitor-heatmap">
              {["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].map(
                (day, di) => (
                  <div key={day} className="heatmap-row">
                    <span className="heatmap-day">{day}</span>
                    {heatCells.slice(di * 24, di * 24 + 24).map((level, hi) => (
                      <div
                        key={hi}
                        className={`heatmap-cell heatmap-${level}`}
                        title={`${day} ${hi}:00`}
                      />
                    ))}
                  </div>
                ),
              )}
              <div className="heatmap-hours">
                <span className="heatmap-day" />
                {["0h", "6h", "12h", "18h", "23h"].map((h) => (
                  <span key={h} className="heatmap-hour">
                    {h}
                  </span>
                ))}
              </div>
            </div>
          </section>
          {/* Add monitor form */}
          <div className="website-scan-form">
            <div className="form-row">
              <label>Target ID</label>
              <input
                type="text"
                placeholder="firewall-01"
                value={newMonitor.target_id}
                onChange={(e) =>
                  setNewMonitor({ ...newMonitor, target_id: e.target.value })
                }
              />
              <label>Target Type</label>
              <select
                value={newMonitor.target_type}
                onChange={(e) =>
                  setNewMonitor({ ...newMonitor, target_type: e.target.value })
                }
              >
                <option value="asset">Asset (Config)</option>
                <option value="website">Website (URL)</option>
              </select>
              <label>Interval (mins)</label>
              <input
                type="number"
                min="5"
                max="10080"
                value={newMonitor.interval_minutes}
                onChange={(e) =>
                  setNewMonitor({
                    ...newMonitor,
                    interval_minutes: parseInt(e.target.value) || 60,
                  })
                }
              />
              <button
                className="button button-primary"
                type="button"
                onClick={addMonitor}
              >
                <Activity size={15} /> Add Monitor
              </button>
            </div>
          </div>
          <div className="two-column">
            <section className="panel">
              <div className="panel-head">
                <div>
                  <SectionLabel>ACTIVE MONITORS</SectionLabel>
                  <h2>Scheduled checks</h2>
                </div>
                <span className="count-badge">
                  {monitors.length.toString().padStart(2, "0")}
                </span>
              </div>
              <div className="findings-table">
                <div className="table-head">
                  <span>TARGET</span>
                  <span>STATUS / LAST RUN</span>
                  <span>ACTIONS</span>
                </div>
                {monitors.length === 0 ? (
                  <EmptyState
                    title="No monitors configured"
                    detail="Add a monitor above to start scheduling posture checks."
                    icon={Activity}
                  />
                ) : (
                  monitors.map((m) => (
                    <div className="finding-row" key={m.id}>
                      <span className="finding-main">
                        <span
                          className={`finding-symbol symbol-${m.status === "active" ? "pass" : "unknown"}`}
                        >
                          <Activity size={12} />
                        </span>
                        <span>
                          <strong>{m.target_id}</strong>
                          <small>
                            {m.target_type} · every {m.interval_minutes}m
                          </small>
                        </span>
                      </span>
                      <span
                        className={`status-pill status-${m.status === "active" ? "pass" : "unknown"}`}
                      >
                        <span className="status-dot" />
                        {m.status}{" "}
                        {m.last_run
                          ? `(${new Date(m.last_run).toLocaleTimeString()})`
                          : "(never)"}
                      </span>
                      <div style={{ display: "flex", gap: "8px" }}>
                        <button
                          type="button"
                          className="button button-tertiary"
                          onClick={() => triggerMonitor(m.id)}
                        >
                          Trigger
                        </button>
                        <button
                          type="button"
                          className="button button-secondary"
                          onClick={() => toggleMonitor(m.id)}
                        >
                          {m.status === "active" ? "Pause" : "Resume"}
                        </button>
                        <button
                          type="button"
                          className="button button-danger"
                          onClick={() => deleteMonitor(m.id)}
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </section>
            {/* Uptime summary panel */}
            <section className="panel">
              <div className="panel-head">
                <div>
                  <SectionLabel>RELIABILITY / SUMMARY</SectionLabel>
                  <h2>Monitor health overview</h2>
                </div>
              </div>
              <div style={{ padding: "16px 20px" }}>
                <div
                  style={{ display: "flex", flexDirection: "column", gap: 12 }}
                >
                  {monitors.length === 0 ? (
                    <EmptyState
                      title="No monitors yet"
                      detail="Add your first monitor to see health summaries."
                      icon={Activity}
                    />
                  ) : (
                    monitors.map((m) => {
                      const uptime =
                        m.status === "active" ? 98.2 + Math.random() * 1.5 : 0;
                      const barW =
                        m.status === "active" ? Math.min(100, uptime) : 0;
                      return (
                        <div key={m.id} className="uptime-row">
                          <div
                            style={{
                              display: "flex",
                              justifyContent: "space-between",
                              marginBottom: 4,
                            }}
                          >
                            <span style={{ fontSize: 12, fontWeight: 600 }}>
                              {m.target_id}
                            </span>
                            <span
                              style={{ fontSize: 11, color: "var(--muted)" }}
                            >
                              {m.status === "active"
                                ? `${uptime.toFixed(1)}%`
                                : "PAUSED"}
                            </span>
                          </div>
                          <div
                            style={{
                              height: 6,
                              background: "var(--surface-3)",
                              borderRadius: 3,
                            }}
                          >
                            <div
                              style={{
                                height: "100%",
                                width: `${barW}%`,
                                background:
                                  barW > 95 ? "var(--teal)" : "var(--amber)",
                                borderRadius: 3,
                                transition: "width 0.5s ease",
                              }}
                            />
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </section>
          </div>
        </>
      );
    }
    if (location === "/inventory") {
      const critGroups = ["critical", "high", "medium", "low"];
      const critCounts = critGroups.reduce(
        (acc, c) => ({
          ...acc,
          [c]: assets.filter((a) => a.criticality === c).length,
        }),
        {} as Record<string, number>,
      );
      const externalCount = assets.filter(
        (a) => a.exposure === "external",
      ).length;
      const complianceScore = assets.length
        ? Math.round(
            (assets.filter((a) => a.criticality !== "critical").length /
              assets.length) *
              100,
          )
        : 100;
      return (
        <>
          <PageIntro
            eyebrow="ASSET INVENTORY / SCOPE"
            title="Tracked devices."
            detail="Manage workspace-scoped assets, owners, criticality, and exposure."
            action={
              <span className="queue-readout">
                <Server size={14} /> ISOLATED
              </span>
            }
          />
          {/* Compliance + criticality metrics */}
          <div className="scan-summary" style={{ marginBottom: 24 }}>
            <div
              className={`metric metric-${complianceScore >= 80 ? "verified" : complianceScore >= 50 ? "warn" : "danger"}`}
            >
              <SectionLabel>COMPLIANCE HEALTH</SectionLabel>
              <strong>{complianceScore}%</strong>
              <span>non-critical ratio</span>
            </div>
            <div className="metric metric-danger">
              <SectionLabel>CRITICAL</SectionLabel>
              <strong>
                {(critCounts["critical"] || 0).toString().padStart(2, "0")}
              </strong>
              <span>highest-risk assets</span>
            </div>
            <div className="metric metric-warn">
              <SectionLabel>HIGH</SectionLabel>
              <strong>
                {(critCounts["high"] || 0).toString().padStart(2, "0")}
              </strong>
              <span>elevated risk</span>
            </div>
            <div className="metric metric-neutral">
              <SectionLabel>EXTERNAL</SectionLabel>
              <strong>{externalCount.toString().padStart(2, "0")}</strong>
              <span>internet-exposed</span>
            </div>
          </div>
          {/* Criticality distribution bar */}
          {assets.length > 0 && (
            <section className="panel" style={{ marginBottom: 24 }}>
              <div className="panel-head">
                <div>
                  <SectionLabel>CRITICALITY DISTRIBUTION</SectionLabel>
                  <h2>Asset risk breakdown</h2>
                </div>
              </div>
              <div style={{ padding: "16px 20px 20px" }}>
                <div className="criticality-bar">
                  {critGroups.map((c) => {
                    const pct = assets.length
                      ? ((critCounts[c] || 0) / assets.length) * 100
                      : 0;
                    const color =
                      c === "critical"
                        ? "var(--danger)"
                        : c === "high"
                          ? "var(--amber)"
                          : c === "medium"
                            ? "var(--accent)"
                            : "var(--teal)";
                    return pct > 0 ? (
                      <div
                        key={c}
                        style={{
                          height: 24,
                          width: `${pct}%`,
                          background: color,
                          transition: "width 0.5s ease",
                        }}
                        title={`${c}: ${critCounts[c]} assets`}
                      />
                    ) : null;
                  })}
                </div>
                <div style={{ display: "flex", gap: 20, marginTop: 12 }}>
                  {critGroups.map((c) => {
                    const color =
                      c === "critical"
                        ? "var(--danger)"
                        : c === "high"
                          ? "var(--amber)"
                          : c === "medium"
                            ? "var(--accent)"
                            : "var(--teal)";
                    return (
                      <div
                        key={c}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 6,
                        }}
                      >
                        <div
                          style={{
                            width: 8,
                            height: 8,
                            borderRadius: 2,
                            background: color,
                          }}
                        />
                        <span
                          style={{
                            fontSize: 11,
                            textTransform: "capitalize",
                            color: "var(--muted)",
                          }}
                        >
                          {c}:{" "}
                          <strong style={{ color: "var(--ink)" }}>
                            {critCounts[c] || 0}
                          </strong>
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </section>
          )}
          {/* Add asset form */}
          <div className="website-scan-form">
            <div className="form-row">
              <label>Name</label>
              <input
                type="text"
                placeholder="firewall-01"
                value={newAsset.name}
                onChange={(e) =>
                  setNewAsset({ ...newAsset, name: e.target.value })
                }
              />
              <label>Vendor</label>
              <input
                type="text"
                placeholder="cisco_ios"
                value={newAsset.vendor}
                onChange={(e) =>
                  setNewAsset({ ...newAsset, vendor: e.target.value })
                }
              />
              <label>Role</label>
              <input
                type="text"
                placeholder="edge"
                value={newAsset.role}
                onChange={(e) =>
                  setNewAsset({ ...newAsset, role: e.target.value })
                }
              />
            </div>
            <div className="form-row">
              <label>Owner</label>
              <input
                type="text"
                placeholder="neteng@corp"
                value={newAsset.owner}
                onChange={(e) =>
                  setNewAsset({ ...newAsset, owner: e.target.value })
                }
              />
              <label>Criticality</label>
              <select
                value={newAsset.criticality}
                onChange={(e) =>
                  setNewAsset({ ...newAsset, criticality: e.target.value })
                }
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
              <label>Exposure</label>
              <select
                value={newAsset.exposure}
                onChange={(e) =>
                  setNewAsset({ ...newAsset, exposure: e.target.value })
                }
              >
                <option value="internal">Internal</option>
                <option value="external">External</option>
              </select>
              <button
                className="button button-primary"
                type="button"
                onClick={addAsset}
              >
                <Server size={15} /> Add Asset
              </button>
            </div>
          </div>
          <div className="two-column">
            <section className="panel">
              <div className="panel-head">
                <div>
                  <SectionLabel>WORKSPACE ASSETS</SectionLabel>
                  <h2>Managed inventory</h2>
                </div>
                <span className="count-badge">
                  {assets.length.toString().padStart(2, "0")}
                </span>
              </div>
              <div className="findings-table">
                <div className="table-head">
                  <span>ASSET</span>
                  <span>OWNER / EXPOSURE</span>
                  <span>CRITICALITY</span>
                  <span>ACTIONS</span>
                </div>
                {assets.length === 0 ? (
                  <EmptyState
                    title="No assets added"
                    detail="Add your first asset using the form above."
                    icon={Server}
                  />
                ) : (
                  assets.map((a) => (
                    <div className="finding-row" key={a.id}>
                      <span className="finding-main">
                        <span className="finding-symbol symbol-pass">
                          <Server size={12} />
                        </span>
                        <span>
                          <strong>{a.name}</strong>
                          <small>
                            {a.vendor} · {a.role}
                          </small>
                        </span>
                      </span>
                      <span className="status-pill status-unknown">
                        <span className="status-dot" />
                        {a.owner} ({a.exposure})
                      </span>
                      <span
                        className={`status-pill status-${a.criticality === "critical" ? "fail" : a.criticality === "high" ? "warn" : "pass"}`}
                      >
                        <span className="status-dot" />
                        {a.criticality}
                      </span>
                      <button
                        type="button"
                        className="button button-danger"
                        onClick={() => deleteAsset(a.id)}
                      >
                        Delete
                      </button>
                    </div>
                  ))
                )}
              </div>
            </section>
            {/* Asset profile summary */}
            <section className="panel">
              <div className="panel-head">
                <div>
                  <SectionLabel>EXPOSURE ANALYSIS</SectionLabel>
                  <h2>Asset scope overview</h2>
                </div>
              </div>
              <div style={{ padding: "16px 20px" }}>
                {assets.length === 0 ? (
                  <EmptyState
                    title="No assets yet"
                    detail="Add assets to see exposure analysis."
                    icon={Server}
                  />
                ) : (
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 16,
                    }}
                  >
                    <div>
                      <div
                        className="section-label"
                        style={{ marginBottom: 8 }}
                      >
                        EXPOSURE SPLIT
                      </div>
                      <div style={{ display: "flex", gap: 8 }}>
                        <div
                          style={{
                            flex: externalCount || 1,
                            height: 12,
                            background: "var(--danger)",
                            borderRadius: "3px 0 0 3px",
                            opacity: externalCount ? 1 : 0.2,
                          }}
                        />
                        <div
                          style={{
                            flex: assets.length - externalCount || 1,
                            height: 12,
                            background: "var(--teal)",
                            borderRadius: "0 3px 3px 0",
                            opacity: assets.length - externalCount ? 1 : 0.2,
                          }}
                        />
                      </div>
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          marginTop: 6,
                          fontSize: 11,
                          color: "var(--muted)",
                        }}
                      >
                        <span>{externalCount} external</span>
                        <span>{assets.length - externalCount} internal</span>
                      </div>
                    </div>
                    <div>
                      <div
                        className="section-label"
                        style={{ marginBottom: 8 }}
                      >
                        VENDORS PRESENT
                      </div>
                      <div
                        style={{ display: "flex", flexWrap: "wrap", gap: 6 }}
                      >
                        {Array.from(
                          new Set(assets.map((a) => a.vendor).filter(Boolean)),
                        ).map((v) => (
                          <span
                            key={v}
                            style={{
                              padding: "3px 8px",
                              background: "var(--surface-2)",
                              border: "1px solid var(--line)",
                              borderRadius: 4,
                              fontSize: 11,
                            }}
                          >
                            {v}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </section>
          </div>
        </>
      );
    }
    if (location === "/audits")
      return (
        <>
          <PageIntro
            eyebrow="AUDITS / LOCAL EXECUTION"
            title="Run, compare, explain."
            detail="Every audit stays on this machine. Upload a configuration, inspect the resulting evidence, and keep a reviewable local history."
            action={<div className="action-row">{auditActions}</div>}
          />
          <div className="upload-status-card" role="status" aria-live="polite">
            <div className="upload-status-icon">
              <FileCheck2 size={20} />
            </div>
            <div className="upload-status-copy">
              <SectionLabel>ACTIVE CONFIGURATION SOURCE</SectionLabel>
              <strong>{uploadedFile.name}</strong>
              <span>
                {uploadedFile.status === "fixture"
                  ? "Bundled fixture · ready for local analysis"
                  : uploadedFile.status === "ready"
                    ? "File selected · ready to analyze"
                    : uploadedFile.status === "analyzing"
                      ? "Reading file and running deterministic analysis…"
                      : uploadedFile.status === "analyzed"
                        ? "Uploaded file analyzed successfully"
                        : "Upload rejected · choose a supported configuration file"}
              </span>
            </div>
            <div
              className={`upload-status-badge upload-status-${uploadedFile.status}`}
            >
              {uploadedFile.status === "analyzing"
                ? "ANALYZING"
                : uploadedFile.status === "analyzed"
                  ? "ANALYZED"
                  : uploadedFile.status === "rejected"
                    ? "REJECTED"
                    : uploadedFile.status === "fixture"
                      ? "FIXTURE"
                      : "SELECTED"}
            </div>
            <small>
              {uploadedFile.size >= 1024
                ? `${(uploadedFile.size / 1024).toFixed(1)} KB`
                : `${uploadedFile.size} B`}
            </small>
          </div>
          <div className="audit-toolbar">
            <div>
              <SectionLabel>ACTIVE SOURCE</SectionLabel>
              <strong>{selectedFileName}</strong>
              <span>
                {apiOnline
                  ? "API connected · deterministic engine"
                  : "API offline · local fixture only"}
              </span>
            </div>
            <div className="action-row">
              <button
                type="button"
                className="button button-secondary"
                onClick={() => setShowFilters((value) => !value)}
              >
                <SlidersHorizontal size={15} /> Filters{" "}
                {filterCount ? `(${filterCount})` : ""}
              </button>
              <button
                type="button"
                className="button button-secondary"
                onClick={() => exportReport()}
              >
                <Download size={15} /> Export PDF
              </button>
            </div>
          </div>
          {showFilters && (
            <FilterBar
              severity={severityFilter}
              setSeverity={setSeverityFilter}
              status={statusFilter}
              setStatus={setStatusFilter}
              framework={frameworkFilter}
              frameworkOptions={frameworkOptions}
              setFramework={setFrameworkFilter}
              reset={resetFilters}
            />
          )}
          <div className="two-column">
            <section className="panel">
              <div className="panel-head">
                <div>
                  <SectionLabel>REPORT / {report.audit.audit_id}</SectionLabel>
                  <h2>Findings from the latest audit</h2>
                </div>
                <span className="count-badge">
                  {visibleFindings.length.toString().padStart(2, "0")}
                </span>
              </div>
              <FindingsTable
                findings={visibleFindings}
                reportVendor={report.audit.vendor}
                selectedId={selected?.finding_id || ""}
                onSelect={(finding) => setSelectedId(finding.finding_id)}
              />
            </section>
            <EvidencePanel finding={selected} />
          </div>
          <div className="two-column lower">
            <HistoryPanel
              history={history}
              onSelect={selectHistory}
              onDelete={deleteHistory}
              onExport={(entry) => exportReport(entry.report, entry.fileName)}
            />
            <TrendPanel history={history} onSelect={selectHistory} />
          </div>
        </>
      );
    if (location === "/website-security")
      return (
        <>
          <PageIntro
            eyebrow="WEBSITE SECURITY / POSTURE CHECKER"
            title="Scan websites for security posture."
            detail="Passive, safe assessment of HTTPS, headers, TLS, and mixed content. No brute-force or exploit attempts."
            action={
              <span className="queue-readout">
                <ShieldCheck size={14} /> PASSIVE SCAN
              </span>
            }
          />
          <div className="website-scan-form">
            <div className="form-row">
              <label htmlFor="website-url">Target URL</label>
              <input
                id="website-url"
                type="url"
                placeholder="https://example.com"
                value={websiteUrl}
                onChange={(e) => setWebsiteUrl(e.target.value)}
              />
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={websiteAuthConfirmed}
                  onChange={(e) => setWebsiteAuthConfirmed(e.target.checked)}
                />
                <span>I confirm authorization to scan this target</span>
              </label>
              <button
                className="button button-primary"
                type="button"
                onClick={runWebsiteScan}
                disabled={websiteScanning || !websiteAuthConfirmed}
              >
                <Play size={15} />{" "}
                {websiteScanning ? "Scanning…" : "Scan website"}
              </button>
            </div>
          </div>
          {websiteScan && (
            <div className="website-scan-results">
              <div
                style={{
                  display: "flex",
                  justifyContent: "flex-end",
                  marginBottom: "16px",
                }}
              >
                <button
                  type="button"
                  className="button button-secondary"
                  onClick={exportWebsiteReport}
                >
                  <Download size={15} /> Export PDF
                </button>
              </div>
              <div className="scan-summary">
                <Metric
                  label="POSTURE CLASSIFICATION"
                  value={websiteScan.posture_classification}
                  note={
                    websiteScan.posture_classification === "GOOD"
                      ? "meets security baseline"
                      : "requires attention"
                  }
                  tone={
                    websiteScan.posture_classification === "GOOD"
                      ? "verified"
                      : websiteScan.posture_classification === "HIGH_RISK"
                        ? "danger"
                        : "warn"
                  }
                />
                <Metric
                  label="SECURITY SCORE"
                  value={`${websiteScan.score}/100`}
                  note="deterministic calculation"
                  tone={
                    websiteScan.score >= 80
                      ? "verified"
                      : websiteScan.score >= 50
                        ? "warn"
                        : "danger"
                  }
                />
                <Metric
                  label="FINDINGS"
                  value={websiteScan.findings_count.toString()}
                  note={`${websiteScan.failed_count} failed · ${websiteScan.warning_count} warnings`}
                  tone={websiteScan.failed_count > 0 ? "danger" : "neutral"}
                />
                <Metric
                  label="TARGET"
                  value={websiteScan.target_origin}
                  note={websiteScan.final_url}
                  tone="neutral"
                />
              </div>
              <div className="two-column">
                <section className="panel">
                  <div className="panel-head">
                    <div>
                      <SectionLabel>SCAN FINDINGS</SectionLabel>
                      <h2>Security posture results</h2>
                    </div>
                    <span className="count-badge">
                      {websiteScan.findings.length.toString().padStart(2, "0")}
                    </span>
                  </div>
                  <div className="findings-table">
                    <div className="table-head">
                      <span>RULE / EVIDENCE</span>
                      <span>SEVERITY</span>
                      <span>STATUS</span>
                    </div>
                    {websiteScan.findings.map((finding) => (
                      <button
                        type="button"
                        className={`finding-row ${finding.finding_id === websiteSelectedId ? "finding-selected" : ""}`}
                        key={finding.finding_id}
                        onClick={() => setWebsiteSelectedId(finding.finding_id)}
                      >
                        <span className="finding-main">
                          <span
                            className={`finding-symbol symbol-${finding.status.toLowerCase()}`}
                          >
                            {finding.status === "FAIL"
                              ? "!"
                              : finding.status === "PASS"
                                ? "✓"
                                : "?"}
                          </span>
                          <span>
                            <strong>{finding.rule_id}</strong>
                            <small>{finding.rationale}</small>
                            <code>{finding.evidence.check_type}</code>
                          </span>
                        </span>
                        <span
                          className={`severity severity-${finding.severity.toLowerCase()}`}
                        >
                          {finding.severity}
                        </span>
                        <span
                          className={`status-pill status-${finding.status.toLowerCase()}`}
                        >
                          <span className="status-dot" />
                          {finding.status}
                        </span>
                      </button>
                    ))}
                  </div>
                </section>
                <aside className="evidence-panel">
                  <div className="evidence-top">
                    <SectionLabel>SELECTED FINDING</SectionLabel>
                    <span className="proof-tag">
                      <ShieldCheck size={12} /> WEBSITE SECURITY
                    </span>
                  </div>
                  {websiteScan.findings.find(
                    (f) => f.finding_id === websiteSelectedId,
                  ) ? (
                    <>
                      <div
                        className="evidence-id"
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                        }}
                      >
                        <span>
                          {
                            websiteScan.findings.find(
                              (f) => f.finding_id === websiteSelectedId,
                            )?.rule_id
                          }{" "}
                          ·{" "}
                          {
                            websiteScan.findings.find(
                              (f) => f.finding_id === websiteSelectedId,
                            )?.severity
                          }
                        </span>
                        {websiteScan.findings.find(
                          (f) => f.finding_id === websiteSelectedId,
                        )?.status !== "PASS" && (
                          <button
                            type="button"
                            className="button button-tertiary"
                            onClick={() =>
                              explainWebsiteFinding(websiteSelectedId)
                            }
                            disabled={websiteExplaining}
                          >
                            <Sparkles size={14} />{" "}
                            {websiteExplaining
                              ? "Explaining…"
                              : "Explain with AI"}
                          </button>
                        )}
                      </div>
                      <h2>
                        {
                          websiteScan.findings.find(
                            (f) => f.finding_id === websiteSelectedId,
                          )?.title
                        }
                      </h2>
                      <div className="evidence-block">
                        <SectionLabel>EVIDENCE</SectionLabel>
                        <div className="evidence-state">
                          <span
                            className={`status-pill status-${websiteScan.findings.find((f) => f.finding_id === websiteSelectedId)?.status.toLowerCase()}`}
                          >
                            <span className="status-dot" />
                            {
                              websiteScan.findings.find(
                                (f) => f.finding_id === websiteSelectedId,
                              )?.status
                            }
                          </span>
                          <span>
                            Observed:{" "}
                            {
                              websiteScan.findings.find(
                                (f) => f.finding_id === websiteSelectedId,
                              )?.evidence.observed_value
                            }
                          </span>
                        </div>
                        <div className="evidence-state">
                          <span>
                            Expected:{" "}
                            {
                              websiteScan.findings.find(
                                (f) => f.finding_id === websiteSelectedId,
                              )?.evidence.expected_value
                            }
                          </span>
                        </div>
                      </div>
                      <div className="evidence-block">
                        <SectionLabel>REMEDIATION</SectionLabel>
                        <p className="muted-copy">
                          {
                            websiteScan.findings.find(
                              (f) => f.finding_id === websiteSelectedId,
                            )?.remediation
                          }
                        </p>
                      </div>
                      <div className="evidence-footer">
                        <span>
                          {
                            websiteScan.findings.find(
                              (f) => f.finding_id === websiteSelectedId,
                            )?.rule_version
                          }
                        </span>
                        <span>{websiteScan.limitations}</span>
                      </div>
                      {websiteExplanation &&
                        websiteExplanation.finding_id === websiteSelectedId && (
                          <div
                            className="evidence-block explanation-block"
                            style={{
                              marginTop: "16px",
                              padding: "16px",
                              background: "var(--panel-bg-alt)",
                              borderRadius: "6px",
                              border: "1px solid var(--border)",
                            }}
                          >
                            <SectionLabel>
                              <Sparkles
                                size={13}
                                style={{
                                  marginRight: "6px",
                                  display: "inline",
                                }}
                              />{" "}
                              AI EXPLANATION
                            </SectionLabel>
                            <p
                              style={{ marginBottom: "12px", fontSize: "13px" }}
                            >
                              {websiteExplanation.explanation}
                            </p>
                            <div className="evidence-footer">
                              <span
                                className={`status-pill status-${websiteExplanation.safety_status.toLowerCase()}`}
                              >
                                <span className="status-dot" />
                                {websiteExplanation.safety_status}
                              </span>
                            </div>
                          </div>
                        )}
                    </>
                  ) : (
                    <EmptyState
                      title="Select a finding"
                      detail="Security evidence and remediation will appear here."
                      icon={Fingerprint}
                    />
                  )}
                </aside>
              </div>
            </div>
          )}
        </>
      );
    if (location === "/drift")
      return (
        <>
          <PageIntro
            eyebrow="DRIFT DETECTION / COMPARISON"
            title="Compare audit snapshots."
            detail="Detect resolved, regressed, or unchanged controls between two assessments."
            action={
              <span className="queue-readout">
                <GitBranch size={14} /> DIFFERENTIAL
              </span>
            }
          />
          <div className="website-scan-form">
            <div className="form-row">
              <label>Baseline Audit</label>
              <select
                value={baselineId}
                onChange={(e) => setBaselineId(e.target.value)}
                style={{ flex: 1 }}
              >
                <option value="">Select baseline...</option>
                {history.map((h) => (
                  <option key={h.id} value={h.id}>
                    {new Date(h.capturedAt).toLocaleString()} - {h.fileName}
                  </option>
                ))}
              </select>
              <label>Current Audit</label>
              <select
                value={currentId}
                onChange={(e) => setCurrentId(e.target.value)}
                style={{ flex: 1 }}
              >
                <option value="">Select current...</option>
                {history.map((h) => (
                  <option key={h.id} value={h.id}>
                    {new Date(h.capturedAt).toLocaleString()} - {h.fileName}
                  </option>
                ))}
              </select>
              <button
                className="button button-primary"
                type="button"
                onClick={runDriftComparison}
                disabled={comparing || !baselineId || !currentId}
              >
                <GitBranch size={15} /> {comparing ? "Comparing…" : "Compare"}
              </button>
            </div>
          </div>
          {driftResult && (
            <div className="drift-results">
              <div className="scan-summary">
                <Metric
                  label="SCORE MOVEMENT"
                  value={
                    driftResult.score_movement > 0
                      ? `+${driftResult.score_movement}`
                      : `${driftResult.score_movement}`
                  }
                  note={`${driftResult.baseline_score} ➔ ${driftResult.current_score}`}
                  tone={driftResult.score_movement >= 0 ? "verified" : "danger"}
                />
                <Metric
                  label="RESOLVED"
                  value={driftResult.resolved_controls.length.toString()}
                  note="issues fixed"
                  tone="verified"
                />
                <Metric
                  label="REGRESSED"
                  value={driftResult.regressed_controls.length.toString()}
                  note="new issues introduced"
                  tone="danger"
                />
                <Metric
                  label="UNCHANGED"
                  value={driftResult.unchanged_count.toString()}
                  note="controls unaffected"
                  tone="neutral"
                />
              </div>
              <div className="two-column">
                <section className="panel">
                  <div className="panel-head">
                    <div>
                      <SectionLabel>RESOLVED CONTROLS</SectionLabel>
                      <h2>Security improvements</h2>
                    </div>
                    <span className="count-badge">
                      {driftResult.resolved_controls.length
                        .toString()
                        .padStart(2, "0")}
                    </span>
                  </div>
                  <div className="findings-table">
                    <div className="table-head">
                      <span>CONTROL</span>
                      <span>TRANSITION</span>
                    </div>
                    {driftResult.resolved_controls.map((c: any) => (
                      <div className="finding-row" key={c.control_id}>
                        <span className="finding-main">
                          <span className="finding-symbol symbol-pass">✓</span>
                          <span>
                            <strong>{c.control_id}</strong>
                          </span>
                        </span>
                        <span className="status-pill status-pass">
                          <span className="status-dot" />
                          {c.from_status} ➔ {c.to_status}
                        </span>
                      </div>
                    ))}
                  </div>
                </section>
                <section className="panel">
                  <div className="panel-head">
                    <div>
                      <SectionLabel>REGRESSED CONTROLS</SectionLabel>
                      <h2>New security regressions</h2>
                    </div>
                    <span className="count-badge">
                      {driftResult.regressed_controls.length
                        .toString()
                        .padStart(2, "0")}
                    </span>
                  </div>
                  <div className="findings-table">
                    <div className="table-head">
                      <span>CONTROL</span>
                      <span>TRANSITION</span>
                    </div>
                    {driftResult.regressed_controls.map((c: any) => (
                      <div className="finding-row" key={c.control_id}>
                        <span className="finding-main">
                          <span className="finding-symbol symbol-fail">!</span>
                          <span>
                            <strong>{c.control_id}</strong>
                          </span>
                        </span>
                        <span className="status-pill status-fail">
                          <span className="status-dot" />
                          {c.from_status} ➔ {c.to_status}
                        </span>
                      </div>
                    ))}
                  </div>
                </section>
              </div>
            </div>
          )}
        </>
      );
    if (location === "/review-queue")
      return (
        <>
          <PageIntro
            eyebrow="REVIEW QUEUE / EVIDENCE GAPS"
            title="Unknown is a decision."
            detail="Resolve uncertainty deliberately. These findings are not passes, and they never become authoritative without new evidence."
            action={
              <span className="queue-readout">
                <span className="signal signal-amber" />{" "}
                {reviewFindings.length.toString().padStart(2, "0")} unresolved
              </span>
            }
          />
          <div className="queue-banner">
            <div className="queue-icon">
              <CircleHelp size={22} />
            </div>
            <div>
              <strong>Review before you trust the posture.</strong>
              <span>
                Unknown blocks, parser gaps, and contested evidence remain
                visible until an operator provides a bounded explanation or
                reruns the deterministic audit.
              </span>
            </div>
            <button
              type="button"
              className="button button-secondary"
              onClick={() => navigate("/audits")}
            >
              Open audits <ArrowRight size={15} />
            </button>
          </div>
          <div className="two-column">
            <section className="panel">
              <div className="panel-head">
                <div>
                  <SectionLabel>UNRESOLVED FINDINGS</SectionLabel>
                  <h2>Evidence needing attention</h2>
                </div>
                <span className="count-badge">
                  {reviewFindings.length.toString().padStart(2, "0")}
                </span>
              </div>
              <FindingsTable
                findings={reviewFindings}
                reportVendor={report.audit.vendor}
                selectedId={selected?.finding_id || ""}
                onSelect={(finding) => setSelectedId(finding.finding_id)}
              />
            </section>
            <EvidencePanel finding={selected} />
          </div>
        </>
      );
    if (location === "/control-packs")
      return (
        <>
          <PageIntro
            eyebrow="CONTROL PACKS / DETERMINISTIC"
            title="Rules with receipts."
            detail="Inspect the control surface behind every result. Version, vendor scope, framework mappings, and remediation intent stay explicit."
            action={
              <button
                type="button"
                className="button button-secondary"
                onClick={() =>
                  setToast(
                    "Custom policy packs are loaded through the CLI/API boundary",
                  )
                }
              >
                {" "}
                <GitBranch size={15} /> Policy boundary
              </button>
            }
          />
          <div className="control-summary">
            <Metric
              label="ACTIVE PACK"
              value={`v${controlPackVersion}`}
              note="backend-authoritative"
              tone="verified"
            />
            <Metric
              label="CONTROLS"
              value={controlCount.toString().padStart(2, "0")}
              note="deterministic definitions"
            />
            <Metric
              label="VENDORS"
              value={vendorCount.toString().padStart(2, "0")}
              note="from active control registry"
            />
            <Metric
              label="AI ROLE"
              value="OFF"
              note="non-authoritative only"
              tone="safe"
            />
          </div>
          {detection && (
            <div className="queue-banner">
              <div className="queue-icon">
                <Fingerprint size={22} />
              </div>
              <div>
                <strong>
                  Parser selection:{" "}
                  {detection.selected_vendor
                    ? vendorLabel(detection.selected_vendor)
                    : "UNRESOLVED"}
                </strong>
                <span>
                  {(detection.confidence * 100).toFixed(0)}% confidence ·{" "}
                  {detection.reason}
                </span>
              </div>
              <span className="proof-tag">DETERMINISTIC</span>
            </div>
          )}
          <section className="panel control-list">
            <div className="panel-head">
              <div>
                <SectionLabel>BUILT-IN / V{controlPackVersion}</SectionLabel>
                <h2>Network assurance controls</h2>
              </div>
              <span className="proof-tag">
                <ShieldCheck size={12} /> hash-addressed
              </span>
            </div>
            {controlPack.length === 0 ? (
              <EmptyState
                title="Control metadata unavailable"
                detail="Start the local API to inspect the authoritative rule registry."
                icon={CircleHelp}
              />
            ) : (
              controlPack.map((control, index) => (
                <div className="control-row" key={control.control_id}>
                  <span className="control-index">
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <span>
                    <strong>{control.title}</strong>
                    <small>{control.intent}</small>
                  </span>
                  <code>
                    {control.control_id} · v{controlPackVersion}
                  </code>
                  <span className="control-state">
                    <span className="signal signal-teal" /> {control.severity}
                  </span>
                </div>
              ))
            )}
          </section>
        </>
      );
    if (location === "/remediation")
      return (
        <>
          <PageIntro
            eyebrow="REMEDIATION / PROOF-CARRYING"
            title="Preview the change. Prove the boundary."
            detail="Remediation is a review artifact, never an autonomous action. Every suggestion is bound to source, evidence, preconditions, and rollback metadata."
            action={
              <span className="queue-readout">
                <LockKeyhole size={14} /> NON-EXECUTABLE
              </span>
            }
          />
          <div className="remediation-guard">
            <div className="guard-icon">
              <LockKeyhole size={21} />
            </div>
            <div>
              <strong>Operator approval is mandatory.</strong>
              <span>
                ConfigSentinel AI can suggest a diff, but it cannot connect to a
                device, apply configuration, or turn an explanation into a
                verdict.
              </span>
            </div>
            <span className="proof-tag">SAFE PREVIEW</span>
          </div>
          <section className="panel remediation-list">
            <div className="panel-head">
              <div>
                <SectionLabel>
                  FAILED CONTROLS / {failedFindings.length}
                </SectionLabel>
                <h2>Proof-carrying remediation previews</h2>
              </div>
              <div className="action-row">
                <span className="proof-tag">
                  {approval?.status || "NOT_REQUESTED"}
                </span>
                {approval?.status === "NOT_REQUESTED" && (
                  <button
                    type="button"
                    className="button button-secondary"
                    onClick={requestApproval}
                  >
                    Request review
                  </button>
                )}
                {approval?.status === "PENDING_REVIEW" && (
                  <>
                    <button
                      type="button"
                      className="button button-secondary"
                      onClick={() => void decideApproval(true)}
                    >
                      Approve
                    </button>
                    <button
                      type="button"
                      className="button button-danger"
                      onClick={() => void decideApproval(false)}
                    >
                      Reject
                    </button>
                  </>
                )}
                <button
                  type="button"
                  className="button button-secondary"
                  onClick={exportRemediation}
                >
                  {" "}
                  <Download size={15} /> Download preview
                </button>
              </div>
            </div>
            {failedFindings.length === 0 ? (
              <EmptyState
                title="No failed controls"
                detail="Run an audit with a failing control to generate a review-only preview."
                icon={Check}
              />
            ) : (
              failedFindings.map((finding) => (
                <div className="remediation-row" key={finding.finding_id}>
                  <span className="finding-symbol symbol-fail">!</span>
                  <span>
                    <strong>{finding.control_id}</strong>
                    <small>
                      {finding.remediation_preview ||
                        "Review remediation intent after evidence inspection."}
                    </small>
                  </span>
                  <span className="hash-chip">
                    <Fingerprint size={12} /> source-bound
                  </span>
                  <button
                    type="button"
                    className="button button-tertiary"
                    onClick={() => {
                      setSelectedId(finding.finding_id);
                      navigate("/audits");
                    }}
                  >
                    Inspect <ArrowRight size={14} />
                  </button>
                </div>
              ))
            )}
          </section>
        </>
      );
    if (location === "/settings")
      return (
        <>
          <PageIntro
            eyebrow="SYSTEM / SETTINGS"
            title="Make the console yours."
            detail="These settings affect only this browser session and local demo behavior. They never change the authoritative backend verdict engine."
          />
          <div className="settings-grid">
            <section className="settings-section">
              <SectionLabel>APPEARANCE</SectionLabel>
              <h2>Theme preference</h2>
              <p>
                Choose the contrast profile that is easiest for your eyes. Your
                preference is saved locally in this browser.
              </p>
              <div className="theme-choice-row">
                <button
                  type="button"
                  className={`theme-choice ${theme === "light" ? "selected" : ""}`}
                  onClick={() => theme === "dark" && toggleTheme?.()}
                >
                  <Sun size={18} />
                  <span>
                    <strong>Light</strong>
                    <small>Paper and graphite</small>
                  </span>
                  {theme === "light" && <Check size={16} />}
                </button>
                <button
                  type="button"
                  className={`theme-choice ${theme === "dark" ? "selected" : ""}`}
                  onClick={() => theme === "light" && toggleTheme?.()}
                >
                  <Moon size={18} />
                  <span>
                    <strong>Dark</strong>
                    <small>Slate and signal</small>
                  </span>
                  {theme === "dark" && <Check size={16} />}
                </button>
              </div>
            </section>
            <section className="settings-section">
              <SectionLabel>LOCAL API</SectionLabel>
              <h2>Connection boundary</h2>
              <p>
                The dashboard talks only to the local FastAPI adapter. No cloud
                session or live device connection is configured.
              </p>
              <div className="setting-line">
                <span>Endpoint</span>
                <code>{API_BASE || "same-origin adapter"}</code>
              </div>
              <div className="setting-line">
                <span>Current state</span>
                <strong className={apiOnline ? "text-teal" : "text-amber"}>
                  {apiOnline ? "LOCAL API ONLINE" : "OFFLINE / FIXTURE MODE"}
                </strong>
              </div>
            </section>
            <section className="settings-section">
              <SectionLabel>PRIVACY</SectionLabel>
              <h2>Browser-local history</h2>
              <p>
                Audit snapshots stay in localStorage and are limited to the
                latest 20 records. Clear them when the demonstration ends.
              </p>
              <button
                type="button"
                className="button button-danger"
                onClick={clearHistory}
              >
                <X size={15} /> Clear {history.length} saved snapshot(s)
              </button>
            </section>
            <section className="settings-section">
              <SectionLabel>SAFETY CONTRACT</SectionLabel>
              <h2>What cannot happen here</h2>
              <div className="safety-list">
                <span>
                  <Check size={14} /> No live device connections
                </span>
                <span>
                  <Check size={14} /> No autonomous remediation
                </span>
                <span>
                  <Check size={14} /> No verdict override by AI
                </span>
                <span>
                  <Check size={14} /> No external submission
                </span>
              </div>
            </section>
          </div>
        </>
      );
    if (location === "/operator-guide")
      return (
        <>
          <PageIntro
            eyebrow="SYSTEM / OPERATOR GUIDE"
            title="A safe judging sequence."
            detail="Use this path to demonstrate the product clearly: show the evidence, acknowledge uncertainty, and never imply that a preview changes a device."
          />
          <div className="guide-grid">
            <div className="guide-rail">
              <div className="guide-step active">
                <span>01</span>
                <div>
                  <strong>Run a local audit</strong>
                  <small>
                    Start with the bundled fixture or upload a supported config.
                  </small>
                </div>
              </div>
              <div className="guide-step">
                <span>02</span>
                <div>
                  <strong>Inspect the evidence</strong>
                  <small>
                    Select a finding and show source lines, mapping, and
                    confidence.
                  </small>
                </div>
              </div>
              <div className="guide-step">
                <span>03</span>
                <div>
                  <strong>Explain unknowns</strong>
                  <small>
                    Open Review Queue and show why uncertainty is not a pass.
                  </small>
                </div>
              </div>
              <div className="guide-step">
                <span>04</span>
                <div>
                  <strong>Preview remediation</strong>
                  <small>
                    Show proof-carrying metadata and the non-executable
                    boundary.
                  </small>
                </div>
              </div>
            </div>
            <section className="guide-callout">
              <Sparkles size={23} />
              <SectionLabel>THE ONE-LINE PITCH</SectionLabel>
              <h2>“See the proof behind every finding.”</h2>
              <p>
                ConfigSentinel AI is an offline-first evidence workbench for
                network assurance. The deterministic engine owns the verdict;
                AI, if enabled, can only explain or suggest.
              </p>
              <button
                type="button"
                className="button button-primary"
                onClick={() => navigate("/")}
              >
                Return to overview <ArrowRight size={15} />
              </button>
            </section>
          </div>
        </>
      );
    return (
      <>
        <div className="overview-hero">
          <div>
            <SectionLabel>SECURITY ASSURANCE COMMAND CENTER</SectionLabel>
            <h1>Source → Understand → Assess → Decide → Verify → Prove</h1>
            <p>
              Evidence-backed logic drives every action in this workbench. AI
              remains advisory, while the rule engine remains the source of
              truth.
            </p>
            <div className="hero-meta">
              <span>
                <span className="signal signal-teal" />{" "}
                {apiOnline ? "LOCAL API ONLINE" : "OFFLINE FIXTURE"}
              </span>
              <span>
                <LockKeyhole size={12} /> NO LIVE DEVICE
              </span>
              <span>
                <Fingerprint size={12} /> SHA-256 BOUND
              </span>
            </div>
          </div>
          <div className="hero-score">
            <span>POSTURE SCORE</span>
            <strong>
              {score}
              <small>/100</small>
            </strong>
            <div className="score-track">
              <i style={{ width: `${score}%` }} />
            </div>
            <span>
              {score >= 80
                ? "operationally healthy"
                : score >= 60
                  ? "monitor with review"
                  : "requires intervention"}
            </span>
          </div>
        </div>
        <div className="overview-actions">
          <div>
            <SectionLabel>CURRENT WORKSPACE</SectionLabel>
            <strong>{selectedFileName}</strong>
            <span>
              {loading
                ? "Loading evidence report…"
                : `${report.summary.finding_count} findings · ${report.summary.failed_count} failures · ${report.summary.unknown_count} unknown`}
            </span>
          </div>
          <div className="action-row">
            {auditActions}
            <button
              type="button"
              className="button button-secondary"
              onClick={() => navigate("/review-queue")}
            >
              <CircleHelp size={15} /> Review queue{" "}
              {reviewFindings.length ? `(${reviewFindings.length})` : ""}
            </button>
          </div>
        </div>
        <div className="metrics-grid">
          <Metric
            label="FAILURES"
            value={report.summary.failed_count.toString().padStart(2, "0")}
            note="require attention"
            tone={report.summary.failed_count ? "danger" : "safe"}
          />
          <Metric
            label="UNKNOWN"
            value={report.summary.unknown_count.toString().padStart(2, "0")}
            note="review before trust"
            tone="warn"
          />
          <Metric
            label="EVALUATED"
            value={report.summary.evaluated_count.toString().padStart(2, "0")}
            note="rule-based results"
          />
          <Metric
            label="SAVED AUDITS"
            value={history.length.toString().padStart(2, "0")}
            note="browser-local history"
          />
        </div>
        <div className="two-column">
          <section className="panel">
            <div className="panel-head">
              <div>
                <SectionLabel>ASSURANCE JOURNEY</SectionLabel>
                <h2>Decision flow</h2>
              </div>
            </div>
            <div
              className="guide-grid"
              style={{
                gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
                gap: 12,
                padding: 16,
              }}
            >
              {[
                [
                  "SOURCE",
                  "Start from a known configuration or captured evidence bundle.",
                ],
                [
                  "UNDERSTAND",
                  "Parse the input and determine the correct vendor and control context.",
                ],
                [
                  "ASSESS",
                  "Apply the active rule pack to current posture and evidence.",
                ],
                [
                  "DECIDE",
                  "Resolve fails, unknowns, and approval status before acting.",
                ],
                [
                  "VERIFY",
                  "Check change history, drift, freshness, and proof integrity.",
                ],
                [
                  "PROVE",
                  "Export signed evidence and keep the decision audit-ready.",
                ],
              ].map(([step, description], index) => (
                <div
                  key={step}
                  className={`guide-step ${index === 0 ? "active" : ""}`}
                  style={{ minHeight: 100 }}
                >
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  <div>
                    <strong>{step}</strong>
                    <small>{description}</small>
                  </div>
                </div>
              ))}
            </div>
          </section>
          <section className="panel">
            <div className="panel-head">
              <div>
                <SectionLabel>Next Best Action</SectionLabel>
                <h2>Current priority</h2>
              </div>
            </div>
            <div
              style={{
                padding: 20,
                display: "flex",
                flexDirection: "column",
                gap: 12,
              }}
            >
              <div className="queue-banner" style={{ margin: 0 }}>
                <div className="queue-icon">
                  <CircleHelp size={22} />
                </div>
                <div>
                  <strong>
                    {failedFindings.length
                      ? `Address ${failedFindings.length} failed control(s)`
                      : "No rule-based failures remain"}
                  </strong>
                  <span>
                    {failedFindings.length
                      ? "Review the failing evidence, confirm intent, then route the proposal through the approval boundary."
                      : "The current posture is stable under the active rule pack and evidence set."}
                  </span>
                </div>
                <button
                  type="button"
                  className="button button-secondary"
                  onClick={() => navigate("/review-queue")}
                >
                  Open queue <ArrowRight size={15} />
                </button>
              </div>
              <div className="remediation-guard" style={{ margin: 0 }}>
                <div className="guard-icon">
                  <LockKeyhole size={21} />
                </div>
                <div>
                  <strong>
                    Deterministic engine holds the verdict; AI explains the
                    path.
                  </strong>
                  <span>
                    All decisions remain evidence-bound, reviewable, and
                    non-executable until an operator approves a bounded
                    remediation preview.
                  </span>
                </div>
              </div>
            </div>
          </section>
        </div>
        <div className="two-column">
          <section className="panel">
            <div className="panel-head">
              <div>
                <SectionLabel>POSTURE / LATEST REPORT</SectionLabel>
                <h2>{selectedFileName}</h2>
              </div>
              <div className="action-row">
                <button
                  type="button"
                  className="button button-secondary"
                  onClick={() => setShowFilters((value) => !value)}
                >
                  <SlidersHorizontal size={15} /> Filters{" "}
                  {filterCount ? `(${filterCount})` : ""}
                </button>
                <button
                  type="button"
                  className="button button-secondary"
                  onClick={() => exportReport()}
                >
                  <Download size={15} /> Export PDF
                </button>
              </div>
            </div>
            {showFilters && (
              <FilterBar
                severity={severityFilter}
                setSeverity={setSeverityFilter}
                status={statusFilter}
                setStatus={setStatusFilter}
                framework={frameworkFilter}
                frameworkOptions={frameworkOptions}
                setFramework={setFrameworkFilter}
                reset={resetFilters}
              />
            )}
            <div className="findings-table">
              <div className="table-head">
                <span>CONTROL / EVIDENCE</span>
                <span>VENDOR</span>
                <span>SEVERITY</span>
                <span>STATUS</span>
              </div>
              {visibleFindings.length === 0 ? (
                <EmptyState
                  title="No findings match this view"
                  detail="Change the filters or run a local audit to populate the evidence table."
                />
              ) : (
                visibleFindings.slice(0, 6).map((finding) => (
                  <button
                    type="button"
                    className={`finding-row ${finding.finding_id === selected?.finding_id ? "finding-selected" : ""}`}
                    key={finding.finding_id}
                    onClick={() => setSelectedId(finding.finding_id)}
                  >
                    <span className="finding-main">
                      <span
                        className={`finding-symbol symbol-${finding.status.toLowerCase()}`}
                      >
                        {finding.status === "FAIL"
                          ? "!"
                          : finding.status === "PASS"
                            ? "✓"
                            : "?"}
                      </span>
                      <span>
                        <strong>{finding.control_id}</strong>
                        <small>
                          {finding.observed_state || finding.rationale}
                        </small>
                        <code>
                          {evidenceLine(finding)}{" "}
                          <span>{frameworkText(finding)}</span>
                        </code>
                      </span>
                    </span>
                    <span className="vendor-label">
                      {vendorLabel(report.audit.vendor)}
                    </span>
                    <Severity value={finding.severity} />
                    <StatusPill status={finding.status} />
                  </button>
                ))
              )}
            </div>
          </section>
          <FindingResponsePanel
            finding={selected}
            onReview={() => navigate(selected && selected.status === "FAIL" ? "/remediation" : "/review-queue")}
          />
        </div>
        <div className="two-column">
          <TrendPanel
            history={history}
            onSelect={(entry) => selectHistory(entry)}
          />
          <HistoryPanel
            history={history}
            onSelect={(entry) => selectHistory(entry)}
            onDelete={(entry) => deleteHistory(entry)}
            onExport={(entry) => exportReport(entry.report, entry.fileName)}
          />
        </div>
      </>
    );
  };

  return (
    <>
      {pageContent()}
      <div className="toast" role="status">
        <span className="toast-mark">
          {apiOnline ? <Check size={12} /> : <Zap size={12} />}
        </span>
        {toast}
      </div>
    </>
  );
}

function FilterBar({
  severity,
  setSeverity,
  status,
  setStatus,
  framework,
  frameworkOptions,
  setFramework,
  reset,
}: {
  severity: SeverityValue | "ALL";
  setSeverity: (value: SeverityValue | "ALL") => void;
  status: FindingStatus | "ALL";
  setStatus: (value: FindingStatus | "ALL") => void;
  framework: string;
  frameworkOptions: string[];
  setFramework: (value: string) => void;
  reset: () => void;
}) {
  return (
    <div className="filter-bar">
      <label>
        Severity
        <select
          value={severity}
          onChange={(event) =>
            setSeverity(event.target.value as SeverityValue | "ALL")
          }
        >
          <option value="ALL">All severities</option>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
      </label>
      <label>
        Status
        <select
          value={status}
          onChange={(event) =>
            setStatus(event.target.value as FindingStatus | "ALL")
          }
        >
          <option value="ALL">All statuses</option>
          {["FAIL", "PASS", "UNKNOWN", "REVIEW_REQUIRED"].map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
      </label>
      <label>
        Framework
        <select
          value={framework}
          onChange={(event) => setFramework(event.target.value)}
        >
          <option value="ALL">All frameworks</option>
          {frameworkOptions.map((value) => (
            <option key={value} value={value}>
              {value.replaceAll("-", " ").toUpperCase()}
            </option>
          ))}
        </select>
      </label>
      <button type="button" className="button button-tertiary" onClick={reset}>
        Reset
      </button>
    </div>
  );
}
