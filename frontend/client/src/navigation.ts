import {
  AlertTriangle,
  Activity,
  Check,
  ClipboardCheck,
  Clock3,
  Download,
  FileCheck2,
  FileText,
  Fingerprint,
  GitBranch,
  Layers3,
  LifeBuoy,
  LockKeyhole,
  Network,
  Play,
  Server,
  Settings2,
  ShieldCheck,
  TerminalSquare,
  Zap,
} from "lucide-react";

export type NavItem = {
  label: string;
  path: string;
  icon: any;
  description: string;
};

export const CORE_ITEMS: NavItem[] = [
  { label: "Overview", path: "/", icon: Layers3, description: "Posture at a glance" },
  { label: "Asset Inventory", path: "/inventory", icon: Server, description: "Manage tracked devices" },
  { label: "Continuous Monitoring", path: "/monitoring", icon: Activity, description: "Scheduled checks" },
  { label: "Website Security", path: "/website-security", icon: ShieldCheck, description: "Scan website posture" },
];

export const ASSURANCE_ITEMS: NavItem[] = [
  { label: "Audits", path: "/audits", icon: ClipboardCheck, description: "Run and compare audits" },
  { label: "Assurance Chain", path: "/assurance-chain", icon: LockKeyhole, description: "Verify evidence timeline" },
  { label: "Review queue", path: "/review-queue", icon: Check, description: "Resolve unknown evidence" },
  { label: "Remediation", path: "/remediation", icon: TerminalSquare, description: "Review proof-carrying fixes" },
  { label: "Drift Detection", path: "/drift", icon: GitBranch, description: "Compare configuration changes" },
  { label: "Notary Console", path: "/notary", icon: LockKeyhole, description: "Sign & verify evidence" },
  { label: "Evidence Exchange", path: "/exchange", icon: Download, description: "Share signed findings" },
];

export const LAB_ITEMS: NavItem[] = [
  { label: "Blast Radius", path: "/blast-radius", icon: AlertTriangle, description: "Assess change impact" },
  { label: "Mutation Lab", path: "/mutation-lab", icon: Zap, description: "Evaluate rule robustness" },
  { label: "Attack Graph", path: "/graph", icon: Network, description: "Simulate exploit paths" },
  { label: "Threat Models", path: "/threat-model", icon: AlertTriangle, description: "Compile code to STRIDE" },
  { label: "Counterfactuals", path: "/counterfactual", icon: Play, description: "Test hypothetical rules" },
  { label: "Parser Differential", path: "/parser-diff", icon: GitBranch, description: "Find ambiguity gaps" },
  { label: "Control packs", path: "/control-packs", icon: FileCheck2, description: "Inspect deterministic rules" },
  { label: "Knowledge Graph", path: "/knowledge-graph", icon: Network, description: "Query institutional memory" },
];

export const SYSTEM_ITEMS: NavItem[] = [
  { label: "Settings", path: "/settings", icon: Settings2, description: "Local preferences" },
  { label: "Operator guide", path: "/operator-guide", icon: LifeBuoy, description: "Safe demo sequence" },
];

export const ALL_NAV_ITEMS = [...CORE_ITEMS, ...ASSURANCE_ITEMS, ...LAB_ITEMS];
