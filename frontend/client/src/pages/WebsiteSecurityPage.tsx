import { useState } from "react";
import { AlertTriangle, Check, Download, Globe2, LockKeyhole, Play, ShieldCheck } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type WebsiteFinding = {
  finding_id: string;
  rule_id: string;
  title: string;
  status: "PASS" | "FAIL" | "WARN" | "UNKNOWN";
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  evidence: { check_type: string; observed_value: string; expected_value: string };
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

const demoScan: WebsiteScanResult = {
  scan_id: "DEMO-WEB-001",
  target_origin: "https://demo.local",
  final_url: "https://demo.local/",
  posture_classification: "REVIEW",
  score: 72,
  findings_count: 4,
  passed_count: 2,
  failed_count: 1,
  warning_count: 1,
  unknown_count: 0,
  critical_count: 0,
  high_count: 1,
  medium_count: 1,
  low_count: 0,
  rule_pack_version: "demo-1.0",
  scan_timestamp: "2026-09-11T09:00:00Z",
  limitations: "Illustrative local fixture. It is not an external scan and does not guarantee absence of vulnerabilities.",
  findings: [
    { finding_id: "demo-https", rule_id: "WEB-HTTPS-001", title: "HTTPS transport", status: "PASS", severity: "HIGH", evidence: { check_type: "transport", observed_value: "HTTPS", expected_value: "HTTPS required" }, rationale: "The demo target uses encrypted transport.", remediation: "Keep HTTPS enforced and renew certificates before expiry.", observed_at: "2026-09-11T09:00:00Z", rule_version: "demo-1.0", limitations: "Fixture only." },
    { finding_id: "demo-headers", rule_id: "WEB-HEADERS-001", title: "Security headers", status: "FAIL", severity: "HIGH", evidence: { check_type: "response_header", observed_value: "Content-Security-Policy missing", expected_value: "CSP should be present" }, rationale: "A missing CSP reduces browser-side containment for injected content.", remediation: "Define and test a restrictive Content-Security-Policy.", observed_at: "2026-09-11T09:00:00Z", rule_version: "demo-1.0", limitations: "Fixture only." },
    { finding_id: "demo-cookie", rule_id: "WEB-COOKIE-001", title: "Cookie security", status: "WARN", severity: "MEDIUM", evidence: { check_type: "set-cookie", observed_value: "SameSite=Lax", expected_value: "Secure, HttpOnly, and appropriate SameSite" }, rationale: "The fixture shows a partially hardened session cookie.", remediation: "Review Secure, HttpOnly, and SameSite attributes for every session cookie.", observed_at: "2026-09-11T09:00:00Z", rule_version: "demo-1.0", limitations: "Fixture only." },
    { finding_id: "demo-redirect", rule_id: "WEB-REDIRECT-001", title: "Redirect behavior", status: "PASS", severity: "MEDIUM", evidence: { check_type: "redirect", observed_value: "Single HTTPS canonical redirect", expected_value: "No downgrade or loop" }, rationale: "The fixture follows one canonical secure redirect.", remediation: "Keep redirect rules explicit and regression-tested.", observed_at: "2026-09-11T09:00:00Z", rule_version: "demo-1.0", limitations: "Fixture only." },
  ],
};

function Label({ children }: { children: React.ReactNode }) { return <div className="section-label">{children}</div>; }
function Metric({ label, value, note, tone = "neutral" }: { label: string; value: string; note: string; tone?: string }) { return <div className={`metric metric-${tone}`}><Label>{label}</Label><strong>{value}</strong><span>{note}</span></div>; }
function Status({ status }: { status: WebsiteFinding["status"] }) { return <span className={`status-pill status-${status.toLowerCase()}`}><span className="status-dot" />{status}</span>; }

export default function WebsiteSecurityPage() {
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [toast, setToast] = useState("");
  const [scan, setScan] = useState<WebsiteScanResult>(demoScan);
  const [selectedId, setSelectedId] = useState(demoScan.findings[0].finding_id);
  const selected = scan.findings.find((finding) => finding.finding_id === selectedId) || scan.findings[0];

  const runScan = async () => {
    if (!websiteUrl.trim()) { setToast("Enter a website URL to scan"); return; }
    if (!authorized) { setToast("Please confirm authorization to scan the target"); return; }
    setScanning(true);
    try {
      const response = await fetch(`${API_BASE}/api/websites/scans`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: websiteUrl, authorization_confirmed: true, workspace_id: "local" }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || `Scan returned ${response.status}`);
      setScan(data as WebsiteScanResult);
      setSelectedId(data.findings[0]?.finding_id || "");
      setToast(`Scan complete: ${data.score}/100 ${data.posture_classification}`);
    } catch (error) {
      setToast(`Scan failed: ${error instanceof Error ? error.message : "local API unavailable"}`);
    } finally { setScanning(false); }
  };

  return <>
    <div className="page-intro">
      <div><Label>WEBSITE SECURITY / POSTURE CHECKER</Label><h1>Inspect the web boundary.</h1><p>Check transport, headers, cookies, redirects, and disclosure signals with a safe, non-exploitative inspection.</p></div>
      <div className="intro-action"><span className="queue-readout"><ShieldCheck size={14} /> LOCAL DEMO / SAFE INSPECTION MODE</span></div>
    </div>
    <div className="queue-banner website-demo-banner"><div className="queue-icon"><Globe2 size={22} /></div><div><strong>{scan.scan_id === demoScan.scan_id ? "Illustrative local website audit" : "Live local API result"}</strong><span>{scan.limitations}</span></div><span className="proof-tag"><LockKeyhole size={12} /> PASSIVE ONLY</span></div>
    <div className="website-scan-form"><div className="form-row"><label htmlFor="website-url">Target URL</label><input id="website-url" type="url" placeholder="https://example.com" value={websiteUrl} onChange={(event) => setWebsiteUrl(event.target.value)} /><label className="checkbox-label"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} /><span>I confirm authorization to scan this target</span></label><button className="button button-primary" type="button" onClick={runScan} disabled={scanning || !authorized}><Play size={15} /> {scanning ? "Scanning…" : "Scan website"}</button></div></div>
    {toast && <div className="queue-banner" role="status"><div className="queue-icon"><AlertTriangle size={18} /></div><div><strong>Inspection status</strong><span>{toast}</span></div></div>}
    <div className="scan-summary"><Metric label="POSTURE CLASSIFICATION" value={scan.posture_classification} note="deterministic calculation" tone={scan.score >= 80 ? "verified" : scan.score >= 50 ? "warn" : "danger"} /><Metric label="SECURITY SCORE" value={`${scan.score}/100`} note="passive inspection score" tone={scan.score >= 80 ? "verified" : scan.score >= 50 ? "warn" : "danger"} /><Metric label="HTTPS / TLS" value={scan.findings.some((finding) => finding.rule_id.includes("HTTPS") && finding.status === "PASS") ? "PASS" : "REVIEW"} note="transport check" tone="verified" /><Metric label="FINDINGS" value={scan.findings_count.toString()} note={`${scan.failed_count} failed · ${scan.warning_count} warning`} tone={scan.failed_count ? "danger" : "verified"} /></div>
    <div className="two-column"><section className="panel"><div className="panel-head"><div><Label>SCAN FINDINGS</Label><h2>{scan.target_origin}</h2></div><span className="proof-tag"><Check size={12} /> {scan.rule_pack_version}</span></div><div className="findings-table website-findings"><div className="table-head"><span>RULE / EVIDENCE</span><span>SEVERITY</span><span>STATUS</span></div>{scan.findings.map((finding) => <button type="button" className={`finding-row ${finding.finding_id === selected?.finding_id ? "finding-selected" : ""}`} key={finding.finding_id} onClick={() => setSelectedId(finding.finding_id)}><span className="finding-main"><span className={`finding-symbol symbol-${finding.status.toLowerCase()}`}>{finding.status === "PASS" ? "✓" : finding.status === "FAIL" ? "!" : "?"}</span><span><strong>{finding.rule_id}</strong><small>{finding.title}: {finding.evidence.observed_value}</small><code>{finding.evidence.check_type}</code></span></span><span className={`severity severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span><Status status={finding.status} /></button>)}</div></section><aside className="evidence-panel"><div className="evidence-top"><Label>SELECTED FINDING</Label><span className="proof-tag"><LockKeyhole size={12} /> REVIEW ONLY</span></div>{selected ? <><div className="evidence-id">{selected.rule_id} · {selected.severity}</div><h2>{selected.title}</h2><div className="evidence-block"><Label>EVIDENCE</Label><div className="evidence-line"><code>{selected.evidence.check_type}</code><span>{selected.evidence.observed_value}</span></div><div className="evidence-line"><code>EXPECTED</code><span>{selected.evidence.expected_value}</span></div></div><div className="evidence-block"><Label>REMEDIATION</Label><p className="muted-copy">{selected.remediation}</p></div><div className="evidence-block"><Label>LIMITATIONS</Label><p className="muted-copy">{selected.limitations}</p></div></> : <div className="empty-state"><span>Select a finding.</span></div>}</aside></div>
    <div className="website-boundary-note"><Download size={15} /><span>Reports are evidence exports for review. This scanner does not exploit targets, change systems, or prove absence of vulnerabilities.</span></div>
  </>;
}
