export type AuditStatus = "FAIL" | "PASS" | "UNKNOWN" | "NOT_APPLICABLE" | "REVIEW_REQUIRED";
export type AuditSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type MetricFinding = { status: AuditStatus; severity: AuditSeverity };

const SEVERITY_WEIGHT: Record<AuditSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export function calculatePostureScore(findings: MetricFinding[]): number {
  const applicable = findings.filter((finding) => finding.status !== "NOT_APPLICABLE");
  if (!applicable.length) return 0;
  const total = applicable.reduce((sum, finding) => sum + SEVERITY_WEIGHT[finding.severity], 0);
  const risk = applicable.reduce(
    (sum, finding) => sum + ((["FAIL", "UNKNOWN", "REVIEW_REQUIRED"] as AuditStatus[]).includes(finding.status) ? SEVERITY_WEIGHT[finding.severity] : 0),
    0,
  );
  return Math.max(0, Math.round(((total - risk) / total) * 100));
}
