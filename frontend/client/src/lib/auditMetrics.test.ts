import { describe, expect, it } from "vitest";
import { calculatePostureScore } from "./auditMetrics";

describe("calculatePostureScore", () => {
  it("treats unknown and review-required findings as risk", () => {
    expect(calculatePostureScore([
      { status: "PASS", severity: "LOW" },
      { status: "UNKNOWN", severity: "CRITICAL" },
      { status: "REVIEW_REQUIRED", severity: "HIGH" },
    ])).toBe(18);
  });

  it("excludes not-applicable controls", () => {
    expect(calculatePostureScore([
      { status: "NOT_APPLICABLE", severity: "CRITICAL" },
      { status: "PASS", severity: "HIGH" },
    ])).toBe(100);
  });

  it("returns zero when there are no applicable findings", () => {
    expect(calculatePostureScore([])).toBe(0);
  });
});
