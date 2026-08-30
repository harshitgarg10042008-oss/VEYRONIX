import os
import json
import time
from configsentinel.parsers import detect_and_parse
from configsentinel.engine import DeterministicComplianceEngine
from configsentinel.models import Severity, FindingStatus

fixtures_dir = "tests/fixtures"
reports = []
correct_vendor = 0
total_fixtures = 0

expected_vendors = {
    "cisco.conf": "cisco_ios",
    "junos.conf": "junos",
    "arista.conf": "arista_eos"
}

def generate_report():
    global correct_vendor, total_fixtures
    
    start_time = time.time()
    total_controls_evaluated = 0
    total_findings = 0
    unknown_syntax_count = 0
    
    engine = DeterministicComplianceEngine()
    
    reports.append("## Fixture Evaluation Matrix\n")
    reports.append("| Fixture | Detected Vendor | Expected Vendor | Controls Evaluated | Findings | Unknown Syntaxes |")
    reports.append("|---|---|---|---|---|---|")

    for filename in os.listdir(fixtures_dir):
        if filename.endswith(".conf"):
            total_fixtures += 1
            filepath = os.path.join(fixtures_dir, filename)
            with open(filepath, "r") as f:
                content = f.read()
                
            expected_vendor = expected_vendors.get(filename, "unknown")
            
            try:
                parsed = detect_and_parse(content, vendor="auto")
                
                expected_to_actual = {
                    "cisco_ios": "cisco",
                    "junos": "juniper",
                    "arista_eos": "arista"
                }
                
                actual_vendor = parsed.config.vendor
                is_correct = (expected_to_actual.get(expected_vendor) == actual_vendor)
                if is_correct:
                    correct_vendor += 1

                # Run engine
                engine_vendor = "cisco_ios" if actual_vendor == "cisco" else "junos" if actual_vendor == "juniper" else actual_vendor
                audit_result = engine.audit(config_text=content, vendor=engine_vendor)
                controls_evaluated = len(engine.control_pack.controls)
                total_controls_evaluated += controls_evaluated
                findings = len(audit_result.findings)
                total_findings += findings
                
                unknowns = sum(1 for f in audit_result.findings if f.status in (FindingStatus.UNKNOWN, FindingStatus.NOT_APPLICABLE))
                unknown_syntax_count += unknowns
                
                reports.append(f"| `{filename}` | `{actual_vendor}` | `{expected_vendor}` | {controls_evaluated} | {findings} | {unknowns} |")
                
            except Exception as e:
                reports.append(f"| `{filename}` | `error` | `{expected_vendor}` | Error: {str(e)} | - | - |")

    duration = time.time() - start_time
    accuracy = (correct_vendor / total_fixtures) * 100 if total_fixtures > 0 else 0

    report_md = f"""# Parser & Control Accuracy Report

**Status:** PENDING EXTERNAL FIXTURES (Currently using synthetic local fixtures)
**Date:** Generated {time.strftime('%Y-%m-%d')}
**Total Fixtures Tested:** {total_fixtures}
**Correctly Detected Vendors:** {correct_vendor}
**Vendor Accuracy:** {accuracy:.2f}%
**Total Controls Evaluated:** {total_controls_evaluated}
**Total Findings Generated:** {total_findings}
**Unknown Syntax Rate:** {unknown_syntax_count}/{total_controls_evaluated}
**Execution Time:** {duration:.3f} seconds

> **Note:** Real-world accuracy claims for false positives and false negatives require sanitized stakeholder configurations, which are currently pending.

""" + "\n".join(reports) + "\n"

    os.makedirs("docs", exist_ok=True)
    with open("docs/ACCURACY_REPORT.md", "w", encoding="utf-8") as f:
        f.write(report_md)

    print("Accuracy report generated in docs/ACCURACY_REPORT.md")

if __name__ == "__main__":
    generate_report()
