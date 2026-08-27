"""Measure local deterministic audit timing without network access."""

from __future__ import annotations

from configsentinel import ConfigSentinelClient, DeterministicComplianceEngine
from configsentinel.hardening import ResourceBudget, benchmark_call


CONFIG = """version 17.9
hostname edge-1
line vty 0 4
 transport input telnet
 logging synchronous
 username admin password 0 [REDACTED]
"""


def main() -> None:
    budget = ResourceBudget()
    budget.validate_text(CONFIG)
    client = ConfigSentinelClient(engine=DeterministicComplianceEngine())
    result = client.audit_text(CONFIG, vendor="cisco_ios")
    stats = benchmark_call(lambda: client.audit_text(CONFIG, vendor="cisco_ios"), iterations=5)
    print(f"audit={result.audit_id} findings={len(result.findings)} failed={result.failed_count}")
    print(stats)


if __name__ == "__main__":
    main()
