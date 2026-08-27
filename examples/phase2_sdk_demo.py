"""Phase 2 SDK demonstration.

Run from the repository root with:
    PYTHONPATH=src python examples/phase2_sdk_demo.py

The fixture engine is intentionally small. Real parsers and control packs are
introduced in later phases.
"""

from configsentinel import ConfigSentinelClient, FixtureAuditEngine, LLMConfig, LLMCopilot


configuration = """!
line vty 0 4
 transport input telnet
!"""

client = ConfigSentinelClient(engine=FixtureAuditEngine())
result = client.audit_text(configuration, vendor="cisco_ios")

print(f"audit={result.audit_id} vendor={result.vendor} failed={result.failed_count}")
for finding in result.findings:
    print(f"{finding.control_id}: {finding.status.value} ({finding.severity.value})")
    for span in finding.evidence:
        print(f"  evidence L{span.start_line}: {span.excerpt}")

# The LLM is disabled by default. Later phases may supply a provider, but the
# deterministic audit remains usable when a model is unavailable.
copilot = LLMCopilot(config=LLMConfig(enabled=False))
print(f"llm_enabled={copilot.config.enabled}")
