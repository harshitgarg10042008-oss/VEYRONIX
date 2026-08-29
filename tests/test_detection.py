from configsentinel.api import AuditApi, AuditPayload, create_app
from configsentinel.detection import detect_vendor
from configsentinel.parsers import detect_and_parse


def test_detects_arista_with_ranked_confidence():
    text = (
        "! Arista\nversion 4.28.0F\nmanagement api http-commands\ninterface Ethernet1\n"
    )
    result = detect_vendor(text)
    assert result.selected_vendor == "arista_eos"
    assert result.confidence >= 0.5
    assert result.ambiguous is False
    assert result.candidates[0].vendor == "arista_eos"


def test_detects_junos_and_auto_parser_uses_selected_vendor():
    text = "set system services ssh\nset system services telnet\n"
    result = detect_vendor(text)
    assert result.selected_vendor == "junos"
    parsed = detect_and_parse(text, vendor="auto")
    assert parsed.config.platform == "junos"


def test_empty_or_unknown_input_fails_closed():
    result = detect_vendor("ordinary prose without configuration markers")
    assert result.selected_vendor is None
    assert result.confidence < 0.5


def test_api_detection_contract_is_local_and_ranked():
    route = next(
        route
        for route in create_app().routes
        if getattr(route, "path", None) == "/api/detect"
    )
    payload = route.endpoint(
        {
            "config_text": "table inet filter {\n chain input {\n  tcp dport 22 accept\n }\n}"
        }
    )
    assert payload["selected_vendor"] == "linux_nftables"
    assert payload["candidates"][0]["vendor"] == "linux_nftables"
