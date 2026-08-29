from configsentinel.sensitive import render_sensitive_scan, scan_sensitive


def test_expanded_scan_detects_multiple_sensitive_categories_without_leaking_values():
    text = "aws_access_key_id=AKIA1234567890ABCDEF\nAuthorization: Bearer abcdefghijklmnop1234\nsnmp-server community public RO\nurl=postgres://admin:secret@example.invalid/db\n"
    scan = scan_sensitive(text)
    kinds = {hit.kind for hit in scan.hits}
    assert {
        "AWS_ACCESS_KEY",
        "BEARER_TOKEN",
        "SNMP_COMMUNITY",
        "CONNECTION_STRING",
    } <= kinds
    rendered = render_sensitive_scan(scan)
    assert "AKIA1234567890ABCDEF" not in rendered
    assert "secret@example.invalid" not in rendered
    assert "REDACTED_SENSITIVE" in rendered


def test_scan_is_empty_for_clean_text():
    scan = scan_sensitive("version 17.9\nno ip http server\n")
    assert scan.count == 0
    assert scan.as_dict()["hits"] == []
