import json
from pathlib import Path
import pytest
from sec_asset_hygiene import (
    SecurityCheckResult,
    generate_json_report,
    generate_sarif_report,
    batch_check_targets,
)


def test_generate_json_report():
    mock_results = [
        SecurityCheckResult(
            target="https://example.com",
            domain="example.com",
            ip_address="93.184.216.34",
            http_status=200,
            hsts_header=True,
            csp_header=False,
            tls_version="TLSv1.3",
            cert_days_remaining=60,
            error=None,
        )
    ]
    report_str = generate_json_report(mock_results)
    data = json.loads(report_str)
    assert "generated_at" in data
    assert len(data["results"]) == 1
    assert data["results"][0]["domain"] == "example.com"
    assert data["results"][0]["hsts_header"] is True


def test_generate_sarif_report():
    mock_results = [
        SecurityCheckResult(
            target="https://vulnerable.local",
            domain="vulnerable.local",
            ip_address="127.0.0.1",
            http_status=200,
            hsts_header=False,
            csp_header=False,
            tls_version=None,
            cert_days_remaining=0,
            error=None,
        )
    ]
    sarif_str = generate_sarif_report(mock_results)
    data = json.loads(sarif_str)
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) > 0
    results = data["runs"][0]["results"]
    assert len(results) == 2
    rule_ids = [r["ruleId"] for r in results]
    assert "SEC001" in rule_ids
    assert "SEC002" in rule_ids


def test_batch_check_targets():
    targets = ["example.com", "http://example.com"]
    results = batch_check_targets(targets, max_workers=2, timeout=1)
    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0].domain == "example.com"
