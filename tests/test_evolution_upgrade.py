import pytest
import os
from evolution_extensions import HygieneEnhancerV2

def test_risk_score_calculation():
    findings = [{"severity": "critical"}, {"severity": "low"}]
    assert HygieneEnhancerV2.calculate_risk_score(findings) == 5.5

def test_empty_risk_score():
    assert HygieneEnhancerV2.calculate_risk_score([]) == 0.0

def test_report_export_success(tmp_path):
    d = tmp_path / "report.json"
    success = HygieneEnhancerV2.export_report([{"id": "test"}], str(d))
    assert success is True
    assert d.exists()

def test_report_export_failure():
    # Invalid path to trigger exception
    assert HygieneEnhancerV2.export_report([], "/root/forbidden.json") is False