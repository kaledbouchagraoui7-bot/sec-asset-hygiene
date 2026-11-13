import pytest
from evolution_extensions import HygieneEnhancerV3

def test_validate_batch_success():
    assets = [{"id": 1, "type": "server"}]
    errors = HygieneEnhancerV3.validate_batch(assets, ["id", "type"])
    assert len(errors) == 0

def test_validate_batch_failure():
    assets = [{"id": 1}]
    errors = HygieneEnhancerV3.validate_batch(assets, ["id", "type"])
    assert len(errors) == 1
    assert "type" in errors[0]

def test_grade_security_posture():
    assert HygieneEnhancerV3.grade_security_posture(9.0) == "CRITICAL"
    assert HygieneEnhancerV3.grade_security_posture(1.0) == "LOW"

def test_export_sarif_structure():
    findings = [{"issue": "CVE-001"}]
    sarif = HygieneEnhancerV3.export_sarif(findings)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["message"]["text"] == "CVE-001"