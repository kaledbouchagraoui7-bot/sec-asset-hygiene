import pytest
from evolution_extensions import HygieneEnhancerV3

def test_validate_batch_detects_missing_keys():
    assets = [{"id": 1}, {"name": "test"}]
    errors = HygieneEnhancerV3.validate_batch(assets, ["id", "name"])
    assert len(errors) == 2

def test_grade_security_posture_logic():
    assert HygieneEnhancerV3.grade_security_posture(9.0) == "CRITICAL"
    assert HygieneEnhancerV3.grade_security_posture(1.0) == "LOW"

def test_sanitize_metadata_removes_secrets():
    data = {"id": 1, "token": "abc-123", "name": "asset"}
    sanitized = HygieneEnhancerV3.sanitize_metadata(data)
    assert "token" not in sanitized
    assert "id" in sanitized

def test_calculate_compliance_rate():
    assert HygieneEnhancerV3.calculate_compliance_rate(5, 10) == 50.0
    assert HygieneEnhancerV3.calculate_compliance_rate(0, 0) == 0.0