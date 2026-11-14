import pytest
from evolution_extensions import HygieneEnhancerV3

def test_grade_security_posture():
    assert HygieneEnhancerV3.grade_security_posture(9.0) == "CRITICAL"
    assert HygieneEnhancerV3.grade_security_posture(1.0) == "LOW"

def test_sanitize_metadata():
    data = {"id": 1, "password": "secret123", "name": "test"}
    sanitized = HygieneEnhancerV3.sanitize_metadata(data)
    assert "password" not in sanitized
    assert sanitized["id"] == 1

def test_validate_schema_strict():
    schema = {"id": int, "name": str}
    assert HygieneEnhancerV3.validate_schema_strict({"id": 1, "name": "test"}, schema) is True
    assert HygieneEnhancerV3.validate_schema_strict({"id": "1", "name": "test"}, schema) is False

def test_calculate_compliance_rate():
    assert HygieneEnhancerV3.calculate_compliance_rate(5, 10) == 50.0
    assert HygieneEnhancerV3.calculate_compliance_rate(0, 0) == 0.0