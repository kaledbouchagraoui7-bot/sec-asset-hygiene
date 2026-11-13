import pytest
import os
from evolution_extensions import HygieneEnhancer, TargetValidator

def test_grading_logic():
    assert HygieneEnhancer.calculate_security_grade(100) == "A"
    assert HygieneEnhancer.calculate_security_grade(10) == "C"

def test_domain_validation():
    targets = ["google.com", "invalid", "test.org"]
    valid = TargetValidator.validate_domain_format(targets)
    assert "google.com" in valid
    assert "invalid" not in valid

def test_report_export(tmp_path):
    d = tmp_path / "report.json"
    data = [{"target": "test.com", "grade": "A"}]
    success = HygieneEnhancer.export_batch_report(data, str(d))
    assert success is True
    assert d.exists()

def test_empty_validation():
    assert TargetValidator.validate_domain_format([]) == []