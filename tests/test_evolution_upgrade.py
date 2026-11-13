import pytest
from unittest.mock import patch, mock_open
from evolution_extensions import HygieneEnhancer, TargetValidator

def test_security_grade_logic():
    assert HygieneEnhancer.calculate_security_grade(100) == "A"
    assert HygieneEnhancer.calculate_security_grade(45) == "B"
    assert HygieneEnhancer.calculate_security_grade(10) == "C"

def test_domain_validation():
    targets = ["valid.com", "bad", "a.co"]
    valid = TargetValidator.validate_domain_format(targets)
    assert "valid.com" in valid
    assert "bad" not in valid
    assert "a.co" in valid

def test_export_batch_report_success():
    with patch("builtins.open", mock_open()) as mocked_file:
        result = HygieneEnhancer.export_batch_report([{"id": 1}], "test.json")
        assert result is True
        mocked_file.assert_called_once_with("test.json", 'w')

def test_export_batch_report_failure():
    with patch("builtins.open", side_effect=IOError):
        result = HygieneEnhancer.export_batch_report([], "invalid/path.json")
        assert result is False