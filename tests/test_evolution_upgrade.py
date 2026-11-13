import pytest
from evolution_extensions import SecurityResult, AdvancedReporter, TargetSanitizer

def test_security_result_validation():
    res = SecurityResult(target="example.com", hsts_header=True)
    assert res.target == "example.com"
    assert res.hsts_header is True

def test_security_result_invalid_days():
    with pytest.raises(ValueError):
        SecurityResult(target="bad.com", cert_days_remaining=-5)

def test_target_sanitization():
    raw = ["  google.com ", "GOOGLE.COM", "", "bing.com"]
    cleaned = TargetSanitizer.sanitize_and_deduplicate(raw)
    assert cleaned == ["bing.com", "google.com"]

def test_sarif_generation():
    results = [SecurityResult(target="test.com", cert_days_remaining=45)]
    output = AdvancedReporter.generate_sarif_compatible(results)
    assert "test.com" in output
    assert "2.1.0" in output