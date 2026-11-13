import pytest
from evolution_extensions import HygieneEnhancerV2

@pytest.fixture
def sample_findings():
    return [{"ruleId": "SEC001", "message": "Critical"}]

@pytest.fixture
def raw_targets():
    return ["  example.com ", "test.org", "", 123]

def test_sarif_structure(sample_findings):
    result = HygieneEnhancerV2.generate_sarif_stub(sample_findings)
    assert result["version"] == "2.1.0"
    assert len(result["runs"][0]["results"]) == 1

def test_batch_sanitize_valid(raw_targets):
    sanitized = HygieneEnhancerV2.batch_sanitize_targets(raw_targets)
    assert "example.com" in sanitized
    assert "test.org" in sanitized
    assert len(sanitized) == 2

def test_sarif_empty():
    result = HygieneEnhancerV2.generate_sarif_stub([])
    assert result["runs"][0]["results"] == []

def test_sanitize_empty_list():
    assert HygieneEnhancerV2.batch_sanitize_targets([]) == []