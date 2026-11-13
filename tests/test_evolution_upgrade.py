import pytest
import os
import json
from evolution_extensions import HygieneScorer, BatchValidator, HygieneReporter

@pytest.fixture
def sample_result():
    return {"hsts_header": True, "csp_header": True, "cert_days_remaining": 45}

def test_calculate_score(sample_result):
    score = HygieneScorer.calculate_score(sample_result)
    assert score == 100

def test_get_grade():
    assert HygieneScorer.get_grade(95) == "A"
    assert HygieneScorer.get_grade(40) == "F"

def test_validate_targets():
    targets = ["example.com", "", "example.com"]
    validation = BatchValidator.validate_targets(targets)
    assert validation["example.com"] is True
    assert validation[""] is False

def test_export_to_json(tmp_path):
    d = tmp_path / "report.json"
    data = [{"id": 1}]
    HygieneReporter.export_to_json(data, str(d))
    assert d.exists()
    with open(d, 'r') as f:
        content = json.load(f)
        assert content["count"] == 1