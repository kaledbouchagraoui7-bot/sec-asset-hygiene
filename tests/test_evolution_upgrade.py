import pytest
import os
from evolution_extensions import HygieneReporter, HygieneScorer

def test_scorer_perfect_score():
    result = {"hsts_header": True, "csp_header": True, "cert_days_remaining": 60}
    assert HygieneScorer.calculate_score(result) == 100

def test_scorer_partial_score():
    result = {"hsts_header": True, "csp_header": False, "cert_days_remaining": 10}
    assert HygieneScorer.calculate_score(result) == 40

def test_json_export_creates_file(tmp_path):
    d = tmp_path / "report.json"
    HygieneReporter.export_to_json([{"target": "test.com"}], str(d))
    assert d.exists()

def test_json_export_content(tmp_path):
    d = tmp_path / "report.json"
    HygieneReporter.export_to_json([{"target": "test.com"}], str(d))
    with open(d, 'r') as f:
        data = f.read()
        assert "test.com" in data