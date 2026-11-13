import json
from typing import List, Dict, Any
from datetime import datetime

class HygieneReporter:
    @staticmethod
    def export_to_json(results: List[Dict[str, Any]], filepath: str) -> None:
        """Exports security check results to a structured JSON file."""
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "count": len(results),
            "data": results
        }
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=4)

class HygieneScorer:
    @staticmethod
    def calculate_score(result: Dict[str, Any]) -> int:
        """Calculates a security score out of 100 based on headers and TLS."""
        score = 0
        if result.get("hsts_header"): score += 40
        if result.get("csp_header"): score += 40
        if (result.get("cert_days_remaining") or 0) > 30: score += 20
        return min(score, 100)

    @staticmethod
    def get_grade(score: int) -> str:
        """Assigns a letter grade based on the calculated security score."""
        if score >= 90: return "A"
        if score >= 70: return "B"
        if score >= 50: return "C"
        return "F"

class BatchValidator:
    @staticmethod
    def validate_targets(targets: List[str]) -> Dict[str, bool]:
        """Validates that target strings are non-empty and unique."""
        return {t: (len(t) > 0) for t in set(targets)}