import json
from typing import List, Dict, Any
from datetime import datetime, timezone

class HygieneEnhancer:
    @staticmethod
    def calculate_security_grade(days_remaining: int) -> str:
        """Grades security posture based on certificate validity."""
        if days_remaining > 90: return "A"
        if days_remaining > 30: return "B"
        return "C"

    @staticmethod
    def export_batch_report(results: List[Dict[str, Any]], filepath: str) -> bool:
        """Exports security findings to a structured JSON file."""
        try:
            report = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "findings": results
            }
            with open(filepath, 'w') as f:
                json.dump(report, f)
            return True
        except (IOError, TypeError):
            return False

class TargetValidator:
    @staticmethod
    def validate_domain_format(targets: List[str]) -> List[str]:
        """Filters targets to ensure they follow basic domain naming conventions."""
        return [t for t in targets if '.' in t and len(t) > 3]