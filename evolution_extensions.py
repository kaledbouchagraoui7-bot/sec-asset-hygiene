import json
from typing import List, Dict, Any

class HygieneEnhancerV3:
    @staticmethod
    def validate_batch(assets: List[Dict[str, Any]], required_keys: List[str]) -> List[str]:
        errors = []
        for i, asset in enumerate(assets):
            missing = [k for k in required_keys if k not in asset]
            if missing:
                errors.append(f"Asset {i} missing: {', '.join(missing)}")
        return errors

    @staticmethod
    def grade_security_posture(score: float) -> str:
        if score >= 8.0: return "CRITICAL"
        if score >= 5.0: return "HIGH"
        if score >= 2.0: return "MEDIUM"
        return "LOW"

    @staticmethod
    def sanitize_metadata(data: Dict[str, Any]) -> Dict[str, Any]:
        """Removes potentially sensitive keys from asset metadata."""
        sensitive_keys = {'password', 'token', 'secret', 'key'}
        return {k: v for k, v in data.items() if k.lower() not in sensitive_keys}

    @staticmethod
    def calculate_compliance_rate(passed: int, total: int) -> float:
        """Calculates percentage of compliant assets."""
        if total == 0: return 0.0
        return round((passed / total) * 100, 2)