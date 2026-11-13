import json
import logging
from typing import List, Dict, Any
from datetime import datetime, timezone

logger = logging.getLogger('evolution_extensions_v3')

class HygieneEnhancerV3:
    @staticmethod
    def validate_batch(assets: List[Dict[str, Any]], required_keys: List[str]) -> List[str]:
        """Validates a batch of assets and returns a list of missing keys for invalid assets."""
        errors = []
        for i, asset in enumerate(assets):
            missing = [k for k in required_keys if k not in asset]
            if missing:
                errors.append(f"Asset {i} missing: {', '.join(missing)}")
        return errors

    @staticmethod
    def grade_security_posture(score: float) -> str:
        """Grades a risk score into a human-readable category."""
        if score >= 8.0: return "CRITICAL"
        if score >= 5.0: return "HIGH"
        if score >= 2.0: return "MEDIUM"
        return "LOW"

    @staticmethod
    def export_sarif(findings: List[Dict[str, Any]], tool_name: str = "sec_asset_hygiene") -> Dict[str, Any]:
        """Generates a minimal SARIF-compliant structure."""
        return {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": tool_name}},
                "results": [{"message": {"text": f.get("issue", "N/A")} for f in findings}]
            }]
        }