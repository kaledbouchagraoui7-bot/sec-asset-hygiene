import json
from typing import List, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field, validator

class SecurityResult(BaseModel):
    target: str
    hsts_header: bool = False
    csp_header: bool = False
    cert_days_remaining: int = Field(ge=0, default=0)

class HygieneReport(BaseModel):
    timestamp: str
    count: int
    data: List[Dict[str, Any]]

class AdvancedReporter:
    @staticmethod
    def generate_sarif_compatible(results: List[SecurityResult]) -> str:
        """Generates a simplified SARIF-like structure for security findings."""
        report = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "AssetHygieneScanner"}},
                "results": [{"message": {"text": f"Target {r.target} scored {r.cert_days_remaining} days"}} for r in results]
            }]
        }
        return json.dumps(report)

class TargetSanitizer:
    @staticmethod
    def sanitize_and_deduplicate(targets: List[str]) -> List[str]:
        """Cleans input strings and ensures uniqueness."""
        return sorted(list({t.strip().lower() for t in targets if t and t.strip()}))