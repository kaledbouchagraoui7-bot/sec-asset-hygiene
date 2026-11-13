import json
import logging
from typing import List, Dict, Any
from datetime import datetime, timezone
from functools import wraps

logger = logging.getLogger('evolution_extensions_v2')

def log_transition(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        logger.info(f"Entering {func.__name__}")
        result = func(*args, **kwargs)
        return result
    return wrapper

class HygieneEnhancerV2:
    @staticmethod
    @log_transition
    def export_report(findings: List[Dict[str, Any]], filepath: str) -> bool:
        try:
            report = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "count": len(findings),
                "results": findings
            }
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            return True
        except Exception:
            return False

    @staticmethod
    @log_transition
    def calculate_risk_score(findings: List[Dict[str, Any]]) -> float:
        if not findings: return 0.0
        severity_map = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.0}
        total = sum(severity_map.get(f.get("severity", "low").lower(), 1.0) for f in findings)
        return round(total / len(findings), 2)