import json
import logging
from typing import List, Dict, Any
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('evolution_extensions')

class HygieneEnhancer:
    @staticmethod
    def calculate_security_grade(days_remaining: int) -> str:
        logger.info(f"Calculating grade for {days_remaining} days")
        if days_remaining > 90: return "A"
        if days_remaining > 30: return "B"
        return "C"

    @staticmethod
    def export_batch_report(results: List[Dict[str, Any]], filepath: str) -> bool:
        try:
            logger.info(f"Exporting {len(results)} findings to {filepath}")
            report = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "findings": results
            }
            with open(filepath, 'w') as f:
                json.dump(report, f)
            return True
        except (IOError, TypeError) as e:
            logger.error(f"Export failed: {e}")
            return False

class TargetValidator:
    @staticmethod
    def validate_domain_format(targets: List[str]) -> List[str]:
        logger.info(f"Validating {len(targets)} targets")
        return [t for t in targets if '.' in t and len(t) > 3]