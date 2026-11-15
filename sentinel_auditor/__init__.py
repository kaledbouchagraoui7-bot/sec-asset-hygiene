"""Passive 25-control domain compliance & nFADP/GDPR/DMARC/TLS auditing subpackage."""

from .sentinel_scanner import (
    count_spf_dns_lookups,
    detect_cmp_and_reject_symmetry,
    generate_excel_audit_workbook,
    generate_visual_scorecard,
    generate_word_audit_report,
    normalize_domain_and_url,
    query_doh_txt,
    write_remediation_configs,
)

__all__ = [
    "count_spf_dns_lookups",
    "detect_cmp_and_reject_symmetry",
    "generate_excel_audit_workbook",
    "generate_visual_scorecard",
    "generate_word_audit_report",
    "normalize_domain_and_url",
    "query_doh_txt",
    "write_remediation_configs",
]
