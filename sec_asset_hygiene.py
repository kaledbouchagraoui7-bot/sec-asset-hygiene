import argparse
import json
import os
import socket
import ssl
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


@dataclass
class SecurityCheckResult:
    target: str
    domain: str
    ip_address: Optional[str]
    http_status: Optional[int]
    hsts_header: bool
    csp_header: bool
    tls_version: Optional[str]
    cert_days_remaining: Optional[int]
    error: Optional[str]


def normalize_target(target: str) -> str:
    """Normalizes target string to canonical standard URL form."""
    target = target.strip().lower()
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    return target


def deduplicate_targets(targets: List[str], threshold: float = 0.85) -> List[str]:
    """Deduplicates target domains using statistical string similarity algorithm."""
    normalized = []
    for t in targets:
        norm = normalize_target(t)
        if norm not in normalized:
            normalized.append(norm)

    unique_targets: List[str] = []
    for target in normalized:
        domain = urlparse(target).netloc
        is_duplicate = False
        for existing in unique_targets:
            existing_domain = urlparse(existing).netloc
            ratio = SequenceMatcher(None, domain, existing_domain).ratio()
            if ratio >= threshold and domain != existing_domain:
                if len(domain) < len(existing_domain):
                    unique_targets.remove(existing)
                    break
                else:
                    is_duplicate = True
                    break
        if not is_duplicate and target not in unique_targets:
            unique_targets.append(target)
    return unique_targets


def check_target_hygiene(target: str, timeout: int = 3) -> SecurityCheckResult:
    """Scans target host for HTTP status, security headers, and TLS cert expiry."""
    normalized = normalize_target(target)
    parsed = urlparse(normalized)
    domain = parsed.netloc or parsed.path

    ip_addr = None
    try:
        ip_addr = socket.gethostbyname(domain)
    except Exception:
        pass

    http_status = None
    hsts = False
    csp = False
    error_msg = None

    req = Request(normalized, headers={"User-Agent": "SecAssetHygiene/1.0 Audit Agent"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urlopen(req, timeout=timeout, context=ctx) as response:
            http_status = response.status
            headers = {k.lower(): v for k, v in response.headers.items()}
            hsts = "strict-transport-security" in headers
            csp = "content-security-policy" in headers
    except HTTPError as e:
        http_status = e.code
        headers = {k.lower(): v for k, v in e.headers.items()}
        hsts = "strict-transport-security" in headers
        csp = "content-security-policy" in headers
    except Exception as e:
        error_msg = str(e)

    tls_ver = None
    cert_days = None
    try:
        conn_ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with conn_ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                tls_ver = ssock.version()
                cert = ssock.getpeercert()
                if cert and "notAfter" in cert:
                    expire_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    cert_days = (expire_date - now).days
    except Exception:
        pass

    return SecurityCheckResult(
        target=target,
        domain=domain,
        ip_address=ip_addr,
        http_status=http_status,
        hsts_header=hsts,
        csp_header=csp,
        tls_version=tls_ver,
        cert_days_remaining=cert_days,
        error=error_msg
    )


def generate_markdown_report(results: List[SecurityCheckResult]) -> str:
    """Generates a structured Markdown security audit report."""
    lines = [
        "# Security Hygiene & Attack Surface Audit Report",
        f"*Generated on: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*",
        "",
        "## Summary Metrics",
        f"- **Total Targets Scanned:** {len(results)}",
        f"- **HSTS Header Compliance:** {sum(1 for r in results if r.hsts_header)} / {len(results)}",
        f"- **CSP Header Compliance:** {sum(1 for r in results if r.csp_header)} / {len(results)}",
        "",
        "## Findings Table",
        "| Domain | IP Address | HTTP Status | HSTS | CSP | TLS Version | Cert Days | Error/Notes |",
        "|---|---|---|---|---|---|---|---|"
    ]
    for r in results:
        hsts_str = "✅ Enforced" if r.hsts_header else "❌ Missing"
        csp_str = "✅ Enforced" if r.csp_header else "❌ Missing"
        status_str = str(r.http_status) if r.http_status else "N/A"
        tls_str = r.tls_version or "N/A"
        cert_str = str(r.cert_days_remaining) if r.cert_days_remaining is not None else "N/A"
        err_str = r.error if r.error else "None"
        lines.append(f"| `{r.domain}` | {r.ip_address or 'Unresolved'} | {status_str} | {hsts_str} | {csp_str} | {tls_str} | {cert_str} | {err_str} |")

    return "\n".join(lines)


def export_obsidian_vault(results: List[SecurityCheckResult], vault_dir: Path):
    """Generates frontmatter-enabled Obsidian notes and an Index vault."""
    vault_dir.mkdir(parents=True, exist_ok=True)
    notes_dir = vault_dir / "Targets"
    notes_dir.mkdir(exist_ok=True)

    index_lines = ["# Attack Surface Vault Index", "", "## Discovered Targets", ""]

    for r in results:
        safe_filename = f"{r.domain.replace('.', '_')}.md"
        note_path = notes_dir / safe_filename
        index_lines.append(f"- [[Targets/{safe_filename[:-3]}|{r.domain}]] - IP: `{r.ip_address or 'N/A'}`")

        content = [
            "---",
            "type: security_target",
            f"domain: \"{r.domain}\"",
            f"ip: \"{r.ip_address or ''}\"",
            f"hsts: {str(r.hsts_header).lower()}",
            f"csp: {str(r.csp_header).lower()}",
            f"status: {r.http_status or 0}",
            "tags:",
            "  - secops/audit",
            "  - target",
            "---",
            f"# Target: {r.domain}",
            "",
            "## Security Posture",
            f"- **IP Address:** `{r.ip_address or 'Unresolved'}`",
            f"- **HTTP Status:** `{r.http_status or 'N/A'}`",
            f"- **HSTS Enforced:** {r.hsts_header}",
            f"- **CSP Configured:** {r.csp_header}",
            f"- **TLS Protocol:** `{r.tls_version or 'N/A'}`",
            f"- **Cert Expiration:** `{r.cert_days_remaining or 'N/A'} days`",
            "",
            "## Automated AI Remediation Tasks",
            "- [ ] Review missing security headers",
            "- [ ] Verify TLS cipher suite security",
        ]
        note_path.write_text("\n".join(content), encoding="utf-8")

    (vault_dir / "Index.md").write_text("\n".join(index_lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="SecAsset Hygiene CLI - Security Scanner & Obsidian Vault Generator")
    parser.add_argument("--targets", nargs="+", help="Space-separated list of target domains")
    parser.add_argument("--file", type=str, help="Path to file containing domain targets (one per line or JSON array)")
    parser.add_argument("--dedup-threshold", type=float, default=0.85, help="Statistical deduplication ratio threshold (0.0 - 1.0)")
    parser.add_argument("--output-report", type=str, default="security_report.md", help="Path for output Markdown report")
    parser.add_argument("--obsidian-vault", type=str, help="Directory path to output populated Obsidian Vault")

    args = parser.parse_args()
    raw_targets = []

    if args.targets:
        raw_targets.extend(args.targets)
    if args.file and os.path.exists(args.file):
        with open(args.file, "r", encoding="utf-8") as f:
            if args.file.endswith(".json"):
                data = json.load(f)
                if isinstance(data, list):
                    raw_targets.extend(data)
            else:
                raw_targets.extend([line.strip() for line in f if line.strip()])

    if not raw_targets:
        print("Error: No targets provided. Specify --targets or --file.")
        sys.exit(1)

    deduped = deduplicate_targets(raw_targets, threshold=args.dedup_threshold)
    print(f"[*] Raw targets count: {len(raw_targets)} | Deduplicated targets count: {len(deduped)}")

    results = [check_target_hygiene(t) for t in deduped]

    report_md = generate_markdown_report(results)
    Path(args.output_report).write_text(report_md, encoding="utf-8")
    print(f"[+] Security report generated: {args.output_report}")

    if args.obsidian_vault:
        export_obsidian_vault(results, Path(args.obsidian_vault))
        print(f"[+] Obsidian Vault generated: {args.obsidian_vault}")


if __name__ == "__main__":
    main()
