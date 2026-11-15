# SecAsset Hygiene & Sentinel Compliance Auditor 🛡️

[![CI](https://github.com/kaledbouchagraoui7-bot/sec-asset-hygiene/actions/workflows/ci.yml/badge.svg)](https://github.com/kaledbouchagraoui7-bot/sec-asset-hygiene/actions/workflows/ci.yml)

An open-source, privacy-first Python suite for DevSecOps, privacy teams, and DPOs combining **DNS/TLS asset hygiene (`sec_asset_hygiene.py`)** and **25-control nFADP/GDPR/DMARC/EAA passive compliance auditing (`sentinel_auditor/`)**.

- **Live Zero-Install ROI Demo (GitHub Pages):** [https://kaledbouchagraoui7-bot.github.io/sec-asset-hygiene/](https://kaledbouchagraoui7-bot.github.io/sec-asset-hygiene/)
- **Automated Verification:** `12` passing `pytest` tests (`8` asset hygiene + `4` Sentinel 25-control auditor tests).

## Capabilities
- **Asset Hygiene & Obsidian Export (`sec_asset_hygiene.py`):** Normalizes URLs/domains, performs statistical target deduplication, audits HTTP status / HSTS / CSP / TLS expiry, and exports Markdown + Obsidian Vault notes.
- **Sentinel 25-Control Passive Compliance Auditor (`sentinel_auditor/`):** Absorbed from `sentinel-compliance-auditor`. Performs passive DNS-over-HTTPS (`DMARC`/`SPF` lookup counter/`CAA`), pre-consent US tracker / Google Fonts checks (Swiss nFADP & EU GDPR), Edge Security (`HSTS`, `CSP`, `security.txt`), Accessibility baseline (`WCAG 2.1 AA`), and outputs Word `.docx`, 4-sheet Excel `.xlsx`, 300-DPI scorecard `.png`/`.pdf`, and drop-in remediation configs.

## Installation
```bash
git clone https://github.com/kaledbouchagraoui7-bot/sec-asset-hygiene.git
cd sec-asset-hygiene
pip install -r requirements.txt
```

## Usage Examples

### Asset Hygiene Scan & Obsidian Vault Export
```bash
python sec_asset_hygiene.py --targets example.com test.org --output-report report.md
python sec_asset_hygiene.py --file asset_list.txt --dedup-threshold 0.85 --obsidian-vault ~/Obsidian/SecurityVault
```

### Sentinel 25-Control Domain Compliance Audit
```bash
python sentinel_auditor/sentinel_scanner.py example.ch --output-dir output
```

## Running Tests
```bash
pytest -v
```

## License
Built as a free, open-source Python utility under the [MIT License](LICENSE). Strictly passive external observation only.
