# SecAsset Hygiene CLI 🛡️

An open-source, privacy-first Python CLI tool for DevSecOps consultants and cybersecurity auditors to perform DNS/TLS hygiene scanning, statistical deduplication of target assets, and export formatted reports directly into Obsidian vaults for local AI agent workflows.

## Features
- 🔍 **DNS & Security Header Scanning**: Audits HTTP status, HSTS, CSP, and TLS certificate expiration using standard library Python.
- 🧹 **Statistical Deduplication**: Deduplicates asset lists using fuzzy string similarity ratios.
- 📝 **Markdown Report Generation**: Produces instant security audit reports for compliance frameworks (ISO27001 / NIS2).
- 🧠 **Obsidian Vault Export**: Generates frontmatter-rich `.md` notes and vault index files ready for AI agent inspection (e.g. Smart Connections / Local LLMs).

## Installation
No third-party dependencies required. Python 3.12+ standard library only.

```bash
git clone https://github.com/kaledbouchagraoui7-bot/sec-asset-hygiene.git
cd sec-asset-hygiene
python3 sec_asset_hygiene.py --help
```

## Usage Examples

### Basic Domain Scan & Report Output
```bash
python3 sec_asset_hygiene.py --targets example.com test.org --output-report report.md
```

### File Input with Deduplication & Obsidian Vault Export
```bash
python3 sec_asset_hygiene.py --file asset_list.txt --dedup-threshold 0.85 --obsidian-vault ~/Obsidian/SecurityVault
```

## Running Tests
Run unit tests using `pytest` or standard `unittest`:
```bash
pytest
```

## About & License
Built as a free, open-source Python utility by a student engineer for learning and practical security hygiene checks.
Licensed under the [MIT License](LICENSE).
