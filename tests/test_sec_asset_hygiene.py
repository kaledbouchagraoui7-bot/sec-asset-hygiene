import unittest
from pathlib import Path
import tempfile
from sec_asset_hygiene import (
    normalize_target,
    deduplicate_targets,
    generate_markdown_report,
    export_obsidian_vault,
    SecurityCheckResult,
)


class TestSecAssetHygiene(unittest.TestCase):

    def test_normalize_target(self):
        self.assertEqual(normalize_target("example.com"), "https://example.com")
        self.assertEqual(normalize_target("http://test.org "), "http://test.org")

    def test_deduplicate_targets(self):
        input_targets = ["https://example.com", "example.com", "https://example.org"]
        deduped = deduplicate_targets(input_targets)
        self.assertEqual(len(deduped), 2)
        self.assertIn("https://example.com", deduped)
        self.assertIn("https://example.org", deduped)

    def test_generate_markdown_report(self):
        mock_results = [
            SecurityCheckResult(
                target="https://example.com",
                domain="example.com",
                ip_address="93.184.216.34",
                http_status=200,
                hsts_header=True,
                csp_header=False,
                tls_version="TLSv1.3",
                cert_days_remaining=90,
                error=None,
            )
        ]
        report = generate_markdown_report(mock_results)
        self.assertIn("# Security Hygiene & Attack Surface Audit Report", report)
        self.assertIn("`example.com`", report)
        self.assertIn("✅ Enforced", report)
        self.assertIn("❌ Missing", report)

    def test_export_obsidian_vault(self):
        mock_results = [
            SecurityCheckResult(
                target="https://testdomain.com",
                domain="testdomain.com",
                ip_address="127.0.0.1",
                http_status=200,
                hsts_header=True,
                csp_header=True,
                tls_version="TLSv1.3",
                cert_days_remaining=30,
                error=None,
            )
        ]
        with tempfile.TemporaryDirectory() as tmp_dir:
            vault_path = Path(tmp_dir) / "TestVault"
            export_obsidian_vault(mock_results, vault_path)

            self.assertTrue(vault_path.exists())
            self.assertTrue((vault_path / "Index.md").exists())
            target_note = vault_path / "Targets" / "testdomain_com.md"
            self.assertTrue(target_note.exists())
            note_text = target_note.read_text(encoding="utf-8")
            self.assertIn("type: security_target", note_text)
            self.assertIn("domain: \"testdomain.com\"", note_text)


if __name__ == "__main__":
    unittest.main()
