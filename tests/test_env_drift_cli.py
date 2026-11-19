"""Deterministic unit tests for env-secrets-drift-entropy-auditor-cli-lite."""

import json
from pathlib import Path
import tempfile
import unittest

from env_drift_auditor.auditor import (
    audit_environments,
    format_json_report,
    format_markdown_report,
    generate_env_example,
)
from env_drift_auditor.cli import main, parse_env_specs
from env_drift_auditor.entropy import (
    detect_secret,
    is_placeholder,
    redact_secret,
    shannon_entropy,
)
from env_drift_auditor.parser import parse_env_text, strip_inline_comment, unquote_value


class TestParser(unittest.TestCase):
    def test_basic_key_value(self):
        data, warns = parse_env_text("FOO=bar\nBAZ=123\n")
        self.assertEqual(data, {"FOO": "bar", "BAZ": "123"})
        self.assertEqual(warns, [])

    def test_export_prefix_and_spaces(self):
        data, _ = parse_env_text("export API_URL = https://example.com\n")
        self.assertEqual(data["API_URL"], "https://example.com")

    def test_comments_and_blank_lines(self):
        data, warns = parse_env_text("\n# comment\n  # indented\nKEY=val\n")
        self.assertEqual(data, {"KEY": "val"})
        self.assertEqual(warns, [])

    def test_inline_comment_unquoted(self):
        self.assertEqual(strip_inline_comment("hello # comment"), "hello")

    def test_inline_comment_inside_quotes_preserved(self):
        self.assertEqual(strip_inline_comment('"hello # world" # trailing'), '"hello # world"')

    def test_unquote_double_and_single(self):
        self.assertEqual(unquote_value('"abc\\ndef"'), "abc\ndef")
        self.assertEqual(unquote_value("'abc\\ndef'"), "abc\\ndef")

    def test_malformed_and_duplicate_warnings(self):
        data, warns = parse_env_text("BAD_LINE\nA=1\nA=2\n")
        self.assertEqual(data["A"], "2")
        self.assertEqual(len(warns), 2)


class TestEntropyAndSecrets(unittest.TestCase):
    def test_shannon_entropy_empty(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_shannon_entropy_uniform_vs_random(self):
        low = shannon_entropy("aaaaaaaaaaaaaaaaaaaa")
        high = shannon_entropy("aB3$kL9!mN2@pQ7#rT5^")
        self.assertLess(low, 0.1)
        self.assertGreater(high, 4.0)

    def test_redact_secret_long(self):
        self.assertEqual(redact_secret("AKIA1234567890ABCDEF"), "AKIA****CDEF")

    def test_redact_secret_short(self):
        self.assertEqual(redact_secret("short"), "*****")

    def test_is_placeholder(self):
        self.assertTrue(is_placeholder("<CHANGE_ME>"))
        self.assertTrue(is_placeholder("EXAMPLE_ONLY_TOKEN"))
        self.assertFalse(is_placeholder("x9K2mP7qR4tV8wZ1yB5n"))

    def test_detect_aws_key(self):
        res = detect_secret("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
        self.assertIsNotNone(res)
        self.assertEqual(res["reason"], "pattern:aws_access_key")

    def test_detect_stripe_key(self):
        res = detect_secret("STRIPE_KEY", "sk_live_51H8xYzAbCdEfGhIjKlMnOp")
        self.assertIsNotNone(res)
        self.assertEqual(res["reason"], "pattern:stripe_key")

    def test_detect_github_token(self):
        res = detect_secret("GH_TOKEN", "ghp_1234567890abcdefghijklmnopqrstuv")
        self.assertIsNotNone(res)
        self.assertEqual(res["reason"], "pattern:github_token")

    def test_detect_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        res = detect_secret("AUTH_JWT", jwt)
        self.assertIsNotNone(res)
        self.assertEqual(res["reason"], "pattern:jwt_token")

    def test_detect_private_key(self):
        res = detect_secret("SSH_KEY", "-----BEGIN OPENSSH PRIVATE KEY-----")
        self.assertIsNotNone(res)
        self.assertEqual(res["reason"], "pattern:private_key")

    def test_detect_db_url_with_creds(self):
        res = detect_secret("DATABASE_URL", "postgres://admin:s3cr3tpass@db.prod.local:5432/app")
        self.assertIsNotNone(res)
        self.assertEqual(res["reason"], "pattern:db_url_with_creds")

    def test_detect_high_entropy_generic(self):
        res = detect_secret("SIGNING_SECRET", "aB3$kL9!mN2@pQ7#rT5^vX8&")
        self.assertIsNotNone(res)
        self.assertEqual(res["reason"], "high_entropy")

    def test_ignore_normal_config_value(self):
        self.assertIsNone(detect_secret("APP_NAME", "billing-api"))


class TestAuditorAndCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write_env(self, name: str, content: str) -> Path:
        p = self.root / name
        p.write_text(content, encoding="utf-8")
        return p

    def test_clean_audit_exit_0(self):
        dev = self._write_env(".env.dev", "APP=web\nPORT=8000\n")
        prod = self._write_env(".env.prod", "APP=web\nPORT=8080\n")
        report = audit_environments({"dev": dev, "prod": prod})
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["status"], "CLEAN")

    def test_missing_key_drift_exit_1(self):
        dev = self._write_env(".env.dev", "APP=web\nEXTRA_FLAG=1\n")
        prod = self._write_env(".env.prod", "APP=web\n")
        report = audit_environments({"dev": dev, "prod": prod})
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["missing_keys"]["prod"], ["EXTRA_FLAG"])

    def test_unsafe_prod_flag_exit_1(self):
        prod = self._write_env(".env.prod", "DEBUG=true\nNODE_ENV=development\n")
        report = audit_environments({"prod": prod})
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(len(report["unsafe_prod_flags"]), 2)

    def test_secret_leak_exit_2(self):
        prod = self._write_env(".env.prod", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
        report = audit_environments({"prod": prod})
        self.assertEqual(report["exit_code"], 2)
        self.assertEqual(report["status"], "SECRET_LEAKS_DETECTED")

    def test_generate_env_example(self):
        dev = self._write_env(".env.dev", "B_KEY=1\nA_KEY=2\n")
        tpl = generate_env_example({"dev": dev})
        self.assertIn("A_KEY=<CHANGE_ME>", tpl)
        self.assertIn("B_KEY=<CHANGE_ME>", tpl)

    def test_json_and_markdown_formatters(self):
        dev = self._write_env(".env.dev", "APP=web\n")
        report = audit_environments({"dev": dev})
        parsed_json = json.loads(format_json_report(report))
        self.assertEqual(parsed_json["status"], "CLEAN")
        md = format_markdown_report(report)
        self.assertIn("# Env Drift & Secrets Audit: `CLEAN`", md)

    def test_cli_parse_env_specs(self):
        specs = parse_env_specs(["dev=.env.dev", ".env.prod"])
        self.assertEqual(specs["dev"], Path(".env.dev"))
        self.assertEqual(specs[".env.prod"], Path(".env.prod"))

    def test_cli_audit_and_template_end_to_end(self):
        dev = self._write_env(".env.dev", "APP=web\n")
        out_tpl = self.root / ".env.example"
        rc_tpl = main(["template", str(dev), "--output", str(out_tpl)])
        self.assertEqual(rc_tpl, 0)
        self.assertIn("APP=<CHANGE_ME>", out_tpl.read_text(encoding="utf-8"))

        rc_audit = main(["audit", f"dev={dev}", "--format", "json"])
        self.assertEqual(rc_audit, 0)


if __name__ == "__main__":
    unittest.main()
