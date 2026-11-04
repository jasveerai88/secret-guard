#!/usr/bin/env python3
"""Tests for secret-guard. Stdlib unittest only, temp dirs
only.

Run from the pack root:
    python3 -m unittest discover -s tests -v

Every expected finding below was worked out by hand from
the documented RULES (see README), never copied from the
tool's own output.

Hand-computed expectation for the in-test leaky fixture
(build_leaky()):

    mcpServers.github.env.GITHUB_TOKEN
        = "ghp_FAKEtoken0123456789abcd" (27 chars)
        key word "token" -> INLINE-SECRET, gh…(27 chars),
        env var GITHUB_TOKEN
    mcpServers.weather.env.SERVICE_KEY
        = "Q7f9Kd2Lm8Zx4Vb6N1pRs3Tg" (24 chars)
        generic key, but an env-block value spanning
        upper+lower+digit -> ENV-LITERAL, Q7…(24 chars),
        env var SERVICE_KEY
    apiKey = "sk-FAKE-0123456789abcdef" (24 chars)
        word pair api+key -> INLINE-SECRET, sk…(24 chars),
        env var API_KEY

    TOTAL: 3 findings = 2 INLINE-SECRET + 1 ENV-LITERAL;
    scan exits 1; fix points them at ${GITHUB_TOKEN},
    ${SERVICE_KEY}, ${API_KEY}.

The bundled samples (examples/make_sample.py) add:
mcp-config.json — the same 3 findings plus non-findings
(a URL, a short low-entropy env value, an existing
${...} reference); .vscode/mcp.json — 1 INLINE-SECRET
whose fix uses VS Code syntax ${env:GITHUB_TOKEN};
clean-config.json — 0 findings, exit 0.

Safety expectations: no run — scan, fix dry-run, fix
--apply, text or --json — ever prints a full secret value
(checked with a distinctive planted string across every
mode); a fix --apply backup holds the original file
byte-for-byte; a scan of a fixed file is CLEAN.
"""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACK_ROOT = Path(__file__).resolve().parent.parent
SRC = PACK_ROOT / "src"
EXAMPLES = PACK_ROOT / "examples"
sys.path.insert(0, str(SRC))

import secret_guard  # noqa: E402

DISTINCTIVE = "sk-DISTINCTIVEz9y8x7w6v5"          # 24 chars
DISTINCTIVE_ENV = "DISTINCTIVEenvvalue0123456789AB"  # 31


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def write(d, rel, text):
    p = Path(d) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def write_json(d, rel, obj):
    return write(d, rel, json.dumps(obj, indent=2) + "\n")


def run_cli(*args):
    """Run the CLI as a subprocess; (exit, stdout, stderr)."""
    proc = subprocess.run(
        [sys.executable, str(SRC / "secret_guard.py"), *args],
        capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def scan_json(*paths):
    code, out, _ = run_cli("scan", *paths, "--json")
    return code, json.loads(out)


def fix_json(*args):
    code, out, _ = run_cli("fix", *args, "--json")
    return code, json.loads(out)


def file_entry(data, index=0):
    return data["files"][index]


def findings_of(data, index=0):
    return file_entry(data, index)["findings"]


def backups_under(d):
    return sorted(Path(d).rglob("*.secret-guard-backup-*"))


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def build_leaky(d, name="config.json"):
    return write_json(d, name, {
        "mcpServers": {
            "github": {"command": "npx",
                       "env": {"GITHUB_TOKEN":
                               "ghp_FAKEtoken0123456789abcd"}},
            "weather": {"command": "python3",
                        "env": {"SERVICE_KEY":
                                "Q7f9Kd2Lm8Zx4Vb6N1pRs3Tg"}},
        },
        "apiKey": "sk-FAKE-0123456789abcdef",
    })


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()


# --------------------------------------------------------------------------
# Bundled samples
# --------------------------------------------------------------------------

class TestBundledSamples(TempDirCase):
    def setUp(self):
        super().setUp()
        self.target = self.d / "samples"
        proc = subprocess.run(
            [sys.executable, str(EXAMPLES / "make_sample.py"),
             str(self.target)],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_make_sample_creates_three_files(self):
        self.assertTrue((self.target / "mcp-config.json").is_file())
        self.assertTrue(
            (self.target / ".vscode" / "mcp.json").is_file())
        self.assertTrue(
            (self.target / "clean-config.json").is_file())

    def test_leaky_sample_exact_findings(self):
        code, data = scan_json(str(self.target / "mcp-config.json"))
        self.assertEqual(code, 1)
        self.assertEqual(data["summary"],
                         {"files": 1, "total": 3,
                          "inline_secret": 2, "env_literal": 1,
                          "unparseable": 0})
        got = [(f["path"], f["rule"], f["fingerprint"],
                f["env_var"]) for f in findings_of(data)]
        self.assertEqual(got, [
            ("mcpServers.github.env.GITHUB_TOKEN",
             "inline-secret", "gh…(27 chars)", "GITHUB_TOKEN"),
            ("mcpServers.weather.env.SERVICE_KEY",
             "env-literal", "Q7…(24 chars)", "SERVICE_KEY"),
            ("apiKey", "inline-secret", "sk…(24 chars)",
             "API_KEY"),
        ])
        self.assertFalse(data["clean"])

    def test_clean_sample_is_clean(self):
        code, data = scan_json(
            str(self.target / "clean-config.json"))
        self.assertEqual(code, 0)
        self.assertTrue(data["clean"])
        self.assertEqual(findings_of(data), [])

    def test_vscode_sample_one_finding_vscode_ref(self):
        p = self.target / ".vscode" / "mcp.json"
        code, data = scan_json(str(p))
        self.assertEqual(code, 1)
        got = findings_of(data)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["path"],
                         "servers.github.env.GITHUB_TOKEN")
        self.assertEqual(got[0]["fingerprint"],
                         "gh…(28 chars)")
        code, data = fix_json(str(p))
        self.assertEqual(code, 1)
        change = file_entry(data)["changes"][0]
        self.assertEqual(change["ref"], "${env:GITHUB_TOKEN}")

    def test_all_samples_together(self):
        code, data = scan_json(
            str(self.target / "mcp-config.json"),
            str(self.target / ".vscode" / "mcp.json"),
            str(self.target / "clean-config.json"))
        self.assertEqual(code, 1)
        self.assertEqual(data["summary"]["files"], 3)
        self.assertEqual(data["summary"]["total"], 4)


# --------------------------------------------------------------------------
# Detection rules
# --------------------------------------------------------------------------

class TestDetection(TempDirCase):
    def scan_one(self, obj):
        p = write_json(self.d, "c.json", obj)
        return scan_json(str(p))

    def test_in_test_leaky_fixture(self):
        p = build_leaky(self.d)
        code, data = scan_json(str(p))
        self.assertEqual(code, 1)
        got = [(f["path"], f["verdict"]) for f in findings_of(data)]
        self.assertEqual(got, [
            ("mcpServers.github.env.GITHUB_TOKEN",
             "INLINE-SECRET"),
            ("mcpServers.weather.env.SERVICE_KEY",
             "ENV-LITERAL"),
            ("apiKey", "INLINE-SECRET"),
        ])

    def test_secret_key_name_variants(self):
        for key in ("OPENAI_API_KEY", "clientSecret",
                    "access_key", "privateKey", "db_password",
                    "Authorization", "AUTH_TOKEN", "apikey",
                    "api_key", "myBearer", "passwd"):
            with self.subTest(key=key):
                code, data = self.scan_one(
                    {key: "some-literal-value-123"})
                self.assertEqual(code, 1)
                self.assertEqual(
                    findings_of(data)[0]["rule"],
                    "inline-secret")

    def test_env_known_prefix_generic_key(self):
        code, data = self.scan_one(
            {"env": {"KEY": "sk-abc12345"}})
        self.assertEqual(code, 1)
        self.assertEqual(findings_of(data)[0]["rule"],
                         "env-literal")

    def test_env_pem_header_generic_key(self):
        code, data = self.scan_one(
            {"env": {"CERT": "-----BEGIN PRIVATE KEY-----"}})
        self.assertEqual(code, 1)
        self.assertEqual(findings_of(data)[0]["rule"],
                         "env-literal")

    def test_secret_inside_list_of_objects(self):
        code, data = self.scan_one(
            {"servers": [{"env": {"API_KEY":
                                  "sk-FAKE-list-0123456"}}]})
        self.assertEqual(code, 1)
        self.assertEqual(findings_of(data)[0]["path"],
                         "servers[0].env.API_KEY")

    def test_secret_key_wins_over_env_rule(self):
        # A secret-NAMED key inside an env block is reported
        # once, as inline-secret — never twice.
        code, data = self.scan_one(
            {"env": {"API_KEY": "Q7f9Kd2Lm8Zx4Vb6N1pRs3Tg"}})
        self.assertEqual(code, 1)
        self.assertEqual(len(findings_of(data)), 1)
        self.assertEqual(findings_of(data)[0]["rule"],
                         "inline-secret")

    def test_fingerprint_short_value(self):
        self.assertEqual(secret_guard.fingerprint("abcdef"),
                         "a…(6 chars)")
        self.assertEqual(
            secret_guard.fingerprint("abcdefgh"),
            "ab…(8 chars)")


class TestNeverFlagged(TempDirCase):
    def assert_clean(self, obj):
        p = write_json(self.d, "c.json", obj)
        code, data = scan_json(str(p))
        self.assertEqual(code, 0, data)
        self.assertEqual(findings_of(data), [])

    def test_env_reference_forms(self):
        for ref in ("${MY_TOKEN}", "${env:MY_TOKEN}", "$MY_TOKEN",
                    "env:MY_TOKEN", "%MY_TOKEN%",
                    "${MY_TOKEN:-fallback}"):
            with self.subTest(ref=ref):
                self.assert_clean({"api_token": ref})

    def test_placeholders(self):
        for val in ("your-key-here", "your_api_key",
                    "changeme", "<paste-your-key>", "xxxxxx",
                    "your secret phrase here", "redacted"):
            with self.subTest(val=val):
                self.assert_clean({"password": val})

    def test_empty_and_whitespace(self):
        self.assert_clean({"api_key": ""})
        self.assert_clean({"api_key": "   "})

    def test_all_digit_value_is_an_id(self):
        self.assert_clean({"token": "123456789012"})

    def test_short_value(self):
        self.assert_clean({"password": "abc12"})

    def test_url_value(self):
        self.assert_clean(
            {"auth": "https://auth.example.invalid/endpoint"})

    def test_author_is_not_auth(self):
        self.assert_clean({"author": "Some Person Name"})

    def test_tokenizer_is_not_token(self):
        self.assert_clean(
            {"tokenizer": "some-long-value-here"})

    def test_api_key_helper_is_a_command(self):
        self.assert_clean(
            {"apiKeyHelper": "/usr/local/bin/get-key.sh --all"})

    def test_high_entropy_outside_env_not_flagged(self):
        self.assert_clean(
            {"sessionId": "Q7f9Kd2Lm8Zx4Vb6N1pRs3Tg"})

    def test_low_entropy_env_values(self):
        self.assert_clean({"env": {"UNITS": "metric",
                                   "REGION": "ca-central-1"}})

    def test_long_plain_sentence_in_env(self):
        self.assert_clean(
            {"env": {"BANNER": "THIS IS A VERY LONG BANNER"}})

    def test_non_string_values(self):
        self.assert_clean({"api_key": 123456789,
                           "token": True, "secret": None,
                           "password": {"nested": "x"}})

    def test_bare_strings_in_lists(self):
        self.assert_clean(
            {"args": ["sk-FAKE-bare-0123456789"]})


# --------------------------------------------------------------------------
# Parser edges and unparseable files
# --------------------------------------------------------------------------

class TestParserEdges(TempDirCase):
    def test_jsonc_comments_and_trailing_comma(self):
        p = write(self.d, "c.json",
                  '// a comment\n{\n  "api_key": '
                  '"sk-FAKE-jsonc-012345", /* block */\n}\n')
        code, data = scan_json(str(p))
        self.assertEqual(code, 1)
        self.assertEqual(findings_of(data)[0]["path"],
                         "api_key")

    def test_double_slash_inside_string_is_data(self):
        obj, err = secret_guard.parse_lenient(
            '{"u": "https://a.invalid//b", "n": 1}')
        self.assertIsNone(err)
        self.assertEqual(obj["u"], "https://a.invalid//b")

    def test_bom_tolerated(self):
        p = Path(self.d) / "c.json"
        p.write_bytes(
            b'\xef\xbb\xbf{"api_key": "sk-FAKE-bom-0123456"}')
        code, data = scan_json(str(p))
        self.assertEqual(code, 1)

    def test_malformed_json_is_unparseable_finding(self):
        p = write(self.d, "c.json", '{ "api_key": [ nope')
        code, out, err = run_cli("scan", str(p), "--json")
        self.assertEqual(code, 1)
        self.assertNotIn("Traceback", err)
        data = json.loads(out)
        f = findings_of(data)[0]
        self.assertEqual(f["rule"], "unparseable")
        self.assertEqual(f["verdict"], "UNPARSEABLE")
        self.assertIsNone(f["path"])

    def test_non_object_roots_are_unparseable(self):
        for text in ('[1, 2, 3]', '"just a string"', '42'):
            with self.subTest(text=text):
                p = write(self.d, "c.json", text)
                code, data = scan_json(str(p))
                self.assertEqual(code, 1)
                self.assertEqual(findings_of(data)[0]["rule"],
                                 "unparseable")

    def test_invalid_utf8_is_unparseable(self):
        p = Path(self.d) / "c.json"
        p.write_bytes(b'{"api_key": "\xff\xfe"}')
        code, data = scan_json(str(p))
        self.assertEqual(code, 1)
        self.assertEqual(findings_of(data)[0]["rule"],
                         "unparseable")

    def test_unparseable_only_verdict_text(self):
        # With nothing fixable found, the closing text must
        # say "could not be checked" — not "move each
        # value", since there is no value to move.
        p = write(self.d, "c.json", "{ broken")
        code, out, _ = run_cli("scan", str(p))
        self.assertEqual(code, 1)
        self.assertIn("VERDICT: UNPARSEABLE", out)
        self.assertNotIn("move each value", out)


# --------------------------------------------------------------------------
# Input errors — clean, exit 2, never a traceback
# --------------------------------------------------------------------------

class TestInputErrors(TempDirCase):
    def test_missing_file_json_mode(self):
        code, out, err = run_cli(
            "scan", str(self.d / "nope.json"), "--json")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out),
                         {"error": f"no such file: "
                                   f"{self.d / 'nope.json'}"})
        self.assertNotIn("Traceback", err)

    def test_missing_file_text_mode(self):
        code, out, err = run_cli(
            "scan", str(self.d / "nope.json"))
        self.assertEqual(code, 2)
        self.assertTrue(out.startswith("ERROR: no such file:"))
        self.assertNotIn("Traceback", err)

    def test_directory_is_an_error(self):
        code, out, _ = run_cli("scan", str(self.d), "--json")
        self.assertEqual(code, 2)
        self.assertIn("error", json.loads(out))

    def test_one_bad_path_fails_the_run(self):
        good = build_leaky(self.d)
        code, out, _ = run_cli(
            "scan", str(good), str(self.d / "nope.json"),
            "--json")
        self.assertEqual(code, 2)
        self.assertIn("error", json.loads(out))

    def test_no_paths_json_mode(self):
        code, out, err = run_cli("scan", "--json")
        self.assertEqual(code, 2)
        self.assertIn("error", json.loads(out))
        self.assertNotIn("Traceback", err)

    def test_no_subcommand(self):
        code, _, err = run_cli()
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", err)

    def test_unknown_flag_json_mode(self):
        code, out, err = run_cli("scan", "x", "--bogus",
                                 "--json")
        self.assertEqual(code, 2)
        self.assertIn("error", json.loads(out))
        self.assertNotIn("Traceback", err)

    def test_duplicate_paths_deduped(self):
        p = build_leaky(self.d)
        code, data = scan_json(str(p), str(p))
        self.assertEqual(code, 1)
        self.assertEqual(data["summary"]["files"], 1)


# --------------------------------------------------------------------------
# Fix
# --------------------------------------------------------------------------

class TestFix(TempDirCase):
    def test_dry_run_writes_nothing(self):
        p = build_leaky(self.d)
        before = sha(p)
        code, data = fix_json(str(p))
        self.assertEqual(code, 1)
        self.assertFalse(data["apply"])
        entry = file_entry(data)
        self.assertEqual(entry["status"], "pending")
        self.assertEqual(len(entry["changes"]), 3)
        self.assertIsNone(entry["backup"])
        self.assertEqual(sha(p), before)
        self.assertEqual(backups_under(self.d), [])
        self.assertEqual(
            [e["name"] for e in data["env_vars"]],
            ["GITHUB_TOKEN", "SERVICE_KEY", "API_KEY"])
        self.assertFalse(data["clean"])

    def test_dry_run_change_refs(self):
        p = build_leaky(self.d)
        _, data = fix_json(str(p))
        refs = {c["path"]: c["ref"]
                for c in file_entry(data)["changes"]}
        self.assertEqual(refs, {
            "mcpServers.github.env.GITHUB_TOKEN":
                "${GITHUB_TOKEN}",
            "mcpServers.weather.env.SERVICE_KEY":
                "${SERVICE_KEY}",
            "apiKey": "${API_KEY}",
        })

    def test_apply_round_trip(self):
        p = build_leaky(self.d)
        original_bytes = p.read_bytes()
        code, data = fix_json(str(p), "--apply")
        self.assertEqual(code, 0)
        self.assertTrue(data["clean"])
        entry = file_entry(data)
        self.assertEqual(entry["status"], "fixed")
        # Backup holds the original byte-for-byte.
        backups = backups_under(self.d)
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(),
                         original_bytes)
        self.assertEqual(entry["backup"], str(backups[0]))
        # Rewritten file: refs in place, everything else
        # preserved.
        after = json.loads(p.read_text(encoding="utf-8"))
        self.assertEqual(
            after["mcpServers"]["github"]["env"]
                 ["GITHUB_TOKEN"], "${GITHUB_TOKEN}")
        self.assertEqual(
            after["mcpServers"]["weather"]["env"]
                 ["SERVICE_KEY"], "${SERVICE_KEY}")
        self.assertEqual(after["apiKey"], "${API_KEY}")
        self.assertEqual(after["mcpServers"]["github"]
                         ["command"], "npx")
        # Scan after fix is clean.
        code, data = scan_json(str(p))
        self.assertEqual(code, 0)
        self.assertTrue(data["clean"])

    def test_second_apply_is_a_noop(self):
        p = build_leaky(self.d)
        fix_json(str(p), "--apply")
        code, data = fix_json(str(p), "--apply")
        self.assertEqual(code, 0)
        self.assertEqual(file_entry(data)["status"], "clean")
        self.assertEqual(file_entry(data)["changes"], [])
        self.assertEqual(len(backups_under(self.d)), 1)

    def test_fix_clean_file(self):
        p = write_json(self.d, "c.json",
                       {"api_key": "${API_KEY}"})
        before = sha(p)
        code, data = fix_json(str(p), "--apply")
        self.assertEqual(code, 0)
        self.assertEqual(file_entry(data)["status"], "clean")
        self.assertEqual(sha(p), before)
        self.assertEqual(backups_under(self.d), [])

    def test_apply_on_clean_file_header_says_no_change(self):
        p = write_json(self.d, "c.json",
                       {"api_key": "${API_KEY}"})
        code, out, _ = run_cli("fix", str(p), "--apply")
        self.assertEqual(code, 0)
        self.assertIn("APPLY — nothing to change", out)

    def test_fix_unparseable_file(self):
        p = write(self.d, "c.json", "{ broken")
        before = sha(p)
        code, data = fix_json(str(p), "--apply")
        self.assertEqual(code, 1)
        self.assertEqual(file_entry(data)["status"],
                         "unparseable")
        self.assertEqual(sha(p), before)
        self.assertEqual(backups_under(self.d), [])

    def test_fix_mixed_files_backup_only_for_changed(self):
        leaky = build_leaky(self.d, "leaky.json")
        clean = write_json(self.d, "clean.json",
                           {"api_key": "${API_KEY}"})
        code, data = fix_json(str(leaky), str(clean),
                              "--apply")
        self.assertEqual(code, 0)
        self.assertEqual(len(backups_under(self.d)), 1)
        statuses = {e["file"]: e["status"]
                    for e in data["files"]}
        self.assertEqual(statuses[str(leaky)], "fixed")
        self.assertEqual(statuses[str(clean)], "clean")

    def test_env_name_collision_uses_ancestor(self):
        p = write_json(self.d, "c.json", {
            "mcpServers": {
                "alpha": {"env": {"API_KEY":
                                   "sk-FAKE-alpha-0123456789"}},
                "beta": {"env": {"API_KEY":
                                  "sk-FAKE-beta-01234567890"}},
            }})
        code, data = fix_json(str(p), "--apply")
        self.assertEqual(code, 0)
        after = json.loads(p.read_text(encoding="utf-8"))
        self.assertEqual(after["mcpServers"]["alpha"]["env"]
                         ["API_KEY"], "${API_KEY}")
        self.assertEqual(after["mcpServers"]["beta"]["env"]
                         ["API_KEY"], "${BETA_API_KEY}")

    def test_same_value_reuses_one_env_var(self):
        p = write_json(self.d, "c.json", {
            "mcpServers": {
                "alpha": {"env": {"API_KEY":
                                   "sk-FAKE-same-0123456789"}},
                "beta": {"env": {"API_KEY":
                                  "sk-FAKE-same-0123456789"}},
            }})
        code, data = fix_json(str(p), "--apply")
        self.assertEqual(code, 0)
        after = json.loads(p.read_text(encoding="utf-8"))
        self.assertEqual(after["mcpServers"]["beta"]["env"]
                         ["API_KEY"], "${API_KEY}")
        names = [e["name"] for e in data["env_vars"]]
        self.assertEqual(names, ["API_KEY", "API_KEY"])

    def test_rewrite_drops_comments_backup_keeps_them(self):
        p = write(self.d, "c.json",
                  '// keep me in the backup\n'
                  '{"api_key": "sk-FAKE-jsonc-012345"}\n')
        code, _ = fix_json(str(p), "--apply")
        self.assertEqual(code, 0)
        self.assertNotIn("// keep me",
                         p.read_text(encoding="utf-8"))
        backup = backups_under(self.d)[0]
        self.assertIn("// keep me in the backup",
                      backup.read_text(encoding="utf-8"))
        code, data = scan_json(str(p))
        self.assertEqual(code, 0)

    def test_env_name_derivation(self):
        cases = {"apiKey": "API_KEY",
                 "clientSecret": "CLIENT_SECRET",
                 "GITHUB_TOKEN": "GITHUB_TOKEN",
                 "my-custom.token": "MY_CUSTOM_TOKEN"}
        for key, expected in cases.items():
            with self.subTest(key=key):
                self.assertEqual(
                    secret_guard._env_base_name(key), expected)


# --------------------------------------------------------------------------
# The core promise: a secret value is NEVER printed
# --------------------------------------------------------------------------

class TestSecretNeverPrinted(TempDirCase):
    def fixture(self):
        return write_json(self.d, "c.json", {
            "api_key": DISTINCTIVE,
            "env": {"GENERIC": DISTINCTIVE_ENV},
        })

    def test_no_mode_prints_a_secret(self):
        p = self.fixture()
        outputs = []
        for args in (("scan", str(p)), ("scan", str(p), "--json"),
                     ("fix", str(p)), ("fix", str(p), "--json")):
            _, out, err = run_cli(*args)
            outputs.append(out + err)
        # --apply runs last (it changes the file) — on both
        # a text and a JSON invocation, using fresh copies.
        for extra in ((), ("--json",)):
            q = self.fixture_copy()
            _, out, err = run_cli("fix", str(q), "--apply",
                                  *extra)
            outputs.append(out + err)
            _, out, err = run_cli("scan", str(q))
            outputs.append(out + err)
        blob = "\n".join(outputs)
        self.assertNotIn(DISTINCTIVE, blob)
        self.assertNotIn(DISTINCTIVE_ENV, blob)
        self.assertIn("sk…(24 chars)", blob)
        self.assertIn("DI…(31 chars)", blob)

    def fixture_copy(self):
        import shutil
        src = self.d / "c.json"
        dst = self.d / f"copy-{len(list(self.d.glob('copy-*')))}.json"
        shutil.copyfile(src, dst)
        return dst

    def test_rewritten_file_holds_no_secret_backup_does(self):
        p = self.fixture()
        code, _ = fix_json(str(p), "--apply")
        self.assertEqual(code, 0)
        self.assertNotIn(DISTINCTIVE,
                         p.read_text(encoding="utf-8"))
        backup = backups_under(self.d)[0]
        self.assertIn(DISTINCTIVE,
                      backup.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# JSON shape
# --------------------------------------------------------------------------

class TestJsonShape(TempDirCase):
    def test_scan_shape(self):
        p = build_leaky(self.d)
        _, data = scan_json(str(p))
        self.assertEqual(data["tool"], "secret-guard")
        self.assertEqual(data["version"], "0.1.0")
        self.assertEqual(data["command"], "scan")
        entry = file_entry(data)
        self.assertEqual(entry["status"], "ok")
        self.assertFalse(entry["clean"])
        f = entry["findings"][0]
        self.assertEqual(
            set(f), {"rule", "verdict", "path", "key",
                     "fingerprint", "env_var", "detail"})

    def test_fix_shape(self):
        p = build_leaky(self.d)
        _, data = fix_json(str(p))
        self.assertEqual(data["command"], "fix")
        self.assertEqual(data["summary"],
                         {"files": 1, "changes": 3,
                          "changed_files": 1,
                          "unparseable": 0})
        change = file_entry(data)["changes"][0]
        self.assertEqual(
            set(change), {"path", "key", "env_var", "ref",
                          "fingerprint"})


if __name__ == "__main__":
    unittest.main()
