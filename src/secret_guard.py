#!/usr/bin/env python3
"""secret-guard — find inline secrets in AI-agent / MCP
config files, and FIX them: rewrite each literal secret
into an environment-variable reference, and print the list
of environment variables you now need to set.

Pure Python standard library. Local only: no network, no
uploads, no accounts. And careful with values in the
strongest sense: a secret's full value is NEVER printed —
not in text output, not in --json output, not in errors.
Reports show a key path and a masked fingerprint (first
characters + length) only.

Why this exists: GitGuardian's State of Secrets Sprawl
research found 24,008 unique secrets in public MCP
configuration files in 2025 — 2,117 of them valid. The
configs agents actually use — .mcp.json, Claude Code
settings, VS Code mcp.json, Cursor-style configs — are
JSON files full of "env" blocks, and the keys get pasted
in literally because that is the path of least resistance.
Scanners (gitleaks, ggshield) find them; almost nothing
rewrites them into the env references each client already
supports. That rewrite is this tool's whole job.

What is checked (and ONLY this — precision over recall; a
scanner that cries wolf on ordinary values gets ignored,
and then it protects nobody):

  Secret-named keys holding literal strings
      A key whose name contains a secret word — token,
      secret, password, passwd, auth, authorization,
      bearer, apikey, or the pairs api+key, private+key,
      access+key, client+secret (word-split on separators
      and camelCase, so "author" and "tokenizer" do NOT
      match) — and whose value is a literal string of 6+
      characters that is not an env reference, not an
      obvious placeholder, and not all digits.
      Rule: inline-secret.
  Env blocks
      A direct string child of any object stored under a
      key named "env" whose value looks like a secret
      whatever the key is called: either high-entropy
      (20+ chars spanning 3+ character classes) or
      carrying a known secret prefix (sk-, ghp_, github_
      pat_, xox[baprs]-, AKIA, AIza, a PEM header).
      Rule: env-literal.

Never flagged: values that are already environment
references (${VAR}, ${env:VAR}, $VAR, env:VAR, %VAR%),
empty strings, obvious placeholders ("your-key-here",
"changeme", "<paste-key>", "xxxx"), URLs (endpoints, not
secrets), all-digit values (IDs, not secrets), and the
Claude Code key "apiKeyHelper" — its value is a shell
command, not a secret. Values under ordinary keys outside
env blocks are not checked at all.

`fix` is a dry run unless --apply is given. Applying
writes a timestamped backup beside the original FIRST
(the original bytes, exactly), then rewrites the file as
clean JSON (indent 2) with each secret replaced by a
reference — ${VAR}, or ${env:VAR} for files under a
.vscode/ folder (VS Code's syntax). Comments and original
formatting are NOT preserved by a rewrite — the backup
is. After writing, the rewritten file is re-scanned in
memory and must come back clean before success is
reported. Fixing a clean file changes nothing and creates
no backup.

Config files in the wild are JSON-with-comments, so
parsing for scan (and for deciding what to fix) is
lenient: // and /* */ comments and trailing commas are
tolerated (string-aware — a // inside a URL string is NOT
a comment). A file that still cannot be parsed — or whose
top level is not a JSON object — is reported as an
UNPARSEABLE finding: it could not be checked, never a
crash, never a silent skip. TOML and YAML configs are not
parsed in v0.1.0.

Exit codes: scan — 0 = CLEAN (no findings) · 1 = FINDINGS
· 2 = ERROR. fix — 0 = nothing pending (already clean, or
--apply wrote and verified every change) · 1 = changes
pending (dry run) or a file could not be fixed
(unparseable) · 2 = ERROR — clean message, never a
traceback; with --json the error is {"error": ...}.
--json prints one JSON object with the same facts and
exit codes as the text view.
"""
import argparse
import copy
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path

__version__ = "0.1.0"
TOOL = "secret-guard"

INLINE_SECRET = "INLINE-SECRET"
ENV_LITERAL = "ENV-LITERAL"
UNPARSEABLE = "UNPARSEABLE"
_VERDICT_ORDER = [INLINE_SECRET, ENV_LITERAL, UNPARSEABLE]

_GROUP_HEADERS = {
    INLINE_SECRET: "INLINE-SECRET — a literal secret "
                   "stored under a secret-named key",
    ENV_LITERAL: "ENV-LITERAL — a secret-shaped literal "
                 "in an env block, whatever the key is "
                 "named",
    UNPARSEABLE: "UNPARSEABLE — could not be parsed, so "
                 "its contents could not be checked",
}

MIN_SECRET_LEN = 6


class ToolError(Exception):
    """A clean, user-facing failure (printed as ERROR, exit 2)."""


# --------------------------------------------------------------------------
# Lenient JSON (JSONC): comments + trailing commas, string-aware
# --------------------------------------------------------------------------

def _strip_comments(text):
    """Remove // line and /* */ block comments, honouring
    string literals (a // inside a quoted URL is data)."""
    out = []
    i, n = 0, len(text)
    in_str = esc = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*"
                                     and text[i + 1] == "/"):
                i += 1
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _strip_trailing_commas(text):
    """Remove a comma whose next non-whitespace character is
    } or ], outside string literals."""
    out = []
    i, n = 0, len(text)
    in_str = esc = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def parse_lenient(text):
    """(obj, None) on success, (None, error message) on
    failure. Tries strict JSON first, then the JSONC-tolerant
    form (comments stripped, trailing commas stripped)."""
    text = text.lstrip("\ufeff")
    try:
        return json.loads(text), None
    except ValueError:
        pass
    try:
        return json.loads(
            _strip_trailing_commas(_strip_comments(text))), None
    except ValueError as exc:
        return None, f"could not be parsed as JSON: {exc}"


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

_WORD_RE = re.compile(
    r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z]+|[0-9]+")


def _words(key):
    """Split a key name into lowercase words, on
    non-alphanumerics and camelCase boundaries:
    'GITHUB_TOKEN' -> [github, token],
    'clientSecret' -> [client, secret],
    'author'       -> [author]  (NOT [auth, or])."""
    words = []
    for part in re.split(r"[^A-Za-z0-9]+", key):
        words.extend(_WORD_RE.findall(part))
    return [w.lower() for w in words if w]


_SECRET_WORDS = {"token", "secret", "password", "passwd",
                 "auth", "authorization", "bearer", "apikey"}
_SECRET_PAIRS = {("api", "key"), ("private", "key"),
                 ("access", "key"), ("client", "secret")}

# Keys whose value is a command or a path by design, never
# a secret — checked by exact (lowercased) name.
_NEVER_SECRET_KEYS = {"apikeyhelper"}


def _is_secret_key(key):
    if key.lower() in _NEVER_SECRET_KEYS:
        return False
    words = _words(key)
    if any(w in _SECRET_WORDS for w in words):
        return True
    return any(pair in zip(words, words[1:])
               for pair in _SECRET_PAIRS)


_PLACEHOLDER_EXACT = {
    "your-key-here", "your_api_key", "your-api-key",
    "your-token-here", "your_token_here",
    "your-password-here", "changeme", "change-me",
    "change_me", "placeholder", "example", "sample",
    "dummy", "fake", "test", "todo", "none", "null",
    "redacted", "insert-here", "insert-your-key-here",
}


def _is_exempt(value):
    """True when a string is NOT a literal secret: an env
    reference, an obvious placeholder, empty, or a URL."""
    s = value.strip()
    if not s:
        return True
    if s.startswith("${") and "}" in s:
        return True  # ${VAR}, ${env:VAR}, ${VAR:-default}
    if re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", s):
        return True  # $VAR
    if re.fullmatch(r"%[A-Za-z_][A-Za-z0-9_]*%", s):
        return True  # %VAR%
    if s.lower().startswith("env:"):
        return True  # env:VAR
    low = s.lower()
    if low in _PLACEHOLDER_EXACT:
        return True
    if s.startswith("<") and s.endswith(">"):
        return True  # <paste-your-key>
    if len(set(s)) == 1:
        return True  # xxxx, ****, ----
    if low.startswith(("your-", "your_", "your ")):
        return True
    if s.startswith(("http://", "https://")):
        return True  # an endpoint, not a secret
    return False


def _is_literal_secret(value):
    """Gate for secret-NAMED keys: a string of 6+ chars,
    not exempt, not all digits (digits are IDs)."""
    if not isinstance(value, str):
        return False
    s = value.strip()
    if len(s) < MIN_SECRET_LEN or s.isdigit():
        return False
    return not _is_exempt(s)


_KNOWN_PREFIXES = ("sk-ant-", "sk-proj-", "sk-", "ghp_",
                   "gho_", "ghu_", "ghs_", "ghr_",
                   "github_pat_", "xoxb-", "xoxa-",
                   "xoxp-", "xoxr-", "xoxs-", "AKIA",
                   "AIza", "-----BEGIN ")


def _looks_secret_shaped(value):
    """Gate for env blocks, whatever the key is named: a
    known secret prefix (10+ chars), or high entropy —
    20+ chars spanning 3+ character classes."""
    s = value.strip()
    if _is_exempt(s) or s.isdigit():
        return False
    if len(s) >= 10 and s.startswith(_KNOWN_PREFIXES):
        return True
    if len(s) < 20:
        return False
    classes = (any(c.islower() for c in s)
               + any(c.isupper() for c in s)
               + any(c.isdigit() for c in s)
               + any(not c.isalnum() for c in s))
    return classes >= 3


def fingerprint(value):
    """The ONLY form in which a secret may be shown: first
    characters + length. Never the value."""
    s = value.strip()
    shown = s[:2] if len(s) >= 8 else s[:1]
    return f"{shown}…({len(s)} chars)"


def _format_path(segments):
    out = ""
    for seg in segments:
        if isinstance(seg, int):
            out += f"[{seg}]"
        else:
            out += ("." if out else "") + seg
    return out


def _walk(node, segments, in_env, out):
    """Collect (segments, key, value) for every string value
    in the tree. in_env is true only for the direct children
    of a dict stored under a key named 'env'."""
    if isinstance(node, dict):
        for key, val in node.items():
            if isinstance(val, str):
                out.append((segments + [key], key, val,
                            in_env))
            else:
                _walk(val, segments + [key],
                      key.lower() == "env", out)
    elif isinstance(node, list):
        for i, val in enumerate(node):
            if isinstance(val, str):
                out.append((segments + [i], None, val, False))
            else:
                _walk(val, segments + [i], False, out)


def detect(data):
    """All findings in a parsed config object, in document
    order. Internal dicts carry the VALUE (needed to apply
    a fix and to dedupe env names); render code must go
    through _public_finding(), which drops it."""
    strings = []
    _walk(data, [], False, strings)
    findings = []
    for segments, key, value, in_env in strings:
        if key is None:
            continue  # a bare string in a list has no key
        path = _format_path(segments)
        if _is_secret_key(key) and _is_literal_secret(value):
            findings.append({
                "rule": "inline-secret",
                "verdict": INLINE_SECRET,
                "segments": segments, "path": path,
                "key": key, "value": value,
                "detail": "key name marks it as a secret "
                          "and the value is a literal "
                          "string, not a reference"})
        elif in_env and _looks_secret_shaped(value):
            findings.append({
                "rule": "env-literal",
                "verdict": ENV_LITERAL,
                "segments": segments, "path": path,
                "key": key, "value": value,
                "detail": "env block value is secret-shaped "
                          "(known prefix or high entropy) "
                          "whatever the key is named"})
    _assign_env_names(findings)
    return findings


def _env_base_name(key):
    name = "_".join(w.upper() for w in _words(key))
    if not name:
        name = "SECRET"
    if name[0].isdigit():
        name = "SECRET_" + name
    return name


def _ancestor_name(segments):
    """Nearest meaningful ancestor segment for disambigu-
    ating an env name: the segment before a trailing
    'env', else the immediate parent segment."""
    parents = [s for s in segments[:-1]
               if not isinstance(s, int)]
    if not parents:
        return None
    pick = parents[-1]
    if pick.lower() == "env" and len(parents) > 1:
        pick = parents[-2]
    name = "_".join(w.upper() for w in _words(pick))
    return name or None


def _assign_env_names(findings):
    """Give each fixable finding the env var name `fix`
    will use. Within one file: the same name + the same
    secret value reuses one variable; a name collision
    with a DIFFERENT value is disambiguated with the
    nearest ancestor segment, then a numeric suffix.
    Identity is compared by value hash — the hash is
    internal only and never printed."""
    used = {}
    for f in findings:
        digest = hashlib.sha256(
            f["value"].encode("utf-8")).hexdigest()
        base = _env_base_name(f["key"])
        candidate = base
        if candidate in used and used[candidate] != digest:
            ancestor = _ancestor_name(f["segments"])
            stem = (f"{ancestor}_{base}" if ancestor
                    else base)
            candidate = stem
            n = 2
            while (candidate in used
                   and used[candidate] != digest):
                candidate = f"{stem}_{n}"
                n += 1
        used[candidate] = digest
        f["env_var"] = candidate


def _public_finding(f):
    return {"rule": f["rule"], "verdict": f["verdict"],
            "path": f["path"], "key": f["key"],
            "fingerprint": fingerprint(f["value"]),
            "env_var": f["env_var"], "detail": f["detail"]}


def _unparseable_finding(detail):
    return {"rule": "unparseable", "verdict": UNPARSEABLE,
            "path": None, "key": None, "fingerprint": None,
            "env_var": None, "detail": detail}


# --------------------------------------------------------------------------
# File analysis
# --------------------------------------------------------------------------

def analyze_file(path):
    """One config file -> {file, status, findings (public),
    internal findings, data, raw bytes}. status is 'ok' or
    'unparseable'. Reads only."""
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return {"file": str(path), "status": "unparseable",
                "findings": [_unparseable_finding(
                    f"could not be read as UTF-8 text: "
                    f"{exc}")],
                "internal": [], "data": None, "raw": raw}
    data, err = parse_lenient(text)
    if data is None:
        return {"file": str(path), "status": "unparseable",
                "findings": [_unparseable_finding(err)],
                "internal": [], "data": None, "raw": raw}
    if not isinstance(data, dict):
        return {"file": str(path), "status": "unparseable",
                "findings": [_unparseable_finding(
                    "the top level is not a JSON object")],
                "internal": [], "data": None, "raw": raw}
    internal = detect(data)
    return {"file": str(path), "status": "ok",
            "findings": [_public_finding(f)
                         for f in internal],
            "internal": internal, "data": data, "raw": raw}


def _summary(results):
    findings = [f for r in results for f in r["findings"]]
    return {"files": len(results),
            "total": len(findings),
            "inline_secret": sum(
                1 for f in findings
                if f["verdict"] == INLINE_SECRET),
            "env_literal": sum(
                1 for f in findings
                if f["verdict"] == ENV_LITERAL),
            "unparseable": sum(
                1 for f in findings
                if f["verdict"] == UNPARSEABLE)}


def _require_files(raw_paths):
    """Validate CLI paths up front: every path must exist
    and be a file. Duplicates are dropped, order kept."""
    out, seen = [], set()
    for raw in raw_paths:
        p = Path(raw)
        if not p.exists():
            raise ToolError(f"no such file: {raw}")
        if p.is_dir():
            raise ToolError(
                f"not a file (it is a folder): {raw}")
        if not p.is_file():
            raise ToolError(f"not a file: {raw}")
        key = str(p)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def _load(path):
    try:
        return analyze_file(path)
    except OSError as exc:
        return {"file": str(path), "status": "unparseable",
                "findings": [_unparseable_finding(
                    f"could not be read: {exc}")],
                "internal": [], "data": None, "raw": b""}


# --------------------------------------------------------------------------
# Fix
# --------------------------------------------------------------------------

def _ref_for(path, env_name):
    """The reference syntax for this file's ecosystem:
    ${env:VAR} for files under a .vscode/ folder (VS Code's
    mcp.json syntax), ${VAR} everywhere else (Claude Code,
    Cursor and generic MCP configs)."""
    parts = {p.lower() for p in Path(path).parts}
    if ".vscode" in parts:
        return "${env:%s}" % env_name
    return "${%s}" % env_name


def _set_at(data, segments, value):
    node = data
    for seg in segments[:-1]:
        node = node[seg]
    node[segments[-1]] = value


def _backup_path(path):
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = Path(str(path) + f".secret-guard-backup-{ts}")
    candidate, n = base, 2
    while candidate.exists():
        candidate = Path(f"{base}-{n}")
        n += 1
    return candidate


def fix_result(result, apply):
    """One analyzed file -> a fix outcome dict:
    {file, status, changes (public), backup}.
    status: clean | unparseable | pending (dry run) |
    fixed (applied + verified). With apply=True this
    WRITES: backup first, then the rewritten file."""
    base = {"file": result["file"], "changes": [],
            "backup": None}
    if result["status"] == "unparseable":
        return {**base, "status": "unparseable"}
    changes = []
    for f in result["internal"]:
        ref = _ref_for(result["file"], f["env_var"])
        changes.append({"path": f["path"], "key": f["key"],
                        "env_var": f["env_var"], "ref": ref,
                        "fingerprint":
                            fingerprint(f["value"])})
    if not changes:
        return {**base, "status": "clean"}
    if not apply:
        return {**base, "status": "pending",
                "changes": changes}
    # Apply: rewrite a copy, verify it re-scans clean IN
    # MEMORY, and only then touch the disk — backup of the
    # original bytes first, the rewrite second.
    new_data = copy.deepcopy(result["data"])
    for f in result["internal"]:
        _set_at(new_data, f["segments"],
                _ref_for(result["file"], f["env_var"]))
    new_text = json.dumps(new_data, indent=2,
                          ensure_ascii=False) + "\n"
    reparsed, err = parse_lenient(new_text)
    if reparsed is None or detect(reparsed):
        raise ToolError(
            f"internal error: the rewrite of "
            f"{result['file']} did not verify clean; "
            f"nothing was written")
    backup = _backup_path(Path(result["file"]))
    try:
        backup.write_bytes(result["raw"])
    except OSError as exc:
        raise ToolError(
            f"could not write the backup {backup}: {exc}; "
            f"{result['file']} was NOT modified")
    try:
        Path(result["file"]).write_text(new_text,
                                         encoding="utf-8")
    except OSError as exc:
        raise ToolError(
            f"could not write {result['file']}: {exc}; "
            f"the original bytes are in the backup "
            f"{backup}")
    return {**base, "status": "fixed", "changes": changes,
            "backup": str(backup)}


def _env_var_list(outcomes):
    out, seen = [], set()
    for o in outcomes:
        for c in o["changes"]:
            key = (c["env_var"], o["file"], c["path"])
            if key not in seen:
                seen.add(key)
                out.append({"name": c["env_var"],
                            "file": o["file"],
                            "path": c["path"]})
    return out


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

class _JsonAwareParser(argparse.ArgumentParser):
    """ArgumentParser that reports usage errors as JSON in
    --json mode ({"error": ...} on stdout, same exit code 2)
    — an agent driving this tool with --json never gets
    plain text or a traceback. The flag lives on the class
    so subparsers share it."""

    json_mode = False

    def error(self, message):
        if self.json_mode:
            print(json.dumps({"error": message}))
            self.exit(2)
        super().error(message)


def cmd_scan(a):
    paths = _require_files(a.paths)
    results = [_load(p) for p in paths]
    s = _summary(results)
    clean = s["total"] == 0
    if a.json:
        print(json.dumps(
            {"tool": TOOL, "version": __version__,
             "command": "scan",
             "files": [{"file": r["file"],
                        "status": r["status"],
                        "findings": r["findings"],
                        "clean": not r["findings"]}
                       for r in results],
             "summary": s, "clean": clean}, indent=2))
        return 0 if clean else 1
    print(f"{TOOL} v{__version__} — scan · "
          f"{s['files']} file(s)")
    print(f"{s['total']} finding(s) — "
          f"{s['inline_secret']} INLINE-SECRET · "
          f"{s['env_literal']} ENV-LITERAL · "
          f"{s['unparseable']} UNPARSEABLE")
    if clean:
        print()
        print("CLEAN — none of the patterns secret-guard "
              "checks were found: no secret-named key holds "
              "a literal value, and no env block holds a "
              "secret-shaped literal.")
        print("CLEAN never means \"this config is safe\". "
              "Values under ordinary key names outside env "
              "blocks are not checked, TOML/YAML configs "
              "are not parsed, and a secret that was ever "
              "committed or shared stays leaked even after "
              "it is moved — rotate it.")
        return 0
    all_findings = [(r["file"], f) for r in results
                    for f in r["findings"]]
    for verdict in _VERDICT_ORDER:
        group = [(file, f) for file, f in all_findings
                 if f["verdict"] == verdict]
        if not group:
            continue
        print()
        print(f"{_GROUP_HEADERS[verdict]} ({len(group)}):")
        for file, f in group:
            if verdict == UNPARSEABLE:
                print(f"  {file} — {f['detail']}")
            else:
                print(f"  {file} — {f['path']}")
                print(f"    key \"{f['key']}\" holds a "
                      f"literal secret: "
                      f"{f['fingerprint']}. Fix rewrites "
                      f"it as the {f['env_var']} environment "
                      f"variable.")
    print()
    if s["inline_secret"] or s["env_literal"]:
        print("VERDICT: FINDINGS — move each value into "
              "the named environment variable (run the fix "
              "command to rewrite the files), and rotate "
              "any secret that was ever committed or "
              "shared: moving it does not un-leak it.")
    else:
        print("VERDICT: UNPARSEABLE — the file(s) above "
              "could not be parsed, so their contents "
              "could not be checked or cleared. Read them "
              "by hand.")
    print("secret-guard never prints a secret's value: "
          "reports show the key path and a fingerprint "
          "(first characters + length) only.")
    return 1


def cmd_fix(a):
    paths = _require_files(a.paths)
    results = [_load(p) for p in paths]
    outcomes = [fix_result(r, a.apply) for r in results]
    env_vars = _env_var_list(outcomes)
    n_changes = sum(len(o["changes"]) for o in outcomes)
    n_unparseable = sum(1 for o in outcomes
                        if o["status"] == "unparseable")
    if not a.apply:
        clean = all(o["status"] == "clean" for o in outcomes)
    else:
        clean = all(o["status"] in ("clean", "fixed")
                    for o in outcomes)
    exit_code = 0 if clean else 1
    if a.json:
        print(json.dumps(
            {"tool": TOOL, "version": __version__,
             "command": "fix", "apply": a.apply,
             "files": outcomes, "env_vars": env_vars,
             "summary": {"files": len(outcomes),
                         "changes": n_changes,
                         "changed_files": sum(
                             1 for o in outcomes
                             if o["changes"]),
                         "unparseable": n_unparseable},
             "clean": clean}, indent=2))
        return exit_code
    if not a.apply:
        mode = "DRY RUN — nothing written"
    elif n_changes:
        mode = "APPLIED"
    else:
        mode = "APPLY — nothing to change"
    print(f"{TOOL} v{__version__} — fix · {mode} · "
          f"{len(outcomes)} file(s)")
    for o in outcomes:
        print()
        if o["status"] == "clean":
            print(f"{o['file']} — clean, no changes")
        elif o["status"] == "unparseable":
            print(f"{o['file']} — UNPARSEABLE: could not "
                  f"be parsed, so it could not be fixed; "
                  f"the file was not touched")
        else:
            verb = ("written" if o["status"] == "fixed"
                    else "pending")
            print(f"{o['file']} — {len(o['changes'])} "
                  f"change(s) {verb}:")
            for c in o["changes"]:
                print(f"  {c['path']} → {c['ref']}  "
                      f"(was {c['fingerprint']})")
            if o["status"] == "fixed":
                print(f"  backup: {o['backup']}")
                print("  verified: the rewritten file "
                      "re-scans clean")
    if env_vars:
        print()
        print("Environment variables to set — the values "
              "are the ones currently in the files; "
              "secret-guard never prints them:")
        for e in env_vars:
            print(f"  {e['name']}  ← {e['file']} · "
                  f"{e['path']}")
    print()
    if not a.apply and n_changes:
        print("DRY RUN — nothing was written and no "
              "backups were made. Re-run with --apply to "
              "rewrite; a timestamped backup of each "
              "changed file is kept beside it first.")
    elif a.apply and n_changes:
        print("Applied and verified. Set the environment "
              "variables above, then restart the client "
              "that reads these configs. Rotate any secret "
              "that was ever committed or shared.")
    elif n_unparseable:
        print("Nothing else to do — but the UNPARSEABLE "
              "file(s) above could not be checked at all.")
    else:
        print("Nothing to do — every file was already "
              "clean, so nothing was written and no "
              "backups were made.")
    return exit_code


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    _JsonAwareParser.json_mode = "--json" in argv
    ap = _JsonAwareParser(
        prog=TOOL,
        description="Find inline secrets in AI-agent / "
                    "MCP config files (Claude Code "
                    "settings, .mcp.json, VS Code mcp.json, "
                    "Cursor-style and generic JSON configs) "
                    "and fix them: rewrite each literal "
                    "secret into an environment-variable "
                    "reference. Values are never printed — "
                    "key paths and fingerprints only. "
                    "(stdlib only, local only).")
    sub = ap.add_subparsers(dest="command", required=True,
                            parser_class=_JsonAwareParser)
    p_scan = sub.add_parser(
        "scan", help="report inline secrets; writes "
                     "nothing")
    p_scan.add_argument("paths", nargs="+",
                        help="config file(s) to scan")
    p_scan.add_argument("--json", action="store_true",
                        help="print one JSON object instead "
                             "of text")
    p_scan.set_defaults(func=cmd_scan)
    p_fix = sub.add_parser(
        "fix", help="rewrite inline secrets as env "
                    "references (dry run unless --apply)")
    p_fix.add_argument("paths", nargs="+",
                       help="config file(s) to fix")
    p_fix.add_argument("--apply", action="store_true",
                       help="write the changes (a "
                            "timestamped backup of each "
                            "changed file is kept beside "
                            "it first); without this flag "
                            "fix is a dry run")
    p_fix.add_argument("--json", action="store_true",
                       help="print one JSON object instead "
                            "of text")
    p_fix.set_defaults(func=cmd_fix)
    a = ap.parse_args(argv)

    def fail(msg):
        if getattr(a, "json", False):
            print(json.dumps({"error": msg}))
        else:
            print(f"ERROR: {msg}")
        return 2

    try:
        return a.func(a)
    except ToolError as exc:
        return fail(str(exc))


if __name__ == "__main__":
    sys.exit(main())
