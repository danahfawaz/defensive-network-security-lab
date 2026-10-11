#!/usr/bin/env python3
"""Render paste-ready device configurations with real secrets.

The configurations committed to this repository contain placeholder hashes instead of passwords, so no secret ever
reaches Git.  Before pasting a configuration into Packet Tracer, run this script: it replaces every placeholder with a
secret you chose (or one it generates) and writes the result to ``build/rendered/`` (git-ignored).

    python scripts/render_configs.py --generate                # first run: create lab-secrets.local.json
    python scripts/render_configs.py --state hardened          # later runs reuse the same secrets
    python scripts/render_configs.py --check                   # verify the committed configs hold placeholders only

Secrets are never printed. They live in ``lab-secrets.local.json`` (git-ignored, mode 0600 where the OS supports it):

    {"FW-EDGE": {"enable": "...", "user:admin": "..."}, "SW-ACCESS": {...}, ...}

Only the standard library is used.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLACEHOLDER = "$1$labonly$xxxxxxxxxxxxxxxxxxxxxx"
STATES = ("baseline", "hardened")

_PH = re.escape(PLACEHOLDER)
_ENABLE = re.compile(rf"^(?P<head>enable secret) 5 {_PH}\s*$")
_USER = re.compile(rf"^(?P<head>username (?P<name>\S+) .*?secret) 5 {_PH}\s*$")
# Anything that looks like a stored credential but is not one of the two placeholder forms above.
_CREDENTIAL = re.compile(r"^\s*(?:enable (?:secret|password)|username \S+ .*(?:secret|password)|password|key-string|"
                         r"snmp-server community|crypto isakmp key|tacacs-server key|radius-server key)\b", re.I)
_REAL_HASH = re.compile(r"\$[1-9]\$[^\s$]+\$[./0-9A-Za-z]{20,}")


class RenderError(Exception):
    pass


def config_files(root: Path, state: str) -> list[Path]:
    """The configurations of one state: its own folder plus the shared simulated Internet."""
    files = sorted((root / "configs" / state).glob("*.cfg")) + sorted((root / "configs" / "internet-sim").glob("*.cfg"))
    if not files:
        raise RenderError(f"no configurations found for state {state!r} under {root / 'configs'}")
    return files


def required_secrets(text: str) -> list[str]:
    """Secret keys a configuration needs: ``enable`` and ``user:<name>``."""
    keys = []
    for line in text.splitlines():
        if _ENABLE.match(line):
            keys.append("enable")
        else:
            m = _USER.match(line)
            if m:
                keys.append(f"user:{m.group('name')}")
    return keys


def generate_secret(length: int = 20) -> str:
    """A random alphanumeric secret (no characters that a terminal or a CLI would treat specially)."""
    alphabet = string.ascii_letters + string.digits
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in value) and any(c.isupper() for c in value) and any(c.isdigit() for c in value):
            return value


def render(text: str, device_secrets: dict[str, str], device: str) -> str:
    out = []
    for line in text.splitlines():
        m = _ENABLE.match(line)
        if m:
            out.append(f"{m.group('head')} {_lookup(device_secrets, 'enable', device)}")
            continue
        m = _USER.match(line)
        if m:
            out.append(f"{m.group('head')} {_lookup(device_secrets, 'user:' + m.group('name'), device)}")
            continue
        out.append(line)
    rendered = "\n".join(out) + "\n"
    if PLACEHOLDER in rendered:
        raise RenderError(f"{device}: a placeholder is left in a form this script does not understand")
    return rendered


def _lookup(device_secrets: dict[str, str], key: str, device: str) -> str:
    try:
        return device_secrets[key]
    except KeyError:
        raise RenderError(f"{device}: no secret for {key!r}; run with --generate to create it") from None


def check_placeholders(root: Path) -> list[str]:
    """Problems that would put a real credential into Git (committed configs may hold placeholders only)."""
    problems = []
    for state in STATES:
        for path in config_files(root, state):
            if path.parent.name == "baseline":
                continue  # the baseline carries the well-known lab password "cisco" on purpose; see its header
            for no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if _ENABLE.match(line) or _USER.match(line):
                    continue
                if _REAL_HASH.search(line) and PLACEHOLDER not in line:
                    problems.append(f"{path.relative_to(root)}:{no}: a password hash that is not the placeholder")
                elif _CREDENTIAL.match(line):
                    problems.append(f"{path.relative_to(root)}:{no}: credential that is neither the placeholder nor a known form")
    return sorted(set(problems))


def load_secrets(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise RenderError(f"{path}: not valid JSON ({exc})") from exc
    if not isinstance(data, dict) or not all(isinstance(v, dict) for v in data.values()):
        raise RenderError(f"{path}: expected {{device: {{key: secret}}}}")
    return data


def save_secrets(path: Path, data: dict[str, dict[str, str]]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:  # e.g. Windows: the file is still git-ignored
        pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", choices=[*STATES, "all"], default="hardened")
    ap.add_argument("--secrets", default="lab-secrets.local.json", help="JSON file with your secrets (default: %(default)s)")
    ap.add_argument("--generate", action="store_true", help="create any secret that is missing from the secrets file")
    ap.add_argument("--out", default="build/rendered", help="output directory (default: %(default)s)")
    ap.add_argument("--check", action="store_true", help="only verify that committed configs contain placeholders, not secrets")
    ap.add_argument("--root", default=str(ROOT), help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    root = Path(args.root)

    try:
        if args.check:
            problems = check_placeholders(root)
            for p in problems:
                print(f"render_configs: {p}", file=sys.stderr)
            print("placeholders only: OK" if not problems else f"{len(problems)} problem(s)")
            return 1 if problems else 0

        secrets_path = Path(args.secrets)
        if not secrets_path.is_absolute():
            secrets_path = root / secrets_path
        out_dir = Path(args.out) if Path(args.out).is_absolute() else root / args.out
        store = load_secrets(secrets_path)
        states = STATES if args.state == "all" else (args.state,)
        written = []
        for state in states:
            for path in config_files(root, state):
                device = path.stem
                text = path.read_text(encoding="utf-8")
                mine = store.setdefault(device, {})
                for key in required_secrets(text):
                    if key not in mine:
                        if not args.generate:
                            raise RenderError(f"{device}: no secret for {key!r} in {secrets_path.name}; run with --generate")
                        mine[key] = generate_secret()
                dest = out_dir / state / path.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(render(text, mine, device), encoding="utf-8")
                written.append(dest)
        save_secrets(secrets_path, {d: s for d, s in store.items() if s})
    except RenderError as exc:
        print(f"render_configs: error: {exc}", file=sys.stderr)
        return 2

    print(f"rendered {len(written)} configuration(s) into {args.out}/ (secrets are in {secrets_path.name}; neither is tracked by Git)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
