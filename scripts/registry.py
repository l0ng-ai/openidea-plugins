#!/usr/bin/env python3
"""The OpenIDEA plugin registry: checks entries and assembles the index.

    registry.py validate --base REF --author LOGIN   # a pull request's changes
    registry.py fetch OUT [--mirror URL]            # packages + index skeleton
    registry.py annotate INDEX [--assets JSON]      # listing details into the index

`fetch` downloads every listed package version into OUT (from the mirror, the
registry's own release, when it has the same bytes; else from the author's
URL), checks each against its sha256, and writes OUT/index.json with the
publishers and revocations. `openidea-plugin index OUT` then adds the plugins,
checking each package's signature against those publishers, and keeps of each
plugin the newest version per plugin API requirement. `annotate` then adds
what the registry knows and the packages don't: each plugin's repository (as
its homepage when the manifest has none), project files it is suggested for,
the maintainers' picks (`featured.toml`) and download counts of the index
release's packages.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAINTAINERS = {"l0ng-ai"}
PUBLISHER_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
PLUGIN_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)*$")
LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
# A project-relative file or folder, as OpenIDEA looks it up: no globs, no way out.
SUGGEST_PATH = re.compile(r"^(?!.*(?:^|/)\.\.?(?:/|$))[A-Za-z0-9_.@+-]+(?:/[A-Za-z0-9_.@+-]+)*$")
MAX_SUGGEST = 8
MAX_PACKAGE = 256 << 20


class Invalid(Exception):
    pass


@dataclass
class Publisher:
    id: str
    name: str
    owners: list[str]
    keys: list[str]
    revoked_keys: list[str] = field(default_factory=list)
    # endorsed key -> {"key": earlier key, "signature": ...} (`openidea-plugin endorse`)
    endorsements: dict[str, dict] = field(default_factory=dict)


@dataclass
class Version:
    id: str
    version: str
    package: str
    sha256: str

    @property
    def file(self) -> str:
        return f"{self.id}-{self.version}.oiplugin"


@dataclass
class Plugin:
    id: str
    publisher: str
    repository: str
    versions: list[Version]
    suggest: list[str] = field(default_factory=list)


@dataclass
class Registry:
    publishers: dict[str, Publisher]
    plugins: dict[str, Plugin]
    revoked: list[dict]
    featured: list[str] = field(default_factory=list)


def _strings(value, what: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise Invalid(f"{what} must be a list of strings")
    return value


def _string(table: dict, key: str, where: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise Invalid(f"{where}: `{key}` is required")
    return value


def _key_ok(key: str) -> bool:
    try:
        return len(base64.b64decode(key, validate=True)) == 32
    except ValueError:
        return False


def parse_publisher(stem: str, text: str) -> Publisher:
    where = f"publishers/{stem}.toml"
    if not PUBLISHER_ID.match(stem):
        raise Invalid(f"{where}: the publisher id (file name) must match {PUBLISHER_ID.pattern}")
    t = tomllib.loads(text)
    unknown = set(t) - {"name", "owners", "keys", "revoked-keys", "endorsements"}
    if unknown:
        raise Invalid(f"{where}: unknown keys {sorted(unknown)}")
    owners = _strings(t.get("owners"), f"{where}: `owners`")
    keys = _strings(t.get("keys"), f"{where}: `keys`")
    revoked = _strings(t.get("revoked-keys", []), f"{where}: `revoked-keys`")
    if not owners or not all(LOGIN.match(o) for o in owners):
        raise Invalid(f"{where}: `owners` lists GitHub accounts")
    if not keys:
        raise Invalid(f"{where}: `keys` needs the public key `openidea-plugin keygen` printed")
    for key in keys + revoked:
        if not _key_ok(key):
            raise Invalid(f"{where}: {key!r} is not an Ed25519 public key (32 bytes, base64)")
    if set(revoked) & set(keys):
        raise Invalid(f"{where}: a key is in both `keys` and `revoked-keys`")
    endorsements = parse_endorsements(t.get("endorsements", {}), keys, revoked, where)
    return Publisher(stem, _string(t, "name", where), owners, keys, revoked, endorsements)


def parse_endorsements(table, keys: list[str], revoked: list[str], where: str) -> dict[str, dict]:
    """`[endorsements]`: a listed key -> the earlier key vouching for it and its
    signature, as `openidea-plugin endorse` prints them. OpenIDEA checks the
    signature; plugins installed from packages signed with the earlier key
    update to ones signed with the endorsed key without asking."""
    if not isinstance(table, dict):
        raise Invalid(f"{where}: `endorsements` is a table")
    out = {}
    for key, e in table.items():
        at = f"{where}: endorsement of {key!r}"
        if key not in keys:
            raise Invalid(f"{at}: the endorsed key must be in `keys`")
        if not isinstance(e, dict) or set(e) != {"key", "signature"}:
            raise Invalid(f"{at}: needs `key` and `signature` (what `openidea-plugin endorse` prints)")
        by, signature = e["key"], e["signature"]
        if by == key or by not in keys + revoked:
            raise Invalid(f"{at}: `key` must be another of the publisher's keys")
        try:
            valid = len(base64.b64decode(signature, validate=True)) == 64
        except (ValueError, TypeError):
            valid = False
        if not valid:
            raise Invalid(f"{at}: `signature` is not an Ed25519 signature (64 bytes, base64)")
        out[key] = {"key": by, "signature": signature}
    return out


def parse_plugin(stem: str, text: str) -> Plugin:
    where = f"plugins/{stem}.toml"
    publisher, _, name = stem.partition(".")
    if not PUBLISHER_ID.match(publisher) or not PLUGIN_NAME.match(name) or len(stem) > 64:
        raise Invalid(f"{where}: the file name is the plugin id, `<publisher>.<name>`")
    t = tomllib.loads(text)
    unknown = set(t) - {"repository", "versions", "suggest"}
    if unknown:
        raise Invalid(f"{where}: unknown keys {sorted(unknown)}")
    repository = _string(t, "repository", where)
    if not repository.startswith("https://"):
        raise Invalid(f"{where}: `repository` is the plugin's public source repository (https)")
    tables = t.get("versions")
    if not isinstance(tables, list) or not tables:
        raise Invalid(f"{where}: list each published package as a `[[versions]]` table")
    versions: list[Version] = []
    for i, v in enumerate(tables):
        at = f"{where}: [[versions]] {i + 1}"
        unknown = set(v) - {"version", "package", "sha256"}
        if unknown:
            raise Invalid(f"{at}: unknown keys {sorted(unknown)}")
        version = Version(stem, _string(v, "version", at), _string(v, "package", at), _string(v, "sha256", at).lower())
        if not SEMVER.match(version.version):
            raise Invalid(f"{at}: `version` is the package's semver version")
        if not version.package.startswith("https://"):
            raise Invalid(f"{at}: `package` is an https URL of the .oiplugin")
        if not SHA256.match(version.sha256):
            raise Invalid(f"{at}: `sha256` is the package file's SHA-256, in hex")
        if any(x.version == version.version for x in versions):
            raise Invalid(f"{at}: {version.version} is listed twice")
        versions.append(version)
    suggest = _strings(t.get("suggest", []), f"{where}: `suggest`")
    if len(suggest) > MAX_SUGGEST or not all(len(p) <= 128 and SUGGEST_PATH.match(p) for p in suggest):
        raise Invalid(
            f"{where}: `suggest` lists up to {MAX_SUGGEST} project-relative paths (`pom.xml`, `config/routes.rb`)"
        )
    return Plugin(stem, publisher, repository, versions, suggest)


def parse_featured(text: str) -> list[str]:
    return _strings(tomllib.loads(text).get("plugins", []), "featured.toml: `plugins`")


def parse_revoked(text: str) -> list[dict]:
    t = tomllib.loads(text)
    out = []
    for i, r in enumerate(t.get("plugin", [])):
        where = f"revoked.toml: [[plugin]] {i + 1}"
        out.append(
            {
                "id": _string(r, "id", where),
                "versions": _strings(r.get("versions", []), f"{where}: `versions`"),
                "reason": _string(r, "reason", where),
            }
        )
    return out


def load(files: dict[str, str]) -> Registry:
    """The registry from {relative path: text}; raises Invalid with every problem."""
    problems: list[str] = []
    publishers: dict[str, Publisher] = {}
    plugins: dict[str, Plugin] = {}
    revoked: list[dict] = []
    featured: list[str] = []
    for path, text in sorted(files.items()):
        p = Path(path)
        try:
            if p.parent.name == "publishers" and p.suffix == ".toml":
                publishers[p.stem] = parse_publisher(p.stem, text)
            elif p.parent.name == "plugins" and p.suffix == ".toml":
                plugins[p.stem] = parse_plugin(p.stem, text)
            elif path == "revoked.toml":
                revoked = parse_revoked(text)
            elif path == "featured.toml":
                featured = parse_featured(text)
        except (Invalid, tomllib.TOMLDecodeError) as e:
            problems.append(f"{path}: {e}" if isinstance(e, tomllib.TOMLDecodeError) else str(e))
    for plugin in plugins.values():
        if plugin.publisher not in publishers:
            problems.append(f"plugins/{plugin.id}.toml: no publishers/{plugin.publisher}.toml")
    for r in revoked:
        if r["id"].partition(".")[0] not in publishers:
            problems.append(f"revoked.toml: {r['id']} is not a plugin of a listed publisher")
    for id in featured:
        if id not in plugins:
            problems.append(f"featured.toml: {id} is not a listed plugin")
    if problems:
        raise Invalid("\n".join(problems))
    return Registry(publishers, plugins, revoked, featured)


def registry_files(ref: str | None = None) -> dict[str, str]:
    """The registry's files in the working tree, or at git `ref`."""
    if ref is None:
        out = {}
        for d in ("publishers", "plugins"):
            for f in (ROOT / d).glob("*.toml"):
                out[f"{d}/{f.name}"] = f.read_text()
        for name in ("revoked.toml", "featured.toml"):
            if (ROOT / name).is_file():
                out[name] = (ROOT / name).read_text()
        return out
    names = git(
        "ls-tree", "-r", "--name-only", ref, "--", "publishers", "plugins", "revoked.toml", "featured.toml"
    ).split()
    return {n: git("show", f"{ref}:{n}") for n in names if n.endswith(".toml")}


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout


def review(base: Registry, head: Registry, changed: list[str], author: str) -> tuple[list[str], list[str]]:
    """(problems, notes) of `author` changing `changed` from `base` to `head`.

    Owners (as listed before the change) may change their publisher and its
    plugins; anything else is the maintainers'. New publishers and new plugins
    are noted for review.
    """
    problems: list[str] = []
    notes: list[str] = []
    maintainer = author in MAINTAINERS

    def may_change(publisher: str, what: str) -> None:
        if maintainer:
            return
        if publisher in base.publishers:
            if author not in base.publishers[publisher].owners:
                problems.append(f"{what}: @{author} is not an owner of publisher {publisher}")
        elif publisher in head.publishers:
            if author not in head.publishers[publisher].owners:
                problems.append(f"{what}: a new publisher lists its author among its owners")
        else:
            problems.append(f"{what}: no publisher {publisher}")

    for path in changed:
        p = Path(path)
        if p.parent.name == "publishers" and p.suffix == ".toml" and len(p.parts) == 2:
            may_change(p.stem, path)
            if p.stem not in base.publishers:
                notes.append(f"new publisher `{p.stem}`")
            elif p.stem not in head.publishers and not maintainer:
                problems.append(f"{path}: only maintainers remove publishers")
        elif p.parent.name == "plugins" and p.suffix == ".toml" and len(p.parts) == 2:
            may_change(p.stem.partition(".")[0], path)
            if p.stem not in base.plugins:
                notes.append(f"new plugin `{p.stem}`")
            elif p.stem in head.plugins:
                before = {v.version for v in base.plugins[p.stem].versions}
                after = {v.version for v in head.plugins[p.stem].versions}
                diff = [f"+{v}" for v in sorted(after - before)] + [f"-{v}" for v in sorted(before - after)]
                notes.append(f"`{p.stem}` {' '.join(diff) or 'details changed'}")
            else:
                notes.append(f"`{p.stem}` delisted")
        elif path.endswith(".gitkeep"):
            pass
        elif not maintainer:
            problems.append(f"{path}: only maintainers change this file")
    return problems, notes


def cmd_validate(args) -> int:
    try:
        head = load(registry_files())
    except Invalid as e:
        print(e, file=sys.stderr)
        return 1
    if not args.base:
        print(f"ok: {len(head.publishers)} publishers, {len(head.plugins)} plugins")
        return 0
    base = load(registry_files(args.base))
    changed = git("diff", "--name-only", f"{args.base}...HEAD").split()
    problems, notes = review(base, head, changed, args.author)
    summary = ["### Registry changes", *(f"- {n}" for n in notes)]
    if any(n.startswith("new ") for n in notes):
        summary.append("\nNew publishers and plugins wait for a maintainer's review.")
    summary += [f"- :x: {p}" for p in problems]
    report = "\n".join(summary)
    print(report)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(report + "\n")
    return 1 if problems else 0


RETRIES = 4


def download(url: str, sleep=time.sleep) -> bytes | None:
    """The bytes at `url`; None when it is not found. Timeouts and 5xx/429 are retried with backoff."""
    request = urllib.request.Request(url, headers={"User-Agent": "openidea-plugin-registry"})
    for attempt in range(RETRIES):
        try:
            with urllib.request.urlopen(request, timeout=60) as r:
                data = r.read(MAX_PACKAGE + 1)
            break
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if (e.code < 500 and e.code != 429) or attempt == RETRIES - 1:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == RETRIES - 1:
                raise
        sleep(5 * 3**attempt)
    if len(data) > MAX_PACKAGE:
        raise Invalid(f"{url}: larger than {MAX_PACKAGE >> 20} MiB")
    return data


def _key_entry(p: Publisher, key: str, revoked: bool) -> dict:
    entry = {"key": key, "revoked": revoked}
    if key in p.endorsements:
        entry["endorsement"] = p.endorsements[key]
    return entry


def index_skeleton(reg: Registry) -> dict:
    return {
        "format": 1,
        "publishers": [
            {
                "id": p.id,
                "name": p.name,
                "keys": [_key_entry(p, k, False) for k in p.keys] + [_key_entry(p, k, True) for k in p.revoked_keys],
            }
            for p in reg.publishers.values()
        ],
        "plugins": [],
        "revoked": reg.revoked,
    }


def cmd_fetch(args) -> int:
    reg = load(registry_files())
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    failed = False
    for v in (v for plugin in reg.plugins.values() for v in plugin.versions):
        try:
            data = download(f"{args.mirror.rstrip('/')}/{v.file}") if args.mirror else None
        except OSError as e:
            print(f"::warning::{v.id} {v.version}: mirror unavailable ({e}); using the author's URL", file=sys.stderr)
            data = None
        source = "mirror"
        if data is None or hashlib.sha256(data).hexdigest() != v.sha256:
            data, source = download(v.package), v.package
        if data is None:
            print(f"::error::{v.id} {v.version}: {v.package} not found", file=sys.stderr)
            failed = True
            continue
        if hashlib.sha256(data).hexdigest() != v.sha256:
            print(f"::error::{v.id} {v.version}: {v.package} doesn't match its sha256", file=sys.stderr)
            failed = True
            continue
        (out / v.file).write_bytes(data)
        print(f"{v.file} ({source})")
    (out / "index.json").write_text(json.dumps(index_skeleton(reg), indent=2) + "\n")
    return 1 if failed else 0


def downloads_by_plugin(assets: list[dict], ids) -> dict[str, int]:
    """Download counts of `<id>-<version>.oiplugin` release assets, per plugin id."""
    out: dict[str, int] = {}
    for asset in assets:
        name = asset.get("name", "")
        if not name.endswith(".oiplugin"):
            continue
        # The longest id the name starts with: ids may contain `-`.
        owner = max((i for i in ids if name.startswith(f"{i}-")), key=len, default=None)
        if owner and SEMVER.match(name[len(owner) + 1 : -len(".oiplugin")]):
            out[owner] = out.get(owner, 0) + int(asset.get("downloadCount") or 0)
    return out


def annotate(index: dict, reg: Registry, assets: list[dict]) -> dict:
    downloads = downloads_by_plugin(assets, reg.plugins.keys())
    for entry in index.get("plugins", []):
        plugin = reg.plugins.get(entry.get("id"))
        if plugin is None:
            continue
        if not entry.get("homepage"):
            entry["homepage"] = plugin.repository
        if plugin.suggest:
            entry["suggest"] = plugin.suggest
        if plugin.id in reg.featured:
            entry["featured"] = True
        if plugin.id in downloads:
            entry["downloads"] = downloads[plugin.id]
    return index


def cmd_annotate(args) -> int:
    reg = load(registry_files())
    assets = json.loads(Path(args.assets).read_text()).get("assets", []) if args.assets else []
    path = Path(args.index)
    index = annotate(json.loads(path.read_text()), reg, assets)
    path.write_text(json.dumps(index, indent=2, ensure_ascii=False) + "\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("validate", help="check the entries (and a pull request's changes with --base)")
    v.add_argument("--base")
    v.add_argument("--author", default="")
    v.set_defaults(run=cmd_validate)
    f = sub.add_parser("fetch", help="download the packages and write the index skeleton")
    f.add_argument("out")
    f.add_argument("--mirror")
    f.set_defaults(run=cmd_fetch)
    a = sub.add_parser("annotate", help="add repository, suggestions, picks and download counts to an index")
    a.add_argument("index")
    a.add_argument("--assets", help="`gh release view index --json assets` output")
    a.set_defaults(run=cmd_annotate)
    args = parser.parse_args()
    try:
        return args.run(args)
    except Invalid as e:
        print(e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
