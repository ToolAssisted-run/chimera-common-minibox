#!/usr/bin/env python3
"""Puts a core package's licences inside the package.

A core package is a binary that a user downloads on its own, so its terms have
to travel with it: the emulator inside it is somebody else's work, under
somebody else's licence, and several of them (Genesis Plus GX, Snes9x, the
FreeDO-descended parts of Opera) forbid commercial redistribution outright
while others (PPSSPP, DOSBox-X) are GPL and require the corresponding source to
be identifiable.

Each core repo declares its parts once, in waterbox/package-licenses.json:

    {
      "effectiveTerms": "GPL-2.0-or-later",
      "commercialUse": "allowed" | "prohibited",
      "components": [
        { "name": "PPSSPP",
          "license": "GPL-2.0-or-later",
          "url": "https://github.com/hrydgard/ppsspp",
          "commit": "{submodule:extern/ppsspp}",
          "file": "extern/ppsspp/LICENSE.TXT",
          "sourceUrl": "https://github.com/hrydgard/ppsspp/archive/{commit}.tar.gz" }
      ]
    }

and this copies every named licence text into <staging>/licenses/ beside a
resolved licenses.json. {selfCommit} and {submodule:<path>} are filled in from
git, and {commit} in a sourceUrl becomes that component's own commit - so the
source a GPL binary corresponds to is a link that resolves forever, not a
promise to email someone.

Usage: package-licenses.py <repo root> <staging dir> [<declaration>]
"""

import json
import os
import re
import subprocess
import sys


def git(root, *args):
    try:
        out = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except Exception:
        return ""


def resolve_commit(root, spec):
    """{selfCommit} / {submodule:<path>} -> a real commit, or "" when unknown."""
    if not spec:
        return ""
    if spec == "{selfCommit}":
        return git(root, "rev-parse", "HEAD")
    match = re.fullmatch(r"\{submodule:(.+)\}", spec)
    if match:
        path = match.group(1)
        # the commit the submodule is CHECKED OUT at, which is what was built -
        # not the pointer, which a patch overlay may have moved past
        return git(os.path.join(root, path), "rev-parse", "HEAD")
    return spec


def safe_name(name):
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "component"


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    root, staging = sys.argv[1], sys.argv[2]
    decl_path = sys.argv[3] if len(sys.argv) > 3 else os.path.join(root, "waterbox", "package-licenses.json")

    if not os.path.exists(decl_path):
        sys.exit(f"no licence declaration at {decl_path}; a package must carry its terms")

    with open(decl_path) as f:
        decl = json.load(f)

    out_dir = os.path.join(staging, "licenses")
    os.makedirs(out_dir, exist_ok=True)

    resolved = []
    for component in decl.get("components", []):
        commit = resolve_commit(root, component.get("commit", ""))
        entry = {
            "name": component.get("name", ""),
            "license": component.get("license", ""),
            "url": component.get("url", ""),
        }
        if commit:
            entry["commit"] = commit
        source_url = component.get("sourceUrl", "")
        if source_url:
            if "{commit}" in source_url and not commit:
                # a source link that cannot name the exact commit is worse than
                # none: it would point at whatever the branch says today
                source_url = ""
            else:
                entry["sourceUrl"] = source_url.replace("{commit}", commit)

        rel = component.get("file", "")
        if rel:
            src = os.path.join(root, rel)
            if not os.path.exists(src):
                sys.exit(f"{component.get('name')}: licence file not found at {rel}")
            name = f"{safe_name(component.get('name', ''))}-{os.path.basename(rel)}"
            with open(src, "rb") as f:
                data = f.read()
            with open(os.path.join(out_dir, name), "wb") as f:
                f.write(data)
            entry["licenseFile"] = name
        resolved.append(entry)

    index = {
        "package": decl.get("package", ""),
        "effectiveTerms": decl.get("effectiveTerms", ""),
        "commercialUse": decl.get("commercialUse", ""),
        "note": decl.get("note", ""),
        "components": resolved,
    }
    with open(os.path.join(out_dir, "licenses.json"), "w") as f:
        json.dump(index, f, indent=2, sort_keys=True)
        f.write("\n")

    print(f"licenses: {len(resolved)} components, terms {index['effectiveTerms']!r}, "
          f"commercial use {index['commercialUse'] or 'unstated'}")


if __name__ == "__main__":
    main()
