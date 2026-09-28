#!/usr/bin/env python3
"""Fail if description.yml's registry pins are not real commits on main.

`repo.ref` and `repo.ref_next` are submitted to duckdb/community-extensions and
tell it which tree to build. Nothing here ever reads them, so a wrong value
costs nothing locally and fails in someone else's CI days later -- and both
pins have already gone stale once each. The checkable part is mechanical, so a
machine should enforce it:

  * 40 lowercase hex characters, not a branch name and not abbreviated. The
    registry silently accepts a branch and then rejects it in validation.
  * resolvable to a commit object in this repository.
  * an ancestor of origin/main, because a pin on a branch that never merges
    names a tree the registry cannot fetch.
  * the tree it names must contain the krb5 dependency in vcpkg.json, without
    which the registry build dies at configure on our own "no GSSAPI" refusal.

What this CANNOT check is whether a pin is CURRENT. A pin necessarily trails the
commit that sets it, so "stale" is not a defect this can see -- re-pinning
before a submission stays a human step. Do not add a tip-of-main equality check
here; it would fail on every commit that touches these fields.

Offline by construction: `make check` must work on a plane, so this only reads
local refs. When refs/remotes/origin/main is absent (a fresh shallow clone) the
ancestry check is skipped with a note rather than failing.
"""
import re
import subprocess
import sys

DESCRIPTION = "description.yml"
FIELDS = ("ref", "ref_next")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def git(*args):
    """Run git, returning (ok, stdout). Never raises on a non-zero exit."""
    proc = subprocess.run(
        ("git",) + args, capture_output=True, text=True, check=False
    )
    return proc.returncode == 0, proc.stdout.strip()


def pins():
    """Read repo.<field> from description.yml.

    Parsed with a regex rather than PyYAML: this runs in `make check`, which the
    Makefile keeps dependency-free, and PyYAML is not guaranteed present.
    """
    text = open(DESCRIPTION, encoding="utf-8").read()
    found = {}
    for field in FIELDS:
        m = re.search(
            rf'^\s{{2}}{field}:\s*"?([^"\s#]+)"?\s*$', text, re.MULTILINE
        )
        if m:
            found[field] = m.group(1)
    return found


def main():
    found = pins()
    failures = []
    notes = []

    missing = [f for f in FIELDS if f not in found]
    if "ref" in missing:
        failures.append("repo.ref is absent; the registry requires it")
    if "ref_next" in missing:
        # Not fatal for the registry, but for THIS extension the prerelease lane
        # is the only one that can succeed, and build_next.yml runs with
        # require_ref_next: true -- so a missing ref_next means it is skipped.
        failures.append(
            "repo.ref_next is absent; the prerelease lane would skip this "
            "extension entirely (build_next.yml sets require_ref_next: true)"
        )

    have_origin_main, _ = git("rev-parse", "--verify", "--quiet",
                              "refs/remotes/origin/main")

    for field, sha in found.items():
        where = f"{DESCRIPTION} repo.{field}"
        if not SHA_RE.match(sha):
            failures.append(
                f"{where}: {sha!r} is not 40 lowercase hex characters "
                f"(a branch name is accepted here and rejected by the registry)"
            )
            continue

        ok, _ = git("cat-file", "-e", f"{sha}^{{commit}}")
        if not ok:
            failures.append(f"{where}: {sha[:12]} is not a commit in this repository")
            continue

        if have_origin_main:
            ok, _ = git("merge-base", "--is-ancestor", sha, "refs/remotes/origin/main")
            if not ok:
                failures.append(
                    f"{where}: {sha[:12]} is not an ancestor of origin/main, "
                    f"so the registry cannot fetch the tree it names"
                )
                continue
        else:
            notes.append(
                f"{where}: skipped the ancestry check "
                f"(no refs/remotes/origin/main in this clone)"
            )

        ok, blob = git("show", f"{sha}:vcpkg.json")
        if not ok:
            failures.append(f"{where}: {sha[:12]} has no vcpkg.json")
        elif '"krb5"' not in blob:
            failures.append(
                f"{where}: the tree at {sha[:12]} does not declare krb5 in "
                f"vcpkg.json, so the registry build fails at configure"
            )

    for note in notes:
        print(f"note: {note}")

    if failures:
        for f in failures:
            print(f"registry refs: {f}", file=sys.stderr)
        return 1

    shown = ", ".join(f"{f}={found[f][:12]}" for f in FIELDS if f in found)
    same = len(set(found.values())) == 1 and len(found) == len(FIELDS)
    print(
        f"registry refs: {shown} — real, on main, krb5 declared"
        + ("; both name one commit" if same else "; the two pins differ")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
