#!/usr/bin/env python3
"""Write the .SRCINFO next to each AUR PKGBUILD, without makepkg.

    python3 packaging/aur/srcinfo.py            # rewrite both
    python3 packaging/aur/srcinfo.py --check    # fail if either is stale
    python3 packaging/aur/srcinfo.py path/to/PKGBUILD ...

The AUR reads a package's metadata from `.SRCINFO`, never from the
PKGBUILD, and refuses a push without one. It is meant to be the output of
`makepkg --printsrcinfo`, but makepkg exists only on Arch, and the PKGBUILDs
are edited and bumped (packaging/bump.py) on machines that are not. A
.SRCINFO that disagrees with its PKGBUILD is the classic AUR mistake: the
package builds, and the website and every AUR helper describe something
else.

So this reproduces what makepkg prints for these two packages, byte for
byte: the PKGBUILD is sourced by bash, exactly as makepkg sources it, and
its variables are written out in the order and with the whitespace
normalisation of libmakepkg's srcinfo.sh. When makepkg is installed,
bump.py uses it instead, and the two should agree; if they ever do not,
makepkg is right and this is the bug.

What it does not cover, because neither package uses it: split packages
(more than one `pkgname`) and per-package overrides inside `package_*()`.
It refuses a PKGBUILD with more than one `pkgname` rather than writing a
.SRCINFO that silently leaves the rest out.

`--check` is what CI runs, so a PKGBUILD edited without regenerating its
.SRCINFO goes red on the pull request rather than on the AUR.
"""

import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent

# libmakepkg/util/schema.sh: `known_hash_algos=({ck,md5,sha{1,224,256,384,512},b2})`.
HASHES = [f"{a}sums" for a in ("ck", "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "b2")]

# libmakepkg/srcinfo.sh, srcinfo_write_global, in its order.
SINGLE = ["pkgdesc", "pkgver", "pkgrel", "epoch", "url", "install", "changelog"]
MULTI = [
    "arch", "groups", "license", "checkdepends", "makedepends",
    "depends", "optdepends", "provides", "conflicts", "replaces",
    "noextract", "options", "backup",
    "source", "validpgpkeys", *HASHES,
]
# And the ones that may carry an `_<arch>` suffix, also in its order.
ARCH_MULTI = [
    "source", "provides", "conflicts", "depends", "replaces",
    "optdepends", "makedepends", "checkdepends", *HASHES,
]

# Sources the PKGBUILD and prints every variable as NUL-separated records:
# name, element count, elements. A scalar is a one-element array to bash's
# `${ref[@]}`, which is what makes one loop serve both. An empty array or
# string is skipped, as makepkg skips it.
DUMP = r'''
set -e
source "$1"
for _name in $(compgen -A variable); do
    case "$_name" in _name|_ref|BASH*|FUNCNAME|PIPESTATUS|GROUPS) continue ;; esac
    declare -n _ref="$_name"
    if (( ${#_ref[@]} )) && [[ -n "${_ref[*]}" ]]; then
        printf '%s\0%s\0' "$_name" "${#_ref[@]}"
        printf '%s\0' "${_ref[@]}"
    fi
    unset -n _ref
done
'''


def variables(pkgbuild: pathlib.Path) -> dict[str, list[str]]:
    """Every non-empty variable the PKGBUILD defines, as a list of values."""
    out = subprocess.run(
        ["bash", "-c", DUMP, "srcinfo", pkgbuild.name],
        cwd=pkgbuild.parent,
        capture_output=True,
        check=True,
        # A clean environment, so nothing the caller exported can leak in
        # as if the PKGBUILD had set it. makepkg sources into its own shell
        # for the same reason.
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    ).stdout.decode()
    fields = out.split("\0")
    found: dict[str, list[str]] = {}
    i = 0
    while i + 1 < len(fields):
        name, count = fields[i], int(fields[i + 1])
        found[name] = fields[i + 2 : i + 2 + count]
        i += 2 + count
    return found


def normalise(value: str) -> str:
    """srcinfo_write_attr: runs of whitespace become one space, then trim."""
    return re.sub(r"\s+", " ", value).strip()


def render(pkgbuild: pathlib.Path) -> str:
    """What `makepkg --printsrcinfo` prints for this PKGBUILD."""
    var = variables(pkgbuild)
    pkgnames = var.get("pkgname", [])
    if len(pkgnames) != 1:
        raise SystemExit(f"{pkgbuild}: expected one pkgname, found {pkgnames!r}")
    pkgbase = var.get("pkgbase", pkgnames)[0]

    lines = [f"pkgbase = {pkgbase}"]
    for attr in SINGLE:
        if attr in var:
            # A scalar; `${!attr}` in makepkg, which is the first element.
            lines.append(f"\t{attr} = {normalise(var[attr][0])}")
    for attr in MULTI:
        lines += [f"\t{attr} = {normalise(v)}" for v in var.get(attr, [])]
    for arch in var.get("arch", []):
        if arch == "any":
            continue
        for attr in ARCH_MULTI:
            name = f"{attr}_{arch}"
            lines += [f"\t{name} = {normalise(v)}" for v in var.get(name, [])]

    lines += ["", f"pkgname = {pkgnames[0]}"]
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    check = "--check" in argv[1:]
    paths = [pathlib.Path(a) for a in argv[1:] if a != "--check"]
    if not paths:
        paths = sorted(HERE.glob("*/PKGBUILD"))

    stale = []
    for pkgbuild in paths:
        srcinfo = pkgbuild.with_name(".SRCINFO")
        want = render(pkgbuild)
        have = srcinfo.read_text() if srcinfo.exists() else None
        if have == want:
            print(f"{srcinfo}: up to date")
        elif check:
            stale.append(srcinfo)
            print(f"{srcinfo}: does not match {pkgbuild.name}", file=sys.stderr)
        else:
            srcinfo.write_text(want)
            print(f"{srcinfo}: written")
    if stale:
        print("regenerate with: python3 packaging/aur/srcinfo.py", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
