#!/usr/bin/env python3
"""Bring the AUR and Gentoo packaging up to a released version.

    python3 packaging/bump.py 0.0.15

Run it after RELEASING.md step 6, never before: it reads what the release
published, and both halves have to exist.

- `aur/stop-bots/PKGBUILD` gets the version and the sha256 of the `.crate`,
  as crates.io records it.
- `aur/stop-bots-bin/PKGBUILD` gets the version and, for every
  `sha256sums_<arch>` it declares, the digest from the `.sha256` file the
  release workflow published next to that architecture's tarball.
- The `.SRCINFO` next to each PKGBUILD is regenerated, with
  `makepkg --printsrcinfo` when makepkg is installed and with
  aur/srcinfo.py, which writes the same thing without it, otherwise.
- `gentoo/stop-bots-<version>.ebuild` is generated from the tag's Cargo.lock
  by gen-ebuild.py, and the previous ebuild is removed.

The checksums are read from what was published rather than computed from a
fresh download: a digest taken from the file you are checking says only that
you downloaded something. The script only reads from the network, and pushes
nothing: submitting to the AUR stays the manual step in packaging/README.md.
"""

import importlib.util
import json
import pathlib
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent

CRATE = "stop-bots"
REPO = "https://github.com/ivankovic/stop-bots"

# crates.io refuses requests without a User-Agent, and asks for one that says
# who is asking. The repository URL says that without naming a person.
USER_AGENT = f"stop-bots packaging/bump.py (+{REPO})"

SHA256 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$")


def fetch(url: str, missing: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise SystemExit(f"{url}: not found. {missing}")
        raise SystemExit(f"{url}: HTTP {e.code}")


def crate_sha256(version: str) -> str:
    """The .crate's sha256, as crates.io recorded it at publish time."""
    body = fetch(
        f"https://crates.io/api/v1/crates/{CRATE}/{version}",
        "Has `cargo publish` run (RELEASING.md step 6)?",
    )
    digest = json.loads(body)["version"]["checksum"]
    if not SHA256.match(digest):
        raise SystemExit(f"crates.io returned {digest!r} as the checksum")
    return digest


def tarball_sha256(version: str, arch: str) -> str:
    """The digest the release workflow published next to one tarball."""
    name = f"{CRATE}-{version}-{arch}-unknown-linux-musl.tar.gz"
    body = fetch(
        f"{REPO}/releases/download/v{version}/{name}.sha256",
        f"Did the release workflow for v{version} publish {name}?",
    )
    fields = body.decode().split()
    # `sha256sum` output: the digest, then the file it is the digest of. The
    # name is checked so a mislabelled asset cannot pass for another one.
    if len(fields) != 2 or not SHA256.match(fields[0]) or fields[1] != name:
        raise SystemExit(f"{name}.sha256 is not a sha256sum line for {name}")
    return fields[0]


def read_var(text: str, var: str) -> str:
    """The value of `var=...` in a PKGBUILD, with one level of quoting removed."""
    match = re.search(rf"^{var}=\(?'?([^')\n]*)'?\)?$", text, re.M)
    if not match:
        raise SystemExit(f"no {var}= line")
    return match.group(1)


def set_var(text: str, var: str, value: str, array: bool = False) -> str:
    new = f"{var}=('{value}')" if array else f"{var}={value}"
    text, n = re.subn(rf"^{var}=.*$", new, text, count=1, flags=re.M)
    if n != 1:
        raise SystemExit(f"no {var}= line")
    return text


def bump_pkgbuild(path: pathlib.Path, version: str, sums: dict[str, str]) -> None:
    """Rewrite pkgver, pkgrel and the listed sha256sums variables in place."""
    text = path.read_text()
    old_version = read_var(text, "pkgver")

    if old_version != version:
        text = set_var(text, "pkgver", version)
        text = set_var(text, "pkgrel", "1")
    for var, digest in sums.items():
        text = set_var(text, var, digest, array=True)
    path.write_text(text)
    print(f"wrote {path.relative_to(ROOT)} ({old_version} -> {version})")

    write_srcinfo(path)


def write_srcinfo(pkgbuild: pathlib.Path) -> None:
    """Regenerate the .SRCINFO from the PKGBUILD just written.

    Always, and from the whole PKGBUILD: the AUR shows what .SRCINFO says,
    so a description or a dependency changed by hand since the last bump
    has to reach it too, not only the version and the checksums.
    """
    path = pkgbuild.with_name(".SRCINFO")
    if shutil.which("makepkg"):
        out = subprocess.run(
            ["makepkg", "--printsrcinfo"],
            cwd=path.parent,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        how = "makepkg --printsrcinfo"
    else:
        out = load("srcinfo", HERE / "aur" / "srcinfo.py").render(pkgbuild)
        how = "aur/srcinfo.py; no makepkg here"
    path.write_text(out)
    print(f"wrote {path.relative_to(ROOT)} ({how})")


def bin_arches(pkgbuild: pathlib.Path) -> list[str]:
    """The architectures the -bin PKGBUILD carries a checksum for."""
    found = re.findall(r"^sha256sums_(\w+)=", pkgbuild.read_text(), re.M)
    if not found:
        raise SystemExit(f"{pkgbuild}: no sha256sums_<arch>= lines")
    return found


def load(name: str, path: pathlib.Path):
    """A sibling script as a module: imported by path (gen-ebuild.py has a
    hyphen in its name), and without leaving a __pycache__ in the tree."""
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def gentoo(version: str) -> None:
    gen = load("gen_ebuild", HERE / "gentoo" / "gen-ebuild.py")
    written = gen.write_ebuild(version, gen.lock_at_tag(version))
    # One ebuild at a time: the overlay instructions copy the one that is here.
    for old in written.parent.glob(f"{CRATE}-*.ebuild"):
        if old != written:
            old.unlink()
            print(f"removed {old.relative_to(ROOT)}")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <version>", file=sys.stderr)
        return 2
    version = argv[1].removeprefix("v")
    if not VERSION.match(version):
        print(f"{version!r} is not a version like 0.0.15", file=sys.stderr)
        return 2

    # Every read before any write, so a release that is only half published
    # leaves the tree as it was rather than half bumped.
    source_pkgbuild = HERE / "aur" / CRATE / "PKGBUILD"
    bin_pkgbuild = HERE / "aur" / f"{CRATE}-bin" / "PKGBUILD"
    source_sums = {"sha256sums": crate_sha256(version)}
    bin_sums = {
        f"sha256sums_{arch}": tarball_sha256(version, arch)
        for arch in bin_arches(bin_pkgbuild)
    }

    bump_pkgbuild(source_pkgbuild, version, source_sums)
    bump_pkgbuild(bin_pkgbuild, version, bin_sums)
    gentoo(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
