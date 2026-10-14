#!/usr/bin/env python3
"""Print one version's section of CHANGELOG.md, as a GitHub release body.

    scripts/changelog-section.py 0.2.0            # or v0.2.0
    scripts/changelog-section.py 0.1.0-rc.1 path/to/CHANGELOG.md

The release workflow runs this twice over: in `verify-version`, where a
missing section fails the release before anything is built, and for the
body of the GitHub release itself. The changelog is the release notes this
project actually writes; GitHub's generated ones are a list of commit
titles, which is a different and worse document.

A release candidate is looked up by its full version. Every candidate so
far has had its own `## [0.1.0-rc.1]` section, and that is the convention:
the notes for a candidate say what is being tried out, so a candidate tag
with no section of its own is the same mistake as a release without one,
not something to paper over by borrowing the final version's text.

Exits non-zero, with the reason on stderr, when there is no `## [<version>]`
heading, or when the section under it is empty. `## [Unreleased]` is never
a release.

The section is printed with its hard-wrapped paragraphs and list items
joined into single lines. CHANGELOG.md wraps at ~90 columns for reading in
a terminal; GitHub renders a release body the way it renders a comment, in
which every newline is a line break, so the wrapped text would come out
ragged. Fenced code blocks are left exactly as written.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# A line that starts a new Markdown block, and so must not be joined onto
# the line before it: a heading, a list item, a quote, a table row, a fence.
BLOCK_START = re.compile(r"^\s*(#|[-*+]\s|\d+[.)]\s|>|\||```)")
FENCE = re.compile(r"^\s*```")


def section(text: str, version: str) -> list[str]:
    """The lines under `## [version]`, up to the next `## ` heading or the
    link definitions at the end of the file."""
    heading = re.compile(rf"^## \[{re.escape(version)}\](\s|$)")
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if heading.match(line):
            break
    else:
        raise SystemExit(
            f"CHANGELOG.md has no `## [{version}]` heading. Move the Unreleased "
            "section under it (RELEASING.md step 2) before tagging."
        )

    body = []
    for line in lines[i + 1 :]:
        # The next release's heading, or `[0.1.1]: https://...` — the link
        # definitions that follow the oldest section.
        if line.startswith("## ") or re.match(r"^\[[^\]]+\]: \S", line):
            break
        body.append(line)
    return body


def unwrap(lines: list[str]) -> list[str]:
    """Join hard-wrapped continuation lines onto the line they continue."""
    out: list[str] = []
    in_fence = False
    for line in lines:
        if FENCE.match(line):
            in_fence = not in_fence
            out.append(line)
            continue
        joinable = (
            not in_fence
            and out
            and out[-1].strip()
            and not FENCE.match(out[-1])
            and line.strip()
            and not BLOCK_START.match(line)
        )
        if joinable:
            out[-1] = f"{out[-1].rstrip()} {line.strip()}"
        else:
            out.append(line.rstrip())
    return out


def compare_link(text: str, version: str) -> str | None:
    """The `[version]: <url>` compare link, if the changelog has one. The
    oldest version's definition points at its own release page instead,
    which is where this text is going, so it is not repeated there."""
    match = re.search(rf"^\[{re.escape(version)}\]: (\S+/compare/\S+)$", text, re.M)
    return match.group(1) if match else None


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(f"usage: {argv[0]} <version> [CHANGELOG.md]", file=sys.stderr)
        return 2
    version = argv[1].removeprefix("v")
    if version.lower() == "unreleased":
        print("Unreleased is not a version", file=sys.stderr)
        return 2
    path = pathlib.Path(argv[2]) if len(argv) == 3 else ROOT / "CHANGELOG.md"
    text = path.read_text()

    body = "\n".join(unwrap(section(text, version))).strip()
    if not body:
        raise SystemExit(f"CHANGELOG.md's `## [{version}]` section is empty.")

    link = compare_link(text, version)
    if link:
        body += f"\n\n**Full diff:** {link}"
    print(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
