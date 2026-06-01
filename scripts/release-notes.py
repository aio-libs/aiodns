#!/usr/bin/env python3
r"""
Generate release notes for the current release.

Reads the version from ``aiodns/__init__.py`` and the matching section from
``ChangeLog``. Fails if they disagree, or if a ``--target`` is supplied and
does not match the current state on disk.

Run after the "Release X.Y.Z" PR has been merged into master, e.g.::

    python scripts/release-notes.py --target 4.0.1 \\
        | gh release create v4.0.1 --repo aio-libs/aiodns \\
              --title v4.0.1 --notes-file -
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

VERSION_RE = re.compile(r"^__version__\s*=\s*['\"]([^'\"]+)['\"]", re.M)
HEADER_RE = re.compile(r'^(\d+\.\d+\.\d+[a-z0-9.\-]*)\s*\n=+\s*$', re.M)


def read_version() -> str:
    text = (ROOT / 'aiodns' / '__init__.py').read_text()
    match = VERSION_RE.search(text)
    if not match:
        sys.exit('could not find __version__ in aiodns/__init__.py')
    return match.group(1)


def read_top_changelog_section() -> tuple[str, str]:
    text = (ROOT / 'ChangeLog').read_text()
    matches = list(HEADER_RE.finditer(text))
    if not matches:
        sys.exit('no version headers found in ChangeLog')
    top = matches[0]
    body_end = matches[1].start() if len(matches) > 1 else len(text)
    body = text[top.end() : body_end].strip('\n')
    return top.group(1), body


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        '--target',
        help='Expected version; abort if __version__/ChangeLog disagree.',
    )
    args = parser.parse_args()

    version = read_version()
    cl_version, cl_body = read_top_changelog_section()

    if version != cl_version:
        sys.exit(
            f'__version__ is {version!r} but the top ChangeLog section is '
            f'{cl_version!r}; did the release PR land?'
        )
    if args.target and args.target != version:
        sys.exit(
            f'--target {args.target!r} does not match current release '
            f'{version!r}; check out master after the release PR merges.'
        )

    print(cl_body)
    return 0


if __name__ == '__main__':
    sys.exit(main())
