#!/usr/bin/env python

from subprocess import run
import sys

# Check if we're not cpython - Exit cleanly if so
if sys.implementation.name != "cpython":
    sys.exit(0)

# We only want to install if we're cpython too
install_success = run("pip install mypy", shell=True).returncode
if install_success:
    print("mypy install failed", file=sys.stderr)
    sys.exit(install_success)

sys.exit(run("mypy aiodns", shell=True).returncode)
