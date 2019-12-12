#!/usr/bin/env python

from subprocess import run
import sys

# Check if we're not cpython - Exit cleanly if so
if sys.implementation.name != "cpython":
    sys.exit(0)

sys.exit(run("mypy aiodns", shell=True).returncode)
