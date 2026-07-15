#!/usr/bin/env python3
import pathlib
import resource
import subprocess
import sys
import time

if len(sys.argv) < 3:
    raise SystemExit("usage: timed.py SORTIE COMMANDE [ARG ...]")

started = time.monotonic()
completed = subprocess.run(sys.argv[2:], check=False)
elapsed = time.monotonic() - started
rss_kib = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
pathlib.Path(sys.argv[1]).write_text(f"{elapsed:.6f} {rss_kib}\n")
raise SystemExit(completed.returncode)
