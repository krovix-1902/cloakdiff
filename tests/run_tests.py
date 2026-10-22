#!/usr/bin/env python3
"""
Starts the mock server, runs cloakdiff against the five test pages and
asserts the verdicts. Two of the five should be caught, three should
come back clean.

    python3 tests/run_tests.py
"""

import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = "http://127.0.0.1:8111"

EXPECTED = {
    "/cloak": "cloaked",       # server-side, keyed on UA and Accept-Language
    "/jscloak": "cloaked",     # client-side, swaps the DOM after load
    "/benign": "clean",        # identical for everyone
    "/dynamic": "clean",       # noisy but not cloaked, the false-positive trap
    "/responsive": "clean",    # legitimately different layout on mobile
}


def wait_for_server(timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(BASE + "/benign", timeout=1).read()
            return True
        except Exception:
            time.sleep(0.3)
    return False


def main() -> int:
    server = subprocess.Popen([sys.executable, str(ROOT / "tests" / "mockserver.py")],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_for_server():
            print("mock server did not start", file=sys.stderr)
            return 1

        urls_file = ROOT / "tests" / "urls.txt"
        urls_file.write_text("\n".join(BASE + p for p in EXPECTED) + "\n")

        report = ROOT / "tests" / "report.json"
        subprocess.run(
            [sys.executable, str(ROOT / "cloakdiff.py"),
             "--urls", str(urls_file),
             "--out", str(report),
             "--screenshots", str(ROOT / "tests" / "shots")],
            check=True,
        )

        data = json.loads(report.read_text())
        failures = []
        print()
        for result in data["results"]:
            path = result["url"].replace(BASE, "")
            want, got = EXPECTED[path], result["verdict"]
            mark = "PASS" if want == got else "FAIL"
            if want != got:
                failures.append(f"{path}: expected {want}, got {got}")
            raw = max((c["text_divergence_raw"] for c in result["comparisons"]), default=0)
            print(f"{mark}  {path:<12} verdict={got:<10} score={result['score']:<8} "
                  f"max_raw_text_div={raw:<8} noise={result['noise_floor']}")

        print()
        if failures:
            for f in failures:
                print("FAILED:", f, file=sys.stderr)
            return 1
        print(f"All {len(EXPECTED)} cases passed.")
        return 0
    finally:
        server.terminate()
        server.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
