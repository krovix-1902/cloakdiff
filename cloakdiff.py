#!/usr/bin/env python3
"""
cloakdiff - a small differential crawler for detecting server-side and
client-side cloaking on suspected phishing / lookalike domains.

The idea is the standard split-view one: fetch the same URL as several
different kinds of visitor and compare what comes back. The part that
actually matters is separating a real cloak from a page that simply
renders differently for everyone, so every profile is crawled twice and
the same-profile variation is used as a noise floor.

Usage:
    python3 cloakdiff.py --urls urls.txt --out report.json
    python3 cloakdiff.py --url https://example.com --screenshots shots/

Safety: point this at dead or sandboxed URLs. Live phishing pages serve
live malware and the whole point of the stealth profile is to look like
a real victim.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright, Error as PlaywrightError

# --------------------------------------------------------------------------
# Profiles
#
# Three visitors, chosen so each one varies a different cloaking dimension:
#   plain    - naive headless, what an unconfigured crawler looks like
#   stealth  - desktop user with consistent UA / language / timezone and
#              the obvious headless tells patched out (device vector,
#              behavioural vector)
#   mobile   - iPhone-ish viewport, UA and touch support (device vector)
#
# Not covered here: the IP vector. Separating datacentre from residential
# egress needs proxies, and without that this will miss any cloak keyed on
# ASN, which is a large share of them. Worth being upfront about.
# --------------------------------------------------------------------------

STEALTH_INIT = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'languages', {get: () => ['en-GB', 'en']});
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
window.chrome = window.chrome || {runtime: {}};
const origQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (p) => (
    p.name === 'notifications'
        ? Promise.resolve({state: Notification.permission})
        : origQuery(p)
);
"""

PROFILES = {
    "plain": {
        "context": {
            "user_agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36"
            ),
            "viewport": {"width": 1280, "height": 800},
            "locale": "en-US",
        },
        "init_script": None,
    },
    "stealth": {
        "context": {
            "user_agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "viewport": {"width": 1920, "height": 1080},
            "locale": "en-GB",
            "timezone_id": "Europe/London",
            "extra_http_headers": {
                "Accept-Language": "en-GB,en;q=0.9",
                "Sec-Ch-Ua": '"Chromium";v="120", "Not(A:Brand";v="24"',
            },
        },
        "init_script": STEALTH_INIT,
    },
    "mobile": {
        "context": {
            "user_agent": (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 "
                "Mobile/15E148 Safari/604.1"
            ),
            "viewport": {"width": 390, "height": 844},
            "locale": "en-GB",
            "timezone_id": "Europe/London",
            "is_mobile": True,
            "has_touch": True,
            "device_scale_factor": 3,
            "extra_http_headers": {"Accept-Language": "en-GB,en;q=0.9"},
        },
        "init_script": STEALTH_INIT,
    },
}

# --------------------------------------------------------------------------
# Normalisation
#
# Pages legitimately carry per-request noise: timestamps, CSRF tokens,
# session ids, cache-busting params, rotating ad slots. Diffing raw text
# makes every page look cloaked. Strip the obvious offenders before
# comparing.
# --------------------------------------------------------------------------

VOLATILE = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), " UUID "),
    (re.compile(r"\b[0-9a-f]{32,}\b", re.I), " HEX "),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?\b"), " TS "),
    (re.compile(r"\b\d{1,2}:\d{2}(:\d{2})?\s?(am|pm)?\b", re.I), " TIME "),
    (re.compile(r"\b\d{9,}\b"), " BIGNUM "),
    (re.compile(r"\s+"), " "),
]


def normalise(text: str) -> str:
    out = text.lower()
    for pattern, replacement in VOLATILE:
        out = pattern.sub(replacement, out)
    return out.strip()


def tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z]{2,}", normalise(text)))


def jaccard_distance(a: str, b: str) -> float:
    """0.0 = identical vocabulary, 1.0 = nothing in common."""
    ta, tb = tokens(a), tokens(b)
    if not ta and not tb:
        return 0.0
    if not ta or not tb:
        return 1.0
    return 1.0 - len(ta & tb) / len(ta | tb)


# --------------------------------------------------------------------------
# Perceptual hashing
#
# dHash rather than an exact hash: a byte-for-byte screenshot comparison
# flags every page with a carousel on it. dHash compares adjacent pixel
# gradients on a downscaled greyscale image, so it survives small visual
# churn and still moves sharply when the page is genuinely different.
# --------------------------------------------------------------------------

def dhash(path: Path, size: int = 8) -> int:
    with Image.open(path) as img:
        img = img.convert("L").resize((size + 1, size), Image.Resampling.LANCZOS)
        pixels = list(img.tobytes())
    bits = 0
    for row in range(size):
        for col in range(size):
            left = pixels[row * (size + 1) + col]
            right = pixels[row * (size + 1) + col + 1]
            bits = (bits << 1) | int(left > right)
    return bits


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


# --------------------------------------------------------------------------
# Crawl
# --------------------------------------------------------------------------

@dataclass
class Capture:
    profile: str
    run: int
    ok: bool
    final_url: str = ""
    status: int | None = None
    title: str = ""
    text: str = ""
    phash: int | None = None
    screenshot: str = ""
    error: str = ""


@dataclass
class URLResult:
    url: str
    captures: list[Capture] = field(default_factory=list)
    noise_floor: dict = field(default_factory=dict)
    comparisons: list[dict] = field(default_factory=list)
    score: float = 0.0
    verdict: str = "unknown"
    notes: list[str] = field(default_factory=list)


def capture(browser, profile_name: str, url: str, run: int, shot_dir: Path | None,
            timeout_ms: int, settle_ms: int) -> Capture:
    spec = PROFILES[profile_name]
    ctx = browser.new_context(**spec["context"])
    if spec["init_script"]:
        ctx.add_init_script(spec["init_script"])
    page = ctx.new_page()
    cap = Capture(profile=profile_name, run=run, ok=False)
    try:
        response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        cap.status = response.status if response else None
        # Client-side cloaks often swap the DOM after load, so give the page
        # a moment rather than diffing the server's first response.
        page.wait_for_timeout(settle_ms)
        cap.final_url = page.url
        cap.title = page.title()
        cap.text = page.inner_text("body")
        if shot_dir:
            safe = re.sub(r"[^a-z0-9]+", "_", url.lower())[:60]
            shot = shot_dir / f"{safe}__{profile_name}__r{run}.png"
            page.screenshot(path=str(shot), full_page=False)
            cap.screenshot = str(shot)
            cap.phash = dhash(shot)
        cap.ok = True
    except PlaywrightError as exc:
        cap.error = str(exc).splitlines()[0][:200]
    finally:
        ctx.close()
    return cap


# --------------------------------------------------------------------------
# Scoring
#
# Deliberately crude, and the thresholds below are guesses until they are
# calibrated against domains with known outcomes. The useful part is not
# the number, it is that the noise floor is subtracted from it: a page
# that differs between profiles no more than it differs from itself has
# not told us anything.
# --------------------------------------------------------------------------

W_TEXT = 1.00
W_VISUAL = 0.45
W_REDIRECT = 0.35

SUSPICIOUS_AT = 0.10
CLOAKED_AT = 0.32


def analyse(result: URLResult) -> URLResult:
    good = [c for c in result.captures if c.ok]
    by_profile: dict[str, list[Capture]] = {}
    for c in good:
        by_profile.setdefault(c.profile, []).append(c)

    if len(by_profile) < 2:
        result.verdict = "inconclusive"
        result.notes.append("Fewer than two profiles loaded the page.")
        return result

    # Noise floor: how much does this page differ from ITSELF on a repeat
    # visit with the same profile? Anything at or below this is just the
    # page being dynamic.
    text_noise, visual_noise = 0.0, 0
    for profile, caps in by_profile.items():
        if len(caps) >= 2:
            text_noise = max(text_noise, jaccard_distance(caps[0].text, caps[1].text))
            if caps[0].phash is not None and caps[1].phash is not None:
                visual_noise = max(visual_noise, hamming(caps[0].phash, caps[1].phash))
    result.noise_floor = {"text": round(text_noise, 4), "visual_bits": visual_noise}

    names = sorted(by_profile)
    worst = 0.0
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            ca, cb = by_profile[a][0], by_profile[b][0]
            raw_text = jaccard_distance(ca.text, cb.text)
            text_div = max(0.0, raw_text - text_noise)

            if ca.phash is not None and cb.phash is not None:
                raw_bits = hamming(ca.phash, cb.phash)
                bits = max(0, raw_bits - visual_noise)
                visual_div = bits / 64.0
            else:
                raw_bits, visual_div = None, 0.0

            redirect_div = 0.0
            if ca.final_url.split("#")[0] != cb.final_url.split("#")[0]:
                redirect_div = 1.0

            score = (W_TEXT * text_div
                     + W_VISUAL * visual_div
                     + W_REDIRECT * redirect_div)
            worst = max(worst, score)

            result.comparisons.append({
                "pair": f"{a} vs {b}",
                "text_divergence_raw": round(raw_text, 4),
                "text_divergence_adjusted": round(text_div, 4),
                "visual_hamming_raw": raw_bits,
                "visual_divergence_adjusted": round(visual_div, 4),
                "redirect_mismatch": bool(redirect_div),
                "final_urls": [ca.final_url, cb.final_url],
                "titles": [ca.title, cb.title],
                "score": round(score, 4),
            })

    result.score = round(worst, 4)
    if worst >= CLOAKED_AT:
        result.verdict = "cloaked"
    elif worst >= SUSPICIOUS_AT:
        result.verdict = "suspicious"
    else:
        result.verdict = "clean"

    if text_noise > 0.25:
        result.notes.append(
            "High same-profile variation: this page is very dynamic, so the "
            "verdict is weak regardless of score."
        )
    failed = [c for c in result.captures if not c.ok]
    if failed:
        result.notes.append(
            f"{len(failed)} of {len(result.captures)} captures failed: "
            + "; ".join(sorted({f'{c.profile}: {c.error}' for c in failed}))
        )
    return result


def run(urls: list[str], shot_dir: Path | None, runs: int,
        timeout_ms: int, settle_ms: int) -> list[URLResult]:
    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--disable-blink-features=AutomationControlled"])
        try:
            for url in urls:
                res = URLResult(url=url)
                for profile_name in PROFILES:
                    for run_i in range(1, runs + 1):
                        res.captures.append(
                            capture(browser, profile_name, url, run_i,
                                    shot_dir, timeout_ms, settle_ms)
                        )
                results.append(analyse(res))
                print(f"  {res.verdict:<12} {res.score:<7} {url}", file=sys.stderr)
        finally:
            browser.close()
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description="Differential crawler for cloaking detection.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--url", help="a single URL")
    src.add_argument("--urls", help="file with one URL per line")
    ap.add_argument("--out", default="report.json")
    ap.add_argument("--screenshots", default="shots", help="screenshot directory, or '' to skip")
    ap.add_argument("--runs", type=int, default=2,
                    help="captures per profile; 2 or more gives a noise floor")
    ap.add_argument("--timeout", type=int, default=20000)
    ap.add_argument("--settle", type=int, default=2500,
                    help="ms to wait after load, for client-side cloaks")
    args = ap.parse_args()

    if args.url:
        urls = [args.url]
    else:
        urls = [l.strip() for l in Path(args.urls).read_text().splitlines()
                if l.strip() and not l.startswith("#")]

    shot_dir = None
    if args.screenshots:
        shot_dir = Path(args.screenshots)
        shot_dir.mkdir(parents=True, exist_ok=True)

    print(f"Crawling {len(urls)} URL(s) across {len(PROFILES)} profiles, "
          f"{args.runs} run(s) each.", file=sys.stderr)
    results = run(urls, shot_dir, args.runs, args.timeout, args.settle)

    report = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "profiles": list(PROFILES),
        "weights": {"text": W_TEXT, "visual": W_VISUAL, "redirect": W_REDIRECT},
        "thresholds": {"suspicious": SUSPICIOUS_AT, "cloaked": CLOAKED_AT},
        "results": [asdict(r) for r in results],
    }
    for r in report["results"]:
        for c in r["captures"]:
            c["text"] = c["text"][:400]
    Path(args.out).write_text(json.dumps(report, indent=2))

    print(f"\nWrote {args.out}", file=sys.stderr)
    counts: dict[str, int] = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    print("  " + ", ".join(f"{v}: {n}" for v, n in sorted(counts.items())), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
