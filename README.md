# cloakdiff

A small differential crawler for detecting cloaking on suspected phishing and
lookalike domains.

Cloaked phishing sites serve one page to security scanners and another to
victims. Any detection pipeline that leans on what the crawler saw, visual
matching especially, is then scoring a page that was never shown to anybody.
The classifier isn't wrong, it was handed the wrong input.

The standard answer is split-view crawling: fetch the same URL as several
different kinds of visitor and compare. The part that actually decides whether
this is usable is telling a real cloak apart from a page that simply renders
differently every time, so that is what most of this code is about.

## How it works

Each URL is fetched by three profiles, each varying a different cloaking
vector:

| Profile | What it looks like | Vector |
| --- | --- | --- |
| `plain` | unconfigured headless Chrome, `HeadlessChrome` UA, no `Accept-Language` | the naive crawler, i.e. the control |
| `stealth` | Windows Chrome UA with matching locale, timezone and client hints, `navigator.webdriver` and friends patched out | device + behavioural |
| `mobile` | iPhone UA, 390x844 viewport, touch enabled | device |

Every profile is crawled twice. The difference between a profile and *itself*
is the noise floor, and it gets subtracted before anything is scored. A page
that varies by profile no more than it varies run to run has told us nothing.

Three divergence signals per pair:

- **Text.** Jaccard distance over the visible body text, after stripping
  volatile tokens (UUIDs, hex blobs, timestamps, long numbers).
- **Visual.** Hamming distance between 64-bit dHash perceptual hashes of the
  screenshots. Perceptual rather than exact, because a byte comparison flags
  every page with a carousel on it.
- **Redirect.** Whether the profiles ended up on different final URLs.

These are combined into a weighted score, and a page is called clean,
suspicious or cloaked. **The thresholds are guesses.** They're calibrated
against the test set below, not against domains with known outcomes, and they
would need redoing properly against real labelled data.

## Results on the test set

`tests/mockserver.py` serves five pages: two cloaks that should be caught, and
three controls that should not be. Run `python3 tests/run_tests.py`.

| Page | Verdict | Score | Max raw text divergence | Noise floor |
| --- | --- | --- | --- | --- |
| `/cloak` server-side, keyed on UA and `Accept-Language` | **cloaked** | 0.949 | 0.907 | 0.0 |
| `/jscloak` client-side, swaps the DOM after load | **cloaked** | 0.889 | 0.882 | 0.0 |
| `/benign` identical for everyone | clean | 0.028 | 0.0 | 0.0 |
| `/dynamic` fresh timestamps, session ids, rotating review | clean | 0.021 | **0.387** | 0.387 |
| `/responsive` genuinely different mobile layout | clean | 0.042 | 0.0 | 0.0 |

`/dynamic` is the interesting row. Its raw text divergence is 0.387, which
would have been called cloaked by a straight diff. The same-profile baseline is
also 0.387, so after subtraction it scores 0.021 and comes back clean. That is
the whole argument for crawling twice.

`/jscloak` is the case a server-side differ misses entirely: identical HTML to
everyone, with JavaScript swapping in the credential form after load unless it
spots `navigator.webdriver`. Catching it needs a real browser and a wait after
load, not just a fetch.

On `/cloak`, `stealth` and `mobile` agree with each other and only `plain`
diverges, which is the correct shape: two profiles that look like real people
saw the same thing, and the naive crawler got the decoy.

## What this does not do

- **No IP vector.** Separating datacentre from residential or mobile egress
  needs proxies. Any cloak keyed on ASN is invisible here, and that's a large
  share of them in the wild. This is the biggest gap.
- **No geo vector** beyond the locale header.
- **Thresholds aren't calibrated** against ground truth, as above.
- **It can be beaten.** The stealth profile patches the obvious headless
  tells; it won't survive a commercial anti-bot stack doing canvas or WebGL
  fingerprinting or timing analysis.
- **Three profiles is not coverage.** The cloaking vectors are roughly
  independent, so real coverage means something closer to the full product of
  profiles, which is exactly what makes this too expensive to run on
  everything and why triage is the actual problem.

## Running it

```bash
pip install playwright pillow
python3 -m playwright install chromium

python3 cloakdiff.py --url https://example.com
python3 cloakdiff.py --urls urls.txt --out report.json --screenshots shots/
python3 tests/run_tests.py
```

Options: `--runs` (captures per profile, 2+ gives the noise floor), `--settle`
(ms to wait after load for client-side cloaks), `--timeout`.

### Safety

Point this at dead or sandboxed URLs. Live phishing pages serve live malware,
and the stealth profile exists specifically to make the site think you are a
real victim. Use a throwaway VM with no saved credentials and nothing shared
with the host.

## Notes

Built in a day as a proof of concept, with AI assistance. Written to find out
where the hard parts actually are rather than to be a finished tool, and the
answer was that the crawling is easy and the threshold is not.
