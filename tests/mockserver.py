#!/usr/bin/env python3
"""
A local test harness for cloakdiff. Serves four pages:

  /cloak      - server-side cloak. Headless UA or missing Accept-Language
                gets a parked-domain page; anyone else gets the credential
                phish. This is the one that must be caught.
  /jscloak    - client-side cloak. Everyone gets the same HTML; JavaScript
                swaps the body to the phish after load unless it detects
                navigator.webdriver. Catches crawlers that only diff the
                server response.
  /benign     - identical for everyone. Must come back clean.
  /dynamic    - identical layout, fresh timestamps / session ids / rotating
                quote on every single request. Must come back clean, which
                is what the noise floor is for.
  /responsive - genuinely responsive: different layout for mobile widths,
                same content. The honest hard case, since this is exactly
                what a naive differ flags as a cloak.
"""

import random
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PHISH = """<!doctype html><html><head><title>Secure Account Verification</title></head>
<body style="font-family:sans-serif;background:#fff">
<h1>Verify your banking details</h1>
<p>Your account has been suspended pending verification. Enter your
credentials and card number to restore access immediately.</p>
<form><input placeholder="Username"><input placeholder="Password" type="password">
<input placeholder="Card number"><button>Restore access</button></form>
<p>Failure to verify within 24 hours will result in permanent closure.</p>
</body></html>"""

DECOY = """<!doctype html><html><head><title>Domain parked</title></head>
<body style="font-family:sans-serif;background:#fff">
<h1>This domain is parked</h1>
<p>This web address has been registered and is not currently in use.
Enquiries about purchasing the domain are welcome.</p>
</body></html>"""

BENIGN = """<!doctype html><html><head><title>Oxford Tile Supplies</title></head>
<body style="font-family:sans-serif;background:#fff">
<h1>Oxford Tile Supplies</h1>
<p>Family run since 1974. Ceramic, porcelain and natural stone tiles for
kitchens, bathrooms and conservatories across Oxfordshire.</p>
<p>Visit our showroom on Botley Road, open Monday to Saturday.</p>
</body></html>"""

JS_CLOAK = """<!doctype html><html><head><title>Loading</title></head>
<body style="font-family:sans-serif;background:#fff">
<div id="c"><h1>Loading your document</h1><p>Please wait.</p></div>
<script>
setTimeout(function () {
  var bot = navigator.webdriver === true
         || /HeadlessChrome/.test(navigator.userAgent);
  if (!bot) {
    document.getElementById('c').innerHTML =
      '<h1>Sign in to view this document</h1>' +
      '<p>Enter your email password to open the shared file.</p>' +
      '<form><input placeholder="Email"><input type="password" ' +
      'placeholder="Password"><button>Open document</button></form>';
    document.title = 'Sign in to continue';
  }
}, 600);
</script>
</body></html>"""

QUOTES = [
    "Tiles arrived next day, very pleased.",
    "Great range and helpful staff in the showroom.",
    "Good prices compared with the big chains.",
    "Second time ordering, no complaints at all.",
]


def dynamic() -> str:
    return f"""<!doctype html><html><head><title>Oxford Tile Supplies</title></head>
<body style="font-family:sans-serif;background:#fff">
<h1>Oxford Tile Supplies</h1>
<p>Family run since 1974. Ceramic, porcelain and natural stone tiles.</p>
<p>Customer review: {random.choice(QUOTES)}</p>
<p>Page generated {datetime.now().isoformat(timespec='seconds')}</p>
<p>Session {uuid.uuid4()}</p>
<p>Basket token {uuid.uuid4().hex}</p>
</body></html>"""


RESPONSIVE = """<!doctype html><html><head><title>Oxford Tile Supplies</title>
<style>
  nav.desktop {display:block} nav.mobile {display:none}
  .cols {display:flex;gap:20px}
  @media (max-width: 600px) {
    nav.desktop {display:none} nav.mobile {display:block}
    .cols {display:block}
  }
</style></head>
<body style="font-family:sans-serif;background:#fff">
<nav class="desktop">Home | Kitchens | Bathrooms | Natural stone | Showroom | Contact</nav>
<nav class="mobile">Menu</nav>
<h1>Oxford Tile Supplies</h1>
<div class="cols">
  <div><h2>Kitchens</h2><p>Splashbacks and floor tiles.</p></div>
  <div><h2>Bathrooms</h2><p>Wet room and wall tiles.</p></div>
  <div><h2>Natural stone</h2><p>Limestone, slate and marble.</p></div>
</div>
<p>Family run since 1974, showroom on Botley Road.</p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, body: str):
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        ua = self.headers.get("User-Agent", "")
        lang = self.headers.get("Accept-Language", "")
        path = self.path.split("?")[0]

        if path == "/cloak":
            looks_like_a_crawler = "HeadlessChrome" in ua or not lang
            self._send(DECOY if looks_like_a_crawler else PHISH)
        elif path == "/jscloak":
            self._send(JS_CLOAK)
        elif path == "/benign":
            self._send(BENIGN)
        elif path == "/dynamic":
            self._send(dynamic())
        elif path == "/responsive":
            self._send(RESPONSIVE)
        else:
            self._send("<h1>404</h1>")


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8111), Handler)
    print("mock server on http://127.0.0.1:8111", flush=True)
    server.serve_forever()
