from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
import os
from functools import partial

PORT = int(os.environ.get("PORT", "8765"))
HOST = os.environ.get("HOST", "127.0.0.1")
LANDING_DIR = os.path.dirname(os.path.abspath(__file__))

class Handler(SimpleHTTPRequestHandler):
    extensions_map = {**SimpleHTTPRequestHandler.extensions_map, ".woff2": "font/woff2"}
    def end_headers(self):
        self.send_header("Cache-Control", "no-cache")
        super().end_headers()

if __name__ == "__main__":
    handler_factory = partial(Handler, directory=LANDING_DIR)
    print(f"Starting Landing Page server on http://{HOST}:{PORT} (serving {LANDING_DIR})...")
    ThreadingHTTPServer((HOST, PORT), handler_factory).serve_forever()
