import http.server
import os
import ssl
import sys
import threading
import unittest
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ctf_cli  # noqa: E402


class _Server:
    """Petit serveur HTTP local ; `handler(req)` -> (status, headers)."""

    def __init__(self, handler):
        seen = self.seen = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append({k.lower(): v for k, v in self.headers.items()})
                status, headers = handler(self)
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *a):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class RedirectTest(unittest.TestCase):
    def _fetch(self, url):
        req = urllib.request.Request(url, headers={
            "Authorization": "Bearer SECRET", "Cookie": "session=SECRET", "CSRF-Token": "SECRET"})
        return ctf_cli._urlopen(req, timeout=5).read()

    def test_cross_host_redirect_strips_credentials(self):
        target = _Server(lambda r: (200, {}))
        origin = _Server(lambda r: (302, {"Location": target.url + "/x"}))
        self.addCleanup(target.close)
        self.addCleanup(origin.close)
        self._fetch(origin.url + "/start")
        self.assertIn("authorization", origin.seen[0])
        self.assertEqual(len(target.seen), 1)
        for h in ("authorization", "cookie", "csrf-token"):
            self.assertNotIn(h, target.seen[0])

    def test_same_host_redirect_keeps_credentials(self):
        box = {}
        srv = _Server(lambda r: (302, {"Location": box["u"] + "/b"}) if r.path == "/a" else (200, {}))
        box["u"] = srv.url
        self.addCleanup(srv.close)
        self._fetch(srv.url + "/a")
        self.assertEqual(srv.seen[1]["authorization"], "Bearer SECRET")


class TlsContextTest(unittest.TestCase):
    def _cfg(self, **active):
        return mock.patch.object(ctf_cli, "load_config", return_value={"active": active})

    def test_verifies_certificates_by_default(self):
        with self._cfg():
            ctx = ctf_cli._ssl_context("https://labs.hackthebox.com/api")
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    def test_insecure_only_for_flagged_ctfd_host(self):
        active = {"platform": "ctfd", "url": "https://ctf.local:8443", "insecure": True}
        with self._cfg(**active):
            self.assertEqual(ctf_cli._ssl_context("https://ctf.local:8443/api").verify_mode, ssl.CERT_NONE)
            self.assertEqual(ctf_cli._ssl_context("https://other.example/api").verify_mode, ssl.CERT_REQUIRED)

    def test_insecure_ignored_for_non_ctfd_platform(self):
        with self._cfg(platform="htb", url="https://labs.hackthebox.com", insecure=True):
            self.assertEqual(ctf_cli._ssl_context("https://labs.hackthebox.com/x").verify_mode, ssl.CERT_REQUIRED)


if __name__ == "__main__":
    unittest.main()
