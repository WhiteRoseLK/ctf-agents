import http.server
import os
import shutil
import ssl
import sys
import tempfile
import threading
import unittest
import urllib.error
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


class InsecureRedirectTest(unittest.TestCase):
    def test_insecure_instance_refuses_cross_origin_redirect(self):
        target = _Server(lambda r: (200, {}))
        origin = _Server(lambda r: (302, {"Location": target.url + "/x"}))
        self.addCleanup(target.close)
        self.addCleanup(origin.close)
        req = urllib.request.Request(origin.url, headers={"Authorization": "Bearer S"})
        ctx = ssl.create_default_context()
        with self.assertRaises(urllib.error.HTTPError):
            ctf_cli.open_url(req, 5, ctx, block_cross_origin=True)
        self.assertEqual(target.seen, [])


class DownloadTokenTest(unittest.TestCase):
    def test_token_not_sent_to_foreign_file_host(self):
        foreign = _Server(lambda r: (200, {}))
        self.addCleanup(foreign.close)
        info = {"files": [foreign.url + "/f.txt"]}
        dest = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dest, True)
        with mock.patch.object(ctf_cli, "ctfd_info", return_value=info), \
                mock.patch.object(ctf_cli, "load_config", return_value={}):
            ctf_cli.ctfd_download("http://ctf.example.invalid", "TOKEN", 1, dest)
        self.assertEqual(len(foreign.seen), 1)
        self.assertNotIn("authorization", foreign.seen[0])
        self.assertNotIn("cookie", foreign.seen[0])

    def test_token_sent_to_same_origin_file_host(self):
        srv = _Server(lambda r: (200, {}))
        self.addCleanup(srv.close)
        dest = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dest, True)
        with mock.patch.object(ctf_cli, "ctfd_info", return_value={"files": ["/files/f.txt"]}), \
                mock.patch.object(ctf_cli, "load_config", return_value={}):
            ctf_cli.ctfd_download(srv.url, "TOKEN", 1, dest)
        self.assertEqual(srv.seen[0]["authorization"], "Token TOKEN")


class OriginTest(unittest.TestCase):
    def test_same_origin_compares_scheme_host_port(self):
        self.assertTrue(ctf_cli.same_origin("https://a.io/x", "https://A.io/y"))
        self.assertFalse(ctf_cli.same_origin("https://a.io", "http://a.io"))
        self.assertFalse(ctf_cli.same_origin("https://a.io", "https://a.io:8443"))


class CaFallbackTest(unittest.TestCase):
    def test_loads_system_bundle_when_default_store_empty(self):
        fake = mock.Mock()
        fake.cert_store_stats.return_value = {"x509_ca": 0}
        with mock.patch.object(ssl, "create_default_context", return_value=fake), \
                mock.patch.object(ctf_cli, "_CA_FALLBACKS", ("/nope", __file__)):
            ctf_cli.default_ssl_context()
        fake.load_verify_locations.assert_called_once_with(__file__)


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
            self.assertEqual(ctf_cli._ssl_context("http://ctf.local:8443/api").verify_mode, ssl.CERT_REQUIRED)

    def test_insecure_ignored_for_non_ctfd_platform(self):
        with self._cfg(platform="htb", url="https://labs.hackthebox.com", insecure=True):
            self.assertEqual(ctf_cli._ssl_context("https://labs.hackthebox.com/x").verify_mode, ssl.CERT_REQUIRED)


if __name__ == "__main__":
    unittest.main()
