import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ctf_cli  # noqa: E402


class CsrfNonceTest(unittest.TestCase):
    def test_session_cookie_not_in_curl_argv(self):
        calls = []

        def fake_run(argv, **kw):
            calls.append((argv, kw))
            return mock.Mock(returncode=0, stdout="x csrfNonce': \"abc123\" y")

        with mock.patch.object(ctf_cli.subprocess, "run", side_effect=fake_run), \
                mock.patch.object(ctf_cli, "load_config", return_value={}):
            nonce = ctf_cli.get_ctfd_csrf_nonce("https://ctf.example", "SECRETCOOKIE")
        self.assertEqual(nonce, "abc123")
        argv, kw = calls[0]
        self.assertFalse(any("SECRETCOOKIE" in a for a in argv))
        self.assertIn("SECRETCOOKIE", kw["input"])

    def test_cookie_cannot_inject_curl_directives(self):
        cfg = ctf_cli._curl_header_config("Cookie", 'session=a"b\\c')
        self.assertEqual(cfg, 'header = "Cookie: session=a\\"b\\\\c"\n')
        for bad in ("x\noutput = /tmp/pwn", "x\r", "x\x00"):
            with self.assertRaises(ValueError):
                ctf_cli._curl_header_config("Cookie", bad)

    def test_malicious_cookie_skips_curl_and_never_runs_it(self):
        with mock.patch.object(ctf_cli.subprocess, "run") as run, \
                mock.patch.object(ctf_cli, "load_config", return_value={}), \
                mock.patch.object(ctf_cli, "_urlopen", side_effect=RuntimeError("stop")):
            with self.assertRaises(RuntimeError):
                ctf_cli.get_ctfd_csrf_nonce("https://ctf.example", "a\noutput = /tmp/pwn")
        run.assert_not_called()

    def test_k_present_only_when_insecure(self):
        calls = []
        fake = lambda a, **k: calls.append(a) or mock.Mock(returncode=0, stdout="csrfNonce': \"ab\"")
        with mock.patch.object(ctf_cli.subprocess, "run", side_effect=fake), \
                mock.patch.object(ctf_cli, "_insecure_allowed", return_value=True):
            ctf_cli.get_ctfd_csrf_nonce("https://ctf.example", "C")
        self.assertIn("-k", calls[0])

    def test_k_only_when_insecure(self):
        calls = []
        with mock.patch.object(ctf_cli.subprocess, "run",
                               side_effect=lambda a, **k: calls.append(a) or mock.Mock(returncode=0, stdout="csrfNonce': \"ab\"")), \
                mock.patch.object(ctf_cli, "load_config", return_value={}):
            ctf_cli.get_ctfd_csrf_nonce("https://ctf.example", "C")
        self.assertNotIn("-k", calls[0])


if __name__ == "__main__":
    unittest.main()
