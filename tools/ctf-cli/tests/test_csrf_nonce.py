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

    def test_k_only_when_insecure(self):
        calls = []
        with mock.patch.object(ctf_cli.subprocess, "run",
                               side_effect=lambda a, **k: calls.append(a) or mock.Mock(returncode=0, stdout="csrfNonce': \"ab\"")), \
                mock.patch.object(ctf_cli, "load_config", return_value={}):
            ctf_cli.get_ctfd_csrf_nonce("https://ctf.example", "C")
        self.assertNotIn("-k", calls[0])


if __name__ == "__main__":
    unittest.main()
