import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ctf_cli  # noqa: E402
import sudocrypt_cli  # noqa: E402


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class SymlinkTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_dir_symlink_target_not_chmodded(self):
        target = os.path.join(self.tmp.name, "real")
        os.mkdir(target, 0o755)
        link = os.path.join(self.tmp.name, "ctf")
        os.symlink(target, link)
        with mock.patch.object(ctf_cli, "CONFIG_FILE", os.path.join(link, "config.json")):
            ctf_cli.save_config({"a": 1})
        self.assertEqual(mode(target), 0o755)
        self.assertEqual(mode(os.path.join(target, "config.json")), 0o600)

    def test_file_symlink_not_followed(self):
        d = os.path.join(self.tmp.name, "ctf")
        os.mkdir(d, 0o700)
        victim = os.path.join(self.tmp.name, "victim")
        with open(victim, "w") as f:
            f.write("keep")
        cfg = os.path.join(d, "config.json")
        os.symlink(victim, cfg)
        with mock.patch.object(ctf_cli, "CONFIG_FILE", cfg):
            with self.assertRaises(OSError):
                ctf_cli.save_config({"a": 1})
        with open(victim) as f:
            self.assertEqual(f.read(), "keep")


class SudocryptModeTest(unittest.TestCase):
    def test_created_0600_from_the_start(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, "sudocrypt_config.json")
            seen = {}
            real_open = os.open

            def spy(path, flags, m=0o777, *a, **k):
                if path == cfg:
                    seen["mode"] = m
                return real_open(path, flags, m, *a, **k)

            with mock.patch.object(sudocrypt_cli, "CONFIG_FILE", cfg), mock.patch("os.open", spy):
                sudocrypt_cli.save_config({"session_id": "x"})
            self.assertEqual(seen["mode"], 0o600)
            self.assertEqual(mode(cfg), 0o600)

    def test_fixes_preexisting_644(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, "sudocrypt_config.json")
            with open(cfg, "w") as f:
                f.write("{}")
            os.chmod(cfg, 0o644)
            with mock.patch.object(sudocrypt_cli, "CONFIG_FILE", cfg):
                sudocrypt_cli.save_config({"session_id": "x"})
            self.assertEqual(mode(cfg), 0o600)


if __name__ == "__main__":
    unittest.main()
