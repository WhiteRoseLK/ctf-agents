import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ctf_cli  # noqa: E402


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class SaveConfigPermsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.join(self.tmp.name, "ctf")
        self.file = os.path.join(self.dir, "config.json")
        for name, val in (("CONFIG_FILE", self.file),):
            p = mock.patch.object(ctf_cli, name, val)
            p.start()
            self.addCleanup(p.stop)

    def test_creates_dir_700_and_file_600(self):
        ctf_cli.save_config({"token": "x"})
        self.assertEqual(mode(self.dir), 0o700)
        self.assertEqual(mode(self.file), 0o600)
        self.assertEqual(ctf_cli.load_config(), {"token": "x"})

    def test_fixes_preexisting_644_file_and_755_dir(self):
        os.makedirs(self.dir, mode=0o755)
        os.chmod(self.dir, 0o755)
        with open(self.file, "w") as f:
            f.write("{}")
        os.chmod(self.file, 0o644)
        ctf_cli.save_config({"token": "y"})
        self.assertEqual(mode(self.file), 0o600)
        self.assertEqual(mode(self.dir), 0o700)

    def test_file_never_world_readable_at_creation(self):
        seen = {}
        real_open = os.open

        def spy(path, flags, m=0o777, *a, **k):
            if path == self.file:
                seen["mode"] = m
            return real_open(path, flags, m, *a, **k)

        with mock.patch("os.open", spy):
            ctf_cli.save_config({"token": "z"})
        self.assertEqual(seen["mode"], 0o600)


if __name__ == "__main__":
    unittest.main()
