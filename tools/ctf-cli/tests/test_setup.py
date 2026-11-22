import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import setup_challenge as sc  # noqa: E402


def read(path):
    with open(path) as f:
        return f.read()


class SlugTest(unittest.TestCase):
    def test_slug_segment(self):
        self.assertEqual(sc.slug_segment("Mobile"), "Mobile")
        self.assertEqual(sc.slug_segment("Web Exploitation"), "Web_Exploitation")
        self.assertEqual(sc.slug_segment("Réseau"), "Reseau")
        self.assertEqual(sc.slug_segment("C++ & Co/Pwn"), "C_Co_Pwn")
        self.assertEqual(sc.slug_segment("-rf"), "rf")

    def test_unusable_segment_rejected(self):
        for bad in ("", "..", "///", "___", "-", "‽"):
            with self.assertRaises(ValueError, msg=bad):
                sc.slug_segment(bad)


class DestTest(unittest.TestCase):
    def test_permanent_platform(self):
        d = sc.compute_dest("htb", "Mobile", "APKey")
        self.assertEqual(d, "HackTheBox/Mobile/APKey")

    def test_new_category_needs_no_code_change(self):
        self.assertEqual(sc.compute_dest("htb", "Quantum Stuff", "Q 1"), "HackTheBox/Quantum_Stuff/Q_1")

    def test_event(self):
        self.assertEqual(sc.compute_dest("ctfd", "Web", "Easy One", event="THCon", year="2026"),
                         "THCon/2026/Web/Easy_One")

    def test_ctfd_requires_event(self):
        with self.assertRaises(ValueError):
            sc.compute_dest("ctfd", "Web", "X")

    def test_dest_matches_export_regex(self):
        d = sc.compute_dest("rootme", "App - Script", "SQL Injection - Authentication")
        self.assertRegex(d, r"^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$")


class NormalizeTest(unittest.TestCase):
    def test_htb_with_instance(self):
        info = {"name": "APKey", "category_name": "Mobile", "difficulty": "Easy", "points": 20,
                "description": "Find the key", "solves": 12, "download": True, "file_name": "a.zip",
                "docker": True, "docker_ip": "83.136.1.2", "docker_ports": [31337]}
        m = sc.normalize("htb", info)
        self.assertEqual((m["name"], m["category"], m["difficulty"], m["points"]), ("APKey", "Mobile", "Easy", "20"))
        self.assertEqual(m["files"], ["a.zip"])
        self.assertEqual(m["connection"], ["83.136.1.2:31337"])

    def test_htb_category_from_id_mapping(self):
        m = sc.normalize("htb", {"name": "X", "challenge_category_id": 4}, categories={4: "Hardware"})
        self.assertEqual(m["category"], "Hardware")

    def test_htb_instance_address_from_play_info(self):
        m = sc.normalize("htb", {"name": "X", "category_name": "Web", "docker": True,
                                 "play_info": {"ip": "5.6.7.8", "ports": [80, 443]}})
        self.assertEqual(m["connection"], ["5.6.7.8:80", "5.6.7.8:443"])

    def test_htb_docker_without_address(self):
        m = sc.normalize("htb", {"name": "X", "category_name": "Web", "docker": True})
        self.assertEqual(m["connection"], [])
        self.assertTrue(m["instance_to_start"])

    def test_ctfd(self):
        info = {"name": "Warmup", "category": "crypto", "value": 50, "type": "dynamic", "description": "d",
                "connection_info": "nc ctf.example 1337", "files": ["/files/a/b.zip?token=1"]}
        m = sc.normalize("ctfd", info)
        self.assertEqual((m["category"], m["points"], m["type"]), ("crypto", "50", "dynamic"))
        self.assertEqual(m["connection"], ["nc ctf.example 1337"])
        self.assertEqual(m["files"], ["b.zip"])

    def test_untrusted_values_are_cleaned(self):
        m = sc.normalize("ctfd", {"name": "X", "category": "W\x00eb", "connection_info": "a\nb\x1b[31m"})
        self.assertNotRegex(m["category"] + "".join(m["connection"]), r"[\x00-\x08\x0b-\x1f\x7f]")


META = {"platform": "htb", "name": "APKey", "category": "Mobile", "type": "Challenge", "difficulty": "Easy",
        "points": 20, "description": "Find the key\n---\n# Heading <script>", "solves": 3,
        "files": ["a.zip"], "connection": ["1.2.3.4:80"], "instance_to_start": False}


class RenderTest(unittest.TestCase):
    def test_sheet_has_status_tag_and_data(self):
        out = sc.render_sheet(META, "HackTheBox/Mobile/APKey")
        self.assertIn("status: en-cours", out)
        self.assertIn("#en-cours", out)
        self.assertIn("**Category:** Mobile", out)
        self.assertIn("1.2.3.4:80", out)
        self.assertIn("a.zip", out)
        self.assertIn("#htb", out)

    def test_description_is_quoted_not_interpreted(self):
        out = sc.render_sheet(META, "HackTheBox/Mobile/APKey")
        for line in ("---", "# Heading <script>"):
            self.assertNotIn("\n" + line + "\n", out.split("Description")[-1].split("## Connexion")[0])
        self.assertNotIn("<script>", out)

    def test_set_status(self):
        out = sc.render_sheet(META, "x")
        new = sc.set_status(out, "resolu")
        self.assertIn("status: resolu", new)
        self.assertIn("#resolu", new)
        self.assertNotIn("#en-cours", new)
        with self.assertRaises(ValueError):
            sc.set_status(out, "bizarre")


class WriteTest(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.vault = os.path.join(self.t.name, "vault")
        os.mkdir(self.vault)

    def test_writes_sheet_at_dest(self):
        p = sc.write_sheet(self.vault, "HackTheBox/Mobile/APKey", "APKey", "content")
        self.assertEqual(p, os.path.join(self.vault, "HackTheBox/Mobile/APKey/APKey.md"))
        self.assertEqual(read(p), "content")

    def test_never_overwrites(self):
        sc.write_sheet(self.vault, "A/B/C", "C", "one")
        with self.assertRaises(FileExistsError):
            sc.write_sheet(self.vault, "A/B/C", "C", "two")
        self.assertEqual(read(os.path.join(self.vault, "A/B/C/C.md")), "one")

    def test_refuses_symlink_in_path(self):
        outside = os.path.join(self.t.name, "outside")
        os.mkdir(outside)
        os.symlink(outside, os.path.join(self.vault, "HackTheBox"))
        with self.assertRaises(ValueError):
            sc.write_sheet(self.vault, "HackTheBox/Mobile/X", "X", "c")
        self.assertEqual(os.listdir(outside), [])

    def test_refuses_bad_dest(self):
        for bad in ("../x", "/abs/x", "a//b", "a/../b", "-x/y"):
            with self.assertRaises(ValueError, msg=bad):
                sc.write_sheet(self.vault, bad, "n", "c")


class NotesTest(unittest.TestCase):
    def test_notes_contents(self):
        out = sc.render_notes(META, "HackTheBox/Mobile/APKey")
        self.assertIn("Catégorie plateforme : Mobile", out)
        self.assertIn("Export : HackTheBox/Mobile/APKey", out)
        self.assertIn("1.2.3.4:80", out)
        self.assertRegex(out, r"(?m)^> Find the key")


class CliSetupTest(unittest.TestCase):
    """cmd_setup de bout en bout, API simulée, vault et challenge jetables."""

    def setUp(self):
        import ctf_cli
        self.ctf_cli = ctf_cli
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.vault = os.path.join(self.t.name, "vault")
        self.cdir = os.path.join(self.t.name, "challenges", "APKey")
        os.makedirs(self.vault)
        os.makedirs(os.path.join(self.cdir, "work"))
        self.info = {"name": "APKey", "challenge_category_id": 9, "difficulty": "Easy", "points": 20,
                     "description": "Find the key", "download": True, "file_name": "a.zip"}
        for target, val in (
            ("load_config", {"active": {"platform": "htb", "token": "T"}}),
            ("htb_info", self.info),
            ("htb_categories", {9: "Mobile"}),
        ):
            p = mock.patch.object(ctf_cli, target, return_value=val)
            p.start()
            self.addCleanup(p.stop)

        def fake_download(token, cid, dest):
            path = os.path.join(dest, "a.zip")
            with open(path, "wb") as f:
                f.write(b"PK")
            return {"info": self.info, "files": [path]}

        p = mock.patch.object(ctf_cli, "htb_download", side_effect=fake_download)
        p.start()
        self.addCleanup(p.stop)

    def args(self, **kw):
        import argparse
        base = dict(id="240", name=None, event=None, year=None, vault=self.vault, challenge_dir=self.cdir)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_full_setup(self):
        out = self.ctf_cli.cmd_setup(self.args())
        sheet = os.path.join(self.vault, "HackTheBox/Mobile/APKey/APKey.md")
        self.assertEqual(out["dest"], "HackTheBox/Mobile/APKey")
        self.assertIn("status: en-cours", read(sheet))
        notes = read(os.path.join(self.cdir, "notes.md"))
        self.assertIn("Catégorie plateforme : Mobile", notes)
        self.assertIn("Export : HackTheBox/Mobile/APKey", notes)
        self.assertTrue(os.path.exists(os.path.join(self.cdir, "work", "a.zip")))
        self.assertEqual(os.listdir(os.path.join(self.vault, "HackTheBox/Mobile/APKey")), ["APKey.md"])  # pas de sources dans le vault

    def test_unknown_category_aborts_before_writing(self):
        self.info["challenge_category_id"] = 99
        with self.assertRaises(SystemExit):
            self.ctf_cli.cmd_setup(self.args())
        self.assertEqual(os.listdir(self.vault), [])

    def test_existing_sheet_is_not_overwritten(self):
        self.ctf_cli.cmd_setup(self.args())
        with self.assertRaises(SystemExit):
            self.ctf_cli.cmd_setup(self.args())

    def test_sheet_status_command(self):
        self.ctf_cli.cmd_setup(self.args())
        sheet = os.path.join(self.vault, "HackTheBox/Mobile/APKey/APKey.md")
        import argparse
        self.ctf_cli.cmd_sheet_status(argparse.Namespace(sheet=sheet, status="resolu", vault=self.vault))
        self.assertIn("status: resolu", read(sheet))

    def test_sheet_status_refuses_path_outside_vault(self):
        import argparse
        outside = os.path.join(self.t.name, "x.md")
        with open(outside, "w") as f:
            f.write("status: en-cours")
        with self.assertRaises(SystemExit):
            self.ctf_cli.cmd_sheet_status(argparse.Namespace(sheet=outside, status="resolu", vault=self.vault))


if __name__ == "__main__":
    unittest.main()
