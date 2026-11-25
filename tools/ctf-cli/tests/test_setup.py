import json
import os
import re
import shutil
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


class InjectionTest(unittest.TestCase):
    EVIL = "Web\n---\nstatus: resolu\n# Pwned"

    def test_multiline_fields_cannot_break_frontmatter_or_callout(self):
        m = sc.normalize("ctfd", {"name": "N\n# Fake", "category": self.EVIL, "type": "a\nb",
                                  "value": "1\n2", "connection_info": "`x`\ny"})
        out = sc.render_sheet(m, "d")
        head = out.split("\n---\n", 2)
        self.assertEqual(out.count("\n---\n"), 1)  # une seule fermeture du frontmatter
        self.assertEqual(len([l for l in out.splitlines() if l.startswith("status:")]), 1)
        self.assertEqual(len([l for l in out.splitlines() if l.startswith("# ")]), 1)  # un seul titre
        self.assertNotIn("\n# Pwned", out)
        self.assertNotIn("`x`", out)

    def test_frontmatter_values_are_quoted(self):
        m = sc.normalize("ctfd", {"name": "N", "category": "a: b {c} #d"})
        self.assertIn('category: "a: b {c} #d"', sc.render_sheet(m, "d"))

    def test_title_and_callout_cannot_transclude_or_tag(self):
        m = sc.normalize("ctfd", {"name": "![[secret]] #x", "category": "[[c]]", "difficulty": "#resolu"})
        out = sc.render_sheet(m, "d")
        self.assertNotIn("![[", out)
        self.assertNotIn("[[c]]", out)
        self.assertEqual(out.count("#resolu"), 0)

    def test_unicode_line_separators_flattened(self):
        self.assertEqual(sc.oneline("a\u2028b\u2029c\x85d"), "a b c d")

    def test_description_cannot_transclude_or_tag(self):
        q = sc._quote("![[secret]] #resolu [[x]]")
        self.assertNotIn("![[", q)
        self.assertNotIn(" #resolu", q)

    def test_set_status_only_touches_status_and_last_tag_line(self):
        meta = dict(META, description="mentions #en-cours in text")
        out = sc.set_status(sc.render_sheet(meta, "x"), "tente")
        self.assertIn("mentions \\#en-cours in text", out)
        self.assertTrue(out.rstrip().endswith("#tente"))

    def test_set_status_refuses_non_sheet(self):
        with self.assertRaises(ValueError):
            sc.set_status("# juste une note\n#en-cours\n", "resolu")


class FilenameTest(unittest.TestCase):
    def test_safe_filename(self):
        import ctf_cli
        for bad in ("../../x.zip", "/etc/passwd", "..\\..\\x", "a/b/c.zip"):
            self.assertNotIn("/", ctf_cli._safe_filename(bad, "d.zip"))
            self.assertNotIn("..", ctf_cli._safe_filename(bad, "d.zip"))
        for empty in ("", None, ".", ".."):
            self.assertEqual(ctf_cli._safe_filename(empty, "d.zip"), "d.zip")

    def test_htb_download_stays_in_dest(self):
        import ctf_cli
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "work")
            info = {"download": True, "file_name": "../../evil.zip"}
            resp = mock.MagicMock()
            resp.__enter__.return_value = __import__("io").BytesIO(b"PK")
            with mock.patch.object(ctf_cli, "htb_info", return_value=info), \
                    mock.patch.object(ctf_cli, "_urlopen", return_value=resp):
                res = ctf_cli.htb_download("T", 1, dest)
            self.assertEqual(os.path.dirname(res["files"][0]), dest)
            self.assertEqual(sorted(os.listdir(d)), ["work"])


class CtfdDownloadTest(unittest.TestCase):
    """ctfd_download : jamais d'écrasement, jamais de suivi de lien symbolique."""

    def setUp(self):
        import ctf_cli
        self.ctf_cli = ctf_cli
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.dest = os.path.join(self.t.name, "work")

    def download(self, urls, bodies):
        import io
        resps = []
        for b in bodies:
            r = mock.MagicMock()
            r.__enter__.return_value = io.BytesIO(b)
            resps.append(r)
        with mock.patch.object(self.ctf_cli, "ctfd_info", return_value={"files": urls}), \
                mock.patch.object(self.ctf_cli, "load_config", return_value={}), \
                mock.patch.object(self.ctf_cli, "_urlopen", side_effect=resps):
            return self.ctf_cli.ctfd_download("https://ctf.example", "T", 1, self.dest)

    def test_same_name_files_are_both_kept(self):
        res = self.download(["/files/a/f.txt", "/files/b/f.txt"], [b"one", b"two"])
        self.assertEqual(len(set(res["files"])), 2)
        self.assertEqual(sorted(read(f) for f in res["files"]), ["one", "two"])

    def test_preexisting_symlink_is_not_followed(self):
        os.makedirs(self.dest)
        target = os.path.join(self.t.name, "victim.txt")
        with open(target, "w") as f:
            f.write("intact")
        os.symlink(target, os.path.join(self.dest, "f.txt"))
        res = self.download(["/files/a/f.txt"], [b"payload"])
        self.assertEqual(read(target), "intact")
        self.assertEqual(read(res["files"][0]), "payload")
        self.assertFalse(os.path.islink(res["files"][0]))

    def test_challenge_json_symlink_is_not_followed(self):
        os.makedirs(self.dest)
        target = os.path.join(self.t.name, "victim.txt")
        with open(target, "w") as f:
            f.write("intact")
        os.symlink(target, os.path.join(self.dest, "challenge.json"))
        with self.assertRaises(OSError):
            self.download([], [])
        self.assertEqual(read(target), "intact")

    def test_read_text_tolerates_non_utf8_bytes(self):
        non_utf8 = os.path.join(self.t.name, "bad.txt")
        with open(non_utf8, "wb") as f:
            f.write(b"header\xff\xfe\xfafooter")
        text = sc.read_text(non_utf8)
        self.assertIn("header", text)
        self.assertIn("footer", text)


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

    def test_failed_run_leaves_no_sheet_and_is_rerunnable(self):
        with mock.patch.object(self.ctf_cli, "htb_download", side_effect=SystemExit(1)):
            with self.assertRaises(SystemExit):
                self.ctf_cli.cmd_setup(self.args())
        self.assertEqual(os.listdir(self.vault), [])
        self.ctf_cli.cmd_setup(self.args())  # relance OK

    def test_existing_sheet_is_not_overwritten(self):
        self.ctf_cli.cmd_setup(self.args())
        with self.assertRaises(SystemExit):
            self.ctf_cli.cmd_setup(self.args())

    def test_rerun_after_failure_keeps_single_setup_block(self):
        notes_path = os.path.join(self.cdir, "notes.md")
        with open(notes_path, "w") as f:
            f.write("notes de l'orchestrateur\n")
        self.ctf_cli.cmd_setup(self.args())
        shutil.rmtree(os.path.join(self.vault, "HackTheBox"))  # simule un échec avant la fiche
        self.ctf_cli.cmd_setup(self.args())
        self.assertEqual(read(notes_path).count("## Setup"), 1)

    def test_rerun_on_fresh_notes_does_not_duplicate_block(self):
        notes_path = os.path.join(self.cdir, "notes.md")
        self.ctf_cli.cmd_setup(self.args())
        shutil.rmtree(os.path.join(self.vault, "HackTheBox"))
        self.ctf_cli.cmd_setup(self.args())
        self.assertEqual(read(notes_path).count("Plateforme : htb"), 1)

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

    def test_setup_challenge_direct_without_argparse(self):
        """setup_challenge appelée directement : paramètres explicites, API injectée."""
        def fake_download(token, cid, dest):
            path = os.path.join(dest, "a.zip")
            with open(path, "wb") as f:
                f.write(b"PK")
            return {"files": [path]}

        api = {"htb_info": lambda token, cid: self.info,
               "htb_categories": lambda token: {9: "Mobile"},
               "htb_download": fake_download}
        res = sc.setup_challenge(profile={"platform": "htb", "token": "T"}, challenge_id="240",
                                 challenge_dir=self.cdir, vault=self.vault, api=api)
        self.assertEqual(res["dest"], "HackTheBox/Mobile/APKey")
        self.assertIn("status: en-cours", read(res["sheet"]))
        self.assertTrue(os.path.exists(os.path.join(res["work"], "a.zip")))
        self.assertEqual(sorted(res), ["connection", "dest", "download_note", "files",
                                       "instance_to_start", "notes", "sheet", "work"])

    def test_setup_challenge_without_profile_exits_2(self):
        with self.assertRaises(SystemExit) as cm:
            sc.setup_challenge(profile=None, challenge_id="1", challenge_dir=self.cdir,
                               vault=self.vault, api={})
        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
