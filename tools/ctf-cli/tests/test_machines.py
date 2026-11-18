import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ctf_cli  # noqa: E402


def page(items, nxt=None):
    return {"data": items, "links": {"next": nxt}}


class MachinesTest(unittest.TestCase):
    def test_list_follows_pagination_and_filters(self):
        p1 = page([{"name": "A", "os": "Linux", "difficultyText": "Easy", "authUserInRootOwns": True}],
                  nxt="https://x/next")
        p2 = page([{"name": "B", "os": "Windows", "difficultyText": "Hard", "authUserInRootOwns": False},
                   {"name": "C", "os": "Linux", "difficultyText": "Hard", "authUserInRootOwns": False}])
        with mock.patch.object(ctf_cli, "api_request", side_effect=[p1, p2]) as api:
            res = ctf_cli.htb_machines_list("t", os_name="linux", solved=False)
        self.assertEqual([m["name"] for m in res], ["C"])
        self.assertEqual(api.call_count, 2)
        self.assertIn("machine/paginated", api.call_args_list[0].args[0])

    def test_list_retired_uses_retired_endpoint(self):
        with mock.patch.object(ctf_cli, "api_request", return_value=page([])) as api:
            ctf_cli.htb_machines_list("t", retired=True)
        self.assertIn("machine/list/retired/paginated", api.call_args.args[0])

    def test_info_quotes_name(self):
        with mock.patch.object(ctf_cli, "api_request", return_value={"info": {"id": 1}}) as api:
            self.assertEqual(ctf_cli.htb_machine_info("t", "a/b"), {"id": 1})
        self.assertTrue(api.call_args.args[0].endswith("machine/profile/a%2Fb"))

    def test_spawn_payload(self):
        with mock.patch.object(ctf_cli, "api_request", return_value={}) as api:
            ctf_cli.htb_machine_spawn("t", "42")
        self.assertEqual(api.call_args.kwargs["data"], {"machine_id": 42})
        self.assertEqual(api.call_args.kwargs["method"], "POST")

    def test_active_none(self):
        with mock.patch.object(ctf_cli, "api_request", return_value={"info": None}):
            self.assertIsNone(ctf_cli.htb_machine_active("t"))

    def test_submit_payload(self):
        with mock.patch.object(ctf_cli, "api_request", return_value={}) as api:
            ctf_cli.htb_machine_submit("t", "7", "HTB{x}")
        self.assertEqual(api.call_args.kwargs["data"], {"id": 7, "flag": "HTB{x}", "difficulty": 50})
        self.assertEqual(api.call_args.args[0], "https://labs.hackthebox.com/api/v5/machine/own")


if __name__ == "__main__":
    unittest.main()
