# SPDX-License-Identifier: MIT OR Apache-2.0

"""
banmanager.py

Functional test exercising the ban manager through the `setban`, `listbans`,
and `clearbans` RPCs.
"""

import time

from requests.exceptions import HTTPError
from test_framework import FlorestaTestFramework
from test_framework.node import NodeType

# Must match the constant in ban_man.rs
DEFAULT_BAN_DURATION = 60 * 60 * 24  # 24 hours


class BanManagerTest(FlorestaTestFramework):
    """
    Comprehensive ban-manager test covering setban, listbans and clearbans.
    """

    def set_test_params(self):
        self.florestad = self.add_node_default_args(variant=NodeType.FLORESTAD)

    def _assert_ban_count(self, expected: int):
        bans = self.florestad.rpc.listbans()
        self.assertEqual(len(bans), expected)
        return bans

    def _find_ban(self, ip: str):
        """Return the ban entry for `ip`, or None."""
        bans = self.florestad.rpc.listbans()
        for b in bans:
            if b["address"] == ip:
                return b
        return None

    def run_test(self):
        self.run_node(self.florestad)

        self.log("=== listbans on fresh node")
        bans = self._assert_ban_count(0)
        self.assertIsSome(bans)

        self.log("=== setban add with default duration")
        ip1 = "1.2.3.4"
        before = int(time.time())
        result = self.florestad.rpc.setban(ip1, "add")
        after = int(time.time())
        # Those above will help us to avoid time sensitive runtime errors.
        self.assertIsNone(result)

        entry = self._find_ban(ip1)
        self.assertIsSome(entry)
        self.assertEqual(entry["address"], ip1)
        # ban_created must be between [before, after]
        self.assertTrue(entry["ban_created"] >= before)
        self.assertTrue(entry["ban_created"] <= after)
        # banned_until = ban_created + 24h
        self.assertEqual(
            entry["banned_until"], entry["ban_created"] + DEFAULT_BAN_DURATION
        )

        # --- 3. setban add with explicit duration -----------------------
        self.log("=== setban add with explicit duration")
        ip2 = "5.6.7.8"
        duration = 3600
        before = int(time.time())
        self.florestad.rpc.setban(ip2, "add", bantime=duration)
        after = int(time.time())

        entry = self._find_ban(ip2)
        self.assertIsSome(entry)
        self.assertTrue(entry["ban_created"] >= before)
        self.assertTrue(entry["ban_created"] <= after)
        self.assertEqual(entry["banned_until"], entry["ban_created"] + duration)

        # both bans coexist
        self._assert_ban_count(2)

        # --- 4. setban add with absolute timestamp ----------------------
        self.log("=== setban add with absolute timestamp")
        ip3 = "10.20.30.40"
        abs_until = int(time.time()) + 7200  # 2 hours from now
        before = int(time.time())
        self.florestad.rpc.setban(ip3, "add", bantime=abs_until, absolute=True)
        after = int(time.time())

        entry = self._find_ban(ip3)
        self.assertIsSome(entry)
        self.assertTrue(entry["ban_created"] >= before)
        self.assertTrue(entry["ban_created"] <= after)
        # The server converts the absolute timestamp to a duration, then
        # computes banned_until = ban_created + (abs_until - now).  Because
        # ban_created ~= now, banned_until should equal abs_until within the
        # runtime tolerance.
        self.assertTrue(entry["banned_until"] >= abs_until - (after - before))
        self.assertTrue(entry["banned_until"] <= abs_until + (after - before))

        self._assert_ban_count(3)

        # --- 5. setban remove -------------------------------------------
        self.log("=== setban remove")
        result = self.florestad.rpc.setban(ip1, "remove")
        self.assertIsNone(result)
        # ip1 gone, ip2 and ip3 remain
        self._assert_ban_count(2)
        entry = self._find_ban(ip1)
        self.assertIsNone(entry)

        # --- 6. setban remove on non-existent ban succeeds --------------
        self.log("=== setban remove non-existent")
        result = self.florestad.rpc.setban("99.99.99.99", "remove")
        self.assertIsNone(result)
        self._assert_ban_count(2)

        # --- 7. re-ban updates expiry -----------------------------------
        self.log("=== re-ban updates expiry")
        old_entry = self._find_ban(ip2)
        new_duration = 99999
        before = int(time.time())
        self.florestad.rpc.setban(ip2, "add", bantime=new_duration)
        after = int(time.time())

        new_entry = self._find_ban(ip2)
        self.assertIsSome(new_entry)
        self.assertTrue(new_entry["ban_created"] >= before)
        self.assertTrue(new_entry["ban_created"] <= after)
        self.assertEqual(
            new_entry["banned_until"], new_entry["ban_created"] + new_duration
        )
        # The new banned_until must be strictly later than the old one
        self.assertTrue(new_entry["banned_until"] > old_entry["banned_until"])

        # --- 8. invalid IP address → error ------------------------------
        self.log("=== setban invalid IP")
        with self.assertRaises(HTTPError):
            self.florestad.rpc.setban("not-an-ip", "add")

        # --- 9. invalid command → error ---------------------------------
        self.log("=== setban invalid command")
        with self.assertRaises(HTTPError):
            self.florestad.rpc.setban("1.1.1.1", "invalid")

        # --- 10. clearbans removes everything ---------------------------
        self.log("=== clearbans")
        result = self.florestad.rpc.clearbans()
        self.assertIsNone(result)
        self._assert_ban_count(0)

        # --- 11. clearbans on empty list succeeds -----------------------
        self.log("=== clearbans on empty")
        result = self.florestad.rpc.clearbans()
        self.assertIsNone(result)
        self._assert_ban_count(0)

        # --- 12. multiple IPs tracked independently ---------------------
        self.log("=== multiple IPs independent tracking")
        ips = [f"10.0.0.{i}" for i in range(1, 6)]
        for ip in ips:
            self.florestad.rpc.setban(ip, "add", bantime=600)

        self._assert_ban_count(5)

        # Remove only the middle one
        self.florestad.rpc.setban(ips[2], "remove")
        self._assert_ban_count(4)
        self.assertIsNone(self._find_ban(ips[2]))

        # The rest are still there
        for ip in [ips[0], ips[1], ips[3], ips[4]]:
            self.assertIsSome(self._find_ban(ip))

        # Clean up
        self.florestad.rpc.clearbans()
        self._assert_ban_count(0)

        self.log("=== all ban-manager tests passed")


if __name__ == "__main__":
    BanManagerTest().main()
