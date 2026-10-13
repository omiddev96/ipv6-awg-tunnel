import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("tunnel", Path(__file__).parents[1] / "tunnel.py")
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
FAKE_PUBLIC = base64.b64encode(bytes(range(32))).decode()
PEER_PUBLIC = base64.b64encode(bytes(range(32, 64))).decode()


def state(role="iran"):
    return {
        "role": role, "interface": "awg-v6", "local_ipv6": "2606:4700::1234",
        "nic": "eth0", "port": 40181, "v4": "10.77.77.0/30",
        "v6": "fd77:77:77::/64", "table": 51871, "priority": 11071,
        "mtu": 1420, "params": t.parameters(), "public_key": FAKE_PUBLIC,
        "peer": {"ipv6": "2606:4700::5678", "port": 40179,
                 "public_key": PEER_PUBLIC},
        "exit_nic": "eth0", "exit_nic6": "eth0",
        "host_route": ["ip", "-6", "route", "add", "2606:4700::5678/128",
                       "via", "fe80::1", "dev", "eth0", "src", "2606:4700::1234"],
    }


def result(stdout="", code=0):
    return types.SimpleNamespace(stdout=stdout, stderr="", returncode=code)


class Validation(unittest.TestCase):
    def test_native_public_ipv6(self):
        self.assertEqual(t.ipv6("2606:4700:0000::1"), "2606:4700::1")

    def test_bad_addresses(self):
        for value in ("127.0.0.1", "::1", "fe80::1", "fd00::1",
                      "2001:db8::1", "::ffff:8.8.8.8", "a\nPostUp = bad"):
            with self.subTest(value=value), self.assertRaises(t.Error):
                t.ipv6(value)

    def test_public_key(self):
        self.assertEqual(t.pubkey(FAKE_PUBLIC), FAKE_PUBLIC)

    def test_invalid_keys(self):
        for value in ("bad", base64.b64encode(bytes(32)).decode(), "a\nb", None):
            with self.subTest(value=value), self.assertRaises(t.Error):
                t.pubkey(value)

    def test_networks(self):
        self.assertEqual(t.networks("10.77.77.0/30", "fd77:77:77::/64"),
                         ("10.77.77.0/30", "fd77:77:77::/64"))

    def test_bad_networks(self):
        for v4, v6 in (("10.77.77.1/30", "fd00::/64"),
                       ("8.8.8.0/30", "fd00::/64"),
                       ("10.0.0.0/24", "fd00::/64"),
                       ("10.0.0.0/30", "2606:4700::/64")):
            with self.subTest(v4=v4), self.assertRaises(t.Error):
                t.networks(v4, v6)

    def test_generated_parameters(self):
        for _ in range(100):
            p = t.parameters()
            self.assertEqual(t.validate_parameters(p), p)

    def test_malformed_parameters(self):
        for mutate in (
            lambda p: p.update(Jc=0),
            lambda p: p.update(Jmax=p["Jmin"]),
            lambda p: p.update(S2=p["S1"] + 56),
            lambda p: p.update(H2=p["H1"]),
            lambda p: p.update(H1=True),
            lambda p: p.update(Unexpected=1),
        ):
            p = t.parameters()
            mutate(p)
            with self.assertRaises(t.Error):
                t.validate_parameters(p)

    def test_roles_inner_addresses(self):
        self.assertEqual(t.inner(state()), ("10.77.77.1", "fd77:77:77::1"))
        self.assertEqual(t.inner(state("exit")), ("10.77.77.2", "fd77:77:77::2"))

    def test_public_profile_has_no_private_material(self):
        s = state()
        s["private_key"] = "DO_NOT_EXPORT"
        self.assertNotIn("private", json.dumps(t.profile(s)))
        self.assertNotIn("DO_NOT_EXPORT", json.dumps(t.profile(s)))

    def test_peer_validation(self):
        s = state()
        p = t.profile(state("exit"))
        p["ipv6"] = "2606:4700::5678"
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "p.json"
            f.write_text(json.dumps(p))
            self.assertEqual(t.read_peer(f, s)["role"], "exit")
            p["role"] = "iran"
            f.write_text(json.dumps(p))
            with self.assertRaises(t.Error):
                t.read_peer(f, s)

    def test_peer_network_mismatch(self):
        p = t.profile(state("exit"))
        p.update(ipv6="2606:4700::5678", ipv4_network="10.78.78.0/30")
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "p.json"
            f.write_text(json.dumps(p))
            with self.assertRaises(t.Error):
                t.read_peer(f, state())


class Configuration(unittest.TestCase):
    def test_off_link_gateway_flag_from_default_route(self):
        selected = [{"gateway": "2606:4700::beef", "dev": "eth0", "flags": []}]
        defaults = [{"dst": "default", "gateway": "2606:4700::beef",
                     "dev": "eth0", "flags": ["onlink"]}]
        with patch.object(t, "run", side_effect=[
                result(json.dumps(selected)), result(json.dumps(defaults))]):
            cmd = t.route_spec(state())
        self.assertIn("onlink", cmd)
        self.assertEqual(cmd[:4], ["ip", "-6", "route", "add"])

    def test_normal_gateway_does_not_add_onlink(self):
        selected = [{"gateway": "fe80::1", "dev": "eth0", "flags": []}]
        with patch.object(t, "run", side_effect=[
                result(json.dumps(selected)), result("[]")]):
            self.assertNotIn("onlink", t.route_spec(state()))

    def test_onlink_from_route_get(self):
        selected = [{"gateway": "fe80::1", "dev": "eth0", "flags": ["onlink"]}]
        with patch.object(t, "run", return_value=result(json.dumps(selected))) as cmd:
            self.assertIn("onlink", t.route_spec(state()))
            self.assertEqual(cmd.call_count, 1)

    def test_wrong_physical_interface_refused(self):
        selected = [{"gateway": "fe80::1", "dev": "some-other-tunnel"}]
        with patch.object(t, "run", return_value=result(json.dumps(selected))):
            with self.assertRaises(t.Error):
                t.route_spec(state())

    def test_config_no_default_route_replacement(self):
        text = t.render(state(), "TEST_ONLY_NOT_A_REAL_PRIVATE_KEY")
        self.assertIn("Table = off", text)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", text)
        self.assertNotIn("ip route replace default", text)
        self.assertIn("PreDown =", text)
        self.assertIn("PostDown =", text)

    def test_exit_peer_is_narrow(self):
        text = t.render(state("exit"), "TEST_ONLY_NOT_A_REAL_PRIVATE_KEY")
        self.assertIn("AllowedIPs = 10.77.77.1/32, fd77:77:77::1/128", text)
        self.assertNotIn("AllowedIPs = 0.0.0.0/0", text)

    def test_no_shell_injection_endpoint(self):
        s = state()
        p = t.profile(state("exit"))
        p.update(ipv6="2606:4700::5678; touch /tmp/unsafe")
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "p.json"
            f.write_text(json.dumps(p))
            with self.assertRaises(t.Error):
                t.read_peer(f, s)

    def test_private_write_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "state"
            t.write_private(p, "one")
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            t.write_private(p, "two")
            self.assertEqual(p.read_text(), "two")
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_forward_rules_are_scoped(self):
        rules = t.fw_rules(state("exit"))
        for tool, table, r in rules:
            self.assertIn(t.COMMENT, r)
            if r[0] == "FORWARD":
                self.assertTrue("-s" in r or "-d" in r)
                self.assertIn("awg-v6", r)
            if table == "nat":
                self.assertIn("-s", r)
                self.assertIn("-o", r)

    def test_iran_does_not_enable_forwarding_nat(self):
        self.assertFalse(any(r[0] == "FORWARD" or tab == "nat"
                             for _, tab, r in t.fw_rules(state())))

    def test_firewall_allow_precedes_drop(self):
        calls = []
        def fake(*cmd, **kwargs):
            calls.append(cmd)
            return result(code=1 if "-C" in cmd else 0)
        with patch.object(t, "run", side_effect=fake):
            t.firewall(state(), True)
        insertions = [c for c in calls if c[0] == "ip6tables" and "-I" in c]
        self.assertEqual(insertions[0][-1], "DROP")
        self.assertEqual(insertions[-1][-1], "ACCEPT")

    def test_firewall_does_not_flush(self):
        calls = []
        with patch.object(t, "run", side_effect=lambda *a, **k: (calls.append(a) or result())):
            t.firewall(state("exit"), False)
        self.assertTrue(all("-D" in c for c in calls))
        self.assertFalse(any("-F" in c or "--flush" in c for c in calls))

    def test_down_keeps_blackhole(self):
        calls = []
        with patch.object(t, "root"), patch.object(t, "load", return_value=state()), \
                patch.object(t, "run", side_effect=lambda *a, **k: (calls.append(a) or result())):
            t.policy(types.SimpleNamespace(action="down"))
        self.assertTrue(any("blackhole" in c and "replace" in c for c in calls))
        self.assertFalse(any("blackhole" in c and "del" in c for c in calls))
        self.assertTrue(any("dev" in c and "del" in c for c in calls))

    def test_guard_does_not_delete_main_default(self):
        calls = []
        with patch.object(t, "run", side_effect=lambda *a, **k: (calls.append(a) or result())):
            t.guard(state())
        for c in calls:
            if "route" in c:
                self.assertIn("table", c)
                self.assertIn("51871", c)

    def test_finish_only_owned_route(self):
        calls = []
        s = state()
        with patch.object(t, "root"), patch.object(t, "load", return_value=s), \
                patch.object(t, "save"), \
                patch.object(t, "run", side_effect=lambda *a, **k: (calls.append(a) or result())):
            t.policy(types.SimpleNamespace(action="finish"))
            self.assertEqual(calls, [])
            s["host_route_active"] = True
            t.policy(types.SimpleNamespace(action="finish"))
        self.assertEqual(calls[0][3], "del")
        self.assertFalse(s["host_route_active"])

    def test_guard_idempotent(self):
        calls = []
        rules = "11071:\tfrom all fwmark 0xca9f lookup 51871\n"
        with patch.object(t, "run", side_effect=lambda *a, **k: (calls.append(a) or result(rules))):
            t.guard(state())
        self.assertFalse(any("rule" in c and "add" in c for c in calls))


class PanelTemplate(unittest.TestCase):
    def template(self):
        return {"outbounds": [{"tag": "direct", "protocol": "freedom"},
                              {"tag": "blocked", "protocol": "blackhole"}],
                "routing": {"domainStrategy": "AsIs", "rules": [
                    {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                    {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
                    {"type": "field", "inboundTag": ["inbound-443"], "outboundTag": "direct"}]}}

    def test_input_not_mutated(self):
        original = self.template()
        snap = copy.deepcopy(original)
        t.panel_template(original, ["inbound-443"], 51871)
        self.assertEqual(original, snap)

    def test_unselected_default_preserved(self):
        j = t.panel_template(self.template(), ["inbound-443"], 51871)
        self.assertEqual(j["outbounds"][0]["tag"], "direct")

    def test_api_block_and_selected_priority(self):
        j = t.panel_template(self.template(), ["inbound-443"], 51871)
        rules = j["routing"]["rules"]
        self.assertEqual(rules[0]["outboundTag"], "api")
        self.assertEqual(rules[1]["outboundTag"], "blocked")
        first = next(r for r in rules if r.get("inboundTag") == ["inbound-443"])
        self.assertEqual(first["outboundTag"], t.TAG)

    def test_dns_mark_and_no_system_fallback(self):
        j = t.panel_template(self.template(), ["inbound-443"], 51871)
        out = j["outbounds"][-1]
        self.assertEqual(out["streamSettings"]["sockopt"]["mark"], 51871)
        self.assertEqual(out["settings"]["domainStrategy"], "ForceIP")
        self.assertEqual(j["dns"]["tag"], t.DNS_TAG)
        self.assertEqual(j["routing"]["rules"][2]["outboundTag"], t.TAG)

    def test_custom_dns_refused(self):
        j = self.template()
        j["dns"] = {"servers": ["localhost"]}
        with self.assertRaises(t.Error):
            t.panel_template(j, ["inbound-443"], 51871)

    def test_existing_tag_refused(self):
        j = self.template()
        j["outbounds"].append({"tag": t.TAG})
        with self.assertRaises(t.Error):
            t.panel_template(j, ["inbound-443"], 51871)

    def test_hash_detects_changes(self):
        self.assertNotEqual(t.digest('{"a":1}'), t.digest('{"a":2}'))


class CLI(unittest.TestCase):
    def test_expected_subcommands(self):
        p = t.parser()
        for cmd in ("test", "status", "rollback-panel", "wizard", "repair"):
            self.assertEqual(p.parse_args([cmd]).command, cmd)
        self.assertEqual(p.parse_args(["peer", "--file", "p.json"]).file, "p.json")

    def test_interface_options(self):
        a = t.parser().parse_args(["init", "--role", "exit",
                                  "--local-ipv6", "2606:4700::1",
                                  "--table", "51881", "--priority", "11081"])
        self.assertEqual(a.table, 51881)
        self.assertEqual(a.priority, 11081)

    def test_installer_requires_consent(self):
        with patch.object(t, "root"), patch.object(Path, "read_text",
                return_value='ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n'):
            with self.assertRaises(t.Error):
                t.install(types.SimpleNamespace(yes=False))

    def test_marked_socket_uses_selected_table(self):
        with patch.object(t.socket, "socket") as sock:
            t.marked_socket(state(), t.socket.AF_INET, t.socket.SOCK_STREAM)
        sock.return_value.setsockopt.assert_called_once_with(
            t.socket.SOL_SOCKET, t.socket.SO_MARK, 51871)

    def test_wizard_declined_install(self):
        with patch.object(t, "root"), patch.object(t, "STATE_FILE") as file, \
                patch.object(t.shutil, "which", return_value=None), \
                patch("builtins.input", return_value="n"):
            file.exists.return_value = False
            with self.assertRaises(t.Error):
                t.wizard(types.SimpleNamespace())

    def test_pairing_code_round_trip_is_public_only(self):
        s = state("exit")
        s["private_key"] = "SHOULD_NOT_APPEAR"
        code = t.pairing_code(s)
        self.assertTrue(code.startswith("AWG1-"))
        decoded = t.decode_pairing_code(code)
        self.assertEqual(decoded, t.profile(s))
        self.assertNotIn("SHOULD_NOT_APPEAR", json.dumps(decoded))

    def test_bad_pairing_code(self):
        for code in ("", "AWG1-not!base64", "other-value", "AWG1-" + "x" * 8192):
            with self.subTest(code=code[:20]), self.assertRaises(t.Error):
                t.decode_pairing_code(code)

    def test_pairing_code_rejects_non_object_json(self):
        encoded = base64.urlsafe_b64encode(b"[]").decode().rstrip("=")
        with self.assertRaises(t.Error):
            t.decode_pairing_code("AWG1-" + encoded)

    def test_non_object_parameters(self):
        for value in (None, [], "bad"):
            with self.assertRaises(t.Error):
                t.validate_parameters(value)

    def test_wizard_resumes_failed_service_without_rekey(self):
        s = state("exit")
        with patch.object(t, "root"), patch.object(t, "STATE_FILE") as f, \
                patch.object(t, "load", return_value=s), \
                patch.object(t, "run", return_value=result(code=1)), \
                patch.object(t, "repair") as repair, patch.object(t, "init") as init, \
                patch.object(t, "test") as test, patch("builtins.input", return_value=""):
            f.exists.return_value = True
            t.wizard(types.SimpleNamespace())
        repair.assert_called_once()
        init.assert_not_called()
        test.assert_called_once()


if __name__ == "__main__":
    unittest.main()