#!/usr/bin/env python3
"""Native IPv6 AmneziaWG tunnel manager. Python standard library only."""
import argparse
import base64
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time

STATE_DIR = Path("/etc/ipv6-awg-tunnel")
STATE_FILE = STATE_DIR / "state.json"
APP = Path("/opt/ipv6-awg-tunnel/tunnel.py")
POLICY = "/usr/local/sbin/ipv6-awg-tunnel"
GUARD = "ipv6-awg-policy-guard"
DROPIN = Path("/etc/systemd/system/x-ui.service.d/ipv6-awg-tunnel.conf")
PANEL_DB = Path("/etc/x-ui/x-ui.db")
XRAY_CONFIG = Path("/usr/local/x-ui/bin/config.json")
XRAY = "/usr/local/x-ui/bin/xray-linux-amd64"
BACKUPS = Path("/var/lib/ipv6-awg-tunnel/backups")
LOG = Path("/var/log/ipv6-awg-tunnel-install.log")
TAG = "ipv6-awg-exit"
DNS_TAG = "ipv6-awg-dns"
COMMENT = "ipv6-awg-tunnel"


class Error(RuntimeError):
    pass


def run(*args, check=True, capture=True, input=None):
    p = subprocess.run([str(x) for x in args], input=input, text=True,
                       capture_output=capture)
    if check and p.returncode:
        # Do not echo subprocess arguments: some commands handle private keys.
        raise Error("A system command failed (exit %d). Check service/package logs."
                    % p.returncode)
    return p


def write_private(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".awg-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def save(s):
    write_private(STATE_FILE, json.dumps(s, indent=2) + "\n")


def load():
    if not STATE_FILE.exists():
        raise Error("Run 'init' first.")
    return json.loads(STATE_FILE.read_text())


def root():
    if os.geteuid() != 0:
        raise Error("Run this command as root.")
    os.umask(0o077)


def ipv6(value):
    try:
        a = ipaddress.IPv6Address(value)
    except ValueError:
        raise Error("Expected an unbracketed IPv6 address.")
    if not a.is_global or a.ipv4_mapped:
        raise Error("A native, globally routable IPv6 address is required.")
    return str(a)


def pubkey(value):
    try:
        b = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise Error("Invalid AmneziaWG public key.")
    if len(b) != 32 or b == bytes(32):
        raise Error("Invalid AmneziaWG public key.")
    return value


def networks(v4, v6):
    try:
        a = ipaddress.IPv4Network(v4, strict=True)
        b = ipaddress.IPv6Network(v6, strict=True)
    except ValueError:
        raise Error("Use canonical IPv4 /30 and ULA IPv6 /64 network addresses.")
    if a.prefixlen != 30 or not a.subnet_of(ipaddress.ip_network("10.0.0.0/8")):
        raise Error("The inner IPv4 network must be a /30 inside 10.0.0.0/8.")
    if b.prefixlen != 64 or not b.subnet_of(ipaddress.ip_network("fc00::/7")):
        raise Error("The inner IPv6 network must be a ULA /64.")
    return str(a), str(b)


def inner(s, role=None):
    offset = 1 if (role or s["role"]) == "iran" else 2
    return (str(ipaddress.ip_network(s["v4"])[offset]),
            str(ipaddress.ip_network(s["v6"])[offset]))


def parameters():
    hs = secrets.SystemRandom().sample(range(10000, 2**31 - 1), 4)
    return dict(Jc=4, Jmin=40, Jmax=100, S1=97, S2=143,
                **dict(zip(("H1", "H2", "H3", "H4"), hs)))


def validate_parameters(p):
    names = {"Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"}
    if set(p) != names or any(type(v) is not int for v in p.values()):
        raise Error("Unexpected obfuscation parameters.")
    if not 1 <= p["Jc"] <= 128 or not 0 <= p["Jmin"] < p["Jmax"] <= 1280:
        raise Error("Invalid junk packet parameters.")
    if not 0 <= p["S1"] <= 1132 or not 0 <= p["S2"] <= 1188:
        raise Error("Invalid handshake padding.")
    if p["S1"] + 56 == p["S2"]:
        raise Error("Handshake packet sizes must differ.")
    hs = [p["H" + str(i)] for i in range(1, 5)]
    if len(set(hs)) != 4 or any(not 5 <= x < 2**31 for x in hs):
        raise Error("Invalid header values.")
    return p


def profile(s):
    return {"format": 1, "role": s["role"], "ipv6": s["local_ipv6"],
            "port": s["port"], "public_key": s["public_key"],
            "ipv4_network": s["v4"], "ipv6_network": s["v6"],
            "parameters": s["params"]}


def read_peer(path, s):
    p = json.loads(Path(path).read_text())
    expected = "exit" if s["role"] == "iran" else "iran"
    if p.get("format") != 1 or p.get("role") != expected:
        raise Error("The peer profile must describe the opposite role.")
    p["ipv6"] = ipv6(p["ipv6"])
    if p["ipv6"] == s["local_ipv6"]:
        raise Error("Both servers cannot use the same public IPv6 address.")
    p["public_key"] = pubkey(p["public_key"])
    if type(p["port"]) is not int or not 1024 <= p["port"] <= 65535:
        raise Error("Invalid peer port.")
    if networks(p["ipv4_network"], p["ipv6_network"]) != (s["v4"], s["v6"]):
        raise Error("Both servers must use the same inner networks.")
    validate_parameters(p["parameters"])
    return p


def assigned(value):
    data = json.loads(run("ip", "-j", "-6", "addr", "show").stdout)
    for nic in data:
        for a in nic.get("addr_info", []):
            if a.get("local") == value and a.get("scope") == "global":
                return nic["ifname"]
    raise Error("The selected public IPv6 address is not assigned locally.")


def service(s):
    return "awg-quick@" + s["interface"]


def config_path(s):
    return Path("/etc/amnezia/amneziawg") / (s["interface"] + ".conf")


def render(s, private_key):
    a, b = inner(s)
    peer_role = "exit" if s["role"] == "iran" else "iran"
    pa, pb = inner(s, peer_role)
    p = s["peer"]
    allowed = "0.0.0.0/0, ::/0" if s["role"] == "iran" else pa + "/32, " + pb + "/128"
    lines = ["[Interface]", "PrivateKey = " + private_key,
             "Address = " + a + "/30, " + b + "/64",
             "ListenPort = " + str(s["port"]), "MTU = " + str(s["mtu"]),
             "Table = off",
             "PreUp = " + POLICY + " policy prepare",
             "PostUp = " + POLICY + " policy up",
             "PreDown = " + POLICY + " policy down",
             "PostDown = " + POLICY + " policy finish"]
    validate_parameters(s["params"])
    lines += [k + " = " + str(v) for k, v in s["params"].items()]
    lines += ["", "[Peer]", "PublicKey = " + p["public_key"],
              "AllowedIPs = " + allowed,
              "Endpoint = [" + p["ipv6"] + "]:" + str(p["port"]),
              "PersistentKeepalive = 25", ""]
    return "\n".join(lines)


def install(args):
    root()
    os_release = dict(line.split("=", 1) for line in
                      Path("/etc/os-release").read_text().splitlines() if "=" in line)
    distro = os_release.get("ID", "").strip('"')
    release = os_release.get("VERSION_ID", "").strip('"')
    if distro != "ubuntu" or release not in ("22.04", "24.04"):
        raise Error("Automatic package installation supports Ubuntu 22.04/24.04 only.")
    if not args.yes:
        raise Error("Use --yes after reading the README and reviewing this script.")
    print("Installing signed upstream Amnezia packages. No full upgrade or reboot.")
    LOG.parent.mkdir(exist_ok=True, parents=True)
    LOG.touch(mode=0o600, exist_ok=True)
    os.chmod(LOG, 0o600)
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive", LC_ALL="C.UTF-8")
    def apt(*command):
        with LOG.open("a") as f:
            p = subprocess.run(command, env=env, stdout=f, stderr=f)
        if p.returncode:
            raise Error("Package installation failed. Read " + str(LOG))
    codename = os_release.get("VERSION_CODENAME", "").strip('"')
    arm = os.uname().machine in ("aarch64", "arm64")
    source_uri = ("https://ports.ubuntu.com/ubuntu-ports/" if arm
                  else "https://archive.ubuntu.com/ubuntu/")
    security_uri = ("https://ports.ubuntu.com/ubuntu-ports/" if arm
                    else "https://security.ubuntu.com/ubuntu/")
    # Source indices on some VPS mirrors do not exist. Keep existing binary
    # repositories unchanged and add separate official Ubuntu source entries.
    source = Path("/etc/apt/sources.list.d/ipv6-awg-kernel-source.sources")
    if not source.exists():
        source.write_text(
            "Types: deb-src\nURIs: " + source_uri + "\n"
            "Suites: " + codename + " " + codename + "-updates\n"
            "Components: main universe\n"
            "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\n"
            "Types: deb-src\nURIs: " + security_uri + "\n"
            "Suites: " + codename + "-security\nComponents: main universe\n"
            "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n")
        os.chmod(source, 0o644)
    kernel = run("uname", "-r").stdout.strip()
    # Use the matching running-kernel headers. Never silently reboot into a
    # different kernel or replace the running kernel to make the build succeed.
    apt("apt-get", "update", "-qq")
    apt("apt-get", "install", "-y", "--no-install-recommends",
        "software-properties-common", "python3-launchpadlib", "gnupg2",
        "linux-headers-" + kernel, "iproute2", "iptables", "curl", "iperf3")
    apt("add-apt-repository", "-y", "ppa:amnezia/ppa")
    apt("apt-get", "update", "-qq")
    apt("apt-get", "install", "-y", "--no-install-recommends", "amneziawg")
    run("modprobe", "amneziawg")
    print(run("awg", "--version").stdout.strip())
    print("Installation complete. Next: init.")


def init(args):
    root()
    if STATE_FILE.exists():
        raise Error("State already exists. Use peer/status; do not overwrite an installation.")
    for cmd in ("awg", "awg-quick", "ip", "iptables", "ip6tables", "systemctl"):
        if not shutil.which(cmd):
            raise Error("Missing command: " + cmd + ". Run install first.")
    run("modprobe", "amneziawg")
    local = ipv6(args.local_ipv6)
    nic = assigned(local)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", args.interface):
        raise Error("Use an interface name of 1-15 letters, digits, underscores or hyphens.")
    if not 1280 <= args.mtu <= 1420:
        raise Error("Use an MTU from 1280 to 1420.")
    if not 1 <= args.table < 2**32 or args.table in (253, 254, 255):
        raise Error("Choose a positive, non-reserved routing table/mark.")
    if not 1 <= args.priority < 32766:
        raise Error("Choose a rule priority between 1 and 32765.")
    v4, v6 = networks(args.ipv4_network, args.ipv6_network)
    for af in ("-4", "-6"):
        if run("ip", af, "route", "show", "table", str(args.table), check=False).stdout.strip():
            raise Error("Routing table already in use; choose a different --table.")
        if any(line.split(":")[0].strip() == str(args.priority)
               for line in run("ip", af, "rule", "show").stdout.splitlines()):
            raise Error("Rule priority already in use; choose a different --priority.")
    # Reject overlapping connected routes instead of hijacking existing tunnels.
    for af, network in (("-4", v4), ("-6", v6)):
        for row in json.loads(run("ip", "-j", af, "route", "show", "table", "all").stdout):
            dst = row.get("dst", "default")
            if dst == "default":
                continue
            try:
                if ipaddress.ip_network(dst, strict=False).overlaps(ipaddress.ip_network(network)):
                    raise Error("An inner network overlaps an existing route.")
            except ValueError:
                continue
    port = args.port
    occupied = run("ss", "-H", "-lun").stdout
    if port is None:
        for _ in range(100):
            candidate = secrets.randbelow(15000) + 40000
            if not re.search(r":" + str(candidate) + r"\s", occupied):
                port = candidate
                break
    if port is None or not 1024 <= port <= 65535 or re.search(r":" + str(port) + r"\s", occupied):
        raise Error("Requested UDP port is invalid or already in use.")
    s = dict(version=1, role=args.role, local_ipv6=local, nic=nic, port=port,
             interface=args.interface, v4=v4, v6=v6, table=args.table,
             priority=args.priority, mtu=args.mtu, params=parameters(), peer=None)
    if config_path(s).exists():
        raise Error("AmneziaWG config already exists. It will not be overwritten.")
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    private = run("awg", "genkey").stdout.strip()
    s["public_key"] = run("awg", "pubkey", input=private + "\n").stdout.strip()
    write_private(STATE_DIR / "private.key", private + "\n")
    APP.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if Path(__file__).resolve() != APP:
        shutil.copyfile(__file__, APP)
    os.chmod(APP, 0o755)
    Path(POLICY).write_text("#!/bin/sh\nexec /usr/bin/python3 " + str(APP) + ' "$@"\n')
    os.chmod(POLICY, 0o755)
    save(s)
    if args.peer_file:
        peer(argparse.Namespace(file=args.peer_file))
        s = load()
    if args.export:
        write_private(args.export, json.dumps(profile(s), indent=2) + "\n")
    print("Initialized " + args.role + ". Public peer profile (no private key):")
    print(json.dumps(profile(s), indent=2))
    print("Open this UDP port in provider firewalls; keep management access unchanged.")


def route_spec(s):
    p = s["peer"]["ipv6"]
    data = json.loads(run("ip", "-j", "-6", "route", "get", p,
                         "from", s["local_ipv6"]).stdout)[0]
    if data.get("dev") != s["nic"]:
        raise Error("Peer route does not use the selected public network interface.")
    cmd = ["ip", "-6", "route", "add", p + "/128"]
    if data.get("gateway"):
        cmd += ["via", data["gateway"]]
    cmd += ["dev", s["nic"], "src", s["local_ipv6"]]
    return cmd


def peer(args):
    root()
    s = load()
    if s.get("uninstalled"):
        raise Error("This installation was uninstalled; archive state before a new init.")
    p = read_peer(args.file, s)
    if p["public_key"] == s["public_key"]:
        raise Error("A server cannot peer with itself.")
    if s.get("peer") and s["peer"] != p:
        raise Error("Changing a live peer is not automatic; uninstall/reconfigure deliberately.")
    s["peer"] = p
    # The exit server owns the shared obfuscation parameters.
    if s["role"] == "iran":
        s["params"] = p["parameters"]
    if "host_route" not in s:
        existing = run("ip", "-6", "route", "show", "exact", p["ipv6"] + "/128").stdout
        if existing.strip():
            raise Error("An endpoint host route already exists. Review it manually first.")
        s["host_route"] = route_spec(s)
    if s["role"] == "exit" and "exit_nic" not in s:
        s["exit_nic"] = json.loads(run("ip", "-j", "-4", "route", "get", "1.1.1.1").stdout)[0]["dev"]
        s["exit_nic6"] = json.loads(run("ip", "-j", "-6", "route", "get",
                                      "2606:4700:4700::1111").stdout)[0]["dev"]
        s["forwarding_before"] = {
            k: run("sysctl", "-n", k).stdout.strip()
            for k in ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding")}
        # Routers normally ignore RA. Preserve RA-based default-route renewal
        # when this VPS currently relies on router advertisements.
        defaults = json.loads(run("ip", "-j", "-6", "route", "show", "default").stdout)
        ra = any(x.get("protocol") == "ra" and x.get("dev") == s["exit_nic6"]
                 for x in defaults)
        if ra:
            key = "net.ipv6.conf." + s["exit_nic6"] + ".accept_ra"
            s["accept_ra_key"] = key
            s["forwarding_before"][key] = run("sysctl", "-n", key).stdout.strip()
    save(s)
    cfg = config_path(s)
    cfg.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_private(cfg, render(s, (STATE_DIR / "private.key").read_text().strip()))
    if s["role"] == "iran":
        guard = Path("/etc/systemd/system/" + GUARD + ".service")
        guard.write_text(
            "[Unit]\nDescription=Fail-closed policy for IPv6 AWG VPN traffic\n"
            "Before=x-ui.service " + service(s) + ".service\n\n"
            "[Service]\nType=oneshot\nExecStart=" + POLICY +
            " policy guard\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n")
        os.chmod(guard, 0o644)
        run("systemctl", "daemon-reload")
        run("systemctl", "enable", "--now", GUARD)
    run("systemctl", "enable", service(s))
    try:
        run("systemctl", "restart", service(s))
    except Error:
        # Failed pre/post-up hooks can leave an endpoint route behind.
        # Keep the Iran guard but remove our experimental firewall/host route.
        policy(argparse.Namespace(action="down"))
        policy(argparse.Namespace(action="finish"))
        raise
    print("Peer configured. Test the tunnel before enabling panel routing.")


def fw_rules(s):
    """Exact, narrowly scoped rules; never flush existing firewall chains."""
    p, nic, port = s["peer"], s["nic"], str(s["port"])
    comment = ["-m", "comment", "--comment", COMMENT]
    rules = [
        ("ip6tables", "filter", ["INPUT", "-i", nic, "-s", p["ipv6"] + "/128",
                               "-d", s["local_ipv6"] + "/128", "-p", "udp",
                               "--dport", port] + comment + ["-j", "ACCEPT"]),
        ("ip6tables", "filter", ["INPUT", "-i", nic, "-p", "udp", "--dport", port]
         + comment + ["-j", "DROP"]),
        ("iptables", "filter", ["INPUT", "-i", nic, "-p", "udp", "--dport", port]
         + comment + ["-j", "DROP"])]
    if s["role"] == "exit":
        a, b = inner(s, "iran")
        for tool, source, eth in (("iptables", a + "/32", s["exit_nic"]),
                                  ("ip6tables", b + "/128", s["exit_nic6"])):
            rules += [
                (tool, "filter", ["FORWARD", "-i", s["interface"], "-o", eth,
                                 "-s", source] + comment + ["-j", "ACCEPT"]),
                (tool, "filter", ["FORWARD", "-i", eth, "-o", s["interface"],
                                 "-d", source, "-m", "conntrack",
                                 "--ctstate", "RELATED,ESTABLISHED"]
                 + comment + ["-j", "ACCEPT"]),
                (tool, "nat", ["POSTROUTING", "-s", source, "-o", eth]
                 + comment + ["-j", "MASQUERADE"])]
    return rules


def firewall(s, add):
    # Insert DROP before ACCEPT so ACCEPT ends up before DROP. Existing unrelated
    # nftables base chains may still drop packets; diagnostics must detect that.
    rules = fw_rules(s)
    for tool, table, rule in (reversed(rules) if add else rules):
        prefix = [tool, "-w", "5", "-t", table]
        if add:
            if run(*prefix, "-C", *rule, check=False).returncode:
                run(*prefix, "-I", *rule)
        else:
            run(*prefix, "-D", *rule, check=False)


def guard(s, remove=False):
    if s["role"] != "iran":
        return
    table, priority = str(s["table"]), str(s["priority"])
    for af in ("-4", "-6"):
        if remove:
            run("ip", af, "rule", "del", "pref", priority, "fwmark", table,
                "lookup", table, check=False)
            run("ip", af, "route", "del", "blackhole", "default", "metric",
                "32767", "table", table, check=False)
        else:
            run("ip", af, "route", "replace", "blackhole", "default",
                "metric", "32767", "table", table)
            rules = run("ip", af, "rule", "show").stdout
            pattern = (r"^" + priority + r":\s+from all fwmark " +
                       hex(s["table"]) + r" lookup " + table + r"$")
            if not re.search(pattern, rules, flags=re.M):
                run("ip", af, "rule", "add", "pref", priority, "fwmark",
                    table, "lookup", table)


def policy(args):
    root()
    s = load()
    action = args.action
    if action == "guard":
        guard(s)
        return
    if not s.get("peer"):
        raise Error("A peer profile is required.")
    if action == "prepare":
        guard(s)
        existing = run("ip", "-6", "route", "show", "exact",
                       s["peer"]["ipv6"] + "/128").stdout.strip()
        if existing:
            raise Error("Endpoint host route already exists; refusing to overwrite it.")
        run(*s["host_route"])
        s["host_route_active"] = True
        save(s)
    elif action == "up":
        guard(s)
        if s["role"] == "iran":
            a, b = inner(s)
            for af, addr in (("-4", a), ("-6", b)):
                run("ip", af, "route", "replace", "default", "dev", s["interface"],
                    "src", addr, "metric", "10", "table", str(s["table"]))
            run("sysctl", "-q", "-w", "net.ipv4.conf." + s["interface"] + ".rp_filter=2")
        else:
            if s.get("accept_ra_key"):
                run("sysctl", "-q", "-w", s["accept_ra_key"] + "=2")
            run("sysctl", "-q", "-w", "net.ipv4.ip_forward=1",
                "net.ipv6.conf.all.forwarding=1")
        firewall(s, True)
    elif action == "down":
        # Never remove the fail-closed guard here: a stopped tunnel must not
        # fall through to the country's physical default route.
        guard(s)
        if s["role"] == "iran":
            for af in ("-4", "-6"):
                run("ip", af, "route", "del", "default", "dev", s["interface"],
                    "metric", "10", "table", str(s["table"]), check=False)
        firewall(s, False)
    elif action == "finish":
        if s.get("host_route_active"):
            cmd = list(s["host_route"])
            cmd[3] = "del"
            run(*cmd, check=False)
            s["host_route_active"] = False
            save(s)


def panel_template(old, tags, mark):
    new = copy.deepcopy(old)
    if "dns" in new:
        raise Error("An existing custom DNS configuration needs a manual merge; it was not overwritten.")
    if any(x.get("tag") == TAG for x in new.get("outbounds", [])):
        raise Error("The managed outbound tag already exists.")
    outbound = {"tag": TAG, "protocol": "freedom",
                "settings": {"domainStrategy": "ForceIP"},
                "streamSettings": {"sockopt": {"mark": mark, "domainStrategy": "ForceIP"}}}
    # Preserve the existing default for unselected inbounds.
    new.setdefault("outbounds", []).append(outbound)
    rules = new.setdefault("routing", {}).get("rules", [])
    api = [r for r in rules if r.get("outboundTag") == "api"]
    blocks = [r for r in rules if r.get("outboundTag") == "blocked"]
    rest = [r for r in rules if r.get("outboundTag") not in ("api", "blocked")]
    new["routing"]["rules"] = api + blocks + [
        {"type": "field", "inboundTag": [DNS_TAG], "outboundTag": TAG},
        {"type": "field", "inboundTag": tags, "outboundTag": TAG}] + rest
    new["dns"] = {"servers": ["1.1.1.1", "8.8.8.8"],
                  "queryStrategy": "UseIP", "tag": DNS_TAG}
    return new


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def panel(args):
    root()
    s = load()
    if s["role"] != "iran" or not s.get("peer"):
        raise Error("Panel integration is only available on a configured Iran role.")
    if s.get("panel"):
        raise Error("Panel integration already exists. Roll it back before reapplying.")
    if not args.yes:
        raise Error("This restarts x-ui briefly. Review the README, then use --yes.")
    if not PANEL_DB.exists() or not XRAY_CONFIG.exists() or not Path(XRAY).exists():
        raise Error("The standard 3x-ui installation was not found.")
    # A non-root x-ui installation needs socket-mark capability. Do not claim
    # that backend tests validate the permissions of another process.
    pid = run("systemctl", "show", "x-ui", "-p", "MainPID", "--value").stdout.strip()
    if not pid.isdigit() or int(pid) == 0:
        raise Error("Start the existing x-ui service before panel integration.")
    status_text = Path("/proc/" + pid + "/status").read_text()
    cap = re.search(r"^CapEff:\s+([0-9a-f]+)$", status_text, flags=re.M)
    if not cap or not int(cap[1], 16) & ((1 << 12) | (1 << 13)):
        raise Error("The panel process lacks capability to set SO_MARK; review service permissions.")
    test(argparse.Namespace())
    c = sqlite3.connect(PANEL_DB, timeout=10)
    try:
        if not c.execute("SELECT 1 FROM settings WHERE key='xrayTemplateConfig'").fetchone():
            raise Error("No saved xrayTemplateConfig. Save the Xray settings once in the panel.")
        enabled = [r[0] for r in c.execute("SELECT tag FROM inbounds WHERE enable=1")]
        tags = args.inbound_tag or enabled
        if not tags or any(t not in enabled for t in tags):
            raise Error("Select at least one existing, enabled inbound tag.")
        old = c.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone()[0]
        new = panel_template(json.loads(old), tags, s["table"])
        newtext = json.dumps(new)
        runtime = json.loads(XRAY_CONFIG.read_text())
        for k in ("outbounds", "routing", "dns"):
            runtime[k] = new[k]
        b = BACKUPS / time.strftime("%Y%m%d-%H%M%S")
        b.mkdir(mode=0o700, parents=True)
        os.chmod(BACKUPS, 0o700)
        bc = sqlite3.connect(b / "x-ui.db")
        c.backup(bc)
        bc.close()
        write_private(b / "template-before.json", old)
        write_private(b / "candidate.json", json.dumps(runtime))
        run(XRAY, "run", "-test", "-config", b / "candidate.json")
        s["panel"] = {"backup": str(b), "hash": digest(newtext), "tags": tags,
                      "dropin_before": DROPIN.read_text() if DROPIN.exists() else None}
        save(s)
        DROPIN.parent.mkdir(parents=True, exist_ok=True)
        DROPIN.write_text("[Unit]\nRequires=" + GUARD + ".service\nWants=" +
                          service(s) + ".service\nAfter=" + GUARD + ".service " +
                          service(s) + ".service\n")
        os.chmod(DROPIN, 0o644)
        run("systemctl", "daemon-reload")
        run("systemd-run", "--unit=ipv6-awg-panel-rollback", "--on-active=180",
            POLICY, "rollback-panel")
        c.execute("BEGIN IMMEDIATE")
        # Detect panel edits that occurred while validation was running.
        if c.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone()[0] != old:
            c.rollback()
            run("systemctl", "stop", "ipv6-awg-panel-rollback.timer", check=False)
            if s["panel"]["dropin_before"] is None:
                DROPIN.unlink(missing_ok=True)
            else:
                DROPIN.write_text(s["panel"]["dropin_before"])
            run("systemctl", "daemon-reload")
            s.pop("panel")
            save(s)
            raise Error("Panel settings changed concurrently. Stop and review the backup.")
        c.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig'", (newtext,))
        c.commit()
        run("systemctl", "restart", "x-ui")
        run("systemctl", "is-active", "--quiet", "x-ui")
        actual = json.loads(XRAY_CONFIG.read_text())
        if not any(o.get("tag") == TAG and
                   o.get("streamSettings", {}).get("sockopt", {}).get("mark") == s["table"]
                   for o in actual["outbounds"]):
            raise Error("The generated runtime did not contain the managed outbound.")
        test(argparse.Namespace())
        run("systemctl", "stop", "ipv6-awg-panel-rollback.timer")
        print("Panel routing enabled. Existing clients/inbounds were not rewritten.")
        print("Now test an actual client from the intended ISP. Server tests are not ISP tests.")
    finally:
        c.close()


def rollback_panel(args):
    root()
    s = load()
    p = s.get("panel")
    if not p:
        print("No managed panel integration to roll back.")
        return
    old = (Path(p["backup"]) / "template-before.json").read_text()
    c = sqlite3.connect(PANEL_DB, timeout=10)
    try:
        c.execute("BEGIN IMMEDIATE")
        current = c.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone()[0]
        if digest(current) != p["hash"] and current != old:
            raise Error("Panel changed after integration. Refusing to overwrite newer edits; merge the private backup manually.")
        c.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig'", (old,))
        c.commit()
    finally:
        c.close()
    if p["dropin_before"] is None:
        DROPIN.unlink(missing_ok=True)
    else:
        DROPIN.write_text(p["dropin_before"])
    run("systemctl", "daemon-reload")
    run("systemctl", "restart", "x-ui")
    run("systemctl", "stop", "ipv6-awg-panel-rollback.timer", check=False)
    s.pop("panel")
    save(s)
    print("Original panel template restored. Users and usage counters preserved.")


def marked_socket(s, family, kind):
    sock = socket.socket(family, kind)
    sock.settimeout(15)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, s["table"])
    return sock


def trace(s, address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    raw = marked_socket(s, family, socket.SOCK_STREAM)
    raw.connect((address, 443))
    with ssl.create_default_context().wrap_socket(raw, server_hostname="one.one.one.one") as tls:
        tls.sendall(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n")
        data = b""
        while len(data) < 65536:
            part = tls.recv(8192)
            if not part:
                break
            data += part
    match = re.search(rb"(?:\r?\n)ip=([0-9a-fA-F:.]+)", data)
    if not match or not ipaddress.ip_address(match[1].decode()).is_global:
        raise Error("No public exit address found in the HTTPS trace response.")
    return match[1].decode()


def test(args):
    root()
    s = load()
    if not s.get("peer"):
        raise Error("Configure both peer profiles first.")
    role = "exit" if s["role"] == "iran" else "iran"
    a, b = inner(s, role)
    run("ping", "-c", "5", "-W", "2", a, capture=False)
    run("ping", "-6", "-c", "3", "-W", "2", b, capture=False)
    if s["role"] != "iran":
        print("Peer reachability passed. Internet-exit tests run on the Iran role.")
        return
    # Both tests use SO_MARK; do not accidentally test Iran's direct connection.
    print("Marked IPv4 HTTPS exit: " + trace(s, "1.1.1.1"))
    print("Marked IPv6 HTTPS exit: " + trace(s, "2606:4700:4700::1111"))
    ident = secrets.token_bytes(2)
    q = ident + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    q += b"\x07example\x03com\x00\x00\x01\x00\x01"
    with marked_socket(s, socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(q, ("1.1.1.1", 53))
        response, sender = sock.recvfrom(4096)
    if sender[0] != "1.1.1.1" or response[:2] != ident or not response[2] & 0x80 or response[3] & 15:
        raise Error("Marked UDP DNS test failed.")
    print("Marked UDP DNS: PASS. These are short server-side tests, not a capacity guarantee.")


def status(args):
    root()
    s = load()
    safe = {k: s[k] for k in ("role", "interface", "local_ipv6", "port", "mtu", "table")}
    print(json.dumps(safe, indent=2))
    run("systemctl", "--no-pager", "--full", "status", service(s), check=False, capture=False)
    for field in ("public-key", "endpoints", "latest-handshakes", "transfer"):
        run("awg", "show", s["interface"], field, check=False, capture=False)
    if s["role"] == "iran":
        for af in ("-4", "-6"):
            run("ip", af, "route", "show", "table", str(s["table"]), capture=False)
    print("Never share the private configuration, private.key, database or backups.")


def export(args):
    root()
    data = json.dumps(profile(load()), indent=2) + "\n"
    if args.output:
        write_private(args.output, data)
    else:
        print(data, end="")


def wizard(args):
    """Interactive entry point; only public profiles are exchanged."""
    root()
    print("IPv6 AmneziaWG setup wizard")
    print("No guarantee against IP blocking or any fixed speed/capacity.")
    print("Keep a separate management session open. Never exchange private keys.")
    if STATE_FILE.exists():
        s = load()
        if s.get("uninstalled"):
            raise Error("Archive uninstalled state privately before reinitializing.")
        print("Resuming the existing " + s["role"] + " installation.")
    else:
        if not shutil.which("awg"):
            if input("Install upstream signed packages now? [y/N]: ").strip().lower() != "y":
                raise Error("Installation declined.")
            install(argparse.Namespace(yes=True))
        role = input("Server role [exit/iran]: ").strip().lower()
        if role not in ("exit", "iran"):
            raise Error("Choose exit or iran.")
        print(run("ip", "-6", "addr", "show", "scope", "global").stdout)
        address = input("Stable public IPv6 address assigned to this server: ").strip()
        port_text = input("Unused local UDP port [blank = random 40000-54999]: ").strip()
        mtu = input("Tunnel MTU [1420; use 1380/1280 for lower-MTU paths]: ").strip()
        options = argparse.Namespace(
            role=role, local_ipv6=address, port=int(port_text) if port_text else None,
            interface="awg-v6", mtu=int(mtu) if mtu else 1420, table=51871,
            priority=11071, ipv4_network="10.77.77.0/30", ipv6_network="fd77:77:77::/64",
            peer_file=None, export=None)
        init(options)
        s = load()
    if not s.get("peer"):
        if s["role"] == "exit":
            print("COPY THIS PUBLIC PROFILE to the Iran server wizard:")
            print(json.dumps(profile(s), indent=2))
        print("Paste the OTHER server's public JSON profile; finish with a blank line.")
        print("Start on exit, paste exit profile into Iran, then paste Iran's updated profile here.")
        lines = []
        while True:
            line = input()
            if not line.strip():
                break
            lines.append(line)
        data = json.loads("\n".join(lines))
        # Validate before installing or opening a peer.
        peer_path = STATE_DIR / "wizard.peer.json"
        write_private(peer_path, json.dumps(data))
        try:
            peer(argparse.Namespace(file=str(peer_path)))
        finally:
            peer_path.unlink(missing_ok=True)
        s = load()
        if s["role"] == "iran":
            print("COPY THIS UPDATED PUBLIC PROFILE back to the exit server wizard:")
            print(json.dumps(profile(s), indent=2))
    input("Finish peer configuration on the other server, then press Enter to test: ")
    test(argparse.Namespace())
    if s["role"] == "iran" and not s.get("panel"):
        answer = input("Route existing 3x-ui inbounds through this tunnel? [y/N]: ").strip().lower()
        if answer == "y":
            print("This briefly restarts x-ui. Existing users/keys/ports remain unchanged.")
            text = input("Inbound tags separated by spaces [ALL = all currently enabled]: ").strip()
            if not text:
                raise Error("Specify inbound tags or explicitly enter ALL.")
            panel(argparse.Namespace(yes=True, inbound_tag=None if text == "ALL" else text.split()))
    print("Setup finished. Test an actual VPN client from its intended ISP.")
    print("Check listener port, External Proxy advertised port, and imported link port.")


def uninstall(args):
    root()
    if not args.yes:
        raise Error("Use --yes after reviewing uninstall and rollback instructions.")
    s = load()
    if s.get("panel"):
        rollback_panel(argparse.Namespace())
        s = load()
    run("systemctl", "disable", "--now", service(s), check=False)
    if s.get("peer"):
        policy(argparse.Namespace(action="down"))
        policy(argparse.Namespace(action="finish"))
    if s["role"] == "iran":
        run("systemctl", "disable", "--now", GUARD, check=False)
        Path("/etc/systemd/system/" + GUARD + ".service").unlink(missing_ok=True)
        guard(s, remove=True)
    else:
        # Forwarding is a shared system setting. Restore explicitly only when
        # requested; another tunnel or Docker may now depend on forwarding.
        if args.restore_forwarding:
            for key, value in s.get("forwarding_before", {}).items():
                run("sysctl", "-q", "-w", key + "=" + value)
    cfg = config_path(s)
    if cfg.exists():
        write_private(STATE_DIR / "uninstalled-config.conf", cfg.read_text())
        cfg.unlink()
    run("systemctl", "daemon-reload")
    # Hooks may have updated route ownership while stopping the service.
    s = load()
    s["uninstalled"] = True
    save(s)
    print("Managed services/rules removed. Keys, state, packages and private backups retained.")


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("install", help="Install upstream signed packages on supported Ubuntu")
    a.add_argument("--yes", action="store_true")
    a.set_defaults(func=install)
    a = sub.add_parser("init", help="Generate local keys and a public peer profile")
    a.add_argument("--role", choices=("iran", "exit"), required=True)
    a.add_argument("--local-ipv6", required=True)
    a.add_argument("--port", type=int)
    a.add_argument("--interface", default="awg-v6")
    a.add_argument("--mtu", type=int, default=1420)
    a.add_argument("--table", type=int, default=51871)
    a.add_argument("--priority", type=int, default=11071)
    a.add_argument("--ipv4-network", default="10.77.77.0/30")
    a.add_argument("--ipv6-network", default="fd77:77:77::/64")
    a.add_argument("--peer-file")
    a.add_argument("--export")
    a.set_defaults(func=init)
    a = sub.add_parser("peer", help="Configure/start a peer from its public JSON profile")
    a.add_argument("--file", required=True)
    a.set_defaults(func=peer)
    a = sub.add_parser("export", help="Export only the public peer profile")
    a.add_argument("--output")
    a.set_defaults(func=export)
    sub.add_parser("wizard", help="Interactive English setup with public profile exchange").set_defaults(func=wizard)
    for name, fn in (("status", status), ("test", test), ("rollback-panel", rollback_panel)):
        sub.add_parser(name).set_defaults(func=fn)
    a = sub.add_parser("panel", help="Route selected 3x-ui inbounds through the tunnel")
    a.add_argument("--yes", action="store_true")
    a.add_argument("--inbound-tag", action="append")
    a.set_defaults(func=panel)
    a = sub.add_parser("uninstall", help="Remove managed configuration without deleting keys/backups")
    a.add_argument("--yes", action="store_true")
    a.add_argument("--restore-forwarding", action="store_true")
    a.set_defaults(func=uninstall)
    a = sub.add_parser("policy", help=argparse.SUPPRESS)
    a.add_argument("action", choices=("guard", "prepare", "up", "down", "finish"))
    a.set_defaults(func=policy)
    return p


def main():
    args = parser().parse_args()
    try:
        args.func(args)
    except (Error, OSError, ValueError, KeyError, EOFError, sqlite3.Error) as e:
        print("ERROR: " + str(e), file=sys.stderr)
        print("Do not disable firewalls or flush routes to work around this error.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())