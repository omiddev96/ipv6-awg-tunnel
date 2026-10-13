# IPv6 AWG Tunnel

A server-to-server **AmneziaWG kernel tunnel over native IPv6**, with dual-stack
Internet egress and optional **3x-ui** routing integration.

```text
VPN client -> Iran server / existing 3x-ui inbound
           -> encrypted AmneziaWG UDP tunnel over public IPv6
           -> exit server -> IPv4 / IPv6 Internet
```

All commands, messages, and instructions are in English.

## Interactive quick start

On both servers, download/review this repository, then run:

```bash
sudo bash install.sh wizard
```

Start the **exit** wizard first. It displays a **public JSON profile**. Paste
that profile into the **Iran** wizard, then copy the Iran wizard's updated
public profile back to the exit wizard. Finish pasted JSON with one blank line.
No private key or server password is exchanged.

After both peers are configured, the wizard tests the tunnel and offers optional
3x-ui integration on the Iran side. Existing installations can resume; they are
not silently overwritten. Advanced network/table choices use the explicit CLI
below rather than the default wizard.

## Read this first

- **No tunnel or inbound can guarantee that an IP will never be blocked.**
  AmneziaWG changes packet signatures; it does not make a public server invisible.
- **No speed, ping, jitter, uptime, or 500-user capacity guarantee.** Benchmark
  your route and monitor the actual client workload.
- The public IPv6 connection is between the servers. VPN clients do **not** need
  IPv6 if your existing inbound accepts IPv4.
- This project does **not** install 3x-ui, create user accounts/inbounds, modify
  client links, or replace inbound TLS/REALITY keys.
- Never commit private keys, panel databases, backups, logs, client access links,
  or runtime configuration to GitHub.
- Do not disable security controls or flush firewall tables to make it work.
- Use servers/networks you control and follow applicable laws/provider terms.

## Supported environments and honest limitations

| Environment | Status |
| --- | --- |
| Ubuntu 24.04, matching kernel headers, systemd, root | Primary supported target |
| Ubuntu 22.04 with the upstream Amnezia PPA and a buildable kernel | Supported installation path; not independently live-tested here |
| ARM64 Ubuntu | Official Ubuntu Ports source indices are selected; not independently live-tested here |
| Debian / other distributions | Automatic installer refuses; no claim of support |
| Windows, OpenVZ, restricted containers, no kernel-module access | Not supported |
| IPv4-only servers | Not supported by this native-IPv6 design |
| Custom nftables/firewalld/provider firewalls | Require manual review; unrelated chains can still block traffic |
| Custom 3x-ui DNS configuration | Automatic panel integration refuses rather than overwriting it |

You need **two servers with working native public IPv6**, a normal Linux kernel,
the ability to load AmneziaWG, and sufficient disk space to build the DKMS module.
The exit server needs working IPv4 and IPv6 Internet access for dual-stack egress.
Matching headers for the **running** kernel must be available. Secure Boot may
require administrator-managed module signing.

The upstream package version is not pinned; the version provided by the signed
Amnezia PPA at installation time is used. Review upstream release changes before
upgrading. The installer never performs a full system upgrade or reboot.

## 1. Inspect both servers

Keep an independent SSH/provider console session available.

```bash
cat /etc/os-release
uname -r
ip -6 addr show scope global
ip -6 route show default
ip -4 route show default
df -h /
```

Select a **stable, assigned public IPv6 address** on each server, not a temporary
privacy address. If a server has multiple addresses, test them separately.

```bash
# Replace the placeholder before running.
ping -6 -c 10 EXIT_PUBLIC_IPV6
```

If there is no public IPv6 address/default route, fix that with the provider
before installing this project. ICMP reachability alone does not prove UDP or
AmneziaWG reachability.

## 2. Download and review on BOTH servers

```bash
sudo apt-get update
sudo apt-get install -y git python3
git clone https://github.com/omiddev96/ipv6-awg-tunnel.git
cd ipv6-awg-tunnel

# Read the code before granting root execution.
less tunnel.py
less README.md

# No executable permission is required when invoking through bash.
sudo bash install.sh install --yes
```

Installation adds the official Amnezia PPA and separate official Ubuntu source
indices for the kernel build. Existing binary repository entries are not changed.
This avoids VPS mirrors that return 404 for source indices.

If package installation fails:

```bash
sudo tail -n 80 /var/log/ipv6-awg-tunnel-install.log
```

Do not upgrade/reboot a production server blindly. Resolve missing running-kernel
headers, source availability, disk space, or module signing deliberately.

## 3. Initialize the EXIT server first

Choose an unused UDP port and replace every placeholder. Ports 40179 and 40181
below are examples, **not universal best ports**. Fresh random ports are used
when `--port` is omitted.

On the exit server:

```bash
sudo bash install.sh init \
  --role exit \
  --local-ipv6 EXIT_PUBLIC_IPV6 \
  --port 40179 \
  --export /root/exit.peer.json
```

The public profile contains the public key, endpoint, inner networks, and shared
obfuscation parameters. **It contains no private key.**

Copy `/root/exit.peer.json` to `/root/exit.peer.json` on the Iran server using
your trusted management connection. For example, from an administrator machine:

```bash
scp root@EXIT_SSH_HOST:/root/exit.peer.json ./exit.peer.json
scp ./exit.peer.json root@IRAN_SSH_HOST:/root/exit.peer.json
```

Use your actual SSH port, SSH key, bastion, or IPv6 management path as necessary.
Do not copy `/etc/ipv6-awg-tunnel/private.key`.

## 4. Initialize the IRAN server

On the Iran server:

```bash
sudo bash install.sh init \
  --role iran \
  --local-ipv6 IRAN_PUBLIC_IPV6 \
  --port 40181 \
  --peer-file /root/exit.peer.json \
  --export /root/iran.peer.json
```

The Iran side adopts the exit side's obfuscation parameters. Export the Iran
profile **after** this step, so both profiles agree.

Copy `/root/iran.peer.json` to the exit server:

```bash
scp root@IRAN_SSH_HOST:/root/iran.peer.json ./iran.peer.json
scp ./iran.peer.json root@EXIT_SSH_HOST:/root/iran.peer.json
```

## 5. Complete the peer on the EXIT server

```bash
sudo bash install.sh peer --file /root/iran.peer.json
```

After `init`, the manager is also installed as:

```bash
sudo ipv6-awg-tunnel status
sudo ipv6-awg-tunnel export --output /root/public.peer.json
```

Open UDP 40179 on the exit server **only from the selected Iran IPv6** and
UDP 40181 on the Iran server **only from the selected exit IPv6** in provider
security groups/firewalls. Substitute your actual ports.

Local rules are added without flushing other rules. Separate nftables base
chains, provider firewalls, or security policies may still drop the packets.

## 6. Test BEFORE moving VPN traffic

On both servers:

```bash
sudo ipv6-awg-tunnel status
sudo ipv6-awg-tunnel test
```

The exit side tests peer reachability. The Iran side also tests:

- marked IPv4 HTTPS traffic;
- marked IPv6 HTTPS traffic;
- marked UDP DNS traffic.

These traffic tests use `SO_MARK`, not the Iran server's direct Internet route.
HTTPS certificate verification remains enabled.

Check the handshake timestamp and transfer counters:

```bash
sudo awg show awg-v6 latest-handshakes
sudo awg show awg-v6 transfer
```

Do not proceed with panel integration if these tests fail.

### Optional short throughput test

On the exit server, bind the test server to the **private tunnel address only**:

```bash
sudo iperf3 -s -B 10.77.77.2 -p 52071
```

On the Iran server:

```bash
iperf3 -c 10.77.77.2 -p 52071 -P 4 -t 10
iperf3 -c 10.77.77.2 -p 52071 -P 4 -t 10 -R
iperf3 -c 10.77.77.2 -p 52071 -u -b 30M -l 1200 -t 10
iperf3 -c 10.77.77.2 -p 52071 -u -b 30M -l 1200 -t 10 -R
```

Stop the exit test server with **Ctrl+C** afterwards. Tests consume bandwidth.
Replace inner addresses if you selected custom networks.

## 7. Integrate an EXISTING 3x-ui panel (optional; Iran only)

Tested integration design targets the standard **3x-ui 2.9.4** layout:

```text
/etc/x-ui/x-ui.db
/usr/local/x-ui/bin/config.json
/usr/local/x-ui/bin/xray-linux-amd64
```

Save the panel's Xray settings once if it does not yet have a saved
`xrayTemplateConfig`. Do not edit the panel concurrently during integration.
Keep a console/SSH connection open.

Select specific existing inbound tags:

```bash
sudo ipv6-awg-tunnel panel --yes \
  --inbound-tag inbound-443 \
  --inbound-tag inbound-8443
```

Or select all inbounds that are enabled **at the time this command runs**:

```bash
sudo ipv6-awg-tunnel panel --yes
```

The integration:

1. tests the tunnel before editing;
2. backs up the database and original template privately;
3. preserves inbound/client credentials and traffic counters;
4. validates the candidate with the installed Xray binary;
5. routes selected inbounds through a marked Freedom outbound;
6. preserves API routing and existing `blocked` rules;
7. sends built-in DNS queries through the marked tunnel;
8. uses `ForceIP` resolution to avoid system-resolution fallback;
9. establishes a startup dependency on the fail-closed guard;
10. arms a 180-second rollback timer before editing;
11. briefly restarts x-ui and checks generated runtime/service health;
12. cancels rollback after the server-side checks pass.

Unselected inbounds retain the previous default outbound/rules. New inbounds
created later are **not automatically enrolled**; route their tags to the managed
outbound in the panel or roll back and reapply with the desired tag list.
The running panel process must have the Linux capability needed for `SO_MARK`;
the script checks this rather than assuming a non-root service can mark sockets.

Automatic checks are not a mobile/ISP end-to-end test. Test your actual client
immediately after integration.

### IMPORTANT: External Proxy port must match the advertised client endpoint

If an inbound actually listens on **8443**, but **External Proxy** advertises
**443**, exported links may connect to the wrong inbound and fail.

Verify all three:

```text
Actual inbound port:          8443
External Proxy advertised port: 8443
Imported client link port:    8443
```

That equality applies when there is **no real reverse proxy/port mapping**
between the advertised and listener ports. If you intentionally run an actual
reverse proxy, its externally reachable port may differ; verify that mapping.

This script deliberately does not change External Proxy settings, listen ports,
REALITY keys, or client links. Fix those in the panel and reimport the client
configuration when necessary.

The selected port is a client-entry setting. It is unrelated to the UDP port of
the server-to-server AmneziaWG tunnel.

## 8. Routine operation

```bash
sudo ipv6-awg-tunnel status
sudo systemctl status awg-quick@awg-v6 --no-pager
sudo journalctl -u awg-quick@awg-v6 -n 80 --no-pager
sudo systemctl restart awg-quick@awg-v6
```

Restarting the tunnel temporarily interrupts routed VPN traffic. Management
traffic keeps the physical main route. No global default route is replaced.

The fail-closed table retains a blackhole default when the Iran tunnel stops.
The guard starts before the managed panel/tunnel; panel startup requires the
guard. If the tunnel fails, marked traffic is dropped rather than exiting through
the Iran server's direct Internet connection.

This only protects traffic actually routed to the managed outbound. A later
manual panel rule that explicitly sends traffic elsewhere is outside that scope.

The exit side enables forwarding on service startup. RA-based IPv6 routes are
handled with per-interface `accept_ra=2` when needed. NAT/forwarding rules are
limited to the tunnel peer's private IPv4/IPv6 addresses.

## 9. Rollback

Restore the previous panel template while leaving the tunnel installed:

```bash
sudo ipv6-awg-tunnel rollback-panel
```

The operation preserves users and usage counters. If someone edited the template
after integration, rollback refuses to overwrite newer changes. Review the
private backup and merge deliberately instead.

Private backups are under:

```text
/var/lib/ipv6-awg-tunnel/backups/
```

Remove managed tunnel configuration on both servers:

```bash
sudo ipv6-awg-tunnel uninstall --yes
```

Panel rollback must succeed before removing an integrated tunnel. Managed
firewall rules, the interface configuration, the endpoint host route, and the
guard/routing rules are removed. Unrelated rules/services are not flushed.

Keys, private backups, manager files, installed packages, and package repositories
are retained. Forwarding is a shared setting and remains enabled by default;
only if no other service depends on it:

```bash
sudo ipv6-awg-tunnel uninstall --yes --restore-forwarding
```

To perform a fresh reinitialization later, privately archive the existing
`/etc/ipv6-awg-tunnel` state directory first. Do not publish that archive.

## 10. Troubleshooting

### No handshake

- Confirm BOTH peer profiles were exchanged and the exit owns the shared parameters.
- Verify selected IPv6 addresses are assigned/stable and reachable.
- Check provider firewalls and local/custom nftables chains.
- Ensure each UDP listener is unused by other services.
- After suspected flow-based blocking, a fresh address/port may behave differently;
  no universal port or concealment guarantee is claimed.
- Review the service log. Do not fall back silently to direct Iran egress.

### Handshake works but Internet traffic fails

- Run the marked `test` on the Iran side.
- Check exit IPv4/IPv6 Internet routes, forwarding and NAT.
- Docker may set a FORWARD drop policy; the installer inserts narrowly scoped
  allow rules without removing Docker's rules.
- Other base-chain drops can still win over accepts.
- Verify MTU. For a lower-MTU route, initially set `--mtu 1380` or `1280` on
  both new installations instead of increasing above 1420 blindly.

### Server checks work but a VPN client does not

- Check app/core versions and transport support (especially XHTTP/REALITY).
- Verify the **External Proxy advertised port** and actual link endpoint.
- Compare the existing inbound with the new inbound on the same ISP.
- Test from the actual mobile/fixed ISP; foreign-server reachability is not proof
  of domestic reachability.
- Verify certificate/SNI, short ID, public key, path and user ID privately.
- Never paste your private key or full access link into a public issue.

### Another tunnel already exists

Existing interfaces, endpoint host routes, inner networks, routing tables,
rule priorities and UDP listeners are checked. The script refuses collisions.
For a different installation, choose unused resources consistently on both sides:

```bash
sudo bash install.sh init --role exit --local-ipv6 EXIT_PUBLIC_IPV6 \
  --interface awg-v6 --port 45001 --table 51881 --priority 11081 \
  --ipv4-network 10.78.78.0/30 --ipv6-network fd78:78:78::/64 \
  --export /root/exit.peer.json
```

Only **one managed installation per server** is supported by this project's
state directory. It does not migrate/delete unrelated tunnels automatically.

## Security and testing

Private files use restricted permissions. Endpoint ports accept only the selected
peer IPv6 locally. Public profiles are intentionally exportable; private server
keys never need to leave their server.

The repository contains no deployment IPs, private keys or client credentials.

```bash
bash -n install.sh
python3 -m py_compile tunnel.py
python3 -m unittest discover -s tests -v
```

Unit tests and syntax checks do not prove a fresh-host DKMS installation will
succeed. The underlying two-server design, dual-stack egress, UDP forwarding,
service restart, fail-closed behavior, and 3x-ui integration were live-tested
on Ubuntu 24.04. The generalized installer itself needs a clean-server trial
before broad production rollout. CI performs static/unit tests, not root-level
network integration tests.

## Upstream references

- [AmneziaWG kernel module and official installation instructions](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)
- [AmneziaWG tools](https://github.com/amnezia-vpn/amneziawg-tools)
- [Xray socket marks / transport options](https://xtls.github.io/en/config/transports/sockopt.html)
- [Xray built-in DNS routing](https://xtls.github.io/en/config/dns.html)
- [3x-ui](https://github.com/MHSanaei/3x-ui)

## License

MIT for this project's installer/manager. Upstream packages retain their own
licenses; AmneziaWG's kernel implementation is GPLv2.