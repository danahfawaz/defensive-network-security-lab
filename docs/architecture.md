# Architecture and security controls

![Topology](generated/topology.svg)

The diagram, the [addressing plan](generated/addressing.md) and the [port map](generated/cabling.md) are generated from `topology/topology.yaml`, which `ciscoaudit design-check` compares against the device configurations (addresses, VLANs, ports, trunks, NAT entries).

## From the original lab to this design

The university project was four 1841 routers, three 2960 switches and six PCs with default hostnames, RIPv1, no VLANs, no passwords and no ACLs. The devices and cables that could be kept were kept; the rest was redesigned because the original topology could not be secured as built.

| Original | Problem | Now |
|---|---|---|
| Router1 hub with Router2 and Router3 beside it | Inter-LAN traffic could be routed around any filter placed on Router1, so there was no single enforcement point | Router1 → **FW-EDGE**, routes every VLAN itself (router-on-a-stick) and is the only inter-zone path; Router2 and Router3 retired |
| Flat LANs, RIPv1 | No segmentation; routing updates accepted from anyone | Five VLAN/zones; static routes only |
| Router4 + Switch2 + PC4/PC5 | – | Kept as the simulated Internet (**ISP-R**, **SW-INET**); PC5 plays the attacker; excluded from the audit |
| Default names, no secrets | – | Hostnames and roles; SSH, local accounts, encrypted secrets |

Retired devices and the cable map are in [cabling](generated/cabling.md); the original configurations are kept under `configs/original-lab/` and audited as the "Day 0" state.

## Zones and policy

FW-EDGE is a three-legged router firewall. Each zone's gateway is an interface (or 802.1Q subinterface) of FW-EDGE with an inbound extended ACL that ends in `deny ip any any log`.

| Zone | VLAN / subnet | Inbound ACL | May initiate |
|---|---|---|---|
| Users | 10 · 10.10.10.0/24 | `IN-USERS` | HTTP/HTTPS/ping to SRV-APP; HTTP/HTTPS/ping to WEB-DMZ; DNS to DNS-DMZ; HTTP/HTTPS/ping to the Internet (PAT) |
| Servers | 20 · 10.10.20.0/24 | `IN-SERVERS` | DNS to DNS-DMZ; ping to its gateway; otherwise only replies (to employees and the administrator, and the HTTP reply to WEB-DMZ) |
| Guest | 30 · 10.10.30.0/24 (DHCP) | `IN-GUEST` | DHCP; DNS to DNS-DMZ; HTTP/HTTPS/ping to the Internet (PAT); nothing internal |
| Management | 99 · 10.10.99.0/24 | `IN-MGMT` | Administrator: SSH to FW-EDGE and SW-DMZ (SW-ACCESS shares the VLAN), HTTP/HTTPS/ping to the servers; log server: NTP to the devices |
| DMZ | 50 · 172.16.50.0/24 | `IN-DMZ` | WEB-DMZ → SRV-APP (HTTP); DMZ switch → syslog/NTP; otherwise only replies |
| Outside | 203.0.113.0/30 | `IN-OUTSIDE` | Internet → public web (80/443) and DNS (53) addresses of the DMZ servers; everything else denied |

The exact list of flows the organisation wants is written once, with a reason for each, in `topology/policy-intent.yaml`; `ciscoaudit matrix` checks the configuration against it for 3 146 sender/destination/service combinations ([validation](validation.md)).

### Address translation

* Users and Guests leave through PAT on the outside interface (`203.0.113.2`).
* The DMZ servers are published with static NAT (`203.0.113.9` web, `203.0.113.10` DNS) from the provider-routed block `203.0.113.8/29`; a `Null0` discard route for the block (a `[PT-VERIFY]` line) stops loops and probes of unused addresses.
* `IN-OUTSIDE` is evaluated *before* NAT, so it matches the public addresses; the NAT inside addresses are never reachable directly.

## Security controls

| Area | Control | Where | Evidence |
|---|---|---|---|
| Segmentation | VLANs per zone; one routed enforcement point | FW-EDGE subinterfaces, SW-ACCESS/SW-DMZ | design-check, scenarios B-nn |
| Traffic filtering | Default-deny inbound extended ACLs with logged final deny | FW-EDGE | audit rules ACL-001/002; scenarios P-nn (allowed) and B-nn (blocked) |
| Anti-spoofing | Own-subnet source in every inbound ACL; bogon and own-public-address denies on the outside | FW-EDGE | scenarios S-nn |
| Remote management | SSH v2 only, `login local` with a local `admin` account (one shared account per device), `VTY-ADMIN` (administrator host only), 5-minute time-out, login throttling, no HTTP server | all audited devices | MGMT-001/002/003/005/010, scenarios M-nn |
| Credentials | `enable secret`, hashed local accounts, `service password-encryption`, no defaults | all | CRED-001..005 |
| Layer 2 | DTP off, native VLAN 999, allowed-VLAN trunks, VTP transparent, port security (sticky, maximum 1), PortFast + BPDU Guard, unused ports shut and parked, DHCP snooping + DAI on the Guest VLAN | switches | L2-001..012, scenarios L-nn |
| Hardening | CDP off, no source routing, no proxy ARP/redirects/unreachables where set, AUX off | all | SVC-001..004, INT-001/002 |
| Visibility | Syslog and NTP to SRV-LOG, time stamps, logged ACL denies | all | LOG-001..003 |
| Known gaps | Stateless ACLs, flat VLANs, in-band DMZ switch, no AAA | – | [limitations](limitations.md), waivers |

Lines that have not been run in Packet Tracer are marked `[PT-VERIFY]` in the configurations and listed in [pt-verify](generated/pt-verify.md).

## Baseline and hardened configurations

`configs/baseline/` configures the same redesigned network the way a first working version usually looks (connectivity works, one weak guest ACL ending in `permit ip any any`, Telnet, shared line passwords, clear-text enable password). `configs/hardened/` is the remediated version. Both are audited, simulated and compared, which gives a before/after story that is computed from the files rather than described.

## Repository map

| Path | Content |
|---|---|
| `src/ciscoaudit/` | auditor (`parser`, `acl`, `rules/`, `report`, `waivers`, `compare`) and policy tools (`policy/`: simulator, scenarios, matrix, design check) |
| `configs/` | `original-lab/`, `baseline/`, `hardened/`, `internet-sim/` |
| `topology/` | `topology.yaml` (the design) and `policy-intent.yaml` (the written policy) |
| `scenarios/` | 124 validation scenarios |
| `waivers/` | accepted risks with reasons and expiry |
| `scripts/` | `render_configs.py` (secrets), `generate_docs.py` (tables, diagram) |
| `docs/` | this documentation; `docs/generated/` is produced by scripts |
| `evidence/` | committed outputs of the tools; `evidence/packet-tracer/` is for your own Packet Tracer results |
| `tests/` | 300+ unit tests |
