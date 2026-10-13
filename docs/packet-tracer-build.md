# Building the lab in Packet Tracer

This is the procedure to turn the committed files into a running Packet Tracer (PT) network and to produce the evidence that is still marked *pending* in the README. It was written without being able to run Packet Tracer, so **every PT menu name below is from general PT knowledge and should be checked against your version (9.0)**. Where a step may behave differently, it is flagged.

Time needed: about 90 minutes for the first build.

## 0. What you need

* Packet Tracer 9.0 (the original project was saved with 9.0.0.0810).
* This repository, and Python 3.11+ with PyYAML (`pip install pyyaml`).
* Nothing else. No password in this repository is real; you choose your own in step 1.

## 1. Render the configurations with your own passwords

The committed configurations contain placeholder hashes (`$1$labonly$xxxx…`). They would not let you log in. Render copies that contain passwords you chose:

```bash
python scripts/render_configs.py --generate          # first run: creates lab-secrets.local.json (git-ignored)
python scripts/render_configs.py --state baseline    # optional: the "before" network
python scripts/render_configs.py --state hardened    # the "after" network
```

Output: `build/rendered/<state>/<DEVICE>.cfg` (git-ignored). Secrets are never printed. Open `lab-secrets.local.json` to read the generated passwords; keep the file private. The baseline deliberately keeps the weak lab password `cisco` so the auditor has something to find.

## 2. Place the devices and cable them

Use the device models in the table; cabling comes from `docs/generated/cabling.md` (generated from `topology/topology.yaml`, so it cannot drift from the configurations).

| Device | Packet Tracer model | Notes |
|---|---|---|
| FW-EDGE | 1841 (IOS 12.4(15)T1) | Add the `WIC-1ENET` module so that `Ethernet0/1/0` exists (the original Router1 already had it). Power the router off to insert the module. |
| ISP-R | 1841 | Needs only the two on-board FastEthernet ports. |
| SW-ACCESS, SW-DMZ, SW-INET | 2960-24TT (IOS 15.0(2)SE4) | |
| PC0–PC5 | PC-PT | |
| SRV-APP, SRV-LOG, WEB-DMZ, DNS-DMZ, WEB-EXT | Server-PT | |

Cabling summary (full table with VLANs: [cabling](generated/cabling.md); diagram: [topology.svg](generated/topology.svg)):

| Link | Cable |
|---|---|
| FW-EDGE Fa0/0 ⇄ SW-ACCESS Fa0/3 | 802.1Q trunk |
| FW-EDGE Fa0/1 ⇄ SW-DMZ Fa0/3 | access VLAN 50 |
| FW-EDGE Eth0/1/0 ⇄ ISP-R Fa0/1 | routed link 203.0.113.0/30 |
| ISP-R Fa0/0 ⇄ SW-INET Fa0/3 | access VLAN 100 |
| hosts | per the port map in [cabling](generated/cabling.md) |

Rename the devices (display name **and** hostname) exactly as in the table; the scenarios and the test plan refer to them by name.

## 3. Configure the hosts (GUI)

Addresses, gateways and DNS servers are listed in [addressing](generated/addressing.md). In PT: select a PC → *Desktop* → *IP Configuration*; select a server → *Desktop* → *IP Configuration*.

* PC2 (guest) must use **DHCP** (the pool lives on FW-EDGE, `10.10.30.100` is the expected first lease). Do not give it a static address.
* PC0, PC1, SRV-APP use `172.16.50.20` as DNS server; PC3, SRV-LOG and the DMZ servers have none.

Server services (*Services* tab of each server; tab names as in PT 8.x, verify in 9.0):

| Server | Turn on | Turn off | Content |
|---|---|---|---|
| SRV-APP | HTTP, HTTPS | everything else | Edit `index.html` so the page says "SRV-APP (internal)". |
| WEB-DMZ | HTTP, HTTPS | everything else | Page says "WEB-DMZ (public)". |
| DNS-DMZ | DNS | everything else | Add `A` records: `www.lab.local → 172.16.50.10`, `app.lab.local → 10.10.20.10`. |
| SRV-LOG | SYSLOG, NTP | everything else | Nothing to configure. |
| WEB-EXT | HTTP | everything else | Page says "WEB-EXT (the Internet)". |

Turn off every service you do not need on each server; PT enables several by default, and the lab policy assumes that nothing else listens.

## 4. Paste the configurations

Always paste in this order, one device at a time, with the device in *CLI* → privileged EXEC → `configure terminal`. Paste the contents of the rendered file.

1. **ISP-R**, **SW-INET** (`build/rendered/<state>/`). They are the same in both states.
2. **SW-ACCESS**, **SW-DMZ**.
3. **FW-EDGE**, last, because it contains the ACLs, NAT and routes that depend on the others.

Pasting a long configuration can overflow PT's CLI buffer. If lines are lost, paste in blocks of ~50 lines and keep an eye on `% Invalid input` messages. **Write down every message you get**; they are the most valuable evidence for the lines listed in [pt-verify](generated/pt-verify.md).

Hardened state only, after the paste, on each device (exported configurations do not contain the RSA key):

```
FW-EDGE(config)# crypto key generate rsa modulus 2048
SW-ACCESS(config)# crypto key generate rsa modulus 2048
SW-DMZ(config)# crypto key generate rsa modulus 2048
```

(The hostname and `ip domain-name lab.local` are already in the configurations. If PT asks for the modulus interactively, enter `2048`.) Then save: `end`, `write memory`.

## 5. Quick sanity checks (before the tests)

```
FW-EDGE# show ip interface brief         ! all interfaces up/up, addresses as in docs/generated/addressing.md
FW-EDGE# show ip route                   ! connected + static routes only
SW-ACCESS# show vlan brief               ! VLANs 10 20 30 99 (+999 parked ports)
SW-ACCESS# show interfaces trunk         ! Fa0/3 trunking, native 999, allowed 10,20,30,99
PC2> ipconfig                            ! DHCP lease 10.10.30.100, gateway 10.10.30.1
```

If the interfaces are down, check the cabling and that the `WIC-1ENET` module is installed. Do not continue to the tests until `PC0 → 10.10.10.1` pings.

## 6. Run the test plan

`ciscoaudit` generates the plan from the scenarios, so it always matches the tests that the simulator runs:

```bash
PYTHONPATH=src python -m ciscoaudit validate --state hardened \
    --pt-plan docs/pt-test-plan.md --pt-results-template evidence/packet-tracer/results.csv
```

Open [pt-test-plan.md](pt-test-plan.md); for each row do what the *How to test in Packet Tracer* column says and enter the result in `evidence/packet-tracer/results.csv` (`succeeded`, `blocked`, `not-supported` or `not-run`). Some tests cannot be performed in Packet Tracer (spoofed sources, hand-crafted ACK segments); the plan marks them *simulation only*.

Take screenshots only of what you actually saw, and save them as `docs/screenshots/NN-<what-it-shows>.png`. Do not crop out error messages.

Then compare PT with the prediction:

```bash
PYTHONPATH=src python -m ciscoaudit pt-compare evidence/packet-tracer/results.csv
```

A disagreement is a finding, not a failure of the project: it means the simulator's model or the Packet Tracer behaviour differs, and `docs/limitations.md` should say which.

## 7. Export and re-audit the configurations from Packet Tracer

For each audited device (FW-EDGE, SW-ACCESS, SW-DMZ): `show running-config`, copy the text into `evidence/packet-tracer/exported/<DEVICE>.cfg`. **Before committing, replace every hash and password with a placeholder** (`render_configs.py --check` shows what a clean file looks like), then:

```bash
PYTHONPATH=src python -m ciscoaudit audit evidence/packet-tracer/exported --waivers waivers/hardened.yaml
PYTHONPATH=src python -m ciscoaudit compare configs/hardened evidence/packet-tracer/exported
```

Differences between the committed configuration and what PT kept are exactly the lines PT silently dropped or rewrote. That is real evidence about Packet Tracer support, positive or negative.

## 8. Before/after demonstration (optional, strong in an interview)

1. Build and test the **baseline**. Run the attacks (guest → servers, Internet → internal, Telnet to the router). Many succeed.
2. Run `ciscoaudit audit configs/baseline`: critical findings.
3. Reset each device (`erase startup-config`, `reload`), paste the **hardened** configurations as in step 4, and repeat the same attacks. They are blocked, and the permitted flows still work.
4. `ciscoaudit compare configs/baseline configs/hardened` lists exactly what was remediated.
