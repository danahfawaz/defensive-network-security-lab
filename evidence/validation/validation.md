# Security validation (simulation)

> Flow, audit and hygiene results are computed offline from the configuration files in `configs/` and the lab design in `topology/topology.yaml`; they say what the configurations do and are **not** Packet Tracer results. The manual checks (X-nn) are the exception: their result is what was observed in Packet Tracer, read from `evidence/packet-tracer/results.csv`.

## Summary

| | Baseline | Hardened |
|---|---:|---:|
| Scenarios that passed | 95 | 115 |
| Scenarios that failed | 0 | 0 |
| Informational (no expectation asserted) | 20 | 0 |
| Manual checks observed in Packet Tracer | 0 | 9 |
| Manual checks awaiting a Packet Tracer run | 0 | 0 |
| Manual checks not applicable (Packet Tracer run on the hardened network only) | 9 | 0 |
| Design checks (config matches topology) | OK | OK |

## Business traffic that must work

| ID | Scenario | Baseline | Hardened | Why (hardened) |
|---|---|---|---|---|
| P-01 | Employee opens the internal application over HTTPS<br>`PC0 -> SRV-APP tcp/443` | delivered | delivered - PASS | delivered to SRV-APP and the reply returns |
| P-02 | Employee opens the internal application over HTTP<br>`PC1 -> SRV-APP tcp/80` | delivered | delivered - PASS | delivered to SRV-APP and the reply returns |
| P-03 | Employee pings the application server<br>`PC0 -> SRV-APP icmp/echo` | delivered | delivered - PASS | delivered to SRV-APP and the reply returns |
| P-04 | Employee opens the company web site over its private address<br>`PC0 -> WEB-DMZ tcp/443` | delivered | delivered - PASS | delivered to WEB-DMZ and the reply returns |
| P-05 | Employee resolves names through the DMZ DNS server (UDP)<br>`PC0 -> DNS-DMZ udp/53` | delivered | delivered - PASS | delivered to DNS-DMZ and the reply returns |
| P-06 | Employee resolves names through the DMZ DNS server (TCP)<br>`PC0 -> DNS-DMZ tcp/53` | delivered | delivered - PASS | delivered to DNS-DMZ and the reply returns |
| P-07 | Employee browses the Internet over HTTP (PAT)<br>`PC0 -> WEB-EXT tcp/80` | delivered | delivered - PASS | delivered to WEB-EXT and the reply returns |
| P-08 | Employee browses the Internet over HTTPS (PAT)<br>`PC1 -> WEB-EXT tcp/443` | delivered | delivered - PASS | delivered to WEB-EXT and the reply returns |
| P-09 | Employee pings an Internet host<br>`PC0 -> WEB-EXT icmp/echo` | delivered | delivered - PASS | delivered to WEB-EXT and the reply returns |
| P-10 | Employee pings the default gateway<br>`PC0 -> 10.10.10.1 icmp/echo` | delivered | delivered - PASS | delivered to FW-EDGE and the reply returns |
| P-11 | Guest browses the Internet over HTTPS<br>`PC2 -> WEB-EXT tcp/443` | delivered | delivered - PASS | delivered to WEB-EXT and the reply returns |
| P-12 | Guest resolves names through the DMZ DNS server<br>`PC2 -> DNS-DMZ udp/53` | delivered | delivered - PASS | delivered to DNS-DMZ and the reply returns |
| P-13 | Guest device asks the router for an address (DHCP DISCOVER)<br>`PC2 -> 255.255.255.255 udp/67 sport=68 spoof=0.0.0.0` | delivered | delivered - PASS | delivered to FW-EDGE |
| P-14 | Guest pings the default gateway<br>`PC2 -> 10.10.30.1 icmp/echo` | delivered | delivered - PASS | delivered to FW-EDGE and the reply returns |
| P-15 | Administrator opens an SSH session to the firewall<br>`PC3 -> FW-EDGE tcp/22` | delivered | delivered - PASS | delivered to FW-EDGE and the reply returns |
| P-16 | Administrator opens an SSH session to the access switch<br>`PC3 -> SW-ACCESS tcp/22` | delivered | delivered - PASS | delivered to SW-ACCESS and the reply returns |
| P-17 | Administrator opens an SSH session to the DMZ switch through the firewall<br>`PC3 -> SW-DMZ tcp/22` | delivered | delivered - PASS | delivered to SW-DMZ and the reply returns |
| P-18 | Administrator checks the application server<br>`PC3 -> SRV-APP tcp/443` | delivered | delivered - PASS | delivered to SRV-APP and the reply returns |
| P-19 | Administrator checks the public web server on its private address<br>`PC3 -> WEB-DMZ tcp/80` | delivered | delivered - PASS | delivered to WEB-DMZ and the reply returns |
| P-20 | Administrator pings an employee workstation<br>`PC3 -> PC0 icmp/echo` | delivered | delivered - PASS | delivered to PC0 and the reply returns |
| P-21 | Internet client reaches the public web server over HTTP<br>`PC4 -> 203.0.113.9 tcp/80` | delivered | delivered - PASS | delivered to WEB-DMZ and the reply returns |
| P-22 | Internet client reaches the public web server over HTTPS<br>`PC4 -> 203.0.113.9 tcp/443` | delivered | delivered - PASS | delivered to WEB-DMZ and the reply returns |
| P-23 | Internet client queries the public DNS server (UDP)<br>`PC4 -> 203.0.113.10 udp/53` | delivered | delivered - PASS | delivered to DNS-DMZ and the reply returns |
| P-24 | Internet client queries the public DNS server (TCP)<br>`PC4 -> 203.0.113.10 tcp/53` | delivered | delivered - PASS | delivered to DNS-DMZ and the reply returns |
| P-25 | Web server calls the application tier (the one DMZ-to-inside flow)<br>`WEB-DMZ -> SRV-APP tcp/80` | delivered | delivered - PASS | delivered to SRV-APP and the reply returns |
| P-26 | Application server resolves names through the DMZ DNS server<br>`SRV-APP -> DNS-DMZ udp/53` | delivered | delivered - PASS | delivered to DNS-DMZ and the reply returns |
| P-27 | DMZ switch sends syslog to the log server<br>`SW-DMZ -> SRV-LOG udp/514 oneway` | delivered | delivered - PASS | delivered to SRV-LOG |
| P-28 | DMZ switch synchronises time with the log server<br>`SW-DMZ -> SRV-LOG udp/123 sport=123` | delivered | delivered - PASS | delivered to SRV-LOG and the reply returns |
| P-29 | Firewall sends syslog to the log server<br>`FW-EDGE -> SRV-LOG udp/514 oneway` | delivered | delivered - PASS | delivered to SRV-LOG |
| P-30 | Firewall synchronises time with the log server<br>`FW-EDGE -> SRV-LOG udp/123 sport=123` | delivered | delivered - PASS | delivered to SRV-LOG and the reply returns |

## Traffic that must be stopped

| ID | Scenario | Baseline | Hardened | Why (hardened) |
|---|---|---|---|---|
| B-01 | Guest device reaches the application server<br>`PC2 -> SRV-APP tcp/443` | delivered | blocked (IN-GUEST @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.30 in ACL IN-GUEST: 'deny ip 10.10.30.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 117) |
| B-02 | Guest device pings an employee workstation<br>`PC2 -> PC0 icmp/echo` | blocked (101 @ FW-EDGE) | blocked (IN-GUEST @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.30 in ACL IN-GUEST: 'deny ip 10.10.30.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 117) |
| B-03 | Guest device pings the administrator workstation<br>`PC2 -> PC3 icmp/echo` | delivered | blocked (IN-GUEST @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.30 in ACL IN-GUEST: 'deny ip 10.10.30.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 117) |
| B-04 | Guest device sends traffic to the log server<br>`PC2 -> SRV-LOG udp/514` | delivered | blocked (IN-GUEST @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.30 in ACL IN-GUEST: 'deny ip 10.10.30.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 117) |
| B-05 | Guest device reaches the DMZ web server on its private address<br>`PC2 -> WEB-DMZ tcp/80` | delivered | blocked (IN-GUEST @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.30 in ACL IN-GUEST: 'deny ip 10.10.30.0 0.0.0.255 172.16.0.0 0.15.255.255 log' (line 118) |
| B-06 | Guest device uses SSH to an Internet host (only web traffic is allowed out)<br>`PC2 -> WEB-EXT tcp/22` | delivered | blocked (IN-GUEST @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.30 in ACL IN-GUEST: 'deny ip any any log' (line 126) |
| B-07 | Employee workstation pings the administrator workstation<br>`PC0 -> PC3 icmp/echo` | delivered | blocked (IN-USERS @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.10 in ACL IN-USERS: 'deny ip 10.10.10.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 79) |
| B-08 | Employee workstation sends traffic to the log server<br>`PC0 -> SRV-LOG udp/514` | delivered | blocked (IN-USERS @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.10 in ACL IN-USERS: 'deny ip 10.10.10.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 79) |
| B-09 | Employee workstation opens RDP to the application server<br>`PC0 -> SRV-APP tcp/3389` | delivered | blocked (IN-USERS @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.10 in ACL IN-USERS: 'deny ip 10.10.10.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 79) |
| B-10 | Employee workstation opens SSH to the application server<br>`PC0 -> SRV-APP tcp/22` | delivered | blocked (IN-USERS @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.10 in ACL IN-USERS: 'deny ip 10.10.10.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 79) |
| B-11 | Employee workstation opens SSH to the DMZ web server<br>`PC0 -> WEB-DMZ tcp/22` | delivered | blocked (IN-USERS @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.10 in ACL IN-USERS: 'deny ip 10.10.10.0 0.0.0.255 172.16.0.0 0.15.255.255 log' (line 80) |
| B-12 | Employee workstation uses SSH to an Internet host<br>`PC0 -> WEB-EXT tcp/22` | delivered | blocked (IN-USERS @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.10 in ACL IN-USERS: 'deny ip any any log' (line 88) |
| B-13 | Employee workstation connects to the guest network<br>`PC0 -> PC2 tcp/445` | blocked (101 @ FW-EDGE, reply) | blocked (IN-USERS @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.10 in ACL IN-USERS: 'deny ip 10.10.10.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 79) |
| B-14 | Application server connects to the Internet<br>`SRV-APP -> WEB-EXT tcp/80` | delivered | blocked (IN-SERVERS @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.20 in ACL IN-SERVERS: 'deny ip any any log' (line 105) |
| B-15 | Application server opens a connection to an employee workstation<br>`SRV-APP -> PC0 tcp/3389` | delivered | blocked (IN-SERVERS @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.20 in ACL IN-SERVERS: 'deny ip any any log' (line 105) |
| B-16 | Application server sends traffic to the log server<br>`SRV-APP -> SRV-LOG udp/514` | delivered | blocked (IN-SERVERS @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.20 in ACL IN-SERVERS: 'deny ip any any log' (line 105) |
| B-17 | Log server connects to the Internet<br>`SRV-LOG -> WEB-EXT tcp/80` | delivered | blocked (IN-MGMT @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.99 in ACL IN-MGMT: 'deny ip any any log' (line 147) |
| B-18 | Administrator workstation browses the Internet<br>`PC3 -> WEB-EXT tcp/80` | delivered | blocked (IN-MGMT @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.99 in ACL IN-MGMT: 'deny ip any any log' (line 147) |
| B-19 | Administrator workstation pings the guest network<br>`PC3 -> PC2 icmp/echo` | delivered | blocked (IN-MGMT @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.99 in ACL IN-MGMT: 'deny ip any any log' (line 147) |
| B-20 | Internet attacker tries Telnet to the firewall's public address<br>`PC5 -> 203.0.113.2 tcp/23` | delivered | blocked (IN-OUTSIDE @ FW-EDGE) - PASS | request denied at FW-EDGE: Ethernet0/1/0 in ACL IN-OUTSIDE: 'deny ip any any log' (line 204) |
| B-21 | Internet attacker tries the HTTP management page of the firewall<br>`PC5 -> 203.0.113.2 tcp/80` | delivered | blocked (IN-OUTSIDE @ FW-EDGE) - PASS | request denied at FW-EDGE: Ethernet0/1/0 in ACL IN-OUTSIDE: 'deny ip any any log' (line 204) |
| B-22 | Internet attacker tries SSH to the public web server<br>`PC5 -> 203.0.113.9 tcp/22` | delivered | blocked (IN-OUTSIDE @ FW-EDGE) - PASS | request denied at FW-EDGE: Ethernet0/1/0 in ACL IN-OUTSIDE: 'deny ip any any log' (line 204) |
| B-23 | Internet attacker tries RDP to the public web server<br>`PC5 -> 203.0.113.9 tcp/3389` | delivered | blocked (IN-OUTSIDE @ FW-EDGE) - PASS | request denied at FW-EDGE: Ethernet0/1/0 in ACL IN-OUTSIDE: 'deny ip any any log' (line 204) |
| B-24 | Internet attacker sends SNMP to the public DNS server<br>`PC5 -> 203.0.113.10 udp/161` | delivered | blocked (IN-OUTSIDE @ FW-EDGE) - PASS | request denied at FW-EDGE: Ethernet0/1/0 in ACL IN-OUTSIDE: 'deny ip any any log' (line 204) |
| B-25 | Internet attacker pings the public web server<br>`PC5 -> 203.0.113.9 icmp/echo` | delivered | blocked (IN-OUTSIDE @ FW-EDGE) - PASS | request denied at FW-EDGE: Ethernet0/1/0 in ACL IN-OUTSIDE: 'deny ip any any log' (line 204) |
| B-26 | Internet attacker probes an unused address of the public block<br>`PC5 -> 203.0.113.11 tcp/80` | blocked (route @ FW-EDGE) | blocked (IN-OUTSIDE @ FW-EDGE) - PASS | request denied at FW-EDGE: Ethernet0/1/0 in ACL IN-OUTSIDE: 'deny ip any any log' (line 204) |
| B-27 | Internet attacker targets the DMZ server's private address<br>`PC5 -> 172.16.50.10 tcp/80` | blocked (route @ ISP-R) | blocked (route @ ISP-R) - PASS | request dropped at ISP-R: no route to 172.16.50.10 |
| B-28 | Internet attacker targets an internal server's private address<br>`PC5 -> 10.10.20.10 tcp/443` | blocked (route @ ISP-R) | blocked (route @ ISP-R) - PASS | request dropped at ISP-R: no route to 10.10.20.10 |
| B-29 | Compromised web server opens RDP to an employee workstation<br>`WEB-DMZ -> PC0 tcp/3389` | delivered | blocked (IN-DMZ @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/1 in ACL IN-DMZ: 'deny ip 172.16.50.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 171) |
| B-30 | Compromised web server opens SSH to the application server<br>`WEB-DMZ -> SRV-APP tcp/22` | delivered | blocked (IN-DMZ @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/1 in ACL IN-DMZ: 'deny ip 172.16.50.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 171) |
| B-31 | Compromised web server uses HTTPS to the application server (only HTTP is allowed)<br>`WEB-DMZ -> SRV-APP tcp/443` | delivered | blocked (IN-DMZ @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/1 in ACL IN-DMZ: 'deny ip 172.16.50.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 171) |
| B-32 | Compromised web server sends traffic to the log server<br>`WEB-DMZ -> SRV-LOG udp/514` | delivered | blocked (IN-DMZ @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/1 in ACL IN-DMZ: 'deny ip 172.16.50.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 171) |
| B-33 | Compromised web server connects out to the Internet<br>`WEB-DMZ -> WEB-EXT tcp/80` | delivered | blocked (IN-DMZ @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/1 in ACL IN-DMZ: 'deny ip any any log' (line 179) |
| B-34 | Compromised DNS server reaches the application server<br>`DNS-DMZ -> SRV-APP tcp/80` | delivered | blocked (IN-DMZ @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/1 in ACL IN-DMZ: 'deny ip 172.16.50.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 171) |
| B-35 | Compromised web server opens SSH to the administrator workstation<br>`WEB-DMZ -> PC3 tcp/22` | delivered | blocked (IN-DMZ @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/1 in ACL IN-DMZ: 'deny ip 172.16.50.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 171) |
| B-36 | Compromised web server pings the guest network<br>`WEB-DMZ -> PC2 icmp/echo` | delivered | blocked (IN-DMZ @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/1 in ACL IN-DMZ: 'deny ip 172.16.50.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 171) |

## Forged source addresses

| ID | Scenario | Baseline | Hardened | Why (hardened) |
|---|---|---|---|---|
| S-01 | Internet attacker forges an internal (10.0.0.0/8) source address<br>`PC5 -> 203.0.113.9 tcp/80 spoof=10.10.10.10` | delivered | blocked (IN-OUTSIDE @ FW-EDGE) - PASS | request denied at FW-EDGE: Ethernet0/1/0 in ACL IN-OUTSIDE: 'deny ip 10.0.0.0 0.255.255.255 any log' (line 183) |
| S-02 | Internet attacker forges a 192.168.0.0/16 source address<br>`PC5 -> 203.0.113.9 tcp/80 spoof=192.168.1.5` | delivered | blocked (IN-OUTSIDE @ FW-EDGE) - PASS | request denied at FW-EDGE: Ethernet0/1/0 in ACL IN-OUTSIDE: 'deny ip 192.168.0.0 0.0.255.255 any log' (line 185) |
| S-03 | Internet attacker forges the DMZ server's private address<br>`PC5 -> 203.0.113.10 udp/53 spoof=172.16.50.20` | delivered | blocked (IN-OUTSIDE @ FW-EDGE) - PASS | request denied at FW-EDGE: Ethernet0/1/0 in ACL IN-OUTSIDE: 'deny ip 172.16.0.0 0.15.255.255 any log' (line 184) |
| S-04 | Internet attacker forges a loopback source address<br>`PC5 -> 203.0.113.9 tcp/80 spoof=127.0.0.1` | delivered | blocked (IN-OUTSIDE @ FW-EDGE) - PASS | request denied at FW-EDGE: Ethernet0/1/0 in ACL IN-OUTSIDE: 'deny ip 127.0.0.0 0.255.255.255 any log' (line 186) |
| S-05 | Internet attacker forges the firewall's own public address (reflection)<br>`PC5 -> 203.0.113.9 tcp/80 spoof=203.0.113.2` | delivered | blocked (IN-OUTSIDE @ FW-EDGE) - PASS | request denied at FW-EDGE: Ethernet0/1/0 in ACL IN-OUTSIDE: 'deny ip host 203.0.113.2 any log' (line 191) |
| S-06 | Internet attacker forges a public DMZ address of the organisation<br>`PC5 -> 203.0.113.10 udp/53 spoof=203.0.113.9` | delivered | blocked (IN-OUTSIDE @ FW-EDGE) - PASS | request denied at FW-EDGE: Ethernet0/1/0 in ACL IN-OUTSIDE: 'deny ip 203.0.113.8 0.0.0.7 any log' (line 192) |
| S-07 | Internet attacker forges a reserved (240.0.0.0/4) source address<br>`PC5 -> 203.0.113.9 tcp/80 spoof=240.0.0.1` | delivered | blocked (IN-OUTSIDE @ FW-EDGE) - PASS | request denied at FW-EDGE: Ethernet0/1/0 in ACL IN-OUTSIDE: 'deny ip 240.0.0.0 15.255.255.255 any log' (line 189) |
| S-08 | Employee workstation forges the administrator's address to reach the firewall<br>`PC0 -> FW-EDGE tcp/23 spoof=10.10.99.10` | delivered | blocked (IN-USERS @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.10 in ACL IN-USERS: 'deny ip any any log' (line 88) |
| S-09 | Guest device forges an employee address<br>`PC2 -> SRV-APP tcp/443 spoof=10.10.10.10` | delivered | blocked (IN-GUEST @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.30 in ACL IN-GUEST: 'deny ip any any log' (line 126) |
| S-10 | DMZ server forges an employee address<br>`WEB-DMZ -> SRV-APP tcp/80 spoof=10.10.10.10` | delivered | blocked (IN-DMZ @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/1 in ACL IN-DMZ: 'deny ip any any log' (line 179) |

## Access to the devices themselves

| ID | Scenario | Baseline | Hardened | Why (hardened) |
|---|---|---|---|---|
| M-01 | Non-administrator host in the Management VLAN opens SSH to the access switch<br>`SRV-LOG -> SW-ACCESS tcp/22` | delivered | blocked (vty @ SW-ACCESS) - PASS | request refused at SW-ACCESS: line vty 0 4: 'access-class VTY-ADMIN in' does not permit 10.10.99.20; line vty 5 15: 'access-class VTY-ADMIN in' does not permit 10.10.99.20 |
| M-02 | Non-administrator host in the Management VLAN opens Telnet to the access switch<br>`SRV-LOG -> SW-ACCESS tcp/23` | delivered | blocked (vty @ SW-ACCESS) - PASS | request refused at SW-ACCESS: line vty 0 4: 'transport input ssh' does not accept telnet; line vty 5 15: 'transport input ssh' does not accept telnet |
| M-03 | Administrator tries Telnet to the access switch<br>`PC3 -> SW-ACCESS tcp/23` | delivered | blocked (vty @ SW-ACCESS) - PASS | request refused at SW-ACCESS: line vty 0 4: 'transport input ssh' does not accept telnet; line vty 5 15: 'transport input ssh' does not accept telnet |
| M-04 | Administrator tries Telnet to the firewall<br>`PC3 -> FW-EDGE tcp/23` | delivered | blocked (IN-MGMT @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.99 in ACL IN-MGMT: 'deny ip any any log' (line 147) |
| M-05 | Administrator tries the HTTP management page of the firewall<br>`PC3 -> FW-EDGE tcp/80` | delivered | blocked (IN-MGMT @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.99 in ACL IN-MGMT: 'deny ip any any log' (line 147) |
| M-06 | Administrator tries Telnet to the DMZ switch<br>`PC3 -> SW-DMZ tcp/23` | delivered | blocked (IN-MGMT @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.99 in ACL IN-MGMT: 'deny ip any any log' (line 147) |
| M-07 | Non-administrator host in the Management VLAN opens SSH to the firewall<br>`SRV-LOG -> FW-EDGE tcp/22` | delivered | blocked (IN-MGMT @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.99 in ACL IN-MGMT: 'deny ip any any log' (line 147) |
| M-08 | Employee workstation opens Telnet to the firewall's gateway address<br>`PC0 -> 10.10.10.1 tcp/23` | delivered | blocked (IN-USERS @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.10 in ACL IN-USERS: 'deny ip 10.10.10.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 79) |
| M-09 | Employee workstation opens Telnet to the access switch<br>`PC0 -> SW-ACCESS tcp/23` | delivered | blocked (IN-USERS @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.10 in ACL IN-USERS: 'deny ip 10.10.10.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 79) |
| M-10 | Employee workstation opens SSH to the DMZ switch<br>`PC1 -> SW-DMZ tcp/22` | delivered | blocked (IN-USERS @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.10 in ACL IN-USERS: 'deny ip 10.10.10.0 0.0.0.255 172.16.0.0 0.15.255.255 log' (line 80) |
| M-11 | Guest device opens Telnet to the firewall's guest-side address<br>`PC2 -> 10.10.30.1 tcp/23` | delivered | blocked (IN-GUEST @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.30 in ACL IN-GUEST: 'deny ip 10.10.30.0 0.0.0.255 10.0.0.0 0.255.255.255 log' (line 117) |
| M-12 | Application server opens Telnet to the firewall<br>`SRV-APP -> 10.10.20.1 tcp/23` | delivered | blocked (IN-SERVERS @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/0.20 in ACL IN-SERVERS: 'deny ip any any log' (line 105) |
| M-13 | Compromised web server opens Telnet to the firewall's DMZ address<br>`WEB-DMZ -> 172.16.50.1 tcp/23` | delivered | blocked (IN-DMZ @ FW-EDGE) - PASS | request denied at FW-EDGE: FastEthernet0/1 in ACL IN-DMZ: 'deny ip 172.16.50.0 0.0.0.255 172.16.0.0 0.15.255.255 log' (line 172) |
| M-14 | Compromised web server opens Telnet to the DMZ switch (same VLAN, no firewall in between)<br>`WEB-DMZ -> SW-DMZ tcp/23` | delivered | blocked (vty @ SW-DMZ) - PASS | request refused at SW-DMZ: line vty 0 4: 'transport input ssh' does not accept telnet; line vty 5 15: 'transport input ssh' does not accept telnet |
| M-15 | Compromised web server opens SSH to the DMZ switch (same VLAN)<br>`WEB-DMZ -> SW-DMZ tcp/22` | delivered | blocked (vty @ SW-DMZ) - PASS | request refused at SW-DMZ: line vty 0 4: 'access-class VTY-ADMIN in' does not permit 172.16.50.10; line vty 5 15: 'access-class VTY-ADMIN in' does not permit 172.16.50.10 |
| M-16 | Defence in depth - a crafted ACK that the stateless ACL lets through is still refused by the VTY<br>`PC5 -> 203.0.113.2 tcp/22 sport=80 ack` | delivered | blocked (vty @ FW-EDGE) - PASS | request refused at FW-EDGE: line vty 0 4: 'access-class VTY-ADMIN in' does not permit 198.51.100.66 |

## Known limitations (documented, not fixed)

| ID | Scenario | Baseline | Hardened | Why (hardened) |
|---|---|---|---|---|
| K-01 | A crafted ACK from the application server reaches an employee workstation (stateless ACL)<br>`SRV-APP -> PC0 tcp/3389 sport=80 ack` | delivered | delivered - PASS | delivered to PC0 |
| K-02 | A crafted ACK from the DMZ web server reaches an employee workstation (stateless ACL)<br>`WEB-DMZ -> PC0 tcp/445 sport=80 ack` | delivered | delivered - PASS | delivered to PC0 |
| K-03 | The DMZ DNS server may send UDP from port 53 to any Internet host<br>`DNS-DMZ -> WEB-EXT udp/53 sport=53` | delivered | delivered - PASS | delivered to WEB-EXT and the reply returns |
| K-04 | Employees cannot reach the public web server through its public address (no hairpin NAT)<br>`PC0 -> 203.0.113.9 tcp/80` | blocked (route @ FW-EDGE) | blocked (route @ FW-EDGE) - PASS | request dropped at FW-EDGE: 203.0.113.9 matches 203.0.113.8/29 -> Null0 (discard route) |
| K-05 | Employee workstations can reach each other inside the Users VLAN<br>`PC0 -> PC1 tcp/445` | delivered | delivered - PASS | delivered to PC1 and the reply returns |
| K-06 | DMZ servers can reach each other inside the DMZ VLAN<br>`WEB-DMZ -> DNS-DMZ tcp/22` | delivered | delivered - PASS | delivered to DNS-DMZ and the reply returns |
| L-09 | DHCP snooping and ARP inspection are not applied to the statically addressed DMZ switch (accepted risk) | finding | finding - PASS | L2-011 on SW-DMZ: DHCP snooping is not enabled; L2-012 on SW-DMZ: Dynamic ARP Inspection is not enabled |
| H-08 | No central AAA server exists in the lab (accepted risk) | finding | finding - PASS | MGMT-009 on FW-EDGE: AAA is not enabled (local-only authentication); MGMT-009 on SW-ACCESS: AAA is not enabled (local-only authentication); MGMT-009 on SW-DMZ: AAA is not enabled (local-only authentication) |

## Switch (Layer 2) protections

| ID | Scenario | Baseline | Hardened | Why (hardened) |
|---|---|---|---|---|
| L-01 | Switch ports do not negotiate trunking (DTP) - VLAN hopping by switch spoofing | finding | clean - PASS | no findings from L2-001, L2-002 on SW-* |
| L-02 | Trunk native VLAN is not VLAN 1 and the trunk carries only needed VLANs - double tagging | finding | clean - PASS | no findings from L2-003, L2-004 on SW-* |
| L-03 | Edge ports limit the number of MAC addresses - MAC flooding and unknown devices | finding | clean - PASS | no findings from L2-005 on SW-* |
| L-04 | Edge ports use PortFast with BPDU Guard - rogue switch and STP manipulation | finding | clean - PASS | no findings from L2-006 on SW-* |
| L-05 | Unused ports are shut down and parked, nothing sits in VLAN 1 | finding | clean - PASS | no findings from L2-007, L2-008, L2-009 on SW-* |
| L-06 | VTP cannot be used to rewrite the VLAN database | finding | clean - PASS | no findings from L2-010 on SW-* |
| L-07 | DHCP snooping protects the guest VLAN against rogue DHCP servers | finding | clean - PASS | no findings from L2-011 on SW-ACCESS |
| L-08 | Dynamic ARP Inspection protects the guest VLAN against ARP spoofing | finding | clean - PASS | no findings from L2-012 on SW-ACCESS |

## Device hardening baseline

| ID | Scenario | Baseline | Hardened | Why (hardened) |
|---|---|---|---|---|
| H-01 | No default, plain-text or reversible credentials on any device | finding | clean - PASS | no findings from CRED-001, CRED-002, CRED-003, CRED-004, CRED-005 on * |
| H-02 | Remote management is SSH-only, per-user and limited to management hosts | finding | clean - PASS | no findings from AUTH-001, AUTH-002, AUTH-003, AUTH-004, MGMT-001, MGMT-002, MGMT-010 on * |
| H-03 | HTTP management, SNMP defaults and the AUX port are off | finding | clean - PASS | no findings from MGMT-005, MGMT-006, MGMT-007, MGMT-008 on * |
| H-04 | Idle sessions time out and a login banner is shown | finding | clean - PASS | no findings from MGMT-003, MGMT-004 on * |
| H-05 | Devices log to the central server with time stamps and a time source | finding | clean - PASS | no findings from LOG-001, LOG-002, LOG-003 on * |
| H-06 | Unneeded services (CDP, source routing, proxy ARP, directed broadcast) are off | finding | clean - PASS | no findings from INT-001, INT-002, SVC-001, SVC-002, SVC-003, SVC-004 on * |
| H-07 | Access lists are default-deny, logged, used and free of permit-any-any | finding | clean - PASS | no findings from ACL-001, ACL-002, ACL-003, ACL-004, ACL-005, ACL-006, ACL-007, ACL-008 on * |

## Checks only Packet Tracer can answer

| ID | Scenario | Baseline | Hardened | Why (hardened) |
|---|---|---|---|---|
| X-01 | The guest PC obtains an address, gateway and DNS server by DHCP | n/a (hardened only) | observed in Packet Tracer | PC2 received 10.10.30.100/24, gateway 10.10.30.1, DNS 172.16.50.20. |
| X-02 | SSH login to the firewall works and Telnet is refused | n/a (hardened only) | observed in Packet Tracer | SSH from PC3 to FW-EDGE succeeded; Telnet was blocked; SSH version 2 enabled. |
| X-03 | Port security shuts the port when a second device appears | n/a (hardened only) | observed in Packet Tracer | A second MAC address on SW-ACCESS Fa0/1 raised PORT_SECURITY-2-PSECURE_VIOLATION and the port entered err-disabled. |
| X-04 | NAT translations appear for browsing and for the published servers | n/a (hardened only) | observed in Packet Tracer | Internal host reached the external web server; Internet host reached the DMZ web server through static NAT; show ip nat translations listed static and dynamic entries. |
| X-05 | The outside ACL blocks the Internet attacker's attempts | n/a (hardened only) | observed in Packet Tracer | From PC5 all eight attempts were blocked: Telnet/HTTP/ICMP to 203.0.113.2; SSH/ICMP/TCP 3389 to 203.0.113.9; SNMP UDP 161 to 203.0.113.10; ICMP to 10.10.10.10. The ACL output did not display deny hit counters (the exported configuration holds no explicit deny entries; see export-comparison.md). |
| X-06 | Syslog and NTP reach the log server | n/a (hardened only) | observed in Packet Tracer | SRV-LOG received a syslog event from SW-ACCESS; FW-EDGE and SW-ACCESS: clock is synchronized, stratum 2, reference 10.10.99.20. |
| X-07 | Re-audit the configurations exported from Packet Tracer | n/a (hardened only) | observed in Packet Tracer | show running-config retrieved on FW-EDGE, SW-ACCESS and SW-DMZ; password hashes replaced by XXXX in exported/; see export-audit.md and export-comparison.md. |
| X-08 | Rogue DHCP server on the guest VLAN is ignored (DHCP snooping) | n/a (hardened only) | observed in Packet Tracer | Rogue DHCP server on VLAN 30 (Fa0/10) did not change the lease of PC2; show ip dhcp snooping: enabled on VLAN 30, Fa0/10 untrusted, Fa0/3 trusted, Fa0/4 untrusted with rate limit. |
| X-09 | Dynamic ARP Inspection is enabled on the guest VLAN | n/a (hardened only) | observed in Packet Tracer | show ip arp inspection: Dynamic ARP Inspection enabled and active on VLAN 30. No live ARP-spoofing attack was run. |

## How to read this

- **delivered**: the request reaches its destination and, for connections, the reply comes back.
- **blocked (X @ Y)**: stopped by ACL `X` (or by `route`, `vty`, `no-service`) on device `Y`; `, reply` means the request got through but the answer was stopped.
- Baseline results are asserted wherever a scenario states one; a mismatch is reported as a failure, so the 'before' column is a fact about the baseline configurations, not a claim.
