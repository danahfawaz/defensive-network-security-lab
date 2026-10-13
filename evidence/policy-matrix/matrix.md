# Reachability matrix (simulation)

> Computed offline by the policy simulator from the configuration files, then compared with the written policy in `topology/policy-intent.yaml`. These are not Packet Tracer results.

Every sender is probed against every destination for each of the services (`icmp`=icmp/echo, `ssh`=tcp/22, `telnet`=tcp/23, `http`=tcp/80, `https`=tcp/443, `rdp`=tcp/3389, `smb`=tcp/445, `dns-udp`=udp/53, `dns-tcp`=tcp/53, `syslog`=udp/514, `snmp`=udp/161). A probe counts as *permitted* if the request reaches its destination (a hole is a hole even when the reply is dropped); the policy's own flows must also work as a round trip. Unused addresses beside each server are probed too, so a rule written for a whole subnet shows up as a permit that the policy does not list.

## Summary

| | baseline | hardened |
|---|---:|---:|
| Probes | 3146 | 3146 |
| Permitted | 1667 | 307 |
| - between zones | 1447 | 87 |
| - inside one zone (switched, never filtered) | 220 | 220 |
| Blocked | 1479 | 2839 |
| **Unexpected permits** (holes) | 1360 | 0 |
| **Unexpected blocks** (broken services) | 0 | 0 |

## Baseline configuration

### Disagreements with the policy (1360)

| Kind | From | To | Service | Stopped by |
|---|---|---|---|---|
| unexpected permit | PC0 | PC2 | icmp | 101 @ FW-EDGE |
| unexpected permit | PC0 | PC2 | ssh | 101 @ FW-EDGE |
| unexpected permit | PC0 | PC2 | telnet | 101 @ FW-EDGE |
| unexpected permit | PC0 | PC2 | http | 101 @ FW-EDGE |
| unexpected permit | PC0 | PC2 | https | 101 @ FW-EDGE |
| unexpected permit | PC0 | PC2 | rdp | 101 @ FW-EDGE |
| unexpected permit | PC0 | PC2 | smb | 101 @ FW-EDGE |
| unexpected permit | PC0 | PC2 | dns-udp | 101 @ FW-EDGE |
| unexpected permit | PC0 | PC2 | dns-tcp | 101 @ FW-EDGE |
| unexpected permit | PC0 | PC2 | syslog | 101 @ FW-EDGE |
| unexpected permit | PC0 | PC2 | snmp | 101 @ FW-EDGE |
| unexpected permit | PC0 | PC3 | icmp | - |
| unexpected permit | PC0 | PC3 | ssh | - |
| unexpected permit | PC0 | PC3 | telnet | - |
| unexpected permit | PC0 | PC3 | http | - |
| unexpected permit | PC0 | PC3 | https | - |
| unexpected permit | PC0 | PC3 | rdp | - |
| unexpected permit | PC0 | PC3 | smb | - |
| unexpected permit | PC0 | PC3 | dns-udp | - |
| unexpected permit | PC0 | PC3 | dns-tcp | - |
| unexpected permit | PC0 | PC3 | syslog | - |
| unexpected permit | PC0 | PC3 | snmp | - |
| unexpected permit | PC0 | SRV-APP | ssh | - |
| unexpected permit | PC0 | SRV-APP | telnet | - |
| unexpected permit | PC0 | SRV-APP | rdp | - |
| unexpected permit | PC0 | SRV-APP | smb | - |
| unexpected permit | PC0 | SRV-APP | dns-udp | - |
| unexpected permit | PC0 | SRV-APP | dns-tcp | - |
| unexpected permit | PC0 | SRV-APP | syslog | - |
| unexpected permit | PC0 | SRV-APP | snmp | - |
| unexpected permit | PC0 | SRV-LOG | icmp | - |
| unexpected permit | PC0 | SRV-LOG | ssh | - |
| unexpected permit | PC0 | SRV-LOG | telnet | - |
| unexpected permit | PC0 | SRV-LOG | http | - |
| unexpected permit | PC0 | SRV-LOG | https | - |
| unexpected permit | PC0 | SRV-LOG | rdp | - |
| unexpected permit | PC0 | SRV-LOG | smb | - |
| unexpected permit | PC0 | SRV-LOG | dns-udp | - |
| unexpected permit | PC0 | SRV-LOG | dns-tcp | - |
| unexpected permit | PC0 | SRV-LOG | syslog | - |
| unexpected permit | PC0 | SRV-LOG | snmp | - |
| unexpected permit | PC0 | WEB-DMZ | ssh | - |
| unexpected permit | PC0 | WEB-DMZ | telnet | - |
| unexpected permit | PC0 | WEB-DMZ | rdp | - |
| unexpected permit | PC0 | WEB-DMZ | smb | - |
| unexpected permit | PC0 | WEB-DMZ | dns-udp | - |
| unexpected permit | PC0 | WEB-DMZ | dns-tcp | - |
| unexpected permit | PC0 | WEB-DMZ | syslog | - |
| unexpected permit | PC0 | WEB-DMZ | snmp | - |
| unexpected permit | PC0 | DNS-DMZ | ssh | - |
| unexpected permit | PC0 | DNS-DMZ | telnet | - |
| unexpected permit | PC0 | DNS-DMZ | http | - |
| unexpected permit | PC0 | DNS-DMZ | https | - |
| unexpected permit | PC0 | DNS-DMZ | rdp | - |
| unexpected permit | PC0 | DNS-DMZ | smb | - |
| unexpected permit | PC0 | DNS-DMZ | syslog | - |
| unexpected permit | PC0 | DNS-DMZ | snmp | - |
| unexpected permit | PC0 | PC4 | ssh | - |
| unexpected permit | PC0 | PC4 | telnet | - |
| unexpected permit | PC0 | PC4 | rdp | - |
| unexpected permit | PC0 | PC4 | smb | - |
| unexpected permit | PC0 | PC4 | dns-udp | - |
| unexpected permit | PC0 | PC4 | dns-tcp | - |
| unexpected permit | PC0 | PC4 | syslog | - |
| unexpected permit | PC0 | PC4 | snmp | - |
| unexpected permit | PC0 | PC5 | ssh | - |
| unexpected permit | PC0 | PC5 | telnet | - |
| unexpected permit | PC0 | PC5 | rdp | - |
| unexpected permit | PC0 | PC5 | smb | - |
| unexpected permit | PC0 | PC5 | dns-udp | - |
| unexpected permit | PC0 | PC5 | dns-tcp | - |
| unexpected permit | PC0 | PC5 | syslog | - |
| unexpected permit | PC0 | PC5 | snmp | - |
| unexpected permit | PC0 | WEB-EXT | ssh | - |
| unexpected permit | PC0 | WEB-EXT | telnet | - |
| unexpected permit | PC0 | WEB-EXT | rdp | - |
| unexpected permit | PC0 | WEB-EXT | smb | - |
| unexpected permit | PC0 | WEB-EXT | dns-udp | - |
| unexpected permit | PC0 | WEB-EXT | dns-tcp | - |
| unexpected permit | PC0 | WEB-EXT | syslog | - |
| unexpected permit | PC0 | WEB-EXT | snmp | - |
| unexpected permit | PC0 | FW-EDGE | icmp | - |
| unexpected permit | PC0 | FW-EDGE | ssh | - |
| unexpected permit | PC0 | FW-EDGE | telnet | - |
| unexpected permit | PC0 | FW-EDGE | http | - |
| unexpected permit | PC0 | SW-ACCESS | icmp | - |
| unexpected permit | PC0 | SW-ACCESS | ssh | - |
| unexpected permit | PC0 | SW-ACCESS | telnet | - |
| unexpected permit | PC0 | SW-DMZ | icmp | - |
| unexpected permit | PC0 | SW-DMZ | ssh | - |
| unexpected permit | PC0 | SW-DMZ | telnet | - |
| unexpected permit | PC0 | FW-EDGE-USERS | ssh | - |
| unexpected permit | PC0 | FW-EDGE-USERS | telnet | - |
| unexpected permit | PC0 | FW-EDGE-USERS | http | - |
| unexpected permit | PC0 | FW-EDGE-SERVERS | icmp | - |
| unexpected permit | PC0 | FW-EDGE-SERVERS | ssh | - |
| unexpected permit | PC0 | FW-EDGE-SERVERS | telnet | - |
| unexpected permit | PC0 | FW-EDGE-SERVERS | http | - |
| unexpected permit | PC0 | FW-EDGE-GUEST | icmp | - |
| unexpected permit | PC0 | FW-EDGE-GUEST | ssh | - |
| unexpected permit | PC0 | FW-EDGE-GUEST | telnet | - |
| unexpected permit | PC0 | FW-EDGE-GUEST | http | - |
| unexpected permit | PC0 | FW-EDGE-DMZ | icmp | - |
| unexpected permit | PC0 | FW-EDGE-DMZ | ssh | - |
| unexpected permit | PC0 | FW-EDGE-DMZ | telnet | - |
| unexpected permit | PC0 | FW-EDGE-DMZ | http | - |
| unexpected permit | PC0 | FW-EDGE-OUTSIDE | icmp | - |
| unexpected permit | PC0 | FW-EDGE-OUTSIDE | ssh | - |
| unexpected permit | PC0 | FW-EDGE-OUTSIDE | telnet | - |
| unexpected permit | PC0 | FW-EDGE-OUTSIDE | http | - |
| unexpected permit | PC0 | UNUSED-SERVERS | icmp | - |
| unexpected permit | PC0 | UNUSED-SERVERS | ssh | - |
| unexpected permit | PC0 | UNUSED-SERVERS | telnet | - |
| unexpected permit | PC0 | UNUSED-SERVERS | http | - |
| unexpected permit | PC0 | UNUSED-SERVERS | https | - |
| unexpected permit | PC0 | UNUSED-SERVERS | rdp | - |
| unexpected permit | PC0 | UNUSED-SERVERS | smb | - |
| unexpected permit | PC0 | UNUSED-SERVERS | dns-udp | - |
| unexpected permit | PC0 | UNUSED-SERVERS | dns-tcp | - |
| unexpected permit | PC0 | UNUSED-SERVERS | syslog | - |
| unexpected permit | PC0 | UNUSED-SERVERS | snmp | - |
| unexpected permit | PC0 | UNUSED-GUEST | icmp | - |
| unexpected permit | PC0 | UNUSED-GUEST | ssh | - |
| unexpected permit | PC0 | UNUSED-GUEST | telnet | - |
| unexpected permit | PC0 | UNUSED-GUEST | http | - |
| unexpected permit | PC0 | UNUSED-GUEST | https | - |
| unexpected permit | PC0 | UNUSED-GUEST | rdp | - |
| unexpected permit | PC0 | UNUSED-GUEST | smb | - |
| unexpected permit | PC0 | UNUSED-GUEST | dns-udp | - |
| unexpected permit | PC0 | UNUSED-GUEST | dns-tcp | - |
| unexpected permit | PC0 | UNUSED-GUEST | syslog | - |
| unexpected permit | PC0 | UNUSED-GUEST | snmp | - |
| unexpected permit | PC0 | UNUSED-MGMT | icmp | - |
| unexpected permit | PC0 | UNUSED-MGMT | ssh | - |
| unexpected permit | PC0 | UNUSED-MGMT | telnet | - |
| unexpected permit | PC0 | UNUSED-MGMT | http | - |
| unexpected permit | PC0 | UNUSED-MGMT | https | - |
| unexpected permit | PC0 | UNUSED-MGMT | rdp | - |
| unexpected permit | PC0 | UNUSED-MGMT | smb | - |
| unexpected permit | PC0 | UNUSED-MGMT | dns-udp | - |
| unexpected permit | PC0 | UNUSED-MGMT | dns-tcp | - |
| unexpected permit | PC0 | UNUSED-MGMT | syslog | - |
| unexpected permit | PC0 | UNUSED-MGMT | snmp | - |
| unexpected permit | PC0 | UNUSED-DMZ | icmp | - |
| unexpected permit | PC0 | UNUSED-DMZ | ssh | - |
| unexpected permit | PC0 | UNUSED-DMZ | telnet | - |
| unexpected permit | PC0 | UNUSED-DMZ | http | - |
| unexpected permit | PC0 | UNUSED-DMZ | https | - |
| unexpected permit | PC0 | UNUSED-DMZ | rdp | - |
| unexpected permit | PC0 | UNUSED-DMZ | smb | - |
| unexpected permit | PC0 | UNUSED-DMZ | dns-udp | - |
| unexpected permit | PC0 | UNUSED-DMZ | dns-tcp | - |
| unexpected permit | PC0 | UNUSED-DMZ | syslog | - |
| unexpected permit | PC0 | UNUSED-DMZ | snmp | - |
| unexpected permit | PC1 | PC2 | icmp | 101 @ FW-EDGE |
| unexpected permit | PC1 | PC2 | ssh | 101 @ FW-EDGE |
| unexpected permit | PC1 | PC2 | telnet | 101 @ FW-EDGE |
| unexpected permit | PC1 | PC2 | http | 101 @ FW-EDGE |
| unexpected permit | PC1 | PC2 | https | 101 @ FW-EDGE |
| unexpected permit | PC1 | PC2 | rdp | 101 @ FW-EDGE |
| unexpected permit | PC1 | PC2 | smb | 101 @ FW-EDGE |
| unexpected permit | PC1 | PC2 | dns-udp | 101 @ FW-EDGE |
| unexpected permit | PC1 | PC2 | dns-tcp | 101 @ FW-EDGE |
| unexpected permit | PC1 | PC2 | syslog | 101 @ FW-EDGE |
| unexpected permit | PC1 | PC2 | snmp | 101 @ FW-EDGE |
| unexpected permit | PC1 | PC3 | icmp | - |
| unexpected permit | PC1 | PC3 | ssh | - |
| unexpected permit | PC1 | PC3 | telnet | - |
| unexpected permit | PC1 | PC3 | http | - |
| unexpected permit | PC1 | PC3 | https | - |
| unexpected permit | PC1 | PC3 | rdp | - |
| unexpected permit | PC1 | PC3 | smb | - |
| unexpected permit | PC1 | PC3 | dns-udp | - |
| unexpected permit | PC1 | PC3 | dns-tcp | - |
| unexpected permit | PC1 | PC3 | syslog | - |
| unexpected permit | PC1 | PC3 | snmp | - |
| unexpected permit | PC1 | SRV-APP | ssh | - |
| unexpected permit | PC1 | SRV-APP | telnet | - |
| unexpected permit | PC1 | SRV-APP | rdp | - |
| unexpected permit | PC1 | SRV-APP | smb | - |
| unexpected permit | PC1 | SRV-APP | dns-udp | - |
| unexpected permit | PC1 | SRV-APP | dns-tcp | - |
| unexpected permit | PC1 | SRV-APP | syslog | - |
| unexpected permit | PC1 | SRV-APP | snmp | - |
| unexpected permit | PC1 | SRV-LOG | icmp | - |
| unexpected permit | PC1 | SRV-LOG | ssh | - |
| unexpected permit | PC1 | SRV-LOG | telnet | - |
| unexpected permit | PC1 | SRV-LOG | http | - |
| unexpected permit | PC1 | SRV-LOG | https | - |
| unexpected permit | PC1 | SRV-LOG | rdp | - |
| unexpected permit | PC1 | SRV-LOG | smb | - |
| unexpected permit | PC1 | SRV-LOG | dns-udp | - |
| unexpected permit | PC1 | SRV-LOG | dns-tcp | - |
| unexpected permit | PC1 | SRV-LOG | syslog | - |
| unexpected permit | PC1 | SRV-LOG | snmp | - |
| unexpected permit | PC1 | WEB-DMZ | ssh | - |
| unexpected permit | PC1 | WEB-DMZ | telnet | - |
| unexpected permit | PC1 | WEB-DMZ | rdp | - |
| unexpected permit | PC1 | WEB-DMZ | smb | - |
| unexpected permit | PC1 | WEB-DMZ | dns-udp | - |
| unexpected permit | PC1 | WEB-DMZ | dns-tcp | - |
| unexpected permit | PC1 | WEB-DMZ | syslog | - |
| unexpected permit | PC1 | WEB-DMZ | snmp | - |
| unexpected permit | PC1 | DNS-DMZ | ssh | - |
| unexpected permit | PC1 | DNS-DMZ | telnet | - |
| unexpected permit | PC1 | DNS-DMZ | http | - |
| unexpected permit | PC1 | DNS-DMZ | https | - |
| unexpected permit | PC1 | DNS-DMZ | rdp | - |
| unexpected permit | PC1 | DNS-DMZ | smb | - |
| unexpected permit | PC1 | DNS-DMZ | syslog | - |
| unexpected permit | PC1 | DNS-DMZ | snmp | - |
| unexpected permit | PC1 | PC4 | ssh | - |
| unexpected permit | PC1 | PC4 | telnet | - |
| unexpected permit | PC1 | PC4 | rdp | - |
| unexpected permit | PC1 | PC4 | smb | - |
| unexpected permit | PC1 | PC4 | dns-udp | - |
| unexpected permit | PC1 | PC4 | dns-tcp | - |
| unexpected permit | PC1 | PC4 | syslog | - |
| unexpected permit | PC1 | PC4 | snmp | - |
| unexpected permit | PC1 | PC5 | ssh | - |
| unexpected permit | PC1 | PC5 | telnet | - |
| unexpected permit | PC1 | PC5 | rdp | - |
| unexpected permit | PC1 | PC5 | smb | - |
| unexpected permit | PC1 | PC5 | dns-udp | - |
| unexpected permit | PC1 | PC5 | dns-tcp | - |
| unexpected permit | PC1 | PC5 | syslog | - |
| unexpected permit | PC1 | PC5 | snmp | - |
| unexpected permit | PC1 | WEB-EXT | ssh | - |
| unexpected permit | PC1 | WEB-EXT | telnet | - |
| unexpected permit | PC1 | WEB-EXT | rdp | - |
| unexpected permit | PC1 | WEB-EXT | smb | - |
| unexpected permit | PC1 | WEB-EXT | dns-udp | - |
| unexpected permit | PC1 | WEB-EXT | dns-tcp | - |
| unexpected permit | PC1 | WEB-EXT | syslog | - |
| unexpected permit | PC1 | WEB-EXT | snmp | - |
| unexpected permit | PC1 | FW-EDGE | icmp | - |
| unexpected permit | PC1 | FW-EDGE | ssh | - |
| unexpected permit | PC1 | FW-EDGE | telnet | - |
| unexpected permit | PC1 | FW-EDGE | http | - |
| unexpected permit | PC1 | SW-ACCESS | icmp | - |
| unexpected permit | PC1 | SW-ACCESS | ssh | - |
| unexpected permit | PC1 | SW-ACCESS | telnet | - |
| unexpected permit | PC1 | SW-DMZ | icmp | - |
| unexpected permit | PC1 | SW-DMZ | ssh | - |
| unexpected permit | PC1 | SW-DMZ | telnet | - |
| unexpected permit | PC1 | FW-EDGE-USERS | ssh | - |
| unexpected permit | PC1 | FW-EDGE-USERS | telnet | - |
| unexpected permit | PC1 | FW-EDGE-USERS | http | - |
| unexpected permit | PC1 | FW-EDGE-SERVERS | icmp | - |
| unexpected permit | PC1 | FW-EDGE-SERVERS | ssh | - |
| unexpected permit | PC1 | FW-EDGE-SERVERS | telnet | - |
| unexpected permit | PC1 | FW-EDGE-SERVERS | http | - |
| unexpected permit | PC1 | FW-EDGE-GUEST | icmp | - |
| unexpected permit | PC1 | FW-EDGE-GUEST | ssh | - |
| unexpected permit | PC1 | FW-EDGE-GUEST | telnet | - |
| unexpected permit | PC1 | FW-EDGE-GUEST | http | - |
| unexpected permit | PC1 | FW-EDGE-DMZ | icmp | - |
| unexpected permit | PC1 | FW-EDGE-DMZ | ssh | - |
| unexpected permit | PC1 | FW-EDGE-DMZ | telnet | - |
| unexpected permit | PC1 | FW-EDGE-DMZ | http | - |
| unexpected permit | PC1 | FW-EDGE-OUTSIDE | icmp | - |
| unexpected permit | PC1 | FW-EDGE-OUTSIDE | ssh | - |
| unexpected permit | PC1 | FW-EDGE-OUTSIDE | telnet | - |
| unexpected permit | PC1 | FW-EDGE-OUTSIDE | http | - |
| unexpected permit | PC1 | UNUSED-SERVERS | icmp | - |
| unexpected permit | PC1 | UNUSED-SERVERS | ssh | - |
| unexpected permit | PC1 | UNUSED-SERVERS | telnet | - |
| unexpected permit | PC1 | UNUSED-SERVERS | http | - |
| unexpected permit | PC1 | UNUSED-SERVERS | https | - |
| unexpected permit | PC1 | UNUSED-SERVERS | rdp | - |
| unexpected permit | PC1 | UNUSED-SERVERS | smb | - |
| unexpected permit | PC1 | UNUSED-SERVERS | dns-udp | - |
| unexpected permit | PC1 | UNUSED-SERVERS | dns-tcp | - |
| unexpected permit | PC1 | UNUSED-SERVERS | syslog | - |
| unexpected permit | PC1 | UNUSED-SERVERS | snmp | - |
| unexpected permit | PC1 | UNUSED-GUEST | icmp | - |
| unexpected permit | PC1 | UNUSED-GUEST | ssh | - |
| unexpected permit | PC1 | UNUSED-GUEST | telnet | - |
| unexpected permit | PC1 | UNUSED-GUEST | http | - |
| unexpected permit | PC1 | UNUSED-GUEST | https | - |
| unexpected permit | PC1 | UNUSED-GUEST | rdp | - |
| unexpected permit | PC1 | UNUSED-GUEST | smb | - |
| unexpected permit | PC1 | UNUSED-GUEST | dns-udp | - |
| unexpected permit | PC1 | UNUSED-GUEST | dns-tcp | - |
| unexpected permit | PC1 | UNUSED-GUEST | syslog | - |
| unexpected permit | PC1 | UNUSED-GUEST | snmp | - |
| unexpected permit | PC1 | UNUSED-MGMT | icmp | - |
| unexpected permit | PC1 | UNUSED-MGMT | ssh | - |
| unexpected permit | PC1 | UNUSED-MGMT | telnet | - |
| unexpected permit | PC1 | UNUSED-MGMT | http | - |
| unexpected permit | PC1 | UNUSED-MGMT | https | - |
| unexpected permit | PC1 | UNUSED-MGMT | rdp | - |
| unexpected permit | PC1 | UNUSED-MGMT | smb | - |
| unexpected permit | PC1 | UNUSED-MGMT | dns-udp | - |
| unexpected permit | PC1 | UNUSED-MGMT | dns-tcp | - |
| unexpected permit | PC1 | UNUSED-MGMT | syslog | - |
| unexpected permit | PC1 | UNUSED-MGMT | snmp | - |
| unexpected permit | PC1 | UNUSED-DMZ | icmp | - |
| unexpected permit | PC1 | UNUSED-DMZ | ssh | - |
| unexpected permit | PC1 | UNUSED-DMZ | telnet | - |
| unexpected permit | PC1 | UNUSED-DMZ | http | - |
| unexpected permit | PC1 | UNUSED-DMZ | https | - |
| unexpected permit | PC1 | UNUSED-DMZ | rdp | - |
| unexpected permit | PC1 | UNUSED-DMZ | smb | - |
| unexpected permit | PC1 | UNUSED-DMZ | dns-udp | - |
| unexpected permit | PC1 | UNUSED-DMZ | dns-tcp | - |
| unexpected permit | PC1 | UNUSED-DMZ | syslog | - |
| unexpected permit | PC1 | UNUSED-DMZ | snmp | - |
| unexpected permit | PC2 | PC3 | icmp | - |
| unexpected permit | PC2 | PC3 | ssh | - |
| unexpected permit | PC2 | PC3 | telnet | - |
| unexpected permit | PC2 | PC3 | http | - |
| unexpected permit | PC2 | PC3 | https | - |
| unexpected permit | PC2 | PC3 | rdp | - |
| unexpected permit | PC2 | PC3 | smb | - |
| unexpected permit | PC2 | PC3 | dns-udp | - |
| unexpected permit | PC2 | PC3 | dns-tcp | - |
| unexpected permit | PC2 | PC3 | syslog | - |
| unexpected permit | PC2 | PC3 | snmp | - |
| unexpected permit | PC2 | SRV-APP | icmp | - |
| unexpected permit | PC2 | SRV-APP | ssh | - |
| unexpected permit | PC2 | SRV-APP | telnet | - |
| unexpected permit | PC2 | SRV-APP | http | - |
| unexpected permit | PC2 | SRV-APP | https | - |
| unexpected permit | PC2 | SRV-APP | rdp | - |
| unexpected permit | PC2 | SRV-APP | smb | - |
| unexpected permit | PC2 | SRV-APP | dns-udp | - |
| unexpected permit | PC2 | SRV-APP | dns-tcp | - |
| unexpected permit | PC2 | SRV-APP | syslog | - |
| unexpected permit | PC2 | SRV-APP | snmp | - |
| unexpected permit | PC2 | SRV-LOG | icmp | - |
| unexpected permit | PC2 | SRV-LOG | ssh | - |
| unexpected permit | PC2 | SRV-LOG | telnet | - |
| unexpected permit | PC2 | SRV-LOG | http | - |
| unexpected permit | PC2 | SRV-LOG | https | - |
| unexpected permit | PC2 | SRV-LOG | rdp | - |
| unexpected permit | PC2 | SRV-LOG | smb | - |
| unexpected permit | PC2 | SRV-LOG | dns-udp | - |
| unexpected permit | PC2 | SRV-LOG | dns-tcp | - |
| unexpected permit | PC2 | SRV-LOG | syslog | - |
| unexpected permit | PC2 | SRV-LOG | snmp | - |
| unexpected permit | PC2 | WEB-DMZ | icmp | - |
| unexpected permit | PC2 | WEB-DMZ | ssh | - |
| unexpected permit | PC2 | WEB-DMZ | telnet | - |
| unexpected permit | PC2 | WEB-DMZ | http | - |
| unexpected permit | PC2 | WEB-DMZ | https | - |
| unexpected permit | PC2 | WEB-DMZ | rdp | - |
| unexpected permit | PC2 | WEB-DMZ | smb | - |
| unexpected permit | PC2 | WEB-DMZ | dns-udp | - |
| unexpected permit | PC2 | WEB-DMZ | dns-tcp | - |
| unexpected permit | PC2 | WEB-DMZ | syslog | - |
| unexpected permit | PC2 | WEB-DMZ | snmp | - |
| unexpected permit | PC2 | DNS-DMZ | icmp | - |
| unexpected permit | PC2 | DNS-DMZ | ssh | - |
| unexpected permit | PC2 | DNS-DMZ | telnet | - |
| unexpected permit | PC2 | DNS-DMZ | http | - |
| unexpected permit | PC2 | DNS-DMZ | https | - |
| unexpected permit | PC2 | DNS-DMZ | rdp | - |
| unexpected permit | PC2 | DNS-DMZ | smb | - |
| unexpected permit | PC2 | DNS-DMZ | syslog | - |
| unexpected permit | PC2 | DNS-DMZ | snmp | - |
| unexpected permit | PC2 | PC4 | ssh | - |
| unexpected permit | PC2 | PC4 | telnet | - |
| unexpected permit | PC2 | PC4 | rdp | - |
| unexpected permit | PC2 | PC4 | smb | - |
| unexpected permit | PC2 | PC4 | dns-udp | - |
| unexpected permit | PC2 | PC4 | dns-tcp | - |
| unexpected permit | PC2 | PC4 | syslog | - |
| unexpected permit | PC2 | PC4 | snmp | - |
| unexpected permit | PC2 | PC5 | ssh | - |
| unexpected permit | PC2 | PC5 | telnet | - |
| unexpected permit | PC2 | PC5 | rdp | - |
| unexpected permit | PC2 | PC5 | smb | - |
| unexpected permit | PC2 | PC5 | dns-udp | - |
| unexpected permit | PC2 | PC5 | dns-tcp | - |
| unexpected permit | PC2 | PC5 | syslog | - |
| unexpected permit | PC2 | PC5 | snmp | - |
| unexpected permit | PC2 | WEB-EXT | ssh | - |
| unexpected permit | PC2 | WEB-EXT | telnet | - |
| unexpected permit | PC2 | WEB-EXT | rdp | - |
| unexpected permit | PC2 | WEB-EXT | smb | - |
| unexpected permit | PC2 | WEB-EXT | dns-udp | - |
| unexpected permit | PC2 | WEB-EXT | dns-tcp | - |
| unexpected permit | PC2 | WEB-EXT | syslog | - |
| unexpected permit | PC2 | WEB-EXT | snmp | - |
| unexpected permit | PC2 | FW-EDGE | icmp | - |
| unexpected permit | PC2 | FW-EDGE | ssh | - |
| unexpected permit | PC2 | FW-EDGE | telnet | - |
| unexpected permit | PC2 | FW-EDGE | http | - |
| unexpected permit | PC2 | SW-ACCESS | icmp | - |
| unexpected permit | PC2 | SW-ACCESS | ssh | - |
| unexpected permit | PC2 | SW-ACCESS | telnet | - |
| unexpected permit | PC2 | SW-DMZ | icmp | - |
| unexpected permit | PC2 | SW-DMZ | ssh | - |
| unexpected permit | PC2 | SW-DMZ | telnet | - |
| unexpected permit | PC2 | FW-EDGE-SERVERS | icmp | - |
| unexpected permit | PC2 | FW-EDGE-SERVERS | ssh | - |
| unexpected permit | PC2 | FW-EDGE-SERVERS | telnet | - |
| unexpected permit | PC2 | FW-EDGE-SERVERS | http | - |
| unexpected permit | PC2 | FW-EDGE-GUEST | ssh | - |
| unexpected permit | PC2 | FW-EDGE-GUEST | telnet | - |
| unexpected permit | PC2 | FW-EDGE-GUEST | http | - |
| unexpected permit | PC2 | FW-EDGE-DMZ | icmp | - |
| unexpected permit | PC2 | FW-EDGE-DMZ | ssh | - |
| unexpected permit | PC2 | FW-EDGE-DMZ | telnet | - |
| unexpected permit | PC2 | FW-EDGE-DMZ | http | - |
| unexpected permit | PC2 | FW-EDGE-OUTSIDE | icmp | - |
| unexpected permit | PC2 | FW-EDGE-OUTSIDE | ssh | - |
| unexpected permit | PC2 | FW-EDGE-OUTSIDE | telnet | - |
| unexpected permit | PC2 | FW-EDGE-OUTSIDE | http | - |
| unexpected permit | PC2 | UNUSED-SERVERS | icmp | - |
| unexpected permit | PC2 | UNUSED-SERVERS | ssh | - |
| unexpected permit | PC2 | UNUSED-SERVERS | telnet | - |
| unexpected permit | PC2 | UNUSED-SERVERS | http | - |
| unexpected permit | PC2 | UNUSED-SERVERS | https | - |
| unexpected permit | PC2 | UNUSED-SERVERS | rdp | - |
| unexpected permit | PC2 | UNUSED-SERVERS | smb | - |
| unexpected permit | PC2 | UNUSED-SERVERS | dns-udp | - |
| unexpected permit | PC2 | UNUSED-SERVERS | dns-tcp | - |
| unexpected permit | PC2 | UNUSED-SERVERS | syslog | - |
| unexpected permit | PC2 | UNUSED-SERVERS | snmp | - |
| unexpected permit | PC2 | UNUSED-MGMT | icmp | - |
| unexpected permit | PC2 | UNUSED-MGMT | ssh | - |
| unexpected permit | PC2 | UNUSED-MGMT | telnet | - |
| unexpected permit | PC2 | UNUSED-MGMT | http | - |
| unexpected permit | PC2 | UNUSED-MGMT | https | - |
| unexpected permit | PC2 | UNUSED-MGMT | rdp | - |
| unexpected permit | PC2 | UNUSED-MGMT | smb | - |
| unexpected permit | PC2 | UNUSED-MGMT | dns-udp | - |
| unexpected permit | PC2 | UNUSED-MGMT | dns-tcp | - |
| unexpected permit | PC2 | UNUSED-MGMT | syslog | - |
| unexpected permit | PC2 | UNUSED-MGMT | snmp | - |
| unexpected permit | PC2 | UNUSED-DMZ | icmp | - |
| unexpected permit | PC2 | UNUSED-DMZ | ssh | - |
| unexpected permit | PC2 | UNUSED-DMZ | telnet | - |
| unexpected permit | PC2 | UNUSED-DMZ | http | - |
| unexpected permit | PC2 | UNUSED-DMZ | https | - |
| unexpected permit | PC2 | UNUSED-DMZ | rdp | - |
| unexpected permit | PC2 | UNUSED-DMZ | smb | - |
| unexpected permit | PC2 | UNUSED-DMZ | dns-udp | - |
| unexpected permit | PC2 | UNUSED-DMZ | dns-tcp | - |
| unexpected permit | PC2 | UNUSED-DMZ | syslog | - |
| unexpected permit | PC2 | UNUSED-DMZ | snmp | - |
| unexpected permit | PC3 | PC0 | ssh | - |
| unexpected permit | PC3 | PC0 | telnet | - |
| unexpected permit | PC3 | PC0 | http | - |
| unexpected permit | PC3 | PC0 | https | - |
| unexpected permit | PC3 | PC0 | rdp | - |
| unexpected permit | PC3 | PC0 | smb | - |
| unexpected permit | PC3 | PC0 | dns-udp | - |
| unexpected permit | PC3 | PC0 | dns-tcp | - |
| unexpected permit | PC3 | PC0 | syslog | - |
| unexpected permit | PC3 | PC0 | snmp | - |
| unexpected permit | PC3 | PC1 | ssh | - |
| unexpected permit | PC3 | PC1 | telnet | - |
| unexpected permit | PC3 | PC1 | http | - |
| unexpected permit | PC3 | PC1 | https | - |
| unexpected permit | PC3 | PC1 | rdp | - |
| unexpected permit | PC3 | PC1 | smb | - |
| unexpected permit | PC3 | PC1 | dns-udp | - |
| unexpected permit | PC3 | PC1 | dns-tcp | - |
| unexpected permit | PC3 | PC1 | syslog | - |
| unexpected permit | PC3 | PC1 | snmp | - |
| unexpected permit | PC3 | PC2 | icmp | - |
| unexpected permit | PC3 | PC2 | ssh | - |
| unexpected permit | PC3 | PC2 | telnet | - |
| unexpected permit | PC3 | PC2 | http | - |
| unexpected permit | PC3 | PC2 | https | - |
| unexpected permit | PC3 | PC2 | rdp | - |
| unexpected permit | PC3 | PC2 | smb | - |
| unexpected permit | PC3 | PC2 | dns-udp | - |
| unexpected permit | PC3 | PC2 | dns-tcp | - |
| unexpected permit | PC3 | PC2 | syslog | - |
| unexpected permit | PC3 | PC2 | snmp | - |
| unexpected permit | PC3 | SRV-APP | ssh | - |
| unexpected permit | PC3 | SRV-APP | telnet | - |
| unexpected permit | PC3 | SRV-APP | rdp | - |
| unexpected permit | PC3 | SRV-APP | smb | - |
| unexpected permit | PC3 | SRV-APP | dns-udp | - |
| unexpected permit | PC3 | SRV-APP | dns-tcp | - |
| unexpected permit | PC3 | SRV-APP | syslog | - |
| unexpected permit | PC3 | SRV-APP | snmp | - |
| unexpected permit | PC3 | WEB-DMZ | ssh | - |
| unexpected permit | PC3 | WEB-DMZ | telnet | - |
| unexpected permit | PC3 | WEB-DMZ | rdp | - |
| unexpected permit | PC3 | WEB-DMZ | smb | - |
| unexpected permit | PC3 | WEB-DMZ | dns-udp | - |
| unexpected permit | PC3 | WEB-DMZ | dns-tcp | - |
| unexpected permit | PC3 | WEB-DMZ | syslog | - |
| unexpected permit | PC3 | WEB-DMZ | snmp | - |
| unexpected permit | PC3 | DNS-DMZ | ssh | - |
| unexpected permit | PC3 | DNS-DMZ | telnet | - |
| unexpected permit | PC3 | DNS-DMZ | http | - |
| unexpected permit | PC3 | DNS-DMZ | https | - |
| unexpected permit | PC3 | DNS-DMZ | rdp | - |
| unexpected permit | PC3 | DNS-DMZ | smb | - |
| unexpected permit | PC3 | DNS-DMZ | dns-udp | - |
| unexpected permit | PC3 | DNS-DMZ | dns-tcp | - |
| unexpected permit | PC3 | DNS-DMZ | syslog | - |
| unexpected permit | PC3 | DNS-DMZ | snmp | - |
| unexpected permit | PC3 | PC4 | icmp | - |
| unexpected permit | PC3 | PC4 | ssh | - |
| unexpected permit | PC3 | PC4 | telnet | - |
| unexpected permit | PC3 | PC4 | http | - |
| unexpected permit | PC3 | PC4 | https | - |
| unexpected permit | PC3 | PC4 | rdp | - |
| unexpected permit | PC3 | PC4 | smb | - |
| unexpected permit | PC3 | PC4 | dns-udp | - |
| unexpected permit | PC3 | PC4 | dns-tcp | - |
| unexpected permit | PC3 | PC4 | syslog | - |
| unexpected permit | PC3 | PC4 | snmp | - |
| unexpected permit | PC3 | PC5 | icmp | - |
| unexpected permit | PC3 | PC5 | ssh | - |
| unexpected permit | PC3 | PC5 | telnet | - |
| unexpected permit | PC3 | PC5 | http | - |
| unexpected permit | PC3 | PC5 | https | - |
| unexpected permit | PC3 | PC5 | rdp | - |
| unexpected permit | PC3 | PC5 | smb | - |
| unexpected permit | PC3 | PC5 | dns-udp | - |
| unexpected permit | PC3 | PC5 | dns-tcp | - |
| unexpected permit | PC3 | PC5 | syslog | - |
| unexpected permit | PC3 | PC5 | snmp | - |
| unexpected permit | PC3 | WEB-EXT | icmp | - |
| unexpected permit | PC3 | WEB-EXT | ssh | - |
| unexpected permit | PC3 | WEB-EXT | telnet | - |
| unexpected permit | PC3 | WEB-EXT | http | - |
| unexpected permit | PC3 | WEB-EXT | https | - |
| unexpected permit | PC3 | WEB-EXT | rdp | - |
| unexpected permit | PC3 | WEB-EXT | smb | - |
| unexpected permit | PC3 | WEB-EXT | dns-udp | - |
| unexpected permit | PC3 | WEB-EXT | dns-tcp | - |
| unexpected permit | PC3 | WEB-EXT | syslog | - |
| unexpected permit | PC3 | WEB-EXT | snmp | - |
| unexpected permit | PC3 | FW-EDGE | telnet | - |
| unexpected permit | PC3 | FW-EDGE | http | - |
| unexpected permit | PC3 | SW-ACCESS | telnet | - |
| unexpected permit | PC3 | SW-DMZ | telnet | - |
| unexpected permit | PC3 | FW-EDGE-USERS | ssh | - |
| unexpected permit | PC3 | FW-EDGE-USERS | telnet | - |
| unexpected permit | PC3 | FW-EDGE-USERS | http | - |
| unexpected permit | PC3 | FW-EDGE-SERVERS | icmp | - |
| unexpected permit | PC3 | FW-EDGE-SERVERS | ssh | - |
| unexpected permit | PC3 | FW-EDGE-SERVERS | telnet | - |
| unexpected permit | PC3 | FW-EDGE-SERVERS | http | - |
| unexpected permit | PC3 | FW-EDGE-GUEST | icmp | - |
| unexpected permit | PC3 | FW-EDGE-GUEST | ssh | - |
| unexpected permit | PC3 | FW-EDGE-GUEST | telnet | - |
| unexpected permit | PC3 | FW-EDGE-GUEST | http | - |
| unexpected permit | PC3 | FW-EDGE-DMZ | icmp | - |
| unexpected permit | PC3 | FW-EDGE-DMZ | ssh | - |
| unexpected permit | PC3 | FW-EDGE-DMZ | telnet | - |
| unexpected permit | PC3 | FW-EDGE-DMZ | http | - |
| unexpected permit | PC3 | FW-EDGE-OUTSIDE | icmp | - |
| unexpected permit | PC3 | FW-EDGE-OUTSIDE | ssh | - |
| unexpected permit | PC3 | FW-EDGE-OUTSIDE | telnet | - |
| unexpected permit | PC3 | FW-EDGE-OUTSIDE | http | - |
| unexpected permit | PC3 | UNUSED-USERS | ssh | - |
| unexpected permit | PC3 | UNUSED-USERS | telnet | - |
| unexpected permit | PC3 | UNUSED-USERS | http | - |
| unexpected permit | PC3 | UNUSED-USERS | https | - |
| unexpected permit | PC3 | UNUSED-USERS | rdp | - |
| unexpected permit | PC3 | UNUSED-USERS | smb | - |
| unexpected permit | PC3 | UNUSED-USERS | dns-udp | - |
| unexpected permit | PC3 | UNUSED-USERS | dns-tcp | - |
| unexpected permit | PC3 | UNUSED-USERS | syslog | - |
| unexpected permit | PC3 | UNUSED-USERS | snmp | - |
| unexpected permit | PC3 | UNUSED-SERVERS | icmp | - |
| unexpected permit | PC3 | UNUSED-SERVERS | ssh | - |
| unexpected permit | PC3 | UNUSED-SERVERS | telnet | - |
| unexpected permit | PC3 | UNUSED-SERVERS | http | - |
| unexpected permit | PC3 | UNUSED-SERVERS | https | - |
| unexpected permit | PC3 | UNUSED-SERVERS | rdp | - |
| unexpected permit | PC3 | UNUSED-SERVERS | smb | - |
| unexpected permit | PC3 | UNUSED-SERVERS | dns-udp | - |
| unexpected permit | PC3 | UNUSED-SERVERS | dns-tcp | - |
| unexpected permit | PC3 | UNUSED-SERVERS | syslog | - |
| unexpected permit | PC3 | UNUSED-SERVERS | snmp | - |
| unexpected permit | PC3 | UNUSED-GUEST | icmp | - |
| unexpected permit | PC3 | UNUSED-GUEST | ssh | - |
| unexpected permit | PC3 | UNUSED-GUEST | telnet | - |
| unexpected permit | PC3 | UNUSED-GUEST | http | - |
| unexpected permit | PC3 | UNUSED-GUEST | https | - |
| unexpected permit | PC3 | UNUSED-GUEST | rdp | - |
| unexpected permit | PC3 | UNUSED-GUEST | smb | - |
| unexpected permit | PC3 | UNUSED-GUEST | dns-udp | - |
| unexpected permit | PC3 | UNUSED-GUEST | dns-tcp | - |
| unexpected permit | PC3 | UNUSED-GUEST | syslog | - |
| unexpected permit | PC3 | UNUSED-GUEST | snmp | - |
| unexpected permit | PC3 | UNUSED-DMZ | icmp | - |
| unexpected permit | PC3 | UNUSED-DMZ | ssh | - |
| unexpected permit | PC3 | UNUSED-DMZ | telnet | - |
| unexpected permit | PC3 | UNUSED-DMZ | http | - |
| unexpected permit | PC3 | UNUSED-DMZ | https | - |
| unexpected permit | PC3 | UNUSED-DMZ | rdp | - |
| unexpected permit | PC3 | UNUSED-DMZ | smb | - |
| unexpected permit | PC3 | UNUSED-DMZ | dns-udp | - |
| unexpected permit | PC3 | UNUSED-DMZ | dns-tcp | - |
| unexpected permit | PC3 | UNUSED-DMZ | syslog | - |
| unexpected permit | PC3 | UNUSED-DMZ | snmp | - |
| unexpected permit | SRV-APP | PC0 | icmp | - |
| unexpected permit | SRV-APP | PC0 | ssh | - |
| unexpected permit | SRV-APP | PC0 | telnet | - |
| unexpected permit | SRV-APP | PC0 | http | - |
| unexpected permit | SRV-APP | PC0 | https | - |
| unexpected permit | SRV-APP | PC0 | rdp | - |
| unexpected permit | SRV-APP | PC0 | smb | - |
| unexpected permit | SRV-APP | PC0 | dns-udp | - |
| unexpected permit | SRV-APP | PC0 | dns-tcp | - |
| unexpected permit | SRV-APP | PC0 | syslog | - |
| unexpected permit | SRV-APP | PC0 | snmp | - |
| unexpected permit | SRV-APP | PC1 | icmp | - |
| unexpected permit | SRV-APP | PC1 | ssh | - |
| unexpected permit | SRV-APP | PC1 | telnet | - |
| unexpected permit | SRV-APP | PC1 | http | - |
| unexpected permit | SRV-APP | PC1 | https | - |
| unexpected permit | SRV-APP | PC1 | rdp | - |
| unexpected permit | SRV-APP | PC1 | smb | - |
| unexpected permit | SRV-APP | PC1 | dns-udp | - |
| unexpected permit | SRV-APP | PC1 | dns-tcp | - |
| unexpected permit | SRV-APP | PC1 | syslog | - |
| unexpected permit | SRV-APP | PC1 | snmp | - |
| unexpected permit | SRV-APP | PC2 | icmp | - |
| unexpected permit | SRV-APP | PC2 | ssh | - |
| unexpected permit | SRV-APP | PC2 | telnet | - |
| unexpected permit | SRV-APP | PC2 | http | - |
| unexpected permit | SRV-APP | PC2 | https | - |
| unexpected permit | SRV-APP | PC2 | rdp | - |
| unexpected permit | SRV-APP | PC2 | smb | - |
| unexpected permit | SRV-APP | PC2 | dns-udp | - |
| unexpected permit | SRV-APP | PC2 | dns-tcp | - |
| unexpected permit | SRV-APP | PC2 | syslog | - |
| unexpected permit | SRV-APP | PC2 | snmp | - |
| unexpected permit | SRV-APP | PC3 | icmp | - |
| unexpected permit | SRV-APP | PC3 | ssh | - |
| unexpected permit | SRV-APP | PC3 | telnet | - |
| unexpected permit | SRV-APP | PC3 | http | - |
| unexpected permit | SRV-APP | PC3 | https | - |
| unexpected permit | SRV-APP | PC3 | rdp | - |
| unexpected permit | SRV-APP | PC3 | smb | - |
| unexpected permit | SRV-APP | PC3 | dns-udp | - |
| unexpected permit | SRV-APP | PC3 | dns-tcp | - |
| unexpected permit | SRV-APP | PC3 | syslog | - |
| unexpected permit | SRV-APP | PC3 | snmp | - |
| unexpected permit | SRV-APP | SRV-LOG | icmp | - |
| unexpected permit | SRV-APP | SRV-LOG | ssh | - |
| unexpected permit | SRV-APP | SRV-LOG | telnet | - |
| unexpected permit | SRV-APP | SRV-LOG | http | - |
| unexpected permit | SRV-APP | SRV-LOG | https | - |
| unexpected permit | SRV-APP | SRV-LOG | rdp | - |
| unexpected permit | SRV-APP | SRV-LOG | smb | - |
| unexpected permit | SRV-APP | SRV-LOG | dns-udp | - |
| unexpected permit | SRV-APP | SRV-LOG | dns-tcp | - |
| unexpected permit | SRV-APP | SRV-LOG | syslog | - |
| unexpected permit | SRV-APP | SRV-LOG | snmp | - |
| unexpected permit | SRV-APP | WEB-DMZ | icmp | - |
| unexpected permit | SRV-APP | WEB-DMZ | ssh | - |
| unexpected permit | SRV-APP | WEB-DMZ | telnet | - |
| unexpected permit | SRV-APP | WEB-DMZ | http | - |
| unexpected permit | SRV-APP | WEB-DMZ | https | - |
| unexpected permit | SRV-APP | WEB-DMZ | rdp | - |
| unexpected permit | SRV-APP | WEB-DMZ | smb | - |
| unexpected permit | SRV-APP | WEB-DMZ | dns-udp | - |
| unexpected permit | SRV-APP | WEB-DMZ | dns-tcp | - |
| unexpected permit | SRV-APP | WEB-DMZ | syslog | - |
| unexpected permit | SRV-APP | WEB-DMZ | snmp | - |
| unexpected permit | SRV-APP | DNS-DMZ | icmp | - |
| unexpected permit | SRV-APP | DNS-DMZ | ssh | - |
| unexpected permit | SRV-APP | DNS-DMZ | telnet | - |
| unexpected permit | SRV-APP | DNS-DMZ | http | - |
| unexpected permit | SRV-APP | DNS-DMZ | https | - |
| unexpected permit | SRV-APP | DNS-DMZ | rdp | - |
| unexpected permit | SRV-APP | DNS-DMZ | smb | - |
| unexpected permit | SRV-APP | DNS-DMZ | syslog | - |
| unexpected permit | SRV-APP | DNS-DMZ | snmp | - |
| unexpected permit | SRV-APP | PC4 | icmp | - |
| unexpected permit | SRV-APP | PC4 | ssh | - |
| unexpected permit | SRV-APP | PC4 | telnet | - |
| unexpected permit | SRV-APP | PC4 | http | - |
| unexpected permit | SRV-APP | PC4 | https | - |
| unexpected permit | SRV-APP | PC4 | rdp | - |
| unexpected permit | SRV-APP | PC4 | smb | - |
| unexpected permit | SRV-APP | PC4 | dns-udp | - |
| unexpected permit | SRV-APP | PC4 | dns-tcp | - |
| unexpected permit | SRV-APP | PC4 | syslog | - |
| unexpected permit | SRV-APP | PC4 | snmp | - |
| unexpected permit | SRV-APP | PC5 | icmp | - |
| unexpected permit | SRV-APP | PC5 | ssh | - |
| unexpected permit | SRV-APP | PC5 | telnet | - |
| unexpected permit | SRV-APP | PC5 | http | - |
| unexpected permit | SRV-APP | PC5 | https | - |
| unexpected permit | SRV-APP | PC5 | rdp | - |
| unexpected permit | SRV-APP | PC5 | smb | - |
| unexpected permit | SRV-APP | PC5 | dns-udp | - |
| unexpected permit | SRV-APP | PC5 | dns-tcp | - |
| unexpected permit | SRV-APP | PC5 | syslog | - |
| unexpected permit | SRV-APP | PC5 | snmp | - |
| unexpected permit | SRV-APP | WEB-EXT | icmp | - |
| unexpected permit | SRV-APP | WEB-EXT | ssh | - |
| unexpected permit | SRV-APP | WEB-EXT | telnet | - |
| unexpected permit | SRV-APP | WEB-EXT | http | - |
| unexpected permit | SRV-APP | WEB-EXT | https | - |
| unexpected permit | SRV-APP | WEB-EXT | rdp | - |
| unexpected permit | SRV-APP | WEB-EXT | smb | - |
| unexpected permit | SRV-APP | WEB-EXT | dns-udp | - |
| unexpected permit | SRV-APP | WEB-EXT | dns-tcp | - |
| unexpected permit | SRV-APP | WEB-EXT | syslog | - |
| unexpected permit | SRV-APP | WEB-EXT | snmp | - |
| unexpected permit | SRV-APP | FW-EDGE | icmp | - |
| unexpected permit | SRV-APP | FW-EDGE | ssh | - |
| unexpected permit | SRV-APP | FW-EDGE | telnet | - |
| unexpected permit | SRV-APP | FW-EDGE | http | - |
| unexpected permit | SRV-APP | SW-ACCESS | icmp | - |
| unexpected permit | SRV-APP | SW-ACCESS | ssh | - |
| unexpected permit | SRV-APP | SW-ACCESS | telnet | - |
| unexpected permit | SRV-APP | SW-DMZ | icmp | - |
| unexpected permit | SRV-APP | SW-DMZ | ssh | - |
| unexpected permit | SRV-APP | SW-DMZ | telnet | - |
| unexpected permit | SRV-APP | FW-EDGE-USERS | icmp | - |
| unexpected permit | SRV-APP | FW-EDGE-USERS | ssh | - |
| unexpected permit | SRV-APP | FW-EDGE-USERS | telnet | - |
| unexpected permit | SRV-APP | FW-EDGE-USERS | http | - |
| unexpected permit | SRV-APP | FW-EDGE-SERVERS | ssh | - |
| unexpected permit | SRV-APP | FW-EDGE-SERVERS | telnet | - |
| unexpected permit | SRV-APP | FW-EDGE-SERVERS | http | - |
| unexpected permit | SRV-APP | FW-EDGE-GUEST | icmp | - |
| unexpected permit | SRV-APP | FW-EDGE-GUEST | ssh | - |
| unexpected permit | SRV-APP | FW-EDGE-GUEST | telnet | - |
| unexpected permit | SRV-APP | FW-EDGE-GUEST | http | - |
| unexpected permit | SRV-APP | FW-EDGE-DMZ | icmp | - |
| unexpected permit | SRV-APP | FW-EDGE-DMZ | ssh | - |
| unexpected permit | SRV-APP | FW-EDGE-DMZ | telnet | - |
| unexpected permit | SRV-APP | FW-EDGE-DMZ | http | - |
| unexpected permit | SRV-APP | FW-EDGE-OUTSIDE | icmp | - |
| unexpected permit | SRV-APP | FW-EDGE-OUTSIDE | ssh | - |
| unexpected permit | SRV-APP | FW-EDGE-OUTSIDE | telnet | - |
| unexpected permit | SRV-APP | FW-EDGE-OUTSIDE | http | - |
| unexpected permit | SRV-APP | UNUSED-USERS | icmp | - |
| unexpected permit | SRV-APP | UNUSED-USERS | ssh | - |
| unexpected permit | SRV-APP | UNUSED-USERS | telnet | - |
| unexpected permit | SRV-APP | UNUSED-USERS | http | - |
| unexpected permit | SRV-APP | UNUSED-USERS | https | - |
| unexpected permit | SRV-APP | UNUSED-USERS | rdp | - |
| unexpected permit | SRV-APP | UNUSED-USERS | smb | - |
| unexpected permit | SRV-APP | UNUSED-USERS | dns-udp | - |
| unexpected permit | SRV-APP | UNUSED-USERS | dns-tcp | - |
| unexpected permit | SRV-APP | UNUSED-USERS | syslog | - |
| unexpected permit | SRV-APP | UNUSED-USERS | snmp | - |
| unexpected permit | SRV-APP | UNUSED-GUEST | icmp | - |
| unexpected permit | SRV-APP | UNUSED-GUEST | ssh | - |
| unexpected permit | SRV-APP | UNUSED-GUEST | telnet | - |
| unexpected permit | SRV-APP | UNUSED-GUEST | http | - |
| unexpected permit | SRV-APP | UNUSED-GUEST | https | - |
| unexpected permit | SRV-APP | UNUSED-GUEST | rdp | - |
| unexpected permit | SRV-APP | UNUSED-GUEST | smb | - |
| unexpected permit | SRV-APP | UNUSED-GUEST | dns-udp | - |
| unexpected permit | SRV-APP | UNUSED-GUEST | dns-tcp | - |
| unexpected permit | SRV-APP | UNUSED-GUEST | syslog | - |
| unexpected permit | SRV-APP | UNUSED-GUEST | snmp | - |
| unexpected permit | SRV-APP | UNUSED-MGMT | icmp | - |
| unexpected permit | SRV-APP | UNUSED-MGMT | ssh | - |
| unexpected permit | SRV-APP | UNUSED-MGMT | telnet | - |
| unexpected permit | SRV-APP | UNUSED-MGMT | http | - |
| unexpected permit | SRV-APP | UNUSED-MGMT | https | - |
| unexpected permit | SRV-APP | UNUSED-MGMT | rdp | - |
| unexpected permit | SRV-APP | UNUSED-MGMT | smb | - |
| unexpected permit | SRV-APP | UNUSED-MGMT | dns-udp | - |
| unexpected permit | SRV-APP | UNUSED-MGMT | dns-tcp | - |
| unexpected permit | SRV-APP | UNUSED-MGMT | syslog | - |
| unexpected permit | SRV-APP | UNUSED-MGMT | snmp | - |
| unexpected permit | SRV-APP | UNUSED-DMZ | icmp | - |
| unexpected permit | SRV-APP | UNUSED-DMZ | ssh | - |
| unexpected permit | SRV-APP | UNUSED-DMZ | telnet | - |
| unexpected permit | SRV-APP | UNUSED-DMZ | http | - |
| unexpected permit | SRV-APP | UNUSED-DMZ | https | - |
| unexpected permit | SRV-APP | UNUSED-DMZ | rdp | - |
| unexpected permit | SRV-APP | UNUSED-DMZ | smb | - |
| unexpected permit | SRV-APP | UNUSED-DMZ | dns-udp | - |
| unexpected permit | SRV-APP | UNUSED-DMZ | dns-tcp | - |
| unexpected permit | SRV-APP | UNUSED-DMZ | syslog | - |
| unexpected permit | SRV-APP | UNUSED-DMZ | snmp | - |
| unexpected permit | SRV-LOG | PC0 | icmp | - |
| unexpected permit | SRV-LOG | PC0 | ssh | - |
| unexpected permit | SRV-LOG | PC0 | telnet | - |
| unexpected permit | SRV-LOG | PC0 | http | - |
| unexpected permit | SRV-LOG | PC0 | https | - |
| unexpected permit | SRV-LOG | PC0 | rdp | - |
| unexpected permit | SRV-LOG | PC0 | smb | - |
| unexpected permit | SRV-LOG | PC0 | dns-udp | - |
| unexpected permit | SRV-LOG | PC0 | dns-tcp | - |
| unexpected permit | SRV-LOG | PC0 | syslog | - |
| unexpected permit | SRV-LOG | PC0 | snmp | - |
| unexpected permit | SRV-LOG | PC1 | icmp | - |
| unexpected permit | SRV-LOG | PC1 | ssh | - |
| unexpected permit | SRV-LOG | PC1 | telnet | - |
| unexpected permit | SRV-LOG | PC1 | http | - |
| unexpected permit | SRV-LOG | PC1 | https | - |
| unexpected permit | SRV-LOG | PC1 | rdp | - |
| unexpected permit | SRV-LOG | PC1 | smb | - |
| unexpected permit | SRV-LOG | PC1 | dns-udp | - |
| unexpected permit | SRV-LOG | PC1 | dns-tcp | - |
| unexpected permit | SRV-LOG | PC1 | syslog | - |
| unexpected permit | SRV-LOG | PC1 | snmp | - |
| unexpected permit | SRV-LOG | PC2 | icmp | - |
| unexpected permit | SRV-LOG | PC2 | ssh | - |
| unexpected permit | SRV-LOG | PC2 | telnet | - |
| unexpected permit | SRV-LOG | PC2 | http | - |
| unexpected permit | SRV-LOG | PC2 | https | - |
| unexpected permit | SRV-LOG | PC2 | rdp | - |
| unexpected permit | SRV-LOG | PC2 | smb | - |
| unexpected permit | SRV-LOG | PC2 | dns-udp | - |
| unexpected permit | SRV-LOG | PC2 | dns-tcp | - |
| unexpected permit | SRV-LOG | PC2 | syslog | - |
| unexpected permit | SRV-LOG | PC2 | snmp | - |
| unexpected permit | SRV-LOG | SRV-APP | icmp | - |
| unexpected permit | SRV-LOG | SRV-APP | ssh | - |
| unexpected permit | SRV-LOG | SRV-APP | telnet | - |
| unexpected permit | SRV-LOG | SRV-APP | http | - |
| unexpected permit | SRV-LOG | SRV-APP | https | - |
| unexpected permit | SRV-LOG | SRV-APP | rdp | - |
| unexpected permit | SRV-LOG | SRV-APP | smb | - |
| unexpected permit | SRV-LOG | SRV-APP | dns-udp | - |
| unexpected permit | SRV-LOG | SRV-APP | dns-tcp | - |
| unexpected permit | SRV-LOG | SRV-APP | syslog | - |
| unexpected permit | SRV-LOG | SRV-APP | snmp | - |
| unexpected permit | SRV-LOG | WEB-DMZ | icmp | - |
| unexpected permit | SRV-LOG | WEB-DMZ | ssh | - |
| unexpected permit | SRV-LOG | WEB-DMZ | telnet | - |
| unexpected permit | SRV-LOG | WEB-DMZ | http | - |
| unexpected permit | SRV-LOG | WEB-DMZ | https | - |
| unexpected permit | SRV-LOG | WEB-DMZ | rdp | - |
| unexpected permit | SRV-LOG | WEB-DMZ | smb | - |
| unexpected permit | SRV-LOG | WEB-DMZ | dns-udp | - |
| unexpected permit | SRV-LOG | WEB-DMZ | dns-tcp | - |
| unexpected permit | SRV-LOG | WEB-DMZ | syslog | - |
| unexpected permit | SRV-LOG | WEB-DMZ | snmp | - |
| unexpected permit | SRV-LOG | DNS-DMZ | icmp | - |
| unexpected permit | SRV-LOG | DNS-DMZ | ssh | - |
| unexpected permit | SRV-LOG | DNS-DMZ | telnet | - |
| unexpected permit | SRV-LOG | DNS-DMZ | http | - |
| unexpected permit | SRV-LOG | DNS-DMZ | https | - |
| unexpected permit | SRV-LOG | DNS-DMZ | rdp | - |
| unexpected permit | SRV-LOG | DNS-DMZ | smb | - |
| unexpected permit | SRV-LOG | DNS-DMZ | dns-udp | - |
| unexpected permit | SRV-LOG | DNS-DMZ | dns-tcp | - |
| unexpected permit | SRV-LOG | DNS-DMZ | syslog | - |
| unexpected permit | SRV-LOG | DNS-DMZ | snmp | - |
| unexpected permit | SRV-LOG | PC4 | icmp | - |
| unexpected permit | SRV-LOG | PC4 | ssh | - |
| unexpected permit | SRV-LOG | PC4 | telnet | - |
| unexpected permit | SRV-LOG | PC4 | http | - |
| unexpected permit | SRV-LOG | PC4 | https | - |
| unexpected permit | SRV-LOG | PC4 | rdp | - |
| unexpected permit | SRV-LOG | PC4 | smb | - |
| unexpected permit | SRV-LOG | PC4 | dns-udp | - |
| unexpected permit | SRV-LOG | PC4 | dns-tcp | - |
| unexpected permit | SRV-LOG | PC4 | syslog | - |
| unexpected permit | SRV-LOG | PC4 | snmp | - |
| unexpected permit | SRV-LOG | PC5 | icmp | - |
| unexpected permit | SRV-LOG | PC5 | ssh | - |
| unexpected permit | SRV-LOG | PC5 | telnet | - |
| unexpected permit | SRV-LOG | PC5 | http | - |
| unexpected permit | SRV-LOG | PC5 | https | - |
| unexpected permit | SRV-LOG | PC5 | rdp | - |
| unexpected permit | SRV-LOG | PC5 | smb | - |
| unexpected permit | SRV-LOG | PC5 | dns-udp | - |
| unexpected permit | SRV-LOG | PC5 | dns-tcp | - |
| unexpected permit | SRV-LOG | PC5 | syslog | - |
| unexpected permit | SRV-LOG | PC5 | snmp | - |
| unexpected permit | SRV-LOG | WEB-EXT | icmp | - |
| unexpected permit | SRV-LOG | WEB-EXT | ssh | - |
| unexpected permit | SRV-LOG | WEB-EXT | telnet | - |
| unexpected permit | SRV-LOG | WEB-EXT | http | - |
| unexpected permit | SRV-LOG | WEB-EXT | https | - |
| unexpected permit | SRV-LOG | WEB-EXT | rdp | - |
| unexpected permit | SRV-LOG | WEB-EXT | smb | - |
| unexpected permit | SRV-LOG | WEB-EXT | dns-udp | - |
| unexpected permit | SRV-LOG | WEB-EXT | dns-tcp | - |
| unexpected permit | SRV-LOG | WEB-EXT | syslog | - |
| unexpected permit | SRV-LOG | WEB-EXT | snmp | - |
| unexpected permit | SRV-LOG | FW-EDGE | ssh | - |
| unexpected permit | SRV-LOG | FW-EDGE | telnet | - |
| unexpected permit | SRV-LOG | FW-EDGE | http | - |
| unexpected permit | SRV-LOG | SW-ACCESS | ssh | - |
| unexpected permit | SRV-LOG | SW-ACCESS | telnet | - |
| unexpected permit | SRV-LOG | SW-DMZ | icmp | - |
| unexpected permit | SRV-LOG | SW-DMZ | ssh | - |
| unexpected permit | SRV-LOG | SW-DMZ | telnet | - |
| unexpected permit | SRV-LOG | FW-EDGE-USERS | icmp | - |
| unexpected permit | SRV-LOG | FW-EDGE-USERS | ssh | - |
| unexpected permit | SRV-LOG | FW-EDGE-USERS | telnet | - |
| unexpected permit | SRV-LOG | FW-EDGE-USERS | http | - |
| unexpected permit | SRV-LOG | FW-EDGE-SERVERS | icmp | - |
| unexpected permit | SRV-LOG | FW-EDGE-SERVERS | ssh | - |
| unexpected permit | SRV-LOG | FW-EDGE-SERVERS | telnet | - |
| unexpected permit | SRV-LOG | FW-EDGE-SERVERS | http | - |
| unexpected permit | SRV-LOG | FW-EDGE-GUEST | icmp | - |
| unexpected permit | SRV-LOG | FW-EDGE-GUEST | ssh | - |
| unexpected permit | SRV-LOG | FW-EDGE-GUEST | telnet | - |
| unexpected permit | SRV-LOG | FW-EDGE-GUEST | http | - |
| unexpected permit | SRV-LOG | FW-EDGE-DMZ | icmp | - |
| unexpected permit | SRV-LOG | FW-EDGE-DMZ | ssh | - |
| unexpected permit | SRV-LOG | FW-EDGE-DMZ | telnet | - |
| unexpected permit | SRV-LOG | FW-EDGE-DMZ | http | - |
| unexpected permit | SRV-LOG | FW-EDGE-OUTSIDE | icmp | - |
| unexpected permit | SRV-LOG | FW-EDGE-OUTSIDE | ssh | - |
| unexpected permit | SRV-LOG | FW-EDGE-OUTSIDE | telnet | - |
| unexpected permit | SRV-LOG | FW-EDGE-OUTSIDE | http | - |
| unexpected permit | SRV-LOG | UNUSED-USERS | icmp | - |
| unexpected permit | SRV-LOG | UNUSED-USERS | ssh | - |
| unexpected permit | SRV-LOG | UNUSED-USERS | telnet | - |
| unexpected permit | SRV-LOG | UNUSED-USERS | http | - |
| unexpected permit | SRV-LOG | UNUSED-USERS | https | - |
| unexpected permit | SRV-LOG | UNUSED-USERS | rdp | - |
| unexpected permit | SRV-LOG | UNUSED-USERS | smb | - |
| unexpected permit | SRV-LOG | UNUSED-USERS | dns-udp | - |
| unexpected permit | SRV-LOG | UNUSED-USERS | dns-tcp | - |
| unexpected permit | SRV-LOG | UNUSED-USERS | syslog | - |
| unexpected permit | SRV-LOG | UNUSED-USERS | snmp | - |
| unexpected permit | SRV-LOG | UNUSED-SERVERS | icmp | - |
| unexpected permit | SRV-LOG | UNUSED-SERVERS | ssh | - |
| unexpected permit | SRV-LOG | UNUSED-SERVERS | telnet | - |
| unexpected permit | SRV-LOG | UNUSED-SERVERS | http | - |
| unexpected permit | SRV-LOG | UNUSED-SERVERS | https | - |
| unexpected permit | SRV-LOG | UNUSED-SERVERS | rdp | - |
| unexpected permit | SRV-LOG | UNUSED-SERVERS | smb | - |
| unexpected permit | SRV-LOG | UNUSED-SERVERS | dns-udp | - |
| unexpected permit | SRV-LOG | UNUSED-SERVERS | dns-tcp | - |
| unexpected permit | SRV-LOG | UNUSED-SERVERS | syslog | - |
| unexpected permit | SRV-LOG | UNUSED-SERVERS | snmp | - |
| unexpected permit | SRV-LOG | UNUSED-GUEST | icmp | - |
| unexpected permit | SRV-LOG | UNUSED-GUEST | ssh | - |
| unexpected permit | SRV-LOG | UNUSED-GUEST | telnet | - |
| unexpected permit | SRV-LOG | UNUSED-GUEST | http | - |
| unexpected permit | SRV-LOG | UNUSED-GUEST | https | - |
| unexpected permit | SRV-LOG | UNUSED-GUEST | rdp | - |
| unexpected permit | SRV-LOG | UNUSED-GUEST | smb | - |
| unexpected permit | SRV-LOG | UNUSED-GUEST | dns-udp | - |
| unexpected permit | SRV-LOG | UNUSED-GUEST | dns-tcp | - |
| unexpected permit | SRV-LOG | UNUSED-GUEST | syslog | - |
| unexpected permit | SRV-LOG | UNUSED-GUEST | snmp | - |
| unexpected permit | SRV-LOG | UNUSED-DMZ | icmp | - |
| unexpected permit | SRV-LOG | UNUSED-DMZ | ssh | - |
| unexpected permit | SRV-LOG | UNUSED-DMZ | telnet | - |
| unexpected permit | SRV-LOG | UNUSED-DMZ | http | - |
| unexpected permit | SRV-LOG | UNUSED-DMZ | https | - |
| unexpected permit | SRV-LOG | UNUSED-DMZ | rdp | - |
| unexpected permit | SRV-LOG | UNUSED-DMZ | smb | - |
| unexpected permit | SRV-LOG | UNUSED-DMZ | dns-udp | - |
| unexpected permit | SRV-LOG | UNUSED-DMZ | dns-tcp | - |
| unexpected permit | SRV-LOG | UNUSED-DMZ | syslog | - |
| unexpected permit | SRV-LOG | UNUSED-DMZ | snmp | - |
| unexpected permit | WEB-DMZ | PC0 | icmp | - |
| unexpected permit | WEB-DMZ | PC0 | ssh | - |
| unexpected permit | WEB-DMZ | PC0 | telnet | - |
| unexpected permit | WEB-DMZ | PC0 | http | - |
| unexpected permit | WEB-DMZ | PC0 | https | - |
| unexpected permit | WEB-DMZ | PC0 | rdp | - |
| unexpected permit | WEB-DMZ | PC0 | smb | - |
| unexpected permit | WEB-DMZ | PC0 | dns-udp | - |
| unexpected permit | WEB-DMZ | PC0 | dns-tcp | - |
| unexpected permit | WEB-DMZ | PC0 | syslog | - |
| unexpected permit | WEB-DMZ | PC0 | snmp | - |
| unexpected permit | WEB-DMZ | PC1 | icmp | - |
| unexpected permit | WEB-DMZ | PC1 | ssh | - |
| unexpected permit | WEB-DMZ | PC1 | telnet | - |
| unexpected permit | WEB-DMZ | PC1 | http | - |
| unexpected permit | WEB-DMZ | PC1 | https | - |
| unexpected permit | WEB-DMZ | PC1 | rdp | - |
| unexpected permit | WEB-DMZ | PC1 | smb | - |
| unexpected permit | WEB-DMZ | PC1 | dns-udp | - |
| unexpected permit | WEB-DMZ | PC1 | dns-tcp | - |
| unexpected permit | WEB-DMZ | PC1 | syslog | - |
| unexpected permit | WEB-DMZ | PC1 | snmp | - |
| unexpected permit | WEB-DMZ | PC2 | icmp | - |
| unexpected permit | WEB-DMZ | PC2 | ssh | - |
| unexpected permit | WEB-DMZ | PC2 | telnet | - |
| unexpected permit | WEB-DMZ | PC2 | http | - |
| unexpected permit | WEB-DMZ | PC2 | https | - |
| unexpected permit | WEB-DMZ | PC2 | rdp | - |
| unexpected permit | WEB-DMZ | PC2 | smb | - |
| unexpected permit | WEB-DMZ | PC2 | dns-udp | - |
| unexpected permit | WEB-DMZ | PC2 | dns-tcp | - |
| unexpected permit | WEB-DMZ | PC2 | syslog | - |
| unexpected permit | WEB-DMZ | PC2 | snmp | - |
| unexpected permit | WEB-DMZ | PC3 | icmp | - |
| unexpected permit | WEB-DMZ | PC3 | ssh | - |
| unexpected permit | WEB-DMZ | PC3 | telnet | - |
| unexpected permit | WEB-DMZ | PC3 | http | - |
| unexpected permit | WEB-DMZ | PC3 | https | - |
| unexpected permit | WEB-DMZ | PC3 | rdp | - |
| unexpected permit | WEB-DMZ | PC3 | smb | - |
| unexpected permit | WEB-DMZ | PC3 | dns-udp | - |
| unexpected permit | WEB-DMZ | PC3 | dns-tcp | - |
| unexpected permit | WEB-DMZ | PC3 | syslog | - |
| unexpected permit | WEB-DMZ | PC3 | snmp | - |
| unexpected permit | WEB-DMZ | SRV-APP | icmp | - |
| unexpected permit | WEB-DMZ | SRV-APP | ssh | - |
| unexpected permit | WEB-DMZ | SRV-APP | telnet | - |
| unexpected permit | WEB-DMZ | SRV-APP | https | - |
| unexpected permit | WEB-DMZ | SRV-APP | rdp | - |
| unexpected permit | WEB-DMZ | SRV-APP | smb | - |
| unexpected permit | WEB-DMZ | SRV-APP | dns-udp | - |
| unexpected permit | WEB-DMZ | SRV-APP | dns-tcp | - |
| unexpected permit | WEB-DMZ | SRV-APP | syslog | - |
| unexpected permit | WEB-DMZ | SRV-APP | snmp | - |
| unexpected permit | WEB-DMZ | SRV-LOG | icmp | - |
| unexpected permit | WEB-DMZ | SRV-LOG | ssh | - |
| unexpected permit | WEB-DMZ | SRV-LOG | telnet | - |
| unexpected permit | WEB-DMZ | SRV-LOG | http | - |
| unexpected permit | WEB-DMZ | SRV-LOG | https | - |
| unexpected permit | WEB-DMZ | SRV-LOG | rdp | - |
| unexpected permit | WEB-DMZ | SRV-LOG | smb | - |
| unexpected permit | WEB-DMZ | SRV-LOG | dns-udp | - |
| unexpected permit | WEB-DMZ | SRV-LOG | dns-tcp | - |
| unexpected permit | WEB-DMZ | SRV-LOG | syslog | - |
| unexpected permit | WEB-DMZ | SRV-LOG | snmp | - |
| unexpected permit | WEB-DMZ | PC4 | icmp | - |
| unexpected permit | WEB-DMZ | PC4 | ssh | - |
| unexpected permit | WEB-DMZ | PC4 | telnet | - |
| unexpected permit | WEB-DMZ | PC4 | http | - |
| unexpected permit | WEB-DMZ | PC4 | https | - |
| unexpected permit | WEB-DMZ | PC4 | rdp | - |
| unexpected permit | WEB-DMZ | PC4 | smb | - |
| unexpected permit | WEB-DMZ | PC4 | dns-udp | - |
| unexpected permit | WEB-DMZ | PC4 | dns-tcp | - |
| unexpected permit | WEB-DMZ | PC4 | syslog | - |
| unexpected permit | WEB-DMZ | PC4 | snmp | - |
| unexpected permit | WEB-DMZ | PC5 | icmp | - |
| unexpected permit | WEB-DMZ | PC5 | ssh | - |
| unexpected permit | WEB-DMZ | PC5 | telnet | - |
| unexpected permit | WEB-DMZ | PC5 | http | - |
| unexpected permit | WEB-DMZ | PC5 | https | - |
| unexpected permit | WEB-DMZ | PC5 | rdp | - |
| unexpected permit | WEB-DMZ | PC5 | smb | - |
| unexpected permit | WEB-DMZ | PC5 | dns-udp | - |
| unexpected permit | WEB-DMZ | PC5 | dns-tcp | - |
| unexpected permit | WEB-DMZ | PC5 | syslog | - |
| unexpected permit | WEB-DMZ | PC5 | snmp | - |
| unexpected permit | WEB-DMZ | WEB-EXT | icmp | - |
| unexpected permit | WEB-DMZ | WEB-EXT | ssh | - |
| unexpected permit | WEB-DMZ | WEB-EXT | telnet | - |
| unexpected permit | WEB-DMZ | WEB-EXT | http | - |
| unexpected permit | WEB-DMZ | WEB-EXT | https | - |
| unexpected permit | WEB-DMZ | WEB-EXT | rdp | - |
| unexpected permit | WEB-DMZ | WEB-EXT | smb | - |
| unexpected permit | WEB-DMZ | WEB-EXT | dns-udp | - |
| unexpected permit | WEB-DMZ | WEB-EXT | dns-tcp | - |
| unexpected permit | WEB-DMZ | WEB-EXT | syslog | - |
| unexpected permit | WEB-DMZ | WEB-EXT | snmp | - |
| unexpected permit | WEB-DMZ | FW-EDGE | icmp | - |
| unexpected permit | WEB-DMZ | FW-EDGE | ssh | - |
| unexpected permit | WEB-DMZ | FW-EDGE | telnet | - |
| unexpected permit | WEB-DMZ | FW-EDGE | http | - |
| unexpected permit | WEB-DMZ | SW-ACCESS | icmp | - |
| unexpected permit | WEB-DMZ | SW-ACCESS | ssh | - |
| unexpected permit | WEB-DMZ | SW-ACCESS | telnet | - |
| unexpected permit | WEB-DMZ | SW-DMZ | ssh | - |
| unexpected permit | WEB-DMZ | SW-DMZ | telnet | - |
| unexpected permit | WEB-DMZ | FW-EDGE-USERS | icmp | - |
| unexpected permit | WEB-DMZ | FW-EDGE-USERS | ssh | - |
| unexpected permit | WEB-DMZ | FW-EDGE-USERS | telnet | - |
| unexpected permit | WEB-DMZ | FW-EDGE-USERS | http | - |
| unexpected permit | WEB-DMZ | FW-EDGE-SERVERS | icmp | - |
| unexpected permit | WEB-DMZ | FW-EDGE-SERVERS | ssh | - |
| unexpected permit | WEB-DMZ | FW-EDGE-SERVERS | telnet | - |
| unexpected permit | WEB-DMZ | FW-EDGE-SERVERS | http | - |
| unexpected permit | WEB-DMZ | FW-EDGE-GUEST | icmp | - |
| unexpected permit | WEB-DMZ | FW-EDGE-GUEST | ssh | - |
| unexpected permit | WEB-DMZ | FW-EDGE-GUEST | telnet | - |
| unexpected permit | WEB-DMZ | FW-EDGE-GUEST | http | - |
| unexpected permit | WEB-DMZ | FW-EDGE-DMZ | icmp | - |
| unexpected permit | WEB-DMZ | FW-EDGE-DMZ | ssh | - |
| unexpected permit | WEB-DMZ | FW-EDGE-DMZ | telnet | - |
| unexpected permit | WEB-DMZ | FW-EDGE-DMZ | http | - |
| unexpected permit | WEB-DMZ | FW-EDGE-OUTSIDE | icmp | - |
| unexpected permit | WEB-DMZ | FW-EDGE-OUTSIDE | ssh | - |
| unexpected permit | WEB-DMZ | FW-EDGE-OUTSIDE | telnet | - |
| unexpected permit | WEB-DMZ | FW-EDGE-OUTSIDE | http | - |
| unexpected permit | WEB-DMZ | UNUSED-USERS | icmp | - |
| unexpected permit | WEB-DMZ | UNUSED-USERS | ssh | - |
| unexpected permit | WEB-DMZ | UNUSED-USERS | telnet | - |
| unexpected permit | WEB-DMZ | UNUSED-USERS | http | - |
| unexpected permit | WEB-DMZ | UNUSED-USERS | https | - |
| unexpected permit | WEB-DMZ | UNUSED-USERS | rdp | - |
| unexpected permit | WEB-DMZ | UNUSED-USERS | smb | - |
| unexpected permit | WEB-DMZ | UNUSED-USERS | dns-udp | - |
| unexpected permit | WEB-DMZ | UNUSED-USERS | dns-tcp | - |
| unexpected permit | WEB-DMZ | UNUSED-USERS | syslog | - |
| unexpected permit | WEB-DMZ | UNUSED-USERS | snmp | - |
| unexpected permit | WEB-DMZ | UNUSED-SERVERS | icmp | - |
| unexpected permit | WEB-DMZ | UNUSED-SERVERS | ssh | - |
| unexpected permit | WEB-DMZ | UNUSED-SERVERS | telnet | - |
| unexpected permit | WEB-DMZ | UNUSED-SERVERS | http | - |
| unexpected permit | WEB-DMZ | UNUSED-SERVERS | https | - |
| unexpected permit | WEB-DMZ | UNUSED-SERVERS | rdp | - |
| unexpected permit | WEB-DMZ | UNUSED-SERVERS | smb | - |
| unexpected permit | WEB-DMZ | UNUSED-SERVERS | dns-udp | - |
| unexpected permit | WEB-DMZ | UNUSED-SERVERS | dns-tcp | - |
| unexpected permit | WEB-DMZ | UNUSED-SERVERS | syslog | - |
| unexpected permit | WEB-DMZ | UNUSED-SERVERS | snmp | - |
| unexpected permit | WEB-DMZ | UNUSED-GUEST | icmp | - |
| unexpected permit | WEB-DMZ | UNUSED-GUEST | ssh | - |
| unexpected permit | WEB-DMZ | UNUSED-GUEST | telnet | - |
| unexpected permit | WEB-DMZ | UNUSED-GUEST | http | - |
| unexpected permit | WEB-DMZ | UNUSED-GUEST | https | - |
| unexpected permit | WEB-DMZ | UNUSED-GUEST | rdp | - |
| unexpected permit | WEB-DMZ | UNUSED-GUEST | smb | - |
| unexpected permit | WEB-DMZ | UNUSED-GUEST | dns-udp | - |
| unexpected permit | WEB-DMZ | UNUSED-GUEST | dns-tcp | - |
| unexpected permit | WEB-DMZ | UNUSED-GUEST | syslog | - |
| unexpected permit | WEB-DMZ | UNUSED-GUEST | snmp | - |
| unexpected permit | WEB-DMZ | UNUSED-MGMT | icmp | - |
| unexpected permit | WEB-DMZ | UNUSED-MGMT | ssh | - |
| unexpected permit | WEB-DMZ | UNUSED-MGMT | telnet | - |
| unexpected permit | WEB-DMZ | UNUSED-MGMT | http | - |
| unexpected permit | WEB-DMZ | UNUSED-MGMT | https | - |
| unexpected permit | WEB-DMZ | UNUSED-MGMT | rdp | - |
| unexpected permit | WEB-DMZ | UNUSED-MGMT | smb | - |
| unexpected permit | WEB-DMZ | UNUSED-MGMT | dns-udp | - |
| unexpected permit | WEB-DMZ | UNUSED-MGMT | dns-tcp | - |
| unexpected permit | WEB-DMZ | UNUSED-MGMT | syslog | - |
| unexpected permit | WEB-DMZ | UNUSED-MGMT | snmp | - |
| unexpected permit | DNS-DMZ | PC0 | icmp | - |
| unexpected permit | DNS-DMZ | PC0 | ssh | - |
| unexpected permit | DNS-DMZ | PC0 | telnet | - |
| unexpected permit | DNS-DMZ | PC0 | http | - |
| unexpected permit | DNS-DMZ | PC0 | https | - |
| unexpected permit | DNS-DMZ | PC0 | rdp | - |
| unexpected permit | DNS-DMZ | PC0 | smb | - |
| unexpected permit | DNS-DMZ | PC0 | dns-udp | - |
| unexpected permit | DNS-DMZ | PC0 | dns-tcp | - |
| unexpected permit | DNS-DMZ | PC0 | syslog | - |
| unexpected permit | DNS-DMZ | PC0 | snmp | - |
| unexpected permit | DNS-DMZ | PC1 | icmp | - |
| unexpected permit | DNS-DMZ | PC1 | ssh | - |
| unexpected permit | DNS-DMZ | PC1 | telnet | - |
| unexpected permit | DNS-DMZ | PC1 | http | - |
| unexpected permit | DNS-DMZ | PC1 | https | - |
| unexpected permit | DNS-DMZ | PC1 | rdp | - |
| unexpected permit | DNS-DMZ | PC1 | smb | - |
| unexpected permit | DNS-DMZ | PC1 | dns-udp | - |
| unexpected permit | DNS-DMZ | PC1 | dns-tcp | - |
| unexpected permit | DNS-DMZ | PC1 | syslog | - |
| unexpected permit | DNS-DMZ | PC1 | snmp | - |
| unexpected permit | DNS-DMZ | PC2 | icmp | - |
| unexpected permit | DNS-DMZ | PC2 | ssh | - |
| unexpected permit | DNS-DMZ | PC2 | telnet | - |
| unexpected permit | DNS-DMZ | PC2 | http | - |
| unexpected permit | DNS-DMZ | PC2 | https | - |
| unexpected permit | DNS-DMZ | PC2 | rdp | - |
| unexpected permit | DNS-DMZ | PC2 | smb | - |
| unexpected permit | DNS-DMZ | PC2 | dns-udp | - |
| unexpected permit | DNS-DMZ | PC2 | dns-tcp | - |
| unexpected permit | DNS-DMZ | PC2 | syslog | - |
| unexpected permit | DNS-DMZ | PC2 | snmp | - |
| unexpected permit | DNS-DMZ | PC3 | icmp | - |
| unexpected permit | DNS-DMZ | PC3 | ssh | - |
| unexpected permit | DNS-DMZ | PC3 | telnet | - |
| unexpected permit | DNS-DMZ | PC3 | http | - |
| unexpected permit | DNS-DMZ | PC3 | https | - |
| unexpected permit | DNS-DMZ | PC3 | rdp | - |
| unexpected permit | DNS-DMZ | PC3 | smb | - |
| unexpected permit | DNS-DMZ | PC3 | dns-udp | - |
| unexpected permit | DNS-DMZ | PC3 | dns-tcp | - |
| unexpected permit | DNS-DMZ | PC3 | syslog | - |
| unexpected permit | DNS-DMZ | PC3 | snmp | - |
| unexpected permit | DNS-DMZ | SRV-APP | icmp | - |
| unexpected permit | DNS-DMZ | SRV-APP | ssh | - |
| unexpected permit | DNS-DMZ | SRV-APP | telnet | - |
| unexpected permit | DNS-DMZ | SRV-APP | http | - |
| unexpected permit | DNS-DMZ | SRV-APP | https | - |
| unexpected permit | DNS-DMZ | SRV-APP | rdp | - |
| unexpected permit | DNS-DMZ | SRV-APP | smb | - |
| unexpected permit | DNS-DMZ | SRV-APP | dns-udp | - |
| unexpected permit | DNS-DMZ | SRV-APP | dns-tcp | - |
| unexpected permit | DNS-DMZ | SRV-APP | syslog | - |
| unexpected permit | DNS-DMZ | SRV-APP | snmp | - |
| unexpected permit | DNS-DMZ | SRV-LOG | icmp | - |
| unexpected permit | DNS-DMZ | SRV-LOG | ssh | - |
| unexpected permit | DNS-DMZ | SRV-LOG | telnet | - |
| unexpected permit | DNS-DMZ | SRV-LOG | http | - |
| unexpected permit | DNS-DMZ | SRV-LOG | https | - |
| unexpected permit | DNS-DMZ | SRV-LOG | rdp | - |
| unexpected permit | DNS-DMZ | SRV-LOG | smb | - |
| unexpected permit | DNS-DMZ | SRV-LOG | dns-udp | - |
| unexpected permit | DNS-DMZ | SRV-LOG | dns-tcp | - |
| unexpected permit | DNS-DMZ | SRV-LOG | syslog | - |
| unexpected permit | DNS-DMZ | SRV-LOG | snmp | - |
| unexpected permit | DNS-DMZ | PC4 | icmp | - |
| unexpected permit | DNS-DMZ | PC4 | ssh | - |
| unexpected permit | DNS-DMZ | PC4 | telnet | - |
| unexpected permit | DNS-DMZ | PC4 | http | - |
| unexpected permit | DNS-DMZ | PC4 | https | - |
| unexpected permit | DNS-DMZ | PC4 | rdp | - |
| unexpected permit | DNS-DMZ | PC4 | smb | - |
| unexpected permit | DNS-DMZ | PC4 | dns-udp | - |
| unexpected permit | DNS-DMZ | PC4 | dns-tcp | - |
| unexpected permit | DNS-DMZ | PC4 | syslog | - |
| unexpected permit | DNS-DMZ | PC4 | snmp | - |
| unexpected permit | DNS-DMZ | PC5 | icmp | - |
| unexpected permit | DNS-DMZ | PC5 | ssh | - |
| unexpected permit | DNS-DMZ | PC5 | telnet | - |
| unexpected permit | DNS-DMZ | PC5 | http | - |
| unexpected permit | DNS-DMZ | PC5 | https | - |
| unexpected permit | DNS-DMZ | PC5 | rdp | - |
| unexpected permit | DNS-DMZ | PC5 | smb | - |
| unexpected permit | DNS-DMZ | PC5 | dns-udp | - |
| unexpected permit | DNS-DMZ | PC5 | dns-tcp | - |
| unexpected permit | DNS-DMZ | PC5 | syslog | - |
| unexpected permit | DNS-DMZ | PC5 | snmp | - |
| unexpected permit | DNS-DMZ | WEB-EXT | icmp | - |
| unexpected permit | DNS-DMZ | WEB-EXT | ssh | - |
| unexpected permit | DNS-DMZ | WEB-EXT | telnet | - |
| unexpected permit | DNS-DMZ | WEB-EXT | http | - |
| unexpected permit | DNS-DMZ | WEB-EXT | https | - |
| unexpected permit | DNS-DMZ | WEB-EXT | rdp | - |
| unexpected permit | DNS-DMZ | WEB-EXT | smb | - |
| unexpected permit | DNS-DMZ | WEB-EXT | dns-udp | - |
| unexpected permit | DNS-DMZ | WEB-EXT | dns-tcp | - |
| unexpected permit | DNS-DMZ | WEB-EXT | syslog | - |
| unexpected permit | DNS-DMZ | WEB-EXT | snmp | - |
| unexpected permit | DNS-DMZ | FW-EDGE | icmp | - |
| unexpected permit | DNS-DMZ | FW-EDGE | ssh | - |
| unexpected permit | DNS-DMZ | FW-EDGE | telnet | - |
| unexpected permit | DNS-DMZ | FW-EDGE | http | - |
| unexpected permit | DNS-DMZ | SW-ACCESS | icmp | - |
| unexpected permit | DNS-DMZ | SW-ACCESS | ssh | - |
| unexpected permit | DNS-DMZ | SW-ACCESS | telnet | - |
| unexpected permit | DNS-DMZ | SW-DMZ | ssh | - |
| unexpected permit | DNS-DMZ | SW-DMZ | telnet | - |
| unexpected permit | DNS-DMZ | FW-EDGE-USERS | icmp | - |
| unexpected permit | DNS-DMZ | FW-EDGE-USERS | ssh | - |
| unexpected permit | DNS-DMZ | FW-EDGE-USERS | telnet | - |
| unexpected permit | DNS-DMZ | FW-EDGE-USERS | http | - |
| unexpected permit | DNS-DMZ | FW-EDGE-SERVERS | icmp | - |
| unexpected permit | DNS-DMZ | FW-EDGE-SERVERS | ssh | - |
| unexpected permit | DNS-DMZ | FW-EDGE-SERVERS | telnet | - |
| unexpected permit | DNS-DMZ | FW-EDGE-SERVERS | http | - |
| unexpected permit | DNS-DMZ | FW-EDGE-GUEST | icmp | - |
| unexpected permit | DNS-DMZ | FW-EDGE-GUEST | ssh | - |
| unexpected permit | DNS-DMZ | FW-EDGE-GUEST | telnet | - |
| unexpected permit | DNS-DMZ | FW-EDGE-GUEST | http | - |
| unexpected permit | DNS-DMZ | FW-EDGE-DMZ | icmp | - |
| unexpected permit | DNS-DMZ | FW-EDGE-DMZ | ssh | - |
| unexpected permit | DNS-DMZ | FW-EDGE-DMZ | telnet | - |
| unexpected permit | DNS-DMZ | FW-EDGE-DMZ | http | - |
| unexpected permit | DNS-DMZ | FW-EDGE-OUTSIDE | icmp | - |
| unexpected permit | DNS-DMZ | FW-EDGE-OUTSIDE | ssh | - |
| unexpected permit | DNS-DMZ | FW-EDGE-OUTSIDE | telnet | - |
| unexpected permit | DNS-DMZ | FW-EDGE-OUTSIDE | http | - |
| unexpected permit | DNS-DMZ | UNUSED-USERS | icmp | - |
| unexpected permit | DNS-DMZ | UNUSED-USERS | ssh | - |
| unexpected permit | DNS-DMZ | UNUSED-USERS | telnet | - |
| unexpected permit | DNS-DMZ | UNUSED-USERS | http | - |
| unexpected permit | DNS-DMZ | UNUSED-USERS | https | - |
| unexpected permit | DNS-DMZ | UNUSED-USERS | rdp | - |
| unexpected permit | DNS-DMZ | UNUSED-USERS | smb | - |
| unexpected permit | DNS-DMZ | UNUSED-USERS | dns-udp | - |
| unexpected permit | DNS-DMZ | UNUSED-USERS | dns-tcp | - |
| unexpected permit | DNS-DMZ | UNUSED-USERS | syslog | - |
| unexpected permit | DNS-DMZ | UNUSED-USERS | snmp | - |
| unexpected permit | DNS-DMZ | UNUSED-SERVERS | icmp | - |
| unexpected permit | DNS-DMZ | UNUSED-SERVERS | ssh | - |
| unexpected permit | DNS-DMZ | UNUSED-SERVERS | telnet | - |
| unexpected permit | DNS-DMZ | UNUSED-SERVERS | http | - |
| unexpected permit | DNS-DMZ | UNUSED-SERVERS | https | - |
| unexpected permit | DNS-DMZ | UNUSED-SERVERS | rdp | - |
| unexpected permit | DNS-DMZ | UNUSED-SERVERS | smb | - |
| unexpected permit | DNS-DMZ | UNUSED-SERVERS | dns-udp | - |
| unexpected permit | DNS-DMZ | UNUSED-SERVERS | dns-tcp | - |
| unexpected permit | DNS-DMZ | UNUSED-SERVERS | syslog | - |
| unexpected permit | DNS-DMZ | UNUSED-SERVERS | snmp | - |
| unexpected permit | DNS-DMZ | UNUSED-GUEST | icmp | - |
| unexpected permit | DNS-DMZ | UNUSED-GUEST | ssh | - |
| unexpected permit | DNS-DMZ | UNUSED-GUEST | telnet | - |
| unexpected permit | DNS-DMZ | UNUSED-GUEST | http | - |
| unexpected permit | DNS-DMZ | UNUSED-GUEST | https | - |
| unexpected permit | DNS-DMZ | UNUSED-GUEST | rdp | - |
| unexpected permit | DNS-DMZ | UNUSED-GUEST | smb | - |
| unexpected permit | DNS-DMZ | UNUSED-GUEST | dns-udp | - |
| unexpected permit | DNS-DMZ | UNUSED-GUEST | dns-tcp | - |
| unexpected permit | DNS-DMZ | UNUSED-GUEST | syslog | - |
| unexpected permit | DNS-DMZ | UNUSED-GUEST | snmp | - |
| unexpected permit | DNS-DMZ | UNUSED-MGMT | icmp | - |
| unexpected permit | DNS-DMZ | UNUSED-MGMT | ssh | - |
| unexpected permit | DNS-DMZ | UNUSED-MGMT | telnet | - |
| unexpected permit | DNS-DMZ | UNUSED-MGMT | http | - |
| unexpected permit | DNS-DMZ | UNUSED-MGMT | https | - |
| unexpected permit | DNS-DMZ | UNUSED-MGMT | rdp | - |
| unexpected permit | DNS-DMZ | UNUSED-MGMT | smb | - |
| unexpected permit | DNS-DMZ | UNUSED-MGMT | dns-udp | - |
| unexpected permit | DNS-DMZ | UNUSED-MGMT | dns-tcp | - |
| unexpected permit | DNS-DMZ | UNUSED-MGMT | syslog | - |
| unexpected permit | DNS-DMZ | UNUSED-MGMT | snmp | - |
| unexpected permit | PC4 | FW-EDGE-OUTSIDE | icmp | - |
| unexpected permit | PC4 | FW-EDGE-OUTSIDE | ssh | - |
| unexpected permit | PC4 | FW-EDGE-OUTSIDE | telnet | - |
| unexpected permit | PC4 | FW-EDGE-OUTSIDE | http | - |
| unexpected permit | PC4 | WEB-DMZ-PUBLIC | icmp | - |
| unexpected permit | PC4 | WEB-DMZ-PUBLIC | ssh | - |
| unexpected permit | PC4 | WEB-DMZ-PUBLIC | telnet | - |
| unexpected permit | PC4 | WEB-DMZ-PUBLIC | rdp | - |
| unexpected permit | PC4 | WEB-DMZ-PUBLIC | smb | - |
| unexpected permit | PC4 | WEB-DMZ-PUBLIC | dns-udp | - |
| unexpected permit | PC4 | WEB-DMZ-PUBLIC | dns-tcp | - |
| unexpected permit | PC4 | WEB-DMZ-PUBLIC | syslog | - |
| unexpected permit | PC4 | WEB-DMZ-PUBLIC | snmp | - |
| unexpected permit | PC4 | DNS-DMZ-PUBLIC | icmp | - |
| unexpected permit | PC4 | DNS-DMZ-PUBLIC | ssh | - |
| unexpected permit | PC4 | DNS-DMZ-PUBLIC | telnet | - |
| unexpected permit | PC4 | DNS-DMZ-PUBLIC | http | - |
| unexpected permit | PC4 | DNS-DMZ-PUBLIC | https | - |
| unexpected permit | PC4 | DNS-DMZ-PUBLIC | rdp | - |
| unexpected permit | PC4 | DNS-DMZ-PUBLIC | smb | - |
| unexpected permit | PC4 | DNS-DMZ-PUBLIC | syslog | - |
| unexpected permit | PC4 | DNS-DMZ-PUBLIC | snmp | - |
| unexpected permit | PC5 | FW-EDGE-OUTSIDE | icmp | - |
| unexpected permit | PC5 | FW-EDGE-OUTSIDE | ssh | - |
| unexpected permit | PC5 | FW-EDGE-OUTSIDE | telnet | - |
| unexpected permit | PC5 | FW-EDGE-OUTSIDE | http | - |
| unexpected permit | PC5 | WEB-DMZ-PUBLIC | icmp | - |
| unexpected permit | PC5 | WEB-DMZ-PUBLIC | ssh | - |
| unexpected permit | PC5 | WEB-DMZ-PUBLIC | telnet | - |
| unexpected permit | PC5 | WEB-DMZ-PUBLIC | rdp | - |
| unexpected permit | PC5 | WEB-DMZ-PUBLIC | smb | - |
| unexpected permit | PC5 | WEB-DMZ-PUBLIC | dns-udp | - |
| unexpected permit | PC5 | WEB-DMZ-PUBLIC | dns-tcp | - |
| unexpected permit | PC5 | WEB-DMZ-PUBLIC | syslog | - |
| unexpected permit | PC5 | WEB-DMZ-PUBLIC | snmp | - |
| unexpected permit | PC5 | DNS-DMZ-PUBLIC | icmp | - |
| unexpected permit | PC5 | DNS-DMZ-PUBLIC | ssh | - |
| unexpected permit | PC5 | DNS-DMZ-PUBLIC | telnet | - |
| unexpected permit | PC5 | DNS-DMZ-PUBLIC | http | - |
| unexpected permit | PC5 | DNS-DMZ-PUBLIC | https | - |
| unexpected permit | PC5 | DNS-DMZ-PUBLIC | rdp | - |
| unexpected permit | PC5 | DNS-DMZ-PUBLIC | smb | - |
| unexpected permit | PC5 | DNS-DMZ-PUBLIC | syslog | - |
| unexpected permit | PC5 | DNS-DMZ-PUBLIC | snmp | - |
| unexpected permit | WEB-EXT | FW-EDGE-OUTSIDE | icmp | - |
| unexpected permit | WEB-EXT | FW-EDGE-OUTSIDE | ssh | - |
| unexpected permit | WEB-EXT | FW-EDGE-OUTSIDE | telnet | - |
| unexpected permit | WEB-EXT | FW-EDGE-OUTSIDE | http | - |
| unexpected permit | WEB-EXT | WEB-DMZ-PUBLIC | icmp | - |
| unexpected permit | WEB-EXT | WEB-DMZ-PUBLIC | ssh | - |
| unexpected permit | WEB-EXT | WEB-DMZ-PUBLIC | telnet | - |
| unexpected permit | WEB-EXT | WEB-DMZ-PUBLIC | rdp | - |
| unexpected permit | WEB-EXT | WEB-DMZ-PUBLIC | smb | - |
| unexpected permit | WEB-EXT | WEB-DMZ-PUBLIC | dns-udp | - |
| unexpected permit | WEB-EXT | WEB-DMZ-PUBLIC | dns-tcp | - |
| unexpected permit | WEB-EXT | WEB-DMZ-PUBLIC | syslog | - |
| unexpected permit | WEB-EXT | WEB-DMZ-PUBLIC | snmp | - |
| unexpected permit | WEB-EXT | DNS-DMZ-PUBLIC | icmp | - |
| unexpected permit | WEB-EXT | DNS-DMZ-PUBLIC | ssh | - |
| unexpected permit | WEB-EXT | DNS-DMZ-PUBLIC | telnet | - |
| unexpected permit | WEB-EXT | DNS-DMZ-PUBLIC | http | - |
| unexpected permit | WEB-EXT | DNS-DMZ-PUBLIC | https | - |
| unexpected permit | WEB-EXT | DNS-DMZ-PUBLIC | rdp | - |
| unexpected permit | WEB-EXT | DNS-DMZ-PUBLIC | smb | - |
| unexpected permit | WEB-EXT | DNS-DMZ-PUBLIC | syslog | - |
| unexpected permit | WEB-EXT | DNS-DMZ-PUBLIC | snmp | - |

### Permitted flows between zones

| From | To | Services | Why |
|---|---|---|---|
| PC0 | PC2 | icmp (request only) ssh (request only) telnet (request only) http (request only) https (request only) rdp (request only) smb (request only) dns-udp (request only) dns-tcp (request only) syslog (request only) snmp (request only) | not in the policy |
| PC0 | PC3 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC0 | SRV-APP | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | Employees use the internal application |
| PC0 | SRV-LOG | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC0 | WEB-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | Employees use the company web site by its private address (there is no hairpin NAT) |
| PC0 | DNS-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | Name resolution for employees |
| PC0 | PC4 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | Employees browse the Internet (translated by PAT) |
| PC0 | PC5 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | Employees browse the Internet (translated by PAT) |
| PC0 | WEB-EXT | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | Employees browse the Internet (translated by PAT) |
| PC0 | FW-EDGE | icmp ssh telnet http | not in the policy |
| PC0 | SW-ACCESS | icmp ssh telnet | not in the policy |
| PC0 | SW-DMZ | icmp ssh telnet | not in the policy |
| PC0 | FW-EDGE-USERS | icmp ssh telnet http | Employees may ping their default gateway |
| PC0 | FW-EDGE-SERVERS | icmp ssh telnet http | not in the policy |
| PC0 | FW-EDGE-GUEST | icmp ssh telnet http | not in the policy |
| PC0 | FW-EDGE-DMZ | icmp ssh telnet http | not in the policy |
| PC0 | FW-EDGE-OUTSIDE | icmp ssh telnet http | not in the policy |
| PC0 | UNUSED-SERVERS | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC0 | UNUSED-GUEST | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC0 | UNUSED-MGMT | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC0 | UNUSED-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC1 | PC2 | icmp (request only) ssh (request only) telnet (request only) http (request only) https (request only) rdp (request only) smb (request only) dns-udp (request only) dns-tcp (request only) syslog (request only) snmp (request only) | not in the policy |
| PC1 | PC3 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC1 | SRV-APP | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | Employees use the internal application |
| PC1 | SRV-LOG | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC1 | WEB-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | Employees use the company web site by its private address (there is no hairpin NAT) |
| PC1 | DNS-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | Name resolution for employees |
| PC1 | PC4 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | Employees browse the Internet (translated by PAT) |
| PC1 | PC5 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | Employees browse the Internet (translated by PAT) |
| PC1 | WEB-EXT | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | Employees browse the Internet (translated by PAT) |
| PC1 | FW-EDGE | icmp ssh telnet http | not in the policy |
| PC1 | SW-ACCESS | icmp ssh telnet | not in the policy |
| PC1 | SW-DMZ | icmp ssh telnet | not in the policy |
| PC1 | FW-EDGE-USERS | icmp ssh telnet http | Employees may ping their default gateway |
| PC1 | FW-EDGE-SERVERS | icmp ssh telnet http | not in the policy |
| PC1 | FW-EDGE-GUEST | icmp ssh telnet http | not in the policy |
| PC1 | FW-EDGE-DMZ | icmp ssh telnet http | not in the policy |
| PC1 | FW-EDGE-OUTSIDE | icmp ssh telnet http | not in the policy |
| PC1 | UNUSED-SERVERS | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC1 | UNUSED-GUEST | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC1 | UNUSED-MGMT | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC1 | UNUSED-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC2 | PC3 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC2 | SRV-APP | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC2 | SRV-LOG | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC2 | WEB-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC2 | DNS-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | Name resolution for guests |
| PC2 | PC4 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | Guests may only use the Internet |
| PC2 | PC5 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | Guests may only use the Internet |
| PC2 | WEB-EXT | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | Guests may only use the Internet |
| PC2 | FW-EDGE | icmp ssh telnet http | not in the policy |
| PC2 | SW-ACCESS | icmp ssh telnet | not in the policy |
| PC2 | SW-DMZ | icmp ssh telnet | not in the policy |
| PC2 | FW-EDGE-SERVERS | icmp ssh telnet http | not in the policy |
| PC2 | FW-EDGE-GUEST | icmp ssh telnet http | Guests may ping their default gateway |
| PC2 | FW-EDGE-DMZ | icmp ssh telnet http | not in the policy |
| PC2 | FW-EDGE-OUTSIDE | icmp ssh telnet http | not in the policy |
| PC2 | UNUSED-SERVERS | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC2 | UNUSED-MGMT | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC2 | UNUSED-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC3 | PC0 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | The administrator diagnoses the Users subnet |
| PC3 | PC1 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | The administrator diagnoses the Users subnet |
| PC3 | PC2 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC3 | SRV-APP | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | The administrator checks the servers |
| PC3 | WEB-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | The administrator checks the servers |
| PC3 | DNS-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | The administrator checks the DNS server |
| PC3 | PC4 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC3 | PC5 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC3 | WEB-EXT | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC3 | FW-EDGE | icmp ssh telnet http | Management hosts may ping the devices in their own VLAN |
| PC3 | SW-ACCESS | icmp ssh telnet | Management hosts may ping the devices in their own VLAN |
| PC3 | SW-DMZ | icmp ssh telnet | The administrator checks that the DMZ switch is up |
| PC3 | FW-EDGE-USERS | icmp ssh telnet http | The administrator diagnoses the Users subnet |
| PC3 | FW-EDGE-SERVERS | icmp ssh telnet http | not in the policy |
| PC3 | FW-EDGE-GUEST | icmp ssh telnet http | not in the policy |
| PC3 | FW-EDGE-DMZ | icmp ssh telnet http | not in the policy |
| PC3 | FW-EDGE-OUTSIDE | icmp ssh telnet http | not in the policy |
| PC3 | UNUSED-USERS | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | The administrator diagnoses the Users subnet |
| PC3 | UNUSED-SERVERS | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC3 | UNUSED-GUEST | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC3 | UNUSED-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-APP | PC0 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-APP | PC1 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-APP | PC2 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-APP | PC3 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-APP | SRV-LOG | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-APP | WEB-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-APP | DNS-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | The application server resolves names |
| SRV-APP | PC4 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-APP | PC5 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-APP | WEB-EXT | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-APP | FW-EDGE | icmp ssh telnet http | not in the policy |
| SRV-APP | SW-ACCESS | icmp ssh telnet | not in the policy |
| SRV-APP | SW-DMZ | icmp ssh telnet | not in the policy |
| SRV-APP | FW-EDGE-USERS | icmp ssh telnet http | not in the policy |
| SRV-APP | FW-EDGE-SERVERS | icmp ssh telnet http | Servers may ping their default gateway |
| SRV-APP | FW-EDGE-GUEST | icmp ssh telnet http | not in the policy |
| SRV-APP | FW-EDGE-DMZ | icmp ssh telnet http | not in the policy |
| SRV-APP | FW-EDGE-OUTSIDE | icmp ssh telnet http | not in the policy |
| SRV-APP | UNUSED-USERS | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-APP | UNUSED-GUEST | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-APP | UNUSED-MGMT | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-APP | UNUSED-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-LOG | PC0 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-LOG | PC1 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-LOG | PC2 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-LOG | SRV-APP | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-LOG | WEB-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-LOG | DNS-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-LOG | PC4 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-LOG | PC5 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-LOG | WEB-EXT | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-LOG | FW-EDGE | icmp ssh telnet http | Management hosts may ping the devices in their own VLAN |
| SRV-LOG | SW-ACCESS | icmp ssh telnet | Management hosts may ping the devices in their own VLAN |
| SRV-LOG | SW-DMZ | icmp ssh telnet | not in the policy |
| SRV-LOG | FW-EDGE-USERS | icmp ssh telnet http | not in the policy |
| SRV-LOG | FW-EDGE-SERVERS | icmp ssh telnet http | not in the policy |
| SRV-LOG | FW-EDGE-GUEST | icmp ssh telnet http | not in the policy |
| SRV-LOG | FW-EDGE-DMZ | icmp ssh telnet http | not in the policy |
| SRV-LOG | FW-EDGE-OUTSIDE | icmp ssh telnet http | not in the policy |
| SRV-LOG | UNUSED-USERS | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-LOG | UNUSED-SERVERS | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-LOG | UNUSED-GUEST | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| SRV-LOG | UNUSED-DMZ | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| WEB-DMZ | PC0 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| WEB-DMZ | PC1 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| WEB-DMZ | PC2 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| WEB-DMZ | PC3 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| WEB-DMZ | SRV-APP | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | The web tier calls the application tier |
| WEB-DMZ | SRV-LOG | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| WEB-DMZ | PC4 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| WEB-DMZ | PC5 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| WEB-DMZ | WEB-EXT | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| WEB-DMZ | FW-EDGE | icmp ssh telnet http | not in the policy |
| WEB-DMZ | SW-ACCESS | icmp ssh telnet | not in the policy |
| WEB-DMZ | SW-DMZ | icmp ssh telnet | The DMZ switch is managed in-band on the DMZ segment |
| WEB-DMZ | FW-EDGE-USERS | icmp ssh telnet http | not in the policy |
| WEB-DMZ | FW-EDGE-SERVERS | icmp ssh telnet http | not in the policy |
| WEB-DMZ | FW-EDGE-GUEST | icmp ssh telnet http | not in the policy |
| WEB-DMZ | FW-EDGE-DMZ | icmp ssh telnet http | not in the policy |
| WEB-DMZ | FW-EDGE-OUTSIDE | icmp ssh telnet http | not in the policy |
| WEB-DMZ | UNUSED-USERS | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| WEB-DMZ | UNUSED-SERVERS | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| WEB-DMZ | UNUSED-GUEST | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| WEB-DMZ | UNUSED-MGMT | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| DNS-DMZ | PC0 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| DNS-DMZ | PC1 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| DNS-DMZ | PC2 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| DNS-DMZ | PC3 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| DNS-DMZ | SRV-APP | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| DNS-DMZ | SRV-LOG | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| DNS-DMZ | PC4 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| DNS-DMZ | PC5 | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| DNS-DMZ | WEB-EXT | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| DNS-DMZ | FW-EDGE | icmp ssh telnet http | not in the policy |
| DNS-DMZ | SW-ACCESS | icmp ssh telnet | not in the policy |
| DNS-DMZ | SW-DMZ | icmp ssh telnet | The DMZ switch is managed in-band on the DMZ segment |
| DNS-DMZ | FW-EDGE-USERS | icmp ssh telnet http | not in the policy |
| DNS-DMZ | FW-EDGE-SERVERS | icmp ssh telnet http | not in the policy |
| DNS-DMZ | FW-EDGE-GUEST | icmp ssh telnet http | not in the policy |
| DNS-DMZ | FW-EDGE-DMZ | icmp ssh telnet http | not in the policy |
| DNS-DMZ | FW-EDGE-OUTSIDE | icmp ssh telnet http | not in the policy |
| DNS-DMZ | UNUSED-USERS | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| DNS-DMZ | UNUSED-SERVERS | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| DNS-DMZ | UNUSED-GUEST | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| DNS-DMZ | UNUSED-MGMT | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | not in the policy |
| PC4 | FW-EDGE-OUTSIDE | icmp ssh telnet http | not in the policy |
| PC4 | WEB-DMZ-PUBLIC | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | The company web site is public |
| PC4 | DNS-DMZ-PUBLIC | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | The company DNS server is public |
| PC5 | FW-EDGE-OUTSIDE | icmp ssh telnet http | not in the policy |
| PC5 | WEB-DMZ-PUBLIC | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | The company web site is public |
| PC5 | DNS-DMZ-PUBLIC | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | The company DNS server is public |
| WEB-EXT | FW-EDGE-OUTSIDE | icmp ssh telnet http | not in the policy |
| WEB-EXT | WEB-DMZ-PUBLIC | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | The company web site is public |
| WEB-EXT | DNS-DMZ-PUBLIC | icmp ssh telnet http https rdp smb dns-udp dns-tcp syslog snmp | The company DNS server is public |

## Hardened configuration

**No disagreements: every permitted flow is in the written policy and every listed flow works.**

### Permitted flows between zones

| From | To | Services | Why |
|---|---|---|---|
| PC0 | SRV-APP | icmp http https | Employees use the internal application |
| PC0 | WEB-DMZ | icmp http https | Employees use the company web site by its private address (there is no hairpin NAT) |
| PC0 | DNS-DMZ | icmp dns-udp dns-tcp | Name resolution for employees |
| PC0 | PC4 | icmp http https | Employees browse the Internet (translated by PAT) |
| PC0 | PC5 | icmp http https | Employees browse the Internet (translated by PAT) |
| PC0 | WEB-EXT | icmp http https | Employees browse the Internet (translated by PAT) |
| PC0 | FW-EDGE-USERS | icmp | Employees may ping their default gateway |
| PC1 | SRV-APP | icmp http https | Employees use the internal application |
| PC1 | WEB-DMZ | icmp http https | Employees use the company web site by its private address (there is no hairpin NAT) |
| PC1 | DNS-DMZ | icmp dns-udp dns-tcp | Name resolution for employees |
| PC1 | PC4 | icmp http https | Employees browse the Internet (translated by PAT) |
| PC1 | PC5 | icmp http https | Employees browse the Internet (translated by PAT) |
| PC1 | WEB-EXT | icmp http https | Employees browse the Internet (translated by PAT) |
| PC1 | FW-EDGE-USERS | icmp | Employees may ping their default gateway |
| PC2 | DNS-DMZ | dns-udp dns-tcp | Name resolution for guests |
| PC2 | PC4 | icmp http https | Guests may only use the Internet |
| PC2 | PC5 | icmp http https | Guests may only use the Internet |
| PC2 | WEB-EXT | icmp http https | Guests may only use the Internet |
| PC2 | FW-EDGE-GUEST | icmp | Guests may ping their default gateway |
| PC3 | PC0 | icmp | The administrator diagnoses the Users subnet |
| PC3 | PC1 | icmp | The administrator diagnoses the Users subnet |
| PC3 | SRV-APP | icmp http https | The administrator checks the servers |
| PC3 | WEB-DMZ | icmp http https | The administrator checks the servers |
| PC3 | DNS-DMZ | icmp | The administrator checks the DNS server |
| PC3 | FW-EDGE | icmp ssh | Management hosts may ping the devices in their own VLAN |
| PC3 | SW-ACCESS | icmp ssh | Management hosts may ping the devices in their own VLAN |
| PC3 | SW-DMZ | icmp ssh | The administrator checks that the DMZ switch is up |
| PC3 | FW-EDGE-USERS | icmp | The administrator diagnoses the Users subnet |
| PC3 | UNUSED-USERS | icmp | The administrator diagnoses the Users subnet |
| SRV-APP | DNS-DMZ | dns-udp dns-tcp | The application server resolves names |
| SRV-APP | FW-EDGE-SERVERS | icmp | Servers may ping their default gateway |
| SRV-LOG | FW-EDGE | icmp | Management hosts may ping the devices in their own VLAN |
| SRV-LOG | SW-ACCESS | icmp | Management hosts may ping the devices in their own VLAN |
| WEB-DMZ | SRV-APP | http | The web tier calls the application tier |
| WEB-DMZ | SW-DMZ | icmp | The DMZ switch is managed in-band on the DMZ segment |
| DNS-DMZ | SW-DMZ | icmp | The DMZ switch is managed in-band on the DMZ segment |
| PC4 | WEB-DMZ-PUBLIC | http https | The company web site is public |
| PC4 | DNS-DMZ-PUBLIC | dns-udp dns-tcp | The company DNS server is public |
| PC5 | WEB-DMZ-PUBLIC | http https | The company web site is public |
| PC5 | DNS-DMZ-PUBLIC | dns-udp dns-tcp | The company DNS server is public |
| WEB-EXT | WEB-DMZ-PUBLIC | http https | The company web site is public |
| WEB-EXT | DNS-DMZ-PUBLIC | dns-udp dns-tcp | The company DNS server is public |
