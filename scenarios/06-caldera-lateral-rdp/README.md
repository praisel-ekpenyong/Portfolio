# Scenario 06 — RDP Lateral Movement & Network Sniffing (Caldera)

**Incident Record:** [`INC-2026-006`](../../incidents/INC-2026-006-rdp-lateral-movement.md)

## Objective

Demonstrate lateral movement and network sniffing triage: RDP port modification on WKSTN-099, execution of tcpdump.exe, PCAP packet analysis via tshark, and containment workflows.

## Caldera Profile

| Setting | Value |
|---------|-------|
| Adversary | `2026-06-18-LATERAL-RDP-LAB` |
| Agent | WKSTN-099 |
| MITRE | T1021.001, T1040, T1112 |

## Lab Replay Checklist

- [ ] Identify the source host and compromised credentials (`jsmith` on `WKSTN-042`)
- [ ] Confirm RDP port modification in the registry
- [ ] Investigate execution of tcpdump.exe on WKSTN-099
- [ ] Perform tshark PCAP forensics to verify DNS volume, cleartext POSTs, and SNIs
- [ ] Apply host isolation via Wazuh firewall rules on both hosts
- [ ] Complete incident report and osTicket #48370
