# Scenario 03 — Lateral Movement / RDP (Caldera)

## Objective

Combine host-based detection with network analysis (PCAP, firewall, Wireshark).

## Caldera Setup

| Setting | Value |
|---------|-------|
| Adversary | `T1-Windows-Lateral` |
| Agent | WKSTN-099 |
| Abilities | tshark capture → RDP port registry change |

## Expected Alerts

| Source | Identifier |
|--------|------------|
| Wazuh | 180002, 180003 |
| Firewall | RDP SYN to DC |
| File system | `capture.pcapng` in Users\Public |

## Tier 1 Tasks

- [ ] Review PCAP per `network/pcap-analysis-guide.md`
- [ ] Correlate Sysmon + registry change
- [ ] Escalate to IR (mandatory for sniffing on finance host)
- [ ] Complete `incidents/INC-2026-003-rdp-port-modification.md`
- [ ] Restore RDP port from backup

## MITRE Mapping

| Technique | Name |
|-----------|------|
| T1040 | Network Sniffing |
| T1021.001 | Remote Desktop Protocol |

## Skills Practiced

Wireshark basics, TCP/IP, IDS/firewall logs, IR escalation, AD environment awareness.