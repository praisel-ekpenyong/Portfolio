# Caldera Scenario Index

**Praisel Ekpenyong** · [GitHub](https://github.com/praisel-ekpenyong) · [LinkedIn](https://www.linkedin.com/in/praiselekpenyong)

Each scenario follows: **Caldera operation → SIEM alert → Tier 1 triage → Incident record**.

| Scenario | Lab | Caldera Profile | Primary Docs |
|----------|-----|-----------------|--------------|
| [01 — Windows BITS Download](01-caldera-windows-download/README.md) | Hybrid | T1-Windows-Download-Exec | INC-2026-001 |
| [02 — Entra Password Spray](02-entra-password-spray/README.md) | Lab 2 | Lab spray script | INC-2026-002 |
| [03 — Lateral / RDP](03-caldera-lateral-rdp/README.md) | Hybrid | T1-Windows-Lateral | INC-2026-003 |
| [04 — Phish to Host](04-caldera-phishing-chain/README.md) | Lab 2 | T1-Phish-to-Host | INC-2026-005 |

## Lab Assignment

| Lab | Environment | Triage consoles |
|-----|-------------|-----------------|
| **Lab 1** | `corp.lab.local` on-prem | Wazuh manager, Splunk, pfSense, Wireshark |
| **Lab 2** | `pe-soc-lab` Azure tenant | Sentinel incident queue, Defender portal, Entra sign-in logs |

## Execution Order

1. Confirm both labs are up (`docs/lab-architecture.md`)
2. Deploy agents (`docs/caldera-setup.md`)
3. Import Wazuh rules (`detections/wazuh/local_rules.xml`)
4. Run operation (`caldera/operations-runbook.md`)
5. Triage using playbook (`docs/soc-playbooks.md`)
6. Complete incident report (`templates/incident-report.md`)
7. File osTicket record (`tickets/sample-tickets.md` as reference)

## Non-Caldera Scenarios

| Incident | Lab | Trigger | Tier 1 focus |
|----------|-----|---------|--------------|
| INC-2026-002 | Lab 2 | Password spray script | Entra risky sign-in, session revocation |
| INC-2026-004 | Lab 2 | pfSense VPN logs | False positive, change-ticket correlation |