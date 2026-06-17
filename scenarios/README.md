# Caldera Scenario Index

**Praisel Ekpenyong** · [GitHub](https://github.com/praisel-ekpenyong) · [LinkedIn](https://www.linkedin.com/in/praiselekpenyong)

Each scenario follows: **Caldera operation → SIEM alert → Tier 1 triage → Incident record**.

| Scenario | Caldera Profile | Primary Docs |
|----------|-----------------|--------------|
| [01 — Windows BITS Download](01-caldera-windows-download/README.md) | T1-Windows-Download-Exec | INC-2026-001 |
| [02 — Linux Persistence](02-caldera-linux-persistence/README.md) | T1-Linux-Persistence | INC-2026-002 |
| [03 — Lateral / RDP](03-caldera-lateral-rdp/README.md) | T1-Windows-Lateral | INC-2026-003 |
| [04 — Phish to Host](04-caldera-phishing-chain/README.md) | T1-Phish-to-Host | INC-2026-005 |

## Execution Order

1. Deploy agents (`docs/caldera-setup.md`)
2. Import Wazuh rules (`detections/wazuh/local_rules.xml`)
3. Run operation (`caldera/operations-runbook.md`)
4. Triage using playbook (`docs/soc-playbooks.md`)
5. Complete incident report (`templates/incident-report.md`)
6. File ticket (`tickets/sample-tickets.md` as reference)

## Non-Caldera Scenario

**INC-2026-004** (VPN false positive) intentionally has no Caldera component — demonstrates organic alert handling.