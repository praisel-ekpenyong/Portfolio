# Scenario Index

Cases are ordered for **portfolio presentation** (interview order), not lab execution order.

| # | Case | Scenario folder | Incident |
|---|------|-----------------|----------|
| 1 | Phishing + endpoint | [04 — Phish to Host](04-caldera-phishing-chain/README.md) | INC-2026-005 |
| 2 | Entra password spray | [02 — Entra spray](02-entra-password-spray/README.md) | INC-2026-002 |
| 3 | LOLBin / BITS | [01 — Windows download](01-caldera-windows-download/README.md) | INC-2026-001 |
| 4 | Scheduled task | [03 — Scheduled task](03-caldera-scheduled-task/README.md) | INC-2026-003 |
| 5 | False positive | (organic — no Caldera) | INC-2026-004 |

## Non-Caldera

| Incident | Trigger |
|----------|---------|
| INC-2026-002 | Lab spray script — `02-entra-password-spray/spray-simulation.md` |
| INC-2026-004 | pfSense VPN logs + change ticket CHG-8821 |

## Supplemental

- [RDP / PCAP lateral](../network/supplemental-rdp-lateral-case.md) — former INC-003, stretch module
- [DNS exfil drill](../network/sample-dns-exfil-analysis.md) — practice only