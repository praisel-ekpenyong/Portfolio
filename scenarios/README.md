# Lab Scenario Index

Scenarios are ordered by threat type and complexity to showcase a logical progression of security operations investigations, rather than the chronological order in which they were run in the lab.

| # | Case | Scenario folder | Incident |
|---|------|-----------------|----------|
| 1 | Phishing + endpoint | [04 — Phish to Host](04-caldera-phishing-chain/README.md) | INC-2026-005 |
| 2 | Entra password spray | [02 — Entra spray](02-entra-password-spray/README.md) | INC-2026-002 |
| 3 | LOLBin / BITS | [01 — Windows download](01-caldera-windows-download/README.md) | INC-2026-001 |
| 4 | Scheduled task | [03 — Scheduled task](03-caldera-scheduled-task/README.md) | INC-2026-003 |
| 5 | False positive | (organic — no Caldera) | INC-2026-004 |
| 6 | RDP lateral movement | [06 — Lateral RDP](06-caldera-lateral-rdp/README.md) | INC-2026-006 |

## Non-Caldera

| Incident | Trigger |
|----------|---------|
| INC-2026-002 | Lab spray script — `02-entra-password-spray/spray-simulation.md` |
| INC-2026-004 | pfSense VPN logs + change ticket CHG-8821 |

## Supplemental

- [DNS exfil drill](../network/sample-dns-exfil-analysis.md) — practice only