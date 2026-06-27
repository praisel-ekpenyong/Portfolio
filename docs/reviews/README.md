# SOC Portfolio Review — Index

Structured review of the **Praisel Ekpenyong SOC Analyst L1** portfolio (`Portfolio/`), conducted June 2026.

## How to use

- **Hiring managers:** Start with [01 — Overview](01-overview-and-structure.md), then [03 — Anchor case (INC-005)](03-inc-2026-005-phishing.md).
- **Self-improvement:** Read scorecards and "Issues & gaps" in each part; prioritize the [wrap-up backlog](08-inc-2026-006-rdp-lateral-and-wrap-up.md#top-remaining-improvements-portfolio-wide).
- **Interview prep:** Use the talking points and [15-minute walk-through](08-inc-2026-006-rdp-lateral-and-wrap-up.md#suggested-interview-walk-through-15-minutes) in Part 8.

## Review parts

| Part | Document | Focus |
|------|----------|-------|
| 1 | [01-overview-and-structure.md](01-overview-and-structure.md) | README, navigation, tests, lab architecture |
| 2 | [02-website.md](02-website.md) | `website/` — UX, SEO, accessibility |
| 3 | [03-inc-2026-005-phishing.md](03-inc-2026-005-phishing.md) | Anchor case — phishing + endpoint correlation |
| 4 | [04-inc-2026-002-entra-spray.md](04-inc-2026-002-entra-spray.md) | Entra password spray + post-auth sweep |
| 5 | [05-inc-2026-001-bits-lolbin.md](05-inc-2026-001-bits-lolbin.md) | LOLBin / BITS download |
| 6 | [06-inc-2026-003-scheduled-task.md](06-inc-2026-003-scheduled-task.md) | Scheduled task persistence |
| 7 | [07-inc-2026-004-vpn-false-positive.md](07-inc-2026-004-vpn-false-positive.md) | False positive + VPN rule tuning |
| 8 | [08-inc-2026-006-rdp-lateral-and-wrap-up.md](08-inc-2026-006-rdp-lateral-and-wrap-up.md) | RDP lateral + scripts/detections/tests + overall scorecard |

## Overall verdict

| Area | Grade |
|------|-------|
| Portfolio overall | **A / A-** |
| Hireability signal | Strong for junior SOC / security analyst roles |

**Validation:** `python -m pytest tests/` — **61 tests passing** (verified during review).

## Changes applied during review

- **INC-2026-003:** Clarified initiating process chain (`cmd.exe` → `schtasks.exe`) vs task action (`powershell.exe`) in incident doc and aligned tickets.
- **Live evidence standard:** Added [`docs/live-evidence-ledger.md`](../live-evidence-ledger.md); removed simulated log playback language from README and shift doc; INC-002/004 updated for live-only evidence.

---

*Generated from structured portfolio review sessions. Update individual part files as artifacts improve.*