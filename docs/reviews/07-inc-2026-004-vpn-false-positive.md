# Part 7 of 8: INC-2026-004 (False Positive / VPN Tuning)

**Scope:** [`incidents/INC-2026-004-false-positive-vpn.md`](../../incidents/INC-2026-004-false-positive-vpn.md), VPN KQL rules, shift VPN storm narrative.

---

## Verdict: Essential portfolio differentiator

Every strong SOC portfolio needs a false-positive case. This one shows safe closure under noise, change-management correlation, and detection improvement. Paired with INC-2026-002, it completes “contain vs tune” judgment.

**Overall case grade: A**

---

## What works exceptionally well

1. **Structured FP checklist** — Invalid users, zero success, no correlated compromise, CHG-8821 explains spike
2. **Change management correlation** — Geo-block cutover at 03:00 UTC, alert at 03:12 UTC
3. **Before/after KQL** — `vpn_failed_logins.kql` vs `vpn_failed_logins_tuned.kql` with validation table
4. **Residual risk documented** — Valid-user spray still caught by `password_spray_entra.kql`
5. **Three-way contrast table** — INC-004 vs INC-002 vs INC-001
6. **Operational follow-through** — Tickets #48322 (closed) + #48355 (tuning, open), shift handoff, VPN storm walkthrough
7. **Severity downgrade** — P3 → P5 / Normal → Low modeled explicitly
8. **Cross-portfolio integration** — Playbooks, INC-002 contrast, shift triage examples

### Tuning validation

| Scenario | Original rule | Tuned rule |
|----------|---------------|------------|
| INC-004 VPN noise (47 fails, invalid users) | MATCH | NO MATCH |

---

## Issues & gaps

| Severity | Issue | Recommendation |
|----------|-------|----------------|
| Low | Recommendation #2 (/24 prior success) not in tuned KQL | Mark future enhancement |
| Low | `wazuh-logtest-results.txt` name misleading for VPN KQL tests | Rename or split validation doc |
| Low | No dedicated timeline section | Optional UTC table |
| Low | SigninLogs enrichment query may confuse reviewers | Note expected empty result |
| Low | Change-window suppression secondary when invalid users fail `knownUsernames` join | Clarify primary fix is valid-username filter |

---

## High-volume shift integration

VPN storm (10:10–10:45 UTC): 47 alerts collapsed to parent #48322; tuning ticket #48355 opened. Demonstrates queue hygiene under alert fatigue.

---

## Interview talking points

1. False positive you closed safely
2. When not to escalate
3. Tuning without missing real spray (INC-002 rule)
4. VPN brute force vs Entra password spray
5. Before/after `vpn_failed_logins*.kql`

---

## Scorecard

| Criterion | Score |
|-----------|-------|
| FP analysis methodology | 10/10 |
| Detection tuning | 9/10 |
| Operational maturity | 9/10 |
| Risk awareness | 10/10 |
| Evidence depth | 8/10 |

---

## Optional clarification (Section 9)

> Primary noise reduction: inner join to `knownUsernames` eliminates scanner attempts with invalid usernames. Change-window suppression adds a secondary guard during tagged `vpn-policy` deployments.

---

[Previous: Part 6](06-inc-2026-003-scheduled-task.md) · [Next: Part 8](08-inc-2026-006-rdp-lateral-and-wrap-up.md) · [Index](README.md)