# Part 4 of 8: INC-2026-002 (Entra Password Spray)

**Scope:** [`incidents/INC-2026-002-entra-password-spray.md`](../../incidents/INC-2026-002-entra-password-spray.md), `detections/sentinel/password_spray_entra.kql`, spray emulation tooling.

---

## Verdict: Strong identity IR with detection engineering depth

Demonstrates the highest-stakes Tier 1 identity scenario: failed logons followed by success. Post-authentication checklist and CA hardening align with SC-200 positioning.

**Overall case grade: A-**

---

## What works exceptionally well

1. **Success changes everything** — Contrast with INC-2026-004 (invalid users, zero successes)
2. **Post-authentication investigation matrix** — MFA enrollment, mailbox rules, OAuth, SharePoint, unmanaged device
3. **Legacy auth MFA bypass** — Explains how spray succeeded despite MFA registration
4. **Shipped detection** — `password_spray_entra.kql` with threshold/window logic
5. **Full IR lifecycle** — Revoke → disable → reset → MFA re-register → user briefing
6. **Supporting ecosystem** — Ticket #48305, `emulate_o365spray.py` (8 tests), `entra_risky_signin.kql`, screenshots

---

## Issues & gaps

| Severity | Issue | Recommendation |
|----------|-------|----------------|
| Medium | Spray doc references PowerShell; tooling is `emulate_o365spray.py` | Link Python script in incident + `spray-simulation.md` |
| Low | KQL rule detects spray pattern by IP; narrative is single-user | Clarify rule scope vs this event |
| Low | ResultType table lists 50076/50079 but rule omits them | Add to filter or mark reference-only |
| Low | `entra_risky_signin.kql` maps 50126 → T1110.001; incident uses T1110.003 | Align MITRE tags |
| Low | No Defender screenshot despite WKSTN-042 correlation | Add or note log-based only |
| Low | Splunk DC cross-check has no sample output | Add rows or mark optional |
| Low | Section 10 (CA recommendations) is long | Optional extract to `docs/identity-hardening.md` |

---

## Detection rule notes (interview fodder)

**Strengths:** Configurable threshold, distinct failure/success counts, MITRE + incident ref.

**Production tuning topics:** Pen-test allowlists, service account exclusions, time-bucketing validation in Sentinel.

---

## Interview talking points

1. What to do when spray succeeds
2. FP vs TP identity (INC-004 contrast)
3. Why MFA did not block (legacy auth)
4. Walk through `password_spray_entra.kql`
5. CA policies from Section 10

---

## Scorecard

| Criterion | Score |
|-----------|-------|
| Identity triage methodology | 10/10 |
| Detection engineering | 9/10 |
| IR process | 9/10 |
| Cross-domain correlation | 8/10 |
| Policy thinking | 10/10 |

---

## Highest-impact fix

In Section 9, link `scripts/emulate_o365spray.py` and note detection rule scope (≥10 failed accounts + ≥1 success from same IP within 15m).

---

[Previous: Part 3](03-inc-2026-005-phishing.md) · [Next: Part 5](05-inc-2026-001-bits-lolbin.md) · [Index](README.md)