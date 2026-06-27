# Scenario 02 — Entra Password Spray & Risky Sign-in

**Incident Record:** [`INC-2026-002`](../../incidents/INC-2026-002-entra-password-spray.md)

**Praisel Ekpenyong** · Lab 2 only · No Caldera

| Field | Value |
|-------|-------|
| Incident | [INC-2026-002](../../incidents/INC-2026-002-entra-password-spray.md) |
| Lab | Lab 2 — `pe-soc-lab` tenant |
| MITRE | T1110.003, T1078 |
| Detection | `detections/sentinel/password_spray_entra.kql` |

## Objective

Demonstrate Tier 1 identity alert triage: password spray against a **valid** Entra user, risky sign-in correlation, session revocation, and escalation after successful authentication.

## Prerequisites

- Entra sign-in connector to Sentinel (`docs/lab-architecture.md`)
- Analytics rule imported from `password_spray_entra.kql`
- Test account `jsmith@corp.lab` (same user as INC-2026-001)

## Execution (Lab)

1. Run controlled spray script against `jsmith@corp.lab` from external IP (lab red-team host `203.0.113.55`). See [`spray-simulation.md`](spray-simulation.md).
2. Confirm Sentinel incident and Entra risky-sign-in alert fire.
3. Triage with `detections/sentinel/entra_risky_signin.kql`.
4. Complete incident report and osTicket #48305.

## Live Run Checklist

- [ ] Confirm user exists in Entra — not a scanner guessing random names
- [ ] Count failures vs successes in `SigninLogs`
- [ ] Check location / IP reputation vs user's normal pattern
- [ ] Revoke sessions and disable account if success observed
- [ ] Correlate `DeviceLogonEvents` on user's workstation
- [ ] Escalate to Tier 2 if account takeover confirmed
- [ ] Document contrast with [INC-2026-004](../../incidents/INC-2026-004-false-positive-vpn.md) (invalid users, no success)

## Pair With

| Incident | Lesson |
|----------|--------|
| INC-2026-004 | Same T1110 family — false positive when usernames invalid and change ticket explains spike |
| INC-2026-005 | Same user `jsmith` — shows email + identity + endpoint correlation across cases |