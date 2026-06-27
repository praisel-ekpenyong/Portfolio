# Live Entra Password Spray (INC-2026-002)

Controlled **live** spray against the `pe-soc-lab` tenant to generate real `SigninLogs` and Sentinel incidents. **Lab use only.**

> Do **not** use `--mock` for incident evidence. Mock mode is reserved for pytest (`tests/test_emulate_o365spray.py`).

## Objective

Produce 18 failed sign-ins followed by one successful authentication for `jsmith@corp.lab` from the lab red-team host (documented as `203.0.113.55`).

## Prerequisites

- Test account `jsmith@corp.lab` in `pe-soc-lab` tenant
- Spray host outside corp network (lab red-team VM with NAT)
- Sentinel rule `password_spray_entra.kql` deployed
- Entra sign-in logs flowing to Sentinel

## Live execution (Python)

From the portfolio root, on the red-team host:

```bash
pip install -r scripts/requirements.txt

# 18 failed attempts (wrong password) — each issues a real Entra sign-in failure
for i in $(seq 1 18); do
  python scripts/emulate_o365spray.py \
    --userlist scripts/spray-users-inc002.txt \
    --password "WrongPassword-LabOnly" \
    --delay 2
done

# 1 successful attempt (lab-known password for jsmith) — real success in SigninLogs
python scripts/emulate_o365spray.py \
  --userlist scripts/spray-users-inc002.txt \
  --password "<lab-known-password>" \
  --delay 0 \
  --output artifacts/spray-run-INC002.json
```

Record **UTC start/end** in osTicket #48305 and [`docs/live-evidence-ledger.md`](../../docs/live-evidence-ledger.md).

## Validation (live SIEM)

1. Sentinel incident #2863 (or equivalent) within ~5 minutes
2. Entra ID Protection risky sign-in for `jsmith@corp.lab`
3. `SigninLogs` shows failures then one `ResultType == 0` from the spray source IP
4. Complete triage per [`INC-2026-002`](../../incidents/INC-2026-002-entra-password-spray.md)

## Pair with

[`INC-2026-004`](../../incidents/INC-2026-004-false-positive-vpn.md) — same T1110 family; false positive when usernames are invalid and no success occurs.