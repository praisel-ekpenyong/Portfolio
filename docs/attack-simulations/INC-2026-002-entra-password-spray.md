# INC-2026-002 · Entra password spray

**Day 2** · Ticket **#48305**

← [All guides](README.md) · [Live evidence ledger](../live-evidence-ledger.md)

**Type:** Live API spray (no Caldera, **no `--mock`**)  
**Target:** `jsmith@corp.lab` from external lab IP  
**MITRE:** T1110.003, T1078

---

## Prerequisites

- Sentinel rule: `detections/sentinel/password_spray_entra.kql`
- Legacy auth or ROPC path allowed for lab tenant (or spray will only produce failures/MFA challenges)
- Red-team host with outbound internet (documented as `203.0.113.55` in write-up)

---

## Red team steps

1. On red-team machine, clone portfolio repo and install deps:
   ```powershell
   pip install -r scripts/requirements.txt
   ```
2. Run **18 failed** live attempts (wrong password):

   **Linux/macOS:**
   ```bash
   for i in $(seq 1 18); do
     python scripts/emulate_o365spray.py \
       --userlist scripts/spray-users-inc002.txt \
       --password "WrongPassword-LabOnly" \
       --delay 2
   done
   ```

   **Windows PowerShell:**
   ```powershell
   1..18 | ForEach-Object {
     python scripts/emulate_o365spray.py `
       --userlist scripts/spray-users-inc002.txt `
       --password "WrongPassword-LabOnly" `
       --delay 2
   }
   ```

3. Run **1 successful** attempt with the lab-known password for `jsmith`:
   ```powershell
   python scripts/emulate_o365spray.py `
     --userlist scripts/spray-users-inc002.txt `
     --password "<lab-known-password>" `
     --delay 0 `
     --output artifacts/spray-run-INC002.json
   ```

4. Record UTC window in osTicket **#48305**.

---

## Validate alerts

| Source | Look for |
|--------|----------|
| Sentinel | Incident from `password_spray_entra` (~#2863) |
| Entra ID Protection | Risky sign-in — High |
| SigninLogs | 18× `50126` (or failures) + 1× `ResultType == 0` |

---

## Blue team / investigation

Follow [`incidents/INC-2026-002-entra-password-spray.md`](../../incidents/INC-2026-002-entra-password-spray.md) — post-auth sweep, session revoke, escalate.

---

## Stop and cleanup

1. Revoke sessions / disable account per playbook.
2. Password reset + MFA re-register.
3. Screenshot Sentinel + Entra; export SigninLogs query results.

**Next:** [INC-2026-001 — BITS download](INC-2026-001-bits-download.md)