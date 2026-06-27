# INC-2026-005 · Phishing + endpoint correlation

**Day 1** · Ticket **#48340**

← [All guides](README.md) · [Live evidence ledger](../live-evidence-ledger.md)

**Type:** Email artifact + Caldera post-click  
**Target:** `jsmith` / `WKSTN-042`  
**MITRE:** T1566.001, T1204.002, T1059.001, T1071.001

---

## Phase A — Email and user report (manual)

1. Place or reference the lab phishing message: `artifacts/phishing-invoice.eml`.
2. Parse headers for the ticket:
   ```powershell
   python scripts/parse_email.py --input artifacts/phishing-invoice.eml --output artifacts/phishing_analysis.md
   ```
3. Open osTicket **#48340** — subject: user-reported phishing (invoice attachment).
4. Record reported time (UTC). Document SPF/DKIM/DMARC failures using [`phishing/email-header-analysis.md`](../../phishing/email-header-analysis.md).
5. Simulate user report: note that `jsmith` opened the ZIP/LNK (execution follows in Phase B).

---

## Phase B — Caldera post-click (live)

1. Caldera UI → **Operations → New Operation**.
2. Set name: `2026-06-17-PHISH-LAB` (or current date).
3. Adversary: **`T1-Phish-to-Host`** · Group: **`blue-team-lab`** · Agent: **WKSTN-042**.
4. **Start** operation ~2 minutes after Phase A report time.
5. Wait for abilities to complete (PowerShell cradle → file write → beacon to `10.10.30.10:8888`).

---

## Validate alerts (within 5 min)

| Source | Look for |
|--------|----------|
| Sentinel | PowerShell from Office/parent chain rule |
| Defender | Suspicious process chain on WKSTN-042 |
| Suricata | Outbound HTTP/C2 to lab C2 |
| Wazuh/Sysmon | `powershell.exe` execution |

---

## Blue team / investigation

Follow [`incidents/INC-2026-005-phishing-chain.md`](../../incidents/INC-2026-005-phishing-chain.md) — staged conclusions, host-network correlation, containment.

---

## Stop and cleanup

1. Stop Caldera operation.
2. Isolate WKSTN-042 (Defender) per incident playbook.
3. Export evidence per [universal procedure](README.md#universal-procedure-every-case).

**Next:** [INC-2026-002 — Entra password spray](INC-2026-002-entra-password-spray.md)