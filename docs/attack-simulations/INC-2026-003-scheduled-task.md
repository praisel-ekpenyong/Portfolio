# INC-2026-003 · Scheduled task persistence

**Day 4** · Ticket **#48318**

← [All guides](README.md) · [Live evidence ledger](../live-evidence-ledger.md)

**Type:** Caldera  
**Target:** WKSTN-042  
**MITRE:** T1053.005, T1059.001

---

## Red team steps

1. Confirm agent **ALIVE** on WKSTN-042.
2. Caldera → **New Operation**.
3. Name: `2026-06-15-SCHTASK-LAB`.
4. Adversary: **`T1-Scheduled-Task`** · Group: **`blue-team-lab`**.
5. **Start** operation.
6. Confirm ability creates task **`ChromeUpdate`** running `powershell.exe` from `%LocalAppData%\Temp\update.ps1`.

---

## Validate alerts

| Source | Signal |
|--------|--------|
| Wazuh | Rule **180002** (~16:04:18 in reference run) |
| Sysmon | EID 1 `schtasks /Create` + EID 11 task file |
| Defender | Persistence: scheduled task |

---

## Blue team / investigation

Follow [`incidents/INC-2026-003-scheduled-task-persistence.md`](../../incidents/INC-2026-003-scheduled-task-persistence.md) — task XML, DC/fleet scope, persistence sweep.

---

## Stop and cleanup

1. Disable/delete task `schtasks /Delete /TN ChromeUpdate /F`.
2. Stop Caldera op; isolate WKSTN-042.
3. Export artifacts → ticket **#48318**.

**Next:** [INC-2026-004 — VPN false positive](INC-2026-004-vpn-false-positive.md)