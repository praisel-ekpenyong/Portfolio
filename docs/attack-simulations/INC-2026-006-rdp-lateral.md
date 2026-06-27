# INC-2026-006 · RDP lateral + network sniffing

**Day 6** · Ticket **#48370**

← [All guides](README.md) · [Live evidence ledger](../live-evidence-ledger.md)

**Type:** Caldera  
**Target:** WKSTN-099 (actions); lateral from WKSTN-042 as `jsmith`  
**MITRE:** T1021.001, T1112, T1040

---

## Prerequisites

- Sandcat **ALIVE** on **WKSTN-099** (and WKSTN-042 for lateral source context).
- RDP allowed WKSTN-042 → WKSTN-099 in lab firewall (or ability will fail).
- `jsmith` credentials valid for RDP.
- `tcpdump.exe` (or lab equivalent) available on WKSTN-099 for sniffer ability.

---

## Red team steps

1. Caldera → **New Operation**.
2. Name: `2026-06-18-LATERAL-RDP-LAB`.
3. Adversary: **`T1-Windows-Lateral`** · Group: **`blue-team-lab`** · Primary agent: **WKSTN-099**.
4. **Start** operation.
5. Monitor chain:
   - RDP from `10.10.10.42` → `10.10.10.99`
   - Registry `RDP-Tcp\PortNumber` → **8443**
   - `tcpdump.exe -w C:\Users\Public\capture.pcapng`

---

## Validate alerts

| Source | Signal |
|--------|--------|
| Wazuh | Rule **180003** (registry) |
| Suricata | RDP on non-standard port **8443** |
| Wazuh | Rule **180004** (`tcpdump.exe`) |

---

## Blue team / investigation

1. Follow [`incidents/INC-2026-006-rdp-lateral-movement.md`](../../incidents/INC-2026-006-rdp-lateral-movement.md).
2. Copy `capture.pcapng` and run `tshark` checks from incident Section 3.
3. Isolate **both** WKSTN-099 and WKSTN-042; revoke `jsmith` tokens.

---

## Stop and cleanup

1. Reset RDP port to **3389** via GPO/PowerShell.
2. Delete PCAP; stop Caldera op.
3. Export artifacts → ticket **#48370**.

**Done:** Return to [README — After all six cases](README.md#after-all-six-cases)