# INC-2026-004 · VPN false positive (live noise)

**Day 5** · Ticket **#48322** · Tuning **#48355**

← [All guides](README.md) · [Live evidence ledger](../live-evidence-ledger.md)

**Type:** Live OpenVPN auth failures (no Caldera)  
**Target:** pfSense VPN → Sentinel `VPNLogs`  
**MITRE:** T1110.001 (ruled out after triage)

---

## Prerequisites

- Open change record **CHG-8821** (geo-block cutover on VPN interface).
- Sentinel rule: `detections/sentinel/vpn_failed_logins.kql` (original, pre-tune).

---

## Red team / noise generation (live)

Choose **one** approach:

### Option A — External scanner (most realistic)

1. Apply geo-block / VPN policy change per CHG-8821.
2. From external lab VM, run repeated OpenVPN connection attempts with **invalid usernames** (`admin`, `root`, `test`, …) against `vpn.corp.lab`.
3. Continue until **40+ `AUTH_FAILED`** events appear in pfSense (reference: 47 failures).

### Option B — Controlled lab brute tool

1. Use a VPN client script that attempts authentication with invalid credentials from a single source IP (`203.0.113.45` documented range).
2. Ensure **zero successful** logins.

---

## Validate alerts

| Source | Signal |
|--------|--------|
| pfSense | `openvpn: AUTH FAILED` lines |
| Sentinel | `Multiple failed VPN logins from single source` |
| SigninLogs | No matching Entra activity from that IP (VPN is separate IdP) |

---

## Blue team / investigation

Follow [`incidents/INC-2026-004-false-positive-vpn.md`](../../incidents/INC-2026-004-false-positive-vpn.md) — change ticket check, close as FP, tune rule to `vpn_failed_logins_tuned.kql`.

---

## Stop and cleanup

1. Close parent ticket **#48322**; open tuning ticket **#48355**.
2. Screenshot Sentinel; save firewall log excerpt.
3. Do **not** permanently block scanner IP if geo-block already handles it.

**Next:** [INC-2026-006 — RDP lateral](INC-2026-006-rdp-lateral.md)