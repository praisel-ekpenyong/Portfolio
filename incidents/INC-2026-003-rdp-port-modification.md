# INC-2026-003 — RDP Port Modification & Network Sniffing (Caldera T1-Windows-Lateral)

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-003 |
| **osTicket** | #48318 |
| **Severity** | P2 — High (escalation candidate P1 if exfil confirmed) |
| **Status** | Closed — True Positive (Lab Emulation) |
| **Detection Source** | Wazuh 180002, 180003; Suricata ET POLICY |
| **Caldera Operation** | `2026-06-19-LATERAL-LAB` |
| **MITRE ATT&CK** | T1040, T1021.001 |
| **Analyst** | Praisel Ekpenyong |
| **Lab Environment** | Hybrid — Lab 1 (Splunk/Wireshark/pfSense) + Lab 2 (Defender) |

---

## 1. Detection

**2026-06-19 16:08:12 UTC** — Wazuh Rule 180002:

```
Network sniffing tool discovered on WKSTN-099 — tshark.exe in command line
```

**16:08:44 UTC** — Wazuh Rule 180003:

```
RDP port has been changed on WKSTN-099
Registry: HKLM\...\RDP-Tcp\PortNumber
```

---

## 2. Validation

| Check | Result |
|-------|--------|
| IT change to move RDP off 3389? | No ticket |
| Wireshark/tshark on finance workstation? | Not in software inventory |
| Registry modification via `reg add` | Confirmed in Sysmon EID 1 |
| PCAP file created in `C:\Users\Public\` | `capture.pcapng` — 12 MB |
| Caldera | T1040 ability 16:08:10, T1021.001 at 16:08:42 |

**Determination:** True positive — reconnaissance and defense evasion via non-standard RDP port.

---

## 3. Enrichment

### Network Analysis (PCAP)

Analyst reviewed `capture.pcapng` in Wireshark:

| Finding | Detail |
|---------|--------|
| Protocols | DNS (45%), TLS (30%), SMB (15%) |
| Sensitive data | No cleartext passwords (TLS enforced) |
| DNS queries | Normal AD DNS — no tunneling detected |
| Conversation filter | `tcp.port == 3389` — single SYN to DC (scan attempt) |

**Wireshark display filter used:**

```
dns.qry.name contains "corp" || tcp.port == 3389 || http.request
```

### Firewall Log Correlation

```
pfSense: WKSTN-099 → 10.10.20.10:3389 ALLOW (internal RDP probe)
```

### Host Context

| Field | Value |
|-------|-------|
| User | CORP\mfinance |
| Department | Finance |
| Prior alerts | None in 90 days |

---

## 4. Containment

| Time (UTC) | Action |
|------------|--------|
| 16:20:00 | Host isolated (MDE) |
| 16:22:00 | Blocked outbound RDP from WKSTN-099 at firewall |
| 16:25:00 | Disabled `CORP\mfinance` pending HR/IT review |

---

## 5. Eradication

| Time (UTC) | Action |
|------------|--------|
| 16:40:00 | Restored RDP port to 3389 via known-good registry export |
| 16:42:00 | Deleted `capture.pcapng` after hash cataloged |
| 16:45:00 | Removed tshark portable copy from `C:\Users\Public\` |
| 16:50:00 | Caldera sandcat process terminated |

---

## 6. Recovery

| Time (UTC) | Action |
|------------|--------|
| 17:10:00 | Verified RDP service on default port |
| 17:15:00 | Re-enabled account after manager confirmation (compromised session theory) |
| 17:30:00 | Host de-isolated |

---

## 7. Escalation

**Escalated to IR at 16:30 UTC** — packet capture on finance host triggers mandatory IR notification per policy.

IR concluded Caldera lab emulation; in production, would hunt for lateral movement to `SRV-DC-01`.

---

## 8. Evidence

### Sysmon — Registry Set (if Sysmon config includes EID 13)

```
EventCode=13
TargetObject: \REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber
Details: DWORD (0x00000d3a) /* 3386 — non-default */
```

### Splunk

```spl
index=sysmon host=WKSTN-099 (EventCode=1 OR EventCode=13)
| search CommandLine="*tshark*" OR CommandLine="*reg add*" OR TargetObject="*RDP-Tcp*"
| table _time EventCode User Image CommandLine TargetObject Details
```

---

## 9. Recommendations

1. Alert on **any** RDP port registry change outside GPO deployment window.
2. Block portable sniffers via AppLocker on workstations.
3. Restrict RDP laterally from workstations to servers (firewall segmentation).
4. Enable Zeek `rdp.log` for metadata without full PCAP storage on endpoints.

---

## 10. Evidence Screenshots

| Tool | Capture |
|------|---------|
| Microsoft Defender | `artifacts/screenshots/defender-inc003.png` |
| Microsoft Sentinel | `artifacts/screenshots/sentinel-inc003.png` |
| osTicket | `artifacts/screenshots/osticket-48318.png` |

---

## 11. Tier 1 Learning Outcomes

- Correlated host-based alerts with firewall and PCAP evidence
- Applied network protocol basics (TCP/3389, DNS, TLS)
- Documented escalation to IR with clear handoff package
- Mapped activity to MITRE T1040 and T1021.001 from Caldera profile