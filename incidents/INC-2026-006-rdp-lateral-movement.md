# INC-2026-006 — RDP Lateral Movement & Network Sniffing (Case #6)

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-006 |
| **Focus Area** | **Network Forensics & RDP Baselines** |
| **osTicket** | #48370 |
| **Severity** | P2 — High |
| **Status** | Closed — True Positive (Lab Emulation) |
| **Detection Source** | Wazuh Rules 180003/180004 + Splunk correlation |
| **Caldera Operation** | `2026-06-18-LATERAL-RDP-LAB` |
| **MITRE ATT&CK** | T1021.001 (RDP), T1040 (Network Sniffing), T1112 (Modify Registry) |
| **Analyst** | Praisel Ekpenyong (SOC Analyst L1) |
| **Lab Environment** | Lab 1 — On-Premises SOC (`corp.lab.local` / Splunk / Wazuh) |

---

## Executive Summary

An alert was triggered on `WKSTN-099` (finance VLAN) indicating an RDP port modification and the execution of `tcpdump.exe` (packet sniffer). Investigation revealed that the threat actor leveraged compromised credentials of `jsmith` to move laterally via RDP from `WKSTN-042` to `WKSTN-099`. Once inside, the actor altered the default RDP port to `8443` for evasion and attempted network traffic sniffing.

I validated the alert against administrative baselines, isolated both workstations, and performed command-line `tshark` PCAP analysis to prove that the sniffer process did not capture or exfiltrate any sensitive data before containment. The hosts were de-isolated after registry remediation and verification of zero lateral propagation.

### MITRE Evidence Map

| Technique | Evidence |
|-----------|----------|
| **T1021.001 Remote Desktop Protocol** | Incoming RDP connection to `WKSTN-099` from `10.10.10.42` (Event 4624 Type 10) |
| **T1112 Modify Registry** | Change of port from `3389` to `8443` in registry under `Terminal Server\WinStations\RDP-Tcp` |
| **T1040 Network Sniffing** | Launch of `tcpdump.exe` targeting local interface to capture raw packets |

---

## 1. Detection

**2026-06-18 10:15:02 UTC** — Wazuh Alert on `WKSTN-099`:
```
Rule: 180003 (level 8) — Suspicious RDP registry port modification detected
Agent: wazuh-agent-wkstn-099
Registry Path: HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber
Value: 8443 (default: 3389)
```

**10:15:15 UTC** — Wazuh Alert on `WKSTN-099`:
```
Rule: 180004 (level 9) — Unauthorized packet sniffer (tcpdump.exe) executed
Agent: wazuh-agent-wkstn-099
Process: C:\Users\Public\tcpdump.exe
CommandLine: tcpdump.exe -i 1 -w C:\Users\Public\capture.pcapng
User: CORP\jsmith
```

---

## 2. Validation (Administrative Baseline Comparison)

To confirm if this represents legitimate administrative activity (such as network troubleshooting by IT support) or a malicious intrusion, I compared the alert details to our standard operating procedures on the finance segment:

| Attribute | Legitimate Admin Activity (WKSTN-001) | Anomalous Lateral Activity (WKSTN-099) |
|-----------|---------------------------------------|----------------------------------------|
| **Origin Host** | IT Admin Jumpbox (`WKSTN-010`) | User workstation (`WKSTN-042`) |
| **Sign-on Context** | Admin account (`adm-praisel`) | Standard user account (`jsmith`) |
| **RDP Port Status** | Standard port `3389` | Evasive port change to `8443` |
| **Change Ticket** | CHG-8840 (network diagnostics) | None |
| **Tool Execution** | Run via administrator-signed scripts | Interactively executed under temp paths |
| **Verdict** | **Benign / Approved** | **Malicious (True Positive)** |

**Determination:** True positive lateral movement and sniffing attempt. No matching change ticket was found, and standard users on the finance VLAN are strictly unauthorized to execute packet capture engines.

---

## 3. Enrichment & PCAP Forensics

### Host Context
* **Source Asset:** `WKSTN-042` (`10.10.10.42` — Finance workstation, already flagged in `INC-2026-005` phishing execution)
* **Destination Asset:** `WKSTN-099` (`10.10.10.99` — Critical finance VLAN server/workstation)
* **Logon Verification (Splunk):**
```spl
index=sysmon EventCode=3 host=WKSTN-099 DestinationPort=3389
| stats count by SourceIp, DestinationIp, User
```
* **Result:** Confirmed inbound RDP flow from `10.10.10.42` to `10.10.10.99` under `CORP\jsmith` immediately preceding the registry port modification.

---

### Command-Line PCAP Analysis via `tshark`

The packet capture file (`C:\Users\Public\capture.pcapng`) was recovered from `WKSTN-099` during the triage sweep. I performed command-line packet inspection to determine the scope of collection and verify if the attacker attempted data exfiltration:

#### 1. Inspect DNS Query Volume for Exfiltration/Tunneling
I checked the capture for high-frequency or anomalous DNS requests that might indicate data exfiltration via DNS tunneling:
```bash
tshark -r capture.pcapng -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort | uniq -c | sort -nr | head -n 10
```
* **Output:**
```
  12 corp.lab.local
   4 wazuh-srv.corp.lab.local
   2 google.com
```
* **Analysis:** DNS traffic is normal. There are no signs of high-frequency queries or long subdomain structures indicating tunneling.

#### 2. Inspect Cleartext HTTP Objects and POST Requests
I searched for plaintext HTTP sessions that the attacker might have sniffed from other hosts on the local network segment:
```bash
tshark -r capture.pcapng -Y "http.request.method == \"POST\"" -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri
```
* **Output:**
*(empty output)*
* **Analysis:** No outbound HTTP POST requests or cleartext credentials were captured during the run.

#### 3. Analyze TLS SNI (Server Name Indication) Headers
I inspected encrypted connections to see if any data was sent out to unauthorized external hosts:
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name | sort | uniq -c
```
* **Output:**
```
   3 law-pe-soc-prod.ods.opinsights.azure.com
   2 wazuh-srv.corp.lab.local
```
* **Analysis:** The only outbound encrypted traffic was routed to the telemetry endpoints (Azure Log Analytics and the Wazuh Manager).

**Eradication Verdict:** The sniffer capture confirmed **zero** exfiltration of credentials or sensitive data. The sniffer run lasted less than 45 seconds before the Wazuh rules isolated the host.

---

## 4. Containment

To prevent lateral traversal to other workstations on the finance VLAN:

| Time (UTC) | Action | Performed By |
|------------|--------|--------------|
| **10:18:00** | Isolated `WKSTN-099` from the local network segment via Wazuh firewall rule | Praisel Ekpenyong |
| **10:19:30** | Isolated `WKSTN-042` (originating host) per playbooks | Praisel Ekpenyong |
| **10:20:15** | Terminated active RDP sessions and disabled RDP access on both hosts | Praisel Ekpenyong |
| **10:22:00** | Revoked all Entra ID tokens and disabled `jsmith` account domain-wide | Tier 1 |

---

## 5. Eradication & Remediation

1. **RDP Port Restore:** Reset the RDP registry port back to standard (`3389`) using a Group Policy update:
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'PortNumber' -Value 3389
```
2. **Process Cleanup:** Verified the termination of `tcpdump.exe` and deleted the local capture file `C:\Users\Public\capture.pcapng`.
3. **AV Verification:** Run a clean Microsoft Defender scan on `WKSTN-099`.

---

## 6. Recovery

1. Re-enabled RDP connections on `WKSTN-099` post-registry baseline validation.
2. Domain controller password reset completed for user `jsmith` (coordinated via phone verification).
3. Removed network isolation rules at **14:00 UTC** after Tier 2 review confirmed zero residual traces.

---

## 7. Escalation

**Escalated to Tier 2 at 10:25 UTC**  
* **Reason:** Confirmed lateral movement across the finance segment and registry evasion modifications.
* **Handoff Artifacts:**
  * Sysmon Event ID 1 (tcpdump execution) logs.
  * Registry modification event logs (Event ID 13).
  * Analyzed `capture.pcapng` metrics.

---

## 8. Timeline (UTC)

| Time | Event |
|------|-------|
| **10:10:00** | Caldera lateral RDP operation begins |
| **10:12:30** | Inbound RDP connection established from `WKSTN-042` to `WKSTN-099` |
| **10:15:02** | RDP registry port modified to `8443`; Wazuh Rule 180003 fires |
| **10:15:15** | Threat actor launches `tcpdump.exe` sniffer; Wazuh Rule 180004 fires |
| **10:18:00** | Tier 1 analyst acknowledges alerts and initiates isolation on `WKSTN-099` |
| **10:19:30** | Source workstation `WKSTN-042` isolated |
| **10:25:00** | Ticket escalated to Tier 2 with PCAP inspection summary |
| **14:00:00** | Incident closed |

---

## 9. Evidence Logs & Queries

### Wazuh Local Rules XML
Rules added to `detections/wazuh/local_rules.xml` to detect this behavior:
```xml
<!-- RDP Port Modification Detection -->
<rule id="180003" level="8">
  <if_sid>60103</if_sid>
  <field name="win.eventdata.targetObject">\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\PortNumber</field>
  <description>Suspicious RDP registry port modification detected</description>
  <group>registry_event,security_compliance</group>
</rule>

<!-- Unauthorized Sniffer Execution -->
<rule id="180004" level="9">
  <if_sid>60002</if_sid>
  <field name="win.eventdata.image">tcpdump.exe</field>
  <description>Unauthorized packet sniffer (tcpdump.exe) executed</description>
  <group>process_creation,incident_response</group>
</rule>
```

### Splunk Search for Correlation
```spl
index=sysmon EventCode=13 Image="*reg.exe*" 
| search TargetObject="*PortNumber*"
| table _time host Image TargetObject Details User
```

---

## 10. Recommendations

1. **Hardening:** Disable RDP access between workstations (WKSTN to WKSTN) on the finance VLAN; allow RDP exclusively from the designated IT Jumpbox.
2. **Software Restriction:** Deploy AppLocker policy to prevent standard users from running diagnostic or sniffing binaries (`tshark.exe`, `wireshark.exe`, `tcpdump`) across all Windows client endpoints.
3. **Detection Improvement:** Trigger high-severity alerts when registry modifications occur under `Terminal Server\WinStations\RDP-Tcp` from non-SYSTEM accounts.
4. **Key Event Telemetry for RDP Investigations:** Security analysts must monitor and audit the following logs on endpoints to trace lateral RDP movements:
   * **Microsoft-Windows-TerminalServices-LocalSessionManager/Operational**: Event ID `21` (Session logon succeeded - connection established) and Event ID `25` (Session reconnection).
   * **Security Log**: Event ID `4624` (Logon) with Logon Type `10` (RDP connection) or Logon Type `3` (Network logon via Network Level Authentication - NLA).

---

## 11. Evidence Screenshots

Screenshots are supplemental walkthrough visuals. The Sysmon excerpt, SPL/KQL, Wazuh rule, and event data are the primary evidence for this case.

| Tool | Capture |
|------|---------|
| Wazuh | `artifacts/screenshots/wazuh-inc006.png` |
| Sysmon / Splunk | `artifacts/screenshots/sysmon-inc006.png` |
| osTicket | `artifacts/screenshots/osticket-48370.png` |

---

## 12. Analyst Notes

This incident was triggered by controlled Caldera emulation to validate Wazuh rules 180003 and 180004. Production analysts would follow identical triage steps; the Caldera operation ID row in the header serves as a lab provenance marker and would not appear in a production write-up.

