# SOC Analyst L1: Portfolio Interview & Discussion Guide

This guide helps you talk through your portfolio in interviews. It explains how to frame your career transition, how to leverage your advanced projects (scripting, PCAP analysis, rule writing) without sounding overqualified, and how to tell the story of your core incident logs.

---

## 1. The Career Transition Pitch

**How to structure it:** Acknowledge your past experience, pivot to your passion for security, and immediately ground it in the hands-on labs you built.

> *"I spent the last two years in customer-facing IT and support roles, where I learned the critical importance of SLA compliance, ticketing hygiene, and clear communication under pressure. However, my goal has always been security operations. To bridge the gap, I built two operational SOC labs—an on-premises environment with Wazuh and Splunk, and a cloud SOC tenant in Microsoft Sentinel. I didn't just configure them; I ran simulated attacks using Apache Caldera, generated real telemetry, and triaged the alerts using standard playbooks. I'm applying today because I want to bring that hands-on triage experience directly to your shift queue."*

---

## 2. Framing "Advanced" Skills (The Pivot Technique)

Hiring managers might ask why a Tier 1 candidate is writing Python tools, carving PCAP files, or writing custom XML rules. Use the templates below to frame these as **value-add skills** rather than daily expectations.

### A. The Custom Rule & SIEM Query Pitch
*   **The Trap:** *“I write custom detection rules from scratch for my company.”* (Too advanced; makes you sound like a Detection Engineer who will get bored triaging alerts).
*   **The Pitch:**
    > *"In my lab, I used Apache Caldera to emulate attacks. To detect them, I pulled standard open-source rules—like Sigma templates—and tuned them to my lab. For example, in the scheduled task case, I tuned the rules to ignore SCCM background noise while flagging execution from temp directories. This taught me how decoders map Sysmon telemetry under the hood. In your SOC, it means when an alert lands in my queue, I don't just follow a playbook blindly; I can read the KQL or SPL query behind it to instantly understand why it fired."*

### B. The Command-Line PCAP Forensics (`tshark`) Pitch
*   **The Trap:** *“I perform deep network forensics and carve PCAP files during incidents.”* (This is a Tier 2/Incident Responder role; T1 analysts escalate lateral movement immediately).
*   **The Pitch:**
    > *"I know my core job as a Tier 1 is to detect, isolate, and escalate lateral movement per the playbook. However, in my RDP Lateral Movement lab, I wanted to go a step further. I recovered the attacker's sniffer capture and used `tshark` on the command line to verify if they succeeded in exfiltrating sensitive credentials or querying external C2 hosts. It taught me how to read protocol headers, check TLS SNI extensions, and verify exfiltration boundaries, which makes me a much more effective contributor during escalations."*

### C. The Scripting & Automation (Python/PowerShell) Pitch
*   **The Trap:** *“I build custom security tools and script containment playbooks.”* (Leans Security Engineering).
*   **The Pitch:**
    > *"I built these utilities specifically to solve the biggest problem in modern SOCs: alert fatigue and manual lookup times. I wrote a Python script to clean defanged URLs and query threat intelligence APIs, and a PowerShell script to gather host connections. In a live environment, my goal isn't to rewrite your playbooks; it's to use basic scripting to automate my manual lookups so I can close benign alerts faster and focus on real threats."*

---

## 3. Case-Study Storytelling (STAR Method)

When asked about specific incidents or technical scenarios, walk the interviewer through the core cases in your portfolio using this structured approach:

### A. The Phishing Triage (INC-2026-005)
*   **Question:** *"How do you analyze a suspicious email?"*
*   **Response:**
    *   **Situation:** Triaged a user-reported invoice email on the cloud gateway.
    *   **Task:** Identify email authenticity and check for endpoint execution.
    *   **Action:** Validated headers (SPF/DMARC failed). Analyzed a password-protected ZIP containing a malicious `.lnk` shortcut. Traced the process tree in Sentinel (Outlook spawning PowerShell executing an encoded payload).
    *   **Result:** Isolated the host `WKSTN-042` via Defender. Triage proved the payload ran but no credentials were submitted. *Crucial L1 point: Delivery does not mean execution, and execution does not mean compromise. The incident was contained successfully at the execution stage.*

### B. The False Positive & Alert Tuning (INC-2026-004)
*   **Question:** *"Tell me about a time you handled a false positive or tuned an alert."*
*   **Response:**
    *   **Situation:** The SOC queue was hit by an alert storm of 47 OpenVPN authentication failures during a night shift.
    *   **Task:** Determine if this was a credential spray campaign or benign noise.
    *   **Action:** Deduplicated the alerts by IP address and correlated them with change management tickets. Found a matching ticket (CHG-8821) for a geo-block cutover.
    *   **Result:** Resolved the alerts as benign noise, closed the ticket, and filed a tuning request to suppress rule triggers during approved network change windows, preventing future fatigue.

### C. The True Positive Compromise (INC-2026-002)
*   **Question:** *"What do you do if you detect a successful login from a suspicious IP?"*
*   **Response:**
    *   **Situation:** Sentinel detected 18 failed sign-in attempts followed by a single successful login to Exchange Online from an anonymous IP in Romania.
    *   **Task:** Investigate a potential account takeover for a valid finance user (`jsmith`).
    *   **Action:** Validated account activity, checked for post-compromise persistence (e.g. new mailbox forwarding rules, MFA registration updates, OAuth consents), and verified compliant device logs.
    *   **Result:** Confirmed the password spray succeeded. Initiated emergency containment: revoked all Active Sessions, temporarily disabled the account in Entra ID, isolated the user's primary endpoint, and coordinated a helpdesk password reset.

### D. The LOLBin Download Triage (INC-2026-001)
*   **Question:** *"How do you handle an alert for a suspicious system tool downloading files?"*
*   **Response:**
    *   **Situation:** Wazuh and Defender flagged a suspicious BITS job on a user workstation ([WKSTN-042](../incidents/INC-2026-001-bits-job-download.md)) downloading an external file.
    *   **Task:** Determine if this BITS transfer was legitimate administrative activity (like an SCCM patch update) or attacker abuse of a Living-off-the-Land Binary (LOLBin).
    *   **Action:** Compared the alert details against our benign administrative baseline. I noted that the transfer was initiated by `cmd.exe` from a standard user session (`jsmith`) to an unauthorized external IP, whereas legitimate updates are spawned by the SCCM service (`CcmExec.exe`) to trusted domains.
    *   **Result:** Confirmed it was a true positive intrusion. Isolated the host via Defender, quarantined the payload, reset the user's credentials, and escalated to Tier 2 for scope verification.

### E. The Scheduled Task Persistence (INC-2026-003)
*   **Question:** *"How do you investigate a scheduled task alert on an endpoint?"*
*   **Response:**
    *   **Situation:** A custom Wazuh rule flagged a new scheduled task named `ChromeUpdate` configured to execute PowerShell from a user's Local Temp directory.
    *   **Task:** Verify the legitimacy of the task and check if it was an attacker establishing persistence.
    *   **Action:** Compared the task to known-good Google Update baselines (which run from `Program Files` and are signed). I checked the Domain Controller security logs to verify it did not propagate via Group Policy, and performed a comprehensive persistence sweep (checking WMI subscriptions, Registry Run keys, and Startup folders) to ensure no secondary footholds were established.
    *   **Result:** Confirmed it was local to the workstation and malicious. Disabled and deleted the task, quarantined the PowerShell script, and escalated to Tier 2 to verify clean system scans before de-isolating the host.

### F. The RDP Lateral Movement & PCAP Forensics (INC-2026-006)
*   **Question:** *"How do you investigate lateral movement or suspicious port changes?"*
*   **Response:**
    *   **Situation:** Wazuh flagged an evasive registry modification changing the default Remote Desktop Protocol (RDP) port from `3389` to `8443` on a critical finance workstation ([WKSTN-099](../incidents/INC-2026-006-rdp-lateral-movement.md)), followed by the execution of a packet sniffer (`tcpdump.exe`).
    *   **Task:** Trace the lateral path, isolate infected systems, and verify if any sensitive data was captured or exfiltrated.
    *   **Action:** Queried Splunk logs to trace the RDP session back to its origin ([WKSTN-042](../incidents/INC-2026-005-phishing-chain.md)), confirming compromised credentials were used. I immediately isolated both systems. I then recovered the attacker's sniffer packet capture and used `tshark` on the command line to verify DNS query volume and TLS SNI traffic to confirm no sensitive data was exfiltrated.
    *   **Result:** Remediated the registry port change, confirmed no data exfiltration took place, verified no further lateral spread, and returned the sanitized systems to service.

---

## 4. Key Questions to Ask the Interviewer

Show that you care about operations, training, and team structure:

1.  **"How does your team handle alert fatigue and false-positive tuning? Do Tier 1 analysts get to participate in proposing queries or exclusions?"**
    *   *Why:* Connects directly to your INC-2026-004 case and shows you want to make the queue better.
2.  **"What EDR and SIEM consoles will I be working out of on a daily basis? Do you have custom in-house playbooks, or do you follow a standard framework like NIST?"**
    *   *Why:* Shows you are ready to use their tooling and follow established SOPs.
3.  **"What is the escalation path to Tier 2 and IR when I identify a true positive lateral movement or account compromise?"**
    *   *Why:* Shows you know your boundaries as a Tier 1 and want to make handoffs clean.
