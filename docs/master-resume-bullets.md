# Master Resume Bullets: SOC Analyst L1

These bullets follow the requested format: **2-3 keywords** + **how they were used** + **where (system/product/team/client/industry)** + **non-technical why (simple, plain impact)**, rewritten to be completely free of metrics, numbers, percentages, or quantifiable claims.

---

### Phishing & Email Security

* **Phishing triage** + **email headers** + **cloud email gateway**  
  Analyzed suspicious user reports using **phishing triage** and checked **email headers** on the **cloud email gateway**, verifying sender authenticity so we could block scam messages before employees got tricked.

* **Defender for Endpoint** + **endpoint correlation** + **process tree**  
  Traced a bad file click using **Defender for Endpoint** for **endpoint correlation** on a **finance team workstation**, checking the process tree and documenting lab isolation criteria before escalation.

* **Phishing triage** + **mailbox scope** + **incident response**  
  Reviewed phishing evidence during **phishing triage** to determine **mailbox scope** across the **lab email tenant**, identifying other recipients so containment could happen before more users clicked.

---

### Identity & Cloud Security

* **Password spray** + **Entra ID** + **incident queue**  
  Triaged identity alerts by looking for **password spray** patterns in **Entra ID** logs on the **cloud incident queue**, documenting lab session-revocation and password-reset steps after a valid-user success.

* **Logon audit** + **MFA method** + **Microsoft Sentinel**  
  Checked compromised accounts using a post-auth **logon audit** and verified the user's **MFA method** in **Microsoft Sentinel**, looking for new forwarding rules or permission changes so we knew whether persistence remained.

---

### Endpoint & LOLBin Security

* **Wazuh** + **Sysmon** + **process monitoring**  
  Spotted malicious file downloads using **Wazuh** and **Sysmon** for **process monitoring** on the **workstation fleet**, checking if normal Windows tools were running unusual commands so we could separate safe admin activity from real threats.

* **Incident response** + **host isolation** + **remediation**  
  Practiced **incident response** steps in the lab, documenting **host isolation** through **Defender for Endpoint** and **remediation** checks so Tier 2 could review a complete handoff.

---

### Persistence & Baseline Auditing

* **Scheduled task** + **persistence check** + **Domain Controller**  
  Audited suspicious startup files and **scheduled task** settings during a **persistence check** on a **finance team workstation**, verifying the task did not exist on the **Domain Controller** so we could prove the threat was stuck on just one machine.

* **Persistence check** + **active directory** + **baseline audit**  
  Conducted a thorough **persistence check** by comparing registry run keys, startup files, and **active directory** user groups to our **baseline audit** on the **finance team VLAN**, confirming the attacker did not leave any other hidden ways to get back into our network.

---

### Detection Tuning & Noise Reduction

* **False positive** + **change management** + **Sentinel**  
  Solved a loud login alert by matching it to a **change management** ticket in the **firewall log queue**, identifying the event as a harmless **false positive** so that we could reduce alert noise on VPN logins.

* **KQL queries** + **Sentinel** + **rule validation**  
  Rewrote search rules using **KQL queries** in **Microsoft Sentinel** and performed **rule validation** on the **VPN log source**, narrowing the trigger window after network updates to cut down on alert noise.

---

### SOC Automation, Scripting & Ticketing

* **Python script** + **IOC enrichment** + **threat intelligence**  
  Built an automated **Python script** to perform **IOC enrichment** by classifying lab indicators locally and supporting public **threat intelligence** lookups so that we could reduce manual lookup times during busy shifts.

* **PowerShell script** + **automated triage** + **ticketing**  
  Wrote an automated **PowerShell script** to gather system memory logs and network connections for **automated triage** on the **internal network segment**, formatting the results for the **ticketing** queue so that the team could acknowledge alerts faster.

* **Post-incident documentation** + **ticketing** + **incident response lifecycle**  
  Logged incident logs and timelines using **post-incident documentation** on our **ticketing** platform, tracking cases through the whole **incident response lifecycle** so the team had a clean paper trail for security audits.

---

### Adversary Emulation & Alert Validation

* **Caldera** + **MITRE ATT&CK** + **alert testing**  
  Simulated adversary behavior with **Caldera** using **MITRE ATT&CK** maps in a **test lab environment**, checking if alerts fired correctly during **alert testing** so detection gaps were easier to find.

---

### Linux & Network Supplemental Operations

* **Linux logs** + **user audit** + **persistence checks**  
  Investigated server logins using **Linux logs** and conducted a **user audit** on a **critical database server**, removing unauthorized cron tasks and fake admin accounts so attackers could not maintain sneak access to our systems.

* **Wireshark** + **Splunk** + **network flow**  
  Analyzed network packet logs with **Wireshark** and **Splunk** during a lateral movement test on the **finance workstation segment**, tracing RDP connection paths and checking the **network flow** using SPL (Search Processing Language) so we could prove no sensitive data was copied off the network.

* **Network analysis** + **Wireshark** + **PCAP interpretation**  
  Conducted **network analysis** and examined packet capture files using **Wireshark** for **PCAP interpretation** on the **company web server segment**, looking at TCP/IP and HTTP/HTTPS headers so we could trace where bad traffic was coming from.

* **DNS analysis** + **firewalls** + **network security**  
  Monitored network queries for **DNS analysis** and reviewed log data on **firewalls** for the **office workstation network**, identifying suspicious domains early so command-and-control patterns were easier to investigate.
