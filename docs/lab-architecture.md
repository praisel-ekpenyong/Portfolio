# SOC Lab Architecture

Controlled environment for Tier 1 analyst training. Attack traffic originates exclusively from **Apache Caldera** operations.

## Network Diagram

```
Internet (simulated) ──► pfSense Firewall ──► 10.10.0.0/24 (DMZ)
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    │                         │                         │
              10.10.10.0/24            10.10.20.0/24            10.10.30.0/24
              (Workstations)           (Servers)                (Security Tools)
                    │                         │                         │
         ┌──────────┴──────────┐    ┌─────────┴─────────┐    ┌─────────┴─────────┐
         │ WKSTN-042  Win10    │    │ SRV-LNX-01 Ubuntu │    │ CALDERA 10.10.30.10│
         │ WKSTN-099  Win10    │    │ SRV-DC-01  AD DS  │    │ WAZUH  10.10.30.20 │
         └─────────────────────┘    └───────────────────┘    │ SPLUNK 10.10.30.30 │
                                                              │ SENTINEL (cloud)   │
                                                              └───────────────────┘
```

## Asset Inventory

| Hostname | IP | OS | Role | Agents / Logging |
|----------|-----|-----|------|------------------|
| CALDERA-SRV | 10.10.30.10 | Ubuntu 22.04 | C2 / emulation | Caldera server |
| WKSTN-042 | 10.10.10.42 | Windows 10 | User workstation | Sysmon, Wazuh, MDE |
| WKSTN-099 | 10.10.10.99 | Windows 10 | Finance user | Sysmon, Wazuh |
| SRV-LNX-01 | 10.10.20.15 | Ubuntu 22.04 | Web/app server | Wazuh, auditd |
| SRV-DC-01 | 10.10.20.10 | Windows Server 2019 | Domain Controller | Windows Events → SIEM |
| WAZUH-SRV | 10.10.30.20 | Ubuntu 22.04 | SIEM (Wazuh) | Wazuh manager |
| SPLUNK-SRV | 10.10.30.30 | Ubuntu 22.04 | SIEM (Splunk) | HF + indexer |

## Log Sources Ingested

| Source | Platform | Key Events |
|--------|----------|------------|
| Microsoft-Windows-Sysmon/Operational | Windows | Process create (1), network (3), DNS (22) |
| Security | Windows / AD | 4624/4625 logon, 4720 account created, 4740 lockout |
| Microsoft Defender for Endpoint | Cloud | Alert stream → Sentinel |
| Azure AD / Entra ID Sign-in Logs | Cloud | Risky sign-in, impossible travel |
| /var/log/auth.log | Linux | SSH auth, sudo |
| auditd | Linux | execve, useradd, crontab |
| pfSense | Firewall | Blocked/allowed flows, VPN logs |
| Zeek / Suricata (optional) | IDS | DNS anomalies, ET rules |

## SIEM Routing

**Option A — Wazuh (open source)**
- Agents on all endpoints → Wazuh manager → Dashboard alerts
- Custom rules in `detections/wazuh/local_rules.xml`

**Option B — Splunk**
- Universal Forwarders → HF → Indexer
- Indexes: `wineventlog`, `sysmon`, `linux`, `network`, `caldera_ops`

**Option C — Microsoft Sentinel**
- AMA + Defender connectors → Log Analytics workspace
- Analytics rules in `detections/sentinel/`

## Caldera Integration Points

1. Deploy **sandcat** agents on WKSTN-042 and SRV-LNX-01 (see `docs/caldera-setup.md`).
2. Tag agents with group `blue-team-lab` for operation filtering.
3. Run adversary profiles documented in `caldera/adversary-profiles.md`.
4. Correlate Caldera operation timestamps with SIEM alert timestamps for validation.

## Firewall / Network Controls

| Rule | Action | Purpose |
|------|--------|---------|
| LAN → CALDERA:8888 | Allow | Agent beaconing (lab only) |
| CALDERA → Internet | Deny | Prevent accidental egress |
| DMZ → DC (LDAP/Kerberos) | Allow | AD auth simulation |
| Any → Splunk 514/9997 | Allow | Log forwarding |

## Isolation & Safety

- Lab VLAN has no route to corporate production.
- Snapshots taken before each Caldera operation.
- Caldera `--insecure` flag used only in lab; credentials rotated after demos.
- Cleanup: stop Caldera operation → verify agent removal → restore VM snapshot if needed.