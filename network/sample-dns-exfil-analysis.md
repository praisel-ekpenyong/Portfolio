# Practice Exercise: DNS Query Anomaly (Not a Closed Incident)

> **Operational status:** Supplementary drill only — no `INC-####` record. Use after Caldera **T1-Phish-to-Host** if HTTP beacon abilities generate periodic DNS, or for Splunk/Sentinel tuning practice.

## Scenario

Splunk notable: `index=dns` reports workstation `WKSTN-042` sent 200 queries in 5 minutes to `*.update-check.azureedge-live.com` with 52-character subdomains.

## Tier 1 Investigation Steps

### 1. Validate Alert

```spl
index=dns src_host=WKSTN-042
| stats count by query
| eval qlen=len(query)
| where qlen > 45
| sort - count
```

### 2. Wireshark Filter (if PCAP available)

```
dns.qry.name contains "azureedge-live"
```

### 3. Enrichment

| IOC | Type | Result |
|-----|------|--------|
| `update-check.azureedge-live.com` | Domain | Registered 3 days ago — suspicious |
| Subdomain pattern | Encoding | Base32-like labels |

Run:

```bash
python scripts/ioc_enrichment.py -i network/sample_dns_iocs.txt -o dns_enrich.json
```

### 4. MITRE Mapping

**T1071.004 — Application Layer Protocol: DNS**

### 5. Tier 1 Actions

1. Isolate host (if not already from parent incident)
2. Block domain at DNS firewall
3. Escalate to T2 for payload decode
4. Link to Caldera operation if lab

## Key Takeaway

DNS tunneling often appears as **volume + length** anomalies before threat intel catches the domain. Tier 1 job is pattern recognition and fast containment, not full decode.

## Production Transfer

In a production SOC, this same workflow applies to any DNS anomaly alert:

1. **Pattern match** — High query volume + long subdomain labels (>40 chars) + recently registered parent domain = probable tunneling.
2. **Correlate** — Link the querying host to any open endpoint or identity incidents (DNS exfil is often a later-stage TTP).
3. **Contain** — Block the parent domain at DNS firewall / sinkhole before escalating — this stops data loss while Tier 2 decodes the payload.
4. **Document** — Record query sample, domain age, subdomain encoding pattern, and querying user/host in the ticket. Tier 2 needs this to assess data exposure.