# Apache Caldera Lab Setup

Caldera drives endpoint scenarios (INC-2026-001, 003, 005). Identity and noise cases (INC-2026-002, 004) use lab scripts or organic telemetry — this guide covers Caldera install and agent deployment.

## Requirements

- Ubuntu 22.04 VM (8 GB RAM, 2 vCPU minimum)
- Python 3.9+
- Target VMs: Windows 10 + Ubuntu 22.04 with outbound access to Caldera on TCP 8888

## Install Caldera Server

```bash
git clone https://github.com/apache/caldera.git --recursive
cd caldera
pip3 install -r requirements.txt
python3 server.py --insecure
```

Default UI: `http://10.10.30.10:8888` — credentials `red` / `admin` (change in lab).

## Deploy Sandcat Agents

### Windows (WKSTN-042)

From Caldera UI → **Agents** → **Deploy Agent** → platform `windows`:

```powershell
$server="http://10.10.30.10:8888"
$url="$server/file/download"
$wc=New-Object System.Net.WebClient
$wc.Headers.add("platform","windows")
$wc.Headers.add("file","sandcat.go")
$data=$wc.DownloadData($url)
$name=$wc.ResponseHeaders["Content-Disposition"].Substring(
  $wc.ResponseHeaders["Content-Disposition"].IndexOf("filename=")+9
).Replace('"','')
Get-Process | Where-Object {$_.Modules.FileName -like "C:\Users\Public\$name.exe"} | Stop-Process -Force
Remove-Item -Force "C:\Users\Public\$name.exe" -ErrorAction SilentlyContinue
[IO.File]::WriteAllBytes("C:\Users\Public\$name.exe",$data)
Start-Process -FilePath "C:\Users\Public\$name.exe" -ArgumentList "-server $server -group blue-team-lab" -WindowStyle Hidden
```

### Linux (SRV-LNX-01)

```bash
server="http://10.10.30.10:8888"
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" $server/file/download > sandcat
chmod +x sandcat
./sandcat -server $server -group blue-team-lab -v
```

Verify agents show **ALIVE** in Caldera UI before running operations.

## Recommended Plugins

| Plugin | Purpose |
|--------|---------|
| `stockpile` | Default TTP library (abilities) |
| `emu` | MITRE emulation plans |
| `sandcat` | Go-based agent |
| `compass` | ATT&CK visualizer |
| `response` | Basic blue-team response actions |

Enable in `conf/local.yml` or via UI **Configuration → Plugins**.

## Pre-Operation Checklist (Tier 1 Analyst)

- [ ] Note operation start time (UTC) for timeline correlation
- [ ] Confirm SIEM ingestion lag < 2 minutes
- [ ] Snapshot target VM (optional)
- [ ] Open osTicket from template (`templates/ticket-triage.md`)
- [ ] Identify expected MITRE techniques from adversary profile

## Post-Operation Cleanup

1. Stop operation in Caldera UI.
2. Allow cleanup abilities to run on operation stop (e.g., remove dropped files).
3. Verify no sandcat process remains:
   - Windows: `Get-Process sandcat*`
   - Linux: `pgrep -a sandcat`
4. Document operation ID and link to incident record.

## Correlating Caldera with SIEM

Export operation JSON from Caldera **Operations → Reports** and parse with:

```bash
python scripts/caldera_log_parser.py --report operation_report.json --output timeline.csv
```

Match `ability_id` and `finished_timestamp` to SIEM alert `_time` fields.