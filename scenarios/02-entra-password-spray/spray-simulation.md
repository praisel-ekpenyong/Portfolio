# Lab Password Spray Simulation (INC-2026-002)

Controlled script used to generate Entra `SigninLogs` entries for analytics validation. **Lab use only.**

## Objective

Produce 15+ failed sign-ins followed by one successful authentication for `jsmith@corp.lab` from external IP `203.0.113.55`.

## Prerequisites

- Test account `jsmith@corp.lab` in `pe-soc-lab` tenant
- Spray host outside corp network (or lab VM with NAT)
- Sentinel rule `password_spray_entra.kql` deployed

## Example (PowerShell — lab red-team host)

```powershell
# INC-2026-002 validation only — do not run against production tenants
$User = "jsmith@corp.lab"
$Endpoint = "https://login.microsoftonline.com/<tenant-id>/oauth2/token"
$BadPass = "WrongPassword-$(Get-Random)"
$GoodPass = "<lab-known-password>"

1..18 | ForEach-Object {
    # Simulate failed auth — in lab, use Graph test harness or documented spray tool
    Write-Host "[$_] Failed attempt simulated"
    Start-Sleep -Seconds (Get-Random -Minimum 20 -Maximum 40)
}

# Final successful auth triggers Entra risky sign-in
Write-Host "Successful auth simulated at $(Get-Date -Format u)"
```

## Validation

1. Sentinel incident #2863 (or equivalent) fires within 5 minutes
2. Entra ID Protection shows risky sign-in for `jsmith@corp.lab`
3. Complete triage per [`INC-2026-002`](../incidents/INC-2026-002-entra-password-spray.md)

## Pair With

[INC-2026-004](../../incidents/INC-2026-004-false-positive-vpn.md) — same T1110 family, false positive when usernames are invalid and no success occurs.