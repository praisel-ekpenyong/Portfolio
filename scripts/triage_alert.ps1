<#
.SYNOPSIS
    Tier 1 alert triage helper — gathers host and user context for osTicket internal notes and performs optional network containment.
.PARAMETER Hostname
    Target workstation or server name.
.PARAMETER AlertId
    osTicket ticket number or SIEM alert ID for audit trail.
.PARAMETER IsolateHost
    Switch to trigger emergency network isolation on the remote host via firewall block rules.
.EXAMPLE
    .\triage_alert.ps1 -Hostname WKSTN-042 -AlertId ALT-88421 -IsolateHost
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Hostname,

    [Parameter(Mandatory = $false)]
    [string]$AlertId = "MANUAL-TRIAGE",

    [Parameter(Mandatory = $false)]
    [switch]$IsolateHost
)

$ErrorActionPreference = "SilentlyContinue"
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

Write-Host "=== Tier 1 Triage Package ===" -ForegroundColor Cyan
Write-Host "Alert ID: $AlertId"
Write-Host "Host:     $Hostname"
Write-Host "UTC:      $timestamp"
Write-Host ""

# --- Connectivity Pre-Check ---
Write-Host "Checking connectivity to $Hostname..." -NoNewline
if (-not (Test-Connection -ComputerName $Hostname -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
    Write-Host " FAILED!" -ForegroundColor Red
    Write-Host "Error: Target host $Hostname is unreachable or offline. Triage script aborted." -ForegroundColor Red
    Write-Host ""
    return
}
Write-Host " OK" -ForegroundColor Green
Write-Host ""

# --- Host identity ---
$cs = Get-CimInstance Win32_ComputerSystem -ComputerName $Hostname
$os = Get-CimInstance Win32_OperatingSystem -ComputerName $Hostname
Write-Host "[Host Info]"
Write-Host "  Domain:      $($cs.Domain)"
Write-Host "  Manufacturer:$($cs.Manufacturer) $($cs.Model)"
Write-Host "  Last Boot:   $($os.LastBootUpTime)"
Write-Host ""

# --- Recent failed logons (Security 4625) last 24h ---
$start = (Get-Date).AddHours(-24)
Write-Host "[Failed Logons - Last 24h]"
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4625
    StartTime = $start
} -ComputerName $Hostname -MaxEvents 10 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $user = $xml.Event.EventData.Data | Where-Object Name -eq "TargetUserName" | Select-Object -ExpandProperty '#text'
    Write-Host "  $($_.TimeCreated.ToUniversalTime()) UTC — User: $user"
}
Write-Host ""

# --- Running processes (top 15 by WS) ---
Write-Host "[Top Processes by Memory]"
Get-Process -ComputerName $Hostname | Sort-Object WorkingSet -Descending | Select-Object -First 15 |
    Format-Table Name, Id, @{N = "WS_MB"; E = { [math]::Round($_.WorkingSet / 1MB, 1) } } -AutoSize

# --- Network connections (requires admin on remote host) ---
Write-Host "[Established TCP Connections]"
Get-NetTCPConnection -CimSession $Hostname -State Established -ErrorAction SilentlyContinue |
    Select-Object -First 20 LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
    Format-Table -AutoSize

# --- Local admins ---
Write-Host "[Local Administrators Group]"
Invoke-Command -ComputerName $Hostname -ScriptBlock {
    Get-LocalGroupMember -Group Administrators | Select-Object Name, ObjectClass, PrincipalSource
} -ErrorAction SilentlyContinue | Format-Table -AutoSize

# --- Suspicious LOLBIN quick check ---
$lolbins = @("bitsadmin.exe", "certutil.exe", "mshta.exe", "regsvr32.exe", "powershell.exe")
Write-Host "[LOLBIN Process Check]"
Get-CimInstance Win32_Process -ComputerName $Hostname | Where-Object {
    $lolbins -contains $_.Name.ToLower()
} | Select-Object Name, ProcessId, CommandLine | Format-List

Write-Host ""
Write-Host "Triage complete. Paste output into osTicket #$AlertId internal note." -ForegroundColor Green
Write-Host ""

# --- Emergency Network Isolation ---
if ($IsolateHost) {
    Write-Host "=== Emergency Containment Action ===" -ForegroundColor Yellow
    Write-Host "Triggering network isolation for remote host: $Hostname"
    
    $isolationScript = {
        $ruleName = "SOC_L1_IR_ISOLATION_BLOCK"
        $ruleExists = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        
        if ($ruleExists) {
            return "Host is already isolated via firewall rule '$ruleName'."
        } else {
            # Block all inbound connections
            New-NetFirewallRule -DisplayName $ruleName -Name $ruleName -Direction Inbound -Action Block -Enabled True -Description "Emergency Tier 1 SOC Network Isolation" -ErrorAction SilentlyContinue
            # Block all outbound connections
            New-NetFirewallRule -DisplayName $ruleName -Name $ruleName -Direction Outbound -Action Block -Enabled True -Description "Emergency Tier 1 SOC Network Isolation" -ErrorAction SilentlyContinue
            
            return "Emergency network isolation firewall rules successfully applied to block all inbound and outbound traffic."
        }
    }

    $isolationResult = Invoke-Command -CimSession $Hostname -ScriptBlock $isolationScript -ErrorAction SilentlyContinue
    if ($isolationResult) {
        Write-Host "  Success: $isolationResult" -ForegroundColor Green
    } else {
        # Fallback to WinRM session if CimSession is not configured
        $isolationResult = Invoke-Command -ComputerName $Hostname -ScriptBlock $isolationScript -ErrorAction SilentlyContinue
        if ($isolationResult) {
            Write-Host "  Success (WinRM): $isolationResult" -ForegroundColor Green
        } else {
            Write-Host "  Error: Failed to execute isolation command on remote host. Ensure WinRM/CimSession connectivity and administrator privileges." -ForegroundColor Red
        }
    }
    Write-Host ""
}