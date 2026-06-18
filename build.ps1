# Build SOC Analyst L1 portfolio artifacts
# Praisel Ekpenyong

$Root = $PSScriptRoot

Write-Host "=== Building SOC Portfolio Artifacts ===" -ForegroundColor Cyan
Write-Host "Analyst: Praisel Ekpenyong`n"

# Install Python deps if needed
$req = Join-Path $Root "scripts\requirements.txt"
if (Test-Path $req) {
    Write-Host "[1/3] Checking Python dependencies..."
    python -c "import requests" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  requests already available."
    } else {
        Write-Host "  Installing Python dependencies..."
        try { pip install -q -r $req } catch { Write-Host "  (pip install failed - install requirements manually)" }
    }
}

# Generate IOC enrichment report
Write-Host "[2/3] Generating IOC enrichment report..."
$iocScript = Join-Path $Root "scripts\ioc_enrichment.py"
$iocInput = Join-Path $Root "scripts\sample_iocs.txt"
$iocOutput = Join-Path $Root "artifacts\enrichment_report.json"
if (Test-Path $iocScript) {
    python $iocScript --input $iocInput --output $iocOutput --delay 0.2
}

# Parse Caldera operations into timeline CSVs
Write-Host "[3/3] Parsing Caldera operation timelines..."
$parser = Join-Path $Root "scripts\caldera_log_parser.py"
if (Test-Path $parser) {
    $operations = @("INC001", "INC003", "INC005")
    foreach ($op in $operations) {
        $report = Join-Path $Root "artifacts\caldera-operation-$op.json"
        $output = Join-Path $Root "artifacts\caldera_timeline_$op.csv"
        if (Test-Path $report) {
            Write-Host "  Parsing $op..."
            python $parser --report $report --output $output
        }
    }
}

Write-Host ""
Write-Host "Build complete." -ForegroundColor Green
Write-Host "Artifacts: artifacts/"
Write-Host "Full docs: README.md"
