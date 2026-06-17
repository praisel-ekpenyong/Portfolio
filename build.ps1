# Build SOC Analyst L1 portfolio artifacts
# Praisel Ekpenyong

$Root = $PSScriptRoot

Write-Host "=== Building SOC Portfolio Artifacts ===" -ForegroundColor Cyan
Write-Host "Analyst: Praisel Ekpenyong`n"

# Install Python deps if needed
$req = Join-Path $Root "scripts\requirements.txt"
if (Test-Path $req) {
    Write-Host "[1/3] Installing Python dependencies..."
    try { pip install -q -r $req } catch { Write-Host "  (pip skipped - requests may already be installed)" }
}

# Generate IOC enrichment report
Write-Host "[2/3] Generating IOC enrichment report..."
$iocScript = Join-Path $Root "scripts\ioc_enrichment.py"
$iocInput = Join-Path $Root "scripts\sample_iocs.txt"
$iocOutput = Join-Path $Root "artifacts\enrichment_report.json"
if (Test-Path $iocScript) {
    python $iocScript --input $iocInput --output $iocOutput --delay 0.2
}

# Parse Caldera operation into timeline CSV
Write-Host "[3/3] Parsing Caldera operation timeline..."
$parser = Join-Path $Root "scripts\caldera_log_parser.py"
$calderaReport = Join-Path $Root "artifacts\caldera-operation-INC001.json"
$timelineOut = Join-Path $Root "artifacts\caldera_timeline_INC001.csv"
if ((Test-Path $parser) -and (Test-Path $calderaReport)) {
    python $parser --report $calderaReport --output $timelineOut
}

Write-Host ""
Write-Host "Build complete." -ForegroundColor Green
Write-Host "Artifacts: artifacts/"
Write-Host "Full docs: README.md"