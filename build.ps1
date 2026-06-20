# Build SOC Analyst L1 portfolio artifacts
# Praisel Ekpenyong

$Root = $PSScriptRoot

Write-Host "=== Building SOC Portfolio Artifacts ===" -ForegroundColor Cyan
Write-Host "Analyst: Praisel Ekpenyong`n"

# Ensure artifacts directory exists
$ArtifactsDir = Join-Path $Root "artifacts"
if (-not (Test-Path $ArtifactsDir)) {
    New-Item -ItemType Directory -Path $ArtifactsDir -Force | Out-Null
}

# Install Python deps if needed
$req = Join-Path $Root "scripts\requirements.txt"
if (Test-Path $req) {
    Write-Host "[1/3] Checking Python dependencies..."
    python -c "import requests, pytest" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Required dependencies already available."
    } else {
        Write-Host "  Installing Python dependencies from requirements.txt..."
        pip install -q -r $req
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  WARNING: pip install failed. Please install dependencies manually." -ForegroundColor Yellow
        }
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

# Parse Caldera operations into timeline CSVs dynamically
Write-Host "[3/3] Parsing Caldera operation timelines..."
$parser = Join-Path $Root "scripts\caldera_log_parser.py"
if (Test-Path $parser) {
    # Dynamically find all operation JSON files
    $opFiles = Get-ChildItem (Join-Path $ArtifactsDir "caldera-operation-*.json") -ErrorAction SilentlyContinue
    if ($opFiles.Count -eq 0) {
        Write-Host "  No Caldera operation files found in artifacts/."
    } else {
        foreach ($file in $opFiles) {
            # Extract operation ID (e.g. INC001) from filename
            if ($file.BaseName -match "caldera-operation-(.+)") {
                $op = $Matches[1]
                $output = Join-Path $ArtifactsDir "caldera_timeline_$op.csv"
                Write-Host "  Parsing $op..."
                python $parser --report $file.FullName --output $output
            }
        }
    }
}

Write-Host ""
Write-Host "Build complete." -ForegroundColor Green
Write-Host "Artifacts: artifacts/"
Write-Host "Full docs: README.md"
