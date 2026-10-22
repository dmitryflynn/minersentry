# Build MinerSentry into a single standalone Windows .exe.
# Usage:  powershell -ExecutionPolicy Bypass -File build.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Building MinerSentry.exe ..." -ForegroundColor Cyan
python -m PyInstaller --noconfirm --onefile --windowed `
    --name MinerSentry `
    --collect-all psutil `
    --exclude-module numpy --exclude-module pandas `
    main.py

if (Test-Path ".\dist\MinerSentry.exe") {
    Write-Host "`nBuilt: $PSScriptRoot\dist\MinerSentry.exe" -ForegroundColor Green
    Get-Item ".\dist\MinerSentry.exe" | Select-Object Name,@{n='MB';e={[math]::Round($_.Length/1MB,1)}}
} else {
    Write-Host "Build failed - MinerSentry.exe not found in dist\" -ForegroundColor Red
    exit 1
}
