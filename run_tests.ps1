# Run the MinerSentry unit test suite.
# Usage:  powershell -ExecutionPolicy Bypass -File run_tests.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
python -m pytest tests\ -q
