[CmdletBinding()]
param(
    [string]$PythonCommand = 'python'
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Venv = Join-Path $Root '.venv-build'

if (-not (Test-Path -LiteralPath $Venv)) {
    & $PythonCommand -m venv $Venv
}

$Python = Join-Path $Venv 'Scripts\python.exe'
& $Python -m pip install --upgrade pip
& $Python -m pip install -e "$Root[dev]"
& $Python -m PyInstaller `
    --noconfirm `
    --clean `
    --windowed `
    --onefile `
    --name 'APKBA-Analyzer' `
    --distpath (Join-Path $Root 'dist') `
    --workpath (Join-Path $Root '.pyinstaller-work') `
    --paths (Join-Path $Root 'src') `
    --collect-data androguard `
    --hidden-import androguard.core.apk `
    (Join-Path $Root 'main.py')

Write-Host "Build complete: $Root\dist\APKBA-Analyzer.exe"
