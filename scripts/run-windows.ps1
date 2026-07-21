[CmdletBinding()]
param(
    [string]$PythonCommand = 'python'
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $Python)) {
    & $PythonCommand -m venv (Join-Path $Root '.venv')
    & $Python -m pip install -e $Root
}
& $Python (Join-Path $Root 'main.py')
