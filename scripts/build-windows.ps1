[CmdletBinding()]
param(
    [string]$PythonCommand = 'python'
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Venv = Join-Path $Root '.venv-build'
$AdbCommand = Get-Command 'adb.exe' -ErrorAction SilentlyContinue
$Adb = if ($null -ne $AdbCommand) { $AdbCommand.Source } else { $null }
if ([string]::IsNullOrWhiteSpace($Adb)) {
    foreach ($SdkRoot in @(
        $env:ANDROID_SDK_ROOT,
        $env:ANDROID_HOME,
        (Join-Path $env:LOCALAPPDATA 'Android\Sdk')
    )) {
        if ([string]::IsNullOrWhiteSpace($SdkRoot)) { continue }
        $Candidate = Join-Path $SdkRoot 'platform-tools\adb.exe'
        if (Test-Path -LiteralPath $Candidate -PathType Leaf) {
            $Adb = $Candidate
            break
        }
    }
}
if ([string]::IsNullOrWhiteSpace($Adb)) {
    throw 'adb.exe was not found. Install official Android Platform Tools before building.'
}
$PlatformTools = Split-Path -Parent $Adb
$AdbWinApi = Join-Path $PlatformTools 'AdbWinApi.dll'
$AdbWinUsbApi = Join-Path $PlatformTools 'AdbWinUsbApi.dll'
foreach ($RequiredFile in @($Adb, $AdbWinApi, $AdbWinUsbApi)) {
    if (-not (Test-Path -LiteralPath $RequiredFile -PathType Leaf)) {
        throw "Required Platform Tools file is missing: $RequiredFile"
    }
}

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
    --add-binary "$Adb;platform-tools" `
    --add-binary "$AdbWinApi;platform-tools" `
    --add-binary "$AdbWinUsbApi;platform-tools" `
    (Join-Path $Root 'main.py')

Write-Host "Build complete: $Root\dist\APKBA-Analyzer.exe"
