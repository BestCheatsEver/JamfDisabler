<#
.SYNOPSIS
    JamfDisabler quick installer for Windows.

.DESCRIPTION
    Downloads the latest stand-alone JamfDisabler.exe from GitHub releases (or
    builds it from source with -Build) and installs it for the current user.
    Nothing is installed as a service, scheduled task or startup entry: it is
    one executable file. Uninstalling = deleting that file.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -Build

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -Dir "C:\Tools"
#>
[CmdletBinding()]
param(
    [string]$Dir = "$env:LOCALAPPDATA\Programs\JamfDisabler",
    [switch]$Build,
    [switch]$AddToPath
)

$ErrorActionPreference = "Stop"
$repo = "BestCheatsEver/JamfDisabler"
$asset = "JamfDisabler-windows-x86_64.exe"
$target = Join-Path $Dir "JamfDisabler.exe"

Write-Host "==> JamfDisabler installer" -ForegroundColor Cyan

if ($Build) {
    Write-Host "==> building from source with PyInstaller"
    python -m pip install --upgrade pyinstaller | Out-Null
    python scripts/build.py --name JamfDisabler
    $source = Join-Path "dist" "JamfDisabler.exe"
} else {
    Write-Host "==> downloading the latest release"
    $url = "https://github.com/$repo/releases/latest/download/$asset"
    $source = Join-Path $env:TEMP $asset
    try {
        Invoke-WebRequest -Uri $url -OutFile $source -UseBasicParsing
    } catch {
        Write-Warning "Download failed ($($_.Exception.Message)). Building from source instead..."
        python -m pip install --upgrade pyinstaller | Out-Null
        python scripts/build.py --name JamfDisabler
        $source = Join-Path "dist" "JamfDisabler.exe"
    }
}

New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Copy-Item -Force $source $target
Unblock-File $target

if ($AddToPath) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$Dir*") {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$Dir", "User")
        Write-Host "==> added $Dir to your user PATH (open a new terminal to use it)"
    }
}

Write-Host ""
Write-Host "==> installed: $target" -ForegroundColor Green
try { & $target --version } catch { }
Write-Host ""
Write-Host "Run it (as Administrator for 'on'/'off'):"
Write-Host "    & '$target' on"
Write-Host "    & '$target' status"
Write-Host "    & '$target' off"
Write-Host ""
Write-Host "Tip: right-click -> Run as administrator also works, and gives you the"
Write-Host "interactive menu with no arguments at all."
