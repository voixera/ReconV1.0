#Requires -Version 5.1
<#
.SYNOPSIS
    Install VXRecon so `vxrecon` (and the `vx` alias) work from anywhere.

.DESCRIPTION
    A tiny, transparent installer. It:

      1. Finds a Python >= 3.11 interpreter.
      2. Performs an editable install (`pip install -e .`) so the `vxrecon`
         console script lands on PATH.
      3. Optionally creates a `vx` shortcut command.
      4. Optionally installs the `[full]` extras for richer DNS/image support.

    Nothing is downloaded from a private server; the only network use is pip
    fetching optional public dependencies if you ask for them.

.PARAMETER Full
    Install the optional extras (dnspython, Pillow, beautifulsoup4,
    cryptography).

.PARAMETER Shortcut
    Also create a `vx` command as a short alias for `vxrecon`.

.PARAMETER User
    Perform a user-level install (`pip install --user`) instead of a
    virtualenv/system install.

.EXAMPLE
    .\install.ps1
    .\install.ps1 -Full -Shortcut
#>
[CmdletBinding()]
param(
    [switch]$Full,
    [switch]$Shortcut,
    [switch]$User
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

function Find-Python {
    foreach ($name in @('python', 'python3', 'py')) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) {
            try {
                $ver = & $cmd.Source -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
                if ($LASTEXITCODE -eq 0 -and [version]$ver -ge [version]'3.11') {
                    return $cmd.Source
                }
            } catch { }
        }
    }
    return $null
}

$python = Find-Python
if (-not $python) {
    Write-Host "[!] Python 3.11+ is required. https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 3
}
Write-Host "[i] Using interpreter: $python" -ForegroundColor Cyan

$pipArgs = @('-m', 'pip', 'install', '-e', '.')
if ($User) { $pipArgs = @('-m', 'pip', 'install', '--user', '-e', '.') }

Push-Location $scriptDir
try {
    if ($Full) {
        Write-Host "[i] Installing with [full] extras..." -ForegroundColor Cyan
        # Editable install with extras.
        $extraArgs = if ($User) { @('-m', 'pip', 'install', '--user', '-e', '.[full]') }
                     else       { @('-m', 'pip', 'install', '-e', '.[full]') }
        & $python @extraArgs
    } else {
        Write-Host "[i] Installing VXRecon (core)..." -ForegroundColor Cyan
        & $python @pipArgs
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Installation failed." -ForegroundColor Red
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}

# Verify the console script resolves.
$vx = Get-Command vxrecon -ErrorAction SilentlyContinue
if ($vx) {
    Write-Host "[+] Installed. 'vxrecon' is available:" -ForegroundColor Green
    Write-Host "    $($vx.Source)" -ForegroundColor Gray
} else {
    Write-Host "[i] VXRecon installed, but 'vxrecon' is not on PATH yet." -ForegroundColor Yellow
    Write-Host "    The pip Scripts directory may need to be added to PATH." -ForegroundColor Yellow
}

if ($Shortcut) {
    $scriptsDir = & $python -c "import sysconfig; print(sysconfig.get_path('scripts'))"
    $vxPath = Join-Path $scriptsDir 'vx.cmd'
    @'
@echo off
vxrecon %*
'@ | Set-Content -Path $vxPath -Encoding ASCII
    Write-Host "[+] Created 'vx' shortcut: $vxPath" -ForegroundColor Green
}

Write-Host ""
Write-Host "Try it:" -ForegroundColor Cyan
Write-Host "    vxrecon doctor" -ForegroundColor Gray
Write-Host "    vxrecon menu" -ForegroundColor Gray
