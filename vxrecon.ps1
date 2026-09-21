#Requires -Version 5.1
<#
.SYNOPSIS
    VXRecon launcher - run VXRecon like `npx vxrecon` from a source checkout.

.DESCRIPTION
    Locates a suitable Python interpreter, verifies the package imports, then
    forwards all arguments to `vxrecon.ui.cli:main`. This lets you run VXRecon
    without `python vxrecon.py` and without installing anything:

        .\vxrecon.ps1 doctor
        .\vxrecon.ps1 dns example.com --json

    If a globally installed `vxrecon` command exists on PATH, this script
    prefers it; otherwise it launches the local source tree.

.PARAMETER Args
    Any arguments are passed straight through to the VXRecon CLI.

.EXAMPLE
    .\vxrecon.ps1
    .\vxrecon.ps1 recon example.com
    .\vxrecon.ps1 compare example-a.com example-b.com --json

.NOTES
    Privacy-first: this launcher makes no network calls of its own. It only
    starts the local VXRecon process.
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# --- 1. Prefer a globally installed console script if present --------------
$globalCmd = Get-Command vxrecon -ErrorAction SilentlyContinue
if ($globalCmd -and $globalCmd.Source -and ($globalCmd.Source -ne $PSCommandPath)) {
    & $globalCmd.Source @Args
    exit $LASTEXITCODE
}

# --- 2. Find a Python interpreter ------------------------------------------
function Resolve-Python {
    $candidates = @('python', 'python3', 'py')
    foreach ($name in $candidates) {
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

$python = Resolve-Python
if (-not $python) {
    Write-Host "[!] VXRecon requires Python 3.11 or newer." -ForegroundColor Yellow
    Write-Host "    Install it from https://www.python.org/downloads/ and retry." -ForegroundColor Yellow
    exit 3
}

# --- 3. Verify the package is importable from the source tree --------------
Push-Location $scriptDir
try {
    & $python -c "import vxrecon" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[i] Local package not found; attempting an editable install..." -ForegroundColor Cyan
        & $python -m pip install -e . --quiet --disable-pip-version-check
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[!] Could not install VXRecon. Run manually:" -ForegroundColor Yellow
            Write-Host "    $python -m pip install -e ." -ForegroundColor Yellow
            exit 3
        }
    }

    # --- 4. Launch the CLI, forwarding all arguments -----------------------
    & $python -m vxrecon @Args
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
