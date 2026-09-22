#Requires -Version 5.1
<#
.SYNOPSIS
    Publish VXRecon to the npm registry.

.DESCRIPTION
    A guided, safe publish helper. It:

      1. Checks Node.js and npm are available.
      2. Logs you in to npm if you are not already (browser-based login).
      3. Runs a dry-run so you can review the exact file set and size.
      4. Publishes with public access.
      5. Verifies the package is visible on the registry.

    Nothing is published until you confirm, and the dry-run shows exactly what
    will be uploaded first.

.PARAMETER SkipLogin
    Do not run `npm login` (use when you are already authenticated).

.PARAMETER Yes
    Skip the interactive confirmation prompt.

.PARAMETER DryRun
    Perform the dry-run and stop (no publish).

.PARAMETER Tag
    npm dist-tag to publish under (default: latest).

.PARAMETER Access
    Access level: public | restricted (default: public).

.EXAMPLE
    .\publish.ps1
    .\publish.ps1 -Yes
    .\publish.ps1 -DryRun

.NOTES
    You must run this yourself; npm authentication requires your own account
    (and possibly 2FA), which cannot be automated on your behalf.
#>
[CmdletBinding()]
param(
    [switch]$SkipLogin,
    [switch]$Yes,
    [switch]$DryRun,
    [string]$Tag = "latest",
    [ValidateSet("public", "restricted")]
    [string]$Access = "public"
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location -LiteralPath $root

function Require-Command([string]$name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Write-Host "[!] '$name' is required but was not found on PATH." -ForegroundColor Red
        Write-Host "    Install Node.js from https://nodejs.org/ and retry." -ForegroundColor Red
        exit 3
    }
}

Write-Host ""
Write-Host "VXRecon npm publisher" -ForegroundColor Green -BackgroundColor Black
Write-Host "=====================" -ForegroundColor DarkGreen
Write-Host ""

Require-Command "node"
Require-Command "npm"

# -- package summary ---------------------------------------------------------
$pkg = Get-Content -LiteralPath (Join-Path $root "package.json") -Raw | ConvertFrom-Json
Write-Host "[i] package : $($pkg.name)" -ForegroundColor Cyan
Write-Host "[i] version : $($pkg.version)" -ForegroundColor Cyan
Write-Host "[i] registry: $(npm config get registry)" -ForegroundColor Cyan
Write-Host ""

# -- login -------------------------------------------------------------------
$loggedIn = $false
try {
    $who = (npm whoami 2>$null)
    if ($LASTEXITCODE -eq 0 -and $who) {
        Write-Host "[+] already logged in as: $who" -ForegroundColor Green
        $loggedIn = $true
    }
} catch { }

if (-not $loggedIn -and -not $SkipLogin -and -not $DryRun) {
    Write-Host "[i] Not logged in. Starting npm login (browser-based)..." -ForegroundColor Yellow
    Write-Host "    A browser window/tab will open; complete the login there." -ForegroundColor Yellow
    Write-Host ""
    npm login --auth-type=web
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] npm login failed. Re-run this script once logged in." -ForegroundColor Red
        exit 3
    }
} elseif (-not $loggedIn -and $DryRun) {
    Write-Host "[i] Not logged in, but -DryRun does not require authentication." -ForegroundColor Yellow
}

# -- dry-run preview ---------------------------------------------------------
Write-Host ""
Write-Host "[i] Previewing the files to be published (dry-run)..." -ForegroundColor Cyan
npm publish --dry-run --access $Access --tag $Tag
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Dry-run failed. Fix the issues above before publishing." -ForegroundColor Red
    exit 1
}

if ($DryRun) {
    Write-Host ""
    Write-Host "[+] Dry-run complete. Nothing was published (-DryRun)." -ForegroundColor Green
    exit 0
}

# -- confirm -----------------------------------------------------------------
if (-not $Yes) {
    Write-Host ""
    $answer = Read-Host "Publish $($pkg.name)@$($pkg.version) to npm now? (y/N)"
    if ($answer -notmatch '^(y|yes)$') {
        Write-Host "[i] Cancelled. Nothing was published." -ForegroundColor Yellow
        exit 0
    }
}

# -- publish -----------------------------------------------------------------
Write-Host ""
Write-Host "[i] Publishing..." -ForegroundColor Cyan
npm publish --access $Access --tag $Tag
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Publish failed. Common causes:" -ForegroundColor Red
    Write-Host "    - name already taken -> use a scope, e.g. @youruser/vxrecon" -ForegroundColor Red
    Write-Host "    - email not verified  -> verify it at https://www.npmjs.com/" -ForegroundColor Red
    Write-Host "    - 2FA required        -> add --otp=<code> or enable automation token" -ForegroundColor Red
    exit 1
}

# -- verify ------------------------------------------------------------------
Write-Host ""
Write-Host "[i] Verifying on the registry..." -ForegroundColor Cyan
Start-Sleep -Seconds 3
$published = (npm view "$($pkg.name)" version 2>$null)
if ($LASTEXITCODE -eq 0 -and $published) {
    Write-Host "[+] Published: $($pkg.name)@$published" -ForegroundColor Green
    Write-Host "    https://www.npmjs.com/package/$($pkg.name)" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next (optional): enable live npm badges in README.md by removing the" -ForegroundColor Gray
    Write-Host "<!-- --> comment around the dynamic badges, then commit and push." -ForegroundColor Gray
} else {
    Write-Host "[!] Publish returned success but the registry lookup failed." -ForegroundColor Yellow
    Write-Host "    It may take a minute to propagate. Check:" -ForegroundColor Yellow
    Write-Host "    https://www.npmjs.com/package/$($pkg.name)" -ForegroundColor Yellow
}
