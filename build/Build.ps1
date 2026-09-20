<#
.SYNOPSIS
    Package PSTerm for distribution.

.DESCRIPTION
    PSTerm does not need building to run - the folder is the install, and the
    native core compiles itself on first launch. This script only produces a
    tidy copy for handing to someone else:

      * pre-compiles the core so the first launch on the target machine is
        instant and works with no compiler prerequisites in play,
      * drops development files, caches and any local profile or credential
        data,
      * optionally wraps it in a single .exe.

    Everything here works offline. v1's build script ran Install-Module from
    the gallery when ps2exe was missing, which meant packaging silently
    required internet access and broke the offline promise.

.PARAMETER Output
    Where to write the package. Defaults to dist\PSTerm next to the repository.

.PARAMETER Exe
    Also produce PSTerm.exe. Requires the ps2exe module to be installed already;
    nothing is downloaded.

.PARAMETER Zip
    Also produce a .zip of the package.

.PARAMETER Sign
    Authenticode-sign the shipped .ps1 files. See Sign-PSTerm.ps1.

.EXAMPLE
    .\build\Build.ps1

.EXAMPLE
    .\build\Build.ps1 -Zip
#>
[CmdletBinding()]
param(
    [string]$Output,
    [switch]$Exe,
    [switch]$Zip,
    [switch]$Sign
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
if (-not $Output) { $Output = Join-Path $Root 'dist\PSTerm' }

Write-Host "PSTerm build" -ForegroundColor Cyan
Write-Host ("-" * 50)
Write-Host "Source : $Root"
Write-Host "Output : $Output"

# ---------------------------------------------------------------- stage -----

if (Test-Path -LiteralPath $Output) {
    Remove-Item -LiteralPath $Output -Recurse -Force
}
New-Item -ItemType Directory -Path $Output -Force | Out-Null

# What ships. Anything not listed here stays out, which is why development
# files cannot leak into a package by accident.
$include = @(
    'PSTerm.ps1'
    'PSTerm.cmd'
    'LICENSE'
    'README.md'
)

foreach ($item in $include) {
    $path = Join-Path $Root $item
    if (Test-Path -LiteralPath $path) {
        Copy-Item -LiteralPath $path -Destination $Output -Force
    }
}

# src, minus anything that is not needed at runtime.
Copy-Item -LiteralPath (Join-Path $Root 'src') -Destination $Output -Recurse -Force

$themes = Join-Path $Root 'themes'
if (Test-Path -LiteralPath $themes) {
    Copy-Item -LiteralPath $themes -Destination $Output -Recurse -Force
}

# A package must not carry the packager's own connections or secrets.
New-Item -ItemType Directory -Path (Join-Path $Output 'Profiles') -Force | Out-Null

Write-Host "Staged source files." -ForegroundColor Green

# -------------------------------------------------------------- compile -----

Write-Host "Pre-compiling the native core..."

. (Join-Path $Root 'src\Bootstrap.ps1')
$sw = [System.Diagnostics.Stopwatch]::StartNew()
Initialize-PSTermCore -Root $Output -Force -Verbose:$VerbosePreference
$sw.Stop()

$binDir = Join-Path $Output 'bin'
$built = @(Get-ChildItem -LiteralPath $binDir -Filter '*.dll' -ErrorAction SilentlyContinue)
Write-Host "Compiled in $($sw.ElapsedMilliseconds) ms -> $($built.Count) assembly(ies)." -ForegroundColor Green

# The cache is per PowerShell edition. Only the edition that ran this build is
# present; the other is compiled on first launch, so note it rather than
# pretending both are covered.
Write-Host "  Cached for: $($PSVersionTable.PSEdition) ($($PSVersionTable.PSVersion))" -ForegroundColor DarkGray

# ----------------------------------------------------------------- sign -----

if ($Sign) {
    $signer = Join-Path $PSScriptRoot 'Sign-PSTerm.ps1'
    if (Test-Path -LiteralPath $signer) {
        Write-Host "Signing scripts..."
        & $signer -Path $Output
    }
    else {
        Write-Warning "Sign-PSTerm.ps1 was not found; skipping signing."
    }
}

# ------------------------------------------------------------------ exe -----

if ($Exe) {
    $ps2exe = Get-Module -ListAvailable -Name ps2exe | Select-Object -First 1
    if (-not $ps2exe) {
        Write-Warning @'
The ps2exe module is not installed, so PSTerm.exe was not produced.
Install it once on a machine with internet access:

    Install-Module ps2exe -Scope CurrentUser

Nothing is downloaded by this script, deliberately: PSTerm is meant to build
and run offline. The folder package works without an .exe.
'@
    }
    else {
        Import-Module ps2exe -ErrorAction Stop
        $icon = Join-Path $Root 'src\icon.ico'
        $exePath = Join-Path $Output 'PSTerm.exe'

        $args = @{
            inputFile   = Join-Path $Output 'PSTerm.ps1'
            outputFile  = $exePath
            title       = 'PSTerm'
            description = 'A native PowerShell serial, SSH and Telnet terminal'
            company     = ''
            product     = 'PSTerm'
            version     = '2.0.0.0'
            noConsole   = $true       # it is a GUI application
            STA         = $true       # WinForms requires a single-threaded apartment
            DPIAware    = $true
        }
        if (Test-Path -LiteralPath $icon) { $args['iconFile'] = $icon }

        Invoke-ps2exe @args
        Write-Host "Produced $exePath" -ForegroundColor Green
    }
}

# ------------------------------------------------------------------ zip -----

if ($Zip) {
    $zipPath = "$Output.zip"
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($Output, $zipPath)
    $size = [math]::Round((Get-Item -LiteralPath $zipPath).Length / 1MB, 2)
    Write-Host "Produced $zipPath ($size MB)" -ForegroundColor Green
}

# --------------------------------------------------------------- verify -----

Write-Host ""
Write-Host "Verifying the package..."
$check = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Output 'PSTerm.ps1') -NoWindow
$check | ForEach-Object { Write-Host "  $_" }

if ($LASTEXITCODE -ne 0) {
    throw "The packaged copy failed its own installation check."
}

$total = [math]::Round((Get-ChildItem -LiteralPath $Output -Recurse -File |
    Measure-Object -Property Length -Sum).Sum / 1MB, 2)

Write-Host ""
Write-Host "Done. Package is $total MB." -ForegroundColor Green
Write-Host "Copy the folder anywhere and run PSTerm.cmd." -ForegroundColor Green
