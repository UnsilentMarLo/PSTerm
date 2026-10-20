<#
.SYNOPSIS
    Run every PSTerm test suite.

.DESCRIPTION
    Runs each suite in its own PowerShell process. That matters: the native core
    is compiled into the process and cannot be unloaded, so sharing one process
    between suites would hide a bug in the compile-and-cache path.

.PARAMETER BothEditions
    Also run everything under the other PowerShell edition, if it is installed.
    The core compiles against different reference assemblies on each, so a change
    can easily build on one and not the other.

.EXAMPLE
    powershell -NoProfile -File tests\Run-AllTests.ps1 -BothEditions
#>
[CmdletBinding()]
param([switch]$BothEditions)

Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$suites = @(
    @{ Name = 'Core';        Path = Join-Path $PSScriptRoot 'Run-Tests.ps1' }
    @{ Name = 'Profiles';    Path = Join-Path $PSScriptRoot 'Run-ProfileTests.ps1' }
    @{ Name = 'Integration'; Path = Join-Path $PSScriptRoot 'Run-IntegrationTests.ps1' }
)

function Get-Hosts {
    $result = @()
    $windowsPowerShell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $windowsPowerShell) {
        $result += @{ Name = 'Windows PowerShell 5.1'; Exe = $windowsPowerShell }
    }
    $pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue)
    if ($pwsh) { $result += @{ Name = 'PowerShell 7'; Exe = $pwsh.Source } }
    $result
}

$hosts = if ($BothEditions) { Get-Hosts } else {
    @(@{ Name = "$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
         Exe  = (Get-Process -Id $PID).Path })
}

$failed = 0
$ran = 0

foreach ($h in $hosts) {
    Write-Host ""
    Write-Host ("=" * 64) -ForegroundColor Cyan
    Write-Host " $($h.Name)" -ForegroundColor Cyan
    Write-Host ("=" * 64) -ForegroundColor Cyan

    foreach ($suite in $suites) {
        $ran++
        & $h.Exe -NoProfile -ExecutionPolicy Bypass -File $suite.Path | Out-Null
        $code = $LASTEXITCODE

        if ($code -eq 0) {
            Write-Host ("  {0,-14} PASS" -f $suite.Name) -ForegroundColor Green
        }
        else {
            $failed++
            Write-Host ("  {0,-14} FAIL  (exit {1})" -f $suite.Name, $code) -ForegroundColor Red
            # Re-run so the actual failures are visible, rather than a bare code.
            & $h.Exe -NoProfile -ExecutionPolicy Bypass -File $suite.Path 2>&1 |
                Select-String -Pattern 'FAIL' | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
        }
    }
}

Write-Host ""
Write-Host ("=" * 64)
if ($failed -eq 0) {
    Write-Host "All $ran suite run(s) passed." -ForegroundColor Green
    exit 0
}
Write-Host "$failed of $ran suite run(s) FAILED." -ForegroundColor Red
exit 1
