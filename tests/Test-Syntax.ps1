<#
.SYNOPSIS
    Parse every PowerShell file in the repository and report syntax errors.

.DESCRIPTION
    Needs no Windows and no compiled core, so it runs anywhere PowerShell does -
    including a CI job on Linux - and catches a broken script before the longer
    suites would. It parses only; it does not run anything.

.EXAMPLE
    pwsh -NoProfile -File tests/Test-Syntax.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$files = Get-ChildItem -LiteralPath $root -Recurse -File -Include '*.ps1', '*.psm1', '*.psd1' |
    Where-Object { $_.FullName -notmatch '[\\/](\.git|dist|bin)[\\/]' }

$bad = 0
foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)

    if ($errors.Count -gt 0) {
        $bad++
        foreach ($e in $errors) {
            Write-Host ("FAIL  {0}:{1}: {2}" -f $file.FullName.Substring($root.Length + 1), $e.Extent.StartLineNumber, $e.Message) -ForegroundColor Red
        }
    }
}

if ($bad -eq 0) {
    Write-Host "All $(@($files).Count) PowerShell files parse." -ForegroundColor Green
    exit 0
}
Write-Host "$bad file(s) have syntax errors." -ForegroundColor Red
exit 1
