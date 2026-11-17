<#
.SYNOPSIS
    The device checks, repeated against real switches. Opt-in: needs hardware.

.DESCRIPTION
    Not part of Run-AllTests.ps1. It expects two Cisco IOS switches on serial ports, the
    first reachable over the network by SSH, set up as the lab was:

        core  (serial -CorePort, SSH at -CoreAddress)   local user -User, enable secret
        edge  (serial -EdgePort)                        same enable secret

    Passwords are parameters (or the environment variables PSTERM_LAB_PASSWORD and
    PSTERM_LAB_ENABLE) so they are not kept in the repository.

    It changes only things it puts back: a description on Vlan1, and a few VLANs. It does
    not reload either switch.

.EXAMPLE
    $env:PSTERM_LAB_PASSWORD = '...'; $env:PSTERM_LAB_ENABLE = '...'
    powershell -NoProfile -STA -File tests\Run-LabTests.ps1
#>
[CmdletBinding()]
param(
    [string]$CorePort = 'COM4',
    [string]$EdgePort = 'COM5',
    [string]$CoreAddress = '192.168.77.1',
    [string]$User = 'labadmin',
    [string]$Password = $env:PSTERM_LAB_PASSWORD,
    [string]$EnableSecret = $env:PSTERM_LAB_ENABLE
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $Password -or -not $EnableSecret) { throw 'Give -Password and -EnableSecret, or set PSTERM_LAB_PASSWORD and PSTERM_LAB_ENABLE.' }

$root = Split-Path -Parent $PSScriptRoot
Add-Type -AssemblyName System.Windows.Forms
. (Join-Path $root 'src\Bootstrap.ps1')
Initialize-PSTermCore -Root $root
foreach ($f in 'Settings', 'Secrets', 'Profiles', 'Store', 'Connect', 'Device') { . (Join-Path $root "src\$f.ps1") }
[void](Test-PSTermDpapiAvailable)

$script:Passed = 0; $script:Failed = 0
$script:Failures = New-Object System.Collections.Generic.List[string]
function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try { & $Body; $script:Passed++; Write-Host "  PASS  $Name" -ForegroundColor DarkGreen }
    catch { $script:Failed++; $m = "  FAIL  $Name`n        $($_.Exception.Message)"; $script:Failures.Add($m); Write-Host $m -ForegroundColor Red }
}
function Assert-True { param($Condition, [string]$Because = '') if (-not $Condition) { throw "expected true: $Because" } }

$sandbox = Join-Path ([System.IO.Path]::GetTempPath()) ("psterm-lab-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $sandbox 'Profiles') -Force | Out-Null
$store = [pscustomobject]@{ version = 2; folders = @(); pinned = @(); credentials = @(); profiles = @() }
[void](Set-PSTermCredential -Store $store -Root $sandbox -Name 'lab login' -Username $User -Secret $Password)
[void](Set-PSTermCredential -Store $store -Root $sandbox -Name 'lab enable' -Secret $EnableSecret)

function Open-Serial($port) {
    $p = New-PSTermProfile -Name $port -Type 'Serial'; $p.serial.portName = $port
    Connect-PSTermDevice -Profile $p -Store $store -Root $sandbox -EnableCredential 'lab enable' -Enter
}
function Open-Ssh {
    $p = New-PSTermProfile -Name 'core ssh' -Type 'SSH'; $p.ssh.host = $CoreAddress; $p.ssh.allowLegacyAlgorithms = $true
    $p.ssh.extraOptions = @("UserKnownHostsFile=$(Join-Path $sandbox 'known_hosts')")
    Connect-PSTermDevice -Profile $p -Store $store -Root $sandbox -Credential 'lab login' -AcceptHostKey
}

Write-Host "`nPSTerm lab tests" -ForegroundColor Cyan
Write-Host ("-" * 60)

try {
    Write-Host "`nSerial consoles" -ForegroundColor Yellow
    foreach ($port in $CorePort, $EdgePort) {
        Test-Case "$port logs in, enters privileged mode and runs a command" {
            $s = Open-Serial $port
            try {
                Assert-True ($s.Mode -eq 'Privileged') "mode: $($s.Mode)"
                $r = Invoke-PSTermCommand $s 'show version | include uptime'
                Assert-True ($r.Succeeded -and $r.Lines.Count -eq 1 -and $r.Lines[0] -match 'uptime') "got: $($r.Lines -join ' | ')"
            }
            finally { Disconnect-PSTermDevice $s }
        }
        Test-Case "$port reports a refused command as an error" {
            $s = Open-Serial $port
            try { Assert-True (-not (Invoke-PSTermCommand $s 'show nonsense').Succeeded) 'it succeeded' }
            finally { Disconnect-PSTermDevice $s }
        }
        Test-Case "$port answers the pager and returns the whole configuration" {
            $s = Open-Serial $port
            try {
                $null = Invoke-PSTermCommand $s 'terminal length 24'
                $r = Invoke-PSTermCommand $s 'show running-config' -TimeoutSec 90
                $null = Invoke-PSTermCommand $s 'terminal length 0'
                Assert-True ($r.Succeeded -and $r.Text -notmatch 'More' -and $r.Lines[-1] -eq 'end') "ok=$($r.Succeeded) last='$($r.Lines[-1])'"
            }
            finally { Disconnect-PSTermDevice $s }
        }
    }

    Write-Host "`nSSH" -ForegroundColor Yellow
    Test-Case 'SSH shows the same configuration as the serial console' {
        $a = Open-Serial $CorePort
        try { $serial = @(Get-PSTermRunningConfig -Session $a) } finally { Disconnect-PSTermDevice $a }
        $b = Open-Ssh
        try { $ssh = @(Get-PSTermRunningConfig -Session $b) } finally { Disconnect-PSTermDevice $b }
        $diff = @(Compare-Object -ReferenceObject $serial -DifferenceObject $ssh)
        Assert-True ($diff.Count -eq 0) "$($diff.Count) differences, first: $(if ($diff) { $diff[0].InputObject })"
    }
    Test-Case 'CDP on the core lists the edge switch' {
        $s = Open-Ssh
        try { Assert-True ((Invoke-PSTermCommand $s 'show cdp neighbors').Text -match 'CMICR|edge') 'no neighbour' }
        finally { Disconnect-PSTermDevice $s }
    }

    Write-Host "`nSafe apply (edge)" -ForegroundColor Yellow
    Test-Case 'a healthy change is kept and the timer is cancelled' {
        $s = Open-Serial $EdgePort
        try {
            $r = Send-PSTermConfig -Session $s -Line @('interface vlan 1', 'description psterm-lab-test') -Safe -RollbackMinutes 3 -Verify { $true }
            Assert-True ($r.Applied -eq 2 -and -not $r.RolledBack) "applied=$($r.Applied)"
            Assert-True ((Invoke-PSTermCommand $s 'show reload').Text -match 'No reload is scheduled') 'a reload is still scheduled'
            Assert-True ((Invoke-PSTermCommand $s 'show running-config interface vlan 1').Text -match 'psterm-lab-test') 'the change is not there'
        }
        finally {
            $null = Send-PSTermConfig -Session $s -Line @('interface vlan 1', 'no description')
            Disconnect-PSTermDevice $s
        }
    }
    Test-Case 'a refused line stops the run and cancels the timer' {
        $s = Open-Serial $EdgePort
        try {
            $r = Send-PSTermConfig -Session $s -Line @('interface vlan 1', 'description first', 'bogus command', 'description never') -Safe -RollbackMinutes 3
            Assert-True ($r.Failed -eq 'bogus command' -and $r.Applied -eq 2) "failed='$($r.Failed)' applied=$($r.Applied)"
            Assert-True ((Invoke-PSTermCommand $s 'show reload').Text -match 'No reload is scheduled') 'a reload is still scheduled'
            Assert-True ((Invoke-PSTermCommand $s 'show running-config interface vlan 1').Text -notmatch 'never') 'a line after the failure was applied'
        }
        finally {
            $null = Send-PSTermConfig -Session $s -Line @('interface vlan 1', 'no description')
            Disconnect-PSTermDevice $s
        }
    }
}
finally { Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host ("-" * 60)
$total = $script:Passed + $script:Failed
if ($script:Failed -eq 0) { Write-Host "All $total lab tests passed." -ForegroundColor Green; exit 0 }
Write-Host "$($script:Failed) of $total lab tests FAILED." -ForegroundColor Red
foreach ($f in $script:Failures) { Write-Host $f -ForegroundColor Red }
exit 1
