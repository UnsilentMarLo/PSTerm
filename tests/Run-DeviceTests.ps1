<#
.SYNOPSIS
    Tests for driving devices from code: DeviceSession, the drivers and the safe-apply and
    backup helpers - against a simulated IOS device, so no hardware is needed.

.DESCRIPTION
    Run-LabTests.ps1 repeats the important ones against real switches.

.EXAMPLE
    powershell -NoProfile -File tests\Run-DeviceTests.ps1
#>
[CmdletBinding()]
param([switch]$FailFast)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'src\Bootstrap.ps1')
Initialize-PSTermCore -Root $root
foreach ($f in 'Settings', 'Secrets', 'Profiles', 'Store', 'Connect', 'Device') { . (Join-Path $root "src\$f.ps1") }

$core = [PSTerm.Vt.TerminalEmulator].Assembly.Location
Add-Type -ReferencedAssemblies (@(Get-PSTermReferences) + $core) -Path (Join-Path $PSScriptRoot 'Fixtures\FakeIosDevice.cs')

$script:Passed = 0; $script:Failed = 0
$script:Failures = New-Object System.Collections.Generic.List[string]

function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try { & $Body; $script:Passed++; Write-Host "  PASS  $Name" -ForegroundColor DarkGreen }
    catch {
        $script:Failed++
        $msg = "  FAIL  $Name`n        $($_.Exception.Message)"
        $script:Failures.Add($msg); Write-Host $msg -ForegroundColor Red
        if ($FailFast) { throw }
    }
}
function Assert-True { param($Condition, [string]$Because = '') if (-not $Condition) { throw "expected true: $Because" } }
function Assert-Equal { param($Expected, $Actual, [string]$Because = '') if ($Expected -ne $Actual) { throw "expected '$Expected' but got '$Actual' $Because" } }

function New-Device {
    param([switch]$Login, [switch]$Open)
    $device = New-Object FakeIosDevice
    if ($Login) { $device.RequireLoginPassword = $true }
    $driver = Get-PSTermDriver -Name 'cisco-ios'
    $session = New-Object PSTerm.Automation.DeviceSession($device, $driver, [PSTerm.Vt.TerminalEncoding]::Utf8)
    $session.Connect()
    if ($Open) {
        $problem = $session.Open($null, $(if ($Login) { 'loginpw' } else { $null }), 'enablepw', $true, 10000)
        if ($problem) { throw "setup: $problem" }
    }
    [pscustomobject]@{ Device = $device; Session = $session }
}

Write-Host "`nPSTerm device tests" -ForegroundColor Cyan
Write-Host ("-" * 60)

Write-Host "`nDrivers" -ForegroundColor Yellow

Test-Case 'the Cisco driver loads and carries its patterns' {
    $d = Get-PSTermDriver -Name 'cisco-ios'
    Assert-Equal 'cisco-ios' $d.Name
    Assert-True ('lab-sw#' -match $d.PromptPattern) 'a privileged prompt did not match'
    Assert-True ('lab-sw(config-if)#' -match $d.PromptPattern) 'a config prompt did not match'
    Assert-True ('% Invalid input' -match $d.ErrorPattern) 'the error pattern'
    Assert-Equal 'terminal length 0' $d.DisablePagerCommand
}

Test-Case 'an unknown driver is refused by name' {
    $failed = $false
    try { [void](Get-PSTermDriver -Name 'no-such-vendor') } catch { $failed = $_.Exception.Message -match 'no-such-vendor' }
    Assert-True $failed 'no clear error'
}

Write-Host "`nLogin" -ForegroundColor Yellow

Test-Case 'logs in, enters privileged mode and knows the mode from the prompt' {
    $t = New-Device -Login -Open
    Assert-Equal 'Privileged' $t.Session.Mode
    Assert-Equal 'sw1#' $t.Session.Prompt
    Assert-Equal 'loginpw|enable|enablepw' ($t.Device.Sent -join '|')
    $t.Session.Dispose()
}

Test-Case 'a refused password is reported and is not tried again' {
    $t = New-Device -Login
    $problem = $t.Session.Open($null, 'wrong', 'enablepw', $true, 8000)
    Assert-True ($problem -match 'refused') "problem: '$problem'"
    Assert-Equal 1 @($t.Device.Sent).Count 'the password was sent more than once'
    $t.Session.Dispose()
}

Test-Case 'a login that asks for a password nobody supplied says so' {
    $t = New-Device -Login
    $problem = $t.Session.Open($null, $null, $null, $false, 8000)
    Assert-True ($problem -match 'none is saved') "problem: '$problem'"
    $t.Session.Dispose()
}

Write-Host "`nRunning commands" -ForegroundColor Yellow

Test-Case 'a command returns its output without the echo or the prompt' {
    $t = New-Device -Open
    $r = $t.Session.Invoke('show version', 8000)
    Assert-True $r.Succeeded 'not successful'
    Assert-Equal 2 $r.Lines.Count "lines: $($r.Lines -join ' | ')"
    Assert-True ($r.Lines[0] -like 'Cisco IOS*') $r.Lines[0]
    Assert-Equal 'sw1#' $r.Prompt
    $t.Session.Dispose()
}

Test-Case 'a refused command is reported as an error, with the device''s words' {
    $t = New-Device -Open
    $r = $t.Session.Invoke('show nonsense there', 8000)
    $r = $t.Session.Invoke('frobnicate', 8000)
    Assert-True (-not $r.Succeeded) 'reported success'
    Assert-True ($r.Error -match 'Invalid input') $r.Error
    $t.Session.Dispose()
}

Test-Case 'the pager is answered, and neither it nor the erase debris reach the output' {
    $t = New-Device -Open
    $t.Device.PageLength = 24
    $r = $t.Session.Invoke('show running-config', 20000)
    Assert-True $r.Succeeded "timedOut=$($r.TimedOut)"
    Assert-True ($r.Text -notmatch 'More') 'the pager prompt is in the output'
    Assert-Equal 'Building configuration...' $r.Lines[0]
    Assert-Equal 'end' $r.Lines[-1]
    Assert-Equal 85 $r.Lines.Count 'every line, once'
    $t.Session.Dispose()
}

Test-Case 'a command that never finishes returns what there is, flagged, instead of hanging' {
    $t = New-Device -Open
    $t.Device.Hostname = 'sw1'
    $started = [Diagnostics.Stopwatch]::StartNew()
    # The device is told to stay silent after the echo by leaving it in a question state.
    $null = $t.Session.Invoke('reload in 5', 300)
    Assert-True ($started.ElapsedMilliseconds -lt 6000) 'it did not give up'
    $t.Session.Dispose()
}

Test-Case 'a console message that follows the prompt does not hide it' {
    $t = New-Device -Open
    $null = $t.Session.Invoke('reload cancel', 8000)
    Start-Sleep -Milliseconds 400                 # the banner arrives after the prompt
    Assert-Equal 'sw1#' $t.Session.Prompt
    $r = $t.Session.Invoke('show version', 8000)
    Assert-True $r.Succeeded 'the next command failed after the banner'
    $t.Session.Dispose()
}

Test-Case 'a log message that arrives without a redrawn prompt does not stop the next command' {
    $t = New-Device -Open
    $t.Device.Syslog('Nov 17 15:00:00.000: %LINK-3-UPDOWN: Interface Gi0/1, changed state to up', $false)
    Start-Sleep -Milliseconds 300
    $r = $t.Session.Invoke('show version', 10000)
    Assert-True $r.Succeeded "timedOut=$($r.TimedOut)"
    $t.Session.Dispose()
}

Write-Host "`nApplying configuration" -ForegroundColor Yellow

Test-Case 'a dry run sends nothing' {
    $t = New-Device -Open
    $before = @($t.Device.Sent).Count
    $r = Send-PSTermConfig -Session $t.Session -Line @('hostname x', 'interface gi0/1') -DryRun
    Assert-Equal $before @($t.Device.Sent).Count
    Assert-Equal 2 @($r.Sent).Count
    $t.Session.Dispose()
}

Test-Case 'configuration is applied, and the session ends outside configuration mode' {
    $t = New-Device -Open
    $r = Send-PSTermConfig -Session $t.Session -Line @('interface gi0/1', 'description uplink')
    Assert-Equal 2 $r.Applied
    Assert-True ($null -eq $r.Failed) 'a line failed'
    Assert-Equal 'Privileged' $t.Session.Mode
    $t.Session.Dispose()
}

Test-Case 'the first refused line stops the run and later lines are not sent' {
    $t = New-Device -Open
    $r = Send-PSTermConfig -Session $t.Session -Line @('interface gi0/1', 'bogus thing', 'description never')
    Assert-Equal 1 $r.Applied
    Assert-Equal 'bogus thing' $r.Failed
    Assert-True ($t.Device.Sent -notcontains 'description never') 'a line after the failure was sent'
    $t.Session.Dispose()
}

Test-Case 'safe apply: the timer is armed, answers "no" to saving, and is cancelled when the change is fine' {
    $t = New-Device -Open
    $t.Device.Dirty = $true                         # unsaved changes make IOS ask "Save?"
    $r = Send-PSTermConfig -Session $t.Session -Line @('interface gi0/1', 'description ok') -Safe -RollbackMinutes 3 -Verify { $true }
    Assert-Equal 2 $r.Applied
    Assert-True (-not $r.RolledBack) 'rolled back'
    Assert-True (-not $t.Device.ReloadArmed) 'the timer was left running'
    Assert-True ($t.Device.Sent -contains 'no') 'the save question was not answered no'
    Assert-True ($t.Device.Sent -notcontains 'yes') 'saved without being asked to'
    $t.Session.Dispose()
}

Test-Case 'safe apply: when the way in is gone the timer is left running' {
    $t = New-Device -Open
    $r = Send-PSTermConfig -Session $t.Session -Line @('hostname broken') -Safe -RollbackMinutes 1 -Verify { $false }
    Assert-True $r.RolledBack 'not reported'
    Assert-True $t.Device.ReloadArmed 'the timer was cancelled'
    $t.Session.Dispose()
}

Test-Case 'safe apply: a refused line cancels the timer, since the device is plainly still there' {
    $t = New-Device -Open
    $r = Send-PSTermConfig -Session $t.Session -Line @('bogus') -Safe -RollbackMinutes 2
    Assert-Equal 'bogus' $r.Failed
    Assert-True (-not $t.Device.ReloadArmed) 'the timer was left running'
    $t.Session.Dispose()
}

Test-Case '-Save writes the configuration only after a clean, verified change' {
    $t = New-Device -Open
    $r = Send-PSTermConfig -Session $t.Session -Line @('hostname renamed') -Safe -Verify { $true } -Save
    Assert-True $r.Saved 'not saved'
    Assert-True (-not $t.Device.Dirty) 'the device still reports unsaved changes'
    $t.Session.Dispose()

    $t = New-Device -Open
    $r = Send-PSTermConfig -Session $t.Session -Line @('bogus') -Save
    Assert-True (-not $r.Saved) 'a failed change was saved'
    $t.Session.Dispose()
}

Test-Case 'a session that is not in privileged mode refuses to configure' {
    $t = New-Device
    Start-Sleep -Milliseconds 400
    $failed = $false
    try { [void](Send-PSTermConfig -Session $t.Session -Line @('hostname x')) } catch { $failed = $_.Exception.Message -match 'privileged' }
    Assert-True $failed 'it carried on in user mode'
    $t.Session.Dispose()
}

Write-Host "`nPasting into a console" -ForegroundColor Yellow

function New-PasteSession {
    $device = New-Object FakeIosDevice
    $term = New-Object PSTerm.Vt.TerminalEmulator(120, 40, 1000)
    $sink = New-Object PSTerm.EmulatorSink($term)
    $session = New-Object PSTerm.TerminalSession($device, $sink, $term, (New-Object PSTerm.Vt.StreamDecoder([PSTerm.Vt.TerminalEncoding]::Utf8)))
    $session.Connect()
    Start-Sleep -Milliseconds 400
    [pscustomobject]@{ Device = $device; Session = $session }
}

function Wait-NotPacing($session, [int]$ms = 20000) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($session.IsPacing -and $sw.ElapsedMilliseconds -lt $ms) { Start-Sleep -Milliseconds 50 }
    Start-Sleep -Milliseconds 300
}

Test-Case 'a paced paste holds the next line back until a slow command has finished' {
    $t = New-PasteSession
    $t.Session.SendPaced("show version`rslow`rshow version`r")
    Wait-NotPacing $t.Session
    $sent = @($t.Device.Sent)
    Assert-Equal 'show version|slow|show version' ($sent -join '|')
    $gap = $t.Device.ReceivedTicks[2] - $t.Device.ReceivedTicks[1]
    Assert-True ($gap -ge 1300) "the line behind a 1.5 s command followed after only $gap ms"
    $t.Session.Dispose()
}

Test-Case 'an unpaced paste sends the lines at once (the contrast)' {
    $t = New-PasteSession
    $t.Session.Send("show version`rslow`rshow version`r")
    Start-Sleep -Milliseconds 600
    $gap = $t.Device.ReceivedTicks[2] - $t.Device.ReceivedTicks[1]
    Assert-True ($gap -lt 500) "gap was $gap ms"
    $t.Session.Dispose()
}

Test-Case 'every line of a paced paste arrives, once and in order' {
    $t = New-PasteSession
    $block = (1..25 | ForEach-Object { "show version $_" }) -join "`r"
    $t.Session.SendPaced($block + "`r")
    Wait-NotPacing $t.Session
    $expected = (1..25 | ForEach-Object { "show version $_" }) -join '|'
    Assert-Equal $expected (@($t.Device.Sent) -join '|')
    $t.Session.Dispose()
}

Test-Case 'a paced paste can be stopped, and stops after the line in flight' {
    $t = New-PasteSession
    $t.Session.SendPaced((1..8 | ForEach-Object { 'slow' }) -join "`r")
    Start-Sleep -Milliseconds 400
    $t.Session.CancelPaced()
    Wait-NotPacing $t.Session 8000
    Assert-True (-not $t.Session.IsPacing) 'still pacing'
    Assert-True (@($t.Device.Sent).Count -lt 8) "all $(@($t.Device.Sent).Count) lines went out"
    $t.Session.Dispose()
}

Test-Case 'text without a line break is sent as it is' {
    $t = New-PasteSession
    $t.Session.SendPaced('show')
    Start-Sleep -Milliseconds 300
    Assert-True (-not $t.Session.IsPacing) 'a single line started a paced run'
    $t.Session.Dispose()
}

Write-Host "`nConfiguration copies" -ForegroundColor Yellow

$dir = Join-Path ([System.IO.Path]::GetTempPath()) ("psterm-backup-" + [guid]::NewGuid().ToString('N'))
try {
    Test-Case 'a backup leaves out the lines that change by themselves' {
        $t = New-Device -Open
        $config = @(Get-PSTermRunningConfig -Session $t.Session)
        Assert-True (-not ($config -match '^Building configuration')) 'a volatile line was kept'
        Assert-True (-not ($config -match '^Current configuration')) 'a volatile line was kept'
        Assert-True ($config -contains 'hostname sw1') 'the configuration is missing'
        $t.Session.Dispose()
    }

    Test-Case 'two backups: no change is reported as none, a change as exactly what moved' {
        $t = New-Device -Open
        $first = Save-PSTermConfigBackup -Session $t.Session -Folder $dir -Name 'sw1'
        Assert-True (Test-Path -LiteralPath $first.Path) 'no file written'
        Assert-True ($null -eq $first.Previous) 'a first backup claims a predecessor'
        Start-Sleep -Milliseconds 1100                # file names carry the second
        $same = Save-PSTermConfigBackup -Session $t.Session -Folder $dir -Name 'sw1'
        Assert-True (-not $same.Changed) "reported a change: +$($same.Added.Count) -$($same.Removed.Count)"
        $null = Send-PSTermConfig -Session $t.Session -Line @('hostname sw1-new')
        Start-Sleep -Milliseconds 1100
        $changed = Save-PSTermConfigBackup -Session $t.Session -Folder $dir -Name 'sw1'
        Assert-True $changed.Changed 'the change was not seen'
        Assert-True ($changed.Added -contains 'hostname sw1-new') "added: $($changed.Added -join ' | ')"
        Assert-True ($changed.Removed -contains 'hostname sw1') "removed: $($changed.Removed -join ' | ')"
        $t.Session.Dispose()
    }

    Test-Case 'a name that is not a legal file name is made into one' {
        $t = New-Device -Open
        $b = Save-PSTermConfigBackup -Session $t.Session -Folder $dir -Name 'core/sw:1'
        Assert-True (Test-Path -LiteralPath $b.Path) 'no file'
        $t.Session.Dispose()
    }
}
finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host ("-" * 60)
$total = $script:Passed + $script:Failed
if ($script:Failed -eq 0) { Write-Host "All $total device tests passed." -ForegroundColor Green; exit 0 }
Write-Host "$($script:Failed) of $total device tests FAILED." -ForegroundColor Red
Write-Host ""
foreach ($f in $script:Failures) { Write-Host $f -ForegroundColor Red }
exit 1
