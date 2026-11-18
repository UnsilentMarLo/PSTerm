# A session factory for the plugin host's worker threads: a simulated switch that replays
# output captured from real switches (tests\Fixtures\ios). The device is also kept where the
# test can look at what it was sent: [AppDomain]::CurrentDomain.GetData('psterm-test-device-<name>').
function New-FakeSwitchFactoryText {
    param([Parameter(Mandatory)][string]$FixtureDir, [string]$Mutate = '', [int]$Delay = 0, [string]$FailFor = '')
    $fx = $FixtureDir
@"
param(`$Profile, `$Login, `$Driver)
`$name = [string]`$Profile.name
if (`$name -eq '$FailFor') { throw 'simulated connection failure' }
`$fx = '$fx'
`$d = New-Object FakeIosDevice
`$d.Hostname = `$name
`$d.CannedDelayMs = $Delay
`$prefix = if (`$name -like '*edge*') { 'lab-edge' } else { 'lab-core' }
`$map = @{
    'show version' = "`$prefix-show-version.txt"; 'show inventory' = "`$prefix-show-inventory.txt"
    'show interfaces' = "`$prefix-show-interfaces.txt"; 'show interfaces status' = "`$prefix-show-interfaces-status.txt"
    'show cdp neighbors detail' = "`$prefix-show-cdp-detail.txt"; 'show processes cpu | include CPU' = "`$prefix-show-processes-cpu.txt"
    'show memory statistics' = "`$prefix-show-memory.txt"
    'show interfaces transceiver' = 'synthetic-show-transceiver.txt'; 'show lldp neighbors detail' = 'synthetic-show-lldp-detail.txt'
}
foreach (`$k in `$map.Keys) {
    `$t = [System.IO.File]::ReadAllText((Join-Path `$fx `$map[`$k]))
    $Mutate
    `$d.Canned[`$k] = `$t
}
[AppDomain]::CurrentDomain.SetData('psterm-test-device-' + `$name, `$d)
`$s = New-Object PSTerm.Automation.DeviceSession(`$d, `$Driver, [PSTerm.Vt.TerminalEncoding]::Utf8)
`$s.Connect()
`$problem = `$s.Open(`$null, `$null, 'enablepw', `$true, 10000)
if (`$problem) { throw `$problem }
`$s.DisablePager()
`$s
"@
}
