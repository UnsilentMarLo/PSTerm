<#
.SYNOPSIS
    Tests for the plugin host, the device parsers, the topology drawing and the built-in
    plugins - against a simulated device that replays output captured from real switches.

.EXAMPLE
    powershell -NoProfile -File tests\Run-PluginTests.ps1
#>
[CmdletBinding()]
param([switch]$FailFast)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'src\Bootstrap.ps1')
Initialize-PSTermCore -Root $root
foreach ($f in 'Settings', 'Secrets', 'Profiles', 'Store', 'Connect', 'Device', 'DeviceParsers', 'Topology', 'Plugins') { . (Join-Path $root "src\$f.ps1") }
[void](Test-PSTermDpapiAvailable)

$core = [PSTerm.Vt.TerminalEmulator].Assembly.Location
Add-Type -ReferencedAssemblies (@(Get-PSTermReferences) + $core) -Path (Join-Path $PSScriptRoot 'Fixtures\FakeIosDevice.cs')
$fx = Join-Path $PSScriptRoot 'Fixtures\ios'

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
function Lines($name) { @(Get-Content -LiteralPath (Join-Path $fx $name) -Encoding UTF8) }

$sandbox = Join-Path ([System.IO.Path]::GetTempPath()) ("psterm-plug-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $sandbox 'Profiles') -Force | Out-Null
$store = [pscustomobject]@{ version = 2; folders = @(); pinned = @(); credentials = @(); profiles = @() }

. (Join-Path $PSScriptRoot 'Fixtures\New-FakeSwitchFactory.ps1')
function New-FactoryText {
    param([string]$Mutate = '', [int]$Delay = 0, [string]$FailFor = '')
    New-FakeSwitchFactoryText -FixtureDir $fx -Mutate $Mutate -Delay $Delay -FailFor $FailFor
}
function New-Targets { param([string[]]$Name) @($Name | ForEach-Object { New-PSTermProfile -Name $_ -Type 'Telnet' }) }
function Get-Builtin { param([string]$Id) Get-PSTermPlugin -Root $sandbox -Id $Id | Select-Object -First 1 }
function Sent($name) { @(([AppDomain]::CurrentDomain.GetData('psterm-test-device-' + $name)).Sent) }

Write-Host "`nPSTerm plugin tests" -ForegroundColor Cyan
Write-Host ("-" * 60)

try {
    Write-Host "`nParsers (output captured from real switches)" -ForegroundColor Yellow

    Test-Case 'show version' {
        $v = ConvertFrom-PSTermIosVersion (Lines 'lab-core-show-version.txt')
        Assert-Equal 'lab-core' $v.Hostname; Assert-Equal '15.2(7)E3' $v.Version; Assert-Equal 'WS-C3560CX-8PC-S' $v.Model
        Assert-True ($v.Serial -like 'FOC*') "serial '$($v.Serial)'"; Assert-Equal 'power-on' $v.LastReload
        Assert-True ($v.Image -like 'flash:*') 'image'
    }
    Test-Case 'show inventory' {
        $i = @(ConvertFrom-PSTermIosInventory (Lines 'lab-edge-show-inventory.txt'))
        Assert-Equal 1 $i.Count; Assert-Equal 'CMICR-4PS' $i[0].Pid; Assert-Equal 'V01' $i[0].Vid
    }
    Test-Case 'show interfaces: state, speed, duplex and counters' {
        $all = @(ConvertFrom-PSTermIosInterfaces (Lines 'lab-core-show-interfaces.txt'))
        Assert-Equal 13 $all.Count
        $g1 = $all | Where-Object { $_.Interface -eq 'GigabitEthernet0/1' }
        Assert-Equal 'up' $g1.Protocol; Assert-Equal 'connected' $g1.Detail; Assert-Equal 'Full' $g1.Duplex; Assert-Equal '1000Mb/s' $g1.Speed
        Assert-True ($g1.InPackets -gt 0) 'packets'
        $g2 = $all | Where-Object { $_.Interface -eq 'GigabitEthernet0/2' }
        Assert-Equal 'down' $g2.Status; Assert-Equal 'notconnect' $g2.Detail
        $v1 = $all | Where-Object { $_.Interface -eq 'Vlan1' }
        Assert-Equal '192.168.77.1/24' $v1.Address
    }
    Test-Case 'show interfaces: counters on a line with errors' {
        $text = @('GigabitEthernet0/5 is up, line protocol is up (connected)', '  Description: uplink to dist', '  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX',
            '  Last clearing of "show interface" counters 1d02h', '  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 14',
            '     120 packets input, 9000 bytes, 0 no buffer', '     3 runts, 2 giants, 0 throttles', '     9 input errors, 7 CRC, 0 frame, 0 overrun, 0 ignored',
            '     0 output errors, 4 collisions, 1 interface resets')
        $i = @(ConvertFrom-PSTermIosInterfaces $text)[0]
        Assert-Equal 7 $i.Crc; Assert-Equal 9 $i.InErrors; Assert-Equal 14 $i.OutDrops; Assert-Equal 4 $i.Collisions; Assert-Equal 2 $i.Giants
        Assert-Equal 'uplink to dist' $i.Description; Assert-Equal '1d02h' $i.LastCleared
    }
    Test-Case 'show interfaces transceiver: columns, N/A and alarm marks' {
        $t = @(ConvertFrom-PSTermIosTransceiver (Lines 'synthetic-show-transceiver.txt'))
        Assert-Equal 3 $t.Count
        Assert-Equal 'Gi1/0/25' $t[0].Port; Assert-Equal -6.8 $t[0].RxPower; Assert-Equal 32.5 $t[0].Temperature
        Assert-Equal -26.7 $t[1].RxPower; Assert-Equal '--' $t[1].RxPowerFlag
        Assert-True ($null -eq $t[2].RxPower) 'N/A is null'
    }
    Test-Case 'a device without transceiver data gives no rows' {
        Assert-Equal 0 @(ConvertFrom-PSTermIosTransceiver @('Diagnostic Monitoring is not implemented.')).Count
    }
    Test-Case 'CDP and LLDP neighbours' {
        $c = @(ConvertFrom-PSTermIosCdp (Lines 'lab-core-show-cdp-detail.txt'))
        Assert-Equal 1 $c.Count; Assert-Equal 'lab-edge.lab.local' $c[0].RemoteDevice; Assert-Equal 'GigabitEthernet0/10' $c[0].LocalPort
        Assert-Equal 'GigabitEthernet1/0/1' $c[0].RemotePort; Assert-Equal '192.168.77.2' $c[0].RemoteIp; Assert-Equal 'CMICR-4PS' $c[0].Platform
        $l = @(ConvertFrom-PSTermIosLldp (Lines 'synthetic-show-lldp-detail.txt'))
        Assert-Equal 1 $l.Count; Assert-Equal 'dist-1.example.net' $l[0].RemoteDevice; Assert-Equal 'Gi0/10' $l[0].RemotePort; Assert-Equal '10.1.1.9' $l[0].RemoteIp
    }
    Test-Case 'CPU, memory and interface status' {
        $cpu = ConvertFrom-PSTermIosCpu (Lines 'lab-core-show-processes-cpu.txt'); Assert-Equal 20 $cpu.Cpu5m
        $mem = ConvertFrom-PSTermIosMemory (Lines 'lab-core-show-memory.txt'); Assert-True ($mem.UsedPercent -gt 10 -and $mem.UsedPercent -lt 20) "used $($mem.UsedPercent)"
        $ports = @(ConvertFrom-PSTermIosInterfaceStatus (Lines 'lab-core-show-interfaces-status.txt'))
        Assert-Equal 12 $ports.Count; Assert-Equal 'connected' $ports[0].Status; Assert-Equal 'a-full' $ports[0].Duplex; Assert-Equal 'Gi0/10' $ports[9].Port
    }
    Test-Case 'port and device names are made comparable' {
        Assert-Equal 'Gi0/10' (Get-PSTermShortPort 'GigabitEthernet0/10'); Assert-Equal 'Te1/1/1' (Get-PSTermShortPort 'TenGigabitEthernet1/1/1')
        Assert-Equal 'Po3' (Get-PSTermShortPort 'Port-channel3'); Assert-Equal 'lab-core' (Get-PSTermShortName 'lab-core.lab.local'); Assert-Equal '10.0.0.1' (Get-PSTermShortName '10.0.0.1')
    }

    Write-Host "`nTopology" -ForegroundColor Yellow

    $rows = @(
        [pscustomobject]@{ Device = 'lab-core'; Protocol = 'CDP'; LocalPort = 'GigabitEthernet0/10'; RemoteDevice = 'lab-edge.lab.local'; RemotePort = 'GigabitEthernet1/0/1'; RemoteIp = '192.168.77.2'; Platform = 'CMICR-4PS' }
        [pscustomobject]@{ Device = 'lab-edge'; Protocol = 'CDP'; LocalPort = 'GigabitEthernet1/0/1'; RemoteDevice = 'lab-core.lab.local'; RemotePort = 'GigabitEthernet0/10'; RemoteIp = '192.168.77.1' }
        [pscustomobject]@{ Device = 'lab-edge'; Protocol = 'LLDP'; LocalPort = 'Gi1/0/1'; RemoteDevice = 'lab-core'; RemotePort = 'Gi0/10' }
        [pscustomobject]@{ Device = 'lab-core'; Protocol = 'CDP'; LocalPort = 'Gi0/2'; RemoteDevice = 'ap-7'; RemotePort = 'Eth0' }
        [pscustomobject]@{ Device = 'lab-core'; Protocol = 'CDP'; LocalPort = 'Gi0/3'; RemoteDevice = 'ap-7'; RemotePort = 'Eth1' })

    Test-Case 'a link seen from both ends and by both protocols is one link' {
        $t = Get-PSTermTopology $rows
        Assert-Equal 3 @($t.Nodes).Count; Assert-Equal 3 @($t.Links).Count
        $l = @($t.Links | Where-Object { $_.A -eq 'lab-core' -and $_.B -eq 'lab-edge' })
        Assert-Equal 1 $l.Count; Assert-Equal 'CDP+LLDP' $l[0].Protocols; Assert-Equal 'Gi0/10' $l[0].PortA
        Assert-True (@($t.Nodes | Where-Object { $_.Name -eq 'ap-7' })[0].Seed -eq $false) 'ap-7 was not queried'
    }
    Test-Case 'the SVG is well-formed and names every device and port' {
        $svg = ConvertTo-PSTermTopologySvg (Get-PSTermTopology $rows)
        $xml = [xml]$svg
        Assert-Equal 'svg' $xml.DocumentElement.LocalName
        foreach ($s in 'lab-core', 'lab-edge', 'ap-7', 'Gi0/10', 'Gi1/0/1', 'Eth1') { Assert-True ($svg.Contains($s)) "missing $s" }
        Assert-Equal 3 @($xml.GetElementsByTagName('line')).Count
    }
    Test-Case 'a device name with markup characters cannot break the SVG' {
        $t = Get-PSTermTopology @([pscustomobject]@{ Device = 'a<b>&c'; Protocol = 'CDP'; LocalPort = 'Gi0/1'; RemoteDevice = 'x"y'; RemotePort = 'Gi0/2' })
        [void]([xml](ConvertTo-PSTermTopologySvg $t))
    }
    Test-Case 'the PNG is written' {
        $path = Join-Path $sandbox 'topo.png'
        Save-PSTermTopologyPng (Get-PSTermTopology $rows) $path
        $bytes = [System.IO.File]::ReadAllBytes($path)
        Assert-True ($bytes.Length -gt 2000 -and $bytes[1] -eq 0x50 -and $bytes[2] -eq 0x4E -and $bytes[3] -eq 0x47) 'not a PNG'
    }
    Test-Case 'an empty topology still draws' {
        [void]([xml](ConvertTo-PSTermTopologySvg (Get-PSTermTopology @())))
    }

    Write-Host "`nFinding plugins" -ForegroundColor Yellow

    Test-Case 'the built-in plugins are found and their forms come from the param block' {
        $all = @(Get-PSTermPlugin -Root $sandbox)
        foreach ($id in 'interface-health', 'transceiver-levels', 'inventory', 'device-health', 'cdp-topology') {
            $p = $all | Where-Object { $_.Id -eq $id }
            Assert-True ($null -ne $p) "missing $id"; Assert-Equal '' $p.Problem "($id)"; Assert-True $p.Builtin "$id builtin"; Assert-Equal 'read' $p.Access
        }
        $ih = Get-Builtin 'interface-health'
        $form = @($ih.Parameters | Where-Object { -not $_.Reserved })
        Assert-Equal 3 $form.Count
        $min = $form | Where-Object { $_.Name -eq 'MinErrors' }
        Assert-Equal 'number' $min.Kind; Assert-Equal 1 $min.Default; Assert-Equal 'Errors that count as a problem' $min.Label; Assert-True ($min.Tip -match 'counters') 'help text becomes the tip'
        Assert-Equal 'check' (($form | Where-Object { $_.Name -eq 'OnlyProblems' }).Kind)
        $lldp = (Get-Builtin 'cdp-topology').Parameters | Where-Object { $_.Name -eq 'IncludeLldp' }
        Assert-Equal 'check' $lldp.Kind; Assert-True ($lldp.Default -eq $true) 'default true'
        Assert-Equal -20 (((Get-Builtin 'transceiver-levels').Parameters | Where-Object { $_.Name -eq 'LowRxDbm' }).Default)
        Assert-True ((Get-Builtin 'cdp-topology').Topology) 'topology flag'
    }

    function New-UserPlugin {
        param([string]$Id, [string]$Script, [hashtable]$Manifest = @{})
        $dir = Join-Path (Join-Path $sandbox 'Plugins') $Id
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $m = @{ title = $Id; version = '1.0' } + $Manifest
        [System.IO.File]::WriteAllText((Join-Path $dir 'plugin.json'), ($m | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
        [System.IO.File]::WriteAllText((Join-Path $dir 'main.ps1'), $Script, (New-Object System.Text.UTF8Encoding($false)))
        Get-PSTermPlugin -Root $sandbox -Id $Id
    }

    Test-Case 'a broken plugin is listed with the reason instead of vanishing' {
        Assert-True ((New-UserPlugin 'no-session' 'param($X) 1').Problem -match 'Session') 'no $Session'
        Assert-True ((New-UserPlugin 'syntax' 'param($Session) if (').Problem -match 'syntax') 'syntax error'
        $dir = Join-Path (Join-Path $sandbox 'Plugins') 'no-script'; New-Item -ItemType Directory $dir -Force | Out-Null
        '{"title":"x"}' | Set-Content -LiteralPath (Join-Path $dir 'plugin.json')
        Assert-True ((Get-PSTermPlugin -Root $sandbox -Id 'no-script').Problem -match 'missing') 'missing script'
        Assert-True ((New-UserPlugin 'sneaky' 'param($Session) 1' @{ script = '..\x.ps1' }).Problem -match 'own folder') 'path escape'
    }
    Test-Case 'a plugin that wants to change things is refused' {
        $p = New-UserPlugin 'writer' 'param($Session) 1' @{ access = 'write' }
        Assert-True ($p.Problem -match 'read-only') 'not flagged'
        $failed = $false
        try { [void](Start-PSTermPluginRun -Plugin $p -Target (New-Targets 'x') -Store $store -Root $sandbox) } catch { $failed = $true }
        Assert-True $failed 'it started'
    }
    Test-Case 'a plugin that is not shipped needs approval, and changing it asks again' {
        $p = New-UserPlugin 'approve-me' 'param($Session) [pscustomobject]@{ Hello = 1 }'
        Assert-True (-not (Test-PSTermPluginApproved -Plugin $p -Root $sandbox)) 'approved by default'
        $failed = $false
        try { [void](Start-PSTermPluginRun -Plugin $p -Target (New-Targets 'x') -Store $store -Root $sandbox -SessionFactory (New-FactoryText)) } catch { $failed = ($_.Exception.Message -match 'approved') }
        Assert-True $failed 'ran without approval'
        Approve-PSTermPlugin -Plugin $p -Root $sandbox
        Assert-True (Test-PSTermPluginApproved -Plugin $p -Root $sandbox) 'not approved afterwards'
        $changed = New-UserPlugin 'approve-me' 'param($Session) [pscustomobject]@{ Hello = 2 }'
        Assert-True (-not (Test-PSTermPluginApproved -Plugin $changed -Root $sandbox)) 'a changed plugin stayed approved'
    }

    Write-Host "`nRunning the built-in plugins on simulated switches" -ForegroundColor Yellow

    $both = New-Targets 'lab-core', 'lab-edge'

    Test-Case 'interface health lists the interfaces that are up, once per device' {
        $r = Invoke-PSTermPlugin -Plugin (Get-Builtin 'interface-health') -Target $both -Store $store -Root $sandbox -SessionFactory (New-FactoryText)
        Assert-Equal 0 @($r.Hosts | Where-Object { $_.Status -ne 'OK' }).Count "hosts: $($r.Hosts | Out-String)"
        Assert-Equal 'Target' @($r.Rows[0].PSObject.Properties)[0].Name
        $core = @($r.Rows | Where-Object { $_.Target -eq 'lab-core' })
        Assert-Equal 2 $core.Count; Assert-Equal 'GigabitEthernet0/1' $core[0].Interface; Assert-Equal 'connected' $core[0].State; Assert-Equal 'lab-core' $core[0].Device
        Assert-True ($r.LogPath -and (Test-Path -LiteralPath $r.LogPath)) 'no log'
    }
    Test-Case 'interface health: -IncludeUnused lists the rest, -OnlyProblems nothing on a clean switch' {
        $all = Invoke-PSTermPlugin -Plugin (Get-Builtin 'interface-health') -Target $both[0] -Store $store -Root $sandbox -Parameter @{ IncludeUnused = $true } -SessionFactory (New-FactoryText)
        Assert-Equal 12 @($all.Rows).Count
        $none = Invoke-PSTermPlugin -Plugin (Get-Builtin 'interface-health') -Target $both[0] -Store $store -Root $sandbox -Parameter @{ OnlyProblems = $true } -SessionFactory (New-FactoryText)
        Assert-Equal 0 @($none.Rows).Count
    }
    Test-Case 'interface health marks errors, drops and half duplex' {
        $mutate = @'
$t = $t -replace '(?s)(GigabitEthernet0/1 is up.*?)0 input errors, 0 CRC', '${1}9 input errors, 7 CRC' -replace '(?s)(GigabitEthernet0/10 is up.*?)Full-duplex', '${1}Half-duplex'
'@
        $r = Invoke-PSTermPlugin -Plugin (Get-Builtin 'interface-health') -Target $both[0] -Store $store -Root $sandbox -Parameter @{ OnlyProblems = $true } -SessionFactory (New-FactoryText -Mutate $mutate)
        Assert-Equal 2 @($r.Rows).Count "rows: $($r.Rows | Out-String)"
        Assert-True ($r.Rows[0].Problem -match 'CRC 7') "problem: $($r.Rows[0].Problem)"
        Assert-True ($r.Rows[1].Problem -match 'half duplex') "problem: $($r.Rows[1].Problem)"
    }
    Test-Case 'device health: one row per device' {
        $r = Invoke-PSTermPlugin -Plugin (Get-Builtin 'device-health') -Target $both -Store $store -Root $sandbox -SessionFactory (New-FactoryText)
        Assert-Equal 2 @($r.Rows).Count "hosts: $($r.Hosts | Out-String)"
        $c = $r.Rows | Where-Object { $_.Target -eq 'lab-core' }
        Assert-Equal 'OK' $c.Status; Assert-Equal 20 $c.Cpu5m; Assert-Equal 2 $c.Connected; Assert-Equal 12 $c.Ports; Assert-Equal 0 $c.Trouble
    }
    Test-Case 'device health reports a busy processor' {
        $r = Invoke-PSTermPlugin -Plugin (Get-Builtin 'device-health') -Target $both[0] -Store $store -Root $sandbox -Parameter @{ CpuWarnPercent = 15 } -SessionFactory (New-FactoryText)
        Assert-Equal 'ATTENTION' $r.Rows[0].Status; Assert-True ($r.Rows[0].Notes -match 'processor 20%') $r.Rows[0].Notes
    }
    Test-Case 'inventory: a row per device, or per part' {
        $r = Invoke-PSTermPlugin -Plugin (Get-Builtin 'inventory') -Target $both -Store $store -Root $sandbox -SessionFactory (New-FactoryText)
        $e = $r.Rows | Where-Object { $_.Target -eq 'lab-edge' }
        Assert-Equal 'CMICR-4PS' $e.Model; Assert-Equal '15.2(8)E3' $e.Version; Assert-Equal 1 $e.Parts
        $p = Invoke-PSTermPlugin -Plugin (Get-Builtin 'inventory') -Target $both -Store $store -Root $sandbox -Parameter @{ IncludeParts = $true } -SessionFactory (New-FactoryText)
        Assert-Equal 2 @($p.Rows).Count; Assert-Equal 'CMICR-4PS' (@($p.Rows | Where-Object { $_.Target -eq 'lab-edge' })[0]).Pid
    }
    Test-Case 'transceiver levels: device alarm marks, low light and modules without data' {
        $r = Invoke-PSTermPlugin -Plugin (Get-Builtin 'transceiver-levels') -Target $both[0] -Store $store -Root $sandbox -SessionFactory (New-FactoryText)
        Assert-Equal 3 @($r.Rows).Count
        Assert-Equal 'OK' $r.Rows[0].Status; Assert-Equal 'ALARM' $r.Rows[1].Status; Assert-True ($r.Rows[1].Notes -match 'low light') $r.Rows[1].Notes; Assert-Equal 'no data' $r.Rows[2].Status
        $only = Invoke-PSTermPlugin -Plugin (Get-Builtin 'transceiver-levels') -Target $both[0] -Store $store -Root $sandbox -Parameter @{ OnlyProblems = $true } -SessionFactory (New-FactoryText)
        Assert-Equal 1 @($only.Rows).Count
    }
    Test-Case 'neighbours: CDP and LLDP rows, and a topology from several devices' {
        $r = Invoke-PSTermPlugin -Plugin (Get-Builtin 'cdp-topology') -Target $both -Store $store -Root $sandbox -SessionFactory (New-FactoryText)
        Assert-Equal 4 @($r.Rows).Count "rows: $($r.Rows | Out-String)"
        $t = Get-PSTermTopology @($r.Rows)
        Assert-Equal 3 @($t.Nodes).Count; Assert-Equal 3 @($t.Links).Count
        $noLldp = Invoke-PSTermPlugin -Plugin (Get-Builtin 'cdp-topology') -Target $both -Store $store -Root $sandbox -Parameter @{ IncludeLldp = $false } -SessionFactory (New-FactoryText)
        Assert-Equal 2 @($noLldp.Rows).Count
    }

    Write-Host "`nThe host" -ForegroundColor Yellow

    Test-Case 'a plugin cannot change a device, however it tries' {
        $p = New-UserPlugin 'tamper' @'
param($Session)
$out = @()
$out += (Invoke-PSTermCommand $Session 'configure terminal').Error
$out += $Session.Invoke('hostname pwned', 5000).Error
$out += $Session.Invoke('show version | redirect flash:x', 5000).Error
$out += $Session.Invoke('show version' + [char]13 + 'reload', 5000).Error
$out += $Session.Invoke('write memory', 5000).Error
$out += $Session.Invoke('reload in 5', 5000, $true).Error
try { $Session.SendRaw("configure terminal`r"); $out += 'raw allowed' } catch { $out += 'raw refused' }
[pscustomobject]@{ Results = ($out -join '|') }
'@
        Approve-PSTermPlugin -Plugin $p -Root $sandbox
        $r = Invoke-PSTermPlugin -Plugin $p -Target (New-Targets 'victim') -Store $store -Root $sandbox -SessionFactory (New-FactoryText)
        Assert-Equal 'OK' $r.Hosts[0].Status "($($r.Hosts[0].Error))"
        $results = $r.Rows[0].Results -split '\|'
        Assert-Equal 7 $results.Count
        foreach ($i in 0..5) { Assert-True ($results[$i] -match 'Refused') "command $i was not refused: '$($results[$i])'" }
        Assert-Equal 'raw refused' $results[6]
        $sent = Sent 'victim'
        foreach ($bad in 'configure terminal', 'hostname pwned', 'write memory', 'reload in 5') { Assert-True ($sent -notcontains $bad) "the device was sent '$bad'" }
        Assert-True (@($sent | Where-Object { $_ -match 'redirect|reload' }).Count -eq 0) 'something dangerous reached the device'
        Assert-True ((Get-Content -Raw -LiteralPath $r.LogPath) -match '\(refused\) configure terminal') 'the log does not show the refusals'
    }
    Test-Case 'look-only commands pass: show, ping, terminal length' {
        $p = New-UserPlugin 'looker' 'param($Session) [pscustomobject]@{ A = (Invoke-PSTermCommand $Session "show clock").Succeeded; B = (Invoke-PSTermCommand $Session "terminal length 0").Succeeded; C = (Invoke-PSTermCommand $Session "sh ip route").Error }'
        Approve-PSTermPlugin -Plugin $p -Root $sandbox
        $r = Invoke-PSTermPlugin -Plugin $p -Target (New-Targets 'x1') -Store $store -Root $sandbox -SessionFactory (New-FactoryText)
        Assert-True ($r.Rows[0].A -and $r.Rows[0].B -and $r.Rows[0].C -notmatch 'Refused') "rows: $($r.Rows | Out-String)"
    }
    Test-Case 'one device failing does not stop the others, and says why' {
        $r = Invoke-PSTermPlugin -Plugin (Get-Builtin 'inventory') -Target (New-Targets 'good-1', 'bad-1', 'good-2') -Store $store -Root $sandbox -SessionFactory (New-FactoryText -FailFor 'bad-1')
        Assert-Equal 2 @($r.Rows).Count
        $bad = $r.Hosts | Where-Object { $_.Target -eq 'bad-1' }
        Assert-Equal 'Failed' $bad.Status; Assert-True ($bad.Error -match 'simulated connection failure') $bad.Error
        Assert-Equal 2 @($r.Hosts | Where-Object { $_.Status -eq 'OK' }).Count
    }
    Test-Case 'a script that throws fails only its own device' {
        $p = New-UserPlugin 'thrower' 'param($Session, $Target) if ($Target.Name -eq "t2") { throw "boom on t2" } [pscustomobject]@{ Name = $Target.Name; Type = $Target.Type }'
        Approve-PSTermPlugin -Plugin $p -Root $sandbox
        $r = Invoke-PSTermPlugin -Plugin $p -Target (New-Targets 't1', 't2', 't3') -Store $store -Root $sandbox -SessionFactory (New-FactoryText)
        Assert-Equal 2 @($r.Rows).Count
        Assert-True (($r.Hosts | Where-Object { $_.Target -eq 't2' }).Error -match 'boom on t2') 'message lost'
        Assert-Equal 'Telnet' $r.Rows[0].Type
    }
    Test-Case 'a device that takes too long is stopped at its timeout, the others finish' {
        $p = New-UserPlugin 'sleepy' 'param($Session, $Target) if ($Target.Name -eq "slow-1") { Start-Sleep -Seconds 30 } [pscustomobject]@{ Name = $Target.Name }' @{ timeoutSec = 2 }
        Approve-PSTermPlugin -Plugin $p -Root $sandbox
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-PSTermPlugin -Plugin $p -Target (New-Targets 'fast-1', 'slow-1', 'fast-2') -Store $store -Root $sandbox -SessionFactory (New-FactoryText)
        Assert-True ($sw.Elapsed.TotalSeconds -lt 15) "took $($sw.Elapsed.TotalSeconds) s"
        Assert-Equal 'TimedOut' (($r.Hosts | Where-Object { $_.Target -eq 'slow-1' }).Status)
        Assert-Equal 2 @($r.Hosts | Where-Object { $_.Status -eq 'OK' }).Count
    }
    Test-Case 'devices run side by side: eight slow ones finish far sooner than one after the other' {
        $p = New-UserPlugin 'waits' 'param($Session) $null = Invoke-PSTermCommand $Session "show slow"; [pscustomobject]@{ Done = 1 }' @{ timeoutSec = 60 }
        Approve-PSTermPlugin -Plugin $p -Root $sandbox
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-PSTermPlugin -Plugin $p -Target (New-Targets (1..8 | ForEach-Object { "w$_" })) -Store $store -Root $sandbox -SessionFactory (New-FactoryText) -ThrottleLimit 8
        $t = $sw.Elapsed.TotalSeconds
        Assert-Equal 8 @($r.Rows).Count "hosts: $($r.Hosts | Out-String)"
        Assert-True ($t -lt 9) "took $t s (one after the other would be 12 s or more)"
    }
    Test-Case 'the throttle limits how many run at once' {
        $p = Get-PSTermPlugin -Root $sandbox -Id 'waits'
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-PSTermPlugin -Plugin $p -Target (New-Targets (1..4 | ForEach-Object { "t$_" })) -Store $store -Root $sandbox -SessionFactory (New-FactoryText) -ThrottleLimit 1
        Assert-True ($sw.Elapsed.TotalSeconds -gt 5.5) "took only $($sw.Elapsed.TotalSeconds) s: they overlapped"
        Assert-Equal 4 @($r.Rows).Count
    }
    Test-Case 'a run can be cancelled' {
        $p = Get-PSTermPlugin -Root $sandbox -Id 'waits'
        $run = Start-PSTermPluginRun -Plugin $p -Target (New-Targets 'c1', 'c2', 'c3') -Store $store -Root $sandbox -SessionFactory (New-FactoryText) -ThrottleLimit 1
        Start-Sleep -Milliseconds 700
        Stop-PSTermPluginRun -Run $run
        Assert-True $run.Done 'not finished'
        Assert-True (@($run.Hosts | Where-Object { $_.Status -eq 'Cancelled' }).Count -ge 2) "hosts: $($run.Hosts | Out-String)"
    }
    Test-Case 'Stop returns at once even when a device is stuck, and the pool is released in the background' {
        $p = New-UserPlugin 'stuck' 'param($Session) Start-Sleep -Seconds 40; [pscustomobject]@{ Never = 1 }' @{ timeoutSec = 120 }
        Approve-PSTermPlugin -Plugin $p -Root $sandbox
        $run = Start-PSTermPluginRun -Plugin $p -Target (New-Targets 's1', 's2', 's3') -Store $store -Root $sandbox -SessionFactory (New-FactoryText)
        Start-Sleep -Milliseconds 2500
        $sw = [Diagnostics.Stopwatch]::StartNew()
        Stop-PSTermPluginRun -Run $run
        $took = $sw.Elapsed.TotalSeconds
        Assert-True $run.Done 'not finished'
        Assert-True ($took -lt 3) "Stop took $took s"
        Assert-Equal 3 @($run.Hosts | Where-Object { $_.Status -eq 'Cancelled' }).Count
    }
    Test-Case 'a timeout also returns at once' {
        $p = New-UserPlugin 'stuck2' 'param($Session) Start-Sleep -Seconds 40' @{ timeoutSec = 2 }
        Approve-PSTermPlugin -Plugin $p -Root $sandbox
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-PSTermPlugin -Plugin $p -Target (New-Targets 'x1', 'x2') -Store $store -Root $sandbox -SessionFactory (New-FactoryText)
        Assert-True ($sw.Elapsed.TotalSeconds -lt 12) "took $($sw.Elapsed.TotalSeconds) s"
        Assert-Equal 2 @($r.Hosts | Where-Object { $_.Status -eq 'TimedOut' }).Count
    }
    Test-Case 'parameters are checked' {
        $p = Get-Builtin 'interface-health'
        $failed = $false
        try { [void](Start-PSTermPluginRun -Plugin $p -Target (New-Targets 'x') -Store $store -Root $sandbox -Parameter @{ Nonsense = 1 } -SessionFactory (New-FactoryText)) } catch { $failed = ($_.Exception.Message -match 'Nonsense') }
        Assert-True $failed 'an unknown parameter was accepted'
        $failed = $false
        try { [void](Start-PSTermPluginRun -Plugin $p -Target @() -Store $store -Root $sandbox) } catch { $failed = $true }
        Assert-True $failed 'no devices was accepted'
    }
    Test-Case 'the log says what was sent where, and no password is in it' {
        $r = Invoke-PSTermPlugin -Plugin (Get-Builtin 'inventory') -Target $both -Store $store -Root $sandbox -SessionFactory (New-FactoryText)
        $log = Get-Content -Raw -LiteralPath $r.LogPath
        foreach ($s in 'Inventory', '> show version', '> show inventory', '[OK] lab-core', '[OK] lab-edge', 'look-only') { Assert-True ($log.Contains($s)) "log lacks '$s'" }
        Assert-True ($log -notmatch 'enablepw') 'a secret is in the log'
    }
    Test-Case 'the rows export as CSV with quoting' {
        $path = Join-Path $sandbox 'out.csv'
        Export-PSTermPluginRows -Row @([pscustomobject]@{ Target = 'a,b'; Note = 'say "hi"'; Count = 3 }, [pscustomobject]@{ Target = 'c'; Note = $null; Count = 4.5 }) -Path $path
        $text = [System.IO.File]::ReadAllText($path)
        Assert-True ($text.Contains('"Target","Note","Count"')) 'header'
        Assert-True ($text.Contains('"a,b","say ""hi""","3"')) 'quoting'
        Assert-True ($text.Contains('"c","","4.5"')) 'null and invariant numbers'
    }
}
finally { Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host ("-" * 60)
$total = $script:Passed + $script:Failed
if ($script:Failed -eq 0) { Write-Host "All $total plugin tests passed." -ForegroundColor Green; exit 0 }
Write-Host "$($script:Failed) of $total plugin tests FAILED." -ForegroundColor Red
foreach ($f in $script:Failures) { Write-Host $f -ForegroundColor Red }
exit 1
