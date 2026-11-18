<#
.SYNOPSIS
    Turn the text a Cisco IOS device prints into objects.

.DESCRIPTION
    Pure functions: text in, objects out, nothing is sent anywhere. They are written
    against output captured from real switches (tests\Fixtures\ios) and are what the
    built-in plugins use. A line they cannot read is skipped, never guessed at.
#>

Set-StrictMode -Version Latest

function Get-PSTermShortPort {
    <#
    .SYNOPSIS
        GigabitEthernet0/10 -> Gi0/10, so the same port written two ways compares equal.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Name)

    $n = $Name.Trim()
    $map = [ordered]@{
        'TwentyFiveGigE' = 'Twe'; 'TwentyFiveGigabitEthernet' = 'Twe'; 'HundredGigE' = 'Hu'; 'FortyGigabitEthernet' = 'Fo'
        'TenGigabitEthernet' = 'Te'; 'TwoGigabitEthernet' = 'Tw'; 'GigabitEthernet' = 'Gi'; 'FastEthernet' = 'Fa'
        'Port-channel' = 'Po'; 'Loopback' = 'Lo'; 'Vlan' = 'Vl'; 'Ethernet' = 'Eth'; 'Management' = 'Mgmt'
    }
    foreach ($long in $map.Keys) {
        if ($n -match ('^' + [regex]::Escape($long) + '(?=\d)')) { return $map[$long] + $n.Substring($long.Length) }
    }
    $n
}

function Get-PSTermShortName {
    <#
    .SYNOPSIS
        A device name without its domain: lab-core.lab.local -> lab-core. An address is
        left alone.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Name)
    $n = $Name.Trim()
    if ($n -match '^\d{1,3}(\.\d{1,3}){3}$') { return $n }
    if ($n -match '^([^.]+)\.') { return $Matches[1] }
    $n
}

function ConvertFrom-PSTermIosVersion {
    <#
    .SYNOPSIS
        "show version" -> Hostname, Uptime, Version, Model, Serial, Image, LastReload.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Line)

    $r = [ordered]@{ Hostname = ''; Uptime = ''; Version = ''; Model = ''; Serial = ''; Image = ''; LastReload = '' }
    $boardId = ''; $boardModel = ''
    foreach ($l in $Line) {
        if (-not $r.Version -and $l -match '^Cisco IOS.*?\bVersion\s+([^,\s]+)') { $r.Version = $Matches[1]; continue }
        if (-not $r.Hostname -and $l -match '^(\S+) uptime is (.+?)\s*$') { $r.Hostname = $Matches[1]; $r.Uptime = $Matches[2]; continue }
        if ($l -match '^System image file is "(.+)"') { $r.Image = $Matches[1]; continue }
        if ($l -match '^Last reload reason:\s*(.+?)\s*$') { $r.LastReload = $Matches[1]; continue }
        if ($l -match '^Model number\s*:\s*(\S+)') { $r.Model = $Matches[1]; continue }
        if ($l -match '^System serial number\s*:\s*(\S+)') { $r.Serial = $Matches[1]; continue }
        if ($l -match '^Processor board ID\s+(\S+)') { $boardId = $Matches[1]; continue }
        if (-not $boardModel -and $l -match '^[Cc]isco\s+(\S+)\s+.*processor') { $boardModel = $Matches[1] }
    }
    if (-not $r.Model) { $r.Model = $boardModel }
    if (-not $r.Serial) { $r.Serial = $boardId }
    [pscustomobject]$r
}

function ConvertFrom-PSTermIosInventory {
    <#
    .SYNOPSIS
        "show inventory" -> one object per part: Name, Description, Pid, Vid, Serial.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Line)

    $name = ''; $descr = ''
    foreach ($l in $Line) {
        if ($l -match '^NAME:\s*"(.*?)"\s*,\s*DESCR:\s*"(.*)"\s*$') { $name = $Matches[1]; $descr = $Matches[2]; continue }
        if ($l -match '^PID:\s*(.*?)\s*,\s*VID:\s*(.*?)\s*,\s*SN:\s*(.*?)\s*$') {
            [pscustomobject][ordered]@{ Name = $name; Description = $descr; Pid = $Matches[1]; Vid = $Matches[2]; Serial = $Matches[3] }
            $name = ''; $descr = ''
        }
    }
}

function ConvertFrom-PSTermIosInterfaces {
    <#
    .SYNOPSIS
        "show interfaces" -> one object per interface with its state and error counters.
    .DESCRIPTION
        The counters are the totals since the device last cleared them (LastCleared says
        when), so a number above zero is history, not necessarily something happening now.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Line)

    $cur = $null
    $emit = {
        param($c)
        if ($null -ne $c) { [pscustomobject]$c }
    }

    foreach ($l in $Line) {
        if ($l -match '^(\S+) is (administratively down|up|down|deleted|[^,]+), line protocol is (\S+)(?:\s+\((.+)\))?') {
            & $emit $cur
            $cur = [ordered]@{
                Interface = $Matches[1]; Status = $Matches[2]; Protocol = $Matches[3]
                Detail = $(if ($Matches.Count -gt 4) { $Matches[4] } else { '' })
                Description = ''; Address = ''; Speed = ''; Duplex = ''; Media = ''
                InPackets = [long]0; OutPackets = [long]0
                InErrors = [long]0; Crc = [long]0; Frame = [long]0; Overrun = [long]0; Ignored = [long]0
                Runts = [long]0; Giants = [long]0
                OutErrors = [long]0; Collisions = [long]0; Resets = [long]0; OutDrops = [long]0
                InBitsPerSec = [long]0; OutBitsPerSec = [long]0; LastCleared = ''
            }
            continue
        }
        if ($null -eq $cur) { continue }

        if ($l -match '^\s+Description:\s*(.*?)\s*$') { $cur.Description = $Matches[1]; continue }
        if ($l -match '^\s+Internet address is\s+(\S+)') { $cur.Address = $Matches[1]; continue }
        if ($l -match '^\s+(Full|Half|Auto)-duplex,\s*([^,]+?)(?:,|\s*$)') {
            $cur.Duplex = $Matches[1]; $cur.Speed = $Matches[2]
            if ($l -match 'media type is\s+(.+?)\s*$') { $cur.Media = $Matches[1] }
            continue
        }
        if ($l -match 'Last clearing of "show interface" counters\s+(.+?)\s*$') { $cur.LastCleared = $Matches[1]; continue }
        if ($l -match 'Total output drops:\s*(\d+)') { $cur.OutDrops = [long]$Matches[1]; continue }
        if ($l -match '5 minute input rate (\d+) bits/sec') { $cur.InBitsPerSec = [long]$Matches[1]; continue }
        if ($l -match '5 minute output rate (\d+) bits/sec') { $cur.OutBitsPerSec = [long]$Matches[1]; continue }
        if ($l -match '^\s+(\d+) packets input') { $cur.InPackets = [long]$Matches[1]; continue }
        if ($l -match '^\s+(\d+) packets output') { $cur.OutPackets = [long]$Matches[1]; continue }
        if ($l -match '^\s+(\d+) runts, (\d+) giants') { $cur.Runts = [long]$Matches[1]; $cur.Giants = [long]$Matches[2]; continue }
        if ($l -match '^\s+(\d+) input errors, (\d+) CRC, (\d+) frame, (\d+) overrun, (\d+) ignored') {
            $cur.InErrors = [long]$Matches[1]; $cur.Crc = [long]$Matches[2]; $cur.Frame = [long]$Matches[3]
            $cur.Overrun = [long]$Matches[4]; $cur.Ignored = [long]$Matches[5]
            continue
        }
        if ($l -match '^\s+(\d+) output errors(?:,\s*(\d+) collisions)?,\s*(\d+) interface resets') {
            $cur.OutErrors = [long]$Matches[1]
            if ($Matches[2]) { $cur.Collisions = [long]$Matches[2] }
            $cur.Resets = [long]$Matches[3]
            continue
        }
    }
    & $emit $cur
}

function ConvertFrom-PSTermIosTransceiver {
    <#
    .SYNOPSIS
        "show interfaces transceiver" -> one object per port: Port, Temperature, Voltage,
        TxPower, RxPower (and BiasCurrent where the device prints it), with the device's
        own alarm marks in the matching *Flag column.
    .DESCRIPTION
        The table has a dashed line under its header; the columns are cut where the
        dashes are. A value the device prints as N/A is $null.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Line)

    $lines = @($Line)
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -notmatch '^-{3,}(\s+-{3,})+\s*$') { continue }
        if ($i -lt 1 -or $lines[$i - 1] -notmatch '^\s*Port\b') { continue }

        # Column spans from the dashes; each column runs to the next one's start.
        $dash = $lines[$i]
        $starts = @([regex]::Matches($dash, '-+') | ForEach-Object { $_.Index })
        $spans = @()
        for ($c = 0; $c -lt $starts.Count; $c++) {
            $to = if ($c + 1 -lt $starts.Count) { $starts[$c + 1] } else { 400 }
            $spans += , @($starts[$c], $to)
        }

        # A header can be one or two lines above the dashes ("Optical" over "Tx Power").
        $headerLines = @($lines[$i - 1])
        if ($i -ge 2 -and $lines[$i - 2].Trim() -and $lines[$i - 2] -notmatch '^(If device|\+\+|NA or|\s*$)') { $headerLines = @($lines[$i - 2], $lines[$i - 1]) }

        $slice = {
            param([string]$text, $span)
            if ($text.Length -le $span[0]) { return '' }
            $len = [Math]::Min($span[1], $text.Length) - $span[0]
            $text.Substring($span[0], $len).Trim()
        }

        $names = @()
        foreach ($span in $spans) {
            $name = (($headerLines | ForEach-Object { & $slice $_ $span }) | Where-Object { $_ }) -join ' '
            $names += $name
        }
        $keys = @()
        foreach ($n in $names) {
            $keys += $(switch -regex ($n) {
                '^Port$' { 'Port'; break }
                'Temp' { 'Temperature'; break }
                'Volt' { 'Voltage'; break }
                'Tx\s*Power|Transmit' { 'TxPower'; break }
                'Rx\s*Power|Receive' { 'RxPower'; break }
                'Current|Bias' { 'BiasCurrent'; break }
                default { ($n -replace '\W+', '') }
            })
        }

        for ($j = $i + 1; $j -lt $lines.Count; $j++) {
            $row = $lines[$j]
            if (-not $row.Trim()) { break }
            $obj = [ordered]@{}
            for ($c = 0; $c -lt $keys.Count; $c++) {
                $raw = & $slice $row $spans[$c]
                if ($c -eq 0) { $obj['Port'] = $raw; continue }
                $key = $keys[$c]
                if ($raw -match '^(-?\d+(?:\.\d+)?)\s*(\+\+|--|\+|-)?$') {
                    $obj[$key] = [double]$Matches[1]
                    $obj[$key + 'Flag'] = $(if ($Matches.Count -gt 2) { $Matches[2] } else { '' })
                }
                else { $obj[$key] = $null; $obj[$key + 'Flag'] = '' }
            }
            if ($obj['Port']) { [pscustomobject]$obj }
        }
        return
    }
}

function ConvertFrom-PSTermIosCdp {
    <#
    .SYNOPSIS
        "show cdp neighbors detail" -> one object per neighbour.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Line)

    $cur = $null
    $emit = { param($c) if ($null -ne $c -and $c.RemoteDevice) { [pscustomobject]$c } }
    foreach ($l in $Line) {
        if ($l -match '^-{5,}\s*$') { & $emit $cur; $cur = [ordered]@{ Protocol = 'CDP'; LocalPort = ''; RemoteDevice = ''; RemotePort = ''; RemoteIp = ''; Platform = ''; Capabilities = '' }; continue }
        if ($null -eq $cur) { continue }
        if ($l -match '^Device ID:\s*(.+?)\s*$') { $cur.RemoteDevice = $Matches[1]; continue }
        if ($l -match '^\s*IP(?:v4)? address:\s*(\d+\.\d+\.\d+\.\d+)') { if (-not $cur.RemoteIp) { $cur.RemoteIp = $Matches[1] }; continue }
        if ($l -match '^Platform:\s*(.*?),\s*Capabilities:\s*(.*?)\s*$') { $cur.Platform = ($Matches[1] -replace '^cisco\s+', ''); $cur.Capabilities = $Matches[2]; continue }
        if ($l -match '^Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*(\S+)') { $cur.LocalPort = $Matches[1]; $cur.RemotePort = $Matches[2]; continue }
    }
    & $emit $cur
}

function ConvertFrom-PSTermIosLldp {
    <#
    .SYNOPSIS
        "show lldp neighbors detail" -> one object per neighbour, shaped like the CDP ones.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Line)

    $cur = $null
    $emit = { param($c) if ($null -ne $c -and ($c.RemoteDevice -or $c.RemotePort)) { [pscustomobject]$c } }
    $inMgmt = $false
    foreach ($l in $Line) {
        if ($l -match '^-{5,}\s*$') { & $emit $cur; $cur = [ordered]@{ Protocol = 'LLDP'; LocalPort = ''; RemoteDevice = ''; RemotePort = ''; RemoteIp = ''; Platform = ''; Capabilities = '' }; $inMgmt = $false; continue }
        if ($null -eq $cur) { continue }
        if ($l -match '^Local Intf:\s*(\S+)') { $cur.LocalPort = $Matches[1]; continue }
        if ($l -match '^Port id:\s*(.+?)\s*$') { $cur.RemotePort = $Matches[1]; continue }
        if ($l -match '^System Name:\s*(.+?)\s*$') { $cur.RemoteDevice = $Matches[1]; continue }
        if ($l -match '^Chassis id:\s*(.+?)\s*$') { if (-not $cur.RemoteDevice) { $cur.RemoteDevice = $Matches[1] }; continue }
        if ($l -match '^System Capabilities:\s*(.+?)\s*$') { $cur.Capabilities = $Matches[1]; continue }
        if ($l -match '^Management Addresses') { $inMgmt = $true; continue }
        if ($inMgmt -and $l -match '^\s*IP:\s*(\d+\.\d+\.\d+\.\d+)') { if (-not $cur.RemoteIp) { $cur.RemoteIp = $Matches[1] }; $inMgmt = $false; continue }
    }
    & $emit $cur
}

function ConvertFrom-PSTermIosInterfaceStatus {
    <#
    .SYNOPSIS
        "show interfaces status" -> Port, Name, Status, Vlan, Duplex, Speed, Type. The
        columns are cut where the header puts them, because a description can hold spaces.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Line)

    $lines = @($Line)
    $h = $lines | Where-Object { $_ -match '^Port\s+Name\s+Status\s+Vlan' } | Select-Object -First 1
    if (-not $h) { return }
    $cName = $h.IndexOf('Name'); $cStatus = $h.IndexOf('Status'); $cVlan = $h.IndexOf('Vlan')
    $started = $false
    foreach ($l in $lines) {
        if (-not $started) { if ($l -eq $h) { $started = $true }; continue }
        if ($l.Length -le $cVlan) { continue }
        $rest = @($l.Substring($cVlan).Trim() -split '\s+')
        [pscustomobject][ordered]@{
            Port   = $l.Substring(0, $cName).Trim()
            Name   = $l.Substring($cName, $cStatus - $cName).Trim()
            Status = $l.Substring($cStatus, $cVlan - $cStatus).Trim()
            Vlan   = $rest[0]
            Duplex = $(if ($rest.Count -gt 1) { $rest[1] } else { '' })
            Speed  = $(if ($rest.Count -gt 2) { $rest[2] } else { '' })
            Type   = $(if ($rest.Count -gt 3) { ($rest[3..($rest.Count - 1)] -join ' ') } else { '' })
        }
    }
}

function ConvertFrom-PSTermIosCpu {
    <#
    .SYNOPSIS
        The "CPU utilization for five seconds: 21%/0%; one minute: 21%; five minutes: 20%" line.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Line)
    foreach ($l in $Line) {
        if ($l -match 'five seconds:\s*(\d+)%(?:/\d+%)?;\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%') {
            return [pscustomobject][ordered]@{ Cpu5s = [int]$Matches[1]; Cpu1m = [int]$Matches[2]; Cpu5m = [int]$Matches[3] }
        }
    }
    $null
}

function ConvertFrom-PSTermIosMemory {
    <#
    .SYNOPSIS
        The Processor line of "show memory statistics": total, used, free in bytes and the
        percentage used.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Line)
    foreach ($l in $Line) {
        if ($l -match '^\s*Processor\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)') {
            $total = [long]$Matches[1]; $used = [long]$Matches[2]
            return [pscustomobject][ordered]@{
                TotalBytes = $total; UsedBytes = $used; FreeBytes = [long]$Matches[3]
                UsedPercent = $(if ($total -gt 0) { [Math]::Round(100.0 * $used / $total, 1) } else { 0 })
            }
        }
    }
    $null
}
