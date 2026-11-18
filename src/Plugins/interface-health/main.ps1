<#
.PARAMETER OnlyProblems
    List only the interfaces that show a problem.
.PARAMETER MinErrors
    An interface is marked when one of its error or drop counters has reached this number. The counters count from the last time the device cleared them.
.PARAMETER IncludeUnused
    Also list interfaces that are down and have never carried a packet.
#>
param(
    [Parameter(Mandatory)]$Session,
    [switch]$OnlyProblems,
    [int]$MinErrors = 1,
    [switch]$IncludeUnused
)

$device = Get-PSTermSessionHostname -Session $Session
$result = Invoke-PSTermCommand $Session 'show interfaces' -TimeoutSec 100 -ThrowOnError

foreach ($i in ConvertFrom-PSTermIosInterfaces $result.Lines) {
    if ($i.Interface -match '^(Vlan|Loopback|Null|Tunnel)') { continue }
    $up = ($i.Protocol -eq 'up')
    if (-not $IncludeUnused -and -not $up -and $i.InPackets -eq 0 -and $i.OutPackets -eq 0) { continue }

    $problems = @()
    if ($i.Crc -ge $MinErrors) { $problems += "CRC $($i.Crc)" }
    if ($i.InErrors -ge $MinErrors -and $i.InErrors -ne $i.Crc) { $problems += "input errors $($i.InErrors)" }
    if ($i.OutErrors -ge $MinErrors) { $problems += "output errors $($i.OutErrors)" }
    if ($i.OutDrops -ge $MinErrors) { $problems += "output drops $($i.OutDrops)" }
    if ($i.Giants -ge $MinErrors) { $problems += "giants $($i.Giants)" }
    if ($up -and $i.Duplex -eq 'Half') { $problems += 'half duplex' }
    if ($i.Detail -match 'err-?disabled') { $problems += 'err-disabled' }

    if ($OnlyProblems -and $problems.Count -eq 0) { continue }

    [pscustomobject][ordered]@{
        Device      = $device
        Interface   = $i.Interface
        Description = $i.Description
        State       = $(if ($i.Detail) { $i.Detail } else { "$($i.Status)/$($i.Protocol)" })
        Speed       = $i.Speed
        Duplex      = $i.Duplex
        Crc         = $i.Crc
        InErrors    = $i.InErrors
        OutErrors   = $i.OutErrors
        OutDrops    = $i.OutDrops
        Resets      = $i.Resets
        Problem     = ($problems -join '; ')
    }
}
