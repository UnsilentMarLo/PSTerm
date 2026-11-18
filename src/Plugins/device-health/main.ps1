<#
.PARAMETER CpuWarnPercent
    The five-minute processor load at or above this is reported.
.PARAMETER MemWarnPercent
    Processor memory use at or above this is reported.
#>
param(
    [Parameter(Mandatory)]$Session,
    [int]$CpuWarnPercent = 80,
    [int]$MemWarnPercent = 85
)

$device = Get-PSTermSessionHostname -Session $Session
$version = ConvertFrom-PSTermIosVersion (Invoke-PSTermCommand $Session 'show version' -TimeoutSec 45 -ThrowOnError).Lines
$cpu = ConvertFrom-PSTermIosCpu (Invoke-PSTermCommand $Session 'show processes cpu | include CPU' -TimeoutSec 30).Lines
$mem = ConvertFrom-PSTermIosMemory (Invoke-PSTermCommand $Session 'show memory statistics' -TimeoutSec 30).Lines
$ports = @(ConvertFrom-PSTermIosInterfaceStatus (Invoke-PSTermCommand $Session 'show interfaces status' -TimeoutSec 45).Lines)

$connected = @($ports | Where-Object { $_.Status -eq 'connected' }).Count
$trouble = @($ports | Where-Object { $_.Status -match 'err-?disabled|faulty|suspended|sfp-config-mismatch' }).Count

$notes = @()
if ($cpu -and $cpu.Cpu5m -ge $CpuWarnPercent) { $notes += "processor $($cpu.Cpu5m)%" }
if ($mem -and $mem.UsedPercent -ge $MemWarnPercent) { $notes += "memory $($mem.UsedPercent)%" }
if ($trouble -gt 0) { $notes += "$trouble port(s) in trouble" }

[pscustomobject][ordered]@{
    Device     = $device
    Status     = $(if ($notes.Count) { 'ATTENTION' } else { 'OK' })
    Cpu5m      = $(if ($cpu) { $cpu.Cpu5m } else { $null })
    MemoryUsed = $(if ($mem) { $mem.UsedPercent } else { $null })
    Uptime     = $version.Uptime
    LastReload = $version.LastReload
    Connected  = $connected
    Ports      = $ports.Count
    Trouble    = $trouble
    Notes      = ($notes -join '; ')
}
