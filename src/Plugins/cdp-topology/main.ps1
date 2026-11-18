<#
.PARAMETER IncludeLldp
    Ask LLDP as well as CDP. Devices that do not run LLDP are simply skipped.
#>
param(
    [Parameter(Mandatory)]$Session,
    [bool]$IncludeLldp = $true
)

$device = Get-PSTermSessionHostname -Session $Session

$rows = @()
$cdp = Invoke-PSTermCommand $Session 'show cdp neighbors detail' -TimeoutSec 45
if ($cdp.Succeeded) { $rows += @(ConvertFrom-PSTermIosCdp $cdp.Lines) }
if ($IncludeLldp) {
    $lldp = Invoke-PSTermCommand $Session 'show lldp neighbors detail' -TimeoutSec 45
    if ($lldp.Succeeded) { $rows += @(ConvertFrom-PSTermIosLldp $lldp.Lines) }
}

foreach ($r in $rows) {
    [pscustomobject][ordered]@{
        Device = $device; Protocol = $r.Protocol; LocalPort = $r.LocalPort
        RemoteDevice = $r.RemoteDevice; RemotePort = $r.RemotePort; RemoteIp = $r.RemoteIp
        Platform = $r.Platform; Capabilities = $r.Capabilities
    }
}
