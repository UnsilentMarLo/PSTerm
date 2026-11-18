<#
.PARAMETER IncludeParts
    List every part the device reports (chassis, modules, power supplies) instead of one row per device.
#>
param(
    [Parameter(Mandatory)]$Session,
    $Target,
    [switch]$IncludeParts
)

$device = Get-PSTermSessionHostname -Session $Session
$version = ConvertFrom-PSTermIosVersion (Invoke-PSTermCommand $Session 'show version' -TimeoutSec 45 -ThrowOnError).Lines
$inv = @(ConvertFrom-PSTermIosInventory (Invoke-PSTermCommand $Session 'show inventory' -TimeoutSec 30).Lines)

if ($IncludeParts) {
    foreach ($part in $inv) {
        [pscustomobject][ordered]@{ Device = $device; Name = $part.Name; Description = $part.Description; Pid = $part.Pid; Vid = $part.Vid; Serial = $part.Serial }
    }
    return
}

[pscustomobject][ordered]@{
    Device     = $device
    Address    = $(if ($Target) { $Target.Address } else { '' })
    Model      = $version.Model
    Serial     = $version.Serial
    Version    = $version.Version
    Uptime     = $version.Uptime
    LastReload = $version.LastReload
    Parts      = $inv.Count
    Image      = $version.Image
}
