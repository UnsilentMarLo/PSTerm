<#
.PARAMETER OnlyProblems
    List only the modules with a warning or an alarm.
.PARAMETER LowRxDbm
    A receive level below this many dBm is reported as low light. The device's own alarm marks are reported whatever this is set to.
.PARAMETER HighTempC
    A module hotter than this is reported.
#>
param(
    [Parameter(Mandatory)]$Session,
    [switch]$OnlyProblems,
    [double]$LowRxDbm = -20,
    [double]$HighTempC = 70
)

$device = Get-PSTermSessionHostname -Session $Session
$result = Invoke-PSTermCommand $Session 'show interfaces transceiver' -TimeoutSec 60
if (-not $result.Succeeded) {
    [pscustomobject][ordered]@{ Device = $device; Port = ''; Temperature = $null; Voltage = $null; TxPower = $null; RxPower = $null; Status = 'not available'; Notes = $result.Error }
    return
}

$any = $false
foreach ($t in ConvertFrom-PSTermIosTransceiver $result.Lines) {
    $any = $true
    $notes = @()
    $alarm = $false
    foreach ($pair in @(@('RxPower', 'receive'), @('TxPower', 'transmit'), @('Temperature', 'temperature'), @('Voltage', 'voltage'))) {
        $flag = $t.($pair[0] + 'Flag')
        if ($flag -eq '--' -or $flag -eq '++') { $alarm = $true; $notes += "$($pair[1]) alarm ($flag)" }
        elseif ($flag -eq '-' -or $flag -eq '+') { $notes += "$($pair[1]) warning ($flag)" }
    }
    if ($null -ne $t.RxPower -and $t.RxPower -lt $LowRxDbm) { $notes += "low light ($($t.RxPower) dBm)" }
    if ($null -ne $t.Temperature -and $t.Temperature -gt $HighTempC) { $notes += "hot ($($t.Temperature) C)" }

    $status = $(if ($alarm) { 'ALARM' } elseif ($notes.Count) { 'WARNING' } elseif ($null -eq $t.RxPower -and $null -eq $t.TxPower) { 'no data' } else { 'OK' })
    if ($OnlyProblems -and $status -in @('OK', 'no data')) { continue }

    [pscustomobject][ordered]@{
        Device = $device; Port = $t.Port; Temperature = $t.Temperature; Voltage = $t.Voltage
        TxPower = $t.TxPower; RxPower = $t.RxPower; Status = $status; Notes = ($notes -join '; ')
    }
}
if (-not $any -and -not $OnlyProblems) {
    [pscustomobject][ordered]@{ Device = $device; Port = ''; Temperature = $null; Voltage = $null; TxPower = $null; RxPower = $null; Status = 'no modules report levels'; Notes = '' }
}
