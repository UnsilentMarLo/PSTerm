<#
.SYNOPSIS
    Tests for the profile store, v1 migration and quick-connect parsing.

.DESCRIPTION
    These cover the PowerShell half of PSTerm - everything that is not in the
    data path. The migration tests matter most: they are what stops an existing
    v1 profiles.json turning into a pile of empty connections.

.EXAMPLE
    powershell -NoProfile -File tests\Run-ProfileTests.ps1
#>
[CmdletBinding()]
param([switch]$FailFast)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'src\Bootstrap.ps1')
Initialize-PSTermCore -Root $root
. (Join-Path $root 'src\Settings.ps1')
. (Join-Path $root 'src\Secrets.ps1')
. (Join-Path $root 'src\Profiles.ps1')
. (Join-Path $root 'src\Connect.ps1')

$script:Passed = 0
$script:Failed = 0
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
function Assert-Equal { param($Expected, $Actual, [string]$Because='')
    if ($Expected -ne $Actual) { throw "expected '$Expected' but got '$Actual' $Because" } }
function Assert-True { param([bool]$Condition, [string]$Because='')
    if (-not $Condition) { throw "expected true: $Because" } }

# A scratch install root per run, so nothing touches the real profile store.
$sandbox = Join-Path ([System.IO.Path]::GetTempPath()) ("psterm-profiles-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $sandbox 'Profiles') -Force | Out-Null

Write-Host "`nPSTerm profile and connection tests" -ForegroundColor Cyan
Write-Host ("-" * 60)

try {

# ------------------------------------------------------- quick connect ------

Write-Host "`nQuick-connect parsing" -ForegroundColor Yellow

Test-Case 'user@host becomes an SSH profile on port 22' {
    $p = ConvertFrom-PSTermQuickConnect -Text 'admin@core-sw1'
    Assert-Equal 'SSH' $p.type
    Assert-Equal 'core-sw1' $p.ssh.host
    Assert-Equal 'admin' $p.ssh.user
    Assert-Equal 22 $p.ssh.port
}

Test-Case 'host:port sets the port' {
    $p = ConvertFrom-PSTermQuickConnect -Text 'jump.example.net:2222'
    Assert-Equal 'jump.example.net' $p.ssh.host
    Assert-Equal 2222 $p.ssh.port
    Assert-Equal '' $p.ssh.user
}

Test-Case 'a full ssh command line is accepted' {
    $p = ConvertFrom-PSTermQuickConnect -Text 'ssh ops@rtr1 -p 2022'
    Assert-Equal 'rtr1' $p.ssh.host
    Assert-Equal 'ops' $p.ssh.user
    Assert-Equal 2022 $p.ssh.port
}

Test-Case 'unknown ssh flags are ignored rather than breaking the parse' {
    # ssh.exe still reads ~/.ssh/config, so dropping extras here is safe.
    $p = ConvertFrom-PSTermQuickConnect -Text 'ssh -4 -C admin@sw9'
    Assert-Equal 'sw9' $p.ssh.host
    Assert-Equal 'admin' $p.ssh.user
}

Test-Case 'telnet with and without a port' {
    $a = ConvertFrom-PSTermQuickConnect -Text 'telnet console.lab'
    Assert-Equal 'Telnet' $a.type
    Assert-Equal 'console.lab' $a.telnet.host
    Assert-Equal 23 $a.telnet.port

    $b = ConvertFrom-PSTermQuickConnect -Text 'telnet termserv 2004'
    Assert-Equal 2004 $b.telnet.port
}

Test-Case 'COM port with and without a baud rate' {
    $a = ConvertFrom-PSTermQuickConnect -Text 'COM3'
    Assert-Equal 'Serial' $a.type
    Assert-Equal 'COM3' $a.serial.portName
    Assert-Equal 9600 $a.serial.baudRate

    $b = ConvertFrom-PSTermQuickConnect -Text 'com12:115200'
    Assert-Equal 'COM12' $b.serial.portName
    Assert-Equal 115200 $b.serial.baudRate
}

Test-Case 'shell names open a local session' {
    foreach ($name in @('cmd', 'powershell', 'pwsh', 'wsl', 'bash')) {
        $p = ConvertFrom-PSTermQuickConnect -Text $name
        Assert-Equal 'Shell' $p.type "for '$name'"
        Assert-True ([bool]$p.shell.commandLine) "command line for '$name'"
    }
}

Test-Case 'empty or nonsense input returns nothing rather than a bad profile' {
    Assert-Equal $null (ConvertFrom-PSTermQuickConnect -Text '')
    Assert-Equal $null (ConvertFrom-PSTermQuickConnect -Text '   ')
    Assert-Equal $null (ConvertFrom-PSTermQuickConnect -Text 'two words here')
}

# ------------------------------------------------------------ store ---------

Write-Host "`nProfile store" -ForegroundColor Yellow

Test-Case 'a fresh install creates a usable store' {
    $store = Import-PSTermProfiles -Root $sandbox
    Assert-Equal 2 $store.version
    Assert-True (@($store.profiles).Count -gt 0) 'should seed some starter profiles'
}

Test-Case 'profiles round-trip through disk' {
    $store = Import-PSTermProfiles -Root $sandbox
    $p = New-PSTermProfile -Name 'round-trip' -Type 'SSH'
    $p.ssh.host = 'rt.example'
    $p.folder = 'Lab/Core'
    Set-PSTermProfile -Store $store -Profile $p | Out-Null
    Save-PSTermProfiles -Root $sandbox -Store $store

    $reloaded = Import-PSTermProfiles -Root $sandbox
    $found = Get-PSTermProfileByName -Store $reloaded -Name 'round-trip'
    Assert-True ([bool]$found) 'profile should survive a save and reload'
    Assert-Equal 'rt.example' $found.ssh.host
    Assert-Equal 'Lab/Core' $found.folder
}

Test-Case 'saving an existing profile replaces rather than duplicates it' {
    $store = Import-PSTermProfiles -Root $sandbox
    $p = Get-PSTermProfileByName -Store $store -Name 'round-trip'
    $p.ssh.host = 'changed.example'
    Set-PSTermProfile -Store $store -Profile $p | Out-Null
    Save-PSTermProfiles -Root $sandbox -Store $store

    $reloaded = Import-PSTermProfiles -Root $sandbox
    $matches = @(@($reloaded.profiles) | Where-Object { $_.name -eq 'round-trip' })
    Assert-Equal 1 $matches.Count 'there should be exactly one'
    Assert-Equal 'changed.example' $matches[0].ssh.host
}

Test-Case 'deleting removes the profile' {
    $store = Import-PSTermProfiles -Root $sandbox
    $p = Get-PSTermProfileByName -Store $store -Name 'round-trip'
    Remove-PSTermProfile -Store $store -Id $p.id | Out-Null
    Save-PSTermProfiles -Root $sandbox -Store $store
    $reloaded = Import-PSTermProfiles -Root $sandbox
    Assert-Equal $null (Get-PSTermProfileByName -Store $reloaded -Name 'round-trip')
}

Test-Case 'folders are listed for the session tree' {
    $store = Import-PSTermProfiles -Root $sandbox
    $a = New-PSTermProfile -Name 'f1'; $a.folder = 'Site A'
    $b = New-PSTermProfile -Name 'f2'; $b.folder = 'Site B'
    $c = New-PSTermProfile -Name 'f3'; $c.folder = 'Site A'
    foreach ($p in @($a,$b,$c)) { Set-PSTermProfile -Store $store -Profile $p | Out-Null }
    $folders = @(Get-PSTermFolders -Store $store)
    Assert-True ($folders -contains 'Site A') 'Site A missing'
    Assert-True ($folders -contains 'Site B') 'Site B missing'
    Assert-Equal 1 (@($folders | Where-Object { $_ -eq 'Site A' }).Count) 'folders should be distinct'
}

Test-Case 'a corrupt store is set aside, not destroyed, and does not stop startup' {
    $bad = Join-Path ([System.IO.Path]::GetTempPath()) ("psterm-bad-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path (Join-Path $bad 'Profiles') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $bad 'Profiles\profiles.json') -Value '{ this is not json'

    $store = Import-PSTermProfiles -Root $bad -WarningAction SilentlyContinue
    Assert-True (@($store.profiles).Count -gt 0) 'should fall back to a fresh store'
    $kept = @(Get-ChildItem -LiteralPath (Join-Path $bad 'Profiles') -Filter '*.corrupt-*')
    Assert-True ($kept.Count -eq 1) 'the unreadable file should be kept for recovery'
    Remove-Item -LiteralPath $bad -Recurse -Force -ErrorAction SilentlyContinue
}

# --------------------------------------------------------- v1 migration -----

Write-Host "`nMigration from v1" -ForegroundColor Yellow

$v1Json = @'
[
  {
    "Name": "Lab-Switch", "Type": "Serial", "COMPort": "COM7", "BaudRate": 115200,
    "DataBits": 8, "Parity": "None", "StopBits": "One", "Handshake": "XOnXOff",
    "RTSEnable": true, "Host": "", "User": "", "SshPort": 22, "TelnetPort": 23,
    "TextColor": "White", "BackgroundColor": "Black", "CursorSize": "Normal",
    "AutoInput": "terminal length 0\nshow version", "BackgroundLogging": true,
    "LogFilePath": "C:\\logs\\lab.log", "RawLogData": false,
    "ObfuscatePasswords": true, "KeepAlive": true, "ForceTerminalColors": true
  },
  {
    "Name": "Edge-Router", "Type": "SSH", "COMPort": "", "BaudRate": 9600,
    "Host": "10.0.0.1", "User": "netops", "SshPort": 2222, "TelnetPort": 23,
    "BackgroundLogging": false, "LogFilePath": "", "RawLogData": true,
    "ObfuscatePasswords": false, "KeepAlive": false, "ForceTerminalColors": false
  },
  {
    "Name": "Console-Server", "Type": "Telnet", "Host": "ts1.lab", "TelnetPort": 2001,
    "BackgroundLogging": false, "KeepAlive": true
  }
]
'@

$migrationRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("psterm-v1-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $migrationRoot 'Profiles') -Force | Out-Null
Set-Content -LiteralPath (Join-Path $migrationRoot 'Profiles\profiles.json') -Value $v1Json -Encoding UTF8

$migrated = Import-PSTermProfiles -Root $migrationRoot

Test-Case 'a v1 file is detected and converted' {
    Assert-Equal 2 $migrated.version
    Assert-Equal 3 (@($migrated.profiles).Count)
}

Test-Case 'the original v1 file is kept as a backup' {
    $backup = Join-Path $migrationRoot 'Profiles\profiles.json.v1-backup'
    Assert-True (Test-Path -LiteralPath $backup) 'the v1 file should be preserved'
}

Test-Case 'serial settings carry over, including the handshake v1 never applied' {
    $p = Get-PSTermProfileByName -Store $migrated -Name 'Lab-Switch'
    Assert-Equal 'Serial' $p.type
    Assert-Equal 'COM7' $p.serial.portName
    Assert-Equal 115200 $p.serial.baudRate
    Assert-Equal 'XOnXOff' $p.serial.handshake
    Assert-True ([bool]$p.serial.rtsEnable) 'RTSEnable was stored in v1 but never used; it is now real'
}

Test-Case 'SSH host, user and port carry over' {
    $p = Get-PSTermProfileByName -Store $migrated -Name 'Edge-Router'
    Assert-Equal 'SSH' $p.type
    Assert-Equal '10.0.0.1' $p.ssh.host
    Assert-Equal 'netops' $p.ssh.user
    Assert-Equal 2222 $p.ssh.port
}

Test-Case 'telnet host and port carry over' {
    $p = Get-PSTermProfileByName -Store $migrated -Name 'Console-Server'
    Assert-Equal 'Telnet' $p.type
    Assert-Equal 'ts1.lab' $p.telnet.host
    Assert-Equal 2001 $p.telnet.port
}

Test-Case 'the v1 KeepAlive flag becomes a real interval' {
    $on = Get-PSTermProfileByName -Store $migrated -Name 'Lab-Switch'
    $off = Get-PSTermProfileByName -Store $migrated -Name 'Edge-Router'
    Assert-Equal 30 $on.ssh.keepAliveSeconds
    Assert-Equal 0 $off.ssh.keepAliveSeconds
}

Test-Case 'AutoInput becomes a list of lines' {
    $p = Get-PSTermProfileByName -Store $migrated -Name 'Lab-Switch'
    $lines = @($p.autoInput)
    Assert-Equal 2 $lines.Count
    Assert-Equal 'terminal length 0' $lines[0]
    Assert-Equal 'show version' $lines[1]
}

Test-Case 'logging settings carry over, RawLogData becoming a format' {
    $a = Get-PSTermProfileByName -Store $migrated -Name 'Lab-Switch'
    Assert-True ([bool]$a.logging.enabled) 'logging should stay on'
    Assert-Equal 'C:\logs\lab.log' $a.logging.pathTemplate
    Assert-Equal 'PlainText' $a.logging.format
    Assert-True ([bool]$a.logging.maskPasswords) 'ObfuscatePasswords should carry over'

    $b = Get-PSTermProfileByName -Store $migrated -Name 'Edge-Router'
    Assert-Equal 'Raw' $b.logging.format
}

Test-Case 'every migrated profile gets an id' {
    foreach ($p in @($migrated.profiles)) {
        Assert-True ([bool]$p.id) "profile '$($p.name)' has no id"
    }
}

Test-Case 'migrating twice does not happen - the file is v2 afterwards' {
    $again = Import-PSTermProfiles -Root $migrationRoot
    Assert-Equal 3 (@($again.profiles).Count)
    Assert-Equal 'COM7' (Get-PSTermProfileByName -Store $again -Name 'Lab-Switch').serial.portName
}

Remove-Item -LiteralPath $migrationRoot -Recurse -Force -ErrorAction SilentlyContinue

# --------------------------------------------- forward compatibility --------

Write-Host "`nSchema tolerance" -ForegroundColor Yellow

Test-Case 'a profile missing newer fields is filled from the defaults' {
    $partial = [pscustomobject]@{
        id = 'abc'; name = 'sparse'; type = 'SSH'
        ssh = [pscustomobject]@{ host = 'h1' }
    }
    $merged = Merge-PSTermProfileDefaults -Profile $partial
    Assert-Equal 'h1' $merged.ssh.host
    Assert-Equal 22 $merged.ssh.port            'port should come from the defaults'
    Assert-Equal 'Utf8' $merged.terminal.encoding 'terminal section should be defaulted'
    Assert-True ($null -ne $merged.logging) 'logging section should exist'
}

Test-Case 'an unknown field is preserved rather than dropped' {
    $withExtra = [pscustomobject]@{ id='x'; name='n'; type='SSH'; somethingNew = 'keep me' }
    $merged = Merge-PSTermProfileDefaults -Profile $withExtra
    Assert-Equal 'keep me' $merged.somethingNew
}

# ------------------------------------------------------------- secrets ------

Write-Host "`nCredential store" -ForegroundColor Yellow

Test-Case 'DPAPI is available' {
    Assert-True (Test-PSTermDpapiAvailable) 'ProtectedData should be usable'
}

Test-Case 'a secret round-trips and is not stored in clear text' {
    Set-PSTermSecret -Root $sandbox -Key 'test-key' -Value 'correct horse battery staple' | Out-Null
    Assert-Equal 'correct horse battery staple' (Get-PSTermSecret -Root $sandbox -Key 'test-key')

    $raw = Get-Content -Raw -LiteralPath (Get-PSTermSecretPath -Root $sandbox)
    Assert-True ($raw -notmatch 'correct horse') 'the secret must not appear in the file'
}

Test-Case 'an unknown key returns nothing rather than throwing' {
    Assert-Equal $null (Get-PSTermSecret -Root $sandbox -Key 'no-such-key')
    Assert-Equal $null (Get-PSTermSecret -Root $sandbox -Key '')
}

Test-Case 'a secret can be removed' {
    Remove-PSTermSecret -Root $sandbox -Key 'test-key'
    Assert-Equal $null (Get-PSTermSecret -Root $sandbox -Key 'test-key')
}

# ---------------------------------------------------------- ssh_config ------

Write-Host "`nssh_config import" -ForegroundColor Yellow

Test-Case 'Host entries become profiles and patterns are skipped' {
    $cfg = Join-Path $sandbox 'ssh_config'
    Set-Content -LiteralPath $cfg -Encoding UTF8 -Value @'
# a comment
Host *
    ForwardAgent yes

Host bastion
    HostName bastion.example.net
    User jump
    Port 2200
    IdentityFile ~/.ssh/id_ed25519

Host inner
    HostName 10.1.2.3
    ProxyJump bastion
    Compression yes
'@
    $hosts = @(Import-SshConfigHosts -Path $cfg)
    Assert-Equal 2 $hosts.Count 'the * pattern should be skipped'

    $bastion = $hosts | Where-Object { $_.name -eq 'bastion' }
    Assert-Equal 'bastion.example.net' $bastion.ssh.host
    Assert-Equal 'jump' $bastion.ssh.user
    Assert-Equal 2200 $bastion.ssh.port

    $inner = $hosts | Where-Object { $_.name -eq 'inner' }
    Assert-Equal '10.1.2.3' $inner.ssh.host
    Assert-Equal 'bastion' $inner.ssh.proxyJump
    Assert-True ([bool]$inner.ssh.compression) 'Compression yes should carry over'
}

Test-Case 'a missing ssh_config is not an error' {
    Assert-Equal 0 (@(Import-SshConfigHosts -Path (Join-Path $sandbox 'no-such-config')).Count)
}

# ------------------------------------------------------- profile targets ----

Write-Host "`nDisplay helpers" -ForegroundColor Yellow

Test-Case 'the target shown in lists is sensible for each type' {
    $ssh = New-PSTermProfile -Type 'SSH'; $ssh.ssh.host = 'h'; $ssh.ssh.user = 'u'
    Assert-Equal 'u@h' (Get-PSTermProfileTarget -Profile $ssh)

    $ssh.ssh.port = 2222
    Assert-Equal 'u@h:2222' (Get-PSTermProfileTarget -Profile $ssh)

    $ser = New-PSTermProfile -Type 'Serial'; $ser.serial.portName = 'COM4'; $ser.serial.baudRate = 115200
    Assert-Equal 'COM4 @ 115200' (Get-PSTermProfileTarget -Profile $ser)

    $tel = New-PSTermProfile -Type 'Telnet'; $tel.telnet.host = 'ts'; $tel.telnet.port = 23
    Assert-Equal 'ts' (Get-PSTermProfileTarget -Profile $tel)
}

# ----------------------------------------------------- backend building -----

Write-Host "`nBackend construction" -ForegroundColor Yellow

Test-Case 'an SSH profile with no host is refused with a clear message' {
    $p = New-PSTermProfile -Type 'SSH'
    try { New-PSTermBackend -Profile $p | Out-Null; throw 'should have thrown' }
    catch { Assert-True ($_.Exception.Message -match 'no host') "got: $($_.Exception.Message)" }
}

Test-Case 'a serial profile with no port is refused with a clear message' {
    $p = New-PSTermProfile -Type 'Serial'
    try { New-PSTermBackend -Profile $p | Out-Null; throw 'should have thrown' }
    catch { Assert-True ($_.Exception.Message -match 'COM port') "got: $($_.Exception.Message)" }
}

Test-Case 'a bad enum name in a hand-edited profile falls back instead of throwing' {
    $p = New-PSTermProfile -Type 'Serial'
    $p.serial.portName = 'COM1'
    $p.serial.parity = 'NotAParity'
    $p.serial.handshake = 'Nonsense'
    $backend = New-PSTermBackend -Profile $p
    Assert-Equal ([System.IO.Ports.Parity]::None) $backend.Settings.Parity
    Assert-Equal ([System.IO.Ports.Handshake]::None) $backend.Settings.Handshake
    $backend.Dispose()
}

Test-Case 'a shell profile with no command line gets a sensible default' {
    $p = New-PSTermProfile -Type 'Shell'
    $backend = New-PSTermBackend -Profile $p
    Assert-True ([bool]$backend.Description) 'should still describe itself'
    $backend.Dispose()
}

Test-Case 'key encoder settings come from the profile' {
    $p = New-PSTermProfile
    $p.terminal.backspace = 'Backspace'
    $p.terminal.functionKeys = 'Vt220'
    $encoder = New-PSTermKeyEncoder -Profile $p
    Assert-Equal ([PSTerm.Vt.BackspaceMode]::Backspace) $encoder.Settings.Backspace
    Assert-Equal ([PSTerm.Vt.FunctionKeyMode]::Vt220) $encoder.Settings.FunctionKeys
}

}
finally {
    Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("-" * 60)
$total = $script:Passed + $script:Failed
if ($script:Failed -eq 0) {
    Write-Host "All $total profile tests passed." -ForegroundColor Green
    exit 0
}
else {
    Write-Host "$($script:Failed) of $total profile tests FAILED." -ForegroundColor Red
    Write-Host ""
    foreach ($f in $script:Failures) { Write-Host $f -ForegroundColor Red }
    exit 1
}
