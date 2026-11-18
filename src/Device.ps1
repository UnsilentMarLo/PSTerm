<#
.SYNOPSIS
    Driving network devices from code: connect, run commands, read the result, push
    configuration safely, and keep dated copies of a configuration.

.DESCRIPTION
    These are the functions a plugin or a script uses. They sit on DeviceSession in the
    compiled core, which works the same over a serial port, Telnet and SSH, so a script
    does not care how it reached the device.

    Nothing here touches a window. A session can run beside the terminal tabs, or with no
    window at all.
#>

Set-StrictMode -Version Latest

function Get-PSTermDriver {
    <#
    .SYNOPSIS
        Load a device driver by name. Drivers are JSON files; one placed in a Drivers
        folder next to PSTerm.ps1 overrides the built-in one of the same name.
    #>
    [CmdletBinding()]
    param([string]$Name = 'cisco-ios', [string]$Root = '')

    $candidates = @()
    if ($Root) { $candidates += (Join-Path $Root "Drivers\$Name.json") }
    $candidates += (Join-Path $PSScriptRoot "Drivers\$Name.json")

    $path = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $path) { throw "There is no device driver called '$Name'." }

    $data = Get-Content -Raw -LiteralPath $path -Encoding UTF8 | ConvertFrom-Json
    $driver = New-Object PSTerm.Automation.DeviceDriver
    foreach ($prop in $data.PSObject.Properties) {
        $field = $driver.GetType().GetField(($prop.Name.Substring(0, 1).ToUpperInvariant() + $prop.Name.Substring(1)))
        if ($field -and $field.FieldType -eq [string]) { $field.SetValue($driver, [string]$prop.Value) }
    }
    $driver
}

function Connect-PSTermDevice {
    <#
    .SYNOPSIS
        Open a session to a device and get it to a usable prompt.
    .PARAMETER Profile
        A connection profile (SSH, Telnet or Serial).
    .PARAMETER Credential
        The name of a quick credential to log in with: its user name and secret are used.
        Without it the profile's own user and password (or its folder's) are used.
    .PARAMETER EnableCredential
        The name of a quick credential holding the enable password.
    .PARAMETER Enter
        Enter privileged mode after login.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)]$Store,
        [Parameter(Mandatory)][string]$Root,
        [string]$Credential = '',
        [string]$EnableCredential = '',
        [string]$DriverName = 'cisco-ios',
        [switch]$Enter,
        [switch]$AcceptHostKey,
        [int]$TimeoutSec = 30
    )

    $login = Resolve-PSTermDeviceLogin -Profile $Profile -Store $Store -Root $Root -Credential $Credential -EnableCredential $EnableCredential
    $driver = Get-PSTermDriver -Name $DriverName -Root $Root
    Open-PSTermDeviceSession -Profile $Profile -Login $login -Driver $driver -Enter:$Enter -AcceptHostKey:$AcceptHostKey -TimeoutSec $TimeoutSec
}

function Resolve-PSTermDeviceLogin {
    <#
    .SYNOPSIS
        Work out the user name, password and enable password for a device from the
        profile, its folder and the named quick credentials. Nothing is typed anywhere
        yet; the result goes to Open-PSTermDeviceSession.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)]$Store,
        [Parameter(Mandatory)][string]$Root,
        [string]$Credential = '',
        [string]$EnableCredential = ''
    )

    $login = Resolve-PSTermLogin -Store $Store -Root $Root -Profile $Profile
    $user = [string]$login.User
    $password = $login.Password

    if ($Credential) {
        $cred = @($Store.credentials) | Where-Object { $_.name -eq $Credential } | Select-Object -First 1
        if (-not $cred) { throw "There is no quick credential called '$Credential'." }
        if ($cred.username) { $user = [string]$cred.username }
        $password = Get-PSTermSecret -Root $Root -Key ([string]$cred.secretKey)
    }

    $enablePassword = $null
    if ($EnableCredential) {
        $e = @($Store.credentials) | Where-Object { $_.name -eq $EnableCredential } | Select-Object -First 1
        if (-not $e) { throw "There is no quick credential called '$EnableCredential'." }
        $enablePassword = Get-PSTermSecret -Root $Root -Key ([string]$e.secretKey)
    }
    [pscustomobject]@{ User = $user; Password = $password; EnablePassword = $enablePassword }
}

function Open-PSTermDeviceSession {
    <#
    .SYNOPSIS
        Open a device session with an already-resolved login. Also what the plugin host
        runs in its worker threads, which is why it takes the driver and the login as
        objects instead of looking them up.
    .PARAMETER ReadOnly
        Make the session refuse every command that is not a look-only command. Done before
        anything else can be sent, and it cannot be undone.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)]$Login,
        [Parameter(Mandatory)]$Driver,
        [switch]$Enter,
        [switch]$AcceptHostKey,
        [switch]$ReadOnly,
        [int]$TimeoutSec = 30,
        # A table the session is put in as soon as it exists, so whoever started this can close
        # it while it is still logging in (the plugin host does, on a timeout or Stop).
        [hashtable]$Publish
    )

    $user = [string]$Login.User
    if ($Profile.type -eq 'SSH') {
        if (-not $user) { throw "No user name is known for '$($Profile.name)'." }
        if ($AcceptHostKey) { $Profile = Copy-PSTermObject -Value $Profile; $Profile.ssh.autoAcceptHostKey = $true }
    }

    # A wide virtual screen, so a long line is not broken by the pseudo-console.
    $backend = New-PSTermBackend -Profile $Profile -Cols 250 -Rows 60 -User $user
    $encoding = if ($Profile.type -eq 'Serial') { [PSTerm.Vt.TerminalEncoding]::Latin1 } else { [PSTerm.Vt.TerminalEncoding]::Utf8 }
    $session = New-Object PSTerm.Automation.DeviceSession($backend, $Driver, $encoding)
    if ($ReadOnly) { $session.MakeReadOnly() }
    if ($Publish) { $Publish['Session'] = $session }

    try { $session.Connect() }
    catch { $session.Dispose(); throw }

    $problem = $session.Open($user, $Login.Password, $Login.EnablePassword, [bool]$Enter, $TimeoutSec * 1000)
    if ($problem) {
        $session.Dispose()
        throw "Could not log in to '$($Profile.name)': $problem"
    }
    $session.DisablePager()
    $session
}
function Get-PSTermSessionHostname {
    <#
    .SYNOPSIS
        The device's own name, read from its prompt: "lab-core#" and "lab-core(config-if)#" are "lab-core".
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Session)
    $p = [string]$Session.Prompt
    $p = $p -replace '\(.*\)\s*[>#]\s*$', '' -replace '\s*[>#]\s*$', ''
    $p.Trim()
}

function Disconnect-PSTermDevice {
    param([Parameter(Mandatory)]$Session)
    try { $Session.Dispose() } catch { }
}

function Invoke-PSTermCommand {
    <#
    .SYNOPSIS
        Run one or more commands and return their results.
    .OUTPUTS
        One result per command: Command, Lines, Text, Prompt, Error, TimedOut, Succeeded.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Session,
        [Parameter(Mandatory, ValueFromPipeline)][string[]]$Command,
        [int]$TimeoutSec = 30,
        [switch]$Confirm,
        # What to answer a "[yes/no]" question with, when -Confirm is given.
        [ValidateSet('no', 'yes')][string]$YesNo = 'no',
        [switch]$ThrowOnError
    )
    process {
        foreach ($c in $Command) {
            $result = $Session.Invoke($c, $TimeoutSec * 1000, [bool]$Confirm, $YesNo)
            if ($ThrowOnError -and -not $result.Succeeded) {
                $why = if ($result.TimedOut) { 'it did not finish' } else { $result.Error }
                throw "'$c' failed: $why"
            }
            $result
        }
    }
}

function Send-PSTermConfig {
    <#
    .SYNOPSIS
        Apply configuration lines, optionally under a rollback timer.
    .DESCRIPTION
        Without -Safe the lines are simply applied and the session is left out of
        configuration mode.

        With -Safe the device is told to reload in a few minutes before anything is
        changed. If the change leaves it reachable (-Verify returns $true, or no check
        was given) the reload is cancelled and, with -Save, the configuration is written.
        If -Verify says the way in is gone, nothing cancels the timer: the device
        reloads and comes back with its saved configuration. That only protects a change
        that has not been saved yet - which is why the save comes last.

        The first line the device refuses stops the run, so a half-applied block is
        reported rather than carried on past. The timer is cancelled in that case,
        because the device is plainly still reachable.
    .OUTPUTS
        Applied (lines accepted), Failed (the line that was refused, or $null), Error,
        RolledBack (timer left running), Saved, Sent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Session,
        [Parameter(Mandatory)][string[]]$Line,
        [switch]$Safe,
        [int]$RollbackMinutes = 5,
        [scriptblock]$Verify,
        [switch]$Save,
        [switch]$DryRun
    )

    $driver = $Session.Driver
    $result = [pscustomobject]@{ Applied = 0; Failed = $null; Error = ''; RolledBack = $false; Saved = $false; Sent = @() }

    $clean = @($Line | ForEach-Object { $_.TrimEnd() } | Where-Object { $_ -and -not $_.TrimStart().StartsWith('!') })
    if ($DryRun) { $result.Sent = $clean; return $result }

    if ($Session.Mode -eq 'User') { throw 'The session is not in privileged mode.' }

    $armed = $false
    if ($Safe) {
        $r = $Session.Invoke(($driver.ReloadInCommand -replace '\{minutes\}', $RollbackMinutes), 15000, $true)
        if (-not $r.Succeeded) { throw "The rollback timer could not be armed: $($r.Error)" }
        $armed = $true
    }

    $null = $Session.Invoke($driver.ConfigureCommand, 10000)
    foreach ($text in $clean) {
        $r = $Session.Invoke($text, 20000, $true)
        if (-not $r.Succeeded) {
            $result.Failed = $text
            $result.Error = if ($r.TimedOut) { 'The device did not answer.' } else { $r.Error }
            break
        }
        $result.Applied++
        $result.Sent += $text
    }
    $null = $Session.Invoke($driver.EndConfigCommand, 10000)

    if ($armed) {
        $healthy = ($null -eq $result.Failed)
        if ($healthy -and $Verify) { try { $healthy = [bool](& $Verify) } catch { $healthy = $false } }
        if ($healthy -or $null -ne $result.Failed) {
            $null = $Session.Invoke($driver.ReloadCancelCommand, 10000, $true)
        }
        else {
            $result.RolledBack = $true
        }
    }

    if ($Save -and -not $result.RolledBack -and $null -eq $result.Failed) {
        $r = $Session.Invoke($driver.SaveCommand, 60000, $true, 'yes')
        $result.Saved = $r.Succeeded
    }
    $result
}

# =============================================================================
# Configuration copies
# =============================================================================

function Get-PSTermRunningConfig {
    <#
    .SYNOPSIS
        The running configuration without the lines that change by themselves
        (timestamps, byte counts), so two copies differ only where the configuration did.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Session, [string[]]$Volatile)

    # A log message the device prints while the configuration scrolls by can cut a line in two,
    # so a copy that saw one is taken again. A configuration never contains such a line itself.
    $result = $null
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        $result = $Session.Invoke('show running-config', 120000)
        if (-not $result.Succeeded) { throw "show running-config failed: $(if ($result.TimedOut) { 'it did not finish' } else { $result.Error })" }
        if (-not $result.NoiseSeen) { break }
        if ($attempt -eq 4) { throw 'The device kept printing log messages into the configuration, so no clean copy could be taken. Try again in a moment.' }
        Start-Sleep -Milliseconds 1500
    }

    if (-not $Volatile) {
        $Volatile = @('^Building configuration', '^Current configuration\s*:', '^! Last configuration change', '^! NVRAM config last updated', '^! No configuration change since', '^ntp clock-period')
    }
    @($result.Lines | Where-Object {
        $line = $_
        -not ($Volatile | Where-Object { $line -match $_ })
    })
}

function Save-PSTermConfigBackup {
    <#
    .SYNOPSIS
        Write the running configuration to a dated file and say how it differs from the
        previous copy.
    .OUTPUTS
        Path, Changed, Added, Removed, Previous.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Session, [Parameter(Mandatory)][string]$Folder, [Parameter(Mandatory)][string]$Name)

    $safeName = $Name -replace '[\\/:*?"<>|]', '_'
    $dir = Join-Path $Folder $safeName
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $config = @(Get-PSTermRunningConfig -Session $Session)
    if ($config.Count -lt 3) { throw 'The configuration that came back is too short to be a configuration.' }

    $previous = Get-ChildItem -LiteralPath $dir -Filter '*.cfg' -File | Sort-Object Name | Select-Object -Last 1
    $path = Join-Path $dir ("{0}-{1}.cfg" -f $safeName, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    [System.IO.File]::WriteAllLines($path, $config, (New-Object System.Text.UTF8Encoding($false)))

    $added = @(); $removed = @()
    if ($previous) {
        $old = @(Get-Content -LiteralPath $previous.FullName -Encoding UTF8)
        foreach ($d in (Compare-Object -ReferenceObject $old -DifferenceObject $config)) {
            if ($d.SideIndicator -eq '=>') { $added += $d.InputObject } else { $removed += $d.InputObject }
        }
    }
    [pscustomobject]@{
        Path     = $path
        Changed  = ($added.Count + $removed.Count) -gt 0
        Added    = $added
        Removed  = $removed
        Previous = if ($previous) { $previous.FullName } else { $null }
    }
}
