<#
.SYNOPSIS
    Turns a profile into a live session, and parses quick-connect strings.
#>

Set-StrictMode -Version Latest

function ConvertTo-PSTermEnum {
    <#
    .SYNOPSIS
        Parse an enum value by name, falling back to a default rather than throwing.
    .DESCRIPTION
        Profile files are hand-editable, so a typo should degrade to the default
        instead of preventing the session from opening.
    #>
    param(
        [Parameter(Mandatory)][type]$Type,
        [AllowEmptyString()][AllowNull()][string]$Name,
        [Parameter(Mandatory)]$Default
    )
    if ([string]::IsNullOrWhiteSpace($Name)) { return $Default }
    try { return [Enum]::Parse($Type, $Name, $true) }
    catch { return $Default }
}

function New-PSTermBackend {
    <#
    .SYNOPSIS
        Build the transport described by a profile.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Profile,
        [int]$Cols = 80,
        [int]$Rows = 24
    )

    switch ($Profile.type) {

        'SSH' {
            if ([string]::IsNullOrWhiteSpace($Profile.ssh.host)) {
                throw 'This SSH profile has no host set.'
            }

            $options = New-Object PSTerm.Backends.SshLaunchOptions
            $options.Host = $Profile.ssh.host
            $options.User = $Profile.ssh.user
            $options.Port = [int]$Profile.ssh.port
            $options.IdentityFile = $Profile.ssh.identityFile
            $options.ProxyJump = $Profile.ssh.proxyJump
            $options.RemoteCommand = $Profile.ssh.remoteCommand
            $options.ForwardAgent = [bool]$Profile.ssh.forwardAgent
            $options.Compression = [bool]$Profile.ssh.compression
            $options.AllowLegacyAlgorithms = [bool]$Profile.ssh.allowLegacyAlgorithms
            $options.KeepAliveSeconds = [int]$Profile.ssh.keepAliveSeconds
            foreach ($extra in @($Profile.ssh.extraOptions)) {
                if ($extra) { $options.ExtraOptions.Add([string]$extra) }
            }

            $commandLine = [PSTerm.Backends.ConPtyCommands]::BuildSshCommandLine($options)
            $label = if ($Profile.ssh.user) { "$($Profile.ssh.user)@$($Profile.ssh.host)" } else { $Profile.ssh.host }

            $backend = New-Object PSTerm.Backends.ConPtyBackend($commandLine, $null, $label)
            $backend.SetInitialSize($Cols, $Rows)
            return $backend
        }

        'Telnet' {
            if ([string]::IsNullOrWhiteSpace($Profile.telnet.host)) {
                throw 'This Telnet profile has no host set.'
            }

            $settings = New-Object PSTerm.Backends.TelnetSettings
            $settings.Host = $Profile.telnet.host
            $settings.Port = [int]$Profile.telnet.port
            $settings.TerminalType = $Profile.telnet.terminalType
            $settings.ActiveNegotiation = [bool]$Profile.telnet.activeNegotiation
            $settings.Binary = [bool]$Profile.telnet.binary
            $settings.KeepAliveSeconds = [int]$Profile.telnet.keepAliveSeconds

            $backend = New-Object PSTerm.Backends.TelnetBackend($settings)
            $backend.SetInitialSize($Cols, $Rows)
            return $backend
        }

        'Serial' {
            if ([string]::IsNullOrWhiteSpace($Profile.serial.portName)) {
                throw 'This serial profile has no COM port set.'
            }

            $settings = New-Object PSTerm.Backends.SerialSettings
            $settings.PortName = $Profile.serial.portName
            $settings.BaudRate = [int]$Profile.serial.baudRate
            $settings.DataBits = [int]$Profile.serial.dataBits
            $settings.Parity    = ConvertTo-PSTermEnum ([System.IO.Ports.Parity])    $Profile.serial.parity    ([System.IO.Ports.Parity]::None)
            $settings.StopBits  = ConvertTo-PSTermEnum ([System.IO.Ports.StopBits])  $Profile.serial.stopBits  ([System.IO.Ports.StopBits]::One)
            $settings.Handshake = ConvertTo-PSTermEnum ([System.IO.Ports.Handshake]) $Profile.serial.handshake ([System.IO.Ports.Handshake]::None)
            $settings.DtrEnable = [bool]$Profile.serial.dtrEnable
            $settings.RtsEnable = [bool]$Profile.serial.rtsEnable
            $settings.ReconnectOnDisconnect = [bool]$Profile.serial.reconnect

            return New-Object PSTerm.Backends.SerialBackend($settings)
        }

        'Shell' {
            $commandLine = $Profile.shell.commandLine
            if ([string]::IsNullOrWhiteSpace($commandLine)) { $commandLine = 'powershell.exe -NoLogo' }

            $workingDir = $Profile.shell.workingDirectory
            if ([string]::IsNullOrWhiteSpace($workingDir)) { $workingDir = $null }

            $backend = New-Object PSTerm.Backends.ConPtyBackend($commandLine, $workingDir, $Profile.name)
            $backend.SetInitialSize($Cols, $Rows)
            return $backend
        }

        default { throw "Unknown connection type '$($Profile.type)'." }
    }
}

function New-PSTermKeyEncoder {
    param([Parameter(Mandatory)]$Profile)

    $settings = New-Object PSTerm.Vt.KeyEncoderSettings
    $settings.Backspace    = ConvertTo-PSTermEnum ([PSTerm.Vt.BackspaceMode])   $Profile.terminal.backspace    ([PSTerm.Vt.BackspaceMode]::Delete)
    $settings.FunctionKeys = ConvertTo-PSTermEnum ([PSTerm.Vt.FunctionKeyMode]) $Profile.terminal.functionKeys ([PSTerm.Vt.FunctionKeyMode]::Xterm)
    $settings.AltSendsEscape = [bool]$Profile.terminal.altSendsEscape
    $settings.EnterSendsCrLf = [bool]$Profile.terminal.enterSendsCrLf

    New-Object PSTerm.Vt.KeyEncoder($settings)
}

function New-PSTermLogger {
    <#
    .SYNOPSIS
        Build a session logger for a profile, or return $null when logging is off.
    #>
    param(
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)][string]$Root,
        # Receives the reason when logging was requested but could not be started, so
        # the caller can say so. A warning stream is no use: there is no console.
        [ref]$Failure
    )

    if (-not $Profile.logging.enabled) { return $null }

    $options = New-Object PSTerm.Io.SessionLoggerOptions

    # A relative template is resolved against the install folder, keeping logs
    # with the portable install rather than scattering them.
    $template = [string]$Profile.logging.pathTemplate
    if (-not [System.IO.Path]::IsPathRooted(($template -replace '\{[^}]*\}', 'x'))) {
        $template = Join-Path $Root $template
    }

    $options.PathTemplate  = $template
    $options.Format        = ConvertTo-PSTermEnum ([PSTerm.Io.LogFormat]) $Profile.logging.format ([PSTerm.Io.LogFormat]::PlainText)
    $options.IncludeInput  = [bool]$Profile.logging.includeInput
    $options.MaskPasswords = [bool]$Profile.logging.maskPasswords
    $options.MaxBytes      = [long]$Profile.logging.maxBytes
    $options.Append        = [bool]$Profile.logging.append

    $tokens = New-Object 'System.Collections.Generic.Dictionary[string,string]'
    $tokens['name']    = [string]$Profile.name
    $tokens['session'] = [string]$Profile.name
    $tokens['host']    = switch ($Profile.type) {
        'Telnet' { [string]$Profile.telnet.host }
        'Serial' { [string]$Profile.serial.portName }
        'Shell'  { 'local' }
        default  { [string]$Profile.ssh.host }
    }
    $tokens['user'] = [string]$Profile.ssh.user
    $tokens['port'] = switch ($Profile.type) {
        'Telnet' { [string]$Profile.telnet.port }
        'Serial' { [string]$Profile.serial.portName }
        'Shell'  { 'local' }
        default  { [string]$Profile.ssh.port }
    }

    try {
        New-Object PSTerm.Io.SessionLogger($options, $tokens)
    }
    catch {
        # Logging must never prevent a connection.
        if ($Failure) { $Failure.Value = $_.Exception.Message }
        $null
    }
}

function ConvertFrom-PSTermQuickConnect {
    <#
    .SYNOPSIS
        Parse a quick-connect string into a profile.

    .DESCRIPTION
        Typing the destination is the fastest way to open a session and avoids a
        dialog entirely. Accepted forms:

            user@host                 SSH on port 22
            host:2222                 SSH on a given port
            ssh user@host -p 2222     SSH with an explicit port
            telnet host               Telnet on port 23
            telnet host 2323          Telnet on a given port
            com3                      Serial at 9600
            com3:115200               Serial at a given speed
            cmd | powershell | pwsh | wsl | bash    a local shell

    .OUTPUTS
        A profile object, or $null when the text cannot be interpreted.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $text = $Text.Trim()
    if (-not $text) { return $null }

    # --- local shells -----------------------------------------------------
    $shells = @{
        'cmd'        = 'cmd.exe'
        'powershell' = 'powershell.exe -NoLogo'
        'pwsh'       = 'pwsh.exe -NoLogo'
        'wsl'        = 'wsl.exe'
        'bash'       = 'bash.exe'
    }
    if ($shells.ContainsKey($text.ToLowerInvariant())) {
        $p = New-PSTermProfile -Name $text.ToLowerInvariant() -Type 'Shell'
        $p.shell.commandLine = $shells[$text.ToLowerInvariant()]
        return $p
    }

    # --- serial: COM3 or COM3:115200 --------------------------------------
    if ($text -match '^(?<port>COM\d+)(?:[:\s]+(?<baud>\d+))?$') {
        $p = New-PSTermProfile -Name $Matches['port'].ToUpperInvariant() -Type 'Serial'
        $p.serial.portName = $Matches['port'].ToUpperInvariant()
        if ($Matches['baud']) { $p.serial.baudRate = [int]$Matches['baud'] }
        return $p
    }

    # --- telnet -----------------------------------------------------------
    if ($text -match '^telnet\s+(?<host>[^\s:]+)(?:[:\s]+(?<port>\d+))?$') {
        $p = New-PSTermProfile -Name $Matches['host'] -Type 'Telnet'
        $p.telnet.host = $Matches['host']
        if ($Matches['port']) { $p.telnet.port = [int]$Matches['port'] }
        return $p
    }

    # --- ssh --------------------------------------------------------------
    $sshText = $text
    $port = 0
    if ($sshText -match '^ssh\s+(?<rest>.+)$') { $sshText = $Matches['rest'].Trim() }

    # An explicit -p / -P flag anywhere in the remainder.
    if ($sshText -match '(?:^|\s)-[pP]\s+(?<port>\d+)') {
        $port = [int]$Matches['port']
        $sshText = ($sshText -replace '(?:^|\s)-[pP]\s+\d+', ' ').Trim()
    }

    # Drop any other flags; ssh.exe reads ~/.ssh/config for the rest.
    $sshText = ($sshText -replace '(?:^|\s)-\S+', ' ').Trim()
    if (-not $sshText) { return $null }

    $user = ''
    $hostPart = $sshText
    if ($hostPart -match '^(?<user>[^@\s]+)@(?<host>.+)$') {
        $user = $Matches['user']
        $hostPart = $Matches['host']
    }

    # host:port, but not an IPv6 literal (which has several colons).
    if ($hostPart -match '^(?<host>[^:\s]+):(?<port>\d+)$') {
        $hostPart = $Matches['host']
        if ($port -eq 0) { $port = [int]$Matches['port'] }
    }

    $hostPart = $hostPart.Trim()
    if (-not $hostPart -or $hostPart -match '\s') { return $null }

    $name = if ($user) { "$user@$hostPart" } else { $hostPart }
    $p = New-PSTermProfile -Name $name -Type 'SSH'
    $p.ssh.host = $hostPart
    $p.ssh.user = $user
    if ($port -gt 0) { $p.ssh.port = $port }
    return $p
}

function Get-PSTermProfileTarget {
    <#
    .SYNOPSIS
        The host or port a profile connects to, for display in lists and titles.
    #>
    param([Parameter(Mandatory)]$Profile)

    switch ($Profile.type) {
        'SSH' {
            $target = [string]$Profile.ssh.host
            if ($Profile.ssh.user) { $target = "$($Profile.ssh.user)@$target" }
            if ([int]$Profile.ssh.port -ne 22) { $target = "${target}:$($Profile.ssh.port)" }
            $target
        }
        'Telnet' {
            $target = [string]$Profile.telnet.host
            if ([int]$Profile.telnet.port -ne 23) { $target = "${target}:$($Profile.telnet.port)" }
            $target
        }
        'Serial' {
            "$($Profile.serial.portName) @ $($Profile.serial.baudRate)"
        }
        'Shell' {
            [string]$Profile.shell.commandLine
        }
        default { '' }
    }
}
