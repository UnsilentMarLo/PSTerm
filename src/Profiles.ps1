<#
.SYNOPSIS
    Connection profile storage.

.DESCRIPTION
    Profiles live in one JSON file next to the application, so the whole install
    stays portable: copy the folder and the saved connections come along.

    Changes from v1's format:
      * Profiles are grouped into folders. A flat list is the single most common
        complaint about PuTTY's session manager and becomes unusable past a few
        dozen devices.
      * Settings are nested per transport instead of every profile carrying every
        field for every transport.
      * Passwords are never stored here. A profile holds only a key into the
        DPAPI-protected store (see Secrets.ps1); the compiled core sends it to the
        first password prompt.
      * Fields that do nothing are gone. v1 wrote RTSEnable and TelnetNegotiation
        into every profile and never read either one; both are now real settings.

    v1 files are migrated automatically on first load.
#>

Set-StrictMode -Version Latest

$script:ProfileSchemaVersion = 2

function New-PSTermProfile {
    <#
    .SYNOPSIS
        A profile with every field defaulted. The single definition of the schema.
    #>
    [CmdletBinding()]
    param(
        [string]$Name = 'New connection',
        [ValidateSet('SSH', 'Telnet', 'Serial', 'Shell')]
        [string]$Type = 'SSH'
    )

    [pscustomobject]@{
        id     = [guid]::NewGuid().ToString('N')
        name   = $Name
        folder = ''
        type   = $Type
        notes  = ''

        ssh = [pscustomobject]@{
            host                  = ''
            user                  = ''
            port                  = 22
            identityFile          = ''
            proxyJump             = ''
            forwardAgent          = $false
            compression           = $false
            allowLegacyAlgorithms = $false
            keepAliveSeconds      = 30
            remoteCommand         = ''
            extraOptions          = @()
        }

        telnet = [pscustomobject]@{
            host              = ''
            port              = 23
            terminalType      = 'xterm-256color'
            activeNegotiation = $true
            binary            = $true
            keepAliveSeconds  = 0
        }

        serial = [pscustomobject]@{
            portName     = ''
            baudRate     = 9600
            dataBits     = 8
            parity       = 'None'
            stopBits     = 'One'
            handshake    = 'None'
            dtrEnable    = $true
            rtsEnable    = $true
            reconnect    = $true
        }

        shell = [pscustomobject]@{
            commandLine      = ''
            workingDirectory = ''
        }

        terminal = [pscustomobject]@{
            encoding      = 'Utf8'
            scrollback    = 10000
            backspace     = 'Delete'
            functionKeys  = 'Xterm'
            altSendsEscape = $true
            enterSendsCrLf = $false
            theme         = 'Dark'
            fontFamily    = 'Consolas'
            fontSize      = 10.5
        }

        logging = [pscustomobject]@{
            enabled       = $false
            pathTemplate  = 'Logs\{name}-{date}.log'
            format        = 'PlainText'
            includeInput  = $false
            maskPasswords = $true
            maxBytes      = 0
            append        = $true
        }

        # Lines sent after connecting, as plain text in profiles.json. Never put a
        # password here: use the Password field, which goes to the credential store.
        autoInput = @()

        # Key into the DPAPI store, not the secret itself.
        credentialKey = ''
    }
}

function Get-PSTermProfilePath {
    param([Parameter(Mandatory)][string]$Root)
    Join-Path $Root 'Profiles\profiles.json'
}

function Import-PSTermProfiles {
    <#
    .SYNOPSIS
        Load the profile store, creating or migrating it as needed.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root)

    $path = Get-PSTermProfilePath -Root $Root

    if (-not (Test-Path -LiteralPath $path)) {
        $store = [pscustomobject]@{
            version  = $script:ProfileSchemaVersion
            folders  = @()
            profiles = @(New-PSTermSampleProfiles)
        }
        Save-PSTermProfiles -Root $Root -Store $store
        return $store
    }

    try {
        $raw = Get-Content -Raw -LiteralPath $path -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($raw)) { throw 'The profile file is empty.' }
        $data = $raw | ConvertFrom-Json
    }
    catch {
        # Never destroy the user's file on a parse error: move it aside so it can
        # be recovered, and carry on with a fresh store.
        $backup = "$path.corrupt-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        try { Move-Item -LiteralPath $path -Destination $backup -Force } catch { }
        Write-Warning "Could not read '$path' ($($_.Exception.Message)). It has been kept as '$backup' and a new profile file created."
        $store = [pscustomobject]@{
            version  = $script:ProfileSchemaVersion
            folders  = @()
            profiles = @(New-PSTermSampleProfiles)
        }
        Save-PSTermProfiles -Root $Root -Store $store
        return $store
    }

    # v1 wrote a bare array of flat profile objects.
    if ($data -is [array] -or -not ($data.PSObject.Properties.Name -contains 'version')) {
        Write-Verbose 'Migrating a v1 profile file to the v2 schema.'
        $store = Convert-PSTermV1Profiles -Legacy $data
        $backup = "$path.v1-backup"
        try { Copy-Item -LiteralPath $path -Destination $backup -Force } catch { }
        Save-PSTermProfiles -Root $Root -Store $store
        return $store
    }

    # Fill in anything a newer version added, so an older file still loads.
    $profiles = @()
    foreach ($p in @($data.profiles)) {
        $profiles += (Merge-PSTermProfileDefaults -Profile $p)
    }

    [pscustomobject]@{
        version  = $script:ProfileSchemaVersion
        folders  = @(if ($data.PSObject.Properties.Name -contains 'folders') { $data.folders } else { @() })
        profiles = $profiles
    }
}

function Merge-PSTermProfileDefaults {
    <#
    .SYNOPSIS
        Return a profile with any missing property filled from the defaults.
    .DESCRIPTION
        Lets the schema grow without invalidating files people already have, and
        means the rest of the code can read any field without null checks.
    #>
    param([Parameter(Mandatory)]$Profile)

    $merged = New-PSTermProfile
    foreach ($prop in $Profile.PSObject.Properties) {
        $name = $prop.Name
        if (-not ($merged.PSObject.Properties.Name -contains $name)) {
            Add-Member -InputObject $merged -NotePropertyName $name -NotePropertyValue $prop.Value -Force
            continue
        }

        $default = $merged.$name
        if ($default -is [pscustomobject] -and $prop.Value -is [pscustomobject]) {
            # Nested section: merge field by field so new fields keep their default.
            foreach ($sub in $prop.Value.PSObject.Properties) {
                if ($default.PSObject.Properties.Name -contains $sub.Name) {
                    $default.($sub.Name) = $sub.Value
                }
                else {
                    Add-Member -InputObject $default -NotePropertyName $sub.Name -NotePropertyValue $sub.Value -Force
                }
            }
        }
        else {
            $merged.$name = $prop.Value
        }
    }

    if ([string]::IsNullOrWhiteSpace([string]$merged.id)) {
        $merged.id = [guid]::NewGuid().ToString('N')
    }
    $merged
}

function Convert-PSTermV1Profiles {
    <#
    .SYNOPSIS
        Translate the v1 flat profile format into the v2 schema.
    #>
    param($Legacy)

    $list = @()
    foreach ($old in @($Legacy)) {
        if (-not $old) { continue }

        $type = switch ([string]$old.Type) {
            'Serial' { 'Serial' }
            'Telnet' { 'Telnet' }
            default  { 'SSH' }
        }

        $p = New-PSTermProfile -Name ([string]$old.Name) -Type $type

        function Get-Legacy($obj, $field, $fallback) {
            if ($obj.PSObject.Properties.Name -contains $field -and $null -ne $obj.$field -and "$($obj.$field)" -ne '') {
                return $obj.$field
            }
            $fallback
        }

        $p.ssh.host = [string](Get-Legacy $old 'Host' '')
        $p.ssh.user = [string](Get-Legacy $old 'User' '')
        $p.ssh.port = [int](Get-Legacy $old 'SshPort' 22)

        $p.telnet.host = [string](Get-Legacy $old 'Host' '')
        $p.telnet.port = [int](Get-Legacy $old 'TelnetPort' 23)

        $p.serial.portName  = [string](Get-Legacy $old 'COMPort' '')
        $p.serial.baudRate  = [int](Get-Legacy $old 'BaudRate' 9600)
        $p.serial.dataBits  = [int](Get-Legacy $old 'DataBits' 8)
        $p.serial.parity    = [string](Get-Legacy $old 'Parity' 'None')
        $p.serial.stopBits  = [string](Get-Legacy $old 'StopBits' 'One')
        $p.serial.handshake = [string](Get-Legacy $old 'Handshake' 'None')
        # RTSEnable existed in v1 profiles but was never applied to the port.
        $p.serial.rtsEnable = [bool](Get-Legacy $old 'RTSEnable' $true)

        $keepAlive = [bool](Get-Legacy $old 'KeepAlive' $false)
        $p.ssh.keepAliveSeconds    = if ($keepAlive) { 30 } else { 0 }
        $p.telnet.keepAliveSeconds = if ($keepAlive) { 30 } else { 0 }

        $p.logging.enabled      = [bool](Get-Legacy $old 'BackgroundLogging' $false)
        $logPath = [string](Get-Legacy $old 'LogFilePath' '')
        if ($logPath) { $p.logging.pathTemplate = $logPath }
        $p.logging.format        = if ([bool](Get-Legacy $old 'RawLogData' $false)) { 'Raw' } else { 'PlainText' }
        $p.logging.maskPasswords = [bool](Get-Legacy $old 'ObfuscatePasswords' $true)

        $auto = [string](Get-Legacy $old 'AutoInput' '')
        if ($auto) {
            $p.autoInput = @($auto -split "`r?`n" | Where-Object { $_.Trim() })
        }

        # v1's ForceTerminalColors picked between the 16 console colours. The
        # nearest equivalent is simply which theme the session opens with.
        $p.terminal.theme = 'Dark'

        $list += $p
    }

    [pscustomobject]@{
        version  = $script:ProfileSchemaVersion
        folders  = @()
        profiles = $list
    }
}

function New-PSTermSampleProfiles {
    <#
    .SYNOPSIS
        Starter profiles that demonstrate the shape without pretending to be real hosts.
    #>
    $shell = New-PSTermProfile -Name 'Local PowerShell' -Type 'Shell'
    $shell.folder = 'Local'
    $shell.shell.commandLine = 'powershell.exe -NoLogo'

    $cmd = New-PSTermProfile -Name 'Command Prompt' -Type 'Shell'
    $cmd.folder = 'Local'
    $cmd.shell.commandLine = 'cmd.exe'

    @($shell, $cmd)
}

function Save-PSTermProfiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)]$Store
    )

    $path = Get-PSTermProfilePath -Root $Root
    $dir = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $json = $Store | ConvertTo-Json -Depth 8

    # Write via a temporary file so an interrupted save cannot leave a truncated
    # profile store behind.
    $temp = "$path.tmp"
    Set-Content -LiteralPath $temp -Value $json -Encoding UTF8
    Move-Item -LiteralPath $temp -Destination $path -Force
}

function Get-PSTermProfileByName {
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Name)
    @($Store.profiles) | Where-Object { $_.name -eq $Name } | Select-Object -First 1
}

function Get-PSTermProfileById {
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Id)
    @($Store.profiles) | Where-Object { $_.id -eq $Id } | Select-Object -First 1
}

function Set-PSTermProfile {
    <#
    .SYNOPSIS
        Insert or replace a profile, matching on id.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)]$Profile)

    $existing = @($Store.profiles) | Where-Object { $_.id -eq $Profile.id }
    if ($existing) {
        $Store.profiles = @(@($Store.profiles) | ForEach-Object {
            if ($_.id -eq $Profile.id) { $Profile } else { $_ }
        })
    }
    else {
        $Store.profiles = @(@($Store.profiles) + $Profile)
    }
    $Store
}

function Remove-PSTermProfile {
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Id)
    $Store.profiles = @(@($Store.profiles) | Where-Object { $_.id -ne $Id })
    $Store
}

function Get-PSTermFolders {
    <#
    .SYNOPSIS
        Distinct folder paths in use, sorted, for building the session tree.
    #>
    param([Parameter(Mandatory)]$Store)
    @($Store.profiles |
        ForEach-Object { [string]$_.folder } |
        Where-Object { $_ } |
        Sort-Object -Unique)
}

# =============================================================================
# Import from other tools
# =============================================================================

function Import-PuttySessions {
    <#
    .SYNOPSIS
        Read saved PuTTY sessions from the registry and convert them to profiles.
    .DESCRIPTION
        Most people evaluating a PuTTY replacement already have dozens of saved
        sessions. Re-entering them by hand is the main reason a switch stalls.
    #>
    [CmdletBinding()]
    param([string]$FolderName = 'PuTTY')

    $key = 'HKCU:\Software\SimonTatham\PuTTY\Sessions'
    if (-not (Test-Path -LiteralPath $key)) {
        Write-Verbose 'No saved PuTTY sessions found.'
        return @()
    }

    $result = @()
    foreach ($session in Get-ChildItem -LiteralPath $key -ErrorAction SilentlyContinue) {
        try {
            $values = Get-ItemProperty -LiteralPath $session.PSPath -ErrorAction Stop
            # Session names are URL-escaped in the registry ("My%20Router").
            $name = [System.Uri]::UnescapeDataString($session.PSChildName)
            if ($name -eq 'Default%20Settings' -or $name -eq 'Default Settings') { continue }

            $protocol = [string]$values.Protocol
            $type = switch ($protocol) {
                'telnet' { 'Telnet' }
                'serial' { 'Serial' }
                default  { 'SSH' }
            }

            $p = New-PSTermProfile -Name $name -Type $type
            $p.folder = $FolderName

            $hostName = [string]$values.HostName
            $p.ssh.host    = $hostName
            $p.telnet.host = $hostName
            $p.ssh.user    = [string]$values.UserName

            if ($values.PSObject.Properties.Name -contains 'PortNumber') {
                $port = [int]$values.PortNumber
                if ($type -eq 'Telnet') { $p.telnet.port = $port } else { $p.ssh.port = $port }
            }

            if ($values.PSObject.Properties.Name -contains 'SerialLine') {
                $p.serial.portName = [string]$values.SerialLine
            }
            if ($values.PSObject.Properties.Name -contains 'SerialSpeed') {
                $p.serial.baudRate = [int]$values.SerialSpeed
            }
            if ($values.PSObject.Properties.Name -contains 'SerialDataBits') {
                $p.serial.dataBits = [int]$values.SerialDataBits
            }
            if ($values.PSObject.Properties.Name -contains 'SerialStopHalfbits') {
                $p.serial.stopBits = if ([int]$values.SerialStopHalfbits -ge 4) { 'Two' } else { 'One' }
            }
            if ($values.PSObject.Properties.Name -contains 'SerialParity') {
                $p.serial.parity = switch ([int]$values.SerialParity) {
                    1 { 'Odd' } 2 { 'Even' } 3 { 'Mark' } 4 { 'Space' } default { 'None' }
                }
            }
            if ($values.PSObject.Properties.Name -contains 'SerialFlowControl') {
                $p.serial.handshake = switch ([int]$values.SerialFlowControl) {
                    1 { 'XOnXOff' } 2 { 'RequestToSend' } default { 'None' }
                }
            }

            # PuTTY's BackspaceIsDelete: 1 means the key sends 0x7F.
            if ($values.PSObject.Properties.Name -contains 'BackspaceIsDelete') {
                $p.terminal.backspace = if ([int]$values.BackspaceIsDelete -eq 0) { 'Backspace' } else { 'Delete' }
            }

            if ($values.PSObject.Properties.Name -contains 'PublicKeyFile') {
                $p.ssh.identityFile = [string]$values.PublicKeyFile
            }

            $result += $p
        }
        catch {
            Write-Verbose "Skipped PuTTY session '$($session.PSChildName)': $($_.Exception.Message)"
        }
    }

    $result
}

function Import-SshConfigHosts {
    <#
    .SYNOPSIS
        Turn Host entries in an OpenSSH config file into profiles.
    .DESCRIPTION
        Only the fields PSTerm shows in its own UI are lifted out. ssh.exe still
        reads the file itself at connect time, so anything not parsed here keeps
        working - this only makes the hosts visible in the session list.
    #>
    [CmdletBinding()]
    param(
        [string]$Path = (Join-Path $env:USERPROFILE '.ssh\config'),
        [string]$FolderName = 'ssh_config'
    )

    if (-not (Test-Path -LiteralPath $Path)) { return @() }

    $result = @()
    $current = $null

    foreach ($line in Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }

        # Keywords may be separated by whitespace or '='.
        if ($trimmed -match '^(?<key>[A-Za-z]+)\s*=?\s+(?<value>.+)$') {
            $key = $Matches['key'].ToLowerInvariant()
            $value = $Matches['value'].Trim()

            if ($key -eq 'host') {
                # A pattern is not a connectable host.
                if ($value -match '[*?]') { $current = $null; continue }
                $current = New-PSTermProfile -Name $value -Type 'SSH'
                $current.folder = $FolderName
                $current.ssh.host = $value
                $result += $current
                continue
            }

            if (-not $current) { continue }

            switch ($key) {
                'hostname'     { $current.ssh.host = $value }
                'user'         { $current.ssh.user = $value }
                'port'         { [int]$p = 0; if ([int]::TryParse($value, [ref]$p)) { $current.ssh.port = $p } }
                'identityfile' { $current.ssh.identityFile = $value.Trim('"') }
                'proxyjump'    { $current.ssh.proxyJump = $value }
                'forwardagent' { $current.ssh.forwardAgent = ($value -match '^(yes|true)$') }
                'compression'  { $current.ssh.compression = ($value -match '^(yes|true)$') }
            }
        }
    }

    $result
}
