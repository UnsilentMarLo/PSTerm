<#
.SYNOPSIS
    Folders with default settings, pinned connections, quick credentials, and
    importing and exporting sessions.

.DESCRIPTION
    Builds on the profile store in Profiles.ps1. Everything here works on the store
    object in memory; callers save it with Save-PSTermProfiles.

    Passwords never enter the store. A password is an entry in the DPAPI file
    (Secrets.ps1) under a key - "profile:<id>", "folder:<path>" or "cred:<id>" -
    and the store holds only the key.
#>

Set-StrictMode -Version Latest

# =============================================================================
# Folders
# =============================================================================

function Get-PSTermFolderRecord {
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Path)
    @($Store.folders) | Where-Object { $_.path -eq $Path } | Select-Object -First 1
}

function Split-PSTermFolderPath {
    param([string]$Path)
    @($Path -split '[\\/]' | Where-Object { $_ })
}

function Join-PSTermFolderPath {
    param([string[]]$Segments)
    (@($Segments) | Where-Object { $_ }) -join '/'
}

function Get-PSTermParentFolder {
    param([string]$Path)
    $segments = @(Split-PSTermFolderPath -Path $Path)
    if ($segments.Count -le 1) { return '' }
    Join-PSTermFolderPath -Segments $segments[0..($segments.Count - 2)]
}

function Get-PSTermAllFolderPaths {
    <#
    .SYNOPSIS
        Every folder that exists: recorded ones, ones profiles sit in, and all of
        their ancestors, so "Lab/Switches" implies "Lab".
    #>
    param([Parameter(Mandatory)]$Store)

    $set = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $add = {
        param($p)
        $acc = @()
        foreach ($seg in (Split-PSTermFolderPath -Path $p)) {
            $acc += $seg
            [void]$set.Add((Join-PSTermFolderPath -Segments $acc))
        }
    }
    foreach ($f in @($Store.folders)) { & $add ([string]$f.path) }
    foreach ($p in @($Store.profiles)) { if ($p.folder) { & $add ([string]$p.folder) } }
    @($set)
}

function Add-PSTermFolder {
    <#
    .SYNOPSIS
        Make sure a folder (and its parents) exists as a record.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Path)

    $Path = Join-PSTermFolderPath -Segments (Split-PSTermFolderPath -Path $Path)
    if (-not $Path) { return $null }

    $acc = @()
    foreach ($seg in (Split-PSTermFolderPath -Path $Path)) {
        $acc += $seg
        $current = Join-PSTermFolderPath -Segments $acc
        if (-not (Get-PSTermFolderRecord -Store $Store -Path $current)) {
            $Store.folders = @(@($Store.folders) + [pscustomobject]@{ path = $current; defaults = $null })
        }
    }
    Get-PSTermFolderRecord -Store $Store -Path $Path
}

function Rename-PSTermFolder {
    <#
    .SYNOPSIS
        Rename or move a folder, taking its subfolders and connections with it.
    #>
    param(
        [Parameter(Mandatory)]$Store,
        [Parameter(Mandatory)][string]$OldPath,
        [Parameter(Mandatory)][string]$NewPath
    )

    $OldPath = Join-PSTermFolderPath -Segments (Split-PSTermFolderPath -Path $OldPath)
    $NewPath = Join-PSTermFolderPath -Segments (Split-PSTermFolderPath -Path $NewPath)
    if (-not $OldPath -or $OldPath -eq $NewPath) { return $false }

    # A folder cannot be moved into itself.
    if ($NewPath -like "$OldPath/*") { return $false }

    $remap = {
        param([string]$p)
        if ($p -eq $OldPath) { return $NewPath }
        if ($p -like "$OldPath/*") { return $NewPath + $p.Substring($OldPath.Length) }
        $p
    }

    [void](Add-PSTermFolder -Store $Store -Path $OldPath)
    foreach ($f in @($Store.folders)) { $f.path = & $remap ([string]$f.path) }
    foreach ($p in @($Store.profiles)) { if ($p.folder) { $p.folder = & $remap ([string]$p.folder) } }
    if ($NewPath) { [void](Add-PSTermFolder -Store $Store -Path $NewPath) }

    # Two records can now share a path; keep the one that carries defaults.
    $seen = @{}
    $kept = @()
    foreach ($f in @($Store.folders | Sort-Object { [bool]$_.defaults } -Descending)) {
        $key = ([string]$f.path).ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $kept += $f
    }
    $Store.folders = $kept
    $true
}

function Remove-PSTermFolder {
    <#
    .SYNOPSIS
        Delete a folder. Its connections move up to the parent unless -DeleteContents.
    .OUTPUTS
        The ids of any connections deleted with it.
    #>
    param(
        [Parameter(Mandatory)]$Store,
        [Parameter(Mandatory)][string]$Path,
        [switch]$DeleteContents
    )

    $Path = Join-PSTermFolderPath -Segments (Split-PSTermFolderPath -Path $Path)
    $parent = Get-PSTermParentFolder -Path $Path
    $deleted = @()

    $inside = {
        param([string]$p)
        $p -eq $Path -or $p -like "$Path/*"
    }

    if ($DeleteContents) {
        $deleted = @(@($Store.profiles) | Where-Object { & $inside ([string]$_.folder) } | ForEach-Object { [string]$_.id })
        $Store.profiles = @(@($Store.profiles) | Where-Object { -not (& $inside ([string]$_.folder)) })
        $Store.pinned = @(@($Store.pinned) | Where-Object { $deleted -notcontains $_ })
    }
    else {
        foreach ($p in @($Store.profiles)) {
            if (& $inside ([string]$p.folder)) {
                $rest = ([string]$p.folder).Substring($Path.Length).TrimStart('/')
                $p.folder = Join-PSTermFolderPath -Segments @($parent, $rest)
            }
        }
    }

    $Store.folders = @(@($Store.folders) | Where-Object { -not (& $inside ([string]$_.path)) })
    $deleted
}

function Move-PSTermProfileToFolder {
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Id, [AllowEmptyString()][string]$Path)
    $profile = Get-PSTermProfileById -Store $Store -Id $Id
    if (-not $profile) { return $false }
    $Path = Join-PSTermFolderPath -Segments (Split-PSTermFolderPath -Path $Path)
    $profile.folder = $Path
    if ($Path) { [void](Add-PSTermFolder -Store $Store -Path $Path) }
    $true
}

function Get-PSTermFolderDefaults {
    <#
    .SYNOPSIS
        The settings new connections in a folder start from: the nearest folder at
        or above this one that has any, or $null.
    #>
    param([Parameter(Mandatory)]$Store, [AllowEmptyString()][string]$Path)

    $current = Join-PSTermFolderPath -Segments (Split-PSTermFolderPath -Path $Path)
    while ($current) {
        $record = Get-PSTermFolderRecord -Store $Store -Path $current
        if ($record -and $record.defaults) { return $record.defaults }
        $current = Get-PSTermParentFolder -Path $current
    }
    $null
}

function Copy-PSTermObject {
    param($Value)
    if ($null -eq $Value) { return $null }
    ($Value | ConvertTo-Json -Depth 8) | ConvertFrom-Json
}

function New-PSTermProfileInFolder {
    <#
    .SYNOPSIS
        A new connection that starts from its folder's default settings.
    .DESCRIPTION
        The defaults are copied, not linked: changing a folder's settings later does
        not rewrite connections that already exist. What is left out is what makes a
        connection itself - its name, address and port name.
    #>
    param(
        [Parameter(Mandatory)]$Store,
        [AllowEmptyString()][string]$Folder = '',
        [string]$Name = 'New connection',
        [string]$Type = ''
    )

    $defaults = Get-PSTermFolderDefaults -Store $Store -Path $Folder
    $profile = New-PSTermProfile -Name $Name -Type $(if ($Type) { $Type } elseif ($defaults) { $defaults.type } else { 'SSH' })
    $profile.folder = $Folder

    if ($defaults) {
        $copy = Copy-PSTermObject -Value $defaults
        foreach ($section in 'ssh', 'telnet', 'serial', 'shell') {
            $keepHost = @{ ssh = 'host'; telnet = 'host'; serial = 'portName'; shell = 'commandLine' }[$section]
            foreach ($prop in $copy.$section.PSObject.Properties) {
                if ($prop.Name -eq $keepHost) { continue }
                $profile.$section.($prop.Name) = $prop.Value
            }
        }
        foreach ($section in 'terminal', 'logging', 'autoEnable') {
            foreach ($prop in $copy.$section.PSObject.Properties) {
                $profile.$section.($prop.Name) = $prop.Value
            }
        }
        $profile.autoInput = @($copy.autoInput)
        $profile.mark = [string]$copy.mark
    }
    $profile
}

# =============================================================================
# Pinned connections
# =============================================================================

function Test-PSTermPinned {
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Id)
    @($Store.pinned) -contains $Id
}

function Set-PSTermPinned {
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Id, [bool]$Pinned = $true)
    $rest = @(@($Store.pinned) | Where-Object { $_ -and $_ -ne $Id })
    $Store.pinned = if ($Pinned) { @($rest + $Id) } else { $rest }
}

# =============================================================================
# Quick credentials
# =============================================================================

function Get-PSTermCredentialById {
    param([Parameter(Mandatory)]$Store, [string]$Id)
    if (-not $Id) { return $null }
    @($Store.credentials) | Where-Object { $_.id -eq $Id } | Select-Object -First 1
}

function Set-PSTermCredential {
    <#
    .SYNOPSIS
        Add or update a quick credential. The secret goes to the encrypted store.
    #>
    param(
        [Parameter(Mandatory)]$Store,
        [Parameter(Mandatory)][string]$Root,
        [string]$Id,
        [Parameter(Mandatory)][string]$Name,
        [string]$Username = '',
        [AllowEmptyString()][string]$Secret
    )

    $existing = if ($Id) { Get-PSTermCredentialById -Store $Store -Id $Id } else { $null }
    if (-not $existing) {
        $existing = [pscustomobject]@{ id = [guid]::NewGuid().ToString('N'); name = $Name; username = $Username; secretKey = '' }
        $Store.credentials = @(@($Store.credentials) + $existing)
    }

    $existing.name = $Name
    $existing.username = $Username
    $existing.secretKey = "cred:$($existing.id)"
    # A blank secret on an existing credential means "unchanged", so a rename does
    # not require typing the password again.
    if ($PSBoundParameters.ContainsKey('Secret') -and ($Secret -ne '' -or -not $Id)) {
        [void](Set-PSTermSecret -Root $Root -Key $existing.secretKey -Value $Secret)
    }
    $existing
}

function Remove-PSTermCredential {
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Id)
    $cred = Get-PSTermCredentialById -Store $Store -Id $Id
    if (-not $cred) { return }
    Remove-PSTermSecret -Root $Root -Key ([string]$cred.secretKey)
    $Store.credentials = @(@($Store.credentials) | Where-Object { $_.id -ne $Id })
    # Connections that pointed at it no longer have an enable credential.
    foreach ($p in @($Store.profiles)) {
        if ($p.autoEnable.credentialId -eq $Id) { $p.autoEnable.credentialId = '' }
    }
    foreach ($f in @($Store.folders)) {
        if ($f.defaults -and $f.defaults.autoEnable.credentialId -eq $Id) { $f.defaults.autoEnable.credentialId = '' }
    }
}

function Resolve-PSTermLogin {
    <#
    .SYNOPSIS
        The user name and password to log in with: the connection's own, then its
        folder's. Returns an object; either field may be empty.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)]$Profile)

    $user = [string]$Profile.ssh.user
    $key = [string]$Profile.credentialKey

    if (-not $user -or -not $key) {
        $folder = Get-PSTermFolderDefaults -Store $Store -Path ([string]$Profile.folder)
        if ($folder) {
            if (-not $user) { $user = [string]$folder.ssh.user }
            if (-not $key) { $key = [string]$folder.credentialKey }
        }
    }

    $password = if ($key) { Get-PSTermSecret -Root $Root -Key $key } else { $null }
    [pscustomobject]@{ User = $user; Password = $password }
}

# =============================================================================
# CSV import
# =============================================================================

function Read-PSTermCsv {
    <#
    .SYNOPSIS
        Read a CSV file, working out the delimiter from the header line.
    .OUTPUTS
        An object with Columns and Rows.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    $firstLine = ($text -split "`r?`n" | Select-Object -First 1)
    $delimiter = ','
    $best = -1
    foreach ($candidate in @(',', ';', "`t", '|')) {
        $count = @($firstLine.ToCharArray() | Where-Object { $_ -eq $candidate[0] }).Count
        if ($count -gt $best) { $best = $count; $delimiter = $candidate }
    }

    $rows = @($text | ConvertFrom-Csv -Delimiter $delimiter)
    $columns = if ($rows.Count -gt 0) { @($rows[0].PSObject.Properties.Name) } else { @($firstLine -split [regex]::Escape($delimiter)) }
    [pscustomobject]@{ Columns = $columns; Rows = $rows; Delimiter = $delimiter }
}

function Get-PSTermCsvGuess {
    <#
    .SYNOPSIS
        Guess which column holds what, from the header names. Handles the English
        and German headers of a NetBox IP address export.
    #>
    param([Parameter(Mandatory)][string[]]$Columns)

    $find = {
        param([string[]]$patterns)
        foreach ($pattern in $patterns) {
            foreach ($c in $Columns) { if ($c -match $pattern) { return $c } }
        }
        ''
    }

    [pscustomobject]@{
        Host   = (& $find @('^ip[- ]?adress', '^ip[- ]?address', '^address', '^host(name)?$', '^ip$', 'adress'))
        Name   = (& $find @('^dns[- ]?name', '^name$', '^hostname$', '^device', '^bezeichnung'))
        Notes  = (& $find @('^beschreibung', '^description', '^comment', '^notes?$', '^kommentar'))
        Folder = (& $find @('^folder$', '^ordner$', '^group$', '^gruppe$', '^site$', '^standort$', '^rolle$', '^role$'))
    }
}

function ConvertFrom-PSTermCsvRows {
    <#
    .SYNOPSIS
        Turn CSV rows into connection profiles (not yet saved).
    .PARAMETER Mapping
        Column names: Host (required), Name, Notes, Folder.
    .PARAMETER BaseFolder
        Folder the imported connections go under.
    .PARAMETER GroupBy
        A column whose values become subfolders, e.g. the device model.
    #>
    param(
        [Parameter(Mandatory)]$Store,
        [Parameter(Mandatory)]$Rows,
        [Parameter(Mandatory)]$Mapping,
        [string]$Type = 'SSH',
        [string]$BaseFolder = '',
        [string]$GroupBy = '',
        [switch]$StripPrefixLength
    )

    # Callers pass a hashtable or an object, with some keys left out.
    $map = @{ Host = ''; Name = ''; Notes = ''; Folder = '' }
    if ($Mapping -is [hashtable]) { foreach ($k in $Mapping.Keys) { $map[$k] = [string]$Mapping[$k] } }
    else { foreach ($prop in $Mapping.PSObject.Properties) { $map[$prop.Name] = [string]$prop.Value } }

    $profiles = @()
    foreach ($row in @($Rows)) {
        $value = {
            param($column)
            if (-not $column -or -not ($row.PSObject.Properties.Name -contains $column)) { return '' }
            ([string]$row.$column).Trim()
        }

        $address = & $value $map.Host
        if (-not $address) { continue }
        # NetBox exports 10.0.0.5/24; the prefix length is not part of the address.
        if ($StripPrefixLength) { $address = ($address -replace '/\d+$', '') }

        $name = & $value $map.Name
        $notes = & $value $map.Notes
        $folder = $BaseFolder

        $rowFolder = & $value $map.Folder
        if ($rowFolder) { $folder = Join-PSTermFolderPath -Segments @($folder, $rowFolder) }
        $group = & $value $GroupBy
        if ($group) { $folder = Join-PSTermFolderPath -Segments @($folder, ($group -replace '[\\/]', '-')) }

        $profile = New-PSTermProfileInFolder -Store $Store -Folder $folder -Type $Type -Name $(if ($name) { $name } else { $address })
        switch ($Type) {
            'Telnet' { $profile.telnet.host = $address }
            default  { $profile.ssh.host = $address }
        }
        if (-not $name) { $profile.autoName = $true }
        $profile.notes = $notes
        $profiles += $profile
    }
    $profiles
}

# =============================================================================
# PSTerm session files
# =============================================================================

$script:SessionFileFormat = 'psterm-sessions'

function Export-PSTermSessions {
    <#
    .SYNOPSIS
        Write connections and their folders to a file that can be shared.
    .DESCRIPTION
        The file is JSON. Passwords are never included - they are bound to one
        Windows account on one machine and should not travel - so an imported
        connection asks for its password again (or takes the folder's).
    #>
    param(
        [Parameter(Mandatory)]$Store,
        [Parameter(Mandatory)][string]$Path,
        $Profiles,
        [string[]]$FolderPaths = @()
    )

    if ($null -eq $Profiles) { $Profiles = @($Store.profiles) }

    $strip = {
        param($p)
        $copy = Copy-PSTermObject -Value $p
        $copy.credentialKey = ''
        $copy.autoEnable.credentialId = ''
        $copy
    }

    $profileList = @(@($Profiles) | ForEach-Object { & $strip $_ })

    # Folders travel with their default settings, and so do the folders above.
    $wanted = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $profileList) { if ($p.folder) { [void]$wanted.Add([string]$p.folder) } }
    foreach ($f in $FolderPaths) { if ($f) { [void]$wanted.Add($f) } }
    foreach ($f in @($wanted)) {
        $parent = Get-PSTermParentFolder -Path $f
        while ($parent) { [void]$wanted.Add($parent); $parent = Get-PSTermParentFolder -Path $parent }
    }

    $folderList = @()
    foreach ($record in @($Store.folders)) {
        if (-not $wanted.Contains([string]$record.path)) { continue }
        $folderList += [pscustomobject]@{
            path     = [string]$record.path
            defaults = $(if ($record.defaults) { & $strip $record.defaults } else { $null })
        }
    }

    $document = [pscustomobject]@{
        format   = $script:SessionFileFormat
        version  = 1
        exported = (Get-Date).ToString('s')
        note     = 'PSTerm sessions. Passwords are not included.'
        folders  = $folderList
        profiles = $profileList
    }
    [System.IO.File]::WriteAllText($Path, ($document | ConvertTo-Json -Depth 9), (New-Object System.Text.UTF8Encoding($false)))
    @($profileList).Count
}

function Import-PSTermSessions {
    <#
    .SYNOPSIS
        Read a PSTerm session file. Returns the profiles and folder records,
        with new ids, ready to be merged into the store.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $raw = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    try { $data = $raw | ConvertFrom-Json }
    catch { throw "This is not a PSTerm session file: $($_.Exception.Message)" }

    if (-not ($data.PSObject.Properties.Name -contains 'format') -or $data.format -ne $script:SessionFileFormat) {
        throw 'This is not a PSTerm session file.'
    }
    if ($data.version -gt 1) {
        throw "This file was written by a newer PSTerm (format version $($data.version))."
    }

    $profiles = @()
    foreach ($p in @($data.profiles)) {
        if (-not $p) { continue }
        $merged = Merge-PSTermProfileDefaults -Profile $p
        $merged.id = [guid]::NewGuid().ToString('N')
        $merged.credentialKey = ''
        $profiles += $merged
    }

    $folders = @()
    foreach ($f in @($data.folders)) {
        if ($f) { $folders += (ConvertTo-PSTermFolderRecord -Value $f) }
    }

    [pscustomobject]@{ Profiles = $profiles; Folders = $folders }
}

function Merge-PSTermImportedSessions {
    <#
    .SYNOPSIS
        Add imported connections and folders to the store. A connection that
        already exists in the same folder under the same name is skipped.
    .OUTPUTS
        The number of connections added.
    #>
    param(
        [Parameter(Mandatory)]$Store,
        [Parameter(Mandatory)]$Profiles,
        $Folders = @()
    )

    foreach ($record in @($Folders)) {
        $existing = Add-PSTermFolder -Store $Store -Path ([string]$record.path)
        # Defaults from the file never replace ones that are already set up here.
        if ($existing -and -not $existing.defaults -and $record.defaults) { $existing.defaults = $record.defaults }
    }

    $added = 0
    foreach ($profile in @($Profiles)) {
        $duplicate = @($Store.profiles) | Where-Object { $_.name -eq $profile.name -and $_.folder -eq $profile.folder }
        if ($duplicate) { continue }
        if ($profile.folder) { [void](Add-PSTermFolder -Store $Store -Path ([string]$profile.folder)) }
        [void](Set-PSTermProfile -Store $Store -Profile $profile)
        $added++
    }
    $added
}
