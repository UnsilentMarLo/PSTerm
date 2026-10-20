<#
.SYNOPSIS
    Encrypted credential storage.

.DESCRIPTION
    Secrets are encrypted with DPAPI under the CurrentUser scope, so the file can
    only be decrypted by the same Windows account on the same machine. Copying the
    portable folder to another machine carries the profiles but not the passwords,
    which is the correct outcome: a saved password should not travel on a USB stick.

    v1 stored an AutoInput script in plain text in profiles.json and had no other
    credential handling at all, so any password used for automated login sat on
    disk in the clear.

    Nothing here ever returns a secret as a plain string unless explicitly asked
    for at the point of use, and profiles store only a key into this file.

    The profile editor saves a connection's password here, and New-PSTermSessionTab
    hands it to the session, whose compiled PasswordResponder sends it to the first
    password prompt. It never passes through a script block on the way out.
#>

Set-StrictMode -Version Latest

function Get-PSTermSecretPath {
    param([Parameter(Mandatory)][string]$Root)
    Join-Path $Root 'Profiles\credentials.dat'
}

function Test-PSTermDpapiAvailable {
    <#
    .SYNOPSIS
        True when DPAPI can be used. It is present on every supported Windows
        install, but PowerShell 7 needs System.Security.Cryptography.ProtectedData.
    #>
    try {
        Add-Type -AssemblyName 'System.Security' -ErrorAction SilentlyContinue
        $null = [System.Security.Cryptography.ProtectedData]
        return $true
    }
    catch {
        return $false
    }
}

function Protect-PSTermString {
    <#
    .SYNOPSIS
        Encrypt a string for the current user.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    try {
        $protected = [System.Security.Cryptography.ProtectedData]::Protect(
            $bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [Convert]::ToBase64String($protected)
    }
    finally {
        # Do not leave the plaintext lying in a managed array for the GC to move around.
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Unprotect-PSTermString {
    <#
    .SYNOPSIS
        Decrypt a string encrypted by Protect-PSTermString. Returns $null if it
        cannot be decrypted, which is the expected result on a different machine
        or under a different user account.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrEmpty($Value)) { return $null }

    try {
        $protected = [Convert]::FromBase64String($Value)
        $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $protected, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    }
    catch {
        return $null
    }
}

function Import-PSTermSecrets {
    param([Parameter(Mandatory)][string]$Root)

    $path = Get-PSTermSecretPath -Root $Root
    if (-not (Test-Path -LiteralPath $path)) { return @{} }

    try {
        $raw = Get-Content -Raw -LiteralPath $path -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }
        $data = $raw | ConvertFrom-Json

        $table = @{}
        foreach ($prop in $data.PSObject.Properties) {
            $table[$prop.Name] = [string]$prop.Value
        }
        return $table
    }
    catch {
        Write-Warning "The credential store could not be read and will be ignored: $($_.Exception.Message)"
        return @{}
    }
}

function Save-PSTermSecrets {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][hashtable]$Secrets
    )

    $path = Get-PSTermSecretPath -Root $Root
    $dir = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $object = [pscustomobject]@{}
    foreach ($key in $Secrets.Keys) {
        Add-Member -InputObject $object -NotePropertyName $key -NotePropertyValue $Secrets[$key] -Force
    }

    $temp = "$path.tmp"
    ($object | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $temp -Encoding UTF8
    Move-Item -LiteralPath $temp -Destination $path -Force
}

function Set-PSTermSecret {
    <#
    .SYNOPSIS
        Store a secret under a key and return the key.
    #>
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value
    )

    $secrets = Import-PSTermSecrets -Root $Root
    if ([string]::IsNullOrEmpty($Value)) {
        $secrets.Remove($Key) | Out-Null
    }
    else {
        $secrets[$Key] = Protect-PSTermString -Value $Value
    }
    Save-PSTermSecrets -Root $Root -Secrets $secrets
    $Key
}

function Get-PSTermSecret {
    <#
    .SYNOPSIS
        Retrieve and decrypt a secret. Returns $null when absent or undecryptable.
    #>
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Key
    )

    if ([string]::IsNullOrWhiteSpace($Key)) { return $null }
    $secrets = Import-PSTermSecrets -Root $Root
    if (-not $secrets.ContainsKey($Key)) { return $null }
    Unprotect-PSTermString -Value $secrets[$Key]
}

function Remove-PSTermSecret {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Key
    )
    $secrets = Import-PSTermSecrets -Root $Root
    if ($secrets.ContainsKey($Key)) {
        $secrets.Remove($Key) | Out-Null
        Save-PSTermSecrets -Root $Root -Secrets $secrets
    }
}
