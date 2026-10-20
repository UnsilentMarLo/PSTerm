<#
.SYNOPSIS
    Application settings, stored next to the profiles so the install stays portable.
#>

Set-StrictMode -Version Latest

function Get-PSTermSettingsPath {
    param([Parameter(Mandatory)][string]$Root)
    Join-Path $Root 'Profiles\settings.json'
}

function New-PSTermDefaultSettings {
    [pscustomobject]@{
        version          = 1
        theme            = 'Dark'
        fontFamily       = 'Consolas'
        fontSize         = 10.5
        scrollback       = 10000
        copyOnSelect     = $true
        confirmOnClose   = $true
        # Pasting several lines into a shell runs every one of them at once.
        confirmMultilinePaste = $true
        defaultLogFolder = 'Logs'
        # Where a brand-new profile starts, so house style only has to be set once.
        defaultBackspace = 'Delete'
        defaultEncoding  = 'Utf8'
    }
}

function Import-PSTermSettings {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root)

    $path = Get-PSTermSettingsPath -Root $Root
    $defaults = New-PSTermDefaultSettings

    if (-not (Test-Path -LiteralPath $path)) { return $defaults }

    try {
        $raw = Get-Content -Raw -LiteralPath $path -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($raw)) { return $defaults }
        $data = $raw | ConvertFrom-Json

        # Merge over the defaults so a file written by an older build still loads.
        foreach ($prop in $data.PSObject.Properties) {
            if ($defaults.PSObject.Properties.Name -contains $prop.Name) {
                $defaults.($prop.Name) = $prop.Value
            }
        }
        return $defaults
    }
    catch {
        Write-Warning "Settings could not be read and defaults will be used: $($_.Exception.Message)"
        return $defaults
    }
}

function Save-PSTermSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)]$Settings
    )

    $path = Get-PSTermSettingsPath -Root $Root
    $dir = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $temp = "$path.tmp"
    ($Settings | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $temp -Encoding UTF8
    Move-Item -LiteralPath $temp -Destination $path -Force
}
