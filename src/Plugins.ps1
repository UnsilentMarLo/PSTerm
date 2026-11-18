<#
.SYNOPSIS
    The plugin host: finds plugins, builds a form from a plugin script's parameters, runs
    the plugin against many devices at once and collects what comes back.

.DESCRIPTION
    A plugin is a folder with a plugin.json (what it is, a few settings) and a PowerShell
    script. The script is written for ONE device: it receives an open session and returns
    objects, one per row of the result. The host runs it for every selected device, up to
    ten at a time, in PSTerm's own runspace pool (the same code on Windows PowerShell 5.1
    and PowerShell 7), and puts the rows together.

        param(
            [Parameter(Mandatory)]$Session,    # the open device session (read-only)
            $Target,                           # optional: name and address of the device
            [switch]$OnlyProblems,             # every other parameter becomes a field in the form
            [int]$MinErrors = 1
        )

    What keeps a plugin honest:
      * The session is read-only. The engine itself refuses any command that is not a
        look-only command (show, ping, traceroute, ...), so a script cannot reconfigure a
        device whatever it contains.
      * The script never sees a password. The host resolves the quick credentials, logs in,
        and hands the script an open session.
      * A plugin that is not shipped with PSTerm runs only after the user has approved that
        exact version of it (a hash of its files); a change asks again.
      * Every run writes a log of what was sent to which device.

    Plugins that change a device are a later step; "access" in plugin.json is "read" for now
    and the host refuses anything else.
#>

Set-StrictMode -Version Latest

# Parameters the host fills in itself; they never become form fields.
$script:PSTermPluginReserved = @('Session', 'Target')

# =============================================================================
# Finding plugins
# =============================================================================

function Get-PSTermPluginFolders {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root)
    @(
        [pscustomobject]@{ Path = (Join-Path $PSScriptRoot 'Plugins'); Builtin = $true }
        [pscustomobject]@{ Path = (Join-Path $Root 'Plugins'); Builtin = $false }
    )
}

function Get-PSTermPluginHash {
    param([Parameter(Mandatory)][string]$Folder)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $all = New-Object System.Collections.Generic.List[byte]
        foreach ($f in (Get-ChildItem -LiteralPath $Folder -File -Recurse | Sort-Object FullName)) {
            $rel = $f.FullName.Substring($Folder.Length).ToLowerInvariant()
            $all.AddRange([System.Text.Encoding]::UTF8.GetBytes($rel + "`n"))
            $all.AddRange([System.IO.File]::ReadAllBytes($f.FullName))
        }
        ([BitConverter]::ToString($sha.ComputeHash($all.ToArray())) -replace '-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function Get-PSTermPluginParameters {
    <#
    .SYNOPSIS
        Read a plugin script's param() block: name, type, default, choices, help text.
        The script is parsed, never run.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ScriptPath, $Overrides)

    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) { throw "The script has a syntax error: $($errors[0].Message) (line $($errors[0].Extent.StartLineNumber))" }

    $help = $null
    try { $help = $ast.GetHelpContent() } catch { }

    $result = @()
    if (-not $ast.ParamBlock) { return $result }

    foreach ($p in $ast.ParamBlock.Parameters) {
        $name = $p.Name.VariablePath.UserPath
        $type = $p.StaticType
        $mandatory = $false; $choices = @()
        foreach ($attr in $p.Attributes) {
            if ($attr -isnot [System.Management.Automation.Language.AttributeAst]) { continue }
            $tn = $attr.TypeName.Name
            if ($tn -eq 'ValidateSet') { foreach ($a in $attr.PositionalArguments) { if ($a -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $choices += $a.Value } } }
            if ($tn -eq 'Parameter') {
                foreach ($na in $attr.NamedArguments) {
                    if ($na.ArgumentName -eq 'Mandatory') { $mandatory = ($na.ExpressionOmitted -or $na.Argument.Extent.Text -ne '$false') }
                }
            }
        }

        $default = $null
        if ($p.DefaultValue) {
            $d = $p.DefaultValue
            $text = $d.Extent.Text
            if ($d -is [System.Management.Automation.Language.ConstantExpressionAst] -or
                ($d -is [System.Management.Automation.Language.VariableExpressionAst] -and $text -in @('$true', '$false', '$null')) -or
                ($d -is [System.Management.Automation.Language.UnaryExpressionAst] -and $text -match '^-\d+(\.\d+)?$')) {
                $default = & ([scriptblock]::Create($text))
            }
        }

        $kind = 'text'
        if ($type -eq [switch] -or $type -eq [bool]) { $kind = 'check' }
        elseif ($type -in @([int], [long], [double], [single], [decimal], [int16], [byte])) { $kind = 'number' }
        elseif ($choices.Count -gt 0) { $kind = 'choice' }
        elseif ($type -eq [string[]]) { $kind = 'lines' }

        $tip = ''
        if ($help -and $help.Parameters -and $help.Parameters.ContainsKey($name.ToUpperInvariant())) { $tip = ([string]$help.Parameters[$name.ToUpperInvariant()]).Trim() }
        # "OnlyProblems" -> "Only problems": sentence case, like every other label.
        $label = ($name -creplace '([a-z])([A-Z])', '$1 $2')
        $label = $label.Substring(0, 1) + $label.Substring(1).ToLowerInvariant()
        $ov = $null
        if ($Overrides -and $Overrides.PSObject.Properties[$name]) { $ov = $Overrides.$name }
        if ($ov) {
            if ($ov.PSObject.Properties['label'] -and $ov.label) { $label = [string]$ov.label }
            if ($ov.PSObject.Properties['tip'] -and $ov.tip) { $tip = [string]$ov.tip }
        }

        $result += [pscustomobject]@{
            Name = $name; Label = $label; Tip = $tip; Kind = $kind; Type = $type
            Default = $default; Choices = $choices; Mandatory = $mandatory
            Reserved = ($name -in $script:PSTermPluginReserved)
        }
    }
    $result
}

function Get-PSTermPlugin {
    <#
    .SYNOPSIS
        Every plugin that can be found, built-in first. One that is broken is still
        returned, with Problem saying why, so it can be shown instead of silently missing.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root, [string]$Id)

    foreach ($place in (Get-PSTermPluginFolders -Root $Root)) {
        if (-not (Test-Path -LiteralPath $place.Path)) { continue }
        foreach ($dir in (Get-ChildItem -LiteralPath $place.Path -Directory | Sort-Object Name)) {
            if ($Id -and $dir.Name -ne $Id) { continue }
            $manifestPath = Join-Path $dir.FullName 'plugin.json'
            if (-not (Test-Path -LiteralPath $manifestPath)) { continue }

            $p = [ordered]@{
                Id = $dir.Name; Title = $dir.Name; Description = ''; Version = ''; Folder = $dir.FullName
                ScriptPath = ''; Builtin = $place.Builtin; Hash = ''; Access = 'read'; Enter = $true
                TimeoutSec = 120; Topology = $false; Driver = 'cisco-ios'; Parameters = @(); Problem = ''
            }
            try {
                $m = Get-Content -Raw -LiteralPath $manifestPath -Encoding UTF8 | ConvertFrom-Json
                foreach ($k in 'title', 'description', 'version') { if ($m.PSObject.Properties[$k] -and $m.$k) { $p[(Get-Culture).TextInfo.ToTitleCase($k)] = [string]$m.$k } }
                if ($m.PSObject.Properties['access'] -and $m.access) { $p.Access = [string]$m.access }
                if ($m.PSObject.Properties['enter']) { $p.Enter = [bool]$m.enter }
                if ($m.PSObject.Properties['timeoutSec'] -and $m.timeoutSec) { $p.TimeoutSec = [int]$m.timeoutSec }
                if ($m.PSObject.Properties['topology']) { $p.Topology = [bool]$m.topology }
                if ($m.PSObject.Properties['driver'] -and $m.driver) { $p.Driver = [string]$m.driver }
                $scriptName = $(if ($m.PSObject.Properties['script'] -and $m.script) { [string]$m.script } else { 'main.ps1' })
                if ($scriptName -match '[\\/]|\.\.') { throw "The script name '$scriptName' must be a file in the plugin's own folder." }
                $p.ScriptPath = Join-Path $dir.FullName $scriptName
                if (-not (Test-Path -LiteralPath $p.ScriptPath)) { throw "The script '$scriptName' is missing." }

                $overrides = $(if ($m.PSObject.Properties['parameters']) { $m.parameters } else { $null })
                $p.Parameters = @(Get-PSTermPluginParameters -ScriptPath $p.ScriptPath -Overrides $overrides)
                if (-not ($p.Parameters | Where-Object { $_.Name -eq 'Session' })) { throw 'The script must declare a $Session parameter.' }
                $p.Hash = Get-PSTermPluginHash -Folder $dir.FullName
                if ($p.Access -ne 'read') { $p.Problem = "It asks for '$($p.Access)' access; only read-only plugins can run for now." }
            }
            catch { $p.Problem = $_.Exception.Message }
            [pscustomobject]$p
        }
    }
}

# =============================================================================
# Approval of plugins that are not shipped with PSTerm
# =============================================================================

function Get-PSTermPluginApprovalPath {
    param([Parameter(Mandatory)][string]$Root)
    Join-Path (Join-Path $Root 'Profiles') 'plugin-approvals.json'
}

function Test-PSTermPluginApproved {
    <#
    .SYNOPSIS
        Built-in plugins are trusted; any other runs only if this exact version was approved.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Plugin, [Parameter(Mandatory)][string]$Root)

    if ($Plugin.Builtin) { return $true }
    $path = Get-PSTermPluginApprovalPath -Root $Root
    if (-not (Test-Path -LiteralPath $path)) { return $false }
    try {
        $data = Get-Content -Raw -LiteralPath $path -Encoding UTF8 | ConvertFrom-Json
        $entry = $data.approved.PSObject.Properties[$Plugin.Id]
        return ($null -ne $entry -and [string]$entry.Value -eq $Plugin.Hash)
    }
    catch { return $false }
}

function Approve-PSTermPlugin {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Plugin, [Parameter(Mandatory)][string]$Root)

    $path = Get-PSTermPluginApprovalPath -Root $Root
    $approved = [ordered]@{}
    if (Test-Path -LiteralPath $path) {
        try {
            $data = Get-Content -Raw -LiteralPath $path -Encoding UTF8 | ConvertFrom-Json
            foreach ($prop in $data.approved.PSObject.Properties) { $approved[$prop.Name] = [string]$prop.Value }
        }
        catch { }
    }
    $approved[$Plugin.Id] = $Plugin.Hash
    $dir = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $json = [pscustomobject]@{ approved = [pscustomobject]$approved } | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($false)))
}

# =============================================================================
# Running a plugin
# =============================================================================

# What runs in each worker thread, once per device. It is text on purpose: it is handed to a
# runspace of the pool and must not depend on anything from the caller's scope.
$script:PSTermPluginWorker = @'
param($Ctx)
$ErrorActionPreference = 'Stop'
$session = $null
try {
    $Ctx.StartTick = [Environment]::TickCount
    $Ctx.Status = 'Running'

    if ($Ctx.Factory) { $session = & ([scriptblock]::Create($Ctx.Factory)) $Ctx.Profile $Ctx.Login $Ctx.Driver }
    else {
        $session = Open-PSTermDeviceSession -Profile $Ctx.Profile -Login $Ctx.Login -Driver $Ctx.Driver `
            -Enter:$Ctx.Enter -AcceptHostKey:$Ctx.AcceptHostKey -ReadOnly -TimeoutSec $Ctx.ConnectTimeoutSec -Publish $Ctx
    }
    # Whatever opened it: from here on it only looks.
    $session.MakeReadOnly()
    $Ctx.Session = $session

    $script = [scriptblock]::Create($Ctx.ScriptText)
    $splat = @{}
    foreach ($k in @($Ctx.Parameter.Keys)) { $splat[$k] = $Ctx.Parameter[$k] }
    $splat['Session'] = $session
    if ($Ctx.WantsTarget) { $splat['Target'] = $Ctx.TargetInfo }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($o in @(& $script @splat)) {
        if ($null -eq $o) { continue }
        $flat = [ordered]@{}
        if ($o -is [string] -or $o -is [ValueType]) { $flat['Value'] = $o }
        else {
            foreach ($prop in $o.PSObject.Properties) {
                $v = $prop.Value
                if ($null -ne $v -and $v -isnot [string] -and $v -isnot [ValueType] -and $v -is [System.Collections.IEnumerable]) { $v = (@($v) -join ', ') }
                elseif ($null -ne $v -and $v -isnot [string] -and $v -isnot [ValueType]) { $v = [string]$v }
                $flat[$prop.Name] = $v
            }
        }
        $rows.Add([pscustomobject]$flat)
    }
    $Ctx.Rows = $rows.ToArray()
    $Ctx.Status = 'OK'
}
catch {
    $Ctx.Error = $_.Exception.Message
    $Ctx.Status = 'Failed'
}
finally {
    if ($session) {
        try { $Ctx.Commands = $session.SentCommands } catch { }
        try { $session.Dispose() } catch { }
    }
    $Ctx.EndTick = [Environment]::TickCount
    $Ctx.Finished = $true
}
'@

function Get-PSTermWorkerFunctions {
    <#
    .SYNOPSIS
        The functions the worker threads need: everything PSTerm loaded from its src folder
        except the window code and the plugin host itself.
    #>
    $src = $PSScriptRoot
    foreach ($f in (Get-ChildItem Function:\ | Where-Object { $_.ScriptBlock -and $_.ScriptBlock.File })) {
        $file = $f.ScriptBlock.File
        if (-not $file.StartsWith($src, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($file -match '[\\/]Ui[\\/]' -or (Split-Path -Leaf $file) -eq 'Plugins.ps1') { continue }
        $f
    }
}

function ConvertTo-PSTermPluginValue {
    param($Spec, $Value)
    switch ($Spec.Kind) {
        'check' { return [bool]$Value }
        'number' {
            if ($null -eq $Value -or "$Value" -eq '') { return $Spec.Default }
            return $(if ($Spec.Type -in @([double], [single], [decimal])) { [double]$Value } else { [int]$Value })
        }
        'lines' {
            if ($Value -is [array]) { return @($Value | ForEach-Object { [string]$_ }) }
            return @(([string]$Value -split "`r?`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }
        default { return [string]$Value }
    }
}

function Start-PSTermPluginRun {
    <#
    .SYNOPSIS
        Start a plugin against some devices and return at once. Call Update-PSTermPluginRun
        (or Wait-PSTermPluginRun) to collect the results.
    .PARAMETER Target
        Connection profiles to run against.
    .PARAMETER Parameter
        Values for the plugin's own parameters, by name. Anything left out gets the script's default.
    .PARAMETER SessionFactory
        Test hook: text of a script block taking (Profile, Login, Driver) and returning a
        session. The host still makes it read-only.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Plugin,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Target,
        [Parameter(Mandatory)]$Store,
        [Parameter(Mandatory)][string]$Root,
        [hashtable]$Parameter = @{},
        [string]$Credential = '',
        [string]$EnableCredential = '',
        [ValidateRange(1, 64)][int]$ThrottleLimit = 10,
        [int]$TimeoutSec = 0,
        [string]$SessionFactory = '',
        [switch]$AcceptHostKey,
        [string]$LogFolder = ''
    )

    if ($Plugin.Problem) { throw "The plugin '$($Plugin.Title)' cannot run: $($Plugin.Problem)" }
    if ($Plugin.Access -ne 'read') { throw "The plugin '$($Plugin.Title)' wants '$($Plugin.Access)' access; only read-only plugins can run." }
    if (-not (Test-PSTermPluginApproved -Plugin $Plugin -Root $Root)) { throw "The plugin '$($Plugin.Title)' has not been approved." }
    if (@($Target).Count -eq 0) { throw 'No devices were chosen.' }

    # Parameters: the script's defaults, then what the caller gave, coerced to the declared types.
    $values = @{}
    foreach ($spec in ($Plugin.Parameters | Where-Object { -not $_.Reserved })) {
        if ($Parameter.ContainsKey($spec.Name)) { $values[$spec.Name] = ConvertTo-PSTermPluginValue -Spec $spec -Value $Parameter[$spec.Name] }
        elseif ($spec.Mandatory -and $null -eq $spec.Default) { throw "The parameter '$($spec.Label)' is required." }
    }
    foreach ($key in $Parameter.Keys) {
        if (-not ($Plugin.Parameters | Where-Object { $_.Name -eq $key })) { throw "The plugin has no parameter called '$key'." }
    }

    $timeout = $(if ($TimeoutSec -gt 0) { $TimeoutSec } else { $Plugin.TimeoutSec })
    $driver = Get-PSTermDriver -Name $Plugin.Driver -Root $Root
    $scriptText = [System.IO.File]::ReadAllText($Plugin.ScriptPath)
    $wantsTarget = [bool]($Plugin.Parameters | Where-Object { $_.Name -eq 'Target' })

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($fn in (Get-PSTermWorkerFunctions)) {
        $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fn.Name, $fn.ScriptBlock.ToString())))
    }
    $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Min($ThrottleLimit, [Math]::Max(1, @($Target).Count)), $iss, $Host)
    $pool.Open()

    $jobs = New-Object System.Collections.Generic.List[object]
    foreach ($profile in @($Target)) {
        $job = [pscustomobject]@{
            Target = [string]$profile.name; Status = 'Queued'; Error = ''; Rows = @(); Commands = @()
            Seconds = 0.0; Done = $false; PS = $null; Handle = $null; Ctx = $null
        }
        $jobs.Add($job)

        $login = $null
        try { $login = Resolve-PSTermDeviceLogin -Profile $profile -Store $Store -Root $Root -Credential $Credential -EnableCredential $EnableCredential }
        catch { $job.Status = 'Failed'; $job.Error = $_.Exception.Message; $job.Done = $true; continue }

        $address = Get-PSTermProfileTarget -Profile $profile
        $ctx = [hashtable]::Synchronized(@{
            Profile = $profile; Login = $login; Driver = $driver; Enter = [bool]$Plugin.Enter
            AcceptHostKey = [bool]$AcceptHostKey; ConnectTimeoutSec = [Math]::Min(60, $timeout)
            Factory = $SessionFactory; ScriptText = $scriptText; Parameter = $values; WantsTarget = $wantsTarget
            TargetInfo = [pscustomobject]@{ Name = [string]$profile.name; Address = [string]$address; Type = [string]$profile.type }
            Status = 'Queued'; StartTick = 0; EndTick = 0; Finished = $false; Error = ''
            Rows = @(); Commands = @(); Session = $null
        })
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:PSTermPluginWorker).AddArgument($ctx)
        $job.Ctx = $ctx; $job.PS = $ps
        $job.Handle = $ps.BeginInvoke()
    }

    if (-not $LogFolder) { $LogFolder = Join-Path (Join-Path $Root 'Logs') 'plugins' }
    [pscustomobject]@{
        Plugin = $Plugin; Jobs = $jobs.ToArray(); Pool = $pool; Parameter = $values; TimeoutSec = $timeout
        Started = Get-Date; Finished = $null; Done = $false; Cancelled = $false
        Rows = @(); Hosts = @(); LogPath = ''; LogFolder = $LogFolder
    }
}

function Update-PSTermPluginRun {
    <#
    .SYNOPSIS
        Collect what has finished, enforce the per-device timeout, and close the run when
        everything is done. Cheap enough to call from a UI timer. Returns the run.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Run)

    if ($Run.Done) { return $Run }
    $now = [Environment]::TickCount

    foreach ($job in $Run.Jobs) {
        if ($job.Done) { continue }
        $ctx = $job.Ctx

        $stopIt = $null
        if ($Run.Cancelled) { $stopIt = 'Cancelled' }
        elseif ($ctx.Status -eq 'Running' -and -not $ctx.Finished -and ($now - $ctx.StartTick) -gt ($Run.TimeoutSec * 1000)) { $stopIt = 'TimedOut' }

        if ($stopIt) {
            # Letting go of the session wakes a script that is blocked waiting for the device.
            # Nothing here may wait: this runs on the window's thread.
            try { $s = $ctx.Session; if ($s) { $s.Abandon() } } catch { }
            $job.Status = $stopIt
            $job.Error = $(if ($stopIt -eq 'TimedOut') { "It took longer than $($Run.TimeoutSec) seconds." } else { 'Stopped.' })
            $job.Commands = @($ctx.Commands)
            $job.Seconds = $(if ($ctx.StartTick) { [Math]::Round(($now - $ctx.StartTick) / 1000.0, 1) } else { 0 })
            $job.Done = $true
            continue
        }

        if ($job.Handle.IsCompleted -or $ctx.Finished) {
            try { [void]$job.PS.EndInvoke($job.Handle) } catch { if (-not $ctx.Error) { $ctx.Error = $_.Exception.Message; $ctx.Status = 'Failed' } }
            $job.Status = $(if ($ctx.Status -eq 'OK') { 'OK' } else { 'Failed' })
            $job.Error = [string]$ctx.Error
            $job.Rows = @($ctx.Rows)
            $job.Commands = @($ctx.Commands)
            $job.Seconds = $(if ($ctx.StartTick) { [Math]::Round((($(if ($ctx.EndTick) { $ctx.EndTick } else { $now })) - $ctx.StartTick) / 1000.0, 1) } else { 0 })
            $job.Done = $true
        }
    }

    if (@($Run.Jobs | Where-Object { -not $_.Done }).Count -gt 0) { return $Run }

    # Everything is finished: put the rows together and write the log.
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($job in $Run.Jobs) {
        foreach ($row in $job.Rows) {
            $flat = [ordered]@{ Target = $job.Target }
            foreach ($prop in $row.PSObject.Properties) { $flat[$prop.Name] = $prop.Value }
            $rows.Add([pscustomobject]$flat)
        }
    }
    $Run.Rows = $rows.ToArray()
    $Run.Hosts = @($Run.Jobs | ForEach-Object {
        [pscustomobject][ordered]@{ Target = $_.Target; Status = $_.Status; Rows = @($_.Rows).Count; Seconds = $_.Seconds; Error = $_.Error }
    })
    $Run.Finished = Get-Date
    $Run.Done = $true

    Close-PSTermPluginRunPool -Run $Run

    try { $Run.LogPath = Write-PSTermPluginLog -Run $Run } catch { }
    $Run
}

function Close-PSTermPluginRunPool {
    <#
    .SYNOPSIS
        Release a finished run's workers without ever making the caller wait. A worker that was
        stopped or timed out may still be unwinding (a serial port that will not close, a login
        that has not noticed), and PowerShell's own Stop, Dispose and pool Close all wait for it.
        Those are left to a background thread.
    #>
    param([Parameter(Mandatory)]$Run)

    $stuck = @()
    foreach ($job in $Run.Jobs) {
        if (-not $job.PS) { continue }
        if ($job.Handle -and $job.Handle.IsCompleted) { try { $job.PS.Dispose() } catch { } }
        else { $stuck += $job }
    }
    if ($stuck.Count -eq 0) {
        try { $Run.Pool.Close(); $Run.Pool.Dispose() } catch { }
        return
    }
    # A thread-pool thread, not a runspace: it is a background thread, so a worker that never
    # finishes cannot keep the process alive after the window has closed.
    [PSTerm.Automation.BackgroundRelease]::Pipelines($Run.Pool, [object[]]@($stuck | ForEach-Object { $_.PS }))
}

function Wait-PSTermPluginRun {
    <#
    .SYNOPSIS
        Block until the run is finished, calling -OnProgress (with the run) as devices complete.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Run, [scriptblock]$OnProgress, [int]$PollMilliseconds = 100)

    $lastDone = -1
    while (-not $Run.Done) {
        [void](Update-PSTermPluginRun -Run $Run)
        $done = @($Run.Jobs | Where-Object { $_.Done }).Count
        if ($OnProgress -and $done -ne $lastDone) { $lastDone = $done; & $OnProgress $Run }
        if (-not $Run.Done) { Start-Sleep -Milliseconds $PollMilliseconds }
    }
    if ($OnProgress) { & $OnProgress $Run }
    $Run
}

function Stop-PSTermPluginRun {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Run)
    $Run.Cancelled = $true
    [void](Update-PSTermPluginRun -Run $Run)
}

function Invoke-PSTermPlugin {
    <#
    .SYNOPSIS
        Run a plugin against devices and wait for it. The result has Rows (everything the
        plugin returned, with a Target column), Hosts (how each device went) and LogPath.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Plugin,
        [Parameter(Mandatory)][object[]]$Target,
        [Parameter(Mandatory)]$Store,
        [Parameter(Mandatory)][string]$Root,
        [hashtable]$Parameter = @{},
        [string]$Credential = '',
        [string]$EnableCredential = '',
        [int]$ThrottleLimit = 10,
        [int]$TimeoutSec = 0,
        [string]$SessionFactory = '',
        [switch]$AcceptHostKey,
        [string]$LogFolder = '',
        [scriptblock]$OnProgress
    )
    $splat = @{}
    foreach ($key in $PSBoundParameters.Keys) { if ($key -ne 'OnProgress') { $splat[$key] = $PSBoundParameters[$key] } }
    $run = Start-PSTermPluginRun @splat
    Wait-PSTermPluginRun -Run $run -OnProgress $OnProgress
}

function Write-PSTermPluginLog {
    <#
    .SYNOPSIS
        A text log of one run: who asked for what, and what was sent to each device.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Run)

    $dir = $Run.LogFolder
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $path = Join-Path $dir ("{0}-{1}.log" -f $Run.Started.ToString('yyyyMMdd-HHmmss'), ($Run.Plugin.Id -replace '[^\w\-]', '_'))

    $out = New-Object System.Collections.Generic.List[string]
    $out.Add("Plugin    : $($Run.Plugin.Title) ($($Run.Plugin.Id)) version $($Run.Plugin.Version)")
    $out.Add("Files     : sha256 $($Run.Plugin.Hash)")
    $out.Add("Access    : $($Run.Plugin.Access) (the session refuses anything that is not a look-only command)")
    $out.Add("Started   : $($Run.Started.ToString('yyyy-MM-dd HH:mm:ss'))   by $($env:USERNAME) on $($env:COMPUTERNAME)")
    $out.Add("Finished  : $($Run.Finished.ToString('yyyy-MM-dd HH:mm:ss'))")
    $pairs = @()
    foreach ($key in @($Run.Parameter.Keys | Sort-Object)) { $pairs += ('{0}={1}' -f $key, $Run.Parameter[$key]) }
    $out.Add('Parameters: ' + ($pairs -join '; '))
    $out.Add("Devices   : $(@($Run.Jobs).Count)   rows: $(@($Run.Rows).Count)")
    $out.Add('')
    foreach ($job in $Run.Jobs) {
        $out.Add("[$($job.Status)] $($job.Target)   $($job.Seconds) s   $(@($job.Rows).Count) rows")
        if ($job.Error) { $out.Add("    error: $($job.Error)") }
        foreach ($c in $job.Commands) { $out.Add("    > $c") }
    }
    [System.IO.File]::WriteAllLines($path, $out, (New-Object System.Text.UTF8Encoding($false)))
    $path
}

function Export-PSTermPluginRows {
    <#
    .SYNOPSIS
        Write the rows of a run as a CSV file (UTF-8 with a header, comma separated).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Row, [Parameter(Mandatory)][string]$Path)

    $lines = New-Object System.Collections.Generic.List[string]
    $cols = New-Object System.Collections.Generic.List[string]
    foreach ($r in $Row) { foreach ($p in $r.PSObject.Properties) { if (-not $cols.Contains($p.Name)) { $cols.Add($p.Name) } } }
    $q = { param($v) $s = $(if ($null -eq $v) { '' } else { [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $v) }); '"' + ($s -replace '"', '""') + '"' }
    $lines.Add((($cols | ForEach-Object { & $q $_ }) -join ','))
    foreach ($r in $Row) {
        $lines.Add((($cols | ForEach-Object { $prop = $r.PSObject.Properties[$_]; & $q $(if ($prop) { $prop.Value } else { $null }) }) -join ','))
    }
    [System.IO.File]::WriteAllLines($Path, $lines, (New-Object System.Text.UTF8Encoding($true)))
}
