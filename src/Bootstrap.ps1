<#
.SYNOPSIS
    Compiles and loads the PSTerm native core.

.DESCRIPTION
    The performance-critical half of PSTerm (VT parsing, the screen buffer,
    rendering and the transport backends) is C# shipped as source under
    src/Core. It is compiled on first run with the C# compiler that is already
    present on every Windows machine - no third-party binaries, no downloads,
    no build step for the user.

    The result is cached to bin/PSTerm.Core.dll, keyed on a hash of the sources,
    so only the very first launch after a change pays the compile cost.

    Note for contributors: the core must stay within C# 5. Windows PowerShell
    5.1 compiles it through the .NET Framework CodeDom provider, which is the
    C# 5 compiler - string interpolation, ?., expression-bodied members and
    nameof will not build there.
#>

Set-StrictMode -Version Latest

$script:PSTermCoreLoaded = $false

function Get-PSTermCoreSources {
    param([Parameter(Mandatory)][string]$Root)
    Get-ChildItem -Path (Join-Path $Root 'src\Core') -Filter '*.cs' -Recurse -File |
        Sort-Object FullName
}

function Get-PSTermSourceHash {
    param([Parameter(Mandatory)][System.IO.FileInfo[]]$Sources)

    # Hash the concatenated content so a change anywhere invalidates the cache.
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $buffer = New-Object System.IO.MemoryStream
        foreach ($file in $Sources) {
            $nameBytes = [System.Text.Encoding]::UTF8.GetBytes($file.Name)
            $buffer.Write($nameBytes, 0, $nameBytes.Length)
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            $buffer.Write($bytes, 0, $bytes.Length)
        }
        $buffer.Position = 0
        ($sha.ComputeHash($buffer) | ForEach-Object { $_.ToString('x2') }) -join ''
    }
    finally {
        $sha.Dispose()
    }
}

function Get-PSTermReferences {
    <#
        Assemblies the core needs. Referenced by simple name so the same list
        resolves under .NET Framework (PS 5.1) and .NET (PS 7).
    #>
    $refs = @(
        'System.dll'
        'System.Core.dll'
        'System.Drawing.dll'
        'System.Windows.Forms.dll'
    )

    if ($PSVersionTable.PSEdition -eq 'Core') {
        # On .NET, passing any explicit reference REPLACES Add-Type's default set,
        # so the whole base class library has to be supplied. The runtime's
        # implementation assemblies cannot stand in for it: System.Private.CoreLib
        # is not a valid reference assembly, so anything that resolves through it
        # (List<T> included) fails to bind.
        #
        # PowerShell 7 ships the proper reference assemblies in $PSHOME\ref. Those
        # cover the BCL; WinForms, Drawing and Ports are then added from the
        # implementation assemblies already loaded in the process.
        $refs = New-Object System.Collections.Generic.List[string]

        $refDir = Join-Path $PSHOME 'ref'
        if (Test-Path -LiteralPath $refDir) {
            foreach ($f in Get-ChildItem -LiteralPath $refDir -Filter '*.dll' -File) {
                $refs.Add($f.FullName)
            }
        }
        else {
            # Unusual PowerShell layout: fall back to the .NET reference pack.
            $packRoot = Join-Path $env:ProgramFiles 'dotnet\packs\Microsoft.NETCore.App.Ref'
            if (Test-Path -LiteralPath $packRoot) {
                $newest = Get-ChildItem -LiteralPath $packRoot -Directory |
                          Sort-Object { try { [version]$_.Name } catch { [version]'0.0' } } -Descending |
                          Select-Object -First 1
                if ($newest) {
                    Get-ChildItem -LiteralPath $newest.FullName -Filter '*.dll' -File -Recurse |
                        ForEach-Object { $refs.Add($_.FullName) }
                }
            }
        }

        if ($refs.Count -eq 0) {
            throw @'
Could not locate .NET reference assemblies for this PowerShell 7 installation.
Run PSTerm with Windows PowerShell instead (PSTerm.cmd does this by default).
'@
        }

        foreach ($name in @('System.Windows.Forms', 'System.Drawing', 'System.IO.Ports')) {
            try { Add-Type -AssemblyName $name -ErrorAction Stop }
            catch { Write-Verbose "Optional assembly '$name' is unavailable: $($_.Exception.Message)" }
        }

        foreach ($typeName in @(
            'System.Windows.Forms.Control',
            'System.Drawing.Point',
            'System.IO.Ports.SerialPort'
        )) {
            $type = $typeName -as [type]
            if ($type -and $type.Assembly.Location) { $refs.Add($type.Assembly.Location) }
        }

        # WinForms types are split across a second assembly that is not always loaded yet.
        $primitives = Join-Path $PSHOME 'System.Windows.Forms.Primitives.dll'
        if (Test-Path -LiteralPath $primitives) { $refs.Add($primitives) }

        return @($refs | Sort-Object -Unique)
    }

    # Windows PowerShell: the CodeDom compiler resolves most framework
    # assemblies by simple name, but not System.IO.Ports. Load it and hand the
    # compiler its real path.
    try {
        Add-Type -AssemblyName 'System.IO.Ports' -ErrorAction Stop
        $portsPath = [System.IO.Ports.SerialPort].Assembly.Location
        if ($portsPath -and (Test-Path -LiteralPath $portsPath)) { $refs += $portsPath }
    }
    catch {
        # Serial support is unavailable on this machine; SSH and Telnet still work.
        Write-Verbose "System.IO.Ports could not be resolved: $($_.Exception.Message)"
    }

    return $refs
}

function Initialize-PSTermCore {
    <#
    .SYNOPSIS
        Loads PSTerm.Core, compiling it first if the cache is cold or stale.
    .PARAMETER Root
        The PSTerm installation root (the folder containing src\).
    .PARAMETER Force
        Recompile even when a valid cached assembly exists.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [switch]$Force
    )

    if ($script:PSTermCoreLoaded -and -not $Force) { return }

    # Already loaded into this process (for example by a previous run in the
    # same session): the type is there, nothing to do.
    if (-not $Force -and ('PSTerm.Vt.TerminalEmulator' -as [type])) {
        $script:PSTermCoreLoaded = $true
        return
    }

    $sources = @(Get-PSTermCoreSources -Root $Root)
    if ($sources.Count -eq 0) {
        throw "No C# sources found under '$(Join-Path $Root 'src\Core')'. The installation looks incomplete."
    }

    $binDir = Join-Path $Root 'bin'
    if (-not (Test-Path -LiteralPath $binDir)) {
        New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    }

    # The cache key includes the PowerShell edition: the two editions compile
    # against different reference assemblies and cannot share an output.
    $edition = if ($PSVersionTable.PSEdition -eq 'Core') { 'core' } else { 'fx' }
    $hash = Get-PSTermSourceHash -Sources $sources
    $dllPath = Join-Path $binDir "PSTerm.Core.$edition.dll"
    $stampPath = Join-Path $binDir "PSTerm.Core.$edition.hash"

    $cacheValid = $false
    if (-not $Force -and (Test-Path -LiteralPath $dllPath) -and (Test-Path -LiteralPath $stampPath)) {
        try {
            $cacheValid = ((Get-Content -LiteralPath $stampPath -Raw).Trim() -eq $hash)
        }
        catch { $cacheValid = $false }
    }

    if ($cacheValid) {
        try {
            Add-Type -LiteralPath $dllPath -ErrorAction Stop
            $script:PSTermCoreLoaded = $true
            Write-Verbose "PSTerm core loaded from cache: $dllPath"
            return
        }
        catch {
            # A corrupt or locked cache falls through to a fresh compile.
            Write-Verbose "Cached core could not be loaded, recompiling: $($_.Exception.Message)"
        }
    }

    Write-Verbose "Compiling PSTerm core ($($sources.Count) source files)..."
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $addTypeArgs = @{
        Path                 = $sources.FullName
        ReferencedAssemblies = Get-PSTermReferences
        ErrorAction          = 'Stop'
    }

    # Compiling straight to the cache path would leave a half-written file behind
    # on failure, and fails outright if another PSTerm instance has it loaded.
    # Build to a temporary file and move it into place.
    $tempDll = Join-Path $binDir ("PSTerm.Core.$edition." + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        Add-Type @addTypeArgs -OutputAssembly $tempDll -OutputType Library

        try {
            Move-Item -LiteralPath $tempDll -Destination $dllPath -Force -ErrorAction Stop
            Set-Content -LiteralPath $stampPath -Value $hash -Encoding ASCII
        }
        catch {
            # Another instance holds the cached DLL open. Not fatal: load the
            # freshly built copy and leave the cache for next time.
            Write-Verbose "Could not update the core cache (in use?): $($_.Exception.Message)"
            Add-Type -LiteralPath $tempDll -ErrorAction Stop
            $script:PSTermCoreLoaded = $true
            return
        }

        Add-Type -LiteralPath $dllPath -ErrorAction Stop
        $script:PSTermCoreLoaded = $true
        $sw.Stop()
        Write-Verbose "PSTerm core compiled in $($sw.ElapsedMilliseconds) ms -> $dllPath"
    }
    catch {
        if (Test-Path -LiteralPath $tempDll) {
            Remove-Item -LiteralPath $tempDll -Force -ErrorAction SilentlyContinue
        }
        throw "Failed to compile the PSTerm core.`n$($_.Exception.Message)"
    }
}
