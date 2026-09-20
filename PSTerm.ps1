<#
    PSTerm - a native PowerShell Serial/SSH/Telnet terminal.
    Copyright (C) 2026 Marlo K <Plays.xenon@yahoo.de>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#>

<#
.SYNOPSIS
    Launches PSTerm.

.DESCRIPTION
    This script only bootstraps: it locates the install folder, compiles or loads
    the native core, loads the UI modules and shows the window. Everything that
    touches session data lives in the compiled core under src\Core.

.PARAMETER Connect
    Open a session immediately, using the same syntax as the quick-connect bar:
    "user@host", "host:2222", "telnet host", "COM3:115200" or a saved profile name.

.PARAMETER NoWindow
    Verify the installation and exit without showing the UI. Useful for a smoke
    test or a first-run compile on a new machine.

.PARAMETER Rebuild
    Force the native core to recompile even when the cache is valid.

.EXAMPLE
    .\PSTerm.ps1

.EXAMPLE
    .\PSTerm.ps1 -Connect admin@core-sw1
#>
[CmdletBinding()]
param(
    [string]$Connect,
    [switch]$NoWindow,
    [switch]$Rebuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# Locate the install folder
# -----------------------------------------------------------------------------
# $PSScriptRoot is empty when the script has been compiled into an executable,
# so fall back to the host process's own directory.

$Root = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Root)) {
    $Root = Split-Path -Parent ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
}
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = (Get-Location).Path }

# -----------------------------------------------------------------------------
# Load assemblies and the native core
# -----------------------------------------------------------------------------

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Visual styles first, before anything can create a window: if a window handle
# already exists when this is called it has no effect for the process, and the
# window frame and common controls fall back to the classic theme.
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

# The core is loaded next because DPI awareness also has to be declared before
# the first window and the call lives in the core. Loading an assembly creates
# no windows, so this ordering is safe.
. (Join-Path $Root 'src\Bootstrap.ps1')

try {
    Initialize-PSTermCore -Root $Root -Force:$Rebuild
    # Without this Windows renders at 96 DPI and stretches the bitmap, which is
    # what makes text look soft on a scaled display.
    $script:DpiAwareness = [PSTerm.Render.NativeTheme]::EnableDpiAwareness()
}
catch {
    $message = "PSTerm could not start.`n`n$($_.Exception.Message)"
    try {
        [void][System.Windows.Forms.MessageBox]::Show($message, 'PSTerm',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error)
    }
    catch { Write-Error $message }
    exit 1
}

. (Join-Path $Root 'src\Settings.ps1')
. (Join-Path $Root 'src\Secrets.ps1')
. (Join-Path $Root 'src\Profiles.ps1')
. (Join-Path $Root 'src\Connect.ps1')
. (Join-Path $Root 'src\Ui\Theme.ps1')
. (Join-Path $Root 'src\Ui\Dialogs.ps1')
. (Join-Path $Root 'src\Ui\MainWindow.ps1')

# -----------------------------------------------------------------------------
# Environment report / smoke test
# -----------------------------------------------------------------------------

if ($NoWindow) {
    Write-Host "PSTerm installation check" -ForegroundColor Cyan
    Write-Host ("-" * 40)
    Write-Host "Install folder  : $Root"
    Write-Host "PowerShell      : $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
    Write-Host "Native core     : loaded"
    Write-Host "DPI awareness   : $script:DpiAwareness" `
        -ForegroundColor $(if ($script:DpiAwareness -eq 'none') { 'Yellow' } else { 'Green' })

    $pty = [PSTerm.Backends.ConPtyBackend]::IsSupported
    Write-Host "Pseudo-console  : $(if ($pty) { 'available' } else { 'NOT available - SSH and local shells need Windows 10 1809+' })" `
        -ForegroundColor $(if ($pty) { 'Green' } else { 'Yellow' })

    $ssh = [PSTerm.Backends.ConPtyCommands]::FindSsh()
    Write-Host "OpenSSH client  : $(if ($ssh) { $ssh } else { 'NOT found - install the OpenSSH Client optional feature' })" `
        -ForegroundColor $(if ($ssh) { 'Green' } else { 'Yellow' })

    $ports = @([PSTerm.Backends.SerialBackend]::GetPortNames())
    Write-Host "Serial ports    : $(if ($ports.Count) { $ports -join ', ' } else { 'none detected' })"

    $store = Import-PSTermProfiles -Root $Root
    Write-Host "Saved profiles  : $(@($store.profiles).Count)"
    exit 0
}

# -----------------------------------------------------------------------------
# Run
# -----------------------------------------------------------------------------

$form = New-PSTermMainWindow -Root $Root

if ($Connect) {
    # Opened from Shown, not before: the terminal control must exist and be laid
    # out before it can tell the transport the real window size.
    $form.Add_Shown({
        $state = $form.Tag
        $profile = Get-PSTermProfileByName -Store $state.Store -Name $Connect
        if (-not $profile) { $profile = ConvertFrom-PSTermQuickConnect -Text $Connect }
        if ($profile) {
            New-PSTermSessionTab -State $state -Profile $profile | Out-Null
        }
        else {
            Set-PSTermStatusMessage -State $state -Message "Could not interpret '$Connect'." -Level Warning
        }
    }.GetNewClosure())
}

# Hide the console window when launched from one. PSTerm.cmd starts PowerShell
# without a window, but running the script directly from a prompt would otherwise
# leave an empty console behind the UI.
if (-not $env:PSTERM_KEEP_CONSOLE) {
    try {
        Add-Type -Namespace PSTermNative -Name Win32 -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern System.IntPtr GetConsoleWindow();
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool ShowWindow(System.IntPtr hWnd, int nCmdShow);
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern int GetConsoleProcessList(int[] processList, int count);
'@ -ErrorAction Stop

        $handle = [PSTermNative.Win32]::GetConsoleWindow()
        if ($handle -ne [IntPtr]::Zero) {
            # Only hide a console PSTerm owns. Hiding a shared one would take the
            # user's own prompt away with it.
            $list = New-Object int[] 4
            $count = [PSTermNative.Win32]::GetConsoleProcessList($list, 4)
            if ($count -le 1) { [void][PSTermNative.Win32]::ShowWindow($handle, 0) }
        }
    }
    catch {
        # Cosmetic only; never block startup over it.
    }
}

[System.Windows.Forms.Application]::Run($form)
