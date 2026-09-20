<#
.SYNOPSIS
    Colours and fonts for the application chrome, and DPI-aware layout helpers.

.DESCRIPTION
    v1 positioned every control with hard-coded pixel coordinates, which breaks on
    any display scaled above 100% - controls overlap and text is clipped. Nothing
    here uses absolute coordinates: sizes are expressed in logical units and scaled
    through Scale(), and layout is done with TableLayoutPanel and docking.
#>

Set-StrictMode -Version Latest

function New-PSTermChromeTheme {
    <#
    .SYNOPSIS
        The palette for the window chrome (not the terminal grid, which has its own).
    #>
    param([ValidateSet('Dark', 'Light')][string]$Mode = 'Dark')

    if ($Mode -eq 'Light') {
        [pscustomobject]@{
            Mode          = 'Light'
            Background    = [System.Drawing.Color]::FromArgb(246, 247, 249)
            Surface       = [System.Drawing.Color]::FromArgb(255, 255, 255)
            SurfaceAlt    = [System.Drawing.Color]::FromArgb(238, 240, 244)
            Border        = [System.Drawing.Color]::FromArgb(214, 217, 223)
            Text          = [System.Drawing.Color]::FromArgb(28, 30, 34)
            TextMuted     = [System.Drawing.Color]::FromArgb(104, 110, 120)
            Accent        = [System.Drawing.Color]::FromArgb(11, 95, 214)
            AccentText    = [System.Drawing.Color]::White
            Selection     = [System.Drawing.Color]::FromArgb(213, 229, 250)
            Success       = [System.Drawing.Color]::FromArgb(22, 128, 62)
            Warning       = [System.Drawing.Color]::FromArgb(176, 106, 0)
            Danger        = [System.Drawing.Color]::FromArgb(197, 48, 48)
        }
    }
    else {
        [pscustomobject]@{
            Mode          = 'Dark'
            Background    = [System.Drawing.Color]::FromArgb(24, 26, 32)
            Surface       = [System.Drawing.Color]::FromArgb(31, 34, 42)
            SurfaceAlt    = [System.Drawing.Color]::FromArgb(38, 42, 52)
            Border        = [System.Drawing.Color]::FromArgb(55, 60, 72)
            Text          = [System.Drawing.Color]::FromArgb(222, 226, 234)
            TextMuted     = [System.Drawing.Color]::FromArgb(140, 148, 162)
            Accent        = [System.Drawing.Color]::FromArgb(91, 174, 255)
            AccentText    = [System.Drawing.Color]::FromArgb(16, 18, 22)
            Selection     = [System.Drawing.Color]::FromArgb(47, 79, 127)
            Success       = [System.Drawing.Color]::FromArgb(111, 224, 111)
            Warning       = [System.Drawing.Color]::FromArgb(242, 210, 92)
            Danger        = [System.Drawing.Color]::FromArgb(255, 85, 85)
        }
    }
}

function New-PSTermTerminalPalette {
    <#
    .SYNOPSIS
        The terminal grid palette matching a theme name.
    #>
    param([string]$Name = 'Dark')

    $palette = New-Object PSTerm.Render.TerminalPalette
    if ($Name -eq 'Light') { $palette.LoadDefaultLight() } else { $palette.LoadDefaultDark() }
    $palette
}

function Get-PSTermScale {
    <#
    .SYNOPSIS
        The display scale factor for a control, so sizes can be given in logical units.
    #>
    param([System.Windows.Forms.Control]$Control)

    try {
        if ($Control -and $Control.IsHandleCreated) {
            # DeviceDpi is per-monitor aware where the OS supports it.
            return $Control.DeviceDpi / 96.0
        }
    }
    catch { }

    try {
        $g = [System.Drawing.Graphics]::FromHwnd([IntPtr]::Zero)
        try { return $g.DpiX / 96.0 } finally { $g.Dispose() }
    }
    catch { return 1.0 }
}

function Set-PSTermTitleBarTheme {
    <#
    .SYNOPSIS
        Ask the desktop window manager for a dark title bar.
    .DESCRIPTION
        WinForms cannot paint the non-client area, so a dark application with a
        light title bar looks half-finished. DWM has exposed this since Windows 10
        20H1 (attribute 20; 19 on earlier builds). It is cosmetic, so every failure
        path is silent.
    #>
    param(
        [Parameter(Mandatory)][System.Windows.Forms.Form]$Form,
        [bool]$Dark
    )

    try {
        if (-not ('PSTermNative.Dwm' -as [type])) {
            Add-Type -Namespace PSTermNative -Name Dwm -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attr, ref int value, int size);
'@ -ErrorAction Stop
        }

        if (-not $Form.IsHandleCreated) { return }
        $value = if ($Dark) { 1 } else { 0 }
        foreach ($attribute in @(20, 19)) {
            $result = [PSTermNative.Dwm]::DwmSetWindowAttribute($Form.Handle, $attribute, [ref]$value, 4)
            if ($result -eq 0) { break }
        }
    }
    catch { }
}

function Set-PSTermFormTheme {
    <#
    .SYNOPSIS
        Apply chrome colours to a control and everything inside it.
    .DESCRIPTION
        WinForms has no theming of its own, so this walks the tree. Controls that
        draw their own content (the terminal) are skipped by name.
    #>
    param(
        [Parameter(Mandatory)][System.Windows.Forms.Control]$Control,
        [Parameter(Mandatory)]$Theme
    )

    if ($Control -is [PSTerm.Render.TerminalControl]) { return }

    switch ($true) {
        ($Control -is [System.Windows.Forms.TabControl]) {
            # The strip behind the tabs is painted by the control itself; without
            # this it stays system-white against a dark terminal.
            $Control.BackColor = $Theme.Background
            $Control.ForeColor = $Theme.Text
        }
        ($Control -is [System.Windows.Forms.TabPage]) {
            $Control.BackColor = $Theme.Background
            $Control.ForeColor = $Theme.Text
        }
        ($Control -is [System.Windows.Forms.SplitContainer]) {
            $Control.BackColor = $Theme.Border
            $Control.Panel1.BackColor = $Theme.Surface
            $Control.Panel2.BackColor = $Theme.Background
        }
        ($Control -is [System.Windows.Forms.TextBox]) {
            $Control.BackColor = $Theme.SurfaceAlt
            $Control.ForeColor = $Theme.Text
            $Control.BorderStyle = 'FixedSingle'
        }
        ($Control -is [System.Windows.Forms.ComboBox]) {
            $Control.BackColor = $Theme.SurfaceAlt
            $Control.ForeColor = $Theme.Text
            $Control.FlatStyle = 'Flat'
        }
        ($Control -is [System.Windows.Forms.Button]) {
            $Control.BackColor = $Theme.SurfaceAlt
            $Control.ForeColor = $Theme.Text
            $Control.FlatStyle = 'Flat'
            $Control.FlatAppearance.BorderColor = $Theme.Border
            $Control.FlatAppearance.MouseOverBackColor = $Theme.Selection
        }
        ($Control -is [System.Windows.Forms.TreeView]) {
            $Control.BackColor = $Theme.Surface
            $Control.ForeColor = $Theme.Text
            $Control.BorderStyle = 'None'
            $Control.LineColor = $Theme.Border
        }
        ($Control -is [System.Windows.Forms.ListBox]) {
            $Control.BackColor = $Theme.Surface
            $Control.ForeColor = $Theme.Text
            $Control.BorderStyle = 'None'
        }
        ($Control -is [System.Windows.Forms.CheckBox]) {
            $Control.BackColor = [System.Drawing.Color]::Transparent
            $Control.ForeColor = $Theme.Text
            $Control.FlatStyle = 'Flat'
        }
        ($Control -is [System.Windows.Forms.Label]) {
            $Control.BackColor = [System.Drawing.Color]::Transparent
            $Control.ForeColor = $Theme.Text
        }
        ($Control -is [System.Windows.Forms.Panel]) {
            $Control.BackColor = $Theme.Background
            $Control.ForeColor = $Theme.Text
        }
        default {
            $Control.BackColor = $Theme.Background
            $Control.ForeColor = $Theme.Text
        }
    }

    foreach ($child in $Control.Controls) {
        Set-PSTermFormTheme -Control $child -Theme $Theme
    }
}

function New-PSTermFont {
    <#
    .SYNOPSIS
        A UI font, preferring the modern Windows UI face and degrading gracefully.
    #>
    param([float]$Size = 9, [System.Drawing.FontStyle]$Style = [System.Drawing.FontStyle]::Regular)

    foreach ($family in @('Segoe UI Variable Text', 'Segoe UI', 'Tahoma')) {
        try { return New-Object System.Drawing.Font($family, $Size, $Style) }
        catch { }
    }
    New-Object System.Drawing.Font([System.Drawing.FontFamily]::GenericSansSerif, $Size, $Style)
}

function New-PSTermMonospaceFont {
    <#
    .SYNOPSIS
        A monospace font for the terminal, preferring faces with good box-drawing
        and powerline coverage. Falls back through what Windows actually ships.
    #>
    param([string]$Family = 'Consolas', [float]$Size = 10.5)

    $candidates = @($Family, 'Cascadia Mono', 'Consolas', 'Lucida Console', 'Courier New')
    foreach ($name in $candidates) {
        if (-not $name) { continue }
        try {
            $font = New-Object System.Drawing.Font($name, $Size, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Point)
            # WinForms silently substitutes a default face for an unknown name, so
            # confirm we actually got what was asked for.
            if ($font.Name -eq $name) { return $font }
            $font.Dispose()
        }
        catch { }
    }
    New-Object System.Drawing.Font([System.Drawing.FontFamily]::GenericMonospace, $Size)
}

function Get-PSTermAvailableMonospaceFonts {
    <#
    .SYNOPSIS
        Installed fonts that are safe to use for a terminal grid.
    #>
    $result = New-Object System.Collections.Generic.List[string]
    try {
        $collection = New-Object System.Drawing.Text.InstalledFontCollection
        foreach ($family in $collection.Families) {
            try {
                if (-not $family.IsStyleAvailable([System.Drawing.FontStyle]::Regular)) { continue }
                # A proportional face makes the grid unusable, so measure two glyphs
                # of very different width and keep only families where they match.
                $font = New-Object System.Drawing.Font($family, 10)
                try {
                    $wide = [System.Windows.Forms.TextRenderer]::MeasureText('W', $font, [System.Drawing.Size]::new(1000, 100), 'NoPadding')
                    $thin = [System.Windows.Forms.TextRenderer]::MeasureText('i', $font, [System.Drawing.Size]::new(1000, 100), 'NoPadding')
                    if ($wide.Width -eq $thin.Width) { $result.Add($family.Name) }
                }
                finally { $font.Dispose() }
            }
            catch { }
        }
    }
    catch { }

    if ($result.Count -eq 0) { $result.Add('Consolas') }
    $result | Sort-Object -Unique
}
