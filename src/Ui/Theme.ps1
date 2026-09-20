<#
.SYNOPSIS
    Colours, fonts and scaling for the application chrome.

.DESCRIPTION
    Two rules keep the interface consistent with the rest of Windows:

    1. The UI font comes from the system (SystemFonts.MessageBoxFont), not from a
       hard-coded face and size. That is what makes PSTerm follow the user's
       display scaling and text-size settings.

    2. Every size is expressed in logical units and multiplied by a scale factor
       derived from that font, with AutoScaleMode set to None so WinForms does
       not apply a second scaling pass on top. v1 used absolute pixels and broke
       above 100% scaling; scaling twice clips controls just as badly.

    Controls the framework refuses to theme - combo boxes, check boxes, menus -
    are owner-drawn in src/Core/Render/ThemedControls.cs.
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
            Background    = [System.Drawing.Color]::FromArgb(243, 244, 247)
            Surface       = [System.Drawing.Color]::FromArgb(255, 255, 255)
            SurfaceAlt    = [System.Drawing.Color]::FromArgb(250, 250, 252)
            Field         = [System.Drawing.Color]::FromArgb(255, 255, 255)
            FieldHover    = [System.Drawing.Color]::FromArgb(240, 242, 246)
            Border        = [System.Drawing.Color]::FromArgb(214, 217, 223)
            BorderStrong  = [System.Drawing.Color]::FromArgb(160, 166, 176)
            Text          = [System.Drawing.Color]::FromArgb(26, 28, 32)
            TextMuted     = [System.Drawing.Color]::FromArgb(96, 102, 112)
            TextDisabled  = [System.Drawing.Color]::FromArgb(150, 156, 166)
            Accent        = [System.Drawing.Color]::FromArgb(0, 95, 184)
            AccentText    = [System.Drawing.Color]::White
            Selection     = [System.Drawing.Color]::FromArgb(205, 226, 252)
            Success       = [System.Drawing.Color]::FromArgb(16, 124, 16)
            Warning       = [System.Drawing.Color]::FromArgb(157, 93, 0)
            Danger        = [System.Drawing.Color]::FromArgb(196, 43, 28)
        }
    }
    else {
        [pscustomobject]@{
            Mode          = 'Dark'
            Background    = [System.Drawing.Color]::FromArgb(24, 26, 32)
            Surface       = [System.Drawing.Color]::FromArgb(32, 35, 43)
            SurfaceAlt    = [System.Drawing.Color]::FromArgb(38, 42, 52)
            Field         = [System.Drawing.Color]::FromArgb(43, 47, 58)
            FieldHover    = [System.Drawing.Color]::FromArgb(52, 57, 70)
            Border        = [System.Drawing.Color]::FromArgb(58, 63, 76)
            BorderStrong  = [System.Drawing.Color]::FromArgb(92, 100, 118)
            Text          = [System.Drawing.Color]::FromArgb(228, 231, 238)
            TextMuted     = [System.Drawing.Color]::FromArgb(150, 158, 172)
            TextDisabled  = [System.Drawing.Color]::FromArgb(108, 114, 128)
            Accent        = [System.Drawing.Color]::FromArgb(96, 176, 255)
            AccentText    = [System.Drawing.Color]::FromArgb(14, 16, 20)
            Selection     = [System.Drawing.Color]::FromArgb(45, 78, 128)
            Success       = [System.Drawing.Color]::FromArgb(108, 223, 108)
            Warning       = [System.Drawing.Color]::FromArgb(243, 212, 96)
            Danger        = [System.Drawing.Color]::FromArgb(255, 99, 99)
        }
    }
}

function New-PSTermControlTheme {
    <#
    .SYNOPSIS
        Convert a chrome theme into the colour set the owner-drawn controls use.
    #>
    param([Parameter(Mandatory)]$Theme)

    $ct = New-Object PSTerm.Render.ControlTheme
    $ct.Background   = $Theme.Background
    $ct.Surface      = $Theme.Surface
    $ct.Field        = $Theme.Field
    $ct.FieldHover   = $Theme.FieldHover
    $ct.Border       = $Theme.Border
    $ct.BorderStrong = $Theme.BorderStrong
    $ct.Text         = $Theme.Text
    $ct.TextMuted    = $Theme.TextMuted
    $ct.TextDisabled = $Theme.TextDisabled
    $ct.Accent       = $Theme.Accent
    $ct.AccentText   = $Theme.AccentText
    $ct.Selection    = $Theme.Selection
    $ct.IsDark       = ($Theme.Mode -eq 'Dark')
    $ct
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

function New-PSTermFont {
    <#
    .SYNOPSIS
        The system UI font, optionally resized relative to it.
    .DESCRIPTION
        Taking the face and size from Windows rather than naming "Segoe UI 9" is
        what makes the interface honour the user's text-size and scaling
        settings. -Relative nudges the size while keeping the system face.
    #>
    param(
        [float]$Relative = 1.0,
        [System.Drawing.FontStyle]$Style = [System.Drawing.FontStyle]::Regular
    )

    $base = [PSTerm.Render.NativeTheme]::GetUiFont()
    if ($Relative -eq 1.0 -and $Style -eq [System.Drawing.FontStyle]::Regular) { return $base }

    try {
        $font = New-Object System.Drawing.Font(
            $base.FontFamily, ($base.SizeInPoints * $Relative), $Style, [System.Drawing.GraphicsUnit]::Point)
        $base.Dispose()
        return $font
    }
    catch {
        return $base
    }
}

function Get-PSTermScale {
    <#
    .SYNOPSIS
        The layout scale factor, derived from the UI font.
    .DESCRIPTION
        Deriving it from the font Windows handed us works whether the process is
        DPI aware (the font comes back larger) or not (Windows scales the whole
        window, and the factor correctly stays 1). Reading DeviceDpi directly
        double-scales in the second case, which clips controls.
    #>
    param([System.Windows.Forms.Control]$Control)

    $font = if ($Control -and $Control.Font) { $Control.Font } else { [PSTerm.Render.NativeTheme]::GetUiFont() }
    [PSTerm.Render.NativeTheme]::GetScale($font)
}

function Set-PSTermTitleBarTheme {
    param(
        [Parameter(Mandatory)][System.Windows.Forms.Form]$Form,
        [bool]$Dark
    )
    [PSTerm.Render.NativeTheme]::SetDarkTitleBar($Form, $Dark)
}

function Set-PSTermFormTheme {
    <#
    .SYNOPSIS
        Apply chrome colours to a control and everything inside it.
    .DESCRIPTION
        WinForms has no theming of its own, so this walks the tree. Controls that
        paint their own content are handed the colour set rather than having
        BackColor poked, and the terminal is skipped entirely - it has its own
        palette.
    #>
    param(
        [Parameter(Mandatory)][System.Windows.Forms.Control]$Control,
        [Parameter(Mandatory)]$Theme,
        $ControlTheme
    )

    if ($Control -is [PSTerm.Render.TerminalControl]) { return }
    if (-not $ControlTheme) { $ControlTheme = New-PSTermControlTheme -Theme $Theme }

    switch ($true) {
        ($Control -is [PSTerm.Render.ThemedComboBox]) {
            $Control.ApplyTheme($ControlTheme)
        }
        ($Control -is [PSTerm.Render.ThemedCheckBox]) {
            $Control.ApplyTheme($ControlTheme)
        }
        ($Control -is [PSTerm.Render.TabStrip]) {
            Set-PSTermTabStripTheme -Strip $Control -Theme $Theme
        }
        ($Control -is [System.Windows.Forms.TextBox]) {
            $Control.BackColor = $Theme.Field
            # A box showing placeholder text keeps its muted colour. The theme
            # pass used to overwrite it, which is why the quick-connect bar was
            # hard to read.
            if (Test-PSTermPlaceholderActive -TextBox $Control) {
                $Control.ForeColor = $Theme.TextMuted
            }
            else {
                $Control.ForeColor = $Theme.Text
            }
            $Control.BorderStyle = 'FixedSingle'
        }
        ($Control -is [System.Windows.Forms.TreeView]) {
            $Control.BackColor = $Theme.Surface
            $Control.ForeColor = $Theme.Text
            $Control.BorderStyle = 'None'
            $Control.LineColor = $Theme.Border
            [PSTerm.Render.NativeTheme]::UseDarkScrollBars($Control)
        }
        ($Control -is [System.Windows.Forms.ListBox]) {
            $Control.BackColor = $Theme.Surface
            $Control.ForeColor = $Theme.Text
            $Control.BorderStyle = 'None'
            [PSTerm.Render.NativeTheme]::UseDarkScrollBars($Control)
        }
        ($Control -is [System.Windows.Forms.Button]) {
            $Control.BackColor = $Theme.Field
            $Control.ForeColor = $Theme.Text
            $Control.FlatStyle = 'Flat'
            $Control.FlatAppearance.BorderSize = 1
            $Control.FlatAppearance.BorderColor = $Theme.Border
            $Control.FlatAppearance.MouseOverBackColor = $Theme.FieldHover
            $Control.FlatAppearance.MouseDownBackColor = $Theme.Selection
            $Control.UseVisualStyleBackColor = $false
        }
        ($Control -is [System.Windows.Forms.CheckBox]) {
            $Control.BackColor = [System.Drawing.Color]::Transparent
            $Control.ForeColor = $Theme.Text
        }
        ($Control -is [System.Windows.Forms.Label]) {
            $Control.BackColor = [System.Drawing.Color]::Transparent
            $Control.ForeColor = $Theme.Text
        }
        ($Control -is [System.Windows.Forms.SplitContainer]) {
            $Control.BackColor = $Theme.Border
            $Control.Panel1.BackColor = $Theme.Surface
            $Control.Panel2.BackColor = $Theme.Background
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
        Set-PSTermFormTheme -Control $child -Theme $Theme -ControlTheme $ControlTheme
    }
}

function Set-PSTermTabStripTheme {
    param(
        [Parameter(Mandatory)]$Strip,
        [Parameter(Mandatory)]$Theme
    )
    $Strip.StripBackground     = $Theme.Background
    $Strip.TabBackground       = $Theme.Background
    $Strip.ActiveTabBackground = $Theme.Surface
    $Strip.HoverTabBackground  = $Theme.SurfaceAlt
    $Strip.TextColor           = $Theme.Text
    $Strip.MutedTextColor      = $Theme.TextMuted
    $Strip.AccentColor         = $Theme.Accent
    $Strip.BorderColor         = $Theme.Border
    $Strip.ConnectedColor      = $Theme.Success
    $Strip.DisconnectedColor   = $Theme.TextMuted
    $Strip.FailedColor         = $Theme.Danger
    $Strip.Invalidate()
}

function New-PSTermMenu {
    <#
    .SYNOPSIS
        A context menu drawn in theme colours.
    .DESCRIPTION
        The default renderer paints a light gutter down the left of every menu
        and picks system colours for the highlighted item, which left the
        selected entry unreadable on a dark window.
    #>
    param([Parameter(Mandatory)]$Theme)

    $menu = New-Object System.Windows.Forms.ContextMenuStrip
    $menu.Renderer = New-Object PSTerm.Render.ThemedMenuRenderer((New-PSTermControlTheme -Theme $Theme))
    $menu.BackColor = $Theme.Surface
    $menu.ForeColor = $Theme.Text
    $menu.Font = New-PSTermFont
    $menu.ShowImageMargin = $false
    $menu
}

# =============================================================================
# Placeholder text
# =============================================================================
# WinForms gained PlaceholderText only in .NET 5 and PSTerm targets 5.1 as well,
# so it is done by hand. The state lives on the control's Tag so the theme pass
# can tell placeholder text from something the user actually typed.

function Set-PSTermPlaceholder {
    param(
        [System.Windows.Forms.TextBox]$TextBox,
        [string]$Text,
        [Parameter(Mandatory)]$Theme
    )

    $TextBox.Tag = [pscustomobject]@{
        Placeholder   = $Text
        IsPlaceholder = $true
        TextColor     = $Theme.Text
        MutedColor    = $Theme.TextMuted
    }
    $TextBox.Text = $Text
    $TextBox.ForeColor = $Theme.TextMuted

    $TextBox.Add_GotFocus({
        param($sender, $e)
        $state = $sender.Tag
        if ($state -and $state.IsPlaceholder) {
            $sender.Text = ''
            $state.IsPlaceholder = $false
            # Set the colour explicitly. ResetForeColor() falls back to the
            # system window text colour - near black - which is invisible here.
            $sender.ForeColor = $state.TextColor
        }
    })

    $TextBox.Add_LostFocus({
        param($sender, $e)
        $state = $sender.Tag
        if ($state -and [string]::IsNullOrEmpty($sender.Text)) {
            $state.IsPlaceholder = $true
            $sender.Text = $state.Placeholder
            $sender.ForeColor = $state.MutedColor
        }
    })
}

function Test-PSTermPlaceholderActive {
    param([System.Windows.Forms.TextBox]$TextBox)
    $state = $TextBox.Tag
    [bool]($state -and ($state.PSObject.Properties.Name -contains 'IsPlaceholder') -and $state.IsPlaceholder)
}

function Get-PSTermPlaceholderText {
    <#
    .SYNOPSIS
        The real contents of a placeholder text box, or '' when only the hint shows.
    #>
    param([System.Windows.Forms.TextBox]$TextBox)
    if (Test-PSTermPlaceholderActive -TextBox $TextBox) { return '' }
    $TextBox.Text.Trim()
}

function Clear-PSTermPlaceholder {
    param([System.Windows.Forms.TextBox]$TextBox)
    $TextBox.Text = ''
    $state = $TextBox.Tag
    if ($state -and ($state.PSObject.Properties.Name -contains 'IsPlaceholder')) {
        $state.IsPlaceholder = $false
        $TextBox.ForeColor = $state.TextColor
    }
}

# =============================================================================
# Terminal fonts
# =============================================================================

function New-PSTermMonospaceFont {
    <#
    .SYNOPSIS
        A monospace font for the terminal grid, falling back through what Windows
        actually ships.
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
                    $wide = [System.Windows.Forms.TextRenderer]::MeasureText('W', $font, (New-Object System.Drawing.Size(1000, 100)), 'NoPadding')
                    $thin = [System.Windows.Forms.TextRenderer]::MeasureText('i', $font, (New-Object System.Drawing.Size(1000, 100)), 'NoPadding')
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
