<#
.SYNOPSIS
    The PSTerm main window: toolbar, session tree, tabs, quick connect and command palette.

.DESCRIPTION
    Layout is entirely docking and TableLayoutPanel, with sizes scaled from the
    display DPI. v1 used absolute pixel coordinates throughout, which breaks on
    any display above 100% scaling.

    All session I/O happens in the compiled core. This file only builds controls
    and reacts to user actions, so nothing here sits in the data path.
#>

Set-StrictMode -Version Latest

# Colours a tab can be marked with.
$script:PSTermMarkColours = [ordered]@{
    Red    = [System.Drawing.Color]::FromArgb(232, 78, 78)
    Orange = [System.Drawing.Color]::FromArgb(240, 154, 56)
    Yellow = [System.Drawing.Color]::FromArgb(232, 202, 64)
    Green  = [System.Drawing.Color]::FromArgb(86, 190, 104)
    Blue   = [System.Drawing.Color]::FromArgb(74, 144, 236)
    Purple = [System.Drawing.Color]::FromArgb(164, 108, 222)
    Grey   = [System.Drawing.Color]::FromArgb(142, 150, 164)
}

function New-PSTermMainWindow {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root)

    # Credentials are protected with DPAPI, which PowerShell 5.1 has to be told to load.
    [void](Test-PSTermDpapiAvailable)

    $state = [pscustomobject]@{
        Root        = $Root
        Store       = (Import-PSTermProfiles -Root $Root)
        Theme       = $null
    # psobject, not object: PowerShell's array subexpression @(...) throws
    # "Argument types do not match" on a List[object] - on both 5.1 and 7 -
    # while every other element type works. The contents are PSCustomObjects
    # anyway, so this is also the more accurate type.
        Tabs        = (New-Object System.Collections.Generic.List[psobject])
        Form        = $null
        Ribbon      = $null
        TabStrip    = $null
        TabHost     = $null
        Split       = $null
        Tree        = $null
        SearchBox   = $null
        QuickBox    = $null
        TreeScroll  = $null
        TreeHost    = $null
        SidebarButton = $null
        Status      = $null
        StatusLeft  = $null
        StatusRight = $null
        Palette     = $null
        Tips        = $null
        # Folders the operator has folded; kept across rebuilds of the tree.
        Collapsed   = @{}
        TreeBuilding = $false
        # Connections waiting for a reverse-DNS answer.
        Lookups     = (New-Object System.Collections.Generic.List[psobject])
        MainTimer   = $null
        Ports       = $null
        PortsVersion = -1
        KnownPorts  = @{}
        PortsReady  = $false
        PendingSidebarWidth = 0
        DetectedPorts = @()
    }

    $settings = Import-PSTermSettings -Root $Root
    $state.Theme = New-PSTermChromeTheme -Mode $settings.theme
    Set-PSTermAppChrome -Theme $state.Theme -Root $Root

    # ---------------------------------------------------------------- form ---

    # ThemedForm buffers the whole window (WS_EX_COMPOSITED). WinForms' own
    # double buffering covers a control's own surface but not the seams between
    # siblings, which is what made drop-downs and menus flicker on hover.
    $form = New-Object PSTerm.Render.ThemedForm
    # Composited painting is left on for dialogs, where it removes the drop-down
    # and menu flicker, but turned off here: measured on this machine it roughly
    # doubles the cost of a full repaint (69ms -> 128ms), and the terminal
    # repaints its whole grid every time output scrolls. The containers in this
    # window are double-buffered individually instead.
    $form.CompositedPainting = $false
    $form.Text = 'PSTerm'
    $form.StartPosition = 'CenterScreen'
    $form.Font = New-PSTermFont
    $form.KeyPreview = $true
    $state.Form = $form

    $scale = Get-PSTermScale -Control $form
    $form.MinimumSize = New-Object System.Drawing.Size([int](780 * $scale), [int](520 * $scale))
    $form.Size = New-Object System.Drawing.Size([int](1180 * $scale), [int](760 * $scale))

    $tips = New-Object PSTerm.Render.ThemedToolTip
    $tips.Apply((New-PSTermControlTheme -Theme $state.Theme))
    $state.Tips = $tips

    # One height for every control that sits in a row beside a button, so the
    # quick-connect bar, the search box and the buttons line up exactly.
    $rowHeight = [int]($form.Font.Height * 1.85)

    # ------------------------------------------------------------- top bar ---

    $padY = [int](6 * $scale)
    $topBar = New-Object PSTerm.Render.ThemedPanel
    $topBar.Dock = 'Top'
    $topBar.Height = $rowHeight + ($padY * 2)
    $topBar.Padding = New-Object System.Windows.Forms.Padding([int](8 * $scale), $padY, [int](8 * $scale), $padY)

    # The sessions panel switch. The glyphs are the left and right chevrons, so it
    # reads as "fold the panel away" / "bring it back".
    $sidebarButton = New-Object System.Windows.Forms.Button
    $sidebarButton.Dock = 'Fill'
    $sidebarButton.Margin = New-Object System.Windows.Forms.Padding(0, 0, [int](6 * $scale), 0)
    $sidebarButton.TabStop = $false
    $iconFamily = [PSTerm.Render.IconFont]::Family
    if ($iconFamily) {
        $sidebarButton.Font = New-Object System.Drawing.Font($iconFamily, [float]($form.Font.SizeInPoints * 1.05))
    }
    $state.SidebarButton = $sidebarButton

    $quickFrame = New-Object PSTerm.Render.FieldFrame
    $quickFrame.Dock = 'Fill'
    $quickFrame.Font = New-PSTermFont
    $quickFrame.Margin = New-Object System.Windows.Forms.Padding(0)
    $quickBox = $quickFrame.Input
    $state.QuickBox = $quickBox

    # A placeholder beats a label here: the bar explains itself and costs no width.
    Set-PSTermPlaceholder -TextBox $quickBox -Theme $state.Theme `
        -Text 'Connect to    user@host    host:2222    telnet host    COM3:115200    cmd        (Enter)'

    $connectButton = New-Object System.Windows.Forms.Button
    $connectButton.Text = 'Connect'
    $connectButton.Dock = 'Fill'
    $connectButton.Margin = New-Object System.Windows.Forms.Padding([int](6 * $scale), 0, 0, 0)

    $menuButton = New-Object System.Windows.Forms.Button
    $menuButton.Text = 'Menu'
    $menuButton.Dock = 'Fill'
    $menuButton.Margin = New-Object System.Windows.Forms.Padding([int](6 * $scale), 0, 0, 0)

    $topLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $topLayout.Dock = 'Fill'
    $topLayout.ColumnCount = 4
    $topLayout.RowCount = 1
    [void]$topLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
    [void]$topLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Absolute', [int](42 * $scale))))
    [void]$topLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
    [void]$topLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Absolute', [int](96 * $scale))))
    [void]$topLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Absolute', [int](76 * $scale))))
    $topLayout.Controls.Add($sidebarButton, 0, 0)
    $topLayout.Controls.Add($quickFrame, 1, 0)
    $topLayout.Controls.Add($connectButton, 2, 0)
    $topLayout.Controls.Add($menuButton, 3, 0)
    $topBar.Controls.Add($topLayout)

    $tips.SetTip($sidebarButton, 'Hide or show the session list (Ctrl+B).')
    $tips.SetTip($quickBox, 'Type where to connect and press Enter: user@host, host:2222, telnet host, COM3:115200, a saved connection name, or cmd.')
    $tips.SetTip($connectButton, 'Connect to what is typed in the box (Enter).')
    $tips.SetTip($menuButton, 'Import and export connections, credentials, settings and the About box.')

    # -------------------------------------------------------------- toolbar --

    $ribbon = New-Object PSTerm.Render.RibbonBar
    $ribbon.Font = New-PSTermFont
    $ribbon.Height = $ribbon.PreferredBarHeight()
    $state.Ribbon = $ribbon

    # Segoe MDL2 / Fluent glyph codes; the second string is what shows if no icon
    # font is installed.
    [void]$ribbon.Add('Connection', 'new',       'New',       ([string][char]0xE710), '+', 'New connection. Opens the connection editor (Ctrl+Shift+T types a destination instead).')
    [void]$ribbon.Add('Connection', 'reconnect', 'Reconnect', ([string][char]0xE72C), 'R', 'Close this session and connect again with the same settings (Ctrl+Shift+R).')
    [void]$ribbon.Add('Connection', 'duplicate', 'Duplicate', ([string][char]0xE8A7), 'D', 'Open another session to the same device in a new tab.')
    [void]$ribbon.Add('Connection', 'close',     'Close',     ([string][char]0xE711), 'X', 'Close this tab (Ctrl+Shift+W).')
    [void]$ribbon.Add('Edit',       'copy',      'Copy',      ([string][char]0xE8C8), 'C', 'Copy the selected text. Selecting text copies it already; right-click copies too.')
    [void]$ribbon.Add('Edit',       'paste',     'Paste',     ([string][char]0xE77F), 'P', 'Paste the clipboard into the session (Ctrl+Shift+V, or right-click).')
    [void]$ribbon.Add('Edit',       'selectall', 'Select all', ([string][char]0xE8B3), 'A', 'Select everything in the terminal, scrollback included.')
    [void]$ribbon.Add('Terminal',   'find',      'Find',      ([string][char]0xE721), 'F', 'Search the scrollback (Ctrl+Shift+F).')
    [void]$ribbon.Add('Terminal',   'clear',     'Clear',     ([string][char]0xE75C), 'C', 'Clear the scrollback (Ctrl+Shift+L).')
    [void]$ribbon.Add('Terminal',   'reset',     'Reset',     ([string][char]0xE895), 'R', 'Reset the terminal: clear the screen, the scrollback and any stuck modes or colours.')
    [void]$ribbon.Add('Terminal',   'break',     'Break',     ([string][char]0xE7BA), 'B', 'Send a serial break (serial connections only). Used to interrupt a boot or reach a ROM monitor.')
    $credItem = $ribbon.Add('Automation', 'creds', 'Credentials', ([string][char]0xE192), 'K', 'Quick credentials: send a saved user name or password to the terminal, for example an enable password.')
    $credItem.DropDown = $true
    $importItem = $ribbon.Add('Sessions', 'import', 'Import', ([string][char]0xE896), 'I', 'Import connections from a CSV file, a PSTerm session file, PuTTY or ssh_config.')
    $importItem.DropDown = $true
    $exportItem = $ribbon.Add('Sessions', 'export', 'Export', ([string][char]0xE898), 'E', 'Export connections to a PSTerm session file to back them up or share them. Passwords are never included.')
    $exportItem.DropDown = $true
    $sideItem = $ribbon.Add('View', 'sidebar', 'Sessions', ([string][char]0xE700), 'S', 'Show or hide the session list (Ctrl+B).')
    $sideItem.Toggle = $true
    $sideItem.Checked = [bool]$settings.sidebarVisible
    [void]$ribbon.Add('View', 'theme', 'Theme', ([string][char]0xE790), 'T', 'Switch between the dark and the light interface.')

    # -------------------------------------------------------------- splitter -

    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = 'Fill'
    $split.SplitterWidth = [Math]::Max(4, [int](4 * $scale))
    $split.FixedPanel = 'Panel1'
    $state.Split = $split

    # ------------------------------------------------------- session tree ----

    $sidePanel = New-Object PSTerm.Render.ThemedPanel
    $sidePanel.Dock = 'Fill'

    $searchHost = New-Object PSTerm.Render.ThemedPanel
    $searchHost.Dock = 'Top'
    # The same height as the quick-connect bar and the buttons: one row height, with
    # the padding counted on both sides so no rounding can make them differ.
    $searchPad = [int](6 * $scale)
    $searchHost.Height = $rowHeight + ($searchPad * 2)
    $searchHost.Padding = New-Object System.Windows.Forms.Padding($searchPad)

    $searchFrame = New-Object PSTerm.Render.FieldFrame
    $searchFrame.Dock = 'Fill'
    $searchFrame.Font = New-PSTermFont
    $searchBox = $searchFrame.Input
    $state.SearchBox = $searchBox
    Set-PSTermPlaceholder -TextBox $searchBox -Theme $state.Theme -Text 'Search sessions'
    $searchHost.Controls.Add($searchFrame)
    $tips.SetTip($searchBox, 'Filter the list by name, address or folder.')

    # ThemedTreeView: TreeView paints its selection bar, expander glyphs and
    # scroll bars with the system visual style and ignores BackColor.
    $treeHost = New-Object PSTerm.Render.ThemedPanel
    $treeHost.Dock = 'Fill'

    $treeScroll = New-Object PSTerm.Render.ThinScrollBar
    $treeScroll.Dock = 'Right'
    $treeScroll.Width = [int](12 * $scale)
    $treeScroll.Visible = $false

    $tree = New-Object PSTerm.Render.ThemedTreeView
    $tree.ItemHeight = [int]($form.Font.Height * 1.55)
    $tree.Indent = [int]($form.Font.Height * 1.1)
    $tree.Font = New-PSTermFont
    $state.Tree = $tree
    $state.TreeScroll = $treeScroll
    $state.TreeHost = $treeHost

    $treeHost.Controls.Add($tree)
    $treeHost.Controls.Add($treeScroll)
    # In front of the tree: the tree is deliberately wider than its panel so its own
    # (unthemeable) scroll bar falls outside, and this one has to cover the seam.
    $treeScroll.BringToFront()

    # Five equal columns, so the row fits however wide the panel is dragged.
    $treeButtons = New-Object System.Windows.Forms.TableLayoutPanel
    $treeButtons.Dock = 'Bottom'
    $treeButtons.Height = $rowHeight + [int](14 * $scale)
    $treeButtons.ColumnCount = 5
    $treeButtons.RowCount = 1
    $treeButtons.Padding = New-Object System.Windows.Forms.Padding([int](6 * $scale), [int](6 * $scale), [int](6 * $scale), [int](6 * $scale))
    for ($i = 0; $i -lt 5; $i++) { [void]$treeButtons.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 20))) }
    [void]$treeButtons.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))

    $buttons = @()
    foreach ($caption in 'New', 'Folder', 'Edit', 'Pin', 'Delete') {
        $b = New-Object System.Windows.Forms.Button
        $b.Text = $caption
        $b.Dock = 'Fill'
        $b.Margin = New-Object System.Windows.Forms.Padding(0, 0, [int](4 * $scale), 0)
        $buttons += $b
    }
    $newButton, $folderButton, $editButton, $pinButton, $deleteButton = $buttons
    for ($i = 0; $i -lt 5; $i++) { $treeButtons.Controls.Add($buttons[$i], $i, 0) }

    $tips.SetTip($newButton, 'New connection. If a folder is selected it is created inside it, with that folder''s default settings.')
    $tips.SetTip($folderButton, 'New folder (inside the selected folder, if there is one).')
    $tips.SetTip($editButton, 'Edit the selected connection, or the selected folder''s default settings.')
    $tips.SetTip($pinButton, 'Pin the selected connection to the top of the list, or unpin it.')
    $tips.SetTip($deleteButton, 'Delete the selected connection or folder.')

    # Order matters for docking: Fill is added first so Top and Bottom take their
    # space from the edges rather than overlapping it.
    $sidePanel.Controls.Add($treeHost)
    $sidePanel.Controls.Add($searchHost)
    $sidePanel.Controls.Add($treeButtons)
    $split.Panel1.Controls.Add($sidePanel)

    # ------------------------------------------------------------- tabs ------

    # A custom strip rather than TabControl: WinForms paints the band behind its
    # tabs with the system visual style and ignores BackColor, so a dark app ends
    # up with a white bar, and it offers no per-tab close button.
    $tabHost = New-Object PSTerm.Render.ThemedPanel
    $tabHost.Dock = 'Fill'

    $tabs = New-Object PSTerm.Render.TabStrip
    $tabs.Dock = 'Top'
    $tabs.Height = [int]($form.Font.Height * 2.0)
    $tabs.Font = New-PSTermFont
    $tabs.MaxTabWidth = [int](220 * $scale)
    $tabs.MinTabWidth = [int](100 * $scale)

    $state.TabStrip = $tabs
    $state.TabHost = $tabHost

    $tabHost.Controls.Add($tabs)
    $split.Panel2.Controls.Add($tabHost)

    # --------------------------------------------------------- status bar ----

    $status = New-Object System.Windows.Forms.StatusStrip
    # Off deliberately: the grip is system-drawn in light colours and cannot be
    # themed. The window still resizes from its edges.
    $status.SizingGrip = $false
    $statusLeft = New-Object System.Windows.Forms.ToolStripStatusLabel
    $statusLeft.Spring = $true
    $statusLeft.TextAlign = 'MiddleLeft'
    $statusLeft.Text = 'Ready'
    $statusRight = New-Object System.Windows.Forms.ToolStripStatusLabel
    $statusRight.TextAlign = 'MiddleRight'
    [void]$status.Items.Add($statusLeft)
    [void]$status.Items.Add($statusRight)
    $state.Status = $status
    $state.StatusLeft = $statusLeft
    $state.StatusRight = $statusRight

    $form.Controls.Add($split)
    $form.Controls.Add($ribbon)
    $form.Controls.Add($topBar)
    $form.Controls.Add($status)

    Apply-PSTermTheme -State $state

    $split.SplitterDistance = [int]([Math]::Max(180, [double]$settings.sidebarWidth) * $scale)
    Set-PSTermSidebar -State $state -Visible ([bool]$settings.sidebarVisible) -NoSave

    # =====================================================================
    # Behaviour
    # =====================================================================

    $tabs.Add_SelectedChanged({
        param($sender, $e)
        Show-PSTermTabContent -State $state
    }.GetNewClosure())

    $tabs.Add_CloseRequested({
        param($sender, $e)
        Close-PSTermTab -State $state -Index $e.Index
    }.GetNewClosure())

    # The plus button opens the connection editor, as the new-tab button of a
    # browser opens a page.
    $tabs.Add_NewTabRequested({
        Invoke-PSTermNewConnection -State $state
    }.GetNewClosure())

    $tabs.Add_ContextRequested({
        param($sender, $e)
        Show-PSTermTabContext -State $state -Index $e.Index -Location $e.ScreenLocation
    }.GetNewClosure())

    $sidebarButton.Add_Click({ Set-PSTermSidebar -State $state -Toggle }.GetNewClosure())

    $ribbon.Add_ItemClicked({
        param($sender, $e)
        Invoke-PSTermRibbonAction -State $state -Key $e.Item.Key -Location $e.MenuLocation
    }.GetNewClosure())

    $quickBox.Add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            $e.SuppressKeyPress = $true
            Invoke-PSTermQuickConnect -State $state
        }
        elseif ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape) {
            $e.SuppressKeyPress = $true
            $tab = Get-PSTermActiveTab -State $state
            if ($tab -and $tab.Control) { $tab.Control.Focus() | Out-Null }
        }
    }.GetNewClosure())

    $connectButton.Add_Click({ Invoke-PSTermQuickConnect -State $state }.GetNewClosure())

    $searchBox.Add_TextChanged({ Update-PSTermTree -State $state }.GetNewClosure())

    $treeHost.Add_Resize({ Update-PSTermTreeScroll -State $state }.GetNewClosure())
    $treeScroll.Add_ValueChanged({
        if ($state.Tree.TopNodeIndex -ne $treeScroll.Value) { $state.Tree.TopNodeIndex = $treeScroll.Value }
    }.GetNewClosure())
    # The tree scrolls itself on the wheel and on arrow keys, so the bar is
    # refreshed from the tree rather than trying to intercept every path.
    $tree.Add_MouseWheel({ Update-PSTermTreeScroll -State $state }.GetNewClosure())
    $tree.Add_AfterSelect({ Update-PSTermTreeScroll -State $state; Update-PSTermTreeButtons -State $state }.GetNewClosure())
    $tree.Add_AfterExpand({
        param($sender, $e)
        if (-not $state.TreeBuilding) { $state.Collapsed.Remove([string]$e.Node.Tag) }
        Update-PSTermTreeScroll -State $state
    }.GetNewClosure())
    $tree.Add_AfterCollapse({
        param($sender, $e)
        if (-not $state.TreeBuilding) { $state.Collapsed[[string]$e.Node.Tag] = $true }
        Update-PSTermTreeScroll -State $state
    }.GetNewClosure())

    $tree.Add_NodeMouseDoubleClick({
        param($sender, $e)
        $info = Get-PSTermNodeInfo -Node $e.Node
        if (-not $info) { return }
        switch ($info.Kind) {
            'p'   { Connect-PSTermProfileById -State $state -Id $info.Value }
            'com' { Open-PSTermDetectedPort -State $state -PortName $info.Value }
        }
    }.GetNewClosure())

    $tree.Add_KeyDown({
        param($sender, $e)
        $info = Get-PSTermNodeInfo -Node $sender.SelectedNode
        if (-not $info) { return }
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            $e.SuppressKeyPress = $true
            switch ($info.Kind) {
                'p'   { Connect-PSTermProfileById -State $state -Id $info.Value }
                'com' { Open-PSTermDetectedPort -State $state -PortName $info.Value }
            }
        }
        elseif ($e.KeyCode -eq [System.Windows.Forms.Keys]::Delete) {
            $e.SuppressKeyPress = $true
            Invoke-PSTermDeleteSelected -State $state
        }
        elseif ($e.KeyCode -eq [System.Windows.Forms.Keys]::F2 -and $info.Kind -eq 'f') {
            $e.SuppressKeyPress = $true
            Invoke-PSTermRenameFolder -State $state -Path $info.Value
        }
    }.GetNewClosure())

    $tree.Add_NodeContext({
        param($sender, $e)
        Show-PSTermTreeContext -State $state -Node $e.Node -Location $e.ScreenLocation
    }.GetNewClosure())

    $tree.Add_NodeButtonClicked({
        param($sender, $e)
        $info = Get-PSTermNodeInfo -Node $e.Node
        if (-not $info) { return }
        if ($e.Button -eq 'add') { Invoke-PSTermNewConnection -State $state -Folder $info.Value }
        elseif ($e.Button -eq 'pin') { Switch-PSTermPinned -State $state -Id $info.Value }
    }.GetNewClosure())

    $tree.Add_DropQuery({
        param($sender, $e)
        $e.Allowed = Test-PSTermDrop -State $state -Source $e.Source -Target $e.Target
    }.GetNewClosure())
    $tree.Add_DropCompleted({
        param($sender, $e)
        Complete-PSTermDrop -State $state -Source $e.Source -Target $e.Target
    }.GetNewClosure())

    $newButton.Add_Click({
        $info = Get-PSTermNodeInfo -Node $state.Tree.SelectedNode
        $folder = if ($info -and $info.Kind -eq 'f') { $info.Value } elseif ($info -and $info.Kind -eq 'p') { [string](Get-PSTermProfileById -Store $state.Store -Id $info.Value).folder } else { '' }
        Invoke-PSTermNewConnection -State $state -Folder $folder
    }.GetNewClosure())
    $folderButton.Add_Click({
        $info = Get-PSTermNodeInfo -Node $state.Tree.SelectedNode
        Invoke-PSTermNewFolder -State $state -Parent $(if ($info -and $info.Kind -eq 'f') { $info.Value } else { '' })
    }.GetNewClosure())
    $editButton.Add_Click({ Invoke-PSTermEditSelected -State $state }.GetNewClosure())
    $pinButton.Add_Click({
        $info = Get-PSTermNodeInfo -Node $state.Tree.SelectedNode
        if ($info -and $info.Kind -eq 'p') { Switch-PSTermPinned -State $state -Id $info.Value }
    }.GetNewClosure())
    $deleteButton.Add_Click({ Invoke-PSTermDeleteSelected -State $state }.GetNewClosure())

    $menuButton.Add_Click({
        Show-PSTermMenu -State $state -Anchor $menuButton
    }.GetNewClosure())

    $form.Add_KeyDown({
        param($sender, $e)
        Invoke-PSTermShortcut -State $state -EventArgs $e
    }.GetNewClosure())

    $split.Add_SplitterMoved({
        if (-not $split.Panel1Collapsed) { $state.PendingSidebarWidth = [int]($split.SplitterDistance / $scale) }
    }.GetNewClosure())

    $form.Add_FormClosing({
        param($sender, $e)
        if (-not (Confirm-PSTermClose -State $state)) { $e.Cancel = $true; return }
        if ($state.MainTimer) { $state.MainTimer.Stop() }
        if ($state.Ports) { $state.Ports.Dispose() }
        if ($state.PendingSidebarWidth -gt 0) {
            $current = Import-PSTermSettings -Root $state.Root
            $current.sidebarWidth = $state.PendingSidebarWidth
            Save-PSTermSettings -Root $state.Root -Settings $current
        }
    }.GetNewClosure())

    $form.Add_Shown({
        [PSTerm.Render.FontProbe]::Warm()
        Set-PSTermTitleBarTheme -Form $state.Form -Dark ($state.Theme.Mode -eq 'Dark')
        Update-PSTermTree -State $state
        Update-PSTermStatus -State $state
        $state.QuickBox.Focus() | Out-Null
        Start-PSTermBackgroundWork -State $state
        Set-PSTermStatusMessage -State $state -Message 'Ctrl+Shift+P for the command palette. Type a destination above and press Enter.'
    }.GetNewClosure())

    # The caller needs the state to open a session from the command line.
    $form.Tag = $state
    $form
}

# =============================================================================
# Theming
# =============================================================================

function Apply-PSTermTheme {
    param([Parameter(Mandatory)]$State)

    $theme = $State.Theme
    Set-PSTermFormTheme -Control $State.Form -Theme $theme

    $State.Status.BackColor = $theme.Surface
    $State.Status.ForeColor = $theme.TextMuted
    foreach ($item in $State.Status.Items) { $item.ForeColor = $theme.TextMuted }

    $controlTheme = New-PSTermControlTheme -Theme $theme
    $State.Tree.ApplyTheme($controlTheme)
    $State.TreeScroll.ApplyTheme($controlTheme)
    $State.Ribbon.ApplyTheme($controlTheme)
    $State.Tips.Apply($controlTheme)
    Set-PSTermTabStripTheme -Strip $State.TabStrip -Theme $theme
    Set-PSTermAppChrome -Theme $theme -Root $State.Root
    $State.Form.Invalidate($true)
}

# =============================================================================
# Sidebar
# =============================================================================

function Set-PSTermSidebar {
    <#
    .SYNOPSIS
        Show or hide the session list.
    #>
    param(
        [Parameter(Mandatory)]$State,
        [bool]$Visible,
        [switch]$Toggle,
        [switch]$NoSave
    )

    if ($Toggle) { $Visible = $State.Split.Panel1Collapsed }
    $State.Split.Panel1Collapsed = -not $Visible

    # A left chevron folds the panel away; a right one brings it back.
    $hasIcons = [bool][PSTerm.Render.IconFont]::Family
    $State.SidebarButton.Text = if ($Visible) { if ($hasIcons) { ([string][char]0xE76B) } else { '<' } } else { if ($hasIcons) { ([string][char]0xE76C) } else { '>' } }

    $item = $State.Ribbon.Find('sidebar')
    if ($item) { $item.Checked = $Visible; $State.Ribbon.Invalidate() }

    if (-not $NoSave) {
        $current = Import-PSTermSettings -Root $State.Root
        $current.sidebarVisible = $Visible
        Save-PSTermSettings -Root $State.Root -Settings $current
    }
    if ($State.Tabs.Count -gt 0) {
        $active = Get-PSTermActiveTab -State $State
        if ($active) { $active.Control.Focus() | Out-Null }
    }
}

# =============================================================================
# Toolbar
# =============================================================================

function Invoke-PSTermRibbonAction {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$Key, [System.Drawing.Point]$Location)

    $tab = Get-PSTermActiveTab -State $State
    $terminal = if ($tab) { $tab.Control } else { $null }

    switch ($Key) {
        'new'       { Invoke-PSTermNewConnection -State $State }
        'reconnect' { Restart-PSTermTab -State $State }
        'duplicate' { if ($tab) { [void](New-PSTermSessionTab -State $State -Profile $tab.Profile -Temporary:([bool]$tab.Temp)) } }
        'close'     { Close-PSTermTab -State $State }
        'copy'      { if ($terminal) { $terminal.CopySelection(); $terminal.Focus() | Out-Null } }
        'paste'     { if ($terminal) { $terminal.PasteClipboard(); $terminal.Focus() | Out-Null } }
        'selectall' { if ($terminal) { $terminal.SelectAll(); $terminal.Focus() | Out-Null } }
        'find'      { Show-PSTermFind -State $State }
        'clear'     { if ($terminal) { $terminal.ClearScrollback(); $terminal.Focus() | Out-Null } }
        'reset'     { if ($terminal) { $terminal.ResetTerminal(); $terminal.Focus() | Out-Null } }
        'break'     { Invoke-PSTermSendBreak -State $State }
        'creds'     { Show-PSTermCredentialMenu -State $State -Location $Location }
        'import'    { Show-PSTermImportMenu -State $State -Location $Location }
        'export'    { Show-PSTermExportMenu -State $State -Location $Location }
        'sidebar'   { Set-PSTermSidebar -State $State -Visible ([bool]$State.Ribbon.Find('sidebar').Checked) }
        'theme'     { Invoke-PSTermToggleTheme -State $State }
    }
}

function Show-PSTermImportMenu {
    param([Parameter(Mandatory)]$State, [System.Drawing.Point]$Location)

    $menu = New-PSTermMenu -Theme $State.Theme
    $items = @(
        @('From CSV file...', { Invoke-PSTermImportCsv -State $State }, 'Create connections from a spreadsheet export, for example a NetBox IP address list.'),
        @('From PSTerm session file...', { Invoke-PSTermImportSessions -State $State }, 'Load a .psterm file exported from PSTerm.'),
        @('From PuTTY sessions', { Invoke-PSTermImportPutty -State $State }, 'Read the sessions saved by PuTTY on this PC.'),
        @('From ssh_config hosts', { Invoke-PSTermImportSshConfig -State $State }, 'Read the hosts in ~/.ssh/config.')
    )
    foreach ($entry in $items) {
        $item = $menu.Items.Add($entry[0])
        $item.ToolTipText = $entry[2]
        $item.Add_Click($entry[1].GetNewClosure())
    }
    $menu.Show($Location)
}

function Show-PSTermExportMenu {
    param([Parameter(Mandatory)]$State, [System.Drawing.Point]$Location)

    $menu = New-PSTermMenu -Theme $State.Theme
    $all = $menu.Items.Add('All connections...')
    $all.ToolTipText = 'Save every connection and folder to a .psterm file.'
    $all.Add_Click({ Invoke-PSTermExportSessions -State $State -Scope All }.GetNewClosure())

    $info = Get-PSTermNodeInfo -Node $State.Tree.SelectedNode
    if ($info -and $info.Kind -eq 'f') {
        $path = $info.Value
        $item = $menu.Items.Add("Folder '$path'...")
        $item.Add_Click({ Invoke-PSTermExportSessions -State $State -Scope Folder -Target $path }.GetNewClosure())
    }
    elseif ($info -and $info.Kind -eq 'p') {
        $id = $info.Value
        $profile = Get-PSTermProfileById -Store $State.Store -Id $id
        if ($profile) {
            $item = $menu.Items.Add("Connection '$($profile.name)'...")
            $item.Add_Click({ Invoke-PSTermExportSessions -State $State -Scope Profile -Target $id }.GetNewClosure())
        }
    }
    $menu.Show($Location)
}

# =============================================================================
# Session tree
# =============================================================================

function Get-PSTermNodeInfo {
    <#
    .SYNOPSIS
        What a tree node is: Kind p (connection), f (folder), pin, ports or com.
    #>
    param($Node)
    if (-not $Node -or -not $Node.Tag) { return $null }
    $text = [string]$Node.Tag
    $colon = $text.IndexOf(':')
    if ($colon -lt 0) { return $null }
    [pscustomobject]@{ Kind = $text.Substring(0, $colon); Value = $text.Substring($colon + 1) }
}

function Update-PSTermTree {
    param([Parameter(Mandatory)]$State)

    $tree = $State.Tree
    $filter = Get-PSTermPlaceholderText -TextBox $State.SearchBox
    $selectedTag = if ($tree.SelectedNode) { [string]$tree.SelectedNode.Tag } else { '' }

    $State.TreeBuilding = $true
    $tree.BeginUpdate()
    try {
        $tree.Nodes.Clear()
        $tree.PinnedIds.Clear()
        foreach ($id in @($State.Store.pinned)) { [void]$tree.PinnedIds.Add([string]$id) }

        $profiles = @($State.Store.profiles)
        $pattern = $null
        if ($filter) {
            # -like treats [ ] * ? as wildcards, and a lone [ is an invalid pattern
            # that throws. Searching for "[lab" must mean those characters.
            $pattern = '*' + [System.Management.Automation.WildcardPattern]::Escape($filter) + '*'
            $profiles = @($profiles | Where-Object {
                $target = Get-PSTermProfileTarget -Profile $_
                ($_.name -like $pattern) -or ($target -like $pattern) -or ($_.folder -like $pattern)
            })
        }

        $label = {
            param($profile)
            $text = [string]$profile.name
            $target = Get-PSTermProfileTarget -Profile $profile
            if ($target -and $target -ne $text) { $text = "$text   -   $target" }
            $text
        }

        $addProfileNode = {
            param($collection, $profile)
            $node = $collection.Add((& $label $profile))
            $node.Tag = "p:$($profile.id)"
            $node.ToolTipText = "$($profile.type): $(Get-PSTermProfileTarget -Profile $profile)"
            $node
        }

        # Pinned connections come first.
        $pinned = @(@($State.Store.pinned) | ForEach-Object {
            $id = $_
            $profiles | Where-Object { $_.id -eq $id }
        } | Where-Object { $_ })
        if ($pinned.Count -gt 0) {
            $section = $tree.Nodes.Add('Pinned')
            $section.Tag = 'pin:'
            foreach ($profile in $pinned) { [void](& $addProfileNode $section.Nodes $profile) }
        }

        # Serial adapters that are plugged in right now.
        $ports = @($State.DetectedPorts)
        if ($ports.Count -gt 0 -and (-not $pattern -or 'serial ports' -like $pattern -or @($ports | Where-Object { $_.PortName -like $pattern }).Count -gt 0)) {
            $section = $tree.Nodes.Add('Detected serial ports')
            $section.Tag = 'ports:'
            foreach ($port in $ports) {
                $text = $port.PortName
                if ($port.Description) { $text = "$($port.PortName)   -   $($port.Description)" }
                $open = @($State.Tabs | Where-Object { -not $_.Closed -and $_.Profile.type -eq 'Serial' -and $_.Profile.serial.portName -eq $port.PortName }).Count -gt 0
                if ($open) { $text += '   (open)' }
                $node = $section.Nodes.Add($text)
                $node.Tag = "com:$($port.PortName)"
                $node.ToolTipText = "Not saved. Double-click to open $($port.PortName) at $((Import-PSTermSettings -Root $State.Root).detectedPortBaud) baud."
            }
        }

        # Folders, including empty ones, and connections inside them.
        $folderPaths = @(Get-PSTermAllFolderPaths -Store $State.Store)
        if ($pattern) {
            $needed = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($profile in $profiles) {
                $path = [string]$profile.folder
                while ($path) { [void]$needed.Add($path); $path = Get-PSTermParentFolder -Path $path }
            }
            $folderPaths = @($folderPaths | Where-Object { $needed.Contains($_) })
        }

        $folderNodes = @{}
        foreach ($path in $folderPaths) {
            $parentPath = Get-PSTermParentFolder -Path $path
            # Assigned in each branch: an if-expression would unroll the collection.
            if ($parentPath -and $folderNodes.ContainsKey($parentPath)) { $collection = $folderNodes[$parentPath].Nodes } else { $collection = $tree.Nodes }
            $segment = @(Split-PSTermFolderPath -Path $path)[-1]
            $node = $collection.Add($segment)
            $node.Tag = "f:$path"
            $folderNodes[$path] = $node
        }

        foreach ($profile in ($profiles | Sort-Object { [string]$_.name })) {
            $folder = [string]$profile.folder
            if ($folder -and $folderNodes.ContainsKey($folder)) { $collection = $folderNodes[$folder].Nodes } else { $collection = $tree.Nodes }
            [void](& $addProfileNode $collection $profile)
        }

        # Open everything the operator has not folded.
        $expand = {
            param($nodes)
            foreach ($n in $nodes) {
                if ($n.Nodes.Count -gt 0 -or ([string]$n.Tag).StartsWith('f:')) {
                    if ($pattern -or -not $State.Collapsed.ContainsKey([string]$n.Tag)) { $n.Expand() }
                    & $expand $n.Nodes
                }
            }
        }
        & $expand $tree.Nodes

        if ($selectedTag) {
            $match = Find-PSTermTreeNode -Nodes $tree.Nodes -Tag $selectedTag
            if ($match) { $tree.SelectedNode = $match }
        }
    }
    finally {
        $tree.EndUpdate()
        $State.TreeBuilding = $false
    }

    Update-PSTermTreeScroll -State $State
    Update-PSTermTreeButtons -State $State
}

function Update-PSTermTreeButtons {
    <#
    .SYNOPSIS
        Keep the Pin / Unpin button's caption and state in step with the selection.
    #>
    param([Parameter(Mandatory)]$State)
    $info = Get-PSTermNodeInfo -Node $State.Tree.SelectedNode
    foreach ($control in $State.TreeHost.Parent.Controls) {
        if ($control -is [System.Windows.Forms.TableLayoutPanel]) {
            foreach ($button in $control.Controls) {
                if ($button.Text -in @('Pin', 'Unpin')) {
                    $isProfile = [bool]($info -and $info.Kind -eq 'p')
                    $button.Enabled = $isProfile
                    $button.Text = if ($isProfile -and (Test-PSTermPinned -Store $State.Store -Id $info.Value)) { 'Unpin' } else { 'Pin' }
                }
            }
        }
    }
}

function Update-PSTermTreeScroll {
    <#
    .SYNOPSIS
        Size the tree so its own scroll bar is clipped out of view, and drive the
        themed one in its place.
    #>
    param([Parameter(Mandatory)]$State)

    $tree = $State.Tree
    $bar = $State.TreeScroll
    $host_ = $State.TreeHost
    if (-not $tree -or -not $bar -or -not $host_) { return }

    $total = $tree.VisibleNodeCount
    $perPage = $tree.RowsPerPage
    $needed = $total -gt $perPage

    if ($bar.Visible -ne $needed) { $bar.Visible = $needed }

    # The system scroll bar is pushed past the right edge of the clipping panel.
    $systemWidth = [System.Windows.Forms.SystemInformation]::VerticalScrollBarWidth
    $barWidth = if ($needed) { $bar.Width } else { 0 }
    $tree.SetBounds(0, 0, ($host_.ClientSize.Width - $barWidth + $systemWidth), $host_.ClientSize.Height)
    # Tell the tree where the visible edge is, so labels ellipsise on screen
    # rather than in the clipped-away strip.
    $tree.RightInset = $systemWidth

    if ($needed) {
        $bar.Maximum = [Math]::Max(0, $total - 1)
        $bar.LargeChange = $perPage
        $bar.Value = $tree.TopNodeIndex
    }
}

function Find-PSTermTreeNode {
    param($Nodes, [string]$Tag)
    foreach ($node in $Nodes) {
        if ([string]$node.Tag -eq $Tag) { return $node }
        $child = Find-PSTermTreeNode -Nodes $node.Nodes -Tag $Tag
        if ($child) { return $child }
    }
    $null
}

# ---- drag and drop -----------------------------------------------------------

function Test-PSTermDrop {
    param([Parameter(Mandatory)]$State, $Source, $Target)

    $s = Get-PSTermNodeInfo -Node $Source
    $t = Get-PSTermNodeInfo -Node $Target
    if (-not $s) { return $false }

    if ($s.Kind -eq 'p') {
        $profile = Get-PSTermProfileById -Store $State.Store -Id $s.Value
        if (-not $profile) { return $false }
        if (-not $t) { return [bool]$profile.folder }
        switch ($t.Kind) {
            'f'   { return ([string]$profile.folder -ne $t.Value) }
            'p'   {
                $other = Get-PSTermProfileById -Store $State.Store -Id $t.Value
                return ($other -and $other.id -ne $profile.id -and [string]$other.folder -ne [string]$profile.folder)
            }
            'pin' { return -not (Test-PSTermPinned -Store $State.Store -Id $s.Value) }
            default { return $false }
        }
    }

    if ($s.Kind -eq 'f') {
        if (-not $t) { return [bool](Get-PSTermParentFolder -Path $s.Value) }
        if ($t.Kind -ne 'f') { return $false }
        if ($t.Value -eq $s.Value -or $t.Value -like "$($s.Value)/*") { return $false }
        return ((Get-PSTermParentFolder -Path $s.Value) -ne $t.Value)
    }
    $false
}

function Complete-PSTermDrop {
    param([Parameter(Mandatory)]$State, $Source, $Target)

    $s = Get-PSTermNodeInfo -Node $Source
    $t = Get-PSTermNodeInfo -Node $Target
    if (-not $s) { return }

    if ($s.Kind -eq 'p') {
        if ($t -and $t.Kind -eq 'pin') {
            Set-PSTermPinned -Store $State.Store -Id $s.Value -Pinned $true
        }
        else {
            $destination = ''
            if ($t -and $t.Kind -eq 'f') { $destination = $t.Value }
            elseif ($t -and $t.Kind -eq 'p') { $destination = [string](Get-PSTermProfileById -Store $State.Store -Id $t.Value).folder }
            [void](Move-PSTermProfileToFolder -Store $State.Store -Id $s.Value -Path $destination)
        }
    }
    elseif ($s.Kind -eq 'f') {
        $leaf = @(Split-PSTermFolderPath -Path $s.Value)[-1]
        $destination = if ($t -and $t.Kind -eq 'f') { Join-PSTermFolderPath -Segments @($t.Value, $leaf) } else { $leaf }
        [void](Rename-PSTermFolder -Store $State.Store -OldPath $s.Value -NewPath $destination)
    }

    Save-PSTermProfiles -Root $State.Root -Store $State.Store
    Update-PSTermTree -State $State
}

# ---- context menus -----------------------------------------------------------

function Add-PSTermMenuItem {
    param($Menu, [string]$Text, [scriptblock]$Action, [string]$Tip = '', [bool]$Enabled = $true)
    $item = $Menu.Items.Add($Text)
    $item.Enabled = $Enabled
    if ($Tip) { $item.ToolTipText = $Tip }
    if ($Action) { $item.Add_Click($Action) }
    $item
}

function Show-PSTermTreeContext {
    param([Parameter(Mandatory)]$State, $Node, [System.Drawing.Point]$Location)

    $menu = New-PSTermMenu -Theme $State.Theme
    $info = Get-PSTermNodeInfo -Node $Node

    if (-not $info) {
        [void](Add-PSTermMenuItem $menu 'New connection...' { Invoke-PSTermNewConnection -State $State }.GetNewClosure() 'Create a connection at the top level.')
        [void](Add-PSTermMenuItem $menu 'New folder...' { Invoke-PSTermNewFolder -State $State -Parent '' }.GetNewClosure() 'Create a folder.')
        [void]$menu.Items.Add('-')
        [void](Add-PSTermMenuItem $menu 'Import from CSV...' { Invoke-PSTermImportCsv -State $State }.GetNewClosure() 'Create connections from a spreadsheet export.')
        [void](Add-PSTermMenuItem $menu 'Import PSTerm session file...' { Invoke-PSTermImportSessions -State $State }.GetNewClosure())
        $menu.Show($Location)
        return
    }

    switch ($info.Kind) {
        'p' {
            $id = $info.Value
            $profile = Get-PSTermProfileById -Store $State.Store -Id $id
            if (-not $profile) { return }
            $pinned = Test-PSTermPinned -Store $State.Store -Id $id

            [void](Add-PSTermMenuItem $menu 'Connect' { Connect-PSTermProfileById -State $State -Id $id }.GetNewClosure() 'Open this connection in a new tab.')
            [void](Add-PSTermMenuItem $menu 'Edit...' { Invoke-PSTermEditSelected -State $State -ProfileId $id }.GetNewClosure() 'Change this connection''s settings.')
            [void](Add-PSTermMenuItem $menu 'Duplicate' { Invoke-PSTermDuplicateProfile -State $State -Id $id }.GetNewClosure() 'Make a copy of this connection (without its password).')
            [void]$menu.Items.Add('-')
            [void](Add-PSTermMenuItem $menu $(if ($pinned) { 'Unpin' } else { 'Pin to top' }) { Switch-PSTermPinned -State $State -Id $id }.GetNewClosure() 'Keep this connection in the Pinned list at the top.')

            $move = $menu.Items.Add('Move to folder')
            $move.ToolTipText = 'Put this connection in another folder. You can also drag it there.'
            $move.DropDown.Renderer = $menu.Renderer
            $move.DropDown.BackColor = $State.Theme.Surface
            $move.DropDown.ForeColor = $State.Theme.Text
            $rootItem = $move.DropDownItems.Add('(top level)')
            $rootItem.Enabled = [bool]$profile.folder
            $rootItem.Add_Click({ [void](Move-PSTermProfileToFolder -Store $State.Store -Id $id -Path ''); Save-PSTermProfiles -Root $State.Root -Store $State.Store; Update-PSTermTree -State $State }.GetNewClosure())
            foreach ($path in @(Get-PSTermAllFolderPaths -Store $State.Store)) {
                $target = $path
                $entry = $move.DropDownItems.Add($target)
                $entry.Enabled = ([string]$profile.folder -ne $target)
                $entry.Add_Click({ [void](Move-PSTermProfileToFolder -Store $State.Store -Id $id -Path $target); Save-PSTermProfiles -Root $State.Root -Store $State.Store; Update-PSTermTree -State $State }.GetNewClosure())
            }

            [void]$menu.Items.Add('-')
            [void](Add-PSTermMenuItem $menu 'Export...' { Invoke-PSTermExportSessions -State $State -Scope Profile -Target $id }.GetNewClosure() 'Save this connection to a file you can share. The password is not included.')
            [void](Add-PSTermMenuItem $menu 'Delete' { Invoke-PSTermDeleteProfile -State $State -Id $id }.GetNewClosure() 'Delete this connection and its saved password.')
        }
        'f' {
            $path = $info.Value
            [void](Add-PSTermMenuItem $menu 'New connection here...' { Invoke-PSTermNewConnection -State $State -Folder $path }.GetNewClosure() 'Create a connection in this folder, starting from the folder''s default settings.')
            [void](Add-PSTermMenuItem $menu 'New subfolder...' { Invoke-PSTermNewFolder -State $State -Parent $path }.GetNewClosure())
            [void]$menu.Items.Add('-')
            [void](Add-PSTermMenuItem $menu 'Folder settings...' { [void](Invoke-PSTermEditProfile -State $State -FolderMode -FolderPath $path) }.GetNewClosure() 'The settings every new connection in this folder starts with: user, password, ports, terminal, logging, auto-enable.')
            [void](Add-PSTermMenuItem $menu 'Rename...' { Invoke-PSTermRenameFolder -State $State -Path $path }.GetNewClosure() 'Rename the folder (F2).')
            $node = $Node
            [void](Add-PSTermMenuItem $menu $(if ($Node.IsExpanded) { 'Collapse' } else { 'Expand' }) { if ($node.IsExpanded) { $node.Collapse() } else { $node.Expand() } }.GetNewClosure())
            [void]$menu.Items.Add('-')
            [void](Add-PSTermMenuItem $menu 'Export folder...' { Invoke-PSTermExportSessions -State $State -Scope Folder -Target $path }.GetNewClosure() 'Save this folder, its settings and its connections to a file you can share.')
            [void](Add-PSTermMenuItem $menu 'Import CSV into this folder...' { Invoke-PSTermImportCsv -State $State -Folder $path }.GetNewClosure())
            [void](Add-PSTermMenuItem $menu 'Delete folder' { Invoke-PSTermDeleteFolder -State $State -Path $path }.GetNewClosure() 'Delete the folder.')
        }
        'com' {
            $port = $info.Value
            [void](Add-PSTermMenuItem $menu "Open $port" { Open-PSTermDetectedPort -State $State -PortName $port }.GetNewClosure() 'Open the port now. Nothing is saved.')
            $baud = $menu.Items.Add('Open at baud rate')
            $baud.DropDown.Renderer = $menu.Renderer
            $baud.DropDown.BackColor = $State.Theme.Surface
            $baud.DropDown.ForeColor = $State.Theme.Text
            foreach ($rate in @(1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200)) {
                $r = $rate
                $entry = $baud.DropDownItems.Add([string]$r)
                $entry.Add_Click({ Open-PSTermDetectedPort -State $State -PortName $port -Baud $r }.GetNewClosure())
            }
            [void](Add-PSTermMenuItem $menu 'Save as connection...' { Save-PSTermDetectedPort -State $State -PortName $port }.GetNewClosure() 'Keep this port as a saved connection so you can set its speed and options.')
        }
        default {
            [void](Add-PSTermMenuItem $menu 'New connection...' { Invoke-PSTermNewConnection -State $State }.GetNewClosure())
        }
    }
    $menu.Show($Location)
}

# ---- tree actions --------------------------------------------------------------

function Invoke-PSTermNewConnection {
    param([Parameter(Mandatory)]$State, [string]$Folder = '')
    [void](Invoke-PSTermEditProfile -State $State -Profile $null -Folder $Folder)
}

function Invoke-PSTermEditSelected {
    param([Parameter(Mandatory)]$State, [string]$ProfileId = '')

    if ($ProfileId) {
        $profile = Get-PSTermProfileById -Store $State.Store -Id $ProfileId
        if ($profile) { [void](Invoke-PSTermEditProfile -State $State -Profile $profile) }
        return
    }

    $info = Get-PSTermNodeInfo -Node $State.Tree.SelectedNode
    if (-not $info) { return }
    if ($info.Kind -eq 'p') {
        $profile = Get-PSTermProfileById -Store $State.Store -Id $info.Value
        if ($profile) { [void](Invoke-PSTermEditProfile -State $State -Profile $profile) }
    }
    elseif ($info.Kind -eq 'f') {
        [void](Invoke-PSTermEditProfile -State $State -FolderMode -FolderPath $info.Value)
    }
}

function Invoke-PSTermNewFolder {
    param([Parameter(Mandatory)]$State, [string]$Parent = '')

    $answer = Show-PSTermInputDialog -State $State -Title 'New folder' -Prompt $(if ($Parent) { "Name of the new folder inside '$Parent':" } else { 'Name of the new folder:' }) `
        -Tip 'Use / to create several levels at once, for example Site A/Floor 2.'
    if (-not $answer -or -not $answer.Value.Trim()) { return }
    $path = Join-PSTermFolderPath -Segments @($Parent, ($answer.Value.Trim() -replace '\\', '/'))
    [void](Add-PSTermFolder -Store $State.Store -Path $path)
    Save-PSTermProfiles -Root $State.Root -Store $State.Store
    $State.Collapsed.Remove("f:$Parent")
    Update-PSTermTree -State $State
    Set-PSTermStatusMessage -State $State -Message "Created folder '$path'."
}

function Invoke-PSTermRenameFolder {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$Path)

    $leaf = @(Split-PSTermFolderPath -Path $Path)[-1]
    $answer = Show-PSTermInputDialog -State $State -Title 'Rename folder' -Prompt "New name for '$Path':" -Value $leaf
    if (-not $answer -or -not $answer.Value.Trim() -or $answer.Value.Trim() -eq $leaf) { return }
    $new = Join-PSTermFolderPath -Segments @((Get-PSTermParentFolder -Path $Path), ($answer.Value.Trim() -replace '[\\/]', '-'))
    if (Rename-PSTermFolder -Store $State.Store -OldPath $Path -NewPath $new) {
        Save-PSTermProfiles -Root $State.Root -Store $State.Store
        Update-PSTermTree -State $State
    }
}

function Invoke-PSTermDeleteFolder {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$Path)

    $inside = @(@($State.Store.profiles) | Where-Object { $_.folder -eq $Path -or ([string]$_.folder) -like "$Path/*" })
    $contents = $false
    if ($inside.Count -gt 0) {
        $answer = Show-PSTermMessage -Theme $State.Theme -Owner $State.Form -Title 'Delete folder' -Buttons YesNo -Level Warning `
            -Message "'$Path' holds $($inside.Count) connection(s).`r`n`r`nYes: delete the folder AND its connections.`r`nNo: leave everything as it is."
        if ($answer -ne 'Yes') { return }
        $contents = $true
    }
    else {
        $answer = Show-PSTermMessage -Theme $State.Theme -Owner $State.Form -Title 'Delete folder' -Buttons YesNo -Level Warning -Message "Delete the empty folder '$Path'?"
        if ($answer -ne 'Yes') { return }
    }

    $deleted = @(Remove-PSTermFolder -Store $State.Store -Path $Path -DeleteContents:$contents)
    foreach ($id in $deleted) {
        foreach ($key in @("profile:$id")) { Remove-PSTermSecret -Root $State.Root -Key $key }
    }
    Remove-PSTermSecret -Root $State.Root -Key "folder:$Path"
    Save-PSTermProfiles -Root $State.Root -Store $State.Store
    Update-PSTermTree -State $State
}

function Invoke-PSTermDuplicateProfile {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$Id)

    $profile = Get-PSTermProfileById -Store $State.Store -Id $Id
    if (-not $profile) { return }
    $copy = Copy-PSTermObject -Value $profile
    $copy.id = [guid]::NewGuid().ToString('N')
    $copy.name = "$($profile.name) (copy)"
    $copy.autoName = $false
    # The copy has no password of its own: a secret key is tied to one connection.
    $copy.credentialKey = ''
    [void](Set-PSTermProfile -Store $State.Store -Profile $copy)
    Save-PSTermProfiles -Root $State.Root -Store $State.Store
    Update-PSTermTree -State $State
    Set-PSTermStatusMessage -State $State -Message "Duplicated '$($profile.name)'. Set its password if it needs one."
}

function Switch-PSTermPinned {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$Id)
    $now = Test-PSTermPinned -Store $State.Store -Id $Id
    Set-PSTermPinned -Store $State.Store -Id $Id -Pinned (-not $now)
    Save-PSTermProfiles -Root $State.Root -Store $State.Store
    Update-PSTermTree -State $State
}

function Invoke-PSTermDeleteSelected {
    param([Parameter(Mandatory)]$State)
    $info = Get-PSTermNodeInfo -Node $State.Tree.SelectedNode
    if (-not $info) { Set-PSTermStatusMessage -State $State -Message 'Select a connection or folder to delete.' -Level Warning; return }
    switch ($info.Kind) {
        'p' { Invoke-PSTermDeleteProfile -State $State -Id $info.Value }
        'f' { Invoke-PSTermDeleteFolder -State $State -Path $info.Value }
        default { Set-PSTermStatusMessage -State $State -Message 'That entry cannot be deleted.' -Level Warning }
    }
}

# =============================================================================
# Detected serial ports
# =============================================================================

function Start-PSTermBackgroundWork {
    <#
    .SYNOPSIS
        Start the timers that keep the window in step with the outside world:
        serial ports appearing, and names arriving from DNS.
    #>
    param([Parameter(Mandatory)]$State)

    $settings = Import-PSTermSettings -Root $State.Root
    if ($settings.detectSerialPorts) {
        $State.Ports = New-Object PSTerm.Automation.SerialPortWatcher
        $State.Ports.Start(1500)
    }

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 700
    $timer.Add_Tick({
        Update-PSTermDetectedPorts -State $State
        Update-PSTermLookups -State $State
    }.GetNewClosure())
    $timer.Start()
    $State.MainTimer = $timer
}

function Update-PSTermDetectedPorts {
    param([Parameter(Mandatory)]$State)

    $watcher = $State.Ports
    if (-not $watcher -or $watcher.Version -eq $State.PortsVersion) { return }
    $State.PortsVersion = $watcher.Version

    $ports = @($watcher.Ports)
    $State.DetectedPorts = $ports

    # Announce an adapter that appeared since the last look - but not the ones that
    # were already plugged in when PSTerm started.
    $names = @($ports | ForEach-Object { $_.PortName })
    if ($State.PortsReady) {
        foreach ($port in $ports) {
            if (-not $State.KnownPorts.ContainsKey($port.PortName)) {
                $what = if ($port.Description) { " ($($port.Description))" } else { '' }
                Set-PSTermStatusMessage -State $State -Message "Serial port $($port.PortName)$what is available. Double-click it under Detected serial ports to open it."
            }
        }
    }
    $State.KnownPorts = @{}
    foreach ($n in $names) { $State.KnownPorts[$n] = $true }
    $State.PortsReady = $true

    Update-PSTermTree -State $State
}

function Open-PSTermDetectedPort {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$PortName, [int]$Baud = 0)

    $settings = Import-PSTermSettings -Root $State.Root
    if ($Baud -le 0) { $Baud = [int]$settings.detectedPortBaud }

    $profile = New-PSTermProfile -Name $PortName -Type 'Serial'
    $profile.serial.portName = $PortName
    $profile.serial.baudRate = $Baud
    $profile.terminal.backspace = $settings.defaultBackspace
    $profile.terminal.encoding = $settings.defaultEncoding
    $profile.terminal.theme = $settings.theme
    $profile.terminal.fontFamily = $settings.fontFamily
    $profile.terminal.fontSize = $settings.fontSize
    [void](New-PSTermSessionTab -State $State -Profile $profile -Temporary)
    Update-PSTermTree -State $State
}

function Save-PSTermDetectedPort {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$PortName)

    $settings = Import-PSTermSettings -Root $State.Root
    $profile = New-PSTermProfile -Name $PortName -Type 'Serial'
    $profile.serial.portName = $PortName
    $profile.serial.baudRate = [int]$settings.detectedPortBaud
    [void](Invoke-PSTermEditProfile -State $State -Profile $profile)
}

# =============================================================================
# Names that fill in by themselves
# =============================================================================

function Register-PSTermAutoName {
    <#
    .SYNOPSIS
        Start looking up a name for a connection that is only called by its address.
    #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Profile)

    $hostText = switch ($Profile.type) { 'SSH' { [string]$Profile.ssh.host } 'Telnet' { [string]$Profile.telnet.host } default { '' } }
    if (-not [PSTerm.Automation.NameLookup]::LooksLikeAddress($hostText)) { return }
    if (@($State.Lookups | Where-Object { $_.Profile.id -eq $Profile.id }).Count -gt 0) { return }

    $State.Lookups.Add([pscustomobject]@{
        Profile = $Profile
        Lookup  = [PSTerm.Automation.NameLookup]::Start($hostText)
        Started = [DateTime]::UtcNow
    })
}

function Update-PSTermLookups {
    param([Parameter(Mandatory)]$State)

    foreach ($entry in @($State.Lookups)) {
        $expired = ([DateTime]::UtcNow - $entry.Started).TotalSeconds -gt 12
        if (-not $entry.Lookup.Done -and -not $expired) { continue }
        [void]$State.Lookups.Remove($entry)
        if ($entry.Lookup.Name -and $entry.Profile.autoName) {
            Set-PSTermProfileName -State $State -Profile $entry.Profile -Name $entry.Lookup.Name
        }
    }
}

function Set-PSTermProfileName {
    <#
    .SYNOPSIS
        Give a connection the name the network or the device reported.
    #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Profile, [Parameter(Mandatory)][string]$Name)

    $Profile.name = $Name
    $Profile.autoName = $false

    $stored = Get-PSTermProfileById -Store $State.Store -Id ([string]$Profile.id)
    if ($stored) {
        $stored.name = $Name
        $stored.autoName = $false
        Save-PSTermProfiles -Root $State.Root -Store $State.Store
        Update-PSTermTree -State $State
    }

    foreach ($tab in @($State.Tabs)) {
        if ($tab.Profile.id -eq $Profile.id -and -not $tab.CustomTitle) { $tab.Item.Title = $Name }
    }
    $State.TabStrip.Invalidate()
    Update-PSTermStatus -State $State
    Set-PSTermStatusMessage -State $State -Message "Named the connection '$Name'."
}

function Start-PSTermPromptNameWatch {
    <#
    .SYNOPSIS
        Name a connection after the device, read from its prompt.
    .DESCRIPTION
        Used when DNS had no answer. A switch's prompt is its host name followed by
        > or #, so once the prompt is steady on screen that is the name.
    #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Tab)

    $watch = [pscustomobject]@{ Ticks = 0; Last = ''; Stable = 0 }
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 800
    $timer.Add_Tick({
        $watch.Ticks++
        if ($Tab.Closed -or -not $Tab.Profile.autoName -or $watch.Ticks -gt 75) {
            $timer.Stop(); $timer.Dispose(); return
        }

        $terminal = $Tab.Control
        $line = ''
        [System.Threading.Monitor]::Enter($terminal.SyncRoot)
        try {
            $screen = $terminal.Terminal.Screen
            $line = $screen.GetLineText($screen.HistoryCount + $terminal.Terminal.CursorY)
        }
        finally { [System.Threading.Monitor]::Exit($terminal.SyncRoot) }

        if ($line -match '^(?<name>[A-Za-z0-9][A-Za-z0-9._-]{1,62})(\((?:config[^)]*)\))?[>#]\s*$') {
            if ($watch.Last -eq $Matches['name']) { $watch.Stable++ } else { $watch.Last = $Matches['name']; $watch.Stable = 1 }
            if ($watch.Stable -ge 2) {
                $timer.Stop(); $timer.Dispose()
                Set-PSTermProfileName -State $State -Profile $Tab.Profile -Name $Matches['name']
            }
        }
        else { $watch.Stable = 0 }
    }.GetNewClosure())
    $timer.Start()
}

# =============================================================================
# Connecting
# =============================================================================

function Invoke-PSTermQuickConnect {
    param([Parameter(Mandatory)]$State)

    $text = Get-PSTermPlaceholderText -TextBox $State.QuickBox
    if (-not $text) { return }

    # An exact profile name wins over parsing, so saved sessions are reachable by name.
    $profile = Get-PSTermProfileByName -Store $State.Store -Name $text
    $temporary = $false
    if (-not $profile) {
        $profile = ConvertFrom-PSTermQuickConnect -Text $text
        $temporary = $true
    }

    if (-not $profile) {
        Set-PSTermStatusMessage -State $State -Message "Could not interpret '$text'. Try user@host, telnet host, COM3:115200 or cmd." -Level Warning
        return
    }

    if ($temporary -and $profile.type -in @('SSH', 'Telnet')) {
        $hostText = if ($profile.type -eq 'SSH') { [string]$profile.ssh.host } else { [string]$profile.telnet.host }
        if ([PSTerm.Automation.NameLookup]::LooksLikeAddress($hostText)) { $profile.autoName = $true }
    }

    Clear-PSTermPlaceholder -TextBox $State.QuickBox
    New-PSTermSessionTab -State $State -Profile $profile -Temporary:$temporary
}

function Connect-PSTermProfileById {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$Id)
    $profile = Get-PSTermProfileById -Store $State.Store -Id $Id
    if ($profile) { New-PSTermSessionTab -State $State -Profile $profile }
}

function New-PSTermSessionTab {
    <#
    .SYNOPSIS
        Create a tab and its terminal, then start connecting.
    #>
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)]$Profile,
        # A connection that is not in the saved list (quick connect, a detected port).
        [switch]$Temporary
    )

    $terminal = New-Object PSTerm.Render.TerminalControl
    $terminal.Dock = 'Fill'
    $terminal.Palette = New-PSTermTerminalPalette -Name ([string]$Profile.terminal.theme)
    $terminal.KeyMap = New-PSTermKeyEncoder -Profile $Profile
    $terminal.SetFont((New-PSTermMonospaceFont -Family ([string]$Profile.terminal.fontFamily) -Size ([float]$Profile.terminal.fontSize)))

    $State.TabHost.Controls.Add($terminal)
    $terminal.BringToFront()

    $item = $State.TabStrip.Add([string]$Profile.name, $null)
    $item.Tooltip = Get-PSTermProfileTarget -Profile $Profile
    $item.State = [PSTerm.Render.TabState]::Connecting
    if ($Profile.mark -and $script:PSTermMarkColours.Contains([string]$Profile.mark)) {
        $item.Mark = $script:PSTermMarkColours[[string]$Profile.mark]
    }

    # The control must be realised before its grid size is meaningful, so the
    # transport is told the real size rather than the 80x24 default.
    $terminal.CreateControl()
    [System.Windows.Forms.Application]::DoEvents()

    $tab = [pscustomobject]@{
        Item        = $item
        Control     = $terminal
        Session     = $null
        Profile     = $Profile
        Temp        = [bool]$Temporary
        Closed      = $false
        Logger      = $null
        RemoteTitle = ''
        AutoInputStarted = $false
        CustomTitle = $false
        User        = ''
        Password    = $null
        Probe       = $null
    }
    $State.Tabs.Add($tab)
    $item.Tag = $tab
    Show-PSTermTabContent -State $State

    # Input, resize and the other handlers belong to the terminal, not to one
    # connection attempt, so they are wired once here.
    $terminal.Add_Input({
        param($sender, $e)
        $session = $tab.Session
        if (-not $session) { return }

        if ($e.IsPaste) {
            if (Test-PSTermPacePaste -State $State -Tab $tab -Text $e.Text) { $session.SendPaced($e.Text); return }
        }
        elseif (-not $e.IsReply -and $session.IsPacing) {
            # Typing while a paste is being fed in means the operator wants it stopped.
            $session.CancelPaced()
        }
        $session.Send($e.Text)
    }.GetNewClosure())

    $terminal.Add_TerminalResized({
        param($sender, $e)
        if ($tab.Session) { $tab.Session.Resize($e.Cols, $e.Rows) }
        Update-PSTermStatus -State $State
    }.GetNewClosure())

    # Multi-line paste into a terminal that has not asked for bracketed paste runs
    # every line as it lands. Ask first.
    $terminal.Add_PasteRequested({
        param($sender, $e)
        $current = Import-PSTermSettings -Root $State.Root
        if (-not $current.confirmMultilinePaste) { return }
        $answer = Show-PSTermMessage -Theme $State.Theme -Owner $State.Form `
            -Title 'Paste' -Buttons YesNo `
            -Message "Paste $($e.LineCount) lines? Each line break is sent as Enter, so every line runs as soon as it arrives."
        if ($answer -ne 'Yes') { $e.Cancel = $true }
    }.GetNewClosure())

    $terminal.Add_TitleChanged({
        param($sender, $e)
        if (-not $e.Text) { return }
        # The tab keeps the profile name: it is what the operator chose and it
        # fits. The host's own title goes where there is room for it.
        $tab.RemoteTitle = $e.Text
        $tab.Item.Tooltip = $e.Text
        Update-PSTermStatus -State $State
    }.GetNewClosure())

    Start-PSTermConnection -State $State -Tab $tab

    Update-PSTermStatus -State $State
    $terminal.Focus() | Out-Null
    $tab
}

function Test-PSTermPacePaste {
    <#
    .SYNOPSIS
        Whether a paste into this tab should be fed to the device line by line.
    #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Tab, [string]$Text = '')

    # A device that asked for bracketed paste takes the whole block as one unit.
    if ($Text.StartsWith([string][char]27 + '[200~')) { return $false }

    switch ([string](Import-PSTermSettings -Root $State.Root).pacePaste) {
        'All'   { return $true }
        'Off'   { return $false }
        'Serial' { return ($Tab.Profile.type -eq 'Serial') }
        default { return $false }
    }
}

function Stop-PSTermConnectionAttempt {
    <#
    .SYNOPSIS
        End a tab's connection attempt before it started, saying why in the terminal.
    #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Tab, [Parameter(Mandatory)][string]$Message, [string]$Level = 'Warning')

    $Tab.Closed = $true
    $Tab.Item.State = [PSTerm.Render.TabState]::Failed
    $State.TabStrip.Invalidate()
    try { $Tab.Control.Feed("`r`n  $Message`r`n") } catch { }
    Set-PSTermStatusMessage -State $State -Message $Message -Level $Level
    Update-PSTermStatus -State $State
}

function Start-PSTermConnection {
    <#
    .SYNOPSIS
        Work out who to log in as, check an unknown SSH host key, then connect.
    #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Tab)

    $profile = $Tab.Profile
    $Tab.User = ''
    $Tab.Password = $null

    if ($profile.type -ne 'SSH') {
        if ($profile.type -eq 'Telnet') {
            $Tab.Password = (Resolve-PSTermLogin -Store $State.Store -Root $State.Root -Profile $profile).Password
        }
        Complete-PSTermConnection -State $State -Tab $Tab
        return
    }

    $login = Resolve-PSTermLogin -Store $State.Store -Root $State.Root -Profile $profile
    $user = [string]$login.User
    if (-not $user) { $user = [string](Import-PSTermSettings -Root $State.Root).defaultSshUser }

    # No user anywhere: ask, rather than letting ssh quietly use the Windows account
    # name - which a device with centralised logins treats as a failed attempt.
    if (-not $user) {
        $answer = Show-PSTermInputDialog -State $State -Title 'SSH user name' `
            -Prompt "Which user should PSTerm log in to $($profile.ssh.host) as?" `
            -CheckboxText 'Remember this user name for the connection' `
            -Tip 'PSTerm does not guess your Windows user name, because that is rarely the account on a switch or router.'
        if (-not $answer -or -not $answer.Value.Trim()) {
            Stop-PSTermConnectionAttempt -State $State -Tab $Tab -Message 'Not connected: no user name was given.'
            return
        }
        $user = $answer.Value.Trim()
        if ($answer.Checked -and -not $Tab.Temp) {
            $stored = Get-PSTermProfileById -Store $State.Store -Id ([string]$profile.id)
            if ($stored) { $stored.ssh.user = $user; Save-PSTermProfiles -Root $State.Root -Store $State.Store }
        }
    }
    $Tab.User = $user
    $Tab.Password = $login.Password

    # An unknown host key is asked about in a dialog, before the session exists, so
    # the question never lands in the middle of a login in the terminal.
    if (-not $profile.ssh.autoAcceptHostKey -and -not $profile.ssh.proxyJump) {
        $Tab.Control.Feed("`r`n  Checking the host key of $($profile.ssh.host)...`r`n")
        Set-PSTermStatusMessage -State $State -Message "Checking the host key of $($profile.ssh.host)..."
        $probe = [PSTerm.Automation.HostKeyProbe]::Start((New-PSTermSshOptions -Profile $profile -User $user))
        $Tab.Probe = $probe

        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = 100
        $timer.Add_Tick({
            if (-not $probe.Done) { return }
            $timer.Stop(); $timer.Dispose()
            if ($Tab.Closed) { return }

            $keys = @($probe.Keys)
            if (-not $probe.Known -and $keys.Count -gt 0) {
                $decision = Show-PSTermHostKeyDialog -State $State -HostName ([string]$profile.ssh.host) -Keys $keys
                if ($decision -eq 'Reject') {
                    Stop-PSTermConnectionAttempt -State $State -Tab $Tab -Message "Not connected: the host key of $($profile.ssh.host) was not trusted."
                    return
                }
                [PSTerm.Automation.HostKeyProbe]::Trust($probe)
                if ($decision -eq 'Always') {
                    $profile.ssh.autoAcceptHostKey = $true
                    $stored = Get-PSTermProfileById -Store $State.Store -Id ([string]$profile.id)
                    if ($stored) { $stored.ssh.autoAcceptHostKey = $true; Save-PSTermProfiles -Root $State.Root -Store $State.Store }
                }
            }
            Complete-PSTermConnection -State $State -Tab $Tab
        }.GetNewClosure())
        $timer.Start()
        return
    }

    Complete-PSTermConnection -State $State -Tab $Tab
}

function Complete-PSTermConnection {
    <#
    .SYNOPSIS
        Build the transport and the session, wire up automation, and connect.
    #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Tab)

    $Profile = $Tab.Profile
    $terminal = $Tab.Control
    $item = $Tab.Item

    try {
        $backend = New-PSTermBackend -Profile $Profile -Cols $terminal.Cols -Rows $terminal.Rows -User $Tab.User

        $encoding = ConvertTo-PSTermEnum ([PSTerm.Vt.TerminalEncoding]) $Profile.terminal.encoding ([PSTerm.Vt.TerminalEncoding]::Utf8)
        $decoder = New-Object PSTerm.Vt.StreamDecoder($encoding)

        $session = New-Object PSTerm.TerminalSession($backend, $terminal, $terminal.Terminal, $decoder)
        $session.SynchronizingObject = $terminal
        $Tab.Session = $session

        $loggerFailure = ''
        $logger = New-PSTermLogger -Profile $Profile -Root $State.Root -Failure ([ref]$loggerFailure)
        if ($logger) {
            $session.Logger = $logger
            $Tab.Logger = $logger
        }
        elseif ($loggerFailure) {
            $terminal.Feed("`r`n  Logging is on for this profile but could not be started:`r`n  $loggerFailure`r`n`r`n")
            Set-PSTermStatusMessage -State $State -Message "Logging could not be started: $loggerFailure" -Level Warning
        }

        Add-PSTermAutomation -State $State -Tab $Tab -Session $session

        $session.Add_PacingMessage({
            param($sender, $e)
            Set-PSTermStatusMessage -State $State -Message $e.Message
        }.GetNewClosure())

        $session.Add_RuleMatched({
            param($sender, $e)
            if ($e.Message -ne 'hostkey-prompt' -or $Tab.Closed) { return }
            # Only reached when the pre-flight check could not read the key (a jump host,
            # an algorithm the scanner does not offer): ssh itself is asking.
            $answer = Show-PSTermMessage -Theme $State.Theme -Owner $State.Form -Title 'Unknown host key' -Buttons YesNo `
                -Message "The server's host key is not known yet. Trust it and continue connecting?"
            $Tab.Session.Send($(if ($answer -eq 'Yes') { "yes`r" } else { "no`r" }))
        }.GetNewClosure())

        $session.Add_SessionClosed({
            param($sender, $e)
            Complete-PSTermTab -State $State -Tab $Tab -Reason $e.Reason -ExitCode $e.ExitCode
        }.GetNewClosure())

        $session.Add_StatusChanged({
            param($sender, $e)
            Set-PSTermStatusMessage -State $State -Message $e.Message
        }.GetNewClosure())

        # Raised when the link is actually up. Telnet connects in the background, so
        # Connect() returning says nothing about it; the dot stays amber until then.
        $session.Add_Connected({
            param($sender, $e)
            if ($Tab.Closed) { return }
            $Tab.Item.State = [PSTerm.Render.TabState]::Connected
            $State.TabStrip.Invalidate()
            Update-PSTermStatus -State $State
            Set-PSTermStatusMessage -State $State -Message "Connected: $(Get-PSTermProfileTarget -Profile $Tab.Profile)"

            if ($Tab.Profile.autoName) {
                Register-PSTermAutoName -State $State -Profile $Tab.Profile
                Start-PSTermPromptNameWatch -State $State -Tab $Tab
            }

            # Lines to send once connected. Never put a password here: profiles.json
            # is plain text.
            if (-not $Tab.AutoInputStarted) {
                $Tab.AutoInputStarted = $true
                $autoInput = @($Tab.Profile.autoInput | Where-Object { $_ })
                if ($autoInput.Count -gt 0) {
                    # Auto-enable gets the prompt first; the commands follow it.
                    $hold = if ($Tab.Profile.autoEnable.enabled) { [int]$Tab.Profile.autoEnable.delayMs + 3000 } else { 0 }
                    Start-PSTermAutoInput -Tab $Tab -Lines $autoInput -InitialDelayMs $hold
                }
            }
        }.GetNewClosure())

        $session.Connect()
    }
    catch {
        $Tab.Closed = $true
        $item.State = [PSTerm.Render.TabState]::Failed
        $State.TabStrip.Invalidate()
        $message = $_.Exception.Message
        $terminal.Feed("`r`n  Could not connect.`r`n`r`n  $message`r`n")
        Set-PSTermStatusMessage -State $State -Message $message -Level Danger
    }

    Update-PSTermStatus -State $State
}

function Add-PSTermAutomation {
    <#
    .SYNOPSIS
        Teach a session to answer its login and enable prompts.
    #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Tab, [Parameter(Mandatory)]$Session)

    $profile = $Tab.Profile

    # The login password, once, at the first password prompt.
    if ($Tab.Password -and $profile.type -in @('SSH', 'Telnet')) {
        $Session.AddRule('login-password', '(password|passphrase)[^:\r\n]*:\s*$', ($Tab.Password + "`r"), 200, $true, $true, 90000, $null, $false)
    }

    # ssh asking about a key it does not know. The pre-flight check normally settles
    # this first; this is the safety net.
    if ($profile.type -eq 'SSH' -and -not $profile.ssh.autoAcceptHostKey) {
        $Session.AddRule('hostkey-prompt', '\(yes/no(/\[fingerprint\])?\)\?', $null, 0, $true, $true, 0, $null, $true)
    }

    # Entering privileged mode: when the user prompt (ending in >) appears, send the
    # command, then answer the password prompt that follows.
    if ($profile.autoEnable.enabled) {
        $credential = Get-PSTermCredentialById -Store $State.Store -Id ([string]$profile.autoEnable.credentialId)
        $secret = $null
        if ($credential) { $secret = Get-PSTermSecret -Root $State.Root -Key ([string]$credential.secretKey) }
        $command = if ($profile.autoEnable.command) { [string]$profile.autoEnable.command } else { 'enable' }
        $delay = [int]$profile.autoEnable.delayMs

        $arms = @('enable-password')
        if ($profile.autoEnable.useUsername -and $credential -and $credential.username) { $arms += 'enable-user' }

        $Session.AddRule('enable-start', '^[\w.\-/()]+>\s*$', ($command + "`r"), $delay, $true, $true, 0, [string[]]$arms, $false)
        if ($arms -contains 'enable-user') {
            $Session.AddRule('enable-user', '(user ?name|login)[^:\r\n]*:\s*$', ([string]$credential.username + "`r"), 150, $true, $false, 20000, $null, $false)
        }
        if ($null -ne $secret) {
            $Session.AddRule('enable-password', '(password|passcode)[^:\r\n]*:\s*$', ($secret + "`r"), 150, $true, $false, 20000, $null, $false)
        }
    }
}

function Start-PSTermAutoInput {
    <#
    .SYNOPSIS
        Send saved lines after connecting, one at a time, as the device becomes ready.
    .DESCRIPTION
        A line goes out once the device has said something new and then gone quiet,
        which is what a prompt looks like from outside. A fixed delay either races
        ahead of a slow login banner or waits needlessly on a fast one. A device that
        never says anything (a serial console waiting for a keypress) gets the line
        after a few seconds anyway.

        Uses a UI timer rather than Start-Sleep: blocking the UI thread here would
        freeze the window and stop the terminal painting the very output being
        waited for.
    #>
    param($Tab, [string[]]$Lines, [int]$InitialDelayMs = 0)

    $queue = New-Object System.Collections.Generic.Queue[string]
    foreach ($line in $Lines) { $queue.Enqueue($line) }

    $quietMs = 400
    $giveUpMs = 4000
    $wait = [pscustomobject]@{
        Clock = [System.Diagnostics.Stopwatch]::StartNew()
        Seen  = $Tab.Session.DataChunks
    }

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 100
    $timer.Add_Tick({
        if ($queue.Count -eq 0 -or -not $Tab.Session -or $Tab.Closed) {
            $timer.Stop()
            $timer.Dispose()
            return
        }
        if ($wait.Clock.ElapsedMilliseconds -lt $InitialDelayMs) { return }

        $session = $Tab.Session
        $heardSomething = $session.DataChunks -gt $wait.Seen
        $ready = $heardSomething -and ($session.IdleMilliseconds -ge $quietMs)
        if (-not $ready -and $wait.Clock.ElapsedMilliseconds -lt ($giveUpMs + $InitialDelayMs)) { return }

        $session.Send(($queue.Dequeue() + "`r"))
        $wait.Seen = $session.DataChunks
        $wait.Clock.Restart()
    }.GetNewClosure())
    $timer.Start()
}

function Complete-PSTermTab {
    param($State, $Tab, [string]$Reason, $ExitCode)

    # A session that ends before it ever connected failed; one that ends afterwards
    # was disconnected. The dot tells them apart.
    $neverConnected = ($Tab.Item.State -eq [PSTerm.Render.TabState]::Connecting)
    $Tab.Closed = $true
    $Tab.Item.State = if ($neverConnected) { [PSTerm.Render.TabState]::Failed } else { [PSTerm.Render.TabState]::Disconnected }

    $note = if ($Reason) { "Session ended: $Reason" }
            elseif ($null -ne $ExitCode -and $ExitCode -ne 0) { "Session ended (exit code $ExitCode)" }
            else { 'Session ended.' }

    try { $Tab.Control.Feed("`r`n`r`n  --- $note Press Ctrl+Shift+R to reconnect, Ctrl+Shift+W to close. ---`r`n") } catch { }

    $State.TabStrip.Invalidate()
    Update-PSTermStatus -State $State
    Set-PSTermStatusMessage -State $State -Message $note
    Update-PSTermTree -State $State
}

function Restart-PSTermTab {
    <#
    .SYNOPSIS
        Reconnect the active tab using the same profile.
    #>
    param([Parameter(Mandatory)]$State, [int]$Index = -1)

    $tab = if ($Index -ge 0) { $State.Tabs | Where-Object { $_.Item -eq $State.TabStrip.Items[$Index] } | Select-Object -First 1 } else { Get-PSTermActiveTab -State $State }
    if (-not $tab) { return }

    $profile = $tab.Profile
    $temporary = [bool]$tab.Temp
    $position = $State.TabStrip.IndexOf($tab.Item)
    Close-PSTermTab -State $State -Index $position -Force
    [void](New-PSTermSessionTab -State $State -Profile $profile -Temporary:$temporary)

    # The new tab is appended; put it back where the old one was.
    $State.TabStrip.MoveItem($State.TabStrip.Count - 1, [Math]::Min($position, $State.TabStrip.Count - 1))
}

# =============================================================================
# Tabs
# =============================================================================

function Get-PSTermActiveTab {
    param([Parameter(Mandatory)]$State)
    $item = $State.TabStrip.SelectedItem
    if (-not $item) { return $null }
    $State.Tabs | Where-Object { $_.Item -eq $item } | Select-Object -First 1
}

function Show-PSTermTabContent {
    <#
    .SYNOPSIS
        Show the terminal belonging to the selected tab and hide the others.
    .DESCRIPTION
        Hidden terminals stay alive and keep receiving output, so switching back
        to a tab shows everything that arrived while it was in the background.
    #>
    param([Parameter(Mandatory)]$State)

    $active = Get-PSTermActiveTab -State $State
    foreach ($tab in @($State.Tabs)) {
        $visible = ($tab -eq $active)
        if ($tab.Control.Visible -ne $visible) { $tab.Control.Visible = $visible }
    }
    if ($active) {
        $active.Control.BringToFront()
        $active.Control.Focus() | Out-Null
    }
    Update-PSTermStatus -State $State
}

function Close-PSTermTab {
    param(
        [Parameter(Mandatory)]$State,
        [int]$Index = -1,
        [switch]$Force
    )

    if ($Index -lt 0) { $Index = $State.TabStrip.SelectedIndex }
    if ($Index -lt 0 -or $Index -ge $State.TabStrip.Count) { return }

    $item = $State.TabStrip.Items[$Index]
    $tab = $State.Tabs | Where-Object { $_.Item -eq $item } | Select-Object -First 1

    if ($tab -and -not $tab.Closed -and -not $Force) {
        $answer = Show-PSTermMessage -Theme $State.Theme -Owner $State.Form `
            -Title 'Close session' -Buttons YesNo `
            -Message "'$($item.Title)' is still connected. Close it?"
        if ($answer -ne 'Yes') { return }
    }

    if ($tab) {
        $tab.Closed = $true
        if ($tab.Session) { try { $tab.Session.Dispose() } catch { } }
        if ($tab.Logger) { try { $tab.Logger.Close() } catch { } }
        $State.TabHost.Controls.Remove($tab.Control)
        $tab.Control.Dispose()
        [void]$State.Tabs.Remove($tab)
    }

    $State.TabStrip.RemoveAt($Index)
    Show-PSTermTabContent -State $State
    if ($State.Tree) { Update-PSTermTree -State $State }
}

function Close-PSTermTabs {
    <#
    .SYNOPSIS
        Close several tabs after a single confirmation.
    #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][int[]]$Indexes)

    $live = 0
    foreach ($i in $Indexes) {
        $item = $State.TabStrip.Items[$i]
        $tab = $State.Tabs | Where-Object { $_.Item -eq $item } | Select-Object -First 1
        if ($tab -and -not $tab.Closed) { $live++ }
    }
    if ($live -gt 0) {
        $answer = Show-PSTermMessage -Theme $State.Theme -Owner $State.Form -Title 'Close sessions' -Buttons YesNo `
            -Message "$live session(s) are still connected. Close them?"
        if ($answer -ne 'Yes') { return }
    }
    foreach ($i in ($Indexes | Sort-Object -Descending)) { Close-PSTermTab -State $State -Index $i -Force }
}

function Show-PSTermTabContext {
    param([Parameter(Mandatory)]$State, [int]$Index, [System.Drawing.Point]$Location)

    $menu = New-PSTermMenu -Theme $State.Theme
    $count = $State.TabStrip.Count

    if ($Index -lt 0) {
        [void](Add-PSTermMenuItem $menu 'New connection...' { Invoke-PSTermNewConnection -State $State }.GetNewClosure())
        [void](Add-PSTermMenuItem $menu 'Close all tabs' { Close-PSTermTabs -State $State -Indexes @(0..($count - 1)) }.GetNewClosure() 'Close every session.' ($count -gt 0))
        $menu.Show($Location)
        return
    }

    $item = $State.TabStrip.Items[$Index]
    $tab = $State.Tabs | Where-Object { $_.Item -eq $item } | Select-Object -First 1
    if (-not $tab) { return }

    [void](Add-PSTermMenuItem $menu 'Reconnect' { Restart-PSTermTab -State $State -Index $Index }.GetNewClosure() 'Close this session and connect again with the same settings.')
    [void](Add-PSTermMenuItem $menu 'Duplicate tab' { [void](New-PSTermSessionTab -State $State -Profile $tab.Profile -Temporary:([bool]$tab.Temp)) }.GetNewClosure() 'Open another session to the same device.')
    [void](Add-PSTermMenuItem $menu 'Rename tab...' { Invoke-PSTermRenameTab -State $State -Tab $tab }.GetNewClosure() 'Change this tab''s title. The connection keeps its name.')

    $mark = $menu.Items.Add('Mark')
    $mark.ToolTipText = 'Colour the tab to flag how important it is.'
    $mark.DropDown.Renderer = $menu.Renderer
    $mark.DropDown.BackColor = $State.Theme.Surface
    $mark.DropDown.ForeColor = $State.Theme.Text
    $none = $mark.DropDownItems.Add('No mark')
    $none.Add_Click({ Set-PSTermTabMark -State $State -Tab $tab -Name '' }.GetNewClosure())
    foreach ($name in $script:PSTermMarkColours.Keys) {
        $colourName = $name
        $entry = $mark.DropDownItems.Add($colourName)
        $swatch = New-Object System.Drawing.Bitmap(14, 14)
        $g = [System.Drawing.Graphics]::FromImage($swatch)
        $g.Clear($script:PSTermMarkColours[$colourName]); $g.Dispose()
        $entry.Image = $swatch
        $entry.Checked = ([string]$tab.Profile.mark -eq $colourName)
        $entry.Add_Click({ Set-PSTermTabMark -State $State -Tab $tab -Name $colourName }.GetNewClosure())
    }

    [void]$menu.Items.Add('-')
    [void](Add-PSTermMenuItem $menu 'Clear scrollback' { $tab.Control.ClearScrollback() }.GetNewClosure())
    [void](Add-PSTermMenuItem $menu 'Edit connection...' {
        $stored = Get-PSTermProfileById -Store $State.Store -Id ([string]$tab.Profile.id)
        if ($stored) { [void](Invoke-PSTermEditProfile -State $State -Profile $stored) }
    }.GetNewClosure() 'Change the saved settings. They apply the next time you connect.' (-not $tab.Temp))
    [void]$menu.Items.Add('-')
    [void](Add-PSTermMenuItem $menu 'Close' { Close-PSTermTab -State $State -Index $Index }.GetNewClosure())
    [void](Add-PSTermMenuItem $menu 'Close other tabs' {
        Close-PSTermTabs -State $State -Indexes @(0..($count - 1) | Where-Object { $_ -ne $Index })
    }.GetNewClosure() '' ($count -gt 1))
    [void](Add-PSTermMenuItem $menu 'Close tabs to the right' {
        Close-PSTermTabs -State $State -Indexes @(($Index + 1)..($count - 1))
    }.GetNewClosure() '' ($Index -lt ($count - 1)))
    $menu.Show($Location)
}

function Set-PSTermTabMark {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Tab, [string]$Name)

    $Tab.Item.Mark = if ($Name) { $script:PSTermMarkColours[$Name] } else { [System.Drawing.Color]::Empty }
    $Tab.Profile.mark = $Name
    $stored = Get-PSTermProfileById -Store $State.Store -Id ([string]$Tab.Profile.id)
    if ($stored) { $stored.mark = $Name; Save-PSTermProfiles -Root $State.Root -Store $State.Store }
    $State.TabStrip.Invalidate()
}

function Invoke-PSTermRenameTab {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Tab)
    $answer = Show-PSTermInputDialog -State $State -Title 'Rename tab' -Prompt 'Title for this tab:' -Value ([string]$Tab.Item.Title)
    if (-not $answer -or -not $answer.Value.Trim()) { return }
    $Tab.Item.Title = $answer.Value.Trim()
    $Tab.CustomTitle = $true
    $State.TabStrip.Invalidate()
    Update-PSTermStatus -State $State
}

function Confirm-PSTermClose {
    param([Parameter(Mandatory)]$State)

    $live = @($State.Tabs | Where-Object { -not $_.Closed })
    if ($live.Count -gt 0) {
        $answer = Show-PSTermMessage -Theme $State.Theme -Owner $State.Form `
            -Title 'Exit' -Buttons YesNo `
            -Message "$($live.Count) session(s) are still connected. Exit PSTerm?"
        if ($answer -ne 'Yes') { return $false }
    }

    foreach ($tab in @($State.Tabs)) {
        if ($tab.Session) { try { $tab.Session.Dispose() } catch { } }
        if ($tab.Logger) { try { $tab.Logger.Close() } catch { } }
    }
    $true
}

# =============================================================================
# Status bar
# =============================================================================

function Set-PSTermStatusMessage {
    param(
        [Parameter(Mandatory)]$State,
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Danger')][string]$Level = 'Info'
    )

    $State.StatusLeft.Text = $Message
    $State.StatusLeft.ForeColor = switch ($Level) {
        'Warning' { $State.Theme.Warning }
        'Danger'  { $State.Theme.Danger }
        default   { $State.Theme.TextMuted }
    }
}

function Update-PSTermStatus {
    param([Parameter(Mandatory)]$State)

    $tab = Get-PSTermActiveTab -State $State
    $ribbon = $State.Ribbon

    # The toolbar enables what the current tab can do.
    if ($ribbon) {
        $has = [bool]$tab
        $live = $has -and -not $tab.Closed
        $serial = $has -and $tab.Profile.type -eq 'Serial' -and $live
        foreach ($key in 'reconnect', 'duplicate', 'close', 'paste', 'selectall', 'find', 'clear', 'reset') { $ribbon.SetEnabled($key, $has) }
        $ribbon.SetEnabled('copy', ($has -and $tab.Control.HasSelection))
        $ribbon.SetEnabled('break', $serial)
        $ribbon.SetEnabled('creds', $live)
    }

    if (-not $tab) {
        $State.StatusRight.Text = ''
        $State.Form.Text = 'PSTerm'
        return
    }

    $terminal = $tab.Control
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add("$($terminal.Cols)x$($terminal.Rows)")
    $parts.Add([string]$tab.Profile.type)
    $parts.Add([string]$tab.Profile.terminal.encoding)
    if ($tab.Logger) { $parts.Add('logging') }
    $parts.Add($(if ($tab.Closed) { 'disconnected' } else { 'connected' }))

    $State.StatusRight.Text = ($parts -join '   |   ')

    $title = if ($tab.RemoteTitle) { "$($tab.Item.Title)  -  $($tab.RemoteTitle)" } else { $tab.Item.Title }
    $State.Form.Text = "$title - PSTerm"
}

# =============================================================================
# Keyboard shortcuts
# =============================================================================

function Invoke-PSTermShortcut {
    param($State, $EventArgs)

    $ctrl = $EventArgs.Control
    $shift = $EventArgs.Shift
    $alt = $EventArgs.Alt

    # Ctrl+B toggles the session list. It has no use in a terminal that Ctrl+Shift
    # does not cover, but plain Ctrl+letter belongs to the device, so it is only
    # claimed when focus is not in a terminal (where ^B is cursor-left on a shell).
    if ($ctrl -and -not $shift -and -not $alt -and $EventArgs.KeyCode -eq [System.Windows.Forms.Keys]::B) {
        $focused = $State.Form.ActiveControl
        if (-not ($focused -is [PSTerm.Render.TerminalControl])) {
            $EventArgs.SuppressKeyPress = $true
            Set-PSTermSidebar -State $State -Toggle
            return
        }
    }

    # Application commands live on Ctrl+Shift, the way Windows Terminal does it.
    # Plain Ctrl+letter belongs to the device: Ctrl+R is reverse search, Ctrl+W
    # deletes a word, Ctrl+L clears the screen, Ctrl+K kills to end of line. A
    # terminal that claims them is unusable for exactly the work it exists for.
    # Ctrl+Shift+C/V are left alone because the terminal handles copy and paste.
    if ($ctrl -and $shift -and -not $alt) {
        switch ($EventArgs.KeyCode) {
            ([System.Windows.Forms.Keys]::P) {
                $EventArgs.SuppressKeyPress = $true
                Show-PSTermCommandPalette -State $State
                return
            }
            ([System.Windows.Forms.Keys]::T) {
                $EventArgs.SuppressKeyPress = $true
                $State.QuickBox.Focus() | Out-Null
                $State.QuickBox.SelectAll()
                return
            }
            ([System.Windows.Forms.Keys]::W) {
                $EventArgs.SuppressKeyPress = $true
                Close-PSTermTab -State $State
                return
            }
            ([System.Windows.Forms.Keys]::R) {
                $EventArgs.SuppressKeyPress = $true
                Restart-PSTermTab -State $State
                return
            }
            ([System.Windows.Forms.Keys]::L) {
                $EventArgs.SuppressKeyPress = $true
                $tab = Get-PSTermActiveTab -State $State
                if ($tab) { $tab.Control.ClearScrollback() }
                return
            }
            ([System.Windows.Forms.Keys]::F) {
                $EventArgs.SuppressKeyPress = $true
                Show-PSTermFind -State $State
                return
            }
            ([System.Windows.Forms.Keys]::Tab) {
                $EventArgs.SuppressKeyPress = $true
                Select-PSTermNextTab -State $State -Delta -1
                return
            }
        }

        # Ctrl+Shift+1..9 jumps straight to a tab.
        if ($EventArgs.KeyCode -ge [System.Windows.Forms.Keys]::D1 -and $EventArgs.KeyCode -le [System.Windows.Forms.Keys]::D9) {
            $index = [int]$EventArgs.KeyCode - [int][System.Windows.Forms.Keys]::D1
            if ($index -lt $State.TabStrip.Count) {
                $EventArgs.SuppressKeyPress = $true
                $State.TabStrip.SelectedIndex = $index
            }
        }
        return
    }

    # Ctrl+Tab cycles tabs. It has no control code, so nothing is taken from the device.
    if ($ctrl -and -not $shift -and -not $alt -and $EventArgs.KeyCode -eq [System.Windows.Forms.Keys]::Tab) {
        $EventArgs.SuppressKeyPress = $true
        Select-PSTermNextTab -State $State -Delta 1
    }
}

function Select-PSTermNextTab {
    param($State, [int]$Delta)
    $count = $State.TabStrip.Count
    if ($count -eq 0) { return }
    $next = ($State.TabStrip.SelectedIndex + $Delta + $count) % $count
    $State.TabStrip.SelectedIndex = $next
}
