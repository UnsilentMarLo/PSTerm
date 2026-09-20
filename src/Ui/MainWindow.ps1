<#
.SYNOPSIS
    The PSTerm main window: session tree, tabs, quick connect and command palette.

.DESCRIPTION
    Layout is entirely docking and TableLayoutPanel, with sizes scaled from the
    display DPI. v1 used absolute pixel coordinates throughout, which breaks on
    any display above 100% scaling.

    All session I/O happens in the compiled core. This file only builds controls
    and reacts to user actions, so nothing here sits in the data path.
#>

Set-StrictMode -Version Latest

function New-PSTermMainWindow {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root)

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
        TabStrip    = $null
        TabHost     = $null
        Tree        = $null
        SearchBox   = $null
        QuickBox    = $null
        Status      = $null
        StatusLeft  = $null
        StatusRight = $null
        Palette     = $null
    }

    $settings = Import-PSTermSettings -Root $Root
    $state.Theme = New-PSTermChromeTheme -Mode $settings.theme

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

    $iconPath = Join-Path $Root 'src\icon.ico'
    if (Test-Path -LiteralPath $iconPath) {
        try { $form.Icon = New-Object System.Drawing.Icon($iconPath) } catch { }
    }

    $scale = Get-PSTermScale -Control $form
    $form.MinimumSize = New-Object System.Drawing.Size([int](760 * $scale), [int](480 * $scale))
    $form.Size = New-Object System.Drawing.Size([int](1100 * $scale), [int](700 * $scale))

    # Row height for anything that sits beside a text field, so the top bar and
    # the buttons in it line up regardless of the system text size.
    $rowHeight = [int]($form.Font.Height * 1.85)

    # ------------------------------------------------------------- top bar ---

    # The bar is sized from the font, and its children are anchored left/right
    # rather than docked, so the row centres them vertically. Docking a
    # single-line TextBox into a taller row is what left it looking clipped.
    $padY = [int](6 * $scale)
    $topBar = New-Object PSTerm.Render.ThemedPanel
    $topBar.Dock = 'Top'
    $topBar.Height = $rowHeight + ($padY * 2)
    $topBar.Padding = New-Object System.Windows.Forms.Padding([int](8 * $scale), $padY, [int](8 * $scale), $padY)

    $quickBox = New-Object System.Windows.Forms.TextBox
    $quickBox.Anchor = 'Left, Right'
    $quickBox.Font = New-PSTermFont
    $quickBox.Margin = New-Object System.Windows.Forms.Padding(0)
    $state.QuickBox = $quickBox

    # A placeholder beats a label here: the bar explains itself and costs no width.
    Set-PSTermPlaceholder -TextBox $quickBox -Theme $state.Theme `
        -Text 'Connect to    user@host    host:2222    telnet host    COM3:115200    cmd        (Enter)'

    $connectButton = New-Object System.Windows.Forms.Button
    $connectButton.Text = 'Connect'
    $connectButton.Anchor = 'Left, Right'
    $connectButton.Height = $rowHeight
    $connectButton.Margin = New-Object System.Windows.Forms.Padding([int](6 * $scale), 0, 0, 0)

    $menuButton = New-Object System.Windows.Forms.Button
    $menuButton.Text = 'Menu'
    $menuButton.Anchor = 'Left, Right'
    $menuButton.Height = $rowHeight
    $menuButton.Margin = New-Object System.Windows.Forms.Padding([int](6 * $scale), 0, 0, 0)

    $topLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $topLayout.Dock = 'Fill'
    $topLayout.ColumnCount = 3
    $topLayout.RowCount = 1
    [void]$topLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
    [void]$topLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
    [void]$topLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Absolute', [int](96 * $scale))))
    [void]$topLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Absolute', [int](76 * $scale))))
    $topLayout.Controls.Add($quickBox, 0, 0)
    $topLayout.Controls.Add($connectButton, 1, 0)
    $topLayout.Controls.Add($menuButton, 2, 0)
    $topBar.Controls.Add($topLayout)

    # -------------------------------------------------------------- splitter -

    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = 'Fill'
    $split.SplitterWidth = [Math]::Max(4, [int](4 * $scale))
    $split.FixedPanel = 'Panel1'

    # ------------------------------------------------------- session tree ----

    $sidePanel = New-Object PSTerm.Render.ThemedPanel
    $sidePanel.Dock = 'Fill'

    $searchHost = New-Object PSTerm.Render.ThemedPanel
    $searchHost.Dock = 'Top'
    $searchHost.Height = $rowHeight + [int](10 * $scale)
    $searchHost.Padding = New-Object System.Windows.Forms.Padding([int](6 * $scale), [int](5 * $scale), [int](6 * $scale), [int](5 * $scale))

    $searchBox = New-Object System.Windows.Forms.TextBox
    $searchBox.Dock = 'Fill'
    $searchBox.Font = New-PSTermFont
    $searchBox.Margin = New-Object System.Windows.Forms.Padding(0)
    $state.SearchBox = $searchBox
    Set-PSTermPlaceholder -TextBox $searchBox -Theme $state.Theme -Text 'Search sessions'
    $searchHost.Controls.Add($searchBox)

    $tree = New-Object System.Windows.Forms.TreeView
    $tree.Dock = 'Fill'
    $tree.HideSelection = $false
    $tree.ShowLines = $false
    $tree.ShowRootLines = $false
    $tree.ShowPlusMinus = $true
    $tree.ItemHeight = [int]($form.Font.Height * 1.55)
    $tree.FullRowSelect = $true
    $state.Tree = $tree

    $treeButtons = New-Object System.Windows.Forms.FlowLayoutPanel
    $treeButtons.Dock = 'Bottom'
    $treeButtons.Height = $rowHeight + [int](10 * $scale)
    $treeButtons.FlowDirection = 'LeftToRight'
    $treeButtons.Padding = New-Object System.Windows.Forms.Padding([int](6 * $scale), [int](5 * $scale), 0, 0)

    $newButton = New-Object System.Windows.Forms.Button
    $newButton.Text = 'New'
    $newButton.Width = [int](62 * $scale); $newButton.Height = $rowHeight
    $editButton = New-Object System.Windows.Forms.Button
    $editButton.Text = 'Edit'
    $editButton.Width = [int](62 * $scale); $editButton.Height = $rowHeight
    $deleteButton = New-Object System.Windows.Forms.Button
    $deleteButton.Text = 'Delete'
    $deleteButton.Width = [int](70 * $scale); $deleteButton.Height = $rowHeight
    $treeButtons.Controls.AddRange(@($newButton, $editButton, $deleteButton))

    # Order matters for docking: Fill is added first so Top and Bottom take their
    # space from the edges rather than overlapping it.
    $sidePanel.Controls.Add($tree)
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
    $form.Controls.Add($topBar)
    $form.Controls.Add($status)

    Apply-PSTermTheme -State $state

    $split.SplitterDistance = [int](230 * $scale)

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

    # The plus button opens the session menu. Moving focus to the quick-connect
    # bar, as it used to, gave no indication of what to do next.
    $tabs.Add_NewTabRequested({
        Show-PSTermNewSessionMenu -State $state -Anchor $state.TabStrip
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

    $tree.Add_NodeMouseDoubleClick({
        param($sender, $e)
        $id = $e.Node.Tag
        if ($id) { Connect-PSTermProfileById -State $state -Id ([string]$id) }
    }.GetNewClosure())

    $tree.Add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter -and $sender.SelectedNode -and $sender.SelectedNode.Tag) {
            $e.SuppressKeyPress = $true
            Connect-PSTermProfileById -State $state -Id ([string]$sender.SelectedNode.Tag)
        }
    }.GetNewClosure())

    $newButton.Add_Click({ Invoke-PSTermEditProfile -State $state -Profile $null }.GetNewClosure())
    $editButton.Add_Click({
        $node = $state.Tree.SelectedNode
        if (-not $node -or -not $node.Tag) { return }
        $profile = Get-PSTermProfileById -Store $state.Store -Id ([string]$node.Tag)
        if ($profile) { Invoke-PSTermEditProfile -State $state -Profile $profile }
    }.GetNewClosure())
    $deleteButton.Add_Click({ Invoke-PSTermDeleteProfile -State $state }.GetNewClosure())

    $menuButton.Add_Click({
        Show-PSTermMenu -State $state -Anchor $menuButton
    }.GetNewClosure())

    $form.Add_KeyDown({
        param($sender, $e)
        Invoke-PSTermShortcut -State $state -EventArgs $e
    }.GetNewClosure())

    $form.Add_FormClosing({
        param($sender, $e)
        if (-not (Confirm-PSTermClose -State $state)) { $e.Cancel = $true }
    }.GetNewClosure())

    $form.Add_Shown({
        Set-PSTermTitleBarTheme -Form $state.Form -Dark ($state.Theme.Mode -eq 'Dark')
        Update-PSTermTree -State $state
        $state.QuickBox.Focus() | Out-Null
        Set-PSTermStatusMessage -State $state -Message 'Ctrl+K for the command palette. Type a destination above and press Enter.'
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

    Set-PSTermTabStripTheme -Strip $State.TabStrip -Theme $theme
    Set-PSTermTitleBarTheme -Form $State.Form -Dark ($theme.Mode -eq 'Dark')
    $State.Form.Invalidate($true)
}

# =============================================================================
# Session tree
# =============================================================================

function Update-PSTermTree {
    param([Parameter(Mandatory)]$State)

    $tree = $State.Tree
    $filter = Get-PSTermPlaceholderText -TextBox $State.SearchBox

    $selectedId = if ($tree.SelectedNode) { [string]$tree.SelectedNode.Tag } else { '' }

    $tree.BeginUpdate()
    try {
        $tree.Nodes.Clear()

        $profiles = @($State.Store.profiles)
        if ($filter) {
            $profiles = @($profiles | Where-Object {
                $target = Get-PSTermProfileTarget -Profile $_
                ($_.name -like "*$filter*") -or ($target -like "*$filter*") -or ($_.folder -like "*$filter*")
            })
        }

        $folderNodes = @{}
        foreach ($profile in ($profiles | Sort-Object { [string]$_.folder }, { [string]$_.name })) {
            $folder = [string]$profile.folder
            $parent = $null

            if ($folder) {
                if (-not $folderNodes.ContainsKey($folder)) {
                    # Nested folders are written as "Lab/Switches".
                    $parentCollection = $tree.Nodes
                    $accumulated = ''
                    foreach ($segment in ($folder -split '[\\/]' | Where-Object { $_ })) {
                        $accumulated = if ($accumulated) { "$accumulated/$segment" } else { $segment }
                        if (-not $folderNodes.ContainsKey($accumulated)) {
                            $node = $parentCollection.Add($segment)
                            $node.Tag = $null
                            $folderNodes[$accumulated] = $node
                        }
                        $parentCollection = $folderNodes[$accumulated].Nodes
                    }
                }
                $parent = $folderNodes[$folder]
            }

            $label = [string]$profile.name
            $target = Get-PSTermProfileTarget -Profile $profile
            if ($target -and $target -ne $label) { $label = "$label   -   $target" }

            $node = if ($parent) { $parent.Nodes.Add($label) } else { $tree.Nodes.Add($label) }
            $node.Tag = [string]$profile.id
            $node.ToolTipText = "$($profile.type): $target"
        }

        $tree.ExpandAll()

        if ($selectedId) {
            $match = Find-PSTermTreeNode -Nodes $tree.Nodes -Id $selectedId
            if ($match) { $tree.SelectedNode = $match }
        }
    }
    finally {
        $tree.EndUpdate()
    }
}

function Find-PSTermTreeNode {
    param($Nodes, [string]$Id)
    foreach ($node in $Nodes) {
        if ([string]$node.Tag -eq $Id) { return $node }
        $child = Find-PSTermTreeNode -Nodes $node.Nodes -Id $Id
        if ($child) { return $child }
    }
    $null
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
    if (-not $profile) { $profile = ConvertFrom-PSTermQuickConnect -Text $text }

    if (-not $profile) {
        Set-PSTermStatusMessage -State $State -Message "Could not interpret '$text'. Try user@host, telnet host, COM3:115200 or cmd." -Level Warning
        return
    }

    Clear-PSTermPlaceholder -TextBox $State.QuickBox
    New-PSTermSessionTab -State $State -Profile $profile
}

function Connect-PSTermProfileById {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$Id)
    $profile = Get-PSTermProfileById -Store $State.Store -Id $Id
    if ($profile) { New-PSTermSessionTab -State $State -Profile $profile }
}

function New-PSTermSessionTab {
    <#
    .SYNOPSIS
        Create a tab, build the terminal and transport, and connect.
    #>
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)]$Profile
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

    # The control must be realised before its grid size is meaningful, so the
    # transport is told the real size rather than the 80x24 default.
    $terminal.CreateControl()
    [System.Windows.Forms.Application]::DoEvents()

    $tab = [pscustomobject]@{
        Item        = $item
        Control     = $terminal
        Session     = $null
        Profile     = $Profile
        Closed      = $false
        Logger      = $null
        RemoteTitle = ''
    }
    $State.Tabs.Add($tab)
    $item.Tag = $tab
    Show-PSTermTabContent -State $State

    try {
        $backend = New-PSTermBackend -Profile $Profile -Cols $terminal.Cols -Rows $terminal.Rows

        $encoding = ConvertTo-PSTermEnum ([PSTerm.Vt.TerminalEncoding]) $Profile.terminal.encoding ([PSTerm.Vt.TerminalEncoding]::Utf8)
        $decoder = New-Object PSTerm.Vt.StreamDecoder($encoding)

        $session = New-Object PSTerm.TerminalSession($backend, $terminal, $terminal.Terminal, $decoder)
        $session.SynchronizingObject = $terminal
        $tab.Session = $session

        $logger = New-PSTermLogger -Profile $Profile -Root $State.Root
        if ($logger) {
            $session.Logger = $logger
            $tab.Logger = $logger
        }

        # Keystrokes and terminal replies both arrive as Input.
        $terminal.Add_Input({
            param($sender, $e)
            if ($tab.Session) { $tab.Session.Send($e.Text) }
        }.GetNewClosure())

        $terminal.Add_TerminalResized({
            param($sender, $e)
            if ($tab.Session) { $tab.Session.Resize($e.Cols, $e.Rows) }
            Update-PSTermStatus -State $State
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

        $session.Add_SessionClosed({
            param($sender, $e)
            Complete-PSTermTab -State $State -Tab $tab -Reason $e.Reason -ExitCode $e.ExitCode
        }.GetNewClosure())

        $session.Add_StatusChanged({
            param($sender, $e)
            Set-PSTermStatusMessage -State $State -Message $e.Message
        }.GetNewClosure())

        $session.Connect()
        $item.State = [PSTerm.Render.TabState]::Connected
        $State.TabStrip.Invalidate()

        # Lines to send once connected. Never put a password here; the credential
        # store exists for that and is encrypted.
        $autoInput = @($Profile.autoInput | Where-Object { $_ })
        if ($autoInput.Count -gt 0) {
            Start-PSTermAutoInput -Tab $tab -Lines $autoInput
        }

        Set-PSTermStatusMessage -State $State -Message "Connected: $(Get-PSTermProfileTarget -Profile $Profile)"
    }
    catch {
        $tab.Closed = $true
        $item.State = [PSTerm.Render.TabState]::Failed
        $State.TabStrip.Invalidate()
        $message = $_.Exception.Message
        $terminal.Feed("`r`n  Could not connect.`r`n`r`n  $message`r`n")
        Set-PSTermStatusMessage -State $State -Message $message -Level Danger
    }

    Update-PSTermStatus -State $State
    $terminal.Focus() | Out-Null
    $tab
}

function Start-PSTermAutoInput {
    <#
    .SYNOPSIS
        Send saved lines after connecting, paced so a device's prompt can keep up.
    .DESCRIPTION
        Uses a UI timer rather than Start-Sleep: blocking the UI thread here would
        freeze the window and stop the terminal painting the very output being
        waited for.
    #>
    param($Tab, [string[]]$Lines)

    $queue = New-Object System.Collections.Generic.Queue[string]
    foreach ($line in $Lines) { $queue.Enqueue($line) }

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 350
    $timer.Add_Tick({
        if ($queue.Count -eq 0 -or -not $Tab.Session -or $Tab.Closed) {
            $timer.Stop()
            $timer.Dispose()
            return
        }
        $Tab.Session.Send(($queue.Dequeue() + "`r"))
    }.GetNewClosure())
    $timer.Start()
}

function Complete-PSTermTab {
    param($State, $Tab, [string]$Reason, $ExitCode)

    $Tab.Closed = $true
    $Tab.Item.State = [PSTerm.Render.TabState]::Disconnected

    $note = if ($Reason) { "Session ended: $Reason" }
            elseif ($null -ne $ExitCode -and $ExitCode -ne 0) { "Session ended (exit code $ExitCode)" }
            else { 'Session ended.' }

    try { $Tab.Control.Feed("`r`n`r`n  --- $note Press Ctrl+R to reconnect, Ctrl+W to close. ---`r`n") } catch { }

    $State.TabStrip.Invalidate()
    Update-PSTermStatus -State $State
    Set-PSTermStatusMessage -State $State -Message $note
}

function Restart-PSTermTab {
    <#
    .SYNOPSIS
        Reconnect the active tab using the same profile.
    #>
    param([Parameter(Mandatory)]$State)

    $tab = Get-PSTermActiveTab -State $State
    if (-not $tab) { return }

    $profile = $tab.Profile
    $index = $State.TabStrip.IndexOf($tab.Item)
    Close-PSTermTab -State $State -Index $index -Force
    New-PSTermSessionTab -State $State -Profile $profile
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
        $answer = [System.Windows.Forms.MessageBox]::Show(
            $State.Form,
            "'$($item.Title)' is still connected. Close it?",
            'Close session',
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question)
        if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    }

    if ($tab) {
        if ($tab.Session) { try { $tab.Session.Dispose() } catch { } }
        if ($tab.Logger) { try { $tab.Logger.Close() } catch { } }
        $State.TabHost.Controls.Remove($tab.Control)
        $tab.Control.Dispose()
        [void]$State.Tabs.Remove($tab)
    }

    $State.TabStrip.RemoveAt($Index)
    Show-PSTermTabContent -State $State
}

function Confirm-PSTermClose {
    param([Parameter(Mandatory)]$State)

    $live = @($State.Tabs | Where-Object { -not $_.Closed })
    if ($live.Count -gt 0) {
        $answer = [System.Windows.Forms.MessageBox]::Show(
            $State.Form,
            "$($live.Count) session(s) are still connected. Exit PSTerm?",
            'Exit',
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question)
        if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return $false }
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

    # Ctrl+Shift+C/V belong to the terminal for copy and paste; everything claimed
    # here would otherwise be unreachable once the terminal has focus.
    if ($ctrl -and -not $shift) {
        switch ($EventArgs.KeyCode) {
            ([System.Windows.Forms.Keys]::K) {
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
                Select-PSTermNextTab -State $State -Delta 1
                return
            }
        }
    }

    if ($ctrl -and $shift -and $EventArgs.KeyCode -eq [System.Windows.Forms.Keys]::Tab) {
        $EventArgs.SuppressKeyPress = $true
        Select-PSTermNextTab -State $State -Delta -1
        return
    }

    # Ctrl+1..9 jumps straight to a tab.
    if ($ctrl -and $EventArgs.KeyCode -ge [System.Windows.Forms.Keys]::D1 -and $EventArgs.KeyCode -le [System.Windows.Forms.Keys]::D9) {
        $index = [int]$EventArgs.KeyCode - [int][System.Windows.Forms.Keys]::D1
        if ($index -lt $State.TabStrip.Count) {
            $EventArgs.SuppressKeyPress = $true
            $State.TabStrip.SelectedIndex = $index
        }
    }
}

function Select-PSTermNextTab {
    param($State, [int]$Delta)
    $count = $State.TabStrip.Count
    if ($count -eq 0) { return }
    $next = ($State.TabStrip.SelectedIndex + $Delta + $count) % $count
    $State.TabStrip.SelectedIndex = $next
}
