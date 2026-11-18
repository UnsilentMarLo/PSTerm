#region Plugin window

# The window for the plugin host (src\Plugins.ps1): pick a plugin, fill in its form, choose
# devices, run, read the table, save it. It runs the plugin on a timer-driven poll, so the
# window stays alive while devices are being asked.

function Set-PSTermGridTheme {
    <#
    .SYNOPSIS
        Theme colours for a DataGridView (the framework paints it with the system theme).
    #>
    param([Parameter(Mandatory)][System.Windows.Forms.DataGridView]$Grid, [Parameter(Mandatory)]$Theme)

    $Grid.BorderStyle = 'None'
    $Grid.EnableHeadersVisualStyles = $false
    $Grid.BackgroundColor = $Theme.Surface
    $Grid.GridColor = $Theme.Border
    $Grid.DefaultCellStyle.BackColor = $Theme.Surface
    $Grid.DefaultCellStyle.ForeColor = $Theme.Text
    $Grid.DefaultCellStyle.SelectionBackColor = $Theme.Selection
    $Grid.DefaultCellStyle.SelectionForeColor = $Theme.Text
    $Grid.AlternatingRowsDefaultCellStyle.BackColor = $Theme.SurfaceAlt
    $Grid.AlternatingRowsDefaultCellStyle.ForeColor = $Theme.Text
    $Grid.AlternatingRowsDefaultCellStyle.SelectionBackColor = $Theme.Selection
    $Grid.AlternatingRowsDefaultCellStyle.SelectionForeColor = $Theme.Text
    $Grid.ColumnHeadersDefaultCellStyle.BackColor = $Theme.Field
    $Grid.ColumnHeadersDefaultCellStyle.ForeColor = $Theme.Text
    $Grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = $Theme.Field
    $Grid.ColumnHeadersDefaultCellStyle.SelectionForeColor = $Theme.Text
    $Grid.ColumnHeadersBorderStyle = 'Single'
    # The same font as the rest of the window, not the control default.
    $Grid.DefaultCellStyle.Font = $Grid.Font
    $Grid.ColumnHeadersDefaultCellStyle.Font = $Grid.Font
    $Grid.CellBorderStyle = 'SingleHorizontal'
    # The grid's scroll bars are child controls of their own, and only take the dark theme
    # once they have a window.
    if ($Theme.Mode -eq 'Dark') {
        # Each scroll bar gets the dark theme when it gets its window, which can be long after
        # the grid is built (the horizontal one is created the first time it is needed). The
        # handlers carry no outside variables: they run long after this function has returned.
        $onHandle = { param($s, $e) try { [PSTerm.Render.NativeTheme]::UseDarkScrollBars($s) } catch { } }
        foreach ($c in (@($Grid) + @($Grid.Controls))) {
            try { [PSTerm.Render.NativeTheme]::UseDarkScrollBars($c) } catch { }
            $c.Add_HandleCreated($onHandle)
        }
        $Grid.Add_ControlAdded({
            param($s, $e)
            try { [PSTerm.Render.NativeTheme]::UseDarkScrollBars($e.Control) } catch { }
            $e.Control.Add_HandleCreated({ param($s2, $e2) try { [PSTerm.Render.NativeTheme]::UseDarkScrollBars($s2) } catch { } })
        })
    }
}

function ConvertTo-PSTermDataTable {
    <#
    .SYNOPSIS
        Rows (objects with the same kind of properties) -> a DataTable, so the grid can sort
        by any column. A column whose values are all numbers is a number column.
    #>
    param([AllowEmptyCollection()][object[]]$Row = @())

    $table = New-Object System.Data.DataTable
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($r in $Row) { foreach ($p in $r.PSObject.Properties) { if (-not $names.Contains($p.Name)) { $names.Add($p.Name) } } }

    foreach ($n in $names) {
        $numeric = $true; $integral = $true; $seen = $false
        foreach ($r in $Row) {
            $prop = $r.PSObject.Properties[$n]
            if (-not $prop -or $null -eq $prop.Value -or $prop.Value -eq '') { continue }
            $seen = $true
            $v = $prop.Value
            if ($v -is [int] -or $v -is [long] -or $v -is [int16] -or $v -is [byte]) { continue }
            if ($v -is [double] -or $v -is [single] -or $v -is [decimal]) { $integral = $false; continue }
            $numeric = $false; break
        }
        $type = $(if ($numeric -and $seen) { $(if ($integral) { [long] } else { [double] }) } else { [string] })
        [void]$table.Columns.Add($n, $type)
    }
    foreach ($r in $Row) {
        $dr = $table.NewRow()
        foreach ($n in $names) {
            $prop = $r.PSObject.Properties[$n]
            if (-not $prop -or $null -eq $prop.Value -or $prop.Value -eq '') { $dr[$n] = [System.DBNull]::Value; continue }
            $col = $table.Columns[$n]
            $dr[$n] = $(if ($col.DataType -eq [string]) { [string]$prop.Value } else { $prop.Value })
        }
        $table.Rows.Add($dr)
    }
    , $table
}

function Set-PSTermListBoxTheme {
    <#
    .SYNOPSIS
        Draw a ListBox in theme colours. The framework paints the selection in the system
        highlight blue, which matches nothing else in the window.
    #>
    param([Parameter(Mandatory)][System.Windows.Forms.ListBox]$List, [Parameter(Mandatory)]$Theme, [Parameter(Mandatory)]$Font, [double]$Scale = 1.0)

    $pad = [int](8 * $Scale)
    $List.DrawMode = 'OwnerDrawFixed'
    $List.ItemHeight = [int]($Font.Height * 1.6)
    $List.Add_DrawItem({
        param($sender, $e)
        if ($e.Index -lt 0) { return }
        $selected = (($e.State -band [System.Windows.Forms.DrawItemState]::Selected) -ne 0)
        $brush = New-Object System.Drawing.SolidBrush($(if ($selected) { $Theme.Selection } else { $Theme.Surface }))
        $e.Graphics.FillRectangle($brush, $e.Bounds)
        $brush.Dispose()
        $bounds = New-Object System.Drawing.Rectangle(($e.Bounds.X + $pad), $e.Bounds.Y, ($e.Bounds.Width - 2 * $pad), $e.Bounds.Height)
        $flags = [System.Windows.Forms.TextFormatFlags]::VerticalCenter -bor [System.Windows.Forms.TextFormatFlags]::Left -bor [System.Windows.Forms.TextFormatFlags]::EndEllipsis -bor [System.Windows.Forms.TextFormatFlags]::NoPrefix
        [System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, [string]$sender.Items[$e.Index], $sender.Font, $bounds, $Theme.Text, $flags)
    }.GetNewClosure())
}

function Get-PSTermPluginTargetLabel {
    param($Profile)
    if ($Profile.folder) { "$($Profile.folder) / $($Profile.name)" } else { [string]$Profile.name }
}

function Get-PSTermPluginTargetEntries {
    <#
    .SYNOPSIS
        Every device a plugin can be pointed at: the saved connections and the serial ports
        PSTerm has detected, each with the connection profile to use and whether a tab of this
        window already holds its serial port (a port can only be opened once).
    #>
    param([Parameter(Mandatory)]$State)

    $openPorts = @{}
    foreach ($t in @($State.Tabs)) {
        if ($t.Closed -or -not $t.Profile -or $t.Profile.type -ne 'Serial') { continue }
        $openPorts[([string]$t.Profile.serial.portName).ToUpperInvariant()] = [string]$t.Profile.name
    }

    $entries = New-Object System.Collections.Generic.List[object]
    $saved = @($State.Store.profiles | Where-Object { $_.type -ne 'Shell' } | Sort-Object @{ Expression = { [string]$_.folder } }, @{ Expression = { [string]$_.name } })
    $savedPorts = @{}
    foreach ($p in $saved) {
        $busy = ''
        if ($p.type -eq 'Serial') {
            $key = ([string]$p.serial.portName).ToUpperInvariant()
            $savedPorts[$key] = $true
            if ($openPorts.ContainsKey($key)) { $busy = "$($p.serial.portName) is open in the tab '$($openPorts[$key])'" }
        }
        $entries.Add([pscustomobject]@{ Id = [string]$p.id; Label = (Get-PSTermPluginTargetLabel $p); Profile = $p; Busy = $busy })
    }

    # Detected ports that are not already a saved connection.
    $baud = 9600
    try { $baud = [int](Import-PSTermSettings -Root $State.Root).detectedPortBaud } catch { }
    foreach ($port in @($State.DetectedPorts)) {
        $name = [string]$port.PortName
        if (-not $name -or $savedPorts.ContainsKey($name.ToUpperInvariant())) { continue }
        $p = New-PSTermProfile -Name $name -Type 'Serial'
        $p.id = "port:$name"
        $p.serial.portName = $name
        $p.serial.baudRate = $baud
        $label = "Detected serial ports / $name"
        if ($port.Description) { $label += "  -  $($port.Description)" }
        $busy = $(if ($openPorts.ContainsKey($name.ToUpperInvariant())) { "$name is open in the tab '$($openPorts[$name.ToUpperInvariant()])'" } else { '' })
        $entries.Add([pscustomobject]@{ Id = "port:$name"; Label = $label; Profile = $p; Busy = $busy })
    }
    $entries.ToArray()
}

function New-PSTermPluginDialog {
    <#
    .SYNOPSIS
        Build the plugin window and return it without showing it. Show-PSTermPluginDialog
        shows it; the tests drive the same object.
    .PARAMETER SessionFactory
        Test hook, passed to the plugin host (see Start-PSTermPluginRun).
    #>
    param([Parameter(Mandatory)]$State, [string]$SessionFactory = '')

    $theme = $State.Theme
    $shell = New-PSTermDialogShell -State $State -Title 'Plugins' -Width 1100 -Height 680 -OkText 'Close' -NoCancel
    $scale = $shell.Scale
    $form = $shell.Form
    # Resizable like the connection editor: sizing border, close button only (no dimmed
    # minimise, no maximise - it is a dialog).
    $form.FormBorderStyle = 'Sizable'
    $form.MinimizeBox = $false; $form.MaximizeBox = $false
    $form.MinimumSize = New-Object System.Drawing.Size([int](860 * $scale), [int](540 * $scale))
    # Never larger than the screen it opens on.
    $area = [System.Windows.Forms.Screen]::FromControl($State.Form).WorkingArea
    $form.ClientSize = New-Object System.Drawing.Size([Math]::Min($form.ClientSize.Width, [int]($area.Width * 0.88)), [Math]::Min($form.ClientSize.Height, [int]($area.Height * 0.82)))
    $tips = $shell.Tips
    $row = $shell.RowHeight

    $st = @{
        Plugins = @(); Plugin = $null; Fields = @{}; Run = $null; Rows = @(); Topology = $null
        Targets = @(); Selected = (New-Object 'System.Collections.Generic.HashSet[string]'); Building = $false
        Preview = $null; Table = $null; HostsTable = $null; LastView = 'Results'
    }

    $header = { param([string]$Text)
        $l = New-Object System.Windows.Forms.Label
        $l.Text = $Text; $l.AutoSize = $false; $l.Dock = 'Top'
        $l.Height = [int]($row * 0.85); $l.TextAlign = 'BottomLeft'
        $l.Padding = New-Object System.Windows.Forms.Padding(2, 0, 0, [int](3 * $scale))
        $l.ForeColor = $theme.TextMuted; $l.Tag = 'muted'
        $l
    }.GetNewClosure()

    # ---- left: plugin, its form, credentials --------------------------------------------
    $gap = [int](10 * $scale)
    $left = New-Object System.Windows.Forms.Panel
    $left.Dock = 'Left'; $left.Width = [int](300 * $scale); $left.AutoScroll = $true
    $left.Padding = New-Object System.Windows.Forms.Padding(0, 0, [int](14 * $scale), 0)

    $pluginList = New-Object System.Windows.Forms.ListBox
    $pluginList.Dock = 'Top'; $pluginList.IntegralHeight = $false; $pluginList.BorderStyle = 'None'
    Set-PSTermListBoxTheme -List $pluginList -Theme $theme -Font $form.Font -Scale $scale
    $pluginList.Height = $pluginList.ItemHeight * 5
    $tips.SetTip($pluginList, 'The plugins that can be run. Built-in ones ship with PSTerm; yours are read from the Plugins folder.')

    $desc = New-Object System.Windows.Forms.Label
    $desc.Dock = 'Top'; $desc.AutoSize = $false; $desc.Height = [int]($row * 2.7)
    $desc.Padding = New-Object System.Windows.Forms.Padding(2, $gap, 2, 0)
    $desc.ForeColor = $theme.TextMuted; $desc.Tag = 'muted'

    # The form built from the script's parameters grows with its fields; the credentials sit
    # right under it instead of at the bottom of the window.
    $formHost = New-Object System.Windows.Forms.Panel
    $formHost.Dock = 'Top'; $formHost.AutoSize = $true; $formHost.AutoSizeMode = 'GrowAndShrink'
    $optionsHeader = & $header 'Options'
    $optionsHeader.Height += $gap
    $optionsHeader.Visible = $false

    $connectionHeader = & $header 'Connection'
    $connectionHeader.Height += $gap
    $credGrid = New-PSTermFieldGrid
    $credGrid.Padding = New-Object System.Windows.Forms.Padding(0, [int](4 * $scale), 0, 0)
    $loginBox = Add-PSTermField $credGrid 'Log in with' (New-PSTermComboField -Items @('(each connection''s own login)')) $theme -Tip 'A quick credential for the user name and password. PSTerm logs in; the plugin never sees the password.' -Tips $tips
    $enableBox = Add-PSTermField $credGrid 'Enable with' (New-PSTermComboField -Items @('(none)')) $theme -Tip 'A quick credential holding the enable password, for devices that need it.' -Tips $tips
    $atOnce = Add-PSTermField $credGrid 'Devices at once' (New-PSTermTextField '10') $theme -Tip 'How many devices are asked at the same time.' -Tips $tips

    $left.Controls.Add($credGrid)
    $left.Controls.Add($connectionHeader)
    $left.Controls.Add($formHost)
    $left.Controls.Add($optionsHeader)
    $left.Controls.Add($desc)
    $left.Controls.Add($pluginList)
    $left.Controls.Add((& $header 'Plugin'))

    # ---- middle: devices --------------------------------------------------------------
    $mid = New-Object System.Windows.Forms.Panel
    $mid.Dock = 'Left'; $mid.Width = [int](250 * $scale)
    $mid.Padding = New-Object System.Windows.Forms.Padding(0, 0, [int](14 * $scale), 0)

    $filter = New-Object System.Windows.Forms.TextBox
    $filter.Dock = 'Fill'
    Set-PSTermPlaceholder -TextBox $filter -Text 'Filter devices' -Theme $theme
    $tips.SetTip($filter, 'Type part of a name or folder to narrow the list. Devices you picked stay picked while hidden.')
    $filterHost = New-Object System.Windows.Forms.Panel
    $filterHost.Dock = 'Top'; $filterHost.Height = $filter.PreferredHeight + [int](6 * $scale)
    $filterHost.Padding = New-Object System.Windows.Forms.Padding(0, 0, 0, [int](6 * $scale))
    $filterHost.Controls.Add($filter)

    $targetList = New-Object System.Windows.Forms.ListBox
    $targetList.Dock = 'Fill'; $targetList.IntegralHeight = $false; $targetList.BorderStyle = 'None'
    $targetList.SelectionMode = 'MultiExtended'
    Set-PSTermListBoxTheme -List $targetList -Theme $theme -Font $form.Font -Scale $scale
    $tips.SetTip($targetList, 'Pick the devices to ask. Ctrl-click and Shift-click pick several.')

    $pickRow = New-Object System.Windows.Forms.FlowLayoutPanel
    $pickRow.Dock = 'Bottom'; $pickRow.Height = $row + $gap
    $pickRow.Padding = New-Object System.Windows.Forms.Padding(0, $gap, 0, 0)
    $pickRow.WrapContents = $false
    $pickAll = New-Object System.Windows.Forms.Button; $pickAll.Text = 'All shown'
    $pickNone = New-Object System.Windows.Forms.Button; $pickNone.Text = 'None'
    $pickCount = New-Object System.Windows.Forms.Label
    $pickCount.AutoSize = $false; $pickCount.Width = [int](76 * $scale); $pickCount.Height = $row; $pickCount.TextAlign = 'MiddleLeft'
    $pickCount.ForeColor = $theme.TextMuted; $pickCount.Tag = 'muted'
    $pickCount.Margin = New-Object System.Windows.Forms.Padding($gap, 0, 0, 0)
    foreach ($b in @($pickAll, $pickNone)) { $b.Width = [int](82 * $scale); $b.Height = $row; $b.Margin = New-Object System.Windows.Forms.Padding(0, 0, [int](6 * $scale), 0) }
    $pickRow.Controls.AddRange(@($pickAll, $pickNone, $pickCount))

    $midHeader = & $header 'Devices'
    $mid.Controls.Add($targetList)
    $mid.Controls.Add($pickRow)
    $mid.Controls.Add($filterHost)
    $mid.Controls.Add($midHeader)
    # ---- right: results ---------------------------------------------------------------
    $right = New-Object System.Windows.Forms.Panel
    $right.Dock = 'Fill'

    $topBar = New-Object System.Windows.Forms.Panel
    $topBar.Dock = 'Top'; $topBar.Height = $filterHost.Height
    $viewBox = New-PSTermComboField -Items @('Results', 'Devices')
    $viewBox.Dock = 'Fill'
    # Level with the device filter on its left: same row height, same gap underneath.
    $viewHost = New-Object System.Windows.Forms.Panel
    $viewHost.Dock = 'Right'; $viewHost.Width = [int](150 * $scale)
    $viewHost.Padding = New-Object System.Windows.Forms.Padding(0, 0, 0, [int](6 * $scale))
    $viewHost.Controls.Add($viewBox)
    $tips.SetTip($viewBox, 'Results: what the plugin returned. Devices: how each device went. Topology: the diagram (neighbour plugins).')
    $status = New-Object System.Windows.Forms.Label
    $status.Dock = 'Fill'; $status.TextAlign = 'MiddleLeft'; $status.ForeColor = $theme.TextMuted; $status.Tag = 'muted'
    $status.Padding = New-Object System.Windows.Forms.Padding(2, 0, 0, [int](6 * $scale))
    $status.Text = 'Pick a plugin and some devices, then Run.'
    $topBar.Controls.Add($status)
    $topBar.Controls.Add($viewHost)

    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = 'Fill'
    $grid.ReadOnly = $true; $grid.AllowUserToAddRows = $false; $grid.AllowUserToDeleteRows = $false
    $grid.RowHeadersVisible = $false; $grid.SelectionMode = 'FullRowSelect'
    $grid.AutoSizeColumnsMode = 'DisplayedCells'; $grid.AllowUserToResizeRows = $false
    $grid.ColumnHeadersHeightSizeMode = 'AutoSize'
    $grid.Font = $form.Font
    # DataGridView has no public switch for double buffering; without it scrolling repaints cell
    # by cell, and parts of the table flicker.
    [System.Windows.Forms.DataGridView].GetProperty('DoubleBuffered', [System.Reflection.BindingFlags]'NonPublic,Instance').SetValue($grid, $true, $null)
    Set-PSTermGridTheme -Grid $grid -Theme $theme

    $picture = New-Object System.Windows.Forms.PictureBox
    $picture.Dock = 'Fill'; $picture.SizeMode = 'Zoom'; $picture.Visible = $false
    $picture.BackColor = $theme.Surface

    $actions = New-Object System.Windows.Forms.FlowLayoutPanel
    $actions.Dock = 'Bottom'; $actions.AutoSize = $true; $actions.AutoSizeMode = 'GrowAndShrink'
    $actions.Padding = New-Object System.Windows.Forms.Padding(0, $gap, 0, 0)
    $actions.WrapContents = $true
    $runButton = New-Object System.Windows.Forms.Button; $runButton.Text = 'Run'
    $stopButton = New-Object System.Windows.Forms.Button; $stopButton.Text = 'Stop'; $stopButton.Enabled = $false
    $csvButton = New-Object System.Windows.Forms.Button; $csvButton.Text = 'Save table...'
    $svgButton = New-Object System.Windows.Forms.Button; $svgButton.Text = 'Save diagram...'
    $logButton = New-Object System.Windows.Forms.Button; $logButton.Text = 'Open log'
    foreach ($b in @($runButton, $stopButton, $csvButton, $svgButton, $logButton)) { $b.Height = $row; $b.Margin = New-Object System.Windows.Forms.Padding(0, 0, [int](6 * $scale), [int](4 * $scale)) }
    # Sized to their words so that all five fit on one line; the row wraps only in a narrow window.
    $runButton.Width = [int](64 * $scale); $stopButton.Width = [int](64 * $scale); $csvButton.Width = [int](100 * $scale)
    $svgButton.Width = [int](116 * $scale); $logButton.Width = [int](84 * $scale)
    $csvButton.Enabled = $false; $svgButton.Enabled = $false; $logButton.Enabled = $false
    $actions.Controls.AddRange(@($runButton, $stopButton, $csvButton, $svgButton, $logButton))
    $tips.SetTip($runButton, 'Run the plugin on the chosen devices. The devices are only looked at, never changed.')
    $tips.SetTip($stopButton, 'Stop the run: devices still being asked are let go.')
    $tips.SetTip($csvButton, 'Save the table as a CSV file (opens in Excel).')
    $tips.SetTip($svgButton, 'Save the topology as an SVG or PNG picture.')
    $tips.SetTip($logButton, 'The log of this run: what was sent to which device.')

    $right.Controls.Add($grid)
    $right.Controls.Add($picture)
    $right.Controls.Add($actions)
    $right.Controls.Add($topBar)
    $right.Controls.Add((& $header 'Output'))

    $shell.Body.Controls.Add($right)
    $shell.Body.Controls.Add($mid)
    $shell.Body.Controls.Add($left)

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 250

    # ---- behaviour --------------------------------------------------------------------

    $setStatus = { param([string]$Text, [string]$Level = 'Info')
        $status.Text = $Text
        $status.Tag = $(if ($Level -eq 'Info') { 'muted' } else { '' })
        $status.ForeColor = switch ($Level) { 'Warning' { $theme.Warning } 'Danger' { $theme.Danger } default { $theme.TextMuted } }
    }.GetNewClosure()

    $fillTargets = {
        $st.Building = $true
        try {
            $needle = $(if (Test-PSTermPlaceholderActive -TextBox $filter) { '' } else { $filter.Text.Trim() })
            $all = @(Get-PSTermPluginTargetEntries -State $State)
            $st.Targets = @($all | Where-Object { -not $needle -or $_.Label -like "*$needle*" })
            $targetList.BeginUpdate()
            $targetList.Items.Clear()
            foreach ($entry in $st.Targets) { [void]$targetList.Items.Add($(if ($entry.Busy) { "$($entry.Label)   (open in a tab)" } else { $entry.Label })) }
            for ($i = 0; $i -lt $st.Targets.Count; $i++) { if ($st.Selected.Contains([string]$st.Targets[$i].Id)) { $targetList.SetSelected($i, $true) } }
            $targetList.EndUpdate()
        }
        finally { $st.Building = $false }
        $pickCount.Text = "$($st.Selected.Count) picked"
    }.GetNewClosure()

    $targetList.Add_SelectedIndexChanged({
        if ($st.Building) { return }
        for ($i = 0; $i -lt $st.Targets.Count; $i++) {
            $id = [string]$st.Targets[$i].Id
            if ($targetList.GetSelected($i)) { [void]$st.Selected.Add($id) } else { [void]$st.Selected.Remove($id) }
        }
        $pickCount.Text = "$($st.Selected.Count) picked"
    }.GetNewClosure())
    $filter.Add_TextChanged({ if (-not $st.Building) { & $fillTargets } }.GetNewClosure())
    $pickAll.Add_Click({ foreach ($entry in $st.Targets) { [void]$st.Selected.Add([string]$entry.Id) }; & $fillTargets }.GetNewClosure())
    $pickNone.Add_Click({ $st.Selected.Clear(); & $fillTargets }.GetNewClosure())

    $fillCredentials = {
        $loginBox.Items.Clear(); $enableBox.Items.Clear()
        [void]$loginBox.Items.Add('(each connection''s own login)'); [void]$enableBox.Items.Add('(none)')
        foreach ($c in @($State.Store.credentials)) { [void]$loginBox.Items.Add([string]$c.name); [void]$enableBox.Items.Add([string]$c.name) }
        $loginBox.SelectedIndex = 0; $enableBox.SelectedIndex = 0
    }.GetNewClosure()

    $buildForm = {
        $formHost.SuspendLayout()
        $formHost.Controls.Clear()
        $st.Fields = @{}
        $p = $st.Plugin
        if ($p -and -not $p.Problem) {
            $g = New-PSTermFieldGrid
            $g.Padding = New-Object System.Windows.Forms.Padding(0, [int](4 * $scale), 0, 0)
            $fields = @($p.Parameters | Where-Object { -not $_.Reserved })
            foreach ($spec in $fields) {
                $control = $null
                switch ($spec.Kind) {
                    'check' { $control = New-PSTermCheckField -Text $spec.Label -Checked ([bool]$spec.Default); $label = '' }
                    'choice' { $control = New-PSTermComboField -Items $spec.Choices -Value ([string]$spec.Default); $label = $spec.Label }
                    'lines' { $control = New-PSTermTextField ''; $control.Multiline = $true; $control.Height = [int]($row * 2.4); $control.ScrollBars = 'Vertical'; $label = $spec.Label }
                    'number' { $control = New-PSTermTextField $(if ($null -ne $spec.Default) { [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $spec.Default) } else { '' }); $label = $spec.Label }
                    default { $control = New-PSTermTextField $(if ($null -ne $spec.Default) { [string]$spec.Default } else { '' }); $label = $spec.Label }
                }
                if ($spec.Kind -eq 'check') {
                    # A check box owns the whole row: its text is the label.
                    $r = $g.RowCount; $g.RowCount = $r + 1
                    [void]$g.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
                    $control.Margin = New-Object System.Windows.Forms.Padding(3, 4, 3, 4)
                    $g.Controls.Add($control, 0, $r)
                    $g.SetColumnSpan($control, 2)
                    if ($spec.Tip) { $tips.SetTip($control, $spec.Tip) }
                }
                else { [void](Add-PSTermField $g $label $control $theme -Tip $spec.Tip -Tips $tips) }
                $st.Fields[$spec.Name] = [pscustomobject]@{ Spec = $spec; Control = $control }
            }
            if ($fields.Count -gt 0) {
                $formHost.Controls.Add($g)
                Set-PSTermFormTheme -Control $g -Theme $theme
            }
            $optionsHeader.Visible = ($fields.Count -gt 0)
        }
        else { $optionsHeader.Visible = $false }
        $formHost.ResumeLayout($true)
    }.GetNewClosure()

    $selectPlugin = {
        $i = $pluginList.SelectedIndex
        $st.Plugin = $(if ($i -ge 0 -and $i -lt $st.Plugins.Count) { $st.Plugins[$i] } else { $null })
        $p = $st.Plugin
        if (-not $p) { $desc.Text = ''; & $buildForm; return }
        $desc.Text = $(if ($p.Problem) { "This plugin cannot run: $($p.Problem)" } else { $p.Description })
        $desc.Tag = $(if ($p.Problem) { '' } else { 'muted' })
        $desc.ForeColor = $(if ($p.Problem) { $theme.Danger } else { $theme.TextMuted })
        & $buildForm
        $viewBox.Items.Clear(); [void]$viewBox.Items.Add('Results'); [void]$viewBox.Items.Add('Devices')
        if ($p.Topology) { [void]$viewBox.Items.Add('Topology') }
        $viewBox.SelectedIndex = 0
    }.GetNewClosure()
    $pluginList.Add_SelectedIndexChanged($selectPlugin)

    $fillPlugins = {
        $st.Plugins = @(Get-PSTermPlugin -Root $State.Root)
        $pluginList.Items.Clear()
        foreach ($p in $st.Plugins) {
            $tag = $(if ($p.Problem) { '  (cannot run)' } elseif (-not $p.Builtin) { '  (yours)' } else { '' })
            [void]$pluginList.Items.Add("$($p.Title)$tag")
        }
        # Room for the plugins there are (at least four rows, at most eight), no empty well.
        $pluginList.Height = $pluginList.ItemHeight * [Math]::Min(8, [Math]::Max(4, $pluginList.Items.Count))
        if ($pluginList.Items.Count -gt 0) { $pluginList.SelectedIndex = 0 }
    }.GetNewClosure()

    $showView = {
        $view = [string]$viewBox.SelectedItem
        if (-not $view) { $view = 'Results' }
        $picture.Visible = ($view -eq 'Topology')
        $grid.Visible = ($view -ne 'Topology')
        if ($view -eq 'Topology') {
            if ($st.Preview) { $st.Preview.Dispose(); $st.Preview = $null }
            $links = $(if ($st.Topology) { @($st.Topology.Links).Count } else { 0 })
            if ($links -gt 0) {
                $st.Preview = New-PSTermTopologyBitmap -Topology $st.Topology -Scale 1.25 -Background $theme.Surface
                $picture.Image = $st.Preview
            }
            else { $picture.Image = $null }
            return
        }
        # Assigned, not returned from an if-expression: PowerShell would unroll a DataTable into its rows.
        if ($view -eq 'Devices') { $table = $st.HostsTable } else { $table = $st.Table }
        $grid.DataSource = $table
        foreach ($col in $grid.Columns) {
            $col.SortMode = 'Automatic'
            # Numbers line up on the right, with their headers.
            if ($col.ValueType -in @([long], [double], [int])) {
                $col.DefaultCellStyle.Alignment = 'MiddleRight'
                $col.HeaderCell.Style.Alignment = 'MiddleRight'
            }
        }
    }.GetNewClosure()
    $viewBox.Add_SelectedIndexChanged($showView)

    # Colour the words that mean trouble.
    $grid.Add_CellFormatting({
        param($sender, $e)
        if ($e.RowIndex -lt 0 -or $e.ColumnIndex -lt 0 -or $null -eq $e.Value) { return }
        $name = $sender.Columns[$e.ColumnIndex].Name
        if ($name -notin @('Status', 'Problem', 'Notes', 'Error')) { return }
        $v = [string]$e.Value
        if ($v -match '^(ALARM|ATTENTION|Failed|TimedOut)$' -or ($name -in @('Problem', 'Error') -and $v)) { $e.CellStyle.ForeColor = $theme.Danger }
        elseif ($v -match '^(WARNING|Cancelled)$' -or ($name -eq 'Notes' -and $v)) { $e.CellStyle.ForeColor = $theme.Warning }
        elseif ($v -match '^(OK)$') { $e.CellStyle.ForeColor = $theme.Success }
    }.GetNewClosure())

    $readParameters = {
        $values = @{}
        foreach ($name in $st.Fields.Keys) {
            $f = $st.Fields[$name]; $c = $f.Control; $spec = $f.Spec
            switch ($spec.Kind) {
                'check' { $values[$name] = [bool]$c.Checked }
                'choice' { if ($c.SelectedItem) { $values[$name] = [string]$c.SelectedItem } }
                'number' {
                    $text = $c.Text.Trim()
                    if ($text -eq '') { continue }
                    $n = 0.0
                    if (-not [double]::TryParse($text, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n) -and
                        -not [double]::TryParse($text, [ref]$n)) { throw "'$($spec.Label)' needs a number." }
                    $values[$name] = $n
                }
                'lines' { $values[$name] = $c.Text }
                default { if ($c.Text.Trim() -ne '' -or $spec.Mandatory) { $values[$name] = $c.Text } }
            }
        }
        $values
    }.GetNewClosure()

    $finish = {
        $timer.Stop()
        $run = $st.Run
        $st.Rows = @($run.Rows)
        $st.Table = ConvertTo-PSTermDataTable -Row $st.Rows
        $st.HostsTable = ConvertTo-PSTermDataTable -Row @($run.Hosts)
        $st.Topology = $(if ($run.Plugin.Topology -and $st.Rows.Count -gt 0) { Get-PSTermTopology -Row $st.Rows } else { $null })

        $ok = @($run.Hosts | Where-Object { $_.Status -eq 'OK' }).Count
        $failed = @($run.Hosts | Where-Object { $_.Status -eq 'Failed' }).Count
        $timed = @($run.Hosts | Where-Object { $_.Status -eq 'TimedOut' }).Count
        $stopped = @($run.Hosts | Where-Object { $_.Status -eq 'Cancelled' }).Count
        $secs = [Math]::Round(($run.Finished - $run.Started).TotalSeconds, 1)
        $text = "$ok of $($run.Hosts.Count) devices answered"
        if ($failed) { $text += ", $failed failed" }
        if ($timed) { $text += ", $timed timed out" }
        if ($stopped) { $text += ", $stopped stopped" }
        $text += " - $($st.Rows.Count) rows in $secs s"
        & $setStatus $text $(if ($failed -or $timed) { 'Warning' } else { 'Info' })

        $runButton.Enabled = $true; $stopButton.Enabled = $false; $pluginList.Enabled = $true
        $csvButton.Enabled = ($st.Rows.Count -gt 0)
        $svgButton.Enabled = ($null -ne $st.Topology -and @($st.Topology.Links).Count -gt 0)
        $logButton.Enabled = [bool]$run.LogPath

        # Show the table; when nothing came back but something went wrong, show why.
        $viewBox.SelectedIndex = $(if ($st.Rows.Count -eq 0 -and ($failed -or $timed)) { 1 } elseif ($run.Plugin.Topology -and $svgButton.Enabled) { 2 } else { 0 })
        & $showView
    }.GetNewClosure()

    $timer.Add_Tick({
        $run = $st.Run
        if (-not $run) { $timer.Stop(); return }
        [void](Update-PSTermPluginRun -Run $run)
        if ($run.Done) { & $finish; return }
        $done = @($run.Jobs | Where-Object { $_.Done }).Count
        & $setStatus "Asking devices... $done of $($run.Jobs.Count) done"
    }.GetNewClosure())

    # Start a run. Returns $true when it started; shows why when it did not.
    $start = {
        $p = $st.Plugin
        if (-not $p) { return $false }
        if ($p.Problem) { [void](Show-PSTermMessage -Theme $theme -Owner $form -Title 'Plugin' -Message $p.Problem -Level Warning); return $false }

        $picked = @(Get-PSTermPluginTargetEntries -State $State | Where-Object { $st.Selected.Contains([string]$_.Id) })
        if ($picked.Count -eq 0) { & $setStatus 'Pick at least one device.' 'Warning'; return $false }
        # A serial port can be open once. One a tab holds would make the plugin wait for nothing.
        $busy = @($picked | Where-Object { $_.Busy })
        if ($busy.Count -gt 0) {
            & $setStatus ("$($busy[0].Busy). Close that tab first, or take it off the list.") 'Warning'
            return $false
        }
        $chosen = @($picked | ForEach-Object { $_.Profile })

        if (-not (Test-PSTermPluginApproved -Plugin $p -Root $State.Root)) {
            $answer = Show-PSTermMessage -Theme $theme -Owner $form -Title 'Approve this plugin?' -Buttons YesNo -Level Warning -Message (
                "'$($p.Title)' is not part of PSTerm. It is PowerShell code from:`r`n`r`n$($p.Folder)`r`n`r`n" +
                "It will run on this computer, but its sessions can only look at devices (show, ping, ...); PSTerm refuses anything else.`r`n`r`n" +
                "Run it only if you trust where it came from. Changing the plugin asks again.`r`n`r`nApprove and run it?")
            if ($answer -ne 'Yes') { return $false }
            Approve-PSTermPlugin -Plugin $p -Root $State.Root
        }

        $values = $null
        try { $values = & $readParameters } catch { & $setStatus $_.Exception.Message 'Warning'; return $false }
        $parallel = 10
        if (-not [int]::TryParse($atOnce.Text.Trim(), [ref]$parallel) -or $parallel -lt 1 -or $parallel -gt 64) { & $setStatus 'Devices at once: a number from 1 to 64.' 'Warning'; return $false }

        $splat = @{
            Plugin = $p; Target = $chosen; Store = $State.Store; Root = $State.Root; Parameter = $values; ThrottleLimit = $parallel
            Credential = $(if ($loginBox.SelectedIndex -gt 0) { [string]$loginBox.SelectedItem } else { '' })
            EnableCredential = $(if ($enableBox.SelectedIndex -gt 0) { [string]$enableBox.SelectedItem } else { '' })
        }
        if ($SessionFactory) { $splat.SessionFactory = $SessionFactory }
        try { $st.Run = Start-PSTermPluginRun @splat }
        catch { & $setStatus $_.Exception.Message 'Danger'; return $false }

        $runButton.Enabled = $false; $stopButton.Enabled = $true; $pluginList.Enabled = $false
        $csvButton.Enabled = $false; $svgButton.Enabled = $false; $logButton.Enabled = $false
        & $setStatus "Asking devices... 0 of $($chosen.Count) done"
        $timer.Start()
        return $true
    }.GetNewClosure()

    $runButton.Add_Click({ [void](& $start) }.GetNewClosure())
    $stopButton.Add_Click({ if ($st.Run -and -not $st.Run.Done) { Stop-PSTermPluginRun -Run $st.Run; & $finish } }.GetNewClosure())

    $csvButton.Add_Click({
        if ($st.Rows.Count -eq 0) { return }
        $dlg = New-Object System.Windows.Forms.SaveFileDialog
        $dlg.Filter = 'CSV file (*.csv)|*.csv'; $dlg.FileName = "$($st.Plugin.Id)-$(Get-Date -Format 'yyyyMMdd-HHmm').csv"
        try { if ($dlg.ShowDialog($form) -eq 'OK') { Export-PSTermPluginRows -Row $st.Rows -Path $dlg.FileName; & $setStatus "Saved $($dlg.FileName)" } }
        finally { $dlg.Dispose() }
    }.GetNewClosure())

    $svgButton.Add_Click({
        if (-not $st.Topology) { return }
        $dlg = New-Object System.Windows.Forms.SaveFileDialog
        $dlg.Filter = 'SVG picture (*.svg)|*.svg|PNG picture (*.png)|*.png'; $dlg.FileName = 'topology'
        try {
            if ($dlg.ShowDialog($form) -eq 'OK') {
                if ($dlg.FileName -match '\.png$') { Save-PSTermTopologyPng -Topology $st.Topology -Path $dlg.FileName }
                else { [System.IO.File]::WriteAllText($dlg.FileName, (ConvertTo-PSTermTopologySvg -Topology $st.Topology), (New-Object System.Text.UTF8Encoding($false))) }
                & $setStatus "Saved $($dlg.FileName)"
            }
        }
        finally { $dlg.Dispose() }
    }.GetNewClosure())

    $logButton.Add_Click({ if ($st.Run -and $st.Run.LogPath) { Start-Process notepad.exe -ArgumentList ('"' + $st.Run.LogPath + '"') } }.GetNewClosure())

    # Closing the window with a run in progress lets the devices go.
    $form.Add_FormClosing({
        $timer.Stop()
        if ($st.Run -and -not $st.Run.Done) { try { Stop-PSTermPluginRun -Run $st.Run } catch { } }
        if ($st.Preview) { $st.Preview.Dispose(); $st.Preview = $null }
    }.GetNewClosure())

    # The window opens with the plugin list focused, not whichever control happens to be first.
    $form.Add_Shown({ $pluginList.Focus() | Out-Null }.GetNewClosure())
    $form.Add_Activated({ if (-not ($st.Run -and -not $st.Run.Done)) { & $fillTargets } }.GetNewClosure())

    & $fillCredentials
    & $fillPlugins
    & $fillTargets

    Set-PSTermFormTheme -Control $form -Theme $theme
    # The grid and the picture were themed by hand; the tree walk would flatten them.
    Set-PSTermGridTheme -Grid $grid -Theme $theme
    $picture.BackColor = $theme.Surface

    [pscustomobject]@{
        Shell = $shell; Form = $form; State = $st
        PluginList = $pluginList; TargetList = $targetList; Grid = $grid; Picture = $picture; Status = $status
        RunButton = $runButton; StopButton = $stopButton; ViewBox = $viewBox; Filter = $filter
        PickAll = $pickAll; PickNone = $pickNone; LoginBox = $loginBox; EnableBox = $enableBox
        Start = $start; Poll = { $timer.Stop(); [void](Update-PSTermPluginRun -Run $st.Run); if ($st.Run.Done) { & $finish } else { $timer.Start() } }.GetNewClosure()
        Timer = $timer
    }
}

function Show-PSTermPluginDialog {
    <#
    .SYNOPSIS
        Open the plugin window.
    #>
    param([Parameter(Mandatory)]$State)
    $dialog = New-PSTermPluginDialog -State $State
    try { [void](Show-PSTermDialogShell -Shell $dialog.Shell -State $State) }
    finally { $dialog.Timer.Dispose() }
}

#endregion
