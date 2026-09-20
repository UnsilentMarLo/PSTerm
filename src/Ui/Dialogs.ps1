<#
.SYNOPSIS
    Profile editor, command palette, scrollback search and the application menu.

.DESCRIPTION
    Every dialog here is laid out with TableLayoutPanel and auto-sizing, never
    absolute coordinates, so it survives display scaling and longer translations.
#>

Set-StrictMode -Version Latest

# =============================================================================
# Small layout helpers
# =============================================================================

function New-PSTermLabel {
    param([string]$Text, $Theme)
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.AutoSize = $true
    $label.Anchor = 'Left'
    $label.Margin = New-Object System.Windows.Forms.Padding(3, 6, 8, 3)
    if ($Theme) { $label.ForeColor = $Theme.Text }
    $label
}

function New-PSTermFieldGrid {
    <#
    .SYNOPSIS
        A two-column label/field grid that grows with its contents.
    #>
    $grid = New-Object System.Windows.Forms.TableLayoutPanel
    $grid.ColumnCount = 2
    $grid.AutoSize = $true
    $grid.AutoSizeMode = 'GrowAndShrink'
    $grid.Dock = 'Top'
    $grid.Padding = New-Object System.Windows.Forms.Padding(8)
    [void]$grid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
    [void]$grid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
    $grid
}

function Add-PSTermField {
    <#
    .SYNOPSIS
        Add a labelled control to a field grid and return the control.
    #>
    param($Grid, [string]$Label, $Control, $Theme)

    $row = $Grid.RowCount
    $Grid.RowCount = $row + 1
    [void]$Grid.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))

    $Grid.Controls.Add((New-PSTermLabel -Text $Label -Theme $Theme), 0, $row)
    $Control.Dock = 'Fill'
    $Control.Margin = New-Object System.Windows.Forms.Padding(3)
    $Grid.Controls.Add($Control, 1, $row)
    $Control
}

function New-PSTermTextField { param([string]$Value = '')
    $t = New-Object System.Windows.Forms.TextBox; $t.Text = [string]$Value; $t }

function New-PSTermComboField {
    param([string[]]$Items, [string]$Value = '', [switch]$Editable)
    $c = New-Object System.Windows.Forms.ComboBox
    $c.DropDownStyle = if ($Editable) { 'DropDown' } else { 'DropDownList' }
    foreach ($item in $Items) { [void]$c.Items.Add($item) }
    if ($Value -and $c.Items.Contains($Value)) { $c.SelectedItem = $Value }
    elseif ($Editable) { $c.Text = [string]$Value }
    elseif ($c.Items.Count -gt 0) { $c.SelectedIndex = 0 }
    $c
}

function New-PSTermCheckField {
    param([string]$Text, [bool]$Checked)
    $c = New-Object System.Windows.Forms.CheckBox
    $c.Text = $Text
    $c.Checked = $Checked
    $c.AutoSize = $true
    $c
}

function ConvertTo-PSTermInt {
    <#
    .SYNOPSIS
        Parse an integer from a text field, falling back rather than throwing.
        v1 cast form text straight to [int] and threw when a field was blank.
    #>
    param([string]$Text, [int]$Default)
    [int]$value = 0
    if ([int]::TryParse(($Text -replace '\s', ''), [ref]$value)) { return $value }
    $Default
}

# =============================================================================
# Profile editor
# =============================================================================

function Invoke-PSTermEditProfile {
    <#
    .SYNOPSIS
        Create or edit a profile. Saves to the store on OK.
    #>
    param(
        [Parameter(Mandatory)]$State,
        $Profile
    )

    $isNew = -not $Profile
    if ($isNew) {
        $Profile = New-PSTermProfile
        $settings = Import-PSTermSettings -Root $State.Root
        $Profile.terminal.backspace = $settings.defaultBackspace
        $Profile.terminal.encoding = $settings.defaultEncoding
        $Profile.terminal.theme = $settings.theme
        $Profile.terminal.fontFamily = $settings.fontFamily
        $Profile.terminal.fontSize = $settings.fontSize
        $Profile.terminal.scrollback = $settings.scrollback
    }

    $theme = $State.Theme
    $scale = Get-PSTermScale -Control $State.Form

    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = if ($isNew) { 'New connection' } else { "Edit - $($Profile.name)" }
    $dialog.StartPosition = 'CenterParent'
    $dialog.FormBorderStyle = 'Sizable'
    $dialog.MinimizeBox = $false
    $dialog.MaximizeBox = $false
    $dialog.Font = New-PSTermFont -Size 9
    $dialog.Size = New-Object System.Drawing.Size([int](560 * $scale), [int](620 * $scale))
    $dialog.MinimumSize = New-Object System.Drawing.Size([int](460 * $scale), [int](420 * $scale))

    # ---- general -------------------------------------------------------
    $general = New-PSTermFieldGrid
    $nameBox   = Add-PSTermField $general 'Name'   (New-PSTermTextField $Profile.name) $theme
    $folderBox = Add-PSTermField $general 'Folder' (New-PSTermComboField -Items (Get-PSTermFolders -Store $State.Store) -Value $Profile.folder -Editable) $theme
    $typeBox   = Add-PSTermField $general 'Type'   (New-PSTermComboField -Items @('SSH', 'Telnet', 'Serial', 'Shell') -Value $Profile.type) $theme

    # ---- per-transport panels ------------------------------------------
    $sshGrid = New-PSTermFieldGrid
    $sshHost     = Add-PSTermField $sshGrid 'Host'          (New-PSTermTextField $Profile.ssh.host) $theme
    $sshUser     = Add-PSTermField $sshGrid 'Username'      (New-PSTermTextField $Profile.ssh.user) $theme
    $sshPort     = Add-PSTermField $sshGrid 'Port'          (New-PSTermTextField $Profile.ssh.port) $theme
    $sshKey      = Add-PSTermField $sshGrid 'Key file'      (New-PSTermTextField $Profile.ssh.identityFile) $theme
    $sshJump     = Add-PSTermField $sshGrid 'Jump host'     (New-PSTermTextField $Profile.ssh.proxyJump) $theme
    $sshKeepAlive= Add-PSTermField $sshGrid 'Keep-alive (s)'(New-PSTermTextField $Profile.ssh.keepAliveSeconds) $theme
    $sshAgent    = Add-PSTermField $sshGrid '' (New-PSTermCheckField 'Forward the SSH agent' ([bool]$Profile.ssh.forwardAgent)) $theme
    $sshCompress = Add-PSTermField $sshGrid '' (New-PSTermCheckField 'Enable compression' ([bool]$Profile.ssh.compression)) $theme
    $sshLegacy   = Add-PSTermField $sshGrid '' (New-PSTermCheckField 'Allow legacy ciphers and key exchange (older equipment)' ([bool]$Profile.ssh.allowLegacyAlgorithms)) $theme

    $telnetGrid = New-PSTermFieldGrid
    $telnetHost = Add-PSTermField $telnetGrid 'Host' (New-PSTermTextField $Profile.telnet.host) $theme
    $telnetPort = Add-PSTermField $telnetGrid 'Port' (New-PSTermTextField $Profile.telnet.port) $theme
    $telnetType = Add-PSTermField $telnetGrid 'Terminal type' (New-PSTermComboField -Items @('xterm-256color', 'xterm', 'vt220', 'vt100', 'ansi', 'linux') -Value $Profile.telnet.terminalType -Editable) $theme
    $telnetNeg  = Add-PSTermField $telnetGrid '' (New-PSTermCheckField 'Negotiate options actively (recommended)' ([bool]$Profile.telnet.activeNegotiation)) $theme
    $telnetBin  = Add-PSTermField $telnetGrid '' (New-PSTermCheckField 'Request 8-bit binary mode (needed for UTF-8)' ([bool]$Profile.telnet.binary)) $theme
    $telnetKeep = Add-PSTermField $telnetGrid 'Keep-alive (s)' (New-PSTermTextField $Profile.telnet.keepAliveSeconds) $theme

    $serialGrid = New-PSTermFieldGrid
    $serialPorts = @([PSTerm.Backends.SerialBackend]::GetPortNames())
    $serialPort = Add-PSTermField $serialGrid 'COM port' (New-PSTermComboField -Items $serialPorts -Value $Profile.serial.portName -Editable) $theme
    $serialBaud = Add-PSTermField $serialGrid 'Baud rate' (New-PSTermComboField -Items @('300','1200','2400','4800','9600','19200','38400','57600','115200','230400','460800','921600') -Value ([string]$Profile.serial.baudRate) -Editable) $theme
    $serialData = Add-PSTermField $serialGrid 'Data bits' (New-PSTermComboField -Items @('5','6','7','8') -Value ([string]$Profile.serial.dataBits)) $theme
    $serialParity = Add-PSTermField $serialGrid 'Parity' (New-PSTermComboField -Items ([enum]::GetNames([System.IO.Ports.Parity])) -Value ([string]$Profile.serial.parity)) $theme
    $serialStop = Add-PSTermField $serialGrid 'Stop bits' (New-PSTermComboField -Items @('One','OnePointFive','Two') -Value ([string]$Profile.serial.stopBits)) $theme
    $serialFlow = Add-PSTermField $serialGrid 'Flow control' (New-PSTermComboField -Items ([enum]::GetNames([System.IO.Ports.Handshake])) -Value ([string]$Profile.serial.handshake)) $theme
    $serialDtr  = Add-PSTermField $serialGrid '' (New-PSTermCheckField 'Assert DTR (most USB console adapters need this)' ([bool]$Profile.serial.dtrEnable)) $theme
    $serialRts  = Add-PSTermField $serialGrid '' (New-PSTermCheckField 'Assert RTS' ([bool]$Profile.serial.rtsEnable)) $theme
    $serialReconnect = Add-PSTermField $serialGrid '' (New-PSTermCheckField 'Reopen the port automatically if the adapter is unplugged' ([bool]$Profile.serial.reconnect)) $theme

    $shellGrid = New-PSTermFieldGrid
    $shellCmd = Add-PSTermField $shellGrid 'Command line' (New-PSTermTextField $Profile.shell.commandLine) $theme
    $shellDir = Add-PSTermField $shellGrid 'Start in' (New-PSTermTextField $Profile.shell.workingDirectory) $theme

    # ---- terminal ------------------------------------------------------
    $termGrid = New-PSTermFieldGrid
    $termEncoding = Add-PSTermField $termGrid 'Encoding' (New-PSTermComboField -Items @('Utf8','Latin1','Ascii','Oem') -Value ([string]$Profile.terminal.encoding)) $theme
    $termBackspace = Add-PSTermField $termGrid 'Backspace sends' (New-PSTermComboField -Items @('Delete','Backspace') -Value ([string]$Profile.terminal.backspace)) $theme
    $termFunctionKeys = Add-PSTermField $termGrid 'Function keys' (New-PSTermComboField -Items @('Xterm','Vt220','LinuxConsole') -Value ([string]$Profile.terminal.functionKeys)) $theme
    $termTheme = Add-PSTermField $termGrid 'Colours' (New-PSTermComboField -Items @('Dark','Light') -Value ([string]$Profile.terminal.theme)) $theme
    $termFont = Add-PSTermField $termGrid 'Font' (New-PSTermComboField -Items (Get-PSTermAvailableMonospaceFonts) -Value ([string]$Profile.terminal.fontFamily) -Editable) $theme
    $termFontSize = Add-PSTermField $termGrid 'Font size' (New-PSTermTextField $Profile.terminal.fontSize) $theme
    $termScrollback = Add-PSTermField $termGrid 'Scrollback lines' (New-PSTermTextField $Profile.terminal.scrollback) $theme
    $termAltEscape = Add-PSTermField $termGrid '' (New-PSTermCheckField 'Alt sends Escape (meta key)' ([bool]$Profile.terminal.altSendsEscape)) $theme

    $backspaceHint = New-PSTermLabel -Text "Tip: if Backspace prints ^H or ~ on a device, switch it to the other setting." -Theme $theme
    $backspaceHint.ForeColor = $theme.TextMuted
    $backspaceHint.MaximumSize = New-Object System.Drawing.Size([int](480 * $scale), 0)

    # ---- logging -------------------------------------------------------
    $logGrid = New-PSTermFieldGrid
    $logEnabled = Add-PSTermField $logGrid '' (New-PSTermCheckField 'Log this session to a file' ([bool]$Profile.logging.enabled)) $theme
    $logPath = Add-PSTermField $logGrid 'File' (New-PSTermTextField $Profile.logging.pathTemplate) $theme
    $logFormat = Add-PSTermField $logGrid 'Format' (New-PSTermComboField -Items @('PlainText','Timestamped','Raw') -Value ([string]$Profile.logging.format)) $theme
    $logInput = Add-PSTermField $logGrid '' (New-PSTermCheckField 'Include what I type' ([bool]$Profile.logging.includeInput)) $theme
    $logMask = Add-PSTermField $logGrid '' (New-PSTermCheckField 'Mask passwords' ([bool]$Profile.logging.maskPasswords)) $theme
    $logAppend = Add-PSTermField $logGrid '' (New-PSTermCheckField 'Append rather than overwrite' ([bool]$Profile.logging.append)) $theme
    $logRotate = Add-PSTermField $logGrid 'Roll over at (bytes, 0 = never)' (New-PSTermTextField $Profile.logging.maxBytes) $theme

    $logHint = New-PSTermLabel -Text 'Supports {name}, {host}, {user}, {port}, {date}, {time} and {datetime}, so each device can write its own dated file. Relative paths go under the PSTerm folder.' -Theme $theme
    $logHint.ForeColor = $theme.TextMuted
    $logHint.MaximumSize = New-Object System.Drawing.Size([int](480 * $scale), 0)

    # ---- auto input ----------------------------------------------------
    $autoGrid = New-PSTermFieldGrid
    $autoBox = New-Object System.Windows.Forms.TextBox
    $autoBox.Multiline = $true
    $autoBox.ScrollBars = 'Vertical'
    $autoBox.AcceptsReturn = $true
    $autoBox.Height = [int](140 * $scale)
    $autoBox.Text = (@($Profile.autoInput) -join "`r`n")
    [void](Add-PSTermField $autoGrid 'Send after connecting' $autoBox $theme)

    $autoHint = New-PSTermLabel -Text 'One command per line, sent with a short pause between each. Do not put passwords here: this file is not encrypted.' -Theme $theme
    $autoHint.ForeColor = $theme.Warning
    $autoHint.MaximumSize = New-Object System.Drawing.Size([int](480 * $scale), 0)

    # ---- assemble tabs --------------------------------------------------
    $pages = New-Object System.Windows.Forms.TabControl
    $pages.Dock = 'Fill'

    function New-PSTermScrollPage {
        param([string]$Title, [System.Windows.Forms.Control[]]$Contents)
        $page = New-Object System.Windows.Forms.TabPage
        $page.Text = $Title
        $page.AutoScroll = $true
        $page.Padding = New-Object System.Windows.Forms.Padding(4)
        # Added in reverse: Dock=Top stacks in the opposite order to insertion.
        for ($i = $Contents.Count - 1; $i -ge 0; $i--) {
            $Contents[$i].Dock = 'Top'
            $page.Controls.Add($Contents[$i])
        }
        $page
    }

    $connectionPage = New-Object System.Windows.Forms.TabPage
    $connectionPage.Text = 'Connection'
    $connectionPage.AutoScroll = $true
    $connectionPage.Padding = New-Object System.Windows.Forms.Padding(4)
    foreach ($panel in @($shellGrid, $serialGrid, $telnetGrid, $sshGrid, $general)) {
        $panel.Dock = 'Top'
        $connectionPage.Controls.Add($panel)
    }

    [void]$pages.TabPages.Add($connectionPage)
    [void]$pages.TabPages.Add((New-PSTermScrollPage 'Terminal' @($termGrid, $backspaceHint)))
    [void]$pages.TabPages.Add((New-PSTermScrollPage 'Logging'  @($logGrid, $logHint)))
    [void]$pages.TabPages.Add((New-PSTermScrollPage 'Automation' @($autoGrid, $autoHint)))

    # ---- buttons --------------------------------------------------------
    $buttonRow = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttonRow.Dock = 'Bottom'
    $buttonRow.FlowDirection = 'RightToLeft'
    $buttonRow.Height = [int](42 * $scale)
    $buttonRow.Padding = New-Object System.Windows.Forms.Padding(8, 6, 8, 6)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = 'Cancel'
    $cancelButton.Width = [int](90 * $scale)

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = if ($isNew) { 'Create' } else { 'Save' }
    $okButton.DialogResult = 'OK'
    $okButton.Width = [int](90 * $scale)

    $buttonRow.Controls.AddRange(@($okButton, $cancelButton))
    $dialog.AcceptButton = $okButton
    $dialog.CancelButton = $cancelButton

    $dialog.Controls.Add($pages)
    $dialog.Controls.Add($buttonRow)

    # Show only the panel for the selected transport.
    $updateVisibility = {
        $selected = [string]$typeBox.SelectedItem
        $sshGrid.Visible    = ($selected -eq 'SSH')
        $telnetGrid.Visible = ($selected -eq 'Telnet')
        $serialGrid.Visible = ($selected -eq 'Serial')
        $shellGrid.Visible  = ($selected -eq 'Shell')
    }.GetNewClosure()
    $typeBox.Add_SelectedIndexChanged($updateVisibility)
    & $updateVisibility

    Set-PSTermFormTheme -Control $dialog -Theme $theme

    if ($dialog.ShowDialog($State.Form) -ne [System.Windows.Forms.DialogResult]::OK) {
        $dialog.Dispose()
        return
    }

    # ---- read back -------------------------------------------------------
    $name = $nameBox.Text.Trim()
    if (-not $name) { $name = 'Unnamed' }

    $Profile.name   = $name
    $Profile.folder = $folderBox.Text.Trim()
    $Profile.type   = [string]$typeBox.SelectedItem

    $Profile.ssh.host = $sshHost.Text.Trim()
    $Profile.ssh.user = $sshUser.Text.Trim()
    $Profile.ssh.port = ConvertTo-PSTermInt $sshPort.Text 22
    $Profile.ssh.identityFile = $sshKey.Text.Trim()
    $Profile.ssh.proxyJump = $sshJump.Text.Trim()
    $Profile.ssh.keepAliveSeconds = ConvertTo-PSTermInt $sshKeepAlive.Text 30
    $Profile.ssh.forwardAgent = $sshAgent.Checked
    $Profile.ssh.compression = $sshCompress.Checked
    $Profile.ssh.allowLegacyAlgorithms = $sshLegacy.Checked

    $Profile.telnet.host = $telnetHost.Text.Trim()
    $Profile.telnet.port = ConvertTo-PSTermInt $telnetPort.Text 23
    $Profile.telnet.terminalType = $telnetType.Text.Trim()
    $Profile.telnet.activeNegotiation = $telnetNeg.Checked
    $Profile.telnet.binary = $telnetBin.Checked
    $Profile.telnet.keepAliveSeconds = ConvertTo-PSTermInt $telnetKeep.Text 0

    $Profile.serial.portName = $serialPort.Text.Trim()
    $Profile.serial.baudRate = ConvertTo-PSTermInt $serialBaud.Text 9600
    $Profile.serial.dataBits = ConvertTo-PSTermInt $serialData.Text 8
    $Profile.serial.parity = [string]$serialParity.SelectedItem
    $Profile.serial.stopBits = [string]$serialStop.SelectedItem
    $Profile.serial.handshake = [string]$serialFlow.SelectedItem
    $Profile.serial.dtrEnable = $serialDtr.Checked
    $Profile.serial.rtsEnable = $serialRts.Checked
    $Profile.serial.reconnect = $serialReconnect.Checked

    $Profile.shell.commandLine = $shellCmd.Text.Trim()
    $Profile.shell.workingDirectory = $shellDir.Text.Trim()

    $Profile.terminal.encoding = [string]$termEncoding.SelectedItem
    $Profile.terminal.backspace = [string]$termBackspace.SelectedItem
    $Profile.terminal.functionKeys = [string]$termFunctionKeys.SelectedItem
    $Profile.terminal.theme = [string]$termTheme.SelectedItem
    $Profile.terminal.fontFamily = $termFont.Text.Trim()
    [double]$size = 0
    $Profile.terminal.fontSize = if ([double]::TryParse(($termFontSize.Text -replace ',', '.'), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$size) -and $size -gt 4) { $size } else { 10.5 }
    $Profile.terminal.scrollback = ConvertTo-PSTermInt $termScrollback.Text 10000
    $Profile.terminal.altSendsEscape = $termAltEscape.Checked

    $Profile.logging.enabled = $logEnabled.Checked
    $Profile.logging.pathTemplate = $logPath.Text.Trim()
    $Profile.logging.format = [string]$logFormat.SelectedItem
    $Profile.logging.includeInput = $logInput.Checked
    $Profile.logging.maskPasswords = $logMask.Checked
    $Profile.logging.append = $logAppend.Checked
    $Profile.logging.maxBytes = ConvertTo-PSTermInt $logRotate.Text 0

    $Profile.autoInput = @($autoBox.Text -split "`r?`n" | Where-Object { $_.Trim() })

    $dialog.Dispose()

    Set-PSTermProfile -Store $State.Store -Profile $Profile | Out-Null
    Save-PSTermProfiles -Root $State.Root -Store $State.Store
    Update-PSTermTree -State $State
    Set-PSTermStatusMessage -State $State -Message "Saved '$name'."
}

function Invoke-PSTermDeleteProfile {
    param([Parameter(Mandatory)]$State)

    $node = $State.Tree.SelectedNode
    if (-not $node -or -not $node.Tag) {
        Set-PSTermStatusMessage -State $State -Message 'Select a connection to delete.' -Level Warning
        return
    }

    $profile = Get-PSTermProfileById -Store $State.Store -Id ([string]$node.Tag)
    if (-not $profile) { return }

    $answer = [System.Windows.Forms.MessageBox]::Show(
        $State.Form,
        "Delete '$($profile.name)'?",
        'Delete connection',
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    if ($profile.credentialKey) {
        Remove-PSTermSecret -Root $State.Root -Key ([string]$profile.credentialKey)
    }

    Remove-PSTermProfile -Store $State.Store -Id ([string]$profile.id) | Out-Null
    Save-PSTermProfiles -Root $State.Root -Store $State.Store
    Update-PSTermTree -State $State
    Set-PSTermStatusMessage -State $State -Message "Deleted '$($profile.name)'."
}

# =============================================================================
# Command palette
# =============================================================================

function Show-PSTermCommandPalette {
    <#
    .SYNOPSIS
        Ctrl+K: one search box over commands and saved connections.
    .DESCRIPTION
        Keeps common actions reachable without hunting through menus, which is the
        main navigation complaint about PuTTY's dialog-first design.
    #>
    param([Parameter(Mandatory)]$State)

    $theme = $State.Theme
    $scale = Get-PSTermScale -Control $State.Form

    # See MainWindow.ps1: @(...) is broken for List[object] in PowerShell.
    $commands = New-Object System.Collections.Generic.List[psobject]

    function Add-Command { param([string]$Title, [string]$Hint, [scriptblock]$Action)
        $commands.Add([pscustomobject]@{ Title = $Title; Hint = $Hint; Action = $Action }) }

    Add-Command 'New connection...'      'Create a saved profile'      { Invoke-PSTermEditProfile -State $State -Profile $null }.GetNewClosure()
    Add-Command 'Close tab'              'Ctrl+W'                      { Close-PSTermTab -State $State }.GetNewClosure()
    Add-Command 'Reconnect tab'          'Ctrl+R'                      { Restart-PSTermTab -State $State }.GetNewClosure()
    Add-Command 'Clear scrollback'       'Ctrl+L'                      { $t = Get-PSTermActiveTab -State $State; if ($t) { $t.Control.ClearScrollback() } }.GetNewClosure()
    Add-Command 'Find in scrollback...'  'Ctrl+F'                      { Show-PSTermFind -State $State }.GetNewClosure()
    Add-Command 'Copy selection'         'Ctrl+Shift+C'                { $t = Get-PSTermActiveTab -State $State; if ($t) { $t.Control.CopySelection() } }.GetNewClosure()
    Add-Command 'Paste'                  'Ctrl+Shift+V'                { $t = Get-PSTermActiveTab -State $State; if ($t) { $t.Control.PasteClipboard() } }.GetNewClosure()
    Add-Command 'Select all'             ''                            { $t = Get-PSTermActiveTab -State $State; if ($t) { $t.Control.SelectAll() } }.GetNewClosure()
    Add-Command 'Reset terminal'         'Clear the screen and modes'  { $t = Get-PSTermActiveTab -State $State; if ($t) { $t.Control.ResetTerminal() } }.GetNewClosure()
    Add-Command 'Send break'             'Serial only'                 { Invoke-PSTermSendBreak -State $State }.GetNewClosure()
    Add-Command 'Import PuTTY sessions'  'From the registry'           { Invoke-PSTermImportPutty -State $State }.GetNewClosure()
    Add-Command 'Import ssh_config hosts' 'From ~/.ssh/config'         { Invoke-PSTermImportSshConfig -State $State }.GetNewClosure()
    Add-Command 'Toggle theme'           'Dark and light'              { Invoke-PSTermToggleTheme -State $State }.GetNewClosure()
    Add-Command 'Open the PSTerm folder' 'Profiles, logs and settings' { Start-Process explorer.exe $State.Root }.GetNewClosure()

    foreach ($profile in @($State.Store.profiles)) {
        $target = Get-PSTermProfileTarget -Profile $profile
        $id = [string]$profile.id
        Add-Command "Connect: $($profile.name)" $target ([scriptblock]::Create("Connect-PSTermProfileById -State `$State -Id '$id'")).GetNewClosure()
    }

    $palette = New-Object System.Windows.Forms.Form
    $palette.FormBorderStyle = 'None'
    $palette.StartPosition = 'Manual'
    $palette.ShowInTaskbar = $false
    $palette.Font = New-PSTermFont -Size 10
    $palette.BackColor = $theme.Border
    $palette.Padding = New-Object System.Windows.Forms.Padding(1)
    $palette.Size = New-Object System.Drawing.Size([int](560 * $scale), [int](380 * $scale))
    $palette.Location = New-Object System.Drawing.Point(
        ($State.Form.Left + [int](($State.Form.Width - 560 * $scale) / 2)),
        ($State.Form.Top + [int](90 * $scale)))

    $inner = New-Object System.Windows.Forms.Panel
    $inner.Dock = 'Fill'
    $inner.BackColor = $theme.Surface

    $query = New-Object System.Windows.Forms.TextBox
    $query.Dock = 'Top'
    $query.BorderStyle = 'None'
    $query.Font = New-PSTermFont -Size 12
    $query.BackColor = $theme.Surface
    $query.ForeColor = $theme.Text
    $query.Height = [int](34 * $scale)

    $list = New-Object System.Windows.Forms.ListBox
    $list.Dock = 'Fill'
    $list.BorderStyle = 'None'
    $list.BackColor = $theme.Surface
    $list.ForeColor = $theme.Text
    $list.DrawMode = 'OwnerDrawFixed'
    $list.ItemHeight = [int](30 * $scale)

    $separator = New-Object System.Windows.Forms.Panel
    $separator.Dock = 'Top'
    $separator.Height = 1
    $separator.BackColor = $theme.Border

    $inner.Controls.Add($list)
    $inner.Controls.Add($separator)
    $inner.Controls.Add($query)
    $palette.Controls.Add($inner)

    $filtered = New-Object System.Collections.Generic.List[psobject]

    $refresh = {
        $text = $query.Text.Trim()
        $filtered.Clear()
        foreach ($command in $commands) {
            if (-not $text -or $command.Title -like "*$text*" -or $command.Hint -like "*$text*") {
                $filtered.Add($command)
            }
        }
        $list.BeginUpdate()
        $list.Items.Clear()
        foreach ($command in $filtered) { [void]$list.Items.Add($command.Title) }
        $list.EndUpdate()
        if ($list.Items.Count -gt 0) { $list.SelectedIndex = 0 }
    }.GetNewClosure()

    $list.Add_DrawItem({
        param($sender, $e)
        if ($e.Index -lt 0 -or $e.Index -ge $filtered.Count) { return }
        $command = $filtered[$e.Index]
        $selected = ($e.State -band [System.Windows.Forms.DrawItemState]::Selected) -ne 0

        $back = if ($selected) { $theme.Selection } else { $theme.Surface }
        $brush = New-Object System.Drawing.SolidBrush($back)
        try { $e.Graphics.FillRectangle($brush, $e.Bounds) } finally { $brush.Dispose() }

        $titleBrush = New-Object System.Drawing.SolidBrush($theme.Text)
        $hintBrush = New-Object System.Drawing.SolidBrush($theme.TextMuted)
        try {
            $e.Graphics.DrawString($command.Title, $sender.Font, $titleBrush,
                ($e.Bounds.Left + 10), ($e.Bounds.Top + 5))
            if ($command.Hint) {
                $hintFont = New-PSTermFont -Size 8
                try {
                    $size = $e.Graphics.MeasureString($command.Hint, $hintFont)
                    $e.Graphics.DrawString($command.Hint, $hintFont, $hintBrush,
                        ($e.Bounds.Right - $size.Width - 10), ($e.Bounds.Top + 7))
                }
                finally { $hintFont.Dispose() }
            }
        }
        finally { $titleBrush.Dispose(); $hintBrush.Dispose() }
    }.GetNewClosure())

    $invoke = {
        $index = $list.SelectedIndex
        if ($index -lt 0 -or $index -ge $filtered.Count) { return }
        $action = $filtered[$index].Action
        $palette.Close()
        & $action
    }.GetNewClosure()

    $query.Add_TextChanged($refresh)

    $query.Add_KeyDown({
        param($sender, $e)
        switch ($e.KeyCode) {
            ([System.Windows.Forms.Keys]::Escape) { $e.SuppressKeyPress = $true; $palette.Close() }
            ([System.Windows.Forms.Keys]::Enter)  { $e.SuppressKeyPress = $true; & $invoke }
            ([System.Windows.Forms.Keys]::Down) {
                $e.SuppressKeyPress = $true
                if ($list.SelectedIndex -lt $list.Items.Count - 1) { $list.SelectedIndex++ }
            }
            ([System.Windows.Forms.Keys]::Up) {
                $e.SuppressKeyPress = $true
                if ($list.SelectedIndex -gt 0) { $list.SelectedIndex-- }
            }
        }
    }.GetNewClosure())

    $list.Add_DoubleClick($invoke)
    $palette.Add_Deactivate({ $palette.Close() }.GetNewClosure())

    & $refresh
    $palette.Show($State.Form)
    $query.Focus() | Out-Null
}

# =============================================================================
# Scrollback search
# =============================================================================

function Show-PSTermFind {
    param([Parameter(Mandatory)]$State)

    $tab = Get-PSTermActiveTab -State $State
    if (-not $tab) { return }

    $theme = $State.Theme
    $scale = Get-PSTermScale -Control $State.Form

    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = 'Find in scrollback'
    $dialog.FormBorderStyle = 'FixedToolWindow'
    $dialog.StartPosition = 'CenterParent'
    $dialog.Font = New-PSTermFont -Size 9
    $dialog.Size = New-Object System.Drawing.Size([int](420 * $scale), [int](150 * $scale))

    $grid = New-PSTermFieldGrid
    $queryBox = Add-PSTermField $grid 'Find' (New-PSTermTextField '') $theme
    $caseBox = Add-PSTermField $grid '' (New-PSTermCheckField 'Match case' $false) $theme

    $row = New-Object System.Windows.Forms.FlowLayoutPanel
    $row.Dock = 'Bottom'
    $row.FlowDirection = 'RightToLeft'
    $row.Height = [int](40 * $scale)
    $row.Padding = New-Object System.Windows.Forms.Padding(8, 5, 8, 5)

    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = 'Close'
    $closeButton.DialogResult = 'Cancel'
    $closeButton.Width = [int](80 * $scale)

    $prevButton = New-Object System.Windows.Forms.Button
    $prevButton.Text = 'Previous'
    $prevButton.Width = [int](80 * $scale)

    $nextButton = New-Object System.Windows.Forms.Button
    $nextButton.Text = 'Next'
    $nextButton.Width = [int](80 * $scale)

    $row.Controls.AddRange(@($closeButton, $nextButton, $prevButton))

    $dialog.Controls.Add($grid)
    $dialog.Controls.Add($row)
    $dialog.CancelButton = $closeButton
    $dialog.AcceptButton = $nextButton

    # Search starts from the live bottom and walks backwards, which is what people
    # mean by "find the last time this happened".
    $cursor = [ref]$tab.Control.Terminal.Screen.TotalLines

    $search = {
        param([bool]$Forward)
        $needle = $queryBox.Text
        if (-not $needle) { return }
        $found = $tab.Control.FindInScrollback($needle, $cursor.Value, $Forward, $caseBox.Checked)
        if ($found -ge 0) {
            $cursor.Value = $found
            $tab.Control.ScrollToLine($found)
            $dialog.Text = "Find in scrollback - line $found"
        }
        else {
            $dialog.Text = 'Find in scrollback - no match'
        }
    }.GetNewClosure()

    $nextButton.Add_Click({ & $search $false }.GetNewClosure())
    $prevButton.Add_Click({ & $search $true }.GetNewClosure())

    Set-PSTermFormTheme -Control $dialog -Theme $theme
    [void]$dialog.ShowDialog($State.Form)
    $dialog.Dispose()
}

# =============================================================================
# Menu and commands
# =============================================================================

function Show-PSTermMenu {
    param([Parameter(Mandatory)]$State, $Anchor)

    $menu = New-Object System.Windows.Forms.ContextMenuStrip
    $menu.BackColor = $State.Theme.Surface
    $menu.ForeColor = $State.Theme.Text

    function Add-MenuItem { param([string]$Text, [scriptblock]$Action)
        $item = $menu.Items.Add($Text)
        $item.Add_Click($Action)
        $item
    }

    [void](Add-MenuItem 'Command palette   (Ctrl+K)' { Show-PSTermCommandPalette -State $State }.GetNewClosure())
    [void]$menu.Items.Add('-')
    [void](Add-MenuItem 'New connection...' { Invoke-PSTermEditProfile -State $State -Profile $null }.GetNewClosure())
    [void](Add-MenuItem 'Import PuTTY sessions' { Invoke-PSTermImportPutty -State $State }.GetNewClosure())
    [void](Add-MenuItem 'Import ssh_config hosts' { Invoke-PSTermImportSshConfig -State $State }.GetNewClosure())
    [void]$menu.Items.Add('-')
    [void](Add-MenuItem 'Toggle theme' { Invoke-PSTermToggleTheme -State $State }.GetNewClosure())
    [void](Add-MenuItem 'Open the PSTerm folder' { Start-Process explorer.exe $State.Root }.GetNewClosure())
    [void]$menu.Items.Add('-')
    [void](Add-MenuItem 'About PSTerm' { Show-PSTermAbout -State $State }.GetNewClosure())

    $menu.Show($Anchor, 0, $Anchor.Height)
}

function Invoke-PSTermToggleTheme {
    param([Parameter(Mandatory)]$State)

    $settings = Import-PSTermSettings -Root $State.Root
    $settings.theme = if ($settings.theme -eq 'Dark') { 'Light' } else { 'Dark' }
    Save-PSTermSettings -Root $State.Root -Settings $settings

    $State.Theme = New-PSTermChromeTheme -Mode $settings.theme
    Apply-PSTermTheme -State $State

    # Existing terminals keep their own per-profile colours; only new tabs and the
    # chrome follow the application theme, so a session's colours never change
    # underneath the operator mid-task.
    Set-PSTermStatusMessage -State $State -Message "Theme: $($settings.theme). Open tabs keep their own colours."
}

function Invoke-PSTermSendBreak {
    param([Parameter(Mandatory)]$State)

    $tab = Get-PSTermActiveTab -State $State
    if (-not $tab -or -not $tab.Session) { return }

    $backend = $tab.Session.Backend
    if ($backend -is [PSTerm.Backends.SerialBackend]) {
        $backend.SendBreak(300)
        Set-PSTermStatusMessage -State $State -Message 'Break sent.'
    }
    else {
        Set-PSTermStatusMessage -State $State -Message 'Break applies to serial sessions only.' -Level Warning
    }
}

function Invoke-PSTermImportPutty {
    param([Parameter(Mandatory)]$State)

    $imported = @(Import-PuttySessions)
    if ($imported.Count -eq 0) {
        Set-PSTermStatusMessage -State $State -Message 'No saved PuTTY sessions were found.' -Level Warning
        return
    }

    $added = Merge-PSTermImported -State $State -Profiles $imported
    Set-PSTermStatusMessage -State $State -Message "Imported $added PuTTY session(s)."
}

function Invoke-PSTermImportSshConfig {
    param([Parameter(Mandatory)]$State)

    $imported = @(Import-SshConfigHosts)
    if ($imported.Count -eq 0) {
        Set-PSTermStatusMessage -State $State -Message 'No hosts were found in ~/.ssh/config.' -Level Warning
        return
    }

    $added = Merge-PSTermImported -State $State -Profiles $imported
    Set-PSTermStatusMessage -State $State -Message "Imported $added host(s) from ssh_config."
}

function Merge-PSTermImported {
    <#
    .SYNOPSIS
        Add imported profiles, skipping ones already present in the same folder.
    #>
    param($State, $Profiles)

    $added = 0
    foreach ($profile in $Profiles) {
        $duplicate = @($State.Store.profiles) | Where-Object {
            $_.name -eq $profile.name -and $_.folder -eq $profile.folder
        }
        if ($duplicate) { continue }
        Set-PSTermProfile -Store $State.Store -Profile $profile | Out-Null
        $added++
    }

    if ($added -gt 0) {
        Save-PSTermProfiles -Root $State.Root -Store $State.Store
        Update-PSTermTree -State $State
    }
    $added
}

function Show-PSTermAbout {
    param([Parameter(Mandatory)]$State)

    $ptyState = if ([PSTerm.Backends.ConPtyBackend]::IsSupported) { 'available' } else { 'NOT available (Windows 10 1809 or later required)' }
    $ssh = [PSTerm.Backends.ConPtyCommands]::FindSsh()
    $sshState = if ($ssh) { $ssh } else { 'not installed (Settings > Optional features > OpenSSH Client)' }

    $message = @"
PSTerm - a native PowerShell terminal

PowerShell : $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))
Pseudo-console : $ptyState
OpenSSH client : $sshState
Install folder : $($State.Root)

Keyboard
  Ctrl+K          Command palette
  Ctrl+T          Focus the quick-connect bar
  Ctrl+W          Close tab
  Ctrl+R          Reconnect tab
  Ctrl+L          Clear scrollback
  Ctrl+F          Find in scrollback
  Ctrl+Tab        Next tab
  Ctrl+1..9       Go to tab
  Ctrl+Shift+C/V  Copy and paste
  Shift+PgUp/PgDn Scroll back
"@

    [void][System.Windows.Forms.MessageBox]::Show($State.Form, $message, 'About PSTerm',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information)
}
