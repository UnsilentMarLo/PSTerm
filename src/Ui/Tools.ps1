<#
.SYNOPSIS
    Smaller dialogs: prompts, the host-key popup, quick credentials, and the
    import and export of sessions.

.DESCRIPTION
    Every dialog is a ThemedForm built by New-PSTermDialogShell, so they share the
    title-bar colours, the icon, the buttons and the tooltips, and none of them
    repeats that setup.
#>

Set-StrictMode -Version Latest

# =============================================================================
# Shared pieces
# =============================================================================

function New-PSTermDialogShell {
    <#
    .SYNOPSIS
        An empty themed dialog with an OK and Cancel row, ready for content.
    #>
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$Title,
        [int]$Width = 460,
        [int]$Height = 220,
        [string]$OkText = 'OK',
        [string]$CancelText = 'Cancel',
        [switch]$NoCancel
    )

    $scale = Get-PSTermScale -Control $State.Form
    $font = New-PSTermFont
    $rowHeight = [int]($font.Height * 1.85)

    $dialog = New-Object PSTerm.Render.ThemedForm
    $dialog.Text = $Title
    $dialog.FormBorderStyle = 'FixedDialog'
    $dialog.StartPosition = 'CenterParent'
    $dialog.MinimizeBox = $false
    $dialog.MaximizeBox = $false
    $dialog.ShowInTaskbar = $false
    $dialog.Font = $font
    $dialog.ClientSize = New-Object System.Drawing.Size([int]($Width * $scale), [int]($Height * $scale))

    $body = New-Object PSTerm.Render.ThemedPanel
    $body.Dock = 'Fill'
    $body.Padding = New-Object System.Windows.Forms.Padding([int](16 * $scale), [int](14 * $scale), [int](16 * $scale), [int](8 * $scale))

    $buttonRow = New-Object PSTerm.Render.ThemedPanel
    $buttonRow.Dock = 'Bottom'
    $buttonRow.Height = $rowHeight + [int](18 * $scale)

    $flow = New-Object System.Windows.Forms.FlowLayoutPanel
    $flow.Dock = 'Fill'
    $flow.FlowDirection = 'RightToLeft'
    $flow.Padding = New-Object System.Windows.Forms.Padding([int](12 * $scale), [int](9 * $scale), [int](12 * $scale), [int](9 * $scale))
    $buttonRow.Controls.Add($flow)

    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = $OkText; $ok.DialogResult = 'OK'
    $ok.Width = [int](110 * $scale); $ok.Height = $rowHeight
    $flow.Controls.Add($ok)
    $dialog.AcceptButton = $ok

    $cancel = $null
    if (-not $NoCancel) {
        $cancel = New-Object System.Windows.Forms.Button
        $cancel.Text = $CancelText; $cancel.DialogResult = 'Cancel'
        $cancel.Width = [int](96 * $scale); $cancel.Height = $rowHeight
        $flow.Controls.Add($cancel)
        $dialog.CancelButton = $cancel
    }
    else { $dialog.CancelButton = $ok }

    $dialog.Controls.Add($body)
    $dialog.Controls.Add($buttonRow)

    $tips = New-Object PSTerm.Render.ThemedToolTip
    $tips.Apply((New-PSTermControlTheme -Theme $State.Theme))

    [pscustomobject]@{
        Form = $dialog; Body = $body; Ok = $ok; Cancel = $cancel; Flow = $flow
        Tips = $tips; Scale = $scale; RowHeight = $rowHeight; Theme = $State.Theme
    }
}

function Show-PSTermDialogShell {
    param([Parameter(Mandatory)]$Shell, [Parameter(Mandatory)]$State)
    Set-PSTermFormTheme -Control $Shell.Form -Theme $State.Theme
    try { $Shell.Form.ShowDialog($State.Form) }
    finally {
        $Shell.Tips.Dispose()
        $Shell.Form.Dispose()
    }
}

function New-PSTermPasswordField {
    <#
    .SYNOPSIS
        A password box with a Show/Hide button. The text box is on the .Tag of the
        returned panel.
    #>
    param([string]$Value = '', $Tips, [string]$Tip = '')

    $panel = New-Object System.Windows.Forms.TableLayoutPanel
    $panel.ColumnCount = 2
    $panel.RowCount = 1
    $panel.Margin = New-Object System.Windows.Forms.Padding(0)
    $panel.Height = [int]((New-PSTermFont).Height * 1.9)
    [void]$panel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
    [void]$panel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
    [void]$panel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))

    $box = New-Object System.Windows.Forms.TextBox
    $box.UseSystemPasswordChar = $true
    $box.Text = $Value
    $box.Dock = 'Fill'
    $box.Margin = New-Object System.Windows.Forms.Padding(0, 3, 4, 3)

    $toggle = New-Object System.Windows.Forms.Button
    $toggle.Text = 'Show'
    $toggle.Dock = 'Fill'
    $toggle.Width = [int]((New-PSTermFont).Height * 4.2)
    $toggle.Margin = New-Object System.Windows.Forms.Padding(0, 1, 0, 1)
    $toggle.TabStop = $false
    $toggle.Add_Click({
        $box.UseSystemPasswordChar = -not $box.UseSystemPasswordChar
        $toggle.Text = if ($box.UseSystemPasswordChar) { 'Show' } else { 'Hide' }
    }.GetNewClosure())

    $panel.Controls.Add($box, 0, 0)
    $panel.Controls.Add($toggle, 1, 0)
    $panel.Tag = $box

    if ($Tips) {
        if ($Tip) { $Tips.SetTip($box, $Tip) }
        $Tips.SetTip($toggle, 'Show or hide the password while you type it.')
    }
    $panel
}

function Add-PSTermDialogLabel {
    param($Parent, [string]$Text, $Theme, [int]$Top, [int]$Left, [int]$Width)
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.AutoSize = $false
    $label.SetBounds($Left, $Top, $Width, [int]((New-PSTermFont).Height * 1.5))
    $label.ForeColor = $Theme.Text
    $Parent.Controls.Add($label)
    $label
}

# =============================================================================
# Prompt for a value
# =============================================================================

function Show-PSTermInputDialog {
    <#
    .SYNOPSIS
        Ask for one value. Returns $null when cancelled, otherwise an object with
        Value and Checked.
    #>
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Prompt,
        [string]$Value = '',
        [switch]$Password,
        [string]$CheckboxText = '',
        [string]$Tip = ''
    )

    $height = if ($CheckboxText) { 190 } else { 160 }
    $shell = New-PSTermDialogShell -State $State -Title $Title -Width 440 -Height $height
    $scale = $shell.Scale

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Prompt
    $label.Dock = 'Top'
    $label.AutoSize = $false
    $label.Height = [int]((New-PSTermFont).Height * 2.6)
    $shell.Body.Controls.Add($label)

    if ($Password) {
        $field = New-PSTermPasswordField -Value $Value -Tips $shell.Tips -Tip $Tip
        $field.Dock = 'Top'
        $inputBox = $field.Tag
        $shell.Body.Controls.Add($field)
    }
    else {
        $inputBox = New-Object System.Windows.Forms.TextBox
        $inputBox.Text = $Value
        $inputBox.Dock = 'Top'
        $shell.Body.Controls.Add($inputBox)
        if ($Tip) { $shell.Tips.SetTip($inputBox, $Tip) }
    }

    $check = $null
    if ($CheckboxText) {
        $check = New-PSTermCheckField $CheckboxText $true
        $check.Dock = 'Top'
        $check.Margin = New-Object System.Windows.Forms.Padding(0, 8, 0, 0)
        $shell.Body.Controls.Add($check)
        $shell.Body.Controls.SetChildIndex($check, 0)
    }
    # Dock=Top stacks in reverse order of addition.
    $shell.Body.Controls.SetChildIndex($label, $shell.Body.Controls.Count - 1)

    $shell.Form.Add_Shown({ $inputBox.Focus() | Out-Null; $inputBox.SelectAll() }.GetNewClosure())
    $result = Show-PSTermDialogShell -Shell $shell -State $State
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) { return $null }

    [pscustomobject]@{ Value = $inputBox.Text; Checked = $(if ($check) { $check.Checked } else { $false }) }
}

# =============================================================================
# Host key
# =============================================================================

function Show-PSTermHostKeyDialog {
    <#
    .SYNOPSIS
        Ask whether to trust an SSH server's host key. Replaces the yes/no prompt
        that ssh prints in the terminal, which interrupts a login.
    .OUTPUTS
        'Trust', 'Always' (trust, and stop asking for this connection) or 'Reject'.
    #>
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$HostName,
        $Keys = @(),
        [string]$Detail = ''
    )

    $keyLines = @($Keys | ForEach-Object { "{0,-8} {1}" -f $_.KeyType, $_.Fingerprint })
    if ($keyLines.Count -eq 0) { $keyLines = @('(the fingerprint could not be read)') }

    $shell = New-PSTermDialogShell -State $State -Title 'Unknown host key' -Width 560 -Height (250 + 22 * [Math]::Min(4, $keyLines.Count)) `
        -OkText 'Trust and connect' -CancelText 'Cancel'
    $scale = $shell.Scale
    $shell.Ok.Width = [int](150 * $scale)

    $always = New-PSTermCheckField 'Always trust unknown keys for this connection' $false
    $always.Dock = 'Bottom'
    $shell.Tips.SetTip($always, "Turns on 'Accept new host keys automatically' for this connection, so this question is not asked again. A host key that later CHANGES is still refused.")

    $keys = New-Object System.Windows.Forms.TextBox
    $keys.Multiline = $true
    $keys.ReadOnly = $true
    $keys.BorderStyle = 'None'
    $keys.ScrollBars = 'None'
    $keys.WordWrap = $false
    $keys.Font = New-PSTermMonospaceFont -Family 'Consolas' -Size 9.5
    $keys.Text = ($keyLines -join "`r`n")
    $keys.Dock = 'Fill'
    $keys.BackColor = $State.Theme.Background
    $keys.ForeColor = $State.Theme.Text
    $keys.TabStop = $false

    $intro = New-Object System.Windows.Forms.Label
    $intro.Text = "PSTerm has not connected to '$HostName' before, so its identity cannot be checked yet.`r`nCompare the fingerprint with the one the device reports (show ssh / crypto key) if you can, then decide whether to trust it."
    $intro.Dock = 'Top'
    $intro.AutoSize = $false
    $intro.Height = [int]((New-PSTermFont).Height * 4.0)

    $shell.Body.Controls.Add($keys)
    $shell.Body.Controls.Add($always)
    $shell.Body.Controls.Add($intro)

    $result = Show-PSTermDialogShell -Shell $shell -State $State
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) { return 'Reject' }
    if ($always.Checked) { 'Always' } else { 'Trust' }
}

# =============================================================================
# Quick credentials
# =============================================================================

function Show-PSTermCredentialManager {
    <#
    .SYNOPSIS
        Add, change and delete quick credentials. Secrets are stored encrypted.
    #>
    param([Parameter(Mandatory)]$State)

    $shell = New-PSTermDialogShell -State $State -Title 'Quick credentials' -Width 640 -Height 360 -OkText 'Close' -NoCancel
    $scale = $shell.Scale
    $theme = $State.Theme

    $list = New-Object System.Windows.Forms.ListBox
    $list.Dock = 'Left'
    $list.Width = [int](200 * $scale)
    $list.BorderStyle = 'None'
    $list.IntegralHeight = $false
    $shell.Tips.SetTip($list, 'Saved credentials. Pick one to change it.')

    $right = New-PSTermFieldGrid
    $right.Dock = 'Top'
    $nameBox = Add-PSTermField $right 'Name' (New-PSTermTextField '') $theme -Tip 'What the credential is for, for example "Lab enable". It is the name shown in the Credentials menu.' -Tips $shell.Tips
    $userBox = Add-PSTermField $right 'User name' (New-PSTermTextField '') $theme -Tip 'Optional. Leave empty for a secret that is typed on its own, such as an enable password.' -Tips $shell.Tips
    $secretPanel = New-PSTermPasswordField -Tips $shell.Tips -Tip 'The secret that is typed into the terminal. It is stored encrypted for your Windows account and never written to the connection file.'
    [void](Add-PSTermField $right 'Secret' $secretPanel $theme)
    $secretBox = $secretPanel.Tag

    $hint = New-Object System.Windows.Forms.Label
    $hint.Text = "Leave the secret empty to keep the one that is saved."
    $hint.ForeColor = $theme.TextMuted
    $hint.Dock = 'Top'
    $hint.Height = [int]((New-PSTermFont).Height * 1.8)
    $hint.Padding = New-Object System.Windows.Forms.Padding(8, 4, 0, 0)

    $buttons = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttons.Dock = 'Top'
    $buttons.Height = $shell.RowHeight + [int](12 * $scale)
    $buttons.Padding = New-Object System.Windows.Forms.Padding(6, 6, 0, 0)

    $new = New-Object System.Windows.Forms.Button; $new.Text = 'New'
    $save = New-Object System.Windows.Forms.Button; $save.Text = 'Save'
    $delete = New-Object System.Windows.Forms.Button; $delete.Text = 'Delete'
    foreach ($b in @($new, $save, $delete)) { $b.Width = [int](88 * $scale); $b.Height = $shell.RowHeight }
    $buttons.Controls.AddRange(@($new, $save, $delete))
    $shell.Tips.SetTip($new, 'Clear the fields to enter a new credential.')
    $shell.Tips.SetTip($save, 'Save this credential (add it, or update the selected one).')
    $shell.Tips.SetTip($delete, 'Delete the selected credential and its stored secret.')

    $shell.Body.Controls.Add($buttons)
    $shell.Body.Controls.Add($hint)
    $shell.Body.Controls.Add($right)
    $shell.Body.Controls.Add($list)

    $script:credEditingId = ''
    $refresh = {
        $list.Items.Clear()
        foreach ($c in @($State.Store.credentials)) { [void]$list.Items.Add([string]$c.name) }
    }.GetNewClosure()
    & $refresh

    $load = {
        $index = $list.SelectedIndex
        $creds = @($State.Store.credentials)
        if ($index -lt 0 -or $index -ge $creds.Count) { return }
        $c = $creds[$index]
        $script:credEditingId = [string]$c.id
        $nameBox.Text = [string]$c.name
        $userBox.Text = [string]$c.username
        $secretBox.Text = ''
    }.GetNewClosure()
    $list.Add_SelectedIndexChanged($load)

    $new.Add_Click({
        $list.ClearSelected()
        $script:credEditingId = ''
        $nameBox.Text = ''; $userBox.Text = ''; $secretBox.Text = ''
        $nameBox.Focus() | Out-Null
    }.GetNewClosure())

    $save.Add_Click({
        $name = $nameBox.Text.Trim()
        if (-not $name) {
            [void](Show-PSTermMessage -Theme $theme -Owner $shell.Form -Title 'Quick credentials' -Message 'Give the credential a name.' -Level Warning)
            return
        }
        $splat = @{ Store = $State.Store; Root = $State.Root; Name = $name; Username = $userBox.Text.Trim(); Secret = $secretBox.Text }
        if ($script:credEditingId) { $splat.Id = $script:credEditingId }
        $saved = Set-PSTermCredential @splat
        $script:credEditingId = [string]$saved.id
        Save-PSTermProfiles -Root $State.Root -Store $State.Store
        $secretBox.Text = ''
        & $refresh
        $index = @($State.Store.credentials).IndexOf($saved)
        if ($index -ge 0) { $list.SelectedIndex = $index }
        Set-PSTermStatusMessage -State $State -Message "Saved credential '$name'."
    }.GetNewClosure())

    $delete.Add_Click({
        if (-not $script:credEditingId) { return }
        $c = Get-PSTermCredentialById -Store $State.Store -Id $script:credEditingId
        if (-not $c) { return }
        $answer = Show-PSTermMessage -Theme $theme -Owner $shell.Form -Title 'Delete credential' -Buttons YesNo -Level Warning `
            -Message "Delete '$($c.name)' and its stored secret?"
        if ($answer -ne 'Yes') { return }
        Remove-PSTermCredential -Store $State.Store -Root $State.Root -Id $script:credEditingId
        Save-PSTermProfiles -Root $State.Root -Store $State.Store
        $script:credEditingId = ''
        $nameBox.Text = ''; $userBox.Text = ''; $secretBox.Text = ''
        & $refresh
    }.GetNewClosure())

    [void](Show-PSTermDialogShell -Shell $shell -State $State)
}

function Show-PSTermCredentialMenu {
    <#
    .SYNOPSIS
        The toolbar's credentials drop-down: send a saved secret to the terminal.
    #>
    param([Parameter(Mandatory)]$State, [System.Drawing.Point]$Location)

    $menu = New-PSTermMenu -Theme $State.Theme
    $tab = Get-PSTermActiveTab -State $State
    $live = $tab -and $tab.Session -and -not $tab.Closed

    $creds = @($State.Store.credentials)
    if ($creds.Count -eq 0) {
        $empty = $menu.Items.Add('No credentials saved yet')
        $empty.Enabled = $false
    }

    foreach ($c in $creds) {
        $credential = $c
        if ($credential.username) {
            $item = $menu.Items.Add("$($credential.name): send user name  ($($credential.username))")
            $item.Enabled = [bool]$live
            $item.ToolTipText = 'Type the user name and press Enter.'
            $item.Add_Click({ Send-PSTermCredential -State $State -Credential $credential -Part User }.GetNewClosure())
        }
        $item = $menu.Items.Add("$($credential.name): send password")
        $item.Enabled = [bool]$live
        $item.ToolTipText = 'Type the saved secret and press Enter.'
        $item.Add_Click({ Send-PSTermCredential -State $State -Credential $credential -Part Secret }.GetNewClosure())
    }

    [void]$menu.Items.Add('-')
    $manage = $menu.Items.Add('Manage credentials...')
    $manage.Add_Click({ Show-PSTermCredentialManager -State $State }.GetNewClosure())

    $menu.Show($Location)
}

function Send-PSTermCredential {
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Credential, [ValidateSet('User', 'Secret')][string]$Part)

    $tab = Get-PSTermActiveTab -State $State
    if (-not $tab -or -not $tab.Session -or $tab.Closed) { return }

    $text = if ($Part -eq 'User') { [string]$Credential.username } else { Get-PSTermSecret -Root $State.Root -Key ([string]$Credential.secretKey) }
    if ($null -eq $text -or $text -eq '') {
        Set-PSTermStatusMessage -State $State -Message "'$($Credential.name)' has no saved $(if ($Part -eq 'User') { 'user name' } else { 'secret' })." -Level Warning
        return
    }
    $tab.Session.Send($text + "`r")
    $tab.Control.Focus() | Out-Null
}

# =============================================================================
# Import and export
# =============================================================================

function Invoke-PSTermImportCsv {
    <#
    .SYNOPSIS
        Create connections from a CSV file, with a preview before anything is added.
    #>
    param([Parameter(Mandatory)]$State, [string]$Path = '', [string]$Folder = '')

    if (-not $Path) {
        $picker = New-Object System.Windows.Forms.OpenFileDialog
        $picker.Title = 'Import connections from CSV'
        $picker.Filter = 'CSV files (*.csv;*.txt)|*.csv;*.txt|All files (*.*)|*.*'
        if ($picker.ShowDialog($State.Form) -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $Path = $picker.FileName
    }

    try { $csv = Read-PSTermCsv -Path $Path }
    catch {
        [void](Show-PSTermMessage -Theme $State.Theme -Owner $State.Form -Title 'Import CSV' -Level Danger -Message "The file could not be read.`r`n`r`n$($_.Exception.Message)")
        return
    }
    if (@($csv.Rows).Count -eq 0) {
        [void](Show-PSTermMessage -Theme $State.Theme -Owner $State.Form -Title 'Import CSV' -Level Warning -Message 'The file has no rows.')
        return
    }

    $guess = Get-PSTermCsvGuess -Columns $csv.Columns
    $columns = @('') + @($csv.Columns)
    $theme = $State.Theme

    $shell = New-PSTermDialogShell -State $State -Title 'Import connections from CSV' -Width 680 -Height 560 -OkText 'Import'
    $scale = $shell.Scale
    $tips = $shell.Tips

    $grid = New-PSTermFieldGrid
    $grid.Dock = 'Top'
    $typeBox = Add-PSTermField $grid 'Connection type' (New-PSTermComboField -Items @('SSH', 'Telnet') -Value 'SSH') $theme -Tip 'The kind of connection to create for every row.' -Tips $tips
    $hostBox = Add-PSTermField $grid 'Address column' (New-PSTermComboField -Items $columns -Value $guess.Host) $theme -Tip 'The column holding the IP address or host name to connect to. A prefix length such as /24 is removed.' -Tips $tips
    $nameBox = Add-PSTermField $grid 'Name column' (New-PSTermComboField -Items $columns -Value $guess.Name) $theme -Tip 'The column used as the connection name. Rows where it is empty are named by their address, and then by the device itself once it is known.' -Tips $tips
    $notesBox = Add-PSTermField $grid 'Notes column' (New-PSTermComboField -Items $columns -Value $guess.Notes) $theme -Tip 'The column copied into the connection''s notes.' -Tips $tips
    $groupBox = Add-PSTermField $grid 'Subfolders by' (New-PSTermComboField -Items $columns -Value $guess.Notes) $theme -Tip 'Sort the connections into a subfolder per value of this column, for example one folder per switch model. Choose the empty entry for none.' -Tips $tips
    $folderBox = Add-PSTermField $grid 'Into folder' (New-PSTermComboField -Items (Get-PSTermAllFolderPaths -Store $State.Store) -Value $Folder -Editable) $theme -Tip 'The folder the imported connections go into. A new name creates it. New connections start from that folder''s default settings.' -Tips $tips
    $stripBox = Add-PSTermField $grid '' (New-PSTermCheckField 'Remove the prefix length from addresses (10.0.0.5/24 -> 10.0.0.5)' $true) $theme -Tip 'NetBox and most IPAM exports write addresses with their subnet mask length, which ssh cannot use.' -Tips $tips

    # A read-only box without scroll bars: a ListBox would bring a white system scroll
    # bar into a dark dialog, and a preview this short does not need one.
    $preview = New-Object System.Windows.Forms.TextBox
    $preview.Multiline = $true
    $preview.ReadOnly = $true
    $preview.WordWrap = $false
    $preview.ScrollBars = 'None'
    $preview.BorderStyle = 'None'
    $preview.TabStop = $false
    $preview.Dock = 'Fill'
    $preview.Font = New-PSTermMonospaceFont -Family 'Consolas' -Size 9.5
    $tips.SetTip($preview, 'The first rows as they will be imported: folder / name  -  address.')

    $summary = New-Object System.Windows.Forms.Label
    $summary.Dock = 'Bottom'
    $summary.Height = [int]((New-PSTermFont).Height * 1.9)
    $summary.ForeColor = $theme.TextMuted

    $shell.Body.Controls.Add($preview)
    $shell.Body.Controls.Add($summary)
    $shell.Body.Controls.Add($grid)

    $script:csvProfiles = @()
    $rebuild = {
        $mapping = @{ Host = [string]$hostBox.SelectedItem; Name = [string]$nameBox.SelectedItem; Notes = [string]$notesBox.SelectedItem; Folder = '' }
        $script:csvProfiles = @()
        $preview.Text = ''
        if (-not $mapping.Host) { $summary.Text = 'Choose the column that holds the address.'; return }
        $script:csvProfiles = @(ConvertFrom-PSTermCsvRows -Store $State.Store -Rows $csv.Rows -Mapping $mapping `
            -Type ([string]$typeBox.SelectedItem) -BaseFolder $folderBox.Text.Trim() -GroupBy ([string]$groupBox.SelectedItem) `
            -StripPrefixLength:$stripBox.Checked)
        $lines = @($script:csvProfiles | Select-Object -First 12 | ForEach-Object {
            $where = if ($_.folder) { "$($_.folder)/" } else { '' }
            "$where$($_.name)  -  $(Get-PSTermProfileTarget -Profile $_)"
        })
        $preview.Text = $lines -join "`r`n"
        $summary.Text = "$(@($script:csvProfiles).Count) of $(@($csv.Rows).Count) rows will be imported" +
            $(if (@($script:csvProfiles).Count -gt 12) { ' (first 12 shown)' } else { '' })
    }.GetNewClosure()

    foreach ($c in @($typeBox, $hostBox, $nameBox, $notesBox, $groupBox)) { $c.Add_SelectedIndexChanged($rebuild) }
    $folderBox.Add_TextChanged($rebuild)
    $stripBox.Add_CheckedChanged($rebuild)
    & $rebuild

    $result = Show-PSTermDialogShell -Shell $shell -State $State
    if ($result -ne [System.Windows.Forms.DialogResult]::OK -or @($script:csvProfiles).Count -eq 0) { return }

    $added = Merge-PSTermImportedSessions -Store $State.Store -Profiles $script:csvProfiles
    Save-PSTermProfiles -Root $State.Root -Store $State.Store
    Update-PSTermTree -State $State
    foreach ($p in $script:csvProfiles) { if ($p.autoName) { Register-PSTermAutoName -State $State -Profile $p } }
    $skipped = @($script:csvProfiles).Count - $added
    Set-PSTermStatusMessage -State $State -Message "Imported $added connection(s) from $(Split-Path -Leaf $Path)$(if ($skipped -gt 0) { "; $skipped already existed" })."
}

function Invoke-PSTermExportSessions {
    <#
    .SYNOPSIS
        Save connections to a PSTerm session file for backup or sharing.
    .PARAMETER Scope
        All, or Folder / Profile with -Target.
    #>
    param(
        [Parameter(Mandatory)]$State,
        [ValidateSet('All', 'Folder', 'Profile')][string]$Scope = 'All',
        [string]$Target = ''
    )

    $profiles = @($State.Store.profiles)
    $folders = @()
    $name = 'psterm-sessions'

    switch ($Scope) {
        'Folder' {
            $profiles = @($profiles | Where-Object { $_.folder -eq $Target -or ([string]$_.folder) -like "$Target/*" })
            $folders = @($Target)
            $name = ($Target -replace '[\\/:*?"<>|]', '-')
        }
        'Profile' {
            $profile = Get-PSTermProfileById -Store $State.Store -Id $Target
            if (-not $profile) { return }
            $profiles = @($profile)
            $name = ([string]$profile.name -replace '[\\/:*?"<>|]', '-')
        }
    }

    $picker = New-Object System.Windows.Forms.SaveFileDialog
    $picker.Title = 'Export connections'
    $picker.Filter = 'PSTerm sessions (*.psterm)|*.psterm|All files (*.*)|*.*'
    $picker.FileName = $name
    $picker.DefaultExt = 'psterm'
    if ($picker.ShowDialog($State.Form) -ne [System.Windows.Forms.DialogResult]::OK) { return }

    try {
        $count = Export-PSTermSessions -Store $State.Store -Path $picker.FileName -Profiles $profiles -FolderPaths $folders
        Set-PSTermStatusMessage -State $State -Message "Exported $count connection(s) to $($picker.FileName). Passwords are not included."
    }
    catch {
        [void](Show-PSTermMessage -Theme $State.Theme -Owner $State.Form -Title 'Export' -Level Danger -Message "The file could not be written.`r`n`r`n$($_.Exception.Message)")
    }
}

function Invoke-PSTermImportSessions {
    param([Parameter(Mandatory)]$State, [string]$Path = '')

    if (-not $Path) {
        $picker = New-Object System.Windows.Forms.OpenFileDialog
        $picker.Title = 'Import connections'
        $picker.Filter = 'PSTerm sessions (*.psterm)|*.psterm|All files (*.*)|*.*'
        if ($picker.ShowDialog($State.Form) -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $Path = $picker.FileName
    }

    try { $imported = Import-PSTermSessions -Path $Path }
    catch {
        [void](Show-PSTermMessage -Theme $State.Theme -Owner $State.Form -Title 'Import' -Level Danger -Message $_.Exception.Message)
        return
    }

    $added = Merge-PSTermImportedSessions -Store $State.Store -Profiles $imported.Profiles -Folders $imported.Folders
    Save-PSTermProfiles -Root $State.Root -Store $State.Store
    Update-PSTermTree -State $State
    $skipped = @($imported.Profiles).Count - $added
    Set-PSTermStatusMessage -State $State -Message "Imported $added connection(s)$(if ($skipped -gt 0) { "; $skipped already existed and were skipped" }). Passwords are not part of a session file, so set them again if needed."
}

# =============================================================================
# Settings
# =============================================================================

function Show-PSTermSettings {
    <#
    .SYNOPSIS
        The few application-wide settings.
    #>
    param([Parameter(Mandatory)]$State)

    $settings = Import-PSTermSettings -Root $State.Root
    $theme = $State.Theme

    $shell = New-PSTermDialogShell -State $State -Title 'Settings' -Width 560 -Height 380 -OkText 'Save'
    $grid = New-PSTermFieldGrid
    $grid.Dock = 'Top'

    $user = Add-PSTermField $grid 'Default SSH user' (New-PSTermTextField ([string]$settings.defaultSshUser)) $theme -Tips $shell.Tips `
        -Tip 'Used when neither the connection nor its folder names an SSH user. Leave empty to be asked each time - PSTerm never guesses your Windows user name.'
    $detect = Add-PSTermField $grid '' (New-PSTermCheckField 'Offer serial ports as soon as they are plugged in' ([bool]$settings.detectSerialPorts)) $theme -Tips $shell.Tips `
        -Tip 'Shows each COM port that appears under Detected serial ports so a console cable can be opened with a double-click. Nothing is saved.'
    $baud = Add-PSTermField $grid 'Detected port speed' (New-PSTermComboField -Items @('1200','2400','4800','9600','19200','38400','57600','115200') -Value ([string]$settings.detectedPortBaud) -Editable) $theme -Tips $shell.Tips `
        -Tip 'The baud rate used when a detected port is opened. Cisco consoles use 9600.'
    $pace = Add-PSTermField $grid 'Paced paste' (New-PSTermComboField -Items @('Off', 'Serial', 'All') -Value ([string]$settings.pacePaste)) $theme -Tips $shell.Tips `
        -Tip 'Feed a pasted block to the device one line at a time, waiting for each answer, instead of all at once. It is about two to three times slower. Turn it on for a console that drops characters when a block arrives at full speed; the Catalyst switches this was tried on did not. Serial = serial connections only.'
    $paste = Add-PSTermField $grid '' (New-PSTermCheckField 'Ask before pasting several lines' ([bool]$settings.confirmMultilinePaste)) $theme -Tips $shell.Tips `
        -Tip 'A pasted line break is an Enter keypress, so every line runs at once. This gives you the chance to say no.'
    $shell.Body.Controls.Add($grid)

    if ((Show-PSTermDialogShell -Shell $shell -State $State) -ne [System.Windows.Forms.DialogResult]::OK) { return }

    $settings.defaultSshUser = $user.Text.Trim()
    $settings.detectSerialPorts = $detect.Checked
    $settings.detectedPortBaud = ConvertTo-PSTermInt $baud.Text 9600
    $settings.confirmMultilinePaste = $paste.Checked
    $settings.pacePaste = [string]$pace.SelectedItem
    Save-PSTermSettings -Root $State.Root -Settings $settings
    Set-PSTermStatusMessage -State $State -Message 'Settings saved. The serial port setting applies the next time PSTerm starts.'
}
