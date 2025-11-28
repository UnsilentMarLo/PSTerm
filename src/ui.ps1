<#
    PSTerm - A powerful native PowerShell Serial/SSH/Telnet Terminal.
    Copyright (C) 2025 Marlo K <Plays.xenon@yahoo.de>

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
#region GUI Function

function Show-ConnectionConfigMenu {

    $consoleHandle = [ConsoleUtils]::GetConsoleWindow()
    if ($consoleHandle -ne [IntPtr]::Zero) {
        [ConsoleUtils]::ShowWindow($consoleHandle, 0) # Hide console
    }

    $form = New-Object Windows.Forms.Form
    $form.Text = "Connection Configuration"
    $form.FormBorderStyle = 'FixedSingle'
    $form.MaximizeBox = $false
    $form.AutoScaleMode = 'Dpi'
    $form.AutoSize = $true
    $form.AutoSizeMode = 'GrowAndShrink'
    $form.StartPosition = "CenterScreen"
    #$form.Padding = 10
    $form.Icon = New-Object System.Drawing.Icon(Join-Path $ScriptBaseDir "src\icon.ico")

    # Helper function to create a label
    function New-Label($text) {
        $lbl = New-Object Windows.Forms.Label
        $lbl.Text = $text
        $lbl.Anchor = 'Left, Top' # CHANGE THIS LINE from 'Left' to 'Left, Top'
        $lbl.TextAlign = 'MiddleLeft'
        $lbl.AutoSize = $true
        return $lbl
    }

    # --- Main Layout ---
    $mainLayout = New-Object Windows.Forms.TableLayoutPanel
    $mainLayout.Dock = 'Fill'
    $mainLayout.AutoSize = $true
    $mainLayout.ColumnCount = 2
    $mainLayout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'AutoSize')) | Out-Null
    $mainLayout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'AutoSize')) | Out-Null
    $form.Controls.Add($mainLayout)

    # --- Profile Controls (Row 0) ---
    $gbProfile = New-Object Windows.Forms.GroupBox; $gbProfile.Text = "Profile"; $gbProfile.Dock = 'Fill'; $gbProfile.AutoSize = $true
    $mainLayout.Controls.Add($gbProfile, 0, 0); $mainLayout.SetColumnSpan($gbProfile, 2)

    $profileTlp = New-Object Windows.Forms.TableLayoutPanel; $profileTlp.Dock = 'Fill'; $profileTlp.AutoSize = $true; $profileTlp.Padding = 5; $profileTlp.ColumnCount = 4
    $profileTlp.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'AutoSize')) | Out-Null # Select Profile:
    $profileTlp.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'Percent', 100)) | Out-Null # ComboBox (Dropdown)
    $profileTlp.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'AutoSize')) | Out-Null # Save Button
    $profileTlp.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'AutoSize')) | Out-Null # Delete Button
    $gbProfile.Controls.Add($profileTlp)

    $profileTlp.Controls.Add((New-Label "Select Profile:"), 0, 0)
    $cbProfiles = New-Object Windows.Forms.ComboBox; $cbProfiles.Dock = 'Fill'; $cbProfiles.Items.AddRange((Get-ProfileList)); $cbProfiles.DropDownStyle = 'DropDown'
    $profileTlp.Controls.Add($cbProfiles, 1, 0)
    $btnSaveProfile = New-Object Windows.Forms.Button; $btnSaveProfile.Text = "Save"; $btnSaveProfile.Anchor = 'Top'
    $profileTlp.Controls.Add($btnSaveProfile, 2, 0)
    $btnDeleteProfile = New-Object Windows.Forms.Button; $btnDeleteProfile.Text = "Delete"; $btnDeleteProfile.Anchor = 'Top'
    $profileTlp.Controls.Add($btnDeleteProfile, 3, 0)


    # --- Left Pane Layout ---
    $leftPane = New-Object Windows.Forms.TableLayoutPanel; $leftPane.Dock = 'Fill'; $leftPane.AutoSize = $true
    $mainLayout.Controls.Add($leftPane, 0, 1)

    # --- Connection Type (Left Pane Row 0) ---
    $gbType = New-Object Windows.Forms.GroupBox; $gbType.Text = "Connection Type"; $gbType.Dock = 'Fill'; $gbType.AutoSize = $true
    $leftPane.Controls.Add($gbType, 0, 0)
    $typeFlow = New-Object Windows.Forms.FlowLayoutPanel; $typeFlow.Dock = 'Fill'; $typeFlow.AutoSize = $true; $typeFlow.Padding = 5
    $gbType.Controls.Add($typeFlow)
    $rbSerial = New-Object Windows.Forms.RadioButton; $rbSerial.Text = "Serial"; $rbSerial.AutoSize = $true
    $rbSsh = New-Object Windows.Forms.RadioButton; $rbSsh.Text = "SSH"; $rbSsh.AutoSize = $true
    $rbTelnet = New-Object Windows.Forms.RadioButton; $rbTelnet.Text = "Telnet"; $rbTelnet.AutoSize = $true
    $typeFlow.Controls.AddRange(@($rbSerial, $rbSsh, $rbTelnet))

    # --- Connection Specifics (Left Pane Row 1) ---
    $gbConnSpecific = New-Object Windows.Forms.GroupBox; $gbConnSpecific.Text = "Connection Settings"; $gbConnSpecific.Dock = 'Fill'; $gbConnSpecific.AutoSize = $true
    $leftPane.Controls.Add($gbConnSpecific, 0, 1)

    # Helper to build a settings panel
    function New-SettingsPanel {
        $tlp = New-Object Windows.Forms.TableLayoutPanel
        $tlp.Dock = 'Fill'; $tlp.AutoSize = $true; $tlp.Padding = 5; $tlp.ColumnCount = 3
        $tlp.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'AutoSize')) | Out-Null
        $tlp.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'Percent', 100)) | Out-Null
        $tlp.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'AutoSize')) | Out-Null
        return $tlp
    }

    # Serial Panel
    $pnlSerial = New-SettingsPanel
    $gbConnSpecific.Controls.Add($pnlSerial)
    $pnlSerial.Controls.Add((New-Label "COM Port:"), 0, 0);
    $pnlSerial.Controls.Add((New-Label "Baud Rate:"), 0, 1);
    $pnlSerial.Controls.Add((New-Label "Data Bits:"), 0, 2);
    $pnlSerial.Controls.Add((New-Label "Parity:"), 0, 3);
    $pnlSerial.Controls.Add((New-Label "Stop Bits:"), 0, 4);
    $pnlSerial.Controls.Add((New-Label "Handshake:"), 0, 5);
    $pnlSerial.Controls.Add((New-Label "Enable DTR:"), 0, 6);

    $cbPort = New-Object Windows.Forms.ComboBox; $cbPort.DropDownStyle = 'DropDownList'; $cbPort.Dock = 'Fill'
    $pnlSerial.Controls.Add($cbPort, 1, 0)
    $btnRefreshPorts = New-Object Windows.Forms.Button; $btnRefreshPorts.Text = "Refresh"; $btnRefreshPorts.AutoSize = $true
    $pnlSerial.Controls.Add($btnRefreshPorts, 2, 0)

    $cbBaud = New-Object Windows.Forms.ComboBox; $cbBaud.DropDownStyle = 'DropDownList'; $cbBaud.Dock = 'Fill'; $cbBaud.Items.AddRange(@("9600", "19200", "38400", "57600", "115200"))
    $pnlSerial.Controls.Add($cbBaud, 1, 1)
    $cbDataBits = New-Object Windows.Forms.ComboBox; $cbDataBits.DropDownStyle = 'DropDownList'; $cbDataBits.Dock = 'Fill'; $cbDataBits.Items.AddRange(@("8", "7"))
    $pnlSerial.Controls.Add($cbDataBits, 1, 2)
    $cbParity = New-Object Windows.Forms.ComboBox; $cbParity.DropDownStyle = 'DropDownList'; $cbParity.Dock = 'Fill'; $cbParity.Items.AddRange(([enum]::GetNames([System.IO.Ports.Parity])))
    $pnlSerial.Controls.Add($cbParity, 1, 3)
    $cbStopBits = New-Object Windows.Forms.ComboBox; $cbStopBits.DropDownStyle = 'DropDownList'; $cbStopBits.Dock = 'Fill'; $cbStopBits.Items.AddRange(([enum]::GetNames([System.IO.Ports.StopBits])))
    $pnlSerial.Controls.Add($cbStopBits, 1, 4)
    $cbHandshake = New-Object Windows.Forms.ComboBox; $cbHandshake.DropDownStyle = 'DropDownList'; $cbHandshake.Dock = 'Fill'; $cbHandshake.Items.AddRange(([enum]::GetNames([System.IO.Ports.Handshake])))
    $pnlSerial.Controls.Add($cbHandshake, 1, 5)
    $chkDtrEnable = New-Object Windows.Forms.CheckBox; $chkDtrEnable.Anchor = 'Left'
    $pnlSerial.Controls.Add($chkDtrEnable, 1, 6)

    # SSH Panel
    $pnlSsh = New-SettingsPanel; $pnlSsh.Visible = $false
    $gbConnSpecific.Controls.Add($pnlSsh)
    $pnlSsh.Controls.Add((New-Label "Host / IP:"), 0, 0); $txtSshHost = New-Object Windows.Forms.TextBox; $txtSshHost.Dock = 'Fill'; $pnlSsh.Controls.Add($txtSshHost, 1, 0)
    $pnlSsh.Controls.Add((New-Label "Username:"), 0, 1); $txtSshUser = New-Object Windows.Forms.TextBox; $txtSshUser.Dock = 'Fill'; $pnlSsh.Controls.Add($txtSshUser, 1, 1)
    $pnlSsh.Controls.Add((New-Label "Port:"), 0, 2); $txtSshPort = New-Object Windows.Forms.TextBox; $txtSshPort.Dock = 'Fill'; $pnlSsh.Controls.Add($txtSshPort, 1, 2)

    # Telnet Panel
    $pnlTelnet = New-SettingsPanel; $pnlTelnet.Visible = $false
    $gbConnSpecific.Controls.Add($pnlTelnet)
    $pnlTelnet.Controls.Add((New-Label "Host / IP:"), 0, 0); $txtTelnetHost = New-Object Windows.Forms.TextBox; $txtTelnetHost.Dock = 'Fill'; $pnlTelnet.Controls.Add($txtTelnetHost, 1, 0)
    $pnlTelnet.Controls.Add((New-Label "Port:"), 0, 1); $txtTelnetPort = New-Object Windows.Forms.TextBox; $txtTelnetPort.Dock = 'Fill'; $pnlTelnet.Controls.Add($txtTelnetPort, 1, 1)

    # --- Auto-Input (Left Pane Row 2) ---
    $gbAutoInput = New-Object Windows.Forms.GroupBox; $gbAutoInput.Text = "Auto-Input Script"; $gbAutoInput.Dock = 'Fill'
    $leftPane.Controls.Add($gbAutoInput, 0, 2)
    $txtAutoInput = New-Object Windows.Forms.TextBox; $txtAutoInput.Multiline = $true; $txtAutoInput.ScrollBars = 'Vertical'; $txtAutoInput.AcceptsReturn = $true; $txtAutoInput.Dock = 'Fill'; $txtAutoInput.Height = 80
    $gbAutoInput.Controls.Add($txtAutoInput)


    # --- Right Pane (Common and Logging) ---
    $gbCommon = New-Object Windows.Forms.GroupBox; $gbCommon.Text = "Terminal and Logging"; $gbCommon.Dock = 'Fill'; $gbCommon.AutoSize = $true
    $mainLayout.Controls.Add($gbCommon, 1, 1); $mainLayout.SetRowSpan($gbCommon, 2)
    $commonTlp = New-SettingsPanel
    $gbCommon.Controls.Add($commonTlp)

    $allColors = [System.Enum]::GetNames([System.ConsoleColor])
    $commonTlp.Controls.Add((New-Label "Text Color:"), 0, 0); $cbTextColor = New-Object Windows.Forms.ComboBox; $cbTextColor.DropDownStyle = 'DropDownList'; $cbTextColor.Dock = 'Fill'; $cbTextColor.Items.AddRange($allColors); $commonTlp.Controls.Add($cbTextColor, 1, 0)
    $commonTlp.Controls.Add((New-Label "Background Color:"), 0, 1); $cbBgColor = New-Object Windows.Forms.ComboBox; $cbBgColor.DropDownStyle = 'DropDownList'; $cbBgColor.Dock = 'Fill'; $cbBgColor.Items.AddRange($allColors); $commonTlp.Controls.Add($cbBgColor, 1, 1)
    $commonTlp.Controls.Add((New-Label "Cursor Size:"), 0, 2); $cbCursorSize = New-Object Windows.Forms.ComboBox; $cbCursorSize.DropDownStyle = 'DropDownList'; $cbCursorSize.Dock = 'Fill'; $cbCursorSize.Items.AddRange(@("Normal", "Small", "Large")); $commonTlp.Controls.Add($cbCursorSize, 1, 2)
    $commonTlp.Controls.Add((New-Label "Force Terminal Colors:"), 0, 3); $chkForceColors = New-Object Windows.Forms.CheckBox; $chkForceColors.Anchor = 'Left'; $commonTlp.Controls.Add($chkForceColors, 1, 3)
    $commonTlp.Controls.Add((New-Label "Send Keep-Alive:"), 0, 4); $chkKeepAlive = New-Object Windows.Forms.CheckBox; $chkKeepAlive.Anchor = 'Left'; $commonTlp.Controls.Add($chkKeepAlive, 1, 4)

    $commonTlp.Controls.Add((New-Label "Enable Logging:"), 0, 5); $chkBackgroundLogging = New-Object Windows.Forms.CheckBox; $chkBackgroundLogging.Anchor = 'Left'; $commonTlp.Controls.Add($chkBackgroundLogging, 1, 5)
    $commonTlp.Controls.Add((New-Label "Log File Path:"), 0, 6)
    $txtLogFilePath = New-Object Windows.Forms.TextBox; $txtLogFilePath.Dock = 'Fill'
    $commonTlp.Controls.Add($txtLogFilePath, 1, 6)
    $btnBrowseLog = New-Object Windows.Forms.Button; $btnBrowseLog.Text = "..."; $btnBrowseLog.AutoSize = $true
    $commonTlp.Controls.Add($btnBrowseLog, 2, 6)

    $commonTlp.Controls.Add((New-Label "Log Raw Stream Data:"), 0, 7); $chkRawLogData = New-Object Windows.Forms.CheckBox; $chkRawLogData.Anchor = 'Top'; $commonTlp.Controls.Add($chkRawLogData, 1, 7)
    $commonTlp.Controls.Add((New-Label "Obfuscate Passwords:"), 0, 8); $chkObfuscate = New-Object Windows.Forms.CheckBox; $chkObfuscate.Anchor = 'Top'; $commonTlp.Controls.Add($chkObfuscate, 1, 8)

    # --- Bottom Buttons (Row 2) ---
    $buttonsFlow = New-Object Windows.Forms.FlowLayoutPanel
    $buttonsFlow.Dock = 'Fill'
    $buttonsFlow.AutoSize = $true
    $buttonsFlow.FlowDirection = 'LeftToRight'
    $buttonsFlow.WrapContents = $false
    $buttonsFlow.Anchor = 'None'

    # Add it centered within the cell
    $mainLayout.Controls.Add($buttonsFlow, 0, 2); $mainLayout.SetColumnSpan($buttonsFlow, 2); $mainLayout.SetCellPosition($buttonsFlow, [System.Windows.Forms.TableLayoutPanelCellPosition]::new(0, 2)); $mainLayout.SetColumnSpan($buttonsFlow, 2)
    $buttonsFlow.Anchor = 'None'

    # Create buttons
    $btnConnect = New-Object Windows.Forms.Button
    $btnConnect.Text = "Connect"
    $btnConnect.DialogResult = [Windows.Forms.DialogResult]::OK
    $btnConnect.Width = 100; $btnConnect.Height = 30

    $btnCancel = New-Object Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.DialogResult = [Windows.Forms.DialogResult]::Cancel
    $btnCancel.Width = 100; $btnCancel.Height = 30
    $buttonsFlow.Controls.AddRange(@($btnCancel, $btnConnect))

    $btnAbout = New-Object Windows.Forms.Button
    $btnAbout.Text = "About"
    $btnAbout.Width = 100; $btnAbout.Height = 30
    $buttonsFlow.Controls.Add($btnAbout)

    # --- Event Handlers & Logic ---
    $currentPorts = @()
    $RefreshPortsAction = {
        param($forceUpdate = $false)
        $newPorts = [System.IO.Ports.SerialPort]::GetPortNames()
        if ($forceUpdate -or (Compare-Object $currentPorts $newPorts)) {
            $selectedPort = $cbPort.Text
            $cbPort.Items.Clear(); $cbPort.Items.AddRange($newPorts)
            if ($newPorts -contains $selectedPort) { $cbPort.Text = $selectedPort }
            elseif ($newPorts.Count -gt 0 -and $cbPort.IsHandleCreated) { $cbPort.SelectedIndex = 0 }
            $currentPorts = $newPorts
        }
    }
    $btnRefreshPorts.add_Click({ $RefreshPortsAction.Invoke($true) })
    $portRefreshTimer = New-Object System.Windows.Forms.Timer; $portRefreshTimer.Interval = 2000
    $portRefreshTimer.add_Tick({ $RefreshPortsAction.Invoke($false) })
    $form.add_Load({ $RefreshPortsAction.Invoke($true); $portRefreshTimer.Start() })
    $form.add_FormClosing({ $portRefreshTimer.Stop(); $portRefreshTimer.Dispose() })

    $UpdateFormForType = {
        $pnlSerial.Visible = $rbSerial.Checked
        $pnlSsh.Visible = $rbSsh.Checked
        $pnlTelnet.Visible = $rbTelnet.Checked
        $form.PerformLayout()
    }
    $rbSerial.add_CheckedChanged($UpdateFormForType)
    $rbSsh.add_CheckedChanged($UpdateFormForType)
    $rbTelnet.add_CheckedChanged($UpdateFormForType)

    $LoadProfileIntoForm = {
        param($profile)
        if (!$profile) { return }
        switch ($profile.Type) {
            "Serial" { $rbSerial.Checked = $true }
            "SSH"    { $rbSsh.Checked = $true }
            "Telnet" { $rbTelnet.Checked = $true }
        }
        $cbPort.Text = $profile.COMPort; $cbBaud.Text = $profile.BaudRate; $cbDataBits.Text = $profile.DataBits; $cbParity.Text = $profile.Parity; $cbStopBits.Text = $profile.StopBits; $cbHandshake.Text = $profile.Handshake; $chkDtrEnable.Checked = $profile.DtrEnable
        $txtSshHost.Text = $profile.Host; $txtSshUser.Text = $profile.User; $txtSshPort.Text = $profile.SshPort
        $txtTelnetHost.Text = $profile.Host; $txtTelnetPort.Text = $profile.TelnetPort
        $cbTextColor.Text = $profile.TextColor; $cbBgColor.Text = $profile.BackgroundColor; $cbCursorSize.Text = $profile.CursorSize
        $chkForceColors.Checked = $profile.ForceTerminalColors; $chkKeepAlive.Checked = $profile.KeepAlive
        $txtAutoInput.Text = $profile.AutoInput
        $chkBackgroundLogging.Checked = $profile.BackgroundLogging; $txtLogFilePath.Text = $profile.LogFilePath; $chkRawLogData.Checked = $profile.RawLogData; $chkObfuscate.Checked = $profile.ObfuscatePasswords
    }

    $cbProfiles.add_SelectedIndexChanged({ $LoadProfileIntoForm.Invoke((Import-Profile $cbProfiles.Text)) })
    $btnSaveProfile.add_Click({
        $profileName = $cbProfiles.Text
        if ([string]::IsNullOrWhiteSpace($profileName)) { [Windows.Forms.MessageBox]::Show("Please enter a profile name.", "Error", "OK", "Error"); return }
        $config = [PSCustomObject]@{
            Name = $profileName; Type = if ($rbSerial.Checked) { "Serial" } elseif ($rbSsh.Checked) { "SSH" } else { "Telnet" }
            COMPort = $cbPort.Text; BaudRate = $cbBaud.Text; DataBits = $cbDataBits.Text; Parity = $cbParity.Text; StopBits = $cbStopBits.Text; Handshake = $cbHandshake.Text; DtrEnable = $chkDtrEnable.Checked
            Host = if ($rbSsh.Checked) { $txtSshHost.Text } elseif ($rbTelnet.Checked) { $txtTelnetHost.Text } else { $txtSshHost.Text }
            User = $txtSshUser.Text; SshPort = $txtSshPort.Text; TelnetPort = $txtTelnetPort.Text
            TextColor = $cbTextColor.Text; BackgroundColor = $cbBgColor.Text; CursorSize = $cbCursorSize.Text
            ForceTerminalColors = $chkForceColors.Checked; KeepAlive = $chkKeepAlive.Checked; AutoInput = $txtAutoInput.Text
            BackgroundLogging = $chkBackgroundLogging.Checked; LogFilePath = $txtLogFilePath.Text; RawLogData = $chkRawLogData.Checked; ObfuscatePasswords = $chkObfuscate.Checked
        }
        Save-Profile $profileName $config
        [Windows.Forms.MessageBox]::Show("Profile '$profileName' saved.", "Success", "OK", "Information")
        $cbProfiles.Items.Clear(); $cbProfiles.Items.AddRange((Get-ProfileList)); $cbProfiles.Text = $profileName
    })
	$btnDeleteProfile.add_Click({
		$profileName = $cbProfiles.Text
		if ([string]::IsNullOrWhiteSpace($profileName)) { [Windows.Forms.MessageBox]::Show("Please select a profile to delete.", "Error", "OK", "Error"); return }
		$confirm = [Windows.Forms.MessageBox]::Show("Are you sure you want to delete profile '$profileName'?", "Confirm Delete", 'YesNo', 'Question')
		if ($confirm -eq 'Yes') {
			if ($ProfilesFile -and (Test-Path $ProfilesFile)) {
				$profiles = @(Get-Content -Raw -Path $ProfilesFile | ConvertFrom-Json)
				$profiles = $profiles | Where-Object { $_.Name -ne $profileName }
				$profiles | ConvertTo-Json -Depth 5 | Set-Content -Path $ProfilesFile -Encoding UTF8
			}
			$cbProfiles.Items.Remove($profileName); $cbProfiles.Text = ""
			[Windows.Forms.MessageBox]::Show("Profile '$profileName' deleted.", "Success", "OK", "Information")
		}
	})
    $btnBrowseLog.add_Click({
        $sfd = New-Object Windows.Forms.SaveFileDialog; $sfd.Filter = "Log Files (*.log)|*.log|All Files (*.*)|*.*"
        if ($sfd.ShowDialog() -eq "OK") { $txtLogFilePath.Text = $sfd.FileName }
    })

    $btnAbout.add_Click({
        $aboutForm = New-Object Windows.Forms.Form
        $aboutForm.Text = "About PSTerm"
        $aboutForm.FormBorderStyle = 'FixedDialog'
        $aboutForm.MaximizeBox = $false
        $aboutForm.MinimizeBox = $false
        $aboutForm.StartPosition = "CenterParent"
        $aboutForm.ClientSize = New-Object System.Drawing.Size(300, 200)

        $layout = New-Object Windows.Forms.TableLayoutPanel
        $layout.Dock = 'Fill'
        $aboutForm.Controls.Add($layout)

        $copyright = New-Object Windows.Forms.Label
        $copyright.Text = "PSTerm - A powerful native PowerShell Serial/SSH/Telnet Terminal.`nCopyright (C) 2025 Marlo K <Plays.xenon@yahoo.de>"
        $copyright.Dock = 'Fill'
        $layout.Controls.Add($copyright, 0, 0)

        $license = New-Object Windows.Forms.Label
        $license.Text = "This program comes with ABSOLUTELY NO WARRANTY."
        $license.Dock = 'Fill'
        $layout.Controls.Add($license, 0, 1)

        $license2 = New-Object Windows.Forms.Label
        $license2.Text = "This is free software, and you are welcome to redistribute it`nunder certain conditions. See the LICENSE file for details."
        $license2.Dock = 'Fill'
        $layout.Controls.Add($license2, 0, 2)

        $okButton = New-Object Windows.Forms.Button
        $okButton.Text = "OK"
        $okButton.DialogResult = [Windows.Forms.DialogResult]::OK
        $okButton.Anchor = 'None'
        $layout.Controls.Add($okButton, 0, 3)

        $aboutForm.ShowDialog($form) | Out-Null
    })

    # Initial load
    $LoadProfileIntoForm.Invoke((Import-Profile "Default-Serial")); $cbProfiles.Text = "Default-Serial"

    $form.Add_Shown({ $form.Activate() })
    $result = $form.ShowDialog()

    [int]$sshPort = 22; [int]::TryParse($txtSshPort.Text, [ref]$sshPort) | Out-Null
    [int]$telnetPort = 23; [int]::TryParse($txtTelnetPort.Text, [ref]$telnetPort) | Out-Null

    if ($result -eq [Windows.Forms.DialogResult]::OK) {
        $global:ConnectionConfig = [PSCustomObject]@{
            Name = $cbProfiles.Text; Type = if ($rbSerial.Checked) { "Serial" } elseif ($rbSsh.Checked) { "SSH" } else { "Telnet" }
            COMPort = $cbPort.Text; BaudRate = [int]$cbBaud.Text; DataBits = [int]$cbDataBits.Text; Parity = $cbParity.Text; StopBits = $cbStopBits.Text; Handshake = $cbHandshake.Text; DtrEnable = $chkDtrEnable.Checked
            Host = if ($rbSsh.Checked) { $txtSshHost.Text } elseif ($rbTelnet.Checked) { $txtTelnetHost.Text } else { "" }; User = $txtSshUser.Text; SshPort = $sshPort; TelnetPort = $telnetPort
            TextColor = $cbTextColor.Text; BackgroundColor = $cbBgColor.Text; CursorSize = $cbCursorSize.Text
            ForceTerminalColors = $chkForceColors.Checked; KeepAlive = $chkKeepAlive.Checked
            AutoInput = $txtAutoInput.Text.Replace("`r`n", "`n"); BackgroundLogging = $chkBackgroundLogging.Checked
            LogFilePath = $txtLogFilePath.Text; RawLogData = $chkRawLogData.Checked; ObfuscatePasswords = $chkObfuscate.Checked
        }
    }
    if ($consoleHandle -ne [IntPtr]::Zero) {
        [ConsoleUtils]::ShowWindow($consoleHandle, 5) # Show console
    }
    $form.Dispose()
    return $result
}

#endregion GUI Function

#region GUI Function (WPF)

function Show-ConnectionConfigMenu_WPF {
    param(
        [string]$ScriptBaseDir,
        [string]$ProfilesFile
    )

    $consoleHandle = [ConsoleUtils]::GetConsoleWindow()
    if ($consoleHandle -ne [IntPtr]::Zero) {
        [ConsoleUtils]::ShowWindow($consoleHandle, 0) # Hide console
    }

    try {
        $brushConverter = New-Object System.Windows.Media.BrushConverter

        $GetThemeColors = {
            param($dark)
            if ($dark) {
                return @{
                    WindowBackground = "#202020"
                    ControlBackground = "#2D2D2D"
                    TextColor = "#FFFFFF"
                    BorderColor = "#404040"
                    AccentColor = "#4CA3DD"
                    ControlHover = "#3A3A3A"
                    ToggleOff = "#505050"
                    ToggleDot = "#FFFFFF"
                }
            } else {
                return @{
                    WindowBackground = "#F3F3F3"
                    ControlBackground = "#FFFFFF"
                    TextColor = "#000000"
                    BorderColor = "#D0D0D0"
                    AccentColor = "#0078D4"
                    ControlHover = "#E0E0E0"
                    ToggleOff = "#808080"
                    ToggleDot = "#FFFFFF"
                }
            }
        }

        $DetectTheme = {
            $isDark = $true
            try {
                $regKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
                if (Test-Path $regKey) {
                    $val = Get-ItemProperty -Path $regKey -Name "AppsUseLightTheme" -ErrorAction SilentlyContinue
                    if ($val -and $val.AppsUseLightTheme -eq 1) { $isDark = $false }
                }
            } catch { }
            return $isDark
        }

        # Load XAML
        $xamlPath = Join-Path $ScriptBaseDir "ConnectionConfig.xaml"
        $xaml = [xml](Get-Content $xamlPath -Raw)
        $reader = New-Object System.Xml.XmlNodeReader($xaml)
        $window = [Windows.Markup.XamlReader]::Load($reader)

        # Initial Theme Apply
        $isDarkTheme = & $DetectTheme
        $colors = & $GetThemeColors $isDarkTheme
        foreach ($key in $colors.Keys) {
            try {
                $colorVal = $colors[$key]
                if (-not [string]::IsNullOrWhiteSpace($colorVal)) {
                    $brush = $brushConverter.ConvertFromString($colorVal.Trim())
                    if ($brush) { $window.Resources.Add($key, $brush) }
                }
            } catch { Write-Warning "Theme Error ($key): $_" }
        }

        # --- Live Theme Update Handler ---
        $themeChangedHandler = {
            param($sender, $e)
            if ($e.Category -eq 'General' -or $e.Category -eq 'Color') {
                $window.Dispatcher.Invoke({
                    $newIsDark = & $DetectTheme
                    $newColors = & $GetThemeColors $newIsDark
                    foreach ($k in $newColors.Keys) {
                        try {
                            $colorVal = $newColors[$k]
                            if (-not [string]::IsNullOrWhiteSpace($colorVal)) {
                                $b = $brushConverter.ConvertFromString($colorVal.Trim())
                                if ($b) {
                                    if ($window.Resources.Contains($k)) { $window.Resources[$k] = $b } 
                                    else { $window.Resources.Add($k, $b) }
                                }
                            }
                        } catch {}
                    }
                    # Update Title Bar
                    $ih = New-Object System.Windows.Interop.WindowInteropHelper($window)
                    $h = $ih.Handle
                    $dm = if ($newIsDark) { 1 } else { 0 }
                    [DwmUtils]::DwmSetWindowAttribute($h, 20, [ref]$dm, 4) | Out-Null
                })
            }
        }
        [Microsoft.Win32.SystemEvents]::add_UserPreferenceChanged($themeChangedHandler)
        $window.add_Closed({ [Microsoft.Win32.SystemEvents]::remove_UserPreferenceChanged($themeChangedHandler) })

        # --- Helper: Themed MessageBox ---
        $ShowMessageBox = {
            param($Title, $Message, $Button = "OK")
            
            $msgWindow = New-Object Windows.Window
            $msgWindow.Title = $Title
            $msgWindow.SizeToContent = 'WidthAndHeight'
            $msgWindow.WindowStartupLocation = 'CenterOwner'
            $msgWindow.Owner = $window
            $msgWindow.ResizeMode = 'NoResize'
            $msgWindow.Background = $window.Resources["WindowBackground"]
            $msgWindow.Foreground = $window.Resources["TextColor"]
            $msgWindow.FontFamily = $window.FontFamily
            $msgWindow.FontSize = 14
            
            # Copy resources (Styles)
            foreach ($key in $window.Resources.Keys) {
                if (-not $msgWindow.Resources.Contains($key)) {
                    $msgWindow.Resources.Add($key, $window.Resources[$key])
                }
            }

            $grid = New-Object Windows.Controls.Grid; $grid.Margin = 20
            $grid.RowDefinitions.Add((New-Object Windows.Controls.RowDefinition -Property @{Height='Auto'}))
            $grid.RowDefinitions.Add((New-Object Windows.Controls.RowDefinition -Property @{Height='Auto'}))
            $msgWindow.Content = $grid
            
            $txt = New-Object Windows.Controls.TextBlock
            $txt.Text = $Message
            $txt.Margin = "0,0,0,20"
            $txt.TextWrapping = 'Wrap'
            $txt.MaxWidth = 350
            $grid.Children.Add($txt); [Windows.Controls.Grid]::SetRow($txt, 0)
            
            $stack = New-Object Windows.Controls.StackPanel
            $stack.Orientation = 'Horizontal'
            $stack.HorizontalAlignment = 'Right'
            $grid.Children.Add($stack); [Windows.Controls.Grid]::SetRow($stack, 1)

            # Return state object to handle variable scoping in closures
            $state = @{ Result = 'Cancel' }

            if ($Button -eq 'YesNo') {
                 $btnYes = New-Object Windows.Controls.Button; $btnYes.Content = "Yes"; $btnYes.MinWidth=80; $btnYes.Margin="5"; $btnYes.IsDefault=$true
                 $btnYes.add_Click({ $state.Result = 'Yes'; $msgWindow.Close() })
                 $btnNo = New-Object Windows.Controls.Button; $btnNo.Content = "No"; $btnNo.MinWidth=80; $btnNo.Margin="5"; $btnNo.IsCancel=$true
                 $btnNo.add_Click({ $state.Result = 'No'; $msgWindow.Close() })
                 $stack.Children.Add($btnYes); $stack.Children.Add($btnNo)
            } else {
                 $btnOk = New-Object Windows.Controls.Button; $btnOk.Content = "OK"; $btnOk.MinWidth=80; $btnOk.Margin="5"; $btnOk.IsDefault=$true
                 $btnOk.add_Click({ $state.Result = 'OK'; $msgWindow.Close() })
                 $stack.Children.Add($btnOk)
            }
            
            # Apply Dark Mode Title Bar
            if ($isDarkTheme) {
                $interopHelper = New-Object System.Windows.Interop.WindowInteropHelper($msgWindow)
                $interopHelper.EnsureHandle()
                $h = $interopHelper.Handle
                $d = 1
                [DwmUtils]::DwmSetWindowAttribute($h, 20, [ref]$d, 4) | Out-Null
            }

            $msgWindow.ShowDialog() | Out-Null
            return $state.Result
        }

        # Set icon
        $window.TaskbarItemInfo = New-Object System.Windows.Shell.TaskbarItemInfo
        $window.TaskbarItemInfo.Overlay = [System.Windows.Media.Imaging.BitmapFrame]::Create([System.Uri](Join-Path $ScriptBaseDir "icon.ico"))
        $window.Icon = [System.Windows.Media.Imaging.BitmapFrame]::Create([System.Uri](Join-Path $ScriptBaseDir "icon.ico"))
        # Find controls
        $controls = @{}
        $window.FindName("cbLoadProfile") | ForEach-Object { $controls.cbLoadProfile = $_ }
        $window.FindName("txtNewProfileName") | ForEach-Object { $controls.txtNewProfileName = $_ }
        $window.FindName("btnSaveProfile") | ForEach-Object { $controls.btnSaveProfile = $_ }
        $window.FindName("btnDeleteProfile") | ForEach-Object { $controls.btnDeleteProfile = $_ }
        $window.FindName("rbSerial") | ForEach-Object { $controls.rbSerial = $_ }
        $window.FindName("rbSsh") | ForEach-Object { $controls.rbSsh = $_ }
        $window.FindName("rbTelnet") | ForEach-Object { $controls.rbTelnet = $_ }
        $window.FindName("pnlSerial") | ForEach-Object { $controls.pnlSerial = $_ }
        $window.FindName("pnlSsh") | ForEach-Object { $controls.pnlSsh = $_ }
        $window.FindName("pnlTelnet") | ForEach-Object { $controls.pnlTelnet = $_ }
        $window.FindName("cbPort") | ForEach-Object { $controls.cbPort = $_ }
        $window.FindName("btnRefreshPorts") | ForEach-Object { $controls.btnRefreshPorts = $_ }
        $window.FindName("cbBaud") | ForEach-Object { $controls.cbBaud = $_ }
        $window.FindName("cbDataBits") | ForEach-Object { $controls.cbDataBits = $_ }
        $window.FindName("cbParity") | ForEach-Object { $controls.cbParity = $_ }
        $window.FindName("cbStopBits") | ForEach-Object { $controls.cbStopBits = $_ }
        $window.FindName("cbHandshake") | ForEach-Object { $controls.cbHandshake = $_ }
        $window.FindName("chkDtrEnable") | ForEach-Object { $controls.chkDtrEnable = $_ }
        $window.FindName("txtSshHost") | ForEach-Object { $controls.txtSshHost = $_ }
        $window.FindName("txtSshUser") | ForEach-Object { $controls.txtSshUser = $_ }
        $window.FindName("txtSshPort") | ForEach-Object { $controls.txtSshPort = $_ }
        $window.FindName("txtTelnetHost") | ForEach-Object { $controls.txtTelnetHost = $_ }
        $window.FindName("txtTelnetPort") | ForEach-Object { $controls.txtTelnetPort = $_ }
        $window.FindName("txtAutoInput") | ForEach-Object { $controls.txtAutoInput = $_ }
        $window.FindName("cbTextColor") | ForEach-Object { $controls.cbTextColor = $_ }
        $window.FindName("cbBgColor") | ForEach-Object { $controls.cbBgColor = $_ }
        $window.FindName("cbCursorSize") | ForEach-Object { $controls.cbCursorSize = $_ }
        $window.FindName("chkForceColors") | ForEach-Object { $controls.chkForceColors = $_ }
        $window.FindName("chkKeepAlive") | ForEach-Object { $controls.chkKeepAlive = $_ }
        $window.FindName("chkBackgroundLogging") | ForEach-Object { $controls.chkBackgroundLogging = $_ }
        $window.FindName("txtLogFilePath") | ForEach-Object { $controls.txtLogFilePath = $_ }
        $window.FindName("btnBrowseLog") | ForEach-Object { $controls.btnBrowseLog = $_ }
        $window.FindName("chkRawLogData") | ForEach-Object { $controls.chkRawLogData = $_ }
        $window.FindName("chkObfuscate") | ForEach-Object { $controls.chkObfuscate = $_ }
        $window.FindName("btnConnect") | ForEach-Object { $controls.btnConnect = $_ }
        $window.FindName("btnCancel") | ForEach-Object { $controls.btnCancel = $_ }
        $window.FindName("btnAbout") | ForEach-Object { $controls.btnAbout = $_ }

        # --- Populate Controls ---
        $controls.cbLoadProfile.ItemsSource = Get-ProfileList
        $controls.cbBaud.ItemsSource = @(9600, 19200, 38400, 57600, 115200)
        $controls.cbDataBits.ItemsSource = @(8, 7)
        $controls.cbParity.ItemsSource = [enum]::GetNames([System.IO.Ports.Parity])
        $controls.cbStopBits.ItemsSource = [enum]::GetNames([System.IO.Ports.StopBits])
        $controls.cbHandshake.ItemsSource = [enum]::GetNames([System.IO.Ports.Handshake])
        $allColors = [System.Enum]::GetNames([System.ConsoleColor])
        $controls.cbTextColor.ItemsSource = $allColors
        $controls.cbBgColor.ItemsSource = $allColors
        $controls.cbCursorSize.ItemsSource = @("Normal", "Small", "Large")

        # --- Event Handlers & Logic ---

        $RefreshPortsAction = {
            param($forceUpdate = $false)
    
            $newPorts = [System.IO.Ports.SerialPort]::GetPortNames()
    
            # Check if an update is needed
            if ($forceUpdate -or (Compare-Object $controls.cbPort.ItemsSource $newPorts)) {
                $selectedPort = $controls.cbPort.SelectedItem
                $controls.cbPort.ItemsSource = $newPorts
        
                # Try to restore the previous selection
                if ($newPorts -contains $selectedPort) { 
                    $controls.cbPort.SelectedItem = $selectedPort 
                }
                # Condition 2: List is populated, default to first item
                elseif ($newPorts.Count -gt 0) { 
                    $controls.cbPort.SelectedIndex = 0 
                }
                # Condition 1: List is empty, show "None" placeholder
                else {
                    $controls.cbPort.SelectedItem = $null
                    $controls.cbPort.Text = "None"
                }
            }
        }

        $controls.btnRefreshPorts.add_Click({ $RefreshPortsAction.Invoke($true) })
        $RefreshPortsAction.Invoke($true)

        $UpdateFormForType = {
            $controls.pnlSerial.Visibility = if ($controls.rbSerial.IsChecked) { 'Visible' } else { 'Collapsed' }
            $controls.pnlSsh.Visibility = if ($controls.rbSsh.IsChecked) { 'Visible' } else { 'Collapsed' }
            $controls.pnlTelnet.Visibility = if ($controls.rbTelnet.IsChecked) { 'Visible' } else { 'Collapsed' }
        }
        $controls.rbSerial.add_Checked($UpdateFormForType); $controls.rbSerial.add_Unchecked($UpdateFormForType)
        $controls.rbSsh.add_Checked($UpdateFormForType); $controls.rbSsh.add_Unchecked($UpdateFormForType)
        $controls.rbTelnet.add_Checked($UpdateFormForType); $controls.rbTelnet.add_Unchecked($UpdateFormForType)

        $LoadProfileIntoForm = {
            param($profile)
            if (!$profile) { return }
            $controls.txtNewProfileName.Text = $profile.Name
            switch ($profile.Type) {
                "Serial" { $controls.rbSerial.IsChecked = $true }
                "SSH"    { $controls.rbSsh.IsChecked = $true }
                "Telnet" { $controls.rbTelnet.IsChecked = $true }
            }
            if ($controls.cbPort.ItemsSource -contains $profile.COMPort) {
                $controls.cbPort.SelectedItem = $profile.COMPort
            } elseif ($controls.cbPort.ItemsSource.Count -eq 0) {
                $controls.cbPort.SelectedItem = $null
                $controls.cbPort.Text = "None"
            }
            $controls.cbBaud.SelectedItem = $profile.BaudRate
            $controls.cbDataBits.SelectedItem = $profile.DataBits
            $controls.cbParity.SelectedItem = $profile.Parity
            $controls.cbStopBits.SelectedItem = $profile.StopBits
            $controls.cbHandshake.SelectedItem = $profile.Handshake
            $controls.chkDtrEnable.IsChecked = $profile.DtrEnable
            $controls.txtSshHost.Text = $profile.Host
            $controls.txtSshUser.Text = $profile.User
            $controls.txtSshPort.Text = $profile.SshPort
            $controls.txtTelnetHost.Text = $profile.Host
            $controls.txtTelnetPort.Text = $profile.TelnetPort
            $controls.cbTextColor.SelectedItem = $profile.TextColor
            $controls.cbBgColor.SelectedItem = $profile.BackgroundColor
            $controls.cbCursorSize.SelectedItem = $profile.CursorSize
            $controls.chkForceColors.IsChecked = $profile.ForceTerminalColors
            $controls.chkKeepAlive.IsChecked = $profile.KeepAlive
            $controls.txtAutoInput.Text = $profile.AutoInput
            $controls.chkBackgroundLogging.IsChecked = $profile.BackgroundLogging
            $controls.txtLogFilePath.Text = $profile.LogFilePath
            $controls.chkRawLogData.IsChecked = $profile.RawLogData
            $controls.chkObfuscate.IsChecked = $profile.ObfuscatePasswords
        }

        $controls.cbLoadProfile.add_SelectionChanged({
            if ($_.AddedItems.Count -gt 0) {
                $LoadProfileIntoForm.Invoke((Import-Profile $_.AddedItems[0]))
            }
        })

        $controls.btnSaveProfile.add_Click({
            $profileName = $controls.txtNewProfileName.Text
            if ([string]::IsNullOrWhiteSpace($profileName)) { $ShowMessageBox.Invoke("Error", "Please enter a profile name."); return }
            $config = [PSCustomObject]@{
                Name = $profileName; Type = if ($controls.rbSerial.IsChecked) { "Serial" } elseif ($controls.rbSsh.IsChecked) { "SSH" } else { "Telnet" }
                COMPort = $controls.cbPort.Text; BaudRate = $controls.cbBaud.Text; DataBits = $controls.cbDataBits.Text; Parity = $controls.cbParity.Text; StopBits = $controls.cbStopBits.Text; Handshake = $controls.cbHandshake.Text; DtrEnable = $controls.chkDtrEnable.IsChecked
                Host = if ($controls.rbSsh.IsChecked) { $controls.txtSshHost.Text } elseif ($controls.rbTelnet.IsChecked) { $controls.txtTelnetHost.Text } else { $controls.txtSshHost.Text }
                User = $controls.txtSshUser.Text; SshPort = $controls.txtSshPort.Text; TelnetPort = $controls.txtTelnetPort.Text
                TextColor = $controls.cbTextColor.Text; BackgroundColor = $controls.cbBgColor.Text; CursorSize = $controls.cbCursorSize.Text
                ForceTerminalColors = $controls.chkForceColors.IsChecked; KeepAlive = $controls.chkKeepAlive.IsChecked; AutoInput = $controls.txtAutoInput.Text
                BackgroundLogging = $controls.chkBackgroundLogging.IsChecked; LogFilePath = $controls.txtLogFilePath.Text; RawLogData = $controls.chkRawLogData.IsChecked; ObfuscatePasswords = $controls.chkObfuscate.IsChecked
            }
            Save-Profile $profileName $config
            $ShowMessageBox.Invoke("Success", "Profile '$profileName' saved.")
            $controls.cbLoadProfile.ItemsSource = Get-ProfileList
            $controls.cbLoadProfile.SelectedItem = $profileName
        })

        $controls.btnDeleteProfile.add_Click({
            $profileName = $controls.cbLoadProfile.SelectedItem
            if ([string]::IsNullOrWhiteSpace($profileName)) { $ShowMessageBox.Invoke("Error", "Please select a profile to delete from the list."); return }
            $confirm = $ShowMessageBox.Invoke("Confirm Delete", "Are you sure you want to delete profile '$profileName'?", 'YesNo')
            if ($confirm -eq 'Yes') {
                Remove-Profile $profileName
                $controls.cbLoadProfile.ItemsSource = Get-ProfileList
                $controls.cbLoadProfile.SelectedItem = $null
                $controls.txtNewProfileName.Text = ""
                $ShowMessageBox.Invoke("Success", "Profile '$profileName' deleted.")
            }
        })

        $controls.btnBrowseLog.add_Click({
            $sfd = New-Object Microsoft.Win32.SaveFileDialog; $sfd.Filter = "Log Files (*.log)|*.log|All Files (*.*)|*.*"
            if ($sfd.ShowDialog() -eq $true) { $controls.txtLogFilePath.Text = $sfd.FileName }
        })

        # Use closure state for dialog result to avoid nullable bool issues
        $configState = @{ Result = 'Cancel' }

        $controls.btnConnect.add_Click({ $configState.Result = 'OK'; $window.Close() })
        $controls.btnCancel.add_Click({ $configState.Result = 'Cancel'; $window.Close() })
        $controls.btnAbout.add_Click({
            $aboutWindow = New-Object Windows.Window
            $aboutWindow.Title = "About PSTerm"
            $aboutWindow.Width = 400
            $aboutWindow.Height = 320
            $aboutWindow.WindowStartupLocation = "CenterOwner"
            $aboutWindow.Owner = $window
            $aboutWindow.ResizeMode = 'NoResize'
            $aboutWindow.Background = $window.Resources["WindowBackground"]
            $aboutWindow.Foreground = $window.Resources["TextColor"]
            $aboutWindow.FontFamily = $window.FontFamily
            $aboutWindow.FontSize = 14

            # Inject Resources into About Window
            foreach ($key in $window.Resources.Keys) {
                if (-not $aboutWindow.Resources.Contains($key)) {
                    $aboutWindow.Resources.Add($key, $window.Resources[$key])
                }
            }

            $stackPanel = New-Object Windows.Controls.StackPanel
            $stackPanel.Margin = 10
            $aboutWindow.Content = $stackPanel

            $copyright = New-Object Windows.Controls.TextBlock
            $copyright.Text = "PSTerm - A powerful native PowerShell Serial/SSH/Telnet Terminal.`nCopyright (C) 2025 Marlo K <Plays.xenon@yahoo.de>"
            $copyright.Margin = "10"
            $copyright.TextWrapping = "Wrap"
            $stackPanel.Children.Add($copyright)

            $license = New-Object Windows.Controls.TextBlock
            $license.Text = "This program comes with ABSOLUTELY NO WARRANTY."
            $license.Margin = "10"
            $stackPanel.Children.Add($license)

            $license2 = New-Object Windows.Controls.TextBlock
            $license2.Text = "This is free software, and you are welcome to redistribute it`nunder certain conditions. See the LICENSE file for details."
            $license2.Margin = "10"
            $license2.TextWrapping = "Wrap"
            $stackPanel.Children.Add($license2)

            $okButton = New-Object Windows.Controls.Button
            $okButton.Content = "OK"
            $okButton.Width = 100
            $okButton.Margin = "10"
            $okButton.HorizontalAlignment = "Center"
            $okButton.Padding = "10,5"
            $okButton.add_Click({ $aboutWindow.Close() })
            $stackPanel.Children.Add($okButton)

            # Apply Dark Mode Title Bar
            if ($isDarkTheme) {
                $interopHelper = New-Object System.Windows.Interop.WindowInteropHelper($aboutWindow)
                $interopHelper.EnsureHandle()
                $h = $interopHelper.Handle
                $d = 1
                [DwmUtils]::DwmSetWindowAttribute($h, 20, [ref]$d, 4) | Out-Null
            }

            $aboutWindow.ShowDialog() | Out-Null
        })

        # Initial load
        $LoadProfileIntoForm.Invoke((Import-Profile "Default-Serial")); $controls.cbLoadProfile.SelectedItem = "Default-Serial"
        $UpdateFormForType.Invoke()

        # Set Dark Mode Title Bar for Main Window
        if ($isDarkTheme) {
            $interopHelper = New-Object System.Windows.Interop.WindowInteropHelper($window)
            $interopHelper.EnsureHandle()
            $handle = $interopHelper.Handle
            $darkMode = 1
            [DwmUtils]::DwmSetWindowAttribute($handle, 20, [ref]$darkMode, 4) | Out-Null
        }

        $window.ShowDialog() | Out-Null

        if ($configState.Result -eq 'OK') {
            try {
                [int]$sshPort = 22; [int]::TryParse($controls.txtSshPort.Text, [ref]$sshPort) | Out-Null
                [int]$telnetPort = 23; [int]::TryParse($controls.txtTelnetPort.Text, [ref]$telnetPort) | Out-Null
                $global:ConnectionConfig = [PSCustomObject]@{
                    Name = $controls.cbLoadProfile.SelectedItem; Type = if ($controls.rbSerial.IsChecked) { "Serial" } elseif ($controls.rbSsh.IsChecked) { "SSH" } else { "Telnet" }
                    COMPort = $controls.cbPort.Text; BaudRate = [int]$controls.cbBaud.SelectedItem; DataBits = [int]$controls.cbDataBits.SelectedItem; Parity = $controls.cbParity.SelectedItem; StopBits = $controls.cbStopBits.SelectedItem; Handshake = $controls.cbHandshake.SelectedItem; DtrEnable = $controls.chkDtrEnable.IsChecked
                    Host = if ($controls.rbSsh.IsChecked) { $controls.txtSshHost.Text } elseif ($controls.rbTelnet.IsChecked) { $controls.txtTelnetHost.Text } else { "" }; User = $controls.txtSshUser.Text; SshPort = $sshPort; TelnetPort = $telnetPort
                    TextColor = $controls.cbTextColor.SelectedItem; BackgroundColor = $controls.cbBgColor.SelectedItem; CursorSize = $controls.cbCursorSize.SelectedItem
                    ForceTerminalColors = $controls.chkForceColors.IsChecked; KeepAlive = $controls.chkKeepAlive.IsChecked
                    AutoInput = $controls.txtAutoInput.Text.Replace("`r`n", "`n"); BackgroundLogging = $controls.chkBackgroundLogging.IsChecked
                    LogFilePath = $controls.txtLogFilePath.Text; RawLogData = $controls.chkRawLogData.IsChecked; ObfuscatePasswords = $controls.chkObfuscate.IsChecked
                }
                return 'OK'
            } catch {
                $ShowMessageBox.Invoke("Error", "Failed to create connection configuration: $_")
            }
        }
        return 'Cancel'
    }
    finally {
        if ($consoleHandle -ne [IntPtr]::Zero) {
            [ConsoleUtils]::ShowWindow($consoleHandle, 5) # Show console
        }
    }
}

#endregion GUI Function (WPF)
