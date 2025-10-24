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
    [ConsoleUtils]::ShowWindow($consoleHandle, 0) # Hide console

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
    [ConsoleUtils]::ShowWindow($consoleHandle, 5) # Show console
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
    [ConsoleUtils]::ShowWindow($consoleHandle, 0) # Hide console

    try {
        # Load XAML
        $xamlPath = Join-Path $ScriptBaseDir "ConnectionConfig.xaml"
        $xaml = [xml](Get-Content $xamlPath -Raw)
        $reader = New-Object System.Xml.XmlNodeReader($xaml)
        $window = [Windows.Markup.XamlReader]::Load($reader)

        # Set icon
        $window.TaskbarItemInfo = New-Object System.Windows.Shell.TaskbarItemInfo
        $window.TaskbarItemInfo.Overlay = [System.Windows.Media.Imaging.BitmapFrame]::Create([System.Uri](Join-Path $ScriptBaseDir "src\icon.ico"))
        $window.Icon = [System.Windows.Media.Imaging.BitmapFrame]::Create([System.Uri](Join-Path $ScriptBaseDir "src\icon.ico"))
        # Find controls
        $controls = @{}
        $window.FindName("cbProfiles") | ForEach-Object { $controls.cbProfiles = $_ }
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
        $controls.cbProfiles.ItemsSource = Get-ProfileList
        $controls.cbBaud.ItemsSource = @("9600", "19200", "38400", "57600", "115200")
        $controls.cbDataBits.ItemsSource = @("8", "7")
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
            if ($forceUpdate -or (Compare-Object $controls.cbPort.ItemsSource $newPorts)) {
                $selectedPort = $controls.cbPort.SelectedItem
                $controls.cbPort.ItemsSource = $newPorts
                if ($newPorts -contains $selectedPort) { $controls.cbPort.SelectedItem = $selectedPort }
                elseif ($newPorts.Count -gt 0) { $controls.cbPort.SelectedIndex = 0 }
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
            switch ($profile.Type) {
                "Serial" { $controls.rbSerial.IsChecked = $true }
                "SSH"    { $controls.rbSsh.IsChecked = $true }
                "Telnet" { $controls.rbTelnet.IsChecked = $true }
            }
            $controls.cbPort.SelectedItem = $profile.COMPort
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

        $controls.cbProfiles.add_SelectionChanged({
            if ($_.AddedItems.Count -gt 0) {
                $LoadProfileIntoForm.Invoke((Import-Profile $_.AddedItems[0]))
            }
        })

        $controls.btnSaveProfile.add_Click({
            $profileName = $controls.cbProfiles.Text
            if ([string]::IsNullOrWhiteSpace($profileName)) { [Windows.MessageBox]::Show("Please enter a profile name.", "Error", "OK", "Error"); return }
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
            [Windows.MessageBox]::Show("Profile '$profileName' saved.", "Success", "OK", "Information")
            $controls.cbProfiles.ItemsSource = Get-ProfileList
            $controls.cbProfiles.Text = $profileName
        })

        $controls.btnDeleteProfile.add_Click({
            $profileName = $controls.cbProfiles.Text
            if ([string]::IsNullOrWhiteSpace($profileName)) { [Windows.MessageBox]::Show("Please select a profile to delete.", "Error", "OK", "Error"); return }
            $confirm = [Windows.MessageBox]::Show("Are you sure you want to delete profile '$profileName'?", "Confirm Delete", 'YesNo', 'Question')
            if ($confirm -eq 'Yes') {
                if ($ProfilesFile -and (Test-Path $ProfilesFile)) {
                    $profiles = @(Get-Content -Raw -Path $ProfilesFile | ConvertFrom-Json)
                    $profiles = $profiles | Where-Object { $_.Name -ne $profileName }
                    $profiles | ConvertTo-Json -Depth 5 | Set-Content -Path $ProfilesFile -Encoding UTF8
                }
                $controls.cbProfiles.ItemsSource = Get-ProfileList
                $controls.cbProfiles.Text = ""
                [Windows.MessageBox]::Show("Profile '$profileName' deleted.", "Success", "OK", "Information")
            }
        })

        $controls.btnBrowseLog.add_Click({
            $sfd = New-Object Microsoft.Win32.SaveFileDialog; $sfd.Filter = "Log Files (*.log)|*.log|All Files (*.*)|*.*"
            if ($sfd.ShowDialog() -eq $true) { $controls.txtLogFilePath.Text = $sfd.FileName }
        })

        $controls.btnConnect.add_Click({ $window.DialogResult = $true; $window.Close() })
        $controls.btnCancel.add_Click({ $window.DialogResult = $false; $window.Close() })
        $controls.btnAbout.add_Click({
            $aboutWindow = New-Object Windows.Window
            $aboutWindow.Title = "About PSTerm"
            $aboutWindow.Width = 400
            $aboutWindow.Height = 300
            $aboutWindow.WindowStartupLocation = "CenterOwner"
            $aboutWindow.Owner = $window

            $stackPanel = New-Object Windows.Controls.StackPanel
            $aboutWindow.Content = $stackPanel

            $copyright = New-Object Windows.Controls.TextBlock
            $copyright.Text = "PSTerm - A powerful native PowerShell Serial/SSH/Telnet Terminal.`nCopyright (C) 2025 Marlo K <Plays.xenon@yahoo.de>"
            $copyright.Margin = "10"
            $stackPanel.Children.Add($copyright)

            $license = New-Object Windows.Controls.TextBlock
            $license.Text = "This program comes with ABSOLUTELY NO WARRANTY."
            $license.Margin = "10"
            $stackPanel.Children.Add($license)

            $license2 = New-Object Windows.Controls.TextBlock
            $license2.Text = "This is free software, and you are welcome to redistribute it`nunder certain conditions. See the LICENSE file for details."
            $license2.Margin = "10"
            $stackPanel.Children.Add($license2)

            $okButton = New-Object Windows.Controls.Button
            $okButton.Content = "OK"
            $okButton.Width = 80
            $okButton.Margin = "10"
            $okButton.HorizontalAlignment = "Center"
            $okButton.add_Click({ $aboutWindow.Close() })
            $stackPanel.Children.Add($okButton)

            $aboutWindow.ShowDialog() | Out-Null
        })

        # Initial load
        $LoadProfileIntoForm.Invoke((Import-Profile "Default-Serial")); $controls.cbProfiles.SelectedItem = "Default-Serial"
        $UpdateFormForType.Invoke()

        $result = $window.ShowDialog()

        if ($result -eq $true) {
            [int]$sshPort = 22; [int]::TryParse($controls.txtSshPort.Text, [ref]$sshPort) | Out-Null
            [int]$telnetPort = 23; [int]::TryParse($controls.txtTelnetPort.Text, [ref]$telnetPort) | Out-Null
            $global:ConnectionConfig = [PSCustomObject]@{
                Name = $controls.cbProfiles.Text; Type = if ($controls.rbSerial.IsChecked) { "Serial" } elseif ($controls.rbSsh.IsChecked) { "SSH" } else { "Telnet" }
                COMPort = $controls.cbPort.Text; BaudRate = [int]$controls.cbBaud.Text; DataBits = [int]$controls.cbDataBits.Text; Parity = $controls.cbParity.Text; StopBits = $controls.cbStopBits.Text; Handshake = $controls.cbHandshake.Text; DtrEnable = $controls.chkDtrEnable.IsChecked
                Host = if ($controls.rbSsh.IsChecked) { $controls.txtSshHost.Text } elseif ($controls.rbTelnet.IsChecked) { $controls.txtTelnetHost.Text } else { "" }; User = $controls.txtSshUser.Text; SshPort = $sshPort; TelnetPort = $telnetPort
                TextColor = $controls.cbTextColor.Text; BackgroundColor = $controls.cbBgColor.Text; CursorSize = $controls.cbCursorSize.Text
                ForceTerminalColors = $controls.chkForceColors.IsChecked; KeepAlive = $controls.chkKeepAlive.IsChecked
                AutoInput = $controls.txtAutoInput.Text.Replace("`r`n", "`n"); BackgroundLogging = $controls.chkBackgroundLogging.IsChecked
                LogFilePath = $controls.txtLogFilePath.Text; RawLogData = $controls.chkRawLogData.IsChecked; ObfuscatePasswords = $controls.chkObfuscate.IsChecked
            }
            return 'OK'
        }
        return 'Cancel'
    }
    finally {
        [ConsoleUtils]::ShowWindow($consoleHandle, 5) # Show console
    }
}

#endregion GUI Function (WPF)
