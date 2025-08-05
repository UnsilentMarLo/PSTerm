#region Type and Profile Setup
# Load necessary assemblies for GUI and serial port
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic
# Fix: Replaced 'System.Net.Sockets' with 'System' for better compatibility on PS 5.x
Add-Type -AssemblyName System

# Use PInvoke to hide/show the console window for a cleaner GUI experience
Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;

    public class ConsoleUtils
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    }
"@

# Fix: Ensure $PSScriptRoot is defined, defaulting to the current directory
$ScriptBaseDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }

# Create a directory for connection profiles if it doesn't exist
$ProfilesDir = Join-Path $ScriptBaseDir "Profiles"
if (!(Test-Path $ProfilesDir)) { New-Item -ItemType Directory -Path $ProfilesDir | Out-Null }

# Consolidate profiles into a single file.
$ProfilesFile = Join-Path $ProfilesDir "profiles.json"
if (-not (Test-Path $ProfilesFile)) {
    Write-Host "Creating default profiles file."
    $defaultProfiles = @(
        @{
            Name              = "Default-Serial"
            Type              = "Serial"
            COMPort           = ""
            BaudRate          = 9600
            DataBits          = 8
            Parity            = "None"
            StopBits          = "One"
            Handshake         = "None"
            RTSEnable         = $false
            Host              = ""
            User              = ""
            SshPort           = 22
            TelnetPort        = 23
            TelnetNegotiation = "Active"
            TextColor         = "White"
            BackgroundColor   = "Black"
            CursorSize        = "Normal"
            AutoInput         = ""
            BackgroundLogging = $false
            LogFilePath       = ""
            RawLogData        = $false
            ObfuscatePasswords= $false
            KeepAlive         = $false
            
        },
        @{
            Name              = "Default-SSH"
            Type              = "SSH"
            COMPort           = ""
            BaudRate          = 9600
            DataBits          = 8
            Parity            = "None"
            StopBits          = "One"
            Handshake         = "None"
            RTSEnable         = $false
            Host              = ""
            User              = ""
            SshPort           = 22
            TelnetPort        = 23
            TelnetNegotiation = "Active"
            TextColor         = "White"
            BackgroundColor   = "Black"
            CursorSize        = "Normal"
            AutoInput         = ""
            BackgroundLogging = $false
            LogFilePath       = ""
            RawLogData        = $false
            ObfuscatePasswords= $false
            KeepAlive         = $false
        },
        @{
            Name              = "Default-Telnet"
            Type              = "Telnet"
            COMPort           = ""
            BaudRate          = 9600
            DataBits          = 8
            Parity            = "None"
            StopBits          = "One"
            Handshake         = "None"
            RTSEnable         = $false
            Host              = ""
            User              = ""
            SshPort           = 22
            TelnetPort        = 23
            TelnetNegotiation = "Active"
            TextColor         = "White"
            BackgroundColor   = "Black"
            CursorSize        = "Normal"
            AutoInput         = ""
            BackgroundLogging = $false
            LogFilePath       = ""
            RawLogData        = $false
            ObfuscatePasswords= $false
            KeepAlive         = $false
        }
    )
    $defaultProfiles | ConvertTo-Json -Depth 5 | Set-Content -Path $ProfilesFile -Encoding UTF8
}

#endregion Type and Profile Setup

#region Profile Management Functions

function Get-ProfileList {
    if ($ProfilesFile -and (Test-Path $ProfilesFile)) {
        $profiles = Get-Content $ProfilesFile | ConvertFrom-Json
        return $profiles | Select-Object -ExpandProperty Name
    }
    return @()
}

function Import-Profile($name) {
    if ($ProfilesFile -and (Test-Path $ProfilesFile)) {
        $profiles = Get-Content $ProfilesFile | ConvertFrom-Json
        return $profiles | Where-Object { $_.Name -eq $name }
    }
    return $null
}

function Save-Profile($name, $config) {
    $profiles = @()
    if ($ProfilesFile -and (Test-Path $ProfilesFile)) {
        $profiles = Get-Content $ProfilesFile | ConvertFrom-Json
    }

    $profiles = $profiles | Where-Object { $_.Name -ne $name }
    $config.Name = $name
    $profiles += $config

    $profiles | ConvertTo-Json -Depth 5 | Set-Content -Path $ProfilesFile -Encoding UTF8
}

#endregion Profile Management Functions

#region Session Handlers

function Start-SessionLogger {
    param(
        [string]$LogFilePath,
        [switch]$RawSessionData,
        [switch]$ObfuscatePasswords
    )
    Write-Warning "Background logging is not fully implemented in this version. Log output will be streamed to a file."
    return $null
}

function Stop-SessionLogger($job) {
    # No action needed as logging is handled in-line
}

function Start-SessionKeepAlive {
    param(
        [System.IO.Stream]$Stream,
        [int]$IntervalSeconds = 30
    )
    
    $job = Start-Job -ScriptBlock {
        param($Stream, $Interval)
        while ($true) {
            Start-Sleep -Seconds $Interval
            try { $Stream.Write([byte[]]@(0), 0, 1) } catch { break }
        }
    } -ArgumentList $Stream, $IntervalSeconds

    return $job
}

function Stop-SessionKeepAlive($job) {
    if ($job) {
        Stop-Job $job -Passthru | Remove-Job
    }
}

function Start-SerialSession {
    param(
        [System.IO.Ports.SerialPort]$Port,
        [string]$AutoInput,
        [switch]$KeepAlive,
        [string]$LogFilePath
    )

    [Console]::TreatControlCAsInput = $true
    if ($LogFilePath) { $logFile = New-Item -Path $LogFilePath -ItemType File -Force }

    $inputHelpers = [Collections.Generic.Dictionary[ConsoleKey, String]]::new()
    $inputHelpers.Add("UpArrow", "$([char]27)[A"); $inputHelpers.Add("DownArrow", "$([char]27)[B")
    $inputHelpers.Add("RightArrow", "$([char]27)[C"); $inputHelpers.Add("LeftArrow", "$([char]27)[D")
    $inputHelpers.Add("Delete", $([char]127)); $inputHelpers.Add("Backspace", $([char]8))
    $inputHelpers.Add("Home", "$([char]27)[H"); $inputHelpers.Add("End", "$([char]27)[F")
    $inputHelpers.Add("PageUp", "$([char]27)[5~"); $inputHelpers.Add("PageDown", "$([char]27)[6~")
    $inputHelpers.Add("Insert", "$([char]27)[2~")

    Write-Host "--- Serial Session Started. Press ESC in the console to exit. ---`n" -ForegroundColor Green
    
    if ($AutoInput) {
        Write-Host "Sending auto-input..." -ForegroundColor Cyan
        $AutoInput.Split("`n") | ForEach-Object { 
            $Port.WriteLine($_) 
            if ($logFile) { Add-Content -Path $logFile -Value $_ }
        }
    }
    
    $keepAliveJob = if ($KeepAlive) { Start-SessionKeepAlive -Stream $Port.BaseStream } else { $null }

    $job = Register-ObjectEvent -InputObject $port -EventName DataReceived -Action {
        $p = $event.MessageData
        $data = $p.ReadExisting()
        Write-Host $data -NoNewline
        if ($logFile) { Add-Content -Path $logFile -Value $data }
    } -MessageData $Port

    while ($true) {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq 'Escape') {
                Write-Host "`n--- Exiting serial session. ---" -ForegroundColor Yellow
                break
            }
            if ($inputHelpers.ContainsKey($key.Key)) {
                $port.Write($inputHelpers[$key.Key])
            }
            else {
                $port.Write($key.KeyChar)
            }
        }
        Start-Sleep -Milliseconds 10
    }

    if ($keepAliveJob) { Stop-SessionKeepAlive $keepAliveJob }
    Get-EventSubscriber -SourceIdentifier $job.Name | Unregister-Event
    $job | Remove-Job -Force
    [Console]::TreatControlCAsInput = $false
}

function Start-SshSession {
    param(
        [PSCustomObject]$Config
    )

    Write-Host "--- Starting SSH Session. Type 'exit' to return to PowerShell. ---`n" -ForegroundColor Green
    Write-Host "Note: You will be prompted for a password after connecting." -ForegroundColor Yellow

    try {
        $sshCommand = "ssh.exe"
        $sshArgs = @(
            "$($Config.User)@$($Config.Host)"
            "-p", "$($Config.SshPort)"
        )
        
        Start-Process -FilePath $sshCommand -ArgumentList $sshArgs -Wait -NoNewWindow
    }
    catch {
        Write-Error "Failed to start ssh.exe. Ensure OpenSSH Client for Windows is installed and in your PATH."
        Write-Error $_
    }
    
    Write-Host "`n--- SSH Session Closed. ---" -ForegroundColor Yellow
}

function Start-TelnetSession {
    param(
        [PSCustomObject]$Config
    )
    Write-Host "--- Telnet Session Started. Press ESC in the console to exit. ---`n" -ForegroundColor Green
    
    # ... [Telnet session logic] ...
    Write-Host "`n--- Telnet Session Closed. ---" -ForegroundColor Yellow
}

#endregion Session Handlers

#region GUI Function

function Show-ConnectionConfigMenu {
    $consoleHandle = [ConsoleUtils]::GetConsoleWindow()
    [ConsoleUtils]::ShowWindow($consoleHandle, 0)

    $form = New-Object Windows.Forms.Form
    $form.Text = "Connection Configuration"
    $form.Size = New-Object Drawing.Size(840, 840)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = 'FixedDialog'
    $form.AutoScroll = $true

    function Add-ControlPair {
        param($parent, $labelText, $yPos, [ref]$controlRef, $items = $null, $type = "ComboBox", $controlX = 150, $controlWidth = 250)
        $lbl = New-Object Windows.Forms.Label; $lbl.Text = $labelText; $lbl.Location = New-Object Drawing.Point(10, $yPos); $lbl.AutoSize = $true; $parent.Controls.Add($lbl)

        if ($type -eq "ComboBox") {
            $ctrl = New-Object Windows.Forms.ComboBox; $ctrl.DropDownStyle = 'DropDownList'
            if ($items) { $ctrl.Items.AddRange($items) }
        } elseif ($type -eq "CheckBox") {
            $ctrl = New-Object Windows.Forms.CheckBox; $ctrl.Text = ""
        } else {
            $ctrl = New-Object Windows.Forms.TextBox
        }
        $ctrl.Location = New-Object Drawing.Point($controlX, ($yPos - 3)); $ctrl.Size = New-Object Drawing.Size($controlWidth, 20); $parent.Controls.Add($ctrl)
        $controlRef.Value = $ctrl
    }

    $gbType = New-Object Windows.Forms.GroupBox; $gbType.Text = "Connection Type"; $gbType.Location = New-Object Drawing.Point(10, 10); $gbType.Size = New-Object Drawing.Size(800, 50); $form.Controls.Add($gbType)
    $rbSerial = New-Object Windows.Forms.RadioButton; $rbSerial.Text = "Serial"; $rbSerial.Location = New-Object Drawing.Point(20, 20); $gbType.Controls.Add($rbSerial)
    $rbSsh = New-Object Windows.Forms.RadioButton; $rbSsh.Text = "SSH"; $rbSsh.Location = New-Object Drawing.Point(220, 20); $gbType.Controls.Add($rbSsh)
    $rbTelnet = New-Object Windows.Forms.RadioButton; $rbTelnet.Text = "Telnet"; $rbTelnet.Location = New-Object Drawing.Point(420, 20); $gbType.Controls.Add($rbTelnet)

    $gbSerial = New-Object Windows.Forms.GroupBox; $gbSerial.Text = "Serial Settings"; $gbSerial.Location = New-Object Drawing.Point(10, 70); $gbSerial.Size = New-Object Drawing.Size(460, 250); $form.Controls.Add($gbSerial)
    $serialY = 25
    $cbPort = $null; Add-ControlPair $gbSerial "COM Port" $serialY ([ref]$cbPort)  $( $ports = [System.IO.Ports.SerialPort]::GetPortNames()
        if (-not $ports) { @("No Ports Found") } else { $ports }
    )
    $serialY += 30; $cbBaud = $null; Add-ControlPair $gbSerial "Baud Rate" $serialY ([ref]$cbBaud) @("9600","19200","38400","57600","115200")
    $serialY += 30; $cbDataBits = $null; Add-ControlPair $gbSerial "Data Bits" $serialY ([ref]$cbDataBits) @("8","7")
    $serialY += 30; $cbParity = $null; Add-ControlPair $gbSerial "Parity" $serialY ([ref]$cbParity) ([enum]::GetNames([System.IO.Ports.Parity]))
    $serialY += 30; $cbStopBits = $null; Add-ControlPair $gbSerial "Stop Bits" $serialY ([ref]$cbStopBits) ([enum]::GetNames([System.IO.Ports.StopBits]))
    $serialY += 30; $cbHandshake = $null; Add-ControlPair $gbSerial "Handshake" $serialY ([ref]$cbHandshake) ([enum]::GetNames([System.IO.Ports.Handshake]))
    $serialY += 30; $cbRtsEnable = $null; Add-ControlPair $gbSerial "RTS Enable" $serialY ([ref]$cbRtsEnable) @("False","True")
    
    $gbSsh = New-Object Windows.Forms.GroupBox; $gbSsh.Text = "SSH Settings"; $gbSsh.Location = New-Object Drawing.Point(10, 70); $gbSsh.Size = New-Object Drawing.Size(460, 250); $gbSsh.Visible = $false; $form.Controls.Add($gbSsh)
    $sshY = 25
    $txtSshHost = $null; Add-ControlPair $gbSsh "Host / IP" $sshY ([ref]$txtSshHost) $null "TextBox"
    $sshY += 30; $txtSshUser = $null; Add-ControlPair $gbSsh "Username" $sshY ([ref]$txtSshUser) $null "TextBox"
    $sshY += 30; $txtSshPort = $null; Add-ControlPair $gbSsh "Port" $sshY ([ref]$txtSshPort) $null "TextBox"
    $sshY += 30; $lblSshInfo = New-Object Windows.Forms.Label; $lblSshInfo.Text = "Note: The terminal will prompt for a password after connecting."; $lblSshInfo.Location = New-Object Drawing.Point(10, $sshY); $lblSshInfo.AutoSize = $true; $lblSshInfo.ForeColor = [System.Drawing.Color]::Gray; $gbSsh.Controls.Add($lblSshInfo)

    $gbTelnet = New-Object Windows.Forms.GroupBox; $gbTelnet.Text = "Telnet Settings"; $gbTelnet.Location = New-Object Drawing.Point(10, 70); $gbTelnet.Size = New-Object Drawing.Size(460, 250); $gbTelnet.Visible = $false; $form.Controls.Add($gbTelnet)
    $telnetY = 25
    $txtTelnetHost = $null; Add-ControlPair $gbTelnet "Host / IP" $telnetY ([ref]$txtTelnetHost) $null "TextBox"
    $telnetY += 30; $txtTelnetPort = $null; Add-ControlPair $gbTelnet "Port" $telnetY ([ref]$txtTelnetPort) $null "TextBox"
    $telnetY += 30; $cbTelnetNegotiation = $null; Add-ControlPair $gbTelnet "Negotiation" $telnetY ([ref]$cbTelnetNegotiation) @("Active","Passive")
    $telnetY += 30; $lblTelnetInfo = New-Object Windows.Forms.Label; $lblTelnetInfo.Text = "Negotiation: Active - sends first. Passive - waits for server."; $lblTelnetInfo.Location = New-Object Drawing.Point(10, $telnetY); $lblTelnetInfo.AutoSize = $true; $lblTelnetInfo.ForeColor = [System.Drawing.Color]::Gray; $gbTelnet.Controls.Add($lblTelnetInfo)

    $gbAppearance = New-Object Windows.Forms.GroupBox; $gbAppearance.Text = "Terminal Appearance"; $gbAppearance.Location = New-Object Drawing.Point(480, 70); $gbAppearance.Size = New-Object Drawing.Size(330, 250); $form.Controls.Add($gbAppearance)
    $appearY = 25
    $consoleColors = [enum]::GetNames([System.ConsoleColor])
    $cbTextColor = $null; Add-ControlPair $gbAppearance "Text Color" $appearY ([ref]$cbTextColor) $consoleColors -controlX 130 -controlWidth 180
    $appearY += 30; $cbBackgroundColor = $null; Add-ControlPair $gbAppearance "Background Color" $appearY ([ref]$cbBackgroundColor) $consoleColors -controlX 130 -controlWidth 180
    $appearY += 30; $cbCursorSize = $null; Add-ControlPair $gbAppearance "Cursor" $appearY ([ref]$cbCursorSize) @("Normal", "Block", "Underline") -controlX 130 -controlWidth 180

    $gbAdvanced = New-Object Windows.Forms.GroupBox; $gbAdvanced.Text = "Advanced Settings"; $gbAdvanced.Location = New-Object Drawing.Point(10, 330); $gbAdvanced.Size = New-Object Drawing.Size(800, 200); $form.Controls.Add($gbAdvanced)
    $advY = 25
    $cbLogging = $null; Add-ControlPair $gbAdvanced "Background Logging" $advY ([ref]$cbLogging) $null "CheckBox" -controlX 150
    $advY += 30; $txtLogFile = $null; Add-ControlPair $gbAdvanced "Log File Path" $advY ([ref]$txtLogFile) $null "TextBox" -controlX 150
    $advY += 30; $cbRawLog = $null; Add-ControlPair $gbAdvanced "Raw Session Data" $advY ([ref]$cbRawLog) $null "CheckBox" -controlX 150
    $advY += 30; $cbObfuscate = $null; Add-ControlPair $gbAdvanced "Obfuscate Passwords" $advY ([ref]$cbObfuscate) $null "CheckBox" -controlX 150
    $advY += 30; $cbKeepAlive = $null; Add-ControlPair $gbAdvanced "Keep-Alive" $advY ([ref]$cbKeepAlive) $null "CheckBox" -controlX 150
    $advY += 30; $lblLoggingInfo = New-Object Windows.Forms.Label; $lblLoggingInfo.Text = "Note: Log file saves all terminal output. Obfuscation is best-effort."; $lblLoggingInfo.Location = New-Object Drawing.Point(10, $advY); $lblLoggingInfo.AutoSize = $true; $lblLoggingInfo.ForeColor = [System.Drawing.Color]::Gray; $gbAdvanced.Controls.Add($lblLoggingInfo)

    $gbAutoInput = New-Object Windows.Forms.GroupBox; $gbAutoInput.Text = "Auto-Input on Connect (one command per line)"; $gbAutoInput.Location = New-Object Drawing.Point(10, 540); $gbAutoInput.Size = New-Object Drawing.Size(800, 100); $form.Controls.Add($gbAutoInput)
    $txtAutoInput = New-Object Windows.Forms.TextBox; $txtAutoInput.Multiline = $true; $txtAutoInput.Location = New-Object Drawing.Point(10, 20); $txtAutoInput.Size = New-Object Drawing.Size(780, 70); $gbAutoInput.Controls.Add($txtAutoInput)
    $lblAutoInputInfo = New-Object Windows.Forms.Label; $lblAutoInputInfo.Text = "Note: For non-sensitive commands like 'enable' or 'terminal length 0'."; $lblAutoInputInfo.Location = New-Object Drawing.Point(10, 595); $lblAutoInputInfo.AutoSize = $true; $lblAutoInputInfo.ForeColor = [System.Drawing.Color]::Gray; $form.Controls.Add($lblAutoInputInfo)

    $gbProfile = New-Object Windows.Forms.GroupBox; $gbProfile.Text = "Profiles"; $gbProfile.Location = New-Object Drawing.Point(10, 650); $gbProfile.Size = New-Object Drawing.Size(800, 70); $form.Controls.Add($gbProfile)
    $lblProfile = New-Object Windows.Forms.Label; $lblProfile.Text = "Load Profile"; $lblProfile.Location = New-Object Drawing.Point(10, 30); $lblProfile.AutoSize = $true; $gbProfile.Controls.Add($lblProfile)
    $cbProfile = New-Object Windows.Forms.ComboBox; $cbProfile.Location = New-Object Drawing.Point(90, 27); $cbProfile.Size = New-Object Drawing.Size(200, 20); $cbProfile.DropDownStyle = 'DropDownList'; $gbProfile.Controls.Add($cbProfile)
    $btnSave = New-Object Windows.Forms.Button; $btnSave.Text = "Save"; $btnSave.Location = New-Object Drawing.Point(300, 25); $gbProfile.Controls.Add($btnSave)
    $btnNew = New-Object Windows.Forms.Button; $btnNew.Text = "Save as New"; $btnNew.Location = New-Object Drawing.Point(385, 25); $btnNew.Size = New-Object Drawing.Size(100, 23); $gbProfile.Controls.Add($btnNew)

    $okButton = New-Object Windows.Forms.Button; $okButton.Text = "Connect"; $okButton.Location = New-Object Drawing.Point(540, 750); $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK; $form.AcceptButton = $okButton; $form.Controls.Add($okButton)
    $cancelButton = New-Object Windows.Forms.Button; $cancelButton.Text = "Cancel"; $cancelButton.Location = New-Object Drawing.Point(630, 750); $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; $form.Controls.Add($cancelButton)

    function Update-ProfileList {
        $current = $cbProfile.SelectedItem
        $cbProfile.Items.Clear()
        $cbProfile.Items.AddRange(@(Get-ProfileList))
        if ($current -and $cbProfile.Items.Contains($current)) {
            $cbProfile.SelectedItem = $current
        } elseif ($cbProfile.Items.Count -gt 0) {
            $cbProfile.SelectedIndex = 0
        }
    }

    function Load-ProfileIntoUI {
        param($profile)
        if (-not $profile) { return }

        if ([string]::IsNullOrEmpty($profile.TextColor) -or -not [System.Enum]::IsDefined([System.ConsoleColor], $profile.TextColor)) {
            $cbTextColor.SelectedItem = "White"
        } else {
            $cbTextColor.SelectedItem = $profile.TextColor
        }

        if ([string]::IsNullOrEmpty($profile.BackgroundColor) -or -not [System.Enum]::IsDefined([System.ConsoleColor], $profile.BackgroundColor)) {
            $cbBackgroundColor.SelectedItem = "Black"
        } else {
            $cbBackgroundColor.SelectedItem = $profile.BackgroundColor
        }
        
        $cbCursorSize.SelectedItem = $profile.CursorSize
        $txtAutoInput.Text = $profile.AutoInput
        $cbLogging.Checked = $profile.BackgroundLogging
        $txtLogFile.Text = $profile.LogFilePath
        $cbRawLog.Checked = $profile.RawLogData
        $cbObfuscate.Checked = $profile.ObfuscatePasswords
        $cbKeepAlive.Checked = $profile.KeepAlive

        $txtTelnetHost.Text = $profile.Host
        $txtTelnetPort.Text = $profile.TelnetPort
        $cbTelnetNegotiation.SelectedItem = $profile.TelnetNegotiation
        $txtSshHost.Text = $profile.Host
        $txtSshUser.Text = $profile.User
        $txtSshPort.Text = $profile.SshPort
        # if ($cbPort.Items.Contains($profile.COMPort)) { $cbPort.SelectedItem = $profile.COMPort } Comports are not persistent
        if ($profile.COMPort) {
            if ($cbPort.Items.Contains($profile.COMPort)) {
                $cbPort.SelectedItem = $profile.COMPort
            } else {
                # Handle case where saved COM port is no longer available
                Write-Host "Warning: Saved COM port '$($profile.COMPort)' not found. Please select a valid port." -ForegroundColor Yellow
                $cbPort.SelectedIndex = 0 # Clear selection
            }
        } else {
            $cbPort.SelectedIndex = 0 # Clear selection if no COM port in profile
        }
        $cbBaud.SelectedItem = "$($profile.BaudRate)"
        $cbDataBits.SelectedItem = "$($profile.DataBits)"
        $cbParity.SelectedItem = $profile.Parity
        $cbStopBits.SelectedItem = $profile.StopBits
        $cbHandshake.SelectedItem = $profile.Handshake
        $cbRtsEnable.SelectedItem = if ($profile.RTSEnable) {"True"} else {"False"}
                
        switch ($profile.Type) {
            "Serial" {
                $rbSerial.Checked = $true
            }
            "SSH" {
                $rbSsh.Checked = $true
            }
            "Telnet" {
                $rbTelnet.Checked = $true
            }
        }
    }

    $cbProfile.add_SelectedIndexChanged({ Load-ProfileIntoUI (Import-Profile $cbProfile.SelectedItem) })

    $btnSave.add_Click({
        if ($cbProfile.SelectedItem) {
            $config = @{
                TextColor = $cbTextColor.SelectedItem; BackgroundColor = $cbBackgroundColor.SelectedItem
                CursorSize = $cbCursorSize.SelectedItem
                AutoInput = $txtAutoInput.Text
                BackgroundLogging = $cbLogging.Checked; LogFilePath = $txtLogFile.Text
                RawLogData = $cbRawLog.Checked; ObfuscatePasswords = $cbObfuscate.Checked
                KeepAlive = $cbKeepAlive.Checked
            }
            if ($rbSerial.Checked) {
                $config.Type = "Serial"
                $config.COMPort = $cbPort.SelectedItem
                $config.BaudRate = [int]$cbBaud.SelectedItem
                $config.DataBits = [int]$cbDataBits.SelectedItem
                $config.Parity = $cbParity.SelectedItem
                $config.StopBits = $cbStopBits.SelectedItem
                $config.Handshake = $cbHandshake.SelectedItem
                $config.RTSEnable = [bool]::Parse($cbRtsEnable.SelectedItem)
            } elseif ($rbSsh.Checked) {
                $config.Type = "SSH"
                $config.Host = $txtSshHost.Text
                $config.User = $txtSshUser.Text
                $config.SshPort = [int]$txtSshPort.Text
            } elseif ($rbTelnet.Checked) {
                $config.Type = "Telnet"
                $config.Host = $txtTelnetHost.Text
                $config.TelnetPort = [int]$txtTelnetPort.Text
                $config.TelnetNegotiation = $cbTelnetNegotiation.SelectedItem
            }
            Save-Profile $cbProfile.SelectedItem $config
            [System.Windows.Forms.MessageBox]::Show("Profile '$($cbProfile.SelectedItem)' saved.", "Success") | Out-Null
        }
    })

    $btnNew.add_Click({
        $name = [Microsoft.VisualBasic.Interaction]::InputBox("Enter new profile name:", "New Profile")
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $config = @{
                TextColor = $cbTextColor.SelectedItem; BackgroundColor = $cbBackgroundColor.SelectedItem
                CursorSize = $cbCursorSize.SelectedItem
                AutoInput = $txtAutoInput.Text
                BackgroundLogging = $cbLogging.Checked; LogFilePath = $txtLogFile.Text
                RawLogData = $cbRawLog.Checked; ObfuscatePasswords = $cbObfuscate.Checked
                KeepAlive = $cbKeepAlive.Checked
            }
            if ($rbSerial.Checked) {
                $config.Type = "Serial"; $config.COMPort = $cbPort.SelectedItem; $config.BaudRate = [int]$cbBaud.SelectedItem
                $config.DataBits = [int]$cbDataBits.SelectedItem; $config.Parity = $cbParity.SelectedItem
                $config.StopBits = $cbStopBits.SelectedItem; $config.Handshake = $cbHandshake.SelectedItem
                $config.RTSEnable = [bool]::Parse($cbRtsEnable.SelectedItem)
            } elseif ($rbSsh.Checked) {
                $config.Type = "SSH"; $config.Host = $txtSshHost.Text; $config.User = $txtSshUser.Text; $config.SshPort = [int]$txtSshPort.Text
            } elseif ($rbTelnet.Checked) {
                $config.Type = "Telnet"; $config.Host = $txtTelnetHost.Text; $config.TelnetPort = [int]$txtTelnetPort.Text
                $config.TelnetNegotiation = $cbTelnetNegotiation.SelectedItem
            }
            Save-Profile $name $config
            Update-ProfileList
            $cbProfile.SelectedItem = $name
            [System.Windows.Forms.MessageBox]::Show("New profile '$name' created.", "Success") | Out-Null
        }
    })

    $rbSerial.add_CheckedChanged({ if ($rbSerial.Checked) { $gbSerial.Visible = $true; $gbSsh.Visible = $false; $gbTelnet.Visible = $false } })
    $rbSsh.add_CheckedChanged({ if ($rbSsh.Checked) { $gbSsh.Visible = $true; $gbSerial.Visible = $false; $gbTelnet.Visible = $false } })
    $rbTelnet.add_CheckedChanged({ if ($rbTelnet.Checked) { $gbTelnet.Visible = $true; $gbSerial.Visible = $false; $gbSsh.Visible = $false } })

    Update-ProfileList
    if ($cbProfile.Items.Count -gt 0) {
        $cbProfile.SelectedIndex = 0
        Load-ProfileIntoUI (Import-Profile $cbProfile.SelectedItem)
    } else {
        $rbSerial.Checked = $true
        $cbTextColor.SelectedItem = "White"; $cbBackgroundColor.SelectedItem = "Black"
    }

    if ($form.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $config = @{
            Success = $true # Erfolgreiche Konfiguration
            Type = if ($rbSerial.Checked) {"Serial"} elseif ($rbSsh.Checked) {"SSH"} else {"Telnet"}
            TextColor = $cbTextColor.SelectedItem; BackgroundColor = $cbBackgroundColor.SelectedItem
            CursorSize = $cbCursorSize.SelectedItem
            AutoInput = $txtAutoInput.Text
            BackgroundLogging = $cbLogging.Checked; LogFilePath = $txtLogFile.Text
            RawLogData = $cbRawLog.Checked; ObfuscatePasswords = $cbObfuscate.Checked
            KeepAlive = $cbKeepAlive.Checked
        }
        if ($rbSerial.Checked) {
            $config.COMPort = $cbPort.SelectedItem; $config.BaudRate = [int]$cbBaud.SelectedItem
            $config.DataBits = [int]$cbDataBits.SelectedItem; $config.Parity = $cbParity.SelectedItem
            $config.StopBits = $cbStopBits.SelectedItem; $config.Handshake = $cbHandshake.SelectedItem
            $config.RTSEnable = [bool]::Parse($cbRtsEnable.SelectedItem)
        } elseif ($rbSsh.Checked) {
            $config.Host = $txtSshHost.Text; $config.User = $txtSshUser.Text; $config.SshPort = [int]$txtSshPort.Text
        } elseif ($rbTelnet.Checked) {
            $config.Host = $txtTelnetHost.Text; $config.TelnetPort = [int]$txtTelnetPort.Text
            $config.TelnetNegotiation = $cbTelnetNegotiation.SelectedItem
        }
        [ConsoleUtils]::ShowWindow($consoleHandle, 1)
        return [PSCustomObject]$config
    }

    [ConsoleUtils]::ShowWindow($consoleHandle, 1)
    return $null
}

#endregion GUI Function

#region Main Execution Function

function New-Session {
    $originalColors = $Host.UI.RawUI
    $originalFg = $originalColors.ForegroundColor
    $originalBg = $originalColors.BackgroundColor

    try {
        $config = Show-ConnectionConfigMenu
        
        # $config wont ever be NULL we check for a custom variable instead.
        if (-not $config.Success) {
            Write-Host "Vorgang vom Benutzer abgebrochen. Skript wird beendet."
            exit
        }

        $textColorFromConfig = $config.TextColor
        if ([string]::IsNullOrEmpty($textColorFromConfig) -or -not [System.Enum]::IsDefined([System.ConsoleColor], $textColorFromConfig)) {
            $host.UI.RawUI.ForegroundColor = [System.ConsoleColor]::White
        } else {
            $host.UI.RawUI.ForegroundColor = [System.ConsoleColor]($textColorFromConfig)
        }

        $bgColorFromConfig = $config.BackgroundColor
        if ([string]::IsNullOrEmpty($bgColorFromConfig) -or -not [System.Enum]::IsDefined([System.ConsoleColor], $bgColorFromConfig)) {
            $host.UI.RawUI.BackgroundColor = [System.ConsoleColor]::Black
        } else {
            $host.UI.RawUI.BackgroundColor = [System.ConsoleColor]($bgColorFromConfig)
        }

        # check if CursorSize is valid
        $host.UI.RawUI.CursorSize = switch ($config.CursorSize) {
            "Normal" { 25 }
            "Block" { 100 }
            "Underline" { 10 }
            default { 25 }
        }

        # $host.UI.RawUI.Window.FontName = $config.TerminalFont
        # $host.UI.RawUI.Window.FontSize.Height = $config.TextSize
        # $host.UI.RawUI.Window.BufferSize.Width = if ($config.LineWrap) { $host.UI.RawUI.Window.BufferSize.Width } else { 10000 }
        Clear-Host

        switch ($config.Type) {
            "Serial" {
                $global:port = New-Object System.IO.Ports.SerialPort (
                    $config.COMPort, $config.BaudRate, $config.Parity, $config.DataBits, $config.StopBits
                )
                $port.Handshake = $config.Handshake
                $port.RtsEnable = $config.RTSEnable
                try {
                    $port.Open()
                } catch {
                    Write-Error "Failed to open serial port '$($config.COMPort)'."
                    throw
                }
                Start-SerialSession -Port $port -AutoInput $config.AutoInput -KeepAlive:$config.KeepAlive -LogFilePath $config.LogFilePath
                $port.Close(); $port.Dispose()
            }
            "SSH" {
                Start-SshSession -Config $config
            }
            "Telnet" {
                Start-TelnetSession -Config $config
            }
        }
    }
    finally {
        $Host.UI.RawUI.ForegroundColor = $originalFg
        $Host.UI.RawUI.BackgroundColor = $originalBg
        Clear-Host
    }
}

# Start the application
New-Session