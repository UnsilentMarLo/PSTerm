#region Type and Profile Setup
# Load necessary assemblies for GUI and serial port
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic
# Fix: Replaced 'System.Net.Sockets' with 'System' for better compatibility on PS 5.x
Add-Type -AssemblyName System
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

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

if ($MyInvocation.MyCommand.CommandType -eq "ExternalScript")
 { $ScriptBaseDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition }
 else
 { $ScriptBaseDir = Split-Path -Parent -Path ([Environment]::GetCommandLineArgs()[0]) 
     if (!$ScriptBaseDir){ $ScriptBaseDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location } } }

$currentPSEdition = $PSVersionTable.PSEdition
$currentCLRVersion = if ($PSVersionTable.CLRVersion) { $PSVersionTable.CLRVersion.ToString() }

Write-Host "Erkannte PowerShell-Edition: $currentPSEdition" -ForegroundColor Cyan
Write-Host "Erkannte CLR-Version: $currentCLRVersion" -ForegroundColor Cyan

if ($currentPSEdition -eq "Core") {
    if ($currentCLRVersion -and $currentCLRVersion.StartsWith("8.") -and (Test-Path (Join-Path $ScriptBaseDir "lib\net8.0"))) { Add-Type -Path (Join-Path $ScriptBaseDir "lib\net8.0\Renci.SshNet.dll") -ErrorAction Stop (Write-Host "net8.0")}
    if ($currentCLRVersion -and $currentCLRVersion.StartsWith("7.")) { Add-Type -Path (Join-Path $ScriptBaseDir "lib\net7.0\Renci.SshNet.dll") -ErrorAction Stop (Write-Host "net7.0")}
    if ($currentCLRVersion -and $currentCLRVersion.StartsWith("6.")) { Add-Type -Path (Join-Path $ScriptBaseDir "lib\net6.0\Renci.SshNet.dll") -ErrorAction Stop (Write-Host "net6.0")}
    else { Add-Type -Path (Join-Path $ScriptBaseDir "lib\netstandard2.1\Renci.SshNet.dll") -ErrorAction Stop (Write-Host "netstandard2.1")}
} else { # Desktop (Windows PowerShell)
    Add-Type -Path (Join-Path $ScriptBaseDir "lib\net462\Renci.SshNet.dll") -ErrorAction Stop
	Write-Host "net462"
}

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

    if ([string]::IsNullOrWhiteSpace($LogFilePath)) { return $null }

    try {
        $logDir = Split-Path -Path $LogFilePath -Parent
        if ($logDir -and (-not (Test-Path $logDir))) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        New-Item -Path $LogFilePath -ItemType File -Force | Out-Null
    }
    catch {
        Write-Error "Failed to create log file at '$LogFilePath'. Logging will be disabled. Error: $_"
        return $null
    }

    $logQueue = [System.Collections.Queue]::Synchronized( (New-Object System.Collections.Queue) )

    $logJob = Start-Job -ScriptBlock {
        param($path, $queue, $obfuscate, $raw)
        
        $passwordPromptDetected = $false
        # Regex to find password prompts. Case-insensitive.
        $passwordPromptRegex = 'password:|passphrase for|enter password'

        while ($true) {
            if ($queue.Count -gt 0) {
                $logEntry = $queue.Dequeue()
                if ($null -eq $logEntry) { continue }

                $dataToLog = $logEntry.Data
                
                # Obfuscation logic only runs if all three conditions are met
                if ($obfuscate -and $raw -and $logEntry.Source) {
                    if ($logEntry.Source -eq 'Server') {
                        # Check for password prompt from the server
                        if ($dataToLog -match $passwordPromptRegex) {
                            $passwordPromptDetected = $true
                        }
                        Add-Content -Path $path -Value $dataToLog -NoNewline
                    }
                    elseif ($logEntry.Source -eq 'User') {
                        if ($passwordPromptDetected) {
                            # Obfuscate the user's input.
                            $obfuscatedData = '*' * $dataToLog.Length
                            Add-Content -Path $path -Value $obfuscatedData -NoNewline
                            # If the input contains a newline, the password entry is over.
                            if ($dataToLog -match "[\r\n]") {
                                $passwordPromptDetected = $false
                            }
                        } else {
                            Add-Content -Path $path -Value $dataToLog -NoNewline
                        }
                    }
                }
                else {
                    # Standard logging if obfuscation is off
                    Add-Content -Path $path -Value $dataToLog -NoNewline
                }
            }
            else {
                Start-Sleep -Milliseconds 100
            }
        }
    } -ArgumentList $LogFilePath, $logQueue, $ObfuscatePasswords.IsPresent, $RawSessionData.IsPresent

    return [PSCustomObject]@{
        Job   = $logJob
        Queue = $logQueue
    }
}

function Stop-SessionLogger($Logger) {
    if ($Logger -and $Logger.Job) {
        Stop-Job $Logger.Job | Remove-Job -Force
    }
}

function Start-SessionKeepAlive {
    param(
        [System.IO.Stream]$Stream,
        [int]$IntervalSeconds = 30
    )
    
    $job = Start-Job -ScriptBlock {
        param($streamRef, $interval)
        # Reconstruct the stream object in the new runspace
        $stream = $streamRef.get_Value()
        while ($true) {
            Start-Sleep -Seconds $interval
            try { $stream.Write([byte[]]@(0), 0, 1) } catch { break } # Send a NULL byte
        }
    } -ArgumentList ([ref]$Stream), $IntervalSeconds

    return $job
}

function Stop-SessionKeepAlive($job) {
    if ($job) {
        Stop-Job $job -Passthru | Remove-Job -Force
    }
}

function Start-SerialSession {
    param(
        [System.IO.Ports.SerialPort]$Port,
        [PSCustomObject]$Config
    )

    [Console]::TreatControlCAsInput = $true
    $logger = $null
    $keepAliveJob = $null
    $receiveEvent = $null

    try {
        if ($Config.BackgroundLogging) {
            $logger = Start-SessionLogger -LogFilePath $Config.LogFilePath -RawSessionData:$Config.RawLogData -ObfuscatePasswords:$Config.ObfuscatePasswords
        }
        
        $inputHelpers = [Collections.Generic.Dictionary[ConsoleKey, String]]::new()
        $inputHelpers.Add("UpArrow", "$([char]27)[A"); $inputHelpers.Add("DownArrow", "$([char]27)[B")
        $inputHelpers.Add("RightArrow", "$([char]27)[C"); $inputHelpers.Add("LeftArrow", "$([char]27)[D")
        $inputHelpers.Add("Delete", $([char]127)); $inputHelpers.Add("Backspace", $([char]8))
        $inputHelpers.Add("Home", "$([char]27)[H"); $inputHelpers.Add("End", "$([char]27)[F")
        $inputHelpers.Add("PageUp", "$([char]27)[5~"); $inputHelpers.Add("PageDown", "$([char]27)[6~")
        $inputHelpers.Add("Insert", "$([char]27)[2~")

        Write-Host "--- Serial Session Started. Press ESC in the console to exit. ---`n" -ForegroundColor Green
        
        if ($Config.AutoInput) {
            Write-Host "Sending auto-input..." -ForegroundColor Cyan
            foreach ($line in $Config.AutoInput.Split("`n")) {
                $command = $line.Trim()
                $Port.WriteLine($command)
                if ($logger) { $logger.Queue.Enqueue([PSCustomObject]@{Source='User'; Data=($command + "`r`n")}) }
                Start-Sleep -Milliseconds 200
            }
        }
        
        if ($Config.KeepAlive) {
            $keepAliveJob = Start-SessionKeepAlive -Stream $Port.BaseStream
        }

        $receiveEvent = Register-ObjectEvent -InputObject $port -EventName DataReceived -Action {
            $p = $event.MessageData.Port
            $logQueue = $event.MessageData.LoggerQueue
            $data = $p.ReadExisting()
            Write-Host $data -NoNewline
            if ($logQueue) { $logQueue.Enqueue([PSCustomObject]@{Source='Server'; Data=$data}) }
        } -MessageData ([PSCustomObject]@{Port = $Port; LoggerQueue = $logger.Queue})

        while ($true) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq 'Escape') { break }
                
                $output = ""
                if ($inputHelpers.ContainsKey($key.Key)) {
                    $output = $inputHelpers[$key.Key]
                    $port.Write($output)
                }
                else {
                    $output = $key.KeyChar
                    $port.Write($output)
                }

                if ($logger -and $Config.RawLogData) { $logger.Queue.Enqueue([PSCustomObject]@{Source='User'; Data=$output}) }
            }
            Start-Sleep -Milliseconds 10
        }
    }
    finally {
        Write-Host "`n--- Exiting serial session. ---" -ForegroundColor Yellow
        if ($keepAliveJob) { Stop-SessionKeepAlive $keepAliveJob }
        if ($receiveEvent) {
            Get-EventSubscriber -SourceIdentifier $receiveEvent.Name | Unregister-Event
            $receiveEvent | Remove-Job -Force
        }
        if ($logger) { Stop-SessionLogger $logger }
        [Console]::TreatControlCAsInput = $false
    }
}

# --- MODIFIED FUNCTION ---
function Start-SshSession {
    param(
        [PSCustomObject]$Config
    )

    # Use SSH.NET for an integrated session with logging capabilities
    $client = $null
    $shellStream = $null
    $logger = $null
    $readerJob = $null
    $passwordPtr = [IntPtr]::Zero

    try {
        # Start the logger if configured
        if ($Config.BackgroundLogging) {
            $logger = Start-SessionLogger -LogFilePath $Config.LogFilePath -RawSessionData:$Config.RawLogData -ObfuscatePasswords:$Config.ObfuscatePasswords
        }

        # Prompt for password securely
        Write-Host "Connecting to $($Config.Host) on port $($Config.SshPort)..." -ForegroundColor Cyan
        $passwordSecure = Read-Host -Prompt "Password for $($Config.User)@$($Config.Host)" -AsSecureString

        # Convert SecureString to plain text for the library
        $passwordPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSecure)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($passwordPtr)

        # Set up authentication method
        $authMethod = New-Object Renci.SshNet.PasswordAuthenticationMethod($Config.User, $plainPassword)

        # Create and configure the SSH client
        $client = New-Object Renci.SshNet.SshClient($Config.Host, $Config.SshPort, $Config.User, $authMethod)
        
        # Configure keep-alive using the library's built-in feature
        if ($Config.KeepAlive) {
            $client.KeepAliveInterval = [TimeSpan]::FromSeconds(30)
        }

        # Connect to the server
        $client.Connect()

        # Create an interactive shell stream
        $termWidth = if ($Host.UI.RawUI.WindowSize.Width -gt 0) { $Host.UI.RawUI.WindowSize.Width } else { 80 }
        $termHeight = if ($Host.UI.RawUI.WindowSize.Height -gt 0) { $Host.UI.RawUI.WindowSize.Height } else { 24 }
        $shellStream = $client.CreateShellStream("xterm-256color", $termWidth, $termHeight, 0, 0, 1024)

        # Start a background job to read data from the server
        $readerJob = Start-Job -ScriptBlock {
            param($streamRef, $logQueueRef)
            $stream = $streamRef.get_Value()
            $logQueue = $logQueueRef.get_Value()
            $buffer = New-Object byte[] 4096
            $encoding = [System.Text.Encoding]::UTF8

            while ($stream.CanRead) {
                try {
                    if ($stream.DataAvailable) {
                        $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
                        if ($bytesRead -gt 0) {
                            $text = $encoding.GetString($buffer, 0, $bytesRead)
                            Write-Host $text -NoNewline
                            if ($logQueue) { $logQueue.Enqueue([PSCustomObject]@{Source='Server'; Data=$text}) }
                        }
                    } else {
                        Start-Sleep -Milliseconds 50
                    }
                } catch {
                    break
                }
            }
        } -ArgumentList ([ref]$shellStream), ([ref]$logger.Queue)

        [Console]::TreatControlCAsInput = $true
        
        $inputHelpers = [Collections.Generic.Dictionary[ConsoleKey, String]]::new()
        $inputHelpers.Add("UpArrow", "$([char]27)[A"); $inputHelpers.Add("DownArrow", "$([char]27)[B")
        $inputHelpers.Add("RightArrow", "$([char]27)[C"); $inputHelpers.Add("LeftArrow", "$([char]27)[D")
        $inputHelpers.Add("Delete", "$([char]27)[3~"); 
        $inputHelpers.Add("Backspace", $([char]127)) 
        $inputHelpers.Add("Home", "$([char]27)[H"); $inputHelpers.Add("End", "$([char]27)[F")
        $inputHelpers.Add("PageUp", "$([char]27)[5~"); $inputHelpers.Add("PageDown", "$([char]27)[6~")
        $inputHelpers.Add("Insert", "$([char]27)[2~")
        $inputHelpers.Add("Tab", "`t")

        Write-Host "`n--- SSH Session Started using SSH.NET. Press ESC in the console to exit. ---" -ForegroundColor Green
        
        # Wait for the initial banner/prompt before sending auto-input
        Start-Sleep -Milliseconds 500 

        # Handle Auto-Input right after connection
        if ($Config.AutoInput) {
            Write-Host "`nSending auto-input..." -ForegroundColor Cyan
            foreach ($line in $Config.AutoInput.Split("`n")) {
                $command = $line.Trim() + "`n"
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($command)
                $shellStream.Write($bytes, 0, $bytes.Length)
                $shellStream.Flush()
                if ($logger) { $logger.Queue.Enqueue([PSCustomObject]@{Source='User'; Data=$command}) }
                Start-Sleep -Milliseconds 200 # Wait a bit between commands
            }
        }

        # Main interactive loop
        while ($client.IsConnected -and $readerJob.State -in @('Running', 'NotStarted')) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq 'Escape') { break }

                $output = if ($inputHelpers.ContainsKey($key.Key)) { $inputHelpers[$key.Key] } else { $key.KeyChar }
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($output)
                $shellStream.Write($bytes, 0, $bytes.Length)
                $shellStream.Flush()
                if ($logger -and $Config.RawLogData) { $logger.Queue.Enqueue([PSCustomObject]@{Source='User'; Data=$output}) }
            }
            Start-Sleep -Milliseconds 20
        }
    }
    catch {
        Write-Error "SSH session failed: $($_.Exception.Message)"
        if ($_.Exception.InnerException) {
            Write-Error "Inner Exception: $($_.Exception.InnerException.Message)"
        }
    }
    finally {
        Write-Host "`n--- SSH Session Closed. ---" -ForegroundColor Yellow
        # Clean up resources
        if ($readerJob) { Stop-Job $readerJob | Remove-Job -Force }
        if ($logger) { Stop-SessionLogger $logger }
        if ($shellStream) { $shellStream.Dispose() }
        if ($client) { if ($client.IsConnected) { $client.Disconnect() }; $client.Dispose() }
        # Securely clear the password from memory
        if ($passwordPtr -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPtr) }
        [Console]::TreatControlCAsInput = $false
    }
}
# --- END MODIFIED FUNCTION ---

function Start-TelnetSession {
    param(
        [PSCustomObject]$Config
    )
    
    $client = New-Object System.Net.Sockets.TcpClient
    $logger = $null
    $keepAliveJob = $null
    $readerJob = $null
    
    try {
        Write-Host "Connecting to $($Config.Host) on port $($Config.TelnetPort)..." -ForegroundColor Cyan
        $client.Connect($Config.Host, $Config.TelnetPort)
        $stream = $client.GetStream()

        if ($Config.BackgroundLogging) {
            $logger = Start-SessionLogger -LogFilePath $Config.LogFilePath -RawSessionData:$Config.RawLogData -ObfuscatePasswords:$Config.ObfuscatePasswords
        }

        $readerJob = Start-Job -ScriptBlock {
            param($streamRef, $logQueueRef)
            $stream = $streamRef.get_Value()
            $logQueue = $logQueueRef.get_Value()
            $encoding = [System.Text.Encoding]::ASCII
            $buffer = New-Object byte[] 4096
            $IAC  = 255; $DONT = 254; $DO   = 253; $WONT = 252; $WILL = 251

            while ($stream.CanRead) {
                try {
                    $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
                    if ($bytesRead -eq 0) { break }

                    $outputBuffer = New-Object System.IO.MemoryStream
                    for ($i = 0; $i -lt $bytesRead; $i++) {
                        if ($buffer[$i] -eq $IAC) {
                            $command = $buffer[++$i]
                            $option = $buffer[++$i]
                            if ($command -eq $DO) { $stream.Write(@($IAC, $WONT, $option), 0, 3) }
                            elseif ($command -eq $WILL) { $stream.Write(@($IAC, $DONT, $option), 0, 3) }
                        } else {
                            $outputBuffer.WriteByte($buffer[$i])
                        }
                    }

                    if ($outputBuffer.Length -gt 0) {
                        $text = $encoding.GetString($outputBuffer.ToArray())
                        Write-Host $text -NoNewline
                        if ($logQueue) { $logQueue.Enqueue([PSCustomObject]@{Source='Server'; Data=$text}) }
                    }
                } catch { break }
            }
        } -ArgumentList ([ref]$stream), ([ref]$logger.Queue)

        [Console]::TreatControlCAsInput = $true
        
        $inputHelpers = [Collections.Generic.Dictionary[ConsoleKey, String]]::new()
        $inputHelpers.Add("UpArrow", "$([char]27)[A"); $inputHelpers.Add("DownArrow", "$([char]27)[B")
        $inputHelpers.Add("RightArrow", "$([char]27)[C"); $inputHelpers.Add("LeftArrow", "$([char]27)[D")
        $inputHelpers.Add("Delete", $([char]127)); $inputHelpers.Add("Backspace", $([char]8))
        $inputHelpers.Add("Home", "$([char]27)[H"); $inputHelpers.Add("End", "$([char]27)[F")
        $inputHelpers.Add("PageUp", "$([char]27)[5~"); $inputHelpers.Add("PageDown", "$([char]27)[6~")
        $inputHelpers.Add("Insert", "$([char]27)[2~")

        Write-Host "--- Telnet Session Started. Press ESC in the console to exit. ---`n" -ForegroundColor Green
        
        if ($Config.AutoInput) {
            Write-Host "Sending auto-input..." -ForegroundColor Cyan
            Start-Sleep -Seconds 1
            foreach ($line in $Config.AutoInput.Split("`n")) {
                $command = $line.Trim() + "`r`n"
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($command)
                $stream.Write($bytes, 0, $bytes.Length)
                if ($logger) { $logger.Queue.Enqueue([PSCustomObject]@{Source='User'; Data=$command}) }
                Start-Sleep -Milliseconds 200
            }
        }
        
        if ($Config.KeepAlive) {
            $keepAliveJob = Start-SessionKeepAlive -Stream $stream
        }
        
        while ($client.Connected -and $readerJob.State -in @('Running', 'NotStarted')) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq 'Escape') { break }

                $output = if ($inputHelpers.ContainsKey($key.Key)) { $inputHelpers[$key.Key] } else { $key.KeyChar }
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($output)
                $stream.Write($bytes, 0, $bytes.Length)
                if ($logger -and $Config.RawLogData) { $logger.Queue.Enqueue([PSCustomObject]@{Source='User'; Data=$output}) }
            }
            Start-Sleep -Milliseconds 20
        }
    }
    catch {
        Write-Error "Telnet session failed: $_"
    }
    finally {
        Write-Host "`n--- Telnet Session Closed. ---" -ForegroundColor Yellow
        if ($keepAliveJob) { Stop-SessionKeepAlive $keepAliveJob }
        if ($readerJob) { Stop-Job $readerJob | Remove-Job -Force }
        if ($logger) { Stop-SessionLogger $logger }
        if ($stream) { $stream.Close() }
        if ($client) { $client.Close() }
        [Console]::TreatControlCAsInput = $false
    }
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
    $cbPort = $null; Add-ControlPair $gbSerial "COM Port" $serialY ([ref]$cbPort) $( $ports = [System.IO.Ports.SerialPort]::GetPortNames()
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
    $sshY += 30; $lblSshInfo = New-Object Windows.Forms.Label; $lblSshInfo.Text = "Note: The terminal might prompt for a password after connecting."; $lblSshInfo.Location = New-Object Drawing.Point(10, $sshY); $lblSshInfo.AutoSize = $true; $lblSshInfo.ForeColor = [System.Drawing.Color]::Gray; $gbSsh.Controls.Add($lblSshInfo)

    $gbTelnet = New-Object Windows.Forms.GroupBox; $gbTelnet.Text = "Telnet Settings"; $gbTelnet.Location = New-Object Drawing.Point(10, 70); $gbTelnet.Size = New-Object Drawing.Size(460, 250); $gbTelnet.Visible = $false; $form.Controls.Add($gbTelnet)
    $telnetY = 25
    $txtTelnetHost = $null; Add-ControlPair $gbTelnet "Host / IP" $telnetY ([ref]$txtTelnetHost) $null "TextBox"
    $telnetY += 30; $txtTelnetPort = $null; Add-ControlPair $gbTelnet "Port" $telnetY ([ref]$txtTelnetPort) $null "TextBox"
    $telnetY += 30; $cbTelnetNegotiation = $null; Add-ControlPair $gbTelnet "Negotiation" $telnetY ([ref]$cbTelnetNegotiation) @("Active","Passive")
    $telnetY += 30; $lblTelnetInfo = New-Object Windows.Forms.Label; $lblTelnetInfo.Text = "Note: Native implementation uses basic 'refuse-all' negotiation."; $lblTelnetInfo.Location = New-Object Drawing.Point(10, $telnetY); $lblTelnetInfo.AutoSize = $true; $lblTelnetInfo.ForeColor = [System.Drawing.Color]::Gray; $gbTelnet.Controls.Add($lblTelnetInfo)

    $gbAppearance = New-Object Windows.Forms.GroupBox; $gbAppearance.Text = "Terminal Appearance"; $gbAppearance.Location = New-Object Drawing.Point(480, 70); $gbAppearance.Size = New-Object Drawing.Size(330, 250); $form.Controls.Add($gbAppearance)
    $appearY = 25
    $consoleColors = [enum]::GetNames([System.ConsoleColor])
    $cbTextColor = $null; Add-ControlPair $gbAppearance "Text Color" $appearY ([ref]$cbTextColor) $consoleColors -controlX 135 -controlWidth 180
    $appearY += 30; $cbBackgroundColor = $null; Add-ControlPair $gbAppearance "Background Color" $appearY ([ref]$cbBackgroundColor) $consoleColors -controlX 135 -controlWidth 180
    $appearY += 30; $cbCursorSize = $null; Add-ControlPair $gbAppearance "Cursor" $appearY ([ref]$cbCursorSize) @("Normal", "Block", "Underline") -controlX 135 -controlWidth 180

    $gbAdvanced = New-Object Windows.Forms.GroupBox; $gbAdvanced.Text = "Advanced Settings"; $gbAdvanced.Location = New-Object Drawing.Point(10, 330); $gbAdvanced.Size = New-Object Drawing.Size(800, 200); $form.Controls.Add($gbAdvanced)
    $advY = 25
    $cbLogging = $null; Add-ControlPair $gbAdvanced "Background Logging" $advY ([ref]$cbLogging) $null "CheckBox" -controlX 160
    $advY += 30; $txtLogFile = $null; Add-ControlPair $gbAdvanced "Log File Path" $advY ([ref]$txtLogFile) $null "TextBox" -controlX 160
    $advY += 30; $cbRawLog = $null; Add-ControlPair $gbAdvanced "Raw Session Data" $advY ([ref]$cbRawLog) $null "CheckBox" -controlX 160
    $advY += 30; $cbObfuscate = $null; Add-ControlPair $gbAdvanced "Obfuscate Passwords" $advY ([ref]$cbObfuscate) $null "CheckBox" -controlX 160
    $advY += 30; $cbKeepAlive = $null; Add-ControlPair $gbAdvanced "Keep-Alive" $advY ([ref]$cbKeepAlive) $null "CheckBox" -controlX 160
    $advY += 30; $lblLoggingInfo = New-Object Windows.Forms.Label

    $lblLoggingInfo.Text = "Note: Obfuscation requires Raw Session Data." # Removed SSH warning
    $lblLoggingInfo.Location = New-Object Drawing.Point(10, $advY); $lblLoggingInfo.AutoSize = $true; $lblLoggingInfo.ForeColor = [System.Drawing.Color]::Gray; $gbAdvanced.Controls.Add($lblLoggingInfo)

    $gbAutoInput = New-Object Windows.Forms.GroupBox; $gbAutoInput.Text = "Auto-Input on Connect (one command per line)"; $gbAutoInput.Location = New-Object Drawing.Point(10, 540); $gbAutoInput.Size = New-Object Drawing.Size(800, 100); $form.Controls.Add($gbAutoInput)
    $txtAutoInput = New-Object Windows.Forms.TextBox; $txtAutoInput.Multiline = $true; $txtAutoInput.Location = New-Object Drawing.Point(10, 20); $txtAutoInput.Size = New-Object Drawing.Size(780, 70); $gbAutoInput.Controls.Add($txtAutoInput)

    $gbProfile = New-Object Windows.Forms.GroupBox; $gbProfile.Text = "Profiles"; $gbProfile.Location = New-Object Drawing.Point(10, 650); $gbProfile.Size = New-Object Drawing.Size(800, 70); $form.Controls.Add($gbProfile)
    $lblProfile = New-Object Windows.Forms.Label; $lblProfile.Text = "Load Profile"; $lblProfile.Location = New-Object Drawing.Point(10, 30); $lblProfile.AutoSize = $true; $gbProfile.Controls.Add($lblProfile)
    $cbProfile = New-Object Windows.Forms.ComboBox; $cbProfile.Location = New-Object Drawing.Point(100, 27); $cbProfile.Size = New-Object Drawing.Size(180, 21); $cbProfile.DropDownStyle = 'DropDownList'; $gbProfile.Controls.Add($cbProfile)
    $btnSaveProfile = New-Object Windows.Forms.Button; $btnSaveProfile.Text = "Save Profile"; $btnSaveProfile.Location = New-Object Drawing.Point(300, 25); $gbProfile.Controls.Add($btnSaveProfile)

    $btnConnect = New-Object Windows.Forms.Button; $btnConnect.Text = "Connect"; $btnConnect.Location = New-Object Drawing.Point(350, 730); $btnConnect.DialogResult = [Windows.Forms.DialogResult]::OK; $form.Controls.Add($btnConnect)

    # --- GUI Logic ---

    $updateControlsVisibility = {
        $isSerial = $rbSerial.Checked
        $isSsh = $rbSsh.Checked
        $isTelnet = $rbTelnet.Checked
        $gbSerial.Visible = $isSerial
        $gbSsh.Visible = $isSsh
        $gbTelnet.Visible = $isTelnet
        $gbAdvanced.Visible = $true
        # Logging and KeepAlive are available for all connection types with the new SSH implementation.
        $cbLogging.Enabled = $true
        $txtLogFile.Enabled = $cbLogging.Checked
        $cbRawLog.Enabled = $cbLogging.Checked
        $cbObfuscate.Enabled = $cbLogging.Checked -and $cbRawLog.Checked
        $cbKeepAlive.Enabled = $true
    }

    $loadProfile = {
        param($profileName)
        $profile = Import-Profile $profileName
        if ($profile) {
            $type = $profile.Type
            if ($type -eq "Serial") { $rbSerial.Checked = $true }
            elseif ($type -eq "SSH") { $rbSsh.Checked = $true }
            elseif ($type -eq "Telnet") { $rbTelnet.Checked = $true }

            # $cbPort.Text = $profile.COMPort
            if ($profile.COMPort) {
                if ($cbPort.Items.Contains($profile.COMPort)) {
                    $cbPort.SelectedItem = $profile.COMPort
                } else {
                    # Handle case where saved COM port is no longer available
                    $cbPort.SelectedIndex = 0 # Clear selection
                }
            } else {
                $cbPort.SelectedIndex = 0 # Clear selection if no COM port in profile
            }

            $cbBaud.Text = $profile.BaudRate
            $cbDataBits.Text = $profile.DataBits
            $cbParity.Text = $profile.Parity
            $cbStopBits.Text = $profile.StopBits
            $cbHandshake.Text = $profile.Handshake
            $cbRtsEnable.Text = $profile.RTSEnable.ToString()

            $txtSshHost.Text = $profile.Host
            $txtSshUser.Text = $profile.User
            $txtSshPort.Text = $profile.SshPort

            $txtTelnetHost.Text = $profile.Host
            $txtTelnetPort.Text = $profile.TelnetPort
            $cbTelnetNegotiation.Text = $profile.TelnetNegotiation

            $cbTextColor.Text = $profile.TextColor
            $cbBackgroundColor.Text = $profile.BackgroundColor
            $cbCursorSize.Text = $profile.CursorSize

            $cbLogging.Checked = $profile.BackgroundLogging
            $txtLogFile.Text = $profile.LogFilePath
            $cbRawLog.Checked = $profile.RawLogData
            $cbObfuscate.Checked = $profile.ObfuscatePasswords
            $cbKeepAlive.Checked = $profile.KeepAlive
            
            $txtAutoInput.Text = $profile.AutoInput
            
            $updateControlsVisibility.Invoke()
        }
    }

    $rbSerial.add_CheckedChanged($updateControlsVisibility)
    $rbSsh.add_CheckedChanged($updateControlsVisibility)
    $rbTelnet.add_CheckedChanged($updateControlsVisibility)
    $cbLogging.add_CheckedChanged({ $txtLogFile.Enabled = $cbLogging.Checked; $cbRawLog.Enabled = $cbLogging.Checked; $cbObfuscate.Enabled = ($cbLogging.Checked -and $cbRawLog.Checked) })
    $cbRawLog.add_CheckedChanged({ $cbObfuscate.Enabled = ($cbLogging.Checked -and $cbRawLog.Checked) })

    $current = $cbProfile.SelectedItem
    $cbProfile.Items.AddRange((Get-ProfileList))
    if ($current -and $cbProfile.Items.Contains($current)) {
        $cbProfile.SelectedItem = $current
    } elseif ($cbProfile.Items.Count -gt 0) {
        $cbProfile.SelectedIndex = 0
    }
    $cbProfile.add_SelectedIndexChanged({ $loadProfile.Invoke($cbProfile.SelectedItem) })

    $btnSaveProfile.add_Click({
        $profileName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter a name for this profile:", "Save Profile", $cbProfile.Text)
        if (![string]::IsNullOrWhiteSpace($profileName)) {
            $config = @{
                Type              = if($rbSerial.Checked) { "Serial" } elseif($rbSsh.Checked) { "SSH" } else { "Telnet" }
                COMPort           = $cbPort.Text
                BaudRate          = [int]$cbBaud.Text
                DataBits          = [int]$cbDataBits.Text
                Parity            = $cbParity.Text
                StopBits          = $cbStopBits.Text
                Handshake         = $cbHandshake.Text
                RTSEnable         = [bool]::Parse($cbRtsEnable.Text)
                Host              = if ($rbSsh.Checked) { $txtSshHost.Text } else { $txtTelnetHost.Text }
                User              = $txtSshUser.Text
                SshPort           = [int]$txtSshPort.Text
                TelnetPort        = [int]$txtTelnetPort.Text
                TelnetNegotiation = $cbTelnetNegotiation.Text
                TextColor         = $cbTextColor.Text
                BackgroundColor   = $cbBackgroundColor.Text
                CursorSize        = $cbCursorSize.Text
                AutoInput         = $txtAutoInput.Text
                BackgroundLogging = $cbLogging.Checked
                LogFilePath       = $txtLogFile.Text
                RawLogData        = $cbRawLog.Checked
                ObfuscatePasswords= $cbObfuscate.Checked
                KeepAlive         = $cbKeepAlive.Checked
            }
            Save-Profile $profileName $config
            $cbProfile.Items.Clear()
            $cbProfile.Items.AddRange((Get-ProfileList))
            $cbProfile.SelectedItem = $profileName
            [Windows.Forms.MessageBox]::Show("Profile '$profileName' saved.", "Success")
        }
    })

    $form.add_Load({ $loadProfile.Invoke("Default-Serial") })
    $result = $form.ShowDialog()

    [ConsoleUtils]::ShowWindow($consoleHandle, 5)

    if ($result -eq [Windows.Forms.DialogResult]::OK) {
        $global:ConnectionConfig = [PSCustomObject]@{
            Type              = if($rbSerial.Checked) { "Serial" } elseif($rbSsh.Checked) { "SSH" } else { "Telnet" }
            COMPort           = $cbPort.Text
            BaudRate          = [int]$cbBaud.Text
            DataBits          = [int]$cbDataBits.Text
            Parity            = $cbParity.Text
            StopBits          = $cbStopBits.Text
            Handshake         = $cbHandshake.Text
            RTSEnable         = [bool]::Parse($cbRtsEnable.Text)
            Host              = if ($rbSsh.Checked) { $txtSshHost.Text } elseif($rbTelnet.Checked) { $txtTelnetHost.Text } else { "" }
            User              = $txtSshUser.Text
            SshPort           = [int]$txtSshPort.Text
            TelnetPort        = [int]$txtTelnetPort.Text
            TelnetNegotiation = $cbTelnetNegotiation.Text
            TextColor         = $cbTextColor.Text
            BackgroundColor   = $cbBackgroundColor.Text
            CursorSize        = $cbCursorSize.Text
            AutoInput         = $txtAutoInput.Text
            BackgroundLogging = $cbLogging.Checked
            LogFilePath       = $txtLogFile.Text
            RawLogData        = $cbRawLog.Checked
            ObfuscatePasswords= $cbObfuscate.Checked
            KeepAlive         = $cbKeepAlive.Checked
        }
    }
    $form.Dispose()
}

#endregion GUI Function

# --- Main Execution Logic ---

Show-ConnectionConfigMenu

if ($global:ConnectionConfig) {
    # Apply appearance settings
    $Host.UI.RawUI.ForegroundColor = $global:ConnectionConfig.TextColor
    $Host.UI.RawUI.BackgroundColor = $global:ConnectionConfig.BackgroundColor
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        switch ($global:ConnectionConfig.CursorSize) {
            "Block" { $Host.UI.RawUI.CursorSize = 100 }
            "Underline" { $Host.UI.RawUI.CursorSize = 15 }
            default { $Host.UI.RawUI.CursorSize = 25 }
        }
    }
    Clear-Host

    $Config = $global:ConnectionConfig
    try {
        if ($Config.Type -eq "Serial") {
            $port = New-Object System.IO.Ports.SerialPort
            $port.PortName = $Config.COMPort
            $port.BaudRate = $Config.BaudRate
            $port.DataBits = $Config.DataBits
            $port.Parity = $Config.Parity
            $port.StopBits = $Config.StopBits
            $port.Handshake = $Config.Handshake
            $port.RtsEnable = $Config.RTSEnable
            $port.Open()
            Start-SerialSession -Port $port -Config $Config
            if ($port.IsOpen) { $port.Close() }
        }
        elseif ($Config.Type -eq "SSH") {
            Start-SshSession -Config $Config
        }
        elseif ($Config.Type -eq "Telnet") {
            Start-TelnetSession -Config $Config
        }
    }
    catch {
        Write-Host ""
        Write-Error "An error occurred during the session: $_"
    }
    finally {
        # Restore original console colors
        $originalColors = $psISE.Options.ConsolePaneBackgroundColor, $psISE.Options.ConsolePaneForegroundColor
        if ($originalColors[0]) {
            $Host.UI.RawUI.BackgroundColor = $originalColors[0]
            $Host.UI.RawUI.ForegroundColor = $originalColors[1]
        } else { # Fallback for non-ISE environments
            $Host.UI.RawUI.ForegroundColor = [System.ConsoleColor]::Gray
            $Host.UI.RawUI.BackgroundColor = [System.ConsoleColor]::Black
        }
        Clear-Host
        Write-Host "Session terminated. Console colors restored." -ForegroundColor Green
    }
}