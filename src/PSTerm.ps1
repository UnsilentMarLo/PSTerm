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
#region Type and Profile Setup
# Load necessary assemblies for GUI and serial port
# Attempt to load WPF assemblies
$WpfAvailable = $false
try {
    Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
    $WpfAvailable = $true
    Write-Host "WPF assemblies loaded successfully. WPF UI will be used." -ForegroundColor Cyan
} catch {
    Write-Warning "Could not load WPF assemblies. Falling back to Windows Forms UI."
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic
Add-Type -AssemblyName System
[System.Windows.Forms.Application]::EnableVisualStyles()
if ($Host.Name -eq 'ConsoleHost') {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}

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

    public class DwmUtils
    {
        [DllImport("dwmapi.dll", PreserveSig = true)]
        public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);
    }
"@

# Determine script base directory reliably
if ($MyInvocation.MyCommand.CommandType -eq "ExternalScript") {
    $ScriptBaseDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
}
else {
    $ScriptBaseDir = Split-Path -Parent -Path ([Environment]::GetCommandLineArgs()[0])
    if ([string]::IsNullOrWhiteSpace($ScriptBaseDir)) {
        $ScriptBaseDir = if (![string]::IsNullOrWhiteSpace($PSScriptRoot)) { $PSScriptRoot } else { Get-Location }
    }
}

$currentPSEdition = $PSVersionTable.PSEdition
$currentCLRVersion = if ($PSVersionTable.CLRVersion) { $PSVersionTable.CLRVersion.ToString() }

Write-Host "Detected PowerShell Edition: $currentPSEdition" -ForegroundColor Cyan
Write-Host "Detected CLR Version: $currentCLRVersion" -ForegroundColor Cyan

# Unblock DLLs that might be blocked after extraction
Get-ChildItem -Path $ScriptBaseDir -Recurse | Unblock-File

# Import the Posh-SSH module
try {
    Import-Module "$ScriptBaseDir\lib\Posh-SSH\Posh-SSH.psd1" -ErrorAction Stop
    Write-Host "Posh-SSH module imported successfully." -ForegroundColor Cyan
}
catch {
    Write-Error "Failed to import the Posh-SSH module. Error: $_"
    Read-Host "Press Enter to exit..."
    exit
}

# Create a directory for connection profiles if it doesn't exist
$ProfilesDir = Join-Path $ScriptBaseDir "Profiles"
if (!(Test-Path $ProfilesDir)) { New-Item -ItemType Directory -Path $ProfilesDir | Out-Null }

# Consolidate profiles into a single JSON file.
$ProfilesFile = Join-Path $ProfilesDir "profiles.json"
if (-not (Test-Path $ProfilesFile)) {
    Write-Host "Creating default profiles file."
    $defaultProfiles = @(
        @{
            Name                = "Default-Serial"
            Type                = "Serial"
            COMPort             = ""
            BaudRate            = 9600
            DataBits            = 8
            Parity              = "None"
            StopBits            = "One"
            Handshake           = "None"
            DtrEnable           = $false
            Host                = ""
            User                = ""
            SshPort             = 22
            TelnetPort          = 23
            TelnetNegotiation   = "Active"
            TextColor           = "White"
            BackgroundColor     = "Black"
            CursorSize          = "Normal"
            AutoInput           = ""
            BackgroundLogging   = $false
            LogFilePath         = ""
            RawLogData          = $false
            ObfuscatePasswords  = $false
            KeepAlive           = $false
            ForceTerminalColors = $true # Serial connections should control the terminal colors by default
        },
        @{
            Name                = "Default-SSH"
            Type                = "SSH"
            COMPort             = ""
            BaudRate            = 9600
            DataBits            = 8
            Parity              = "None"
            StopBits            = "One"
            Handshake           = "None"
            DtrEnable           = $false
            Host                = ""
            User                = ""
            SshPort             = 22
            TelnetPort          = 23
            TelnetNegotiation   = "Active"
            TextColor           = "White"
            BackgroundColor     = "Black"
            CursorSize          = "Normal"
            AutoInput           = ""
            BackgroundLogging   = $false
            LogFilePath         = ""
            RawLogData          = $false
            ObfuscatePasswords  = $false
            KeepAlive           = $false
            ForceTerminalColors = $false # SSH servers often force their own colors; disable by default
        },
        @{
            Name                = "Default-Telnet"
            Type                = "Telnet"
            COMPort             = ""
            BaudRate            = 9600
            DataBits            = 8
            Parity              = "None"
            StopBits            = "One"
            Handshake           = "None"
            DtrEnable           = $false
            Host                = ""
            User                = ""
            SshPort             = 22
            TelnetPort          = 23
            TelnetNegotiation   = "Active"
            TextColor           = "White"
            BackgroundColor     = "Black"
            CursorSize          = "Normal"
            AutoInput           = ""
            BackgroundLogging   = $false
            LogFilePath         = ""
            RawLogData          = $false
            ObfuscatePasswords  = $false
            KeepAlive           = $false
            ForceTerminalColors = $true # Telnet connections should control the terminal colors by default
        }
    )
    $defaultProfiles | ConvertTo-Json -Depth 5 | Set-Content -Path $ProfilesFile -Encoding UTF8
}

#endregion Type and Profile Setup

#region Profile Management Functions

function Get-ProfileList {
    if ($ProfilesFile -and (Test-Path $ProfilesFile)) {
        try {
            $profiles = Get-Content -Raw -Path $ProfilesFile | ConvertFrom-Json
            if ($profiles -is [array]) {
                return $profiles.Name
            } elseif ($profiles) {
                return @($profiles.Name)
            }
        } catch {
            Write-Warning "Could not read or parse profiles file: $ProfilesFile"
        }
    }
    return @()
}


function Import-Profile($name) {
    if ($ProfilesFile -and (Test-Path $ProfilesFile)) {
        $profiles = Get-Content -Raw -Path $ProfilesFile | ConvertFrom-Json
        # Handle case where JSON contains a single object instead of an array
        if ($profiles -isnot [array]) { $profiles = @($profiles) }
        return $profiles | Where-Object { $_.Name -eq $name }
    }
    return $null
}

function Save-Profile($name, $config) {
    $name = $name.Trim()
    $profiles = @()

    if ($ProfilesFile -and (Test-Path $ProfilesFile)) {
        $profiles = Get-Content -Raw -Path $ProfilesFile | ConvertFrom-Json

        # Ensure it's always a flat array of objects
        if ($profiles -isnot [System.Collections.IEnumerable] -or $profiles -is [string]) {
            $profiles = @($profiles) # Single object -> array
        } else {
            $profiles = @($profiles) -ne $null # Flatten nested array
        }
    }

    # Filter out matching profile names (case-insensitive) - a consideration
    # $profiles = $profiles | Where-Object { $_.Name -and $_.Name.Trim().ToLower() -ne $name.ToLower() }

	$profiles = $profiles | Where-Object { $_.Name -ne $name }

    $config.Name = $name
    $profiles += $config

    $profiles | ConvertTo-Json -Depth 5 | Set-Content -Path $ProfilesFile -Encoding UTF8
}

function Remove-Profile($name) {
    if ($ProfilesFile -and (Test-Path $ProfilesFile)) {
        try {
            $content = Get-Content -Raw -Path $ProfilesFile
            if ([string]::IsNullOrWhiteSpace($content)) { return }
            
            $profiles = $content | ConvertFrom-Json
            if ($profiles -isnot [array]) { $profiles = @($profiles) }
            
            $profiles = $profiles | Where-Object { $_.Name -ne $name }
            
            # Ensure output is a valid JSON array or object
            $json = $profiles | ConvertTo-Json -Depth 5
            if ([string]::IsNullOrWhiteSpace($json) -or $json -eq 'null') { $json = "[]" }
            
            Set-Content -Path $ProfilesFile -Value $json -Encoding UTF8
        } catch {
            Write-Warning "Failed to delete profile '$name': $_"
        }
    }
}

#endregion Profile Management Functions

#region Session Handlers

function Show-SessionEndedMenu {
    param([string]$Message = "")

    if (-not [string]::IsNullOrWhiteSpace($Message)) {
        Write-Host "`n$Message" -ForegroundColor Yellow
    }

    while ($true) {
        Write-Host "`nConnection Closed. Select an action:" -ForegroundColor Cyan
        Write-Host "[R] Retry Connection"
        Write-Host "[A] Auto-Retry until connected (Press Ctrl+C to abort)"
        Write-Host "[E] Exit to Configuration Menu"
        Write-Host "[ESC] Close Application"
        
        try {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq 'Escape') { return 'X' }
            $char = $key.KeyChar.ToString().ToUpper()
        } catch {
            $char = Read-Host "Enter selection (R/A/E)"
            if ($char) { $char = $char.ToString().ToUpper().Substring(0,1) }
        }

        if ($char -in 'R', 'A', 'E') {
            return $char
        }
    }
}

# Function to remove ANSI escape sequences from a string
function Remove-AnsiEscapeSequences {
    param([string]$textinput)
    if (-not $textinput) { return '' }

    # Pattern to match ANSI escape codes
    $ansiPattern = '\x1B\[[0-9;?]*[@-~]'
    $cleanedText = $textinput -replace $ansiPattern, ''

    # Pattern to match other non-printable control characters, preserving CR, LF, Tab, and Backspace (for log processing)
    # Changed \x00-\x08 to \x00-\x07 so \x08 (BS) is preserved.
    $controlCharPattern = '[\x00-\x07\x0B\x0C\x0E-\x1F\x7F]'
    $cleanedText = $cleanedText -replace $controlCharPattern, ''

    return $cleanedText
}

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
        # Create or overwrite log file
        New-Item -Path $LogFilePath -ItemType File -Force | Out-Null
    }
    catch {
        Write-Error "Failed to create log file at '$LogFilePath'. Logging will be disabled. Error: $_"
        return $null
    }

    # Create a thread-safe queue for log entries
    $logQueue = [System.Collections.Queue]::Synchronized((New-Object System.Collections.Queue))
    $stopFlag = [ref]$false

    # Define the logger scriptblock to run in a background runspace
    $loggerScript = {
        param($path, $queue, $stopRef, $obfuscate, $raw)

        $passwordPromptDetected = $false
        $passwordPromptRegex = 'password:|passphrase for|enter password'
        $lineBuffer = New-Object System.Text.StringBuilder
        
        $streamWriter = [System.IO.StreamWriter]::new($path, $true, [System.Text.Encoding]::UTF8)
        $streamWriter.AutoFlush = $true

        $ProcessAndWrite = {
            param($text)
            
            # If Raw mode, dump directly
            if ($raw) {
                $streamWriter.Write($text)
                return
            }

            # If Obfuscation is on, we are dealing with a modified string (potentially).
            # We treat the text as linear stream.
            
            $chars = $text.ToCharArray()
            foreach ($c in $chars) {
                # Handle Backspace (0x08)
                if ($c -eq [char]8) {
                    if ($lineBuffer.Length -gt 0) { $lineBuffer.Length-- }
                }
                # Handle Newlines (Flush on LF only to keep CRLF atomic)
                elseif ($c -eq "`n") {
                    $lineBuffer.Append($c)
                    $streamWriter.Write($lineBuffer.ToString())
                    $lineBuffer.Clear()
                }
                else {
                    $lineBuffer.Append($c)
                }
            }
        }

        try {
            while (-not $stopRef.Value) {
                while ($queue.Count -gt 0) {
                    $logEntry = $queue.Dequeue()
                    if ($null -eq $logEntry) { continue }

                    $dataToLog = $logEntry.Data

                    if ($obfuscate) {
                        if ($logEntry.Source -eq 'Server') {
                            if ($dataToLog -match $passwordPromptRegex) {
                                $passwordPromptDetected = $true
                            }
                            $ProcessAndWrite.Invoke($dataToLog)
                        }
                        elseif ($logEntry.Source -eq 'User') {
                            if ($passwordPromptDetected) {
                                $obfuscatedData = '*' * $dataToLog.Length
                                $ProcessAndWrite.Invoke($obfuscatedData)
                                # Reset after user hits enter
                                if ($dataToLog -match "[\r\n]") {
                                    $passwordPromptDetected = $false
                                }
                            }
                            else {
                                $ProcessAndWrite.Invoke($dataToLog)
                            }
                        }
                    }
                    else {
                        $ProcessAndWrite.Invoke($dataToLog)
                    }
                }
                Start-Sleep -Milliseconds 100
            }
        }
        finally {
            # Flush remaining buffer on exit
            if ($null -ne $lineBuffer -and $lineBuffer.Length -gt 0) {
                $streamWriter.Write($lineBuffer.ToString())
            }
            $streamWriter.Dispose()
        }
    }

    # Create and start the runspace
    $runspace = [powershell]::Create()
    $runspace.AddScript($loggerScript).AddArgument($LogFilePath).AddArgument($logQueue).AddArgument($stopFlag).AddArgument($ObfuscatePasswords.IsPresent).AddArgument($RawSessionData.IsPresent) | Out-Null
    $runspace.Runspace.ThreadOptions = "ReuseThread"
    $asyncResult = $runspace.BeginInvoke()

    # Return a control object for the logger
    return [PSCustomObject]@{
        Runspace    = $runspace
        AsyncResult = $asyncResult
        Queue       = $logQueue
        StopFlag    = $stopFlag
    }
}

function Stop-SessionLogger {
    param(
        [Parameter(Mandatory = $true)]
        $Logger
    )
    if ($Logger -and $Logger.Runspace) {
        $Logger.StopFlag.Value = $true
        # Wait for the logger to finish processing its queue before disposing
        try {
            $Logger.Runspace.EndInvoke($Logger.AsyncResult)
        } catch {
            # Ignore errors on dispose, as the runspace might already be stopped.
        }
        $Logger.Runspace.Dispose()
    }
}

function Start-SessionKeepAlive {
    param(
        [System.IO.Stream]$Stream,
        [int]$IntervalSeconds = 30
    )
    # Start a background job to send a NULL byte periodically to keep the session alive
    $job = Start-Job -ScriptBlock {
        param($stream, $interval)
        while ($true) {
            Start-Sleep -Seconds $interval
            try {
                if ($stream.CanWrite) {
                    $stream.Write([byte[]]@(0), 0, 1)
                } else { break }
            }
            catch { break }
        }
    } -ArgumentList $Stream, $IntervalSeconds
    return $job
}

function Stop-SessionKeepAlive($job) {
    if ($job) {
        Stop-Job $job -Passthru | Remove-Job -Force
    }
}

function Start-SerialSession {
    param(
        [PSCustomObject]$Config
    )

    $autoRetry = $false

    do {
        $Port = $null
        try {
            # Apply terminal colors if forced, else reset to defaults for host compatibility
            if ($Config.ForceTerminalColors) {
                $Host.UI.RawUI.ForegroundColor = $Config.TextColor
                $Host.UI.RawUI.BackgroundColor = $Config.BackgroundColor
                Clear-Host
            } else {
                [Console]::ResetColor()
                Clear-Host
            }

            $host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size ($host.UI.RawUI.BufferSize.Width, 10000)

            if ([string]::IsNullOrWhiteSpace($Config.COMPort)) { throw "No COM Port selected." }
            $Port = New-Object System.IO.Ports.SerialPort($Config.COMPort, $Config.BaudRate, $Config.Parity, $Config.DataBits, $Config.StopBits)
            $Port.Handshake = $Config.Handshake
            $Port.DtrEnable = $Config.DtrEnable
            
            # Connection Attempt
            while ($true) {
                try {
                    $Port.Open()
                    break # Connected
                }
                catch {
                    if ($autoRetry) {
                        Write-Host "`rConnection failed. Retrying in 3 seconds... (Press Ctrl+C to cancel)" -NoNewline -ForegroundColor Yellow
                        Start-Sleep -Seconds 3
                    } else {
                        throw $_
                    }
                }
            }

            try { [Console]::TreatControlCAsInput = $true } catch { Write-Verbose "Could not set Console Mode: $_" }
            $logger = $null
            $logUserInput = $false # Default to false (assume server echoes back) to prevent double logging
            $keepAliveJob = $null
            $receiveEvent = $null

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
                    if ($logger) { $logger.Queue.Enqueue([PSCustomObject]@{Source = 'User'; Data = ($command + "`r`n") }) }
                    Start-Sleep -Milliseconds 200
                }
            }

            if ($Config.KeepAlive) {
                $keepAliveJob = Start-SessionKeepAlive -Stream $Port.BaseStream
            }

            # Register an event for receiving data
            $receiveEvent = Register-ObjectEvent -InputObject $Port -EventName DataReceived -Action {
                try {
                    $p = $event.MessageData.Port
                    $log = $event.MessageData.Logger
                    $cfg = $event.MessageData.Config
                    $data = $p.ReadExisting()
                    Write-Host $data -NoNewline

                    if ($null -ne $log) {
                        if ($cfg.RawLogData) {
                            $dataToLog = $data
                        } else {
                            # Preserve \x08 (BS) for logger processing
                            $dataToLog = $data -replace '\x1B\[[0-9;?]*[@-~]', '' -replace '[\x00-\x07\x0B\x0C\x0E-\x1F\x7F]', ''
                        }
                        $log.Queue.Enqueue([PSCustomObject]@{Source = 'Server'; Data = $dataToLog })
                    }
                }
                catch { Write-Warning "Event handler error: $_" }
            } -MessageData ([PSCustomObject]@{Port = $Port; Logger = $logger; Config = $Config })

            # Main loop for user input
            $consoleInputBroken = $false
            while ($true) {
                if (-not $consoleInputBroken) {
                    try {
                        if ([Console]::KeyAvailable) {
                            $key = [Console]::ReadKey($true)
                            if ($key.Key -eq 'Escape') { break }

                            $output = if ($inputHelpers.ContainsKey($key.Key)) { $inputHelpers[$key.Key] } else { $key.KeyChar }
                            $Port.Write($output)

                            if ($logger -and $logUserInput) {
                                $dataToLog = if ($Config.RawLogData) { $output } else { Remove-AnsiEscapeSequences $output }
                                $logger.Queue.Enqueue([PSCustomObject]@{Source = 'User'; Data = $dataToLog })
                            }
                        }
                    } catch {
                        Write-Warning "Interactive console input not supported in this environment. Input disabled."
                        $consoleInputBroken = $true
                    }
                }
                Start-Sleep -Milliseconds 10
            }
        }
        catch {
            if (-not $autoRetry) {
                Write-Error "Serial session error: $_"
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
            if ($Port -and $Port.IsOpen) { $Port.Close() }
            try { [Console]::TreatControlCAsInput = $false } catch { }
        }

        # Session Ended Menu
        $action = Show-SessionEndedMenu
        if ($action -eq 'X') { return 'EXIT' }
        if ($action -eq 'E') { return }
        if ($action -eq 'R') { $autoRetry = $false }
        if ($action -eq 'A') { $autoRetry = $true }

    } while ($true)
}

function Start-SshSession {
    param(
        [PSCustomObject]$Config
    )

    $autoRetry = $false
    # Pre-prompt for credentials so we don't ask on every retry
    $user = if ($Config.User) { $Config.User } else { Read-Host "Enter SSH username" }
    $securePassword = Read-Host "Enter SSH password for '$user'" -AsSecureString
    $credential = New-Object System.Management.Automation.PSCredential ($user, $securePassword)
    if (-not $credential) { throw "User cancelled the credential prompt." }

    do {
        $poshSession = $null
        $client = $null
        $shellStream = $null
        $logger = $null

        try {
            # Apply terminal colors if forced, else reset
            if ($Config.ForceTerminalColors) {
                $Host.UI.RawUI.ForegroundColor = $Config.TextColor
                $Host.UI.RawUI.BackgroundColor = $Config.BackgroundColor
                Clear-Host
            } else {
                [Console]::ResetColor()
                Clear-Host
            }
            # Always increase buffer for better scrollback
            $host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size ($host.UI.RawUI.BufferSize.Width, 10000)

            while ($true) {
                try {
                    Write-Host "Connecting to $($Config.Host) on port $($Config.SshPort)..." -ForegroundColor Cyan
                    
                    $sessionParams = @{
                        ComputerName = $Config.Host
                        Port         = $Config.SshPort
                        Credential   = $credential
                        ErrorAction  = 'Stop'
                    }
                    if ($Config.KeepAlive) {
                        $sessionParams['KeepAliveInterval'] = 30 # Posh-SSH KeepAlive is in seconds
                    }

                    $poshSession = New-SSHSession @sessionParams
                    $client = ($poshSession | Select-Object -First 1).Session
                    if (-not $client.IsConnected) { throw "Failed to establish an SSH connection." }
                    break # Connected
                }
                catch {
                    if ($autoRetry) {
                        Write-Host "Connection failed: $($_.Exception.Message). Retrying in 3 seconds... (Press Ctrl+C to cancel)" -ForegroundColor Yellow
                        Start-Sleep -Seconds 3
                    } else {
                        throw $_
                    }
                }
            }

            if ($Config.BackgroundLogging) {
                $logger = Start-SessionLogger -LogFilePath $Config.LogFilePath -RawSessionData:$Config.RawLogData -ObfuscatePasswords:$Config.ObfuscatePasswords
            }

            $termWidth = if ($Host.UI.RawUI.WindowSize.Width -gt 0) { $Host.UI.RawUI.WindowSize.Width } else { 80 }
            $termHeight = if ($Host.UI.RawUI.WindowSize.Height -gt 0) { $Host.UI.RawUI.WindowSize.Height } else { 24 }
            $shellStream = $client.CreateShellStream("xterm-256color", $termWidth, $termHeight, 0, 0, 4096)

        # --- Echo Detection ---
        $logUserInput = $true # Default to true (no echo)
        if ($logger) {
            Write-Host "Performing echo detection..." -ForegroundColor DarkGray
            try {
                $testString = [guid]::NewGuid().ToString()
                $testBytes = [System.Text.Encoding]::UTF8.GetBytes($testString)
                $shellStream.Write($testBytes, 0, $testBytes.Length); $shellStream.Flush()
                Start-Sleep -Milliseconds 250

                if ($shellStream.DataAvailable) {
                    $buffer = New-Object byte[] 4096
                    $read = $shellStream.Read($buffer, 0, $buffer.Length)
                    if ($read -gt 0) {
                        $response = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $read)
                        if ($response.Contains($testString)) {
                            Write-Host "Echo detected. Disabling client-side input logging." -ForegroundColor DarkGray
                            $logUserInput = $false
                            $backspaceChars = ("`b" * $testString.Length) + (" " * $testString.Length) + ("`b" * $testString.Length)
                            $backspaceBytes = [System.Text.Encoding]::UTF8.GetBytes($backspaceChars)
                            $shellStream.Write($backspaceBytes, 0, $backspaceBytes.Length); $shellStream.Flush()
                            Start-Sleep -Milliseconds 100
                        }
                    }
                }
                while ($shellStream.DataAvailable) { $shellStream.Read((New-Object byte[] 4096), 0, 4096) > $null }
            } catch {
                Write-Warning "Could not perform SSH echo test. Assuming echo is enabled to prevent double logs."
                $logUserInput = $false
            }
        }
        # --- End Echo Detection ---

        try { [Console]::TreatControlCAsInput = $true } catch { Write-Verbose "Could not set Console Mode: $_" }

        Write-Host "--- SSH Session Started. Press ESC in the console to exit. ---`n" -ForegroundColor Green

        $inputHelpers = [Collections.Generic.Dictionary[ConsoleKey, String]]::new()
        $inputHelpers.Add("UpArrow", "$([char]27)[A"); $inputHelpers.Add("DownArrow", "$([char]27)[B")
        $inputHelpers.Add("RightArrow", "$([char]27)[C"); $inputHelpers.Add("LeftArrow", "$([char]27)[D")
        $inputHelpers.Add("Delete", "$([char]27)[3~"); $inputHelpers.Add("Backspace", $([char]127))
        $inputHelpers.Add("Home", "$([char]27)[H"); $inputHelpers.Add("End", "$([char]27)[F")
        $inputHelpers.Add("PageUp", "$([char]27)[5~"); $inputHelpers.Add("PageDown", "$([char]27)[6~")
        $inputHelpers.Add("Insert", "$([char]27)[2~"); $inputHelpers.Add("Tab", "`t")

        # Read initial output from server and log it
        Start-Sleep -Milliseconds 500
        $initialOutput = ''
        $buffer = New-Object byte[] 4096
        while ($shellStream.DataAvailable) {
            $read = $shellStream.Read($buffer, 0, $buffer.Length)
            if ($read -gt 0) {
                $initialOutput += [System.Text.Encoding]::UTF8.GetString($buffer, 0, $read)
            } else { break }
        }
        Write-Host $initialOutput -NoNewline
        if ($logger) {
            $dataToLog = if ($Config.RawLogData) { $initialOutput } else { Remove-AnsiEscapeSequences $initialOutput }
            $logger.Queue.Enqueue([PSCustomObject]@{Source = 'Server'; Data = $dataToLog })
        }

        if ($Config.AutoInput) {
            Write-Host "`nSending auto-input..." -ForegroundColor Cyan
            foreach ($line in $Config.AutoInput.Split("`n")) {
                $command = $line.Trim() + "`r`n"
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($command)
                $shellStream.Write($bytes, 0, $bytes.Length)
                $shellStream.Flush()
                if ($logger -and $logUserInput) { $logger.Queue.Enqueue([PSCustomObject]@{Source = 'User'; Data = $command }) }
                Start-Sleep -Milliseconds 200
            }
        }

        # Main interactive loop
        $consoleInputBroken = $false
        while ($client.IsConnected) {
            try {
                if ($shellStream.DataAvailable) {
                    $bytesRead = $shellStream.Read($buffer, 0, $buffer.Length)
                    if ($bytesRead -gt 0) {
                        $text = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
                        Write-Host $text -NoNewline
                        if ($logger) {
                            $dataToLog = if ($Config.RawLogData) { $text } else { Remove-AnsiEscapeSequences $text }
                            $logger.Queue.Enqueue([PSCustomObject]@{Source = 'Server'; Data = $dataToLog })
                        }
                    }
                }

                if (-not $consoleInputBroken) {
                    try {
                        if ([Console]::KeyAvailable) {
                            $key = [Console]::ReadKey($true)
                            if ($key.Key -eq 'Escape') { break }

                            $output = if ($inputHelpers.ContainsKey($key.Key)) { $inputHelpers[$key.Key] } else { $key.KeyChar }
                            $bytes = [System.Text.Encoding]::UTF8.GetBytes($output)
                            $shellStream.Write($bytes, 0, $bytes.Length)
                            $shellStream.Flush()

                            if ($logger -and $logUserInput) {
                                $dataToLog = if ($Config.RawLogData) { $output } else { Remove-AnsiEscapeSequences $output }
                                $logger.Queue.Enqueue([PSCustomObject]@{Source = 'User'; Data = $dataToLog })
                            }
                        }
                    } catch {
                        Write-Warning "Interactive console input not supported. Input disabled."
                        $consoleInputBroken = $true
                    }
                }
                Start-Sleep -Milliseconds 20
            }
            catch [System.ObjectDisposedException] {
                # This is an expected exception when the remote host closes the connection (e.g., via 'exit' command).
                # We break the loop gracefully and let the 'finally' block handle cleanup.
                Write-Verbose "ShellStream was disposed, indicating a clean session exit."
                break
            }
            catch {
                # Catch any other unexpected errors during the session.
                Write-Error "An error occurred during the SSH session: $_"
                break
            }
        }
    }
    catch {
        if (-not $autoRetry) {
             Write-Error "SSH session failed: $($_.Exception.Message)"
             if ($_.Exception.InnerException) { Write-Error "Inner Exception: $($_.Exception.InnerException.Message)" }
        }
    }
    finally {
        Write-Host "`n--- SSH Session Closed. ---" -ForegroundColor Yellow
        if ($logger) { Stop-SessionLogger $logger }
        if ($shellStream) { $shellStream.Dispose() }
        if ($poshSession) { Remove-SSHSession -SSHSession $poshSession }
        try { [Console]::TreatControlCAsInput = $false } catch { }
    }

    # Session Ended Menu
    $action = Show-SessionEndedMenu
    if ($action -eq 'X') { return 'EXIT' }
    if ($action -eq 'E') { return }
    if ($action -eq 'R') { $autoRetry = $false }
    if ($action -eq 'A') { $autoRetry = $true }

    } while ($true)
}

function Start-TelnetSession {
    param(
        [PSCustomObject]$Config
    )

    $autoRetry = $false

    do {
        $client = New-Object System.Net.Sockets.TcpClient
        $stream = $null
        $logger = $null
        $logUserInput = $false # Default to false (assume server echoes back) to prevent double logging
        $keepAliveJob = $null
        $readerJob = $null

        try {
            # Apply terminal colors if forced, else reset
            if ($Config.ForceTerminalColors) {
                $Host.UI.RawUI.ForegroundColor = $Config.TextColor
                $Host.UI.RawUI.BackgroundColor = $Config.BackgroundColor
                Clear-Host
            } else {
                [Console]::ResetColor()
                Clear-Host
            }

            $host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size ($host.UI.RawUI.BufferSize.Width, 10000)

            while ($true) {
                try {
                    Write-Host "Connecting to $($Config.Host) on port $($Config.TelnetPort)..." -ForegroundColor Cyan
                    $client.Connect($Config.Host, $Config.TelnetPort)
                    $stream = $client.GetStream()
                    break # Connected
                }
                catch {
                    if ($autoRetry) {
                        Write-Host "Connection failed. Retrying in 3 seconds... (Press Ctrl+C to cancel)" -ForegroundColor Yellow
                        Start-Sleep -Seconds 3
                        # Re-create TcpClient for next attempt
                        $client = New-Object System.Net.Sockets.TcpClient
                    } else {
                        throw $_
                    }
                }
            }

            if ($Config.BackgroundLogging) {
                $logger = Start-SessionLogger -LogFilePath $Config.LogFilePath -RawSessionData:$Config.RawLogData -ObfuscatePasswords:$Config.ObfuscatePasswords
            }

            # Start a background job to read from the stream
        $readerJob = Start-Job -InitializationScript {
            function Remove-AnsiEscapeSequences {
                param([string]$textinput)
                if (-not $textinput) { return '' }
                $ansiPattern = '\x1B\[[0-9;?]*[@-~]'
                $cleanedText = $textinput -replace $ansiPattern, ''
                # Preserve \x08 (BS) for logger processing
                $controlCharPattern = '[\x00-\x07\x0B\x0C\x0E-\x1F\x7F]'
                $cleanedText -replace $controlCharPattern, ''
            }
        } -ScriptBlock {
            param($streamRef, $logQueueRef, $rawLogData)
            $stream = $streamRef.get_Value()
            $logQueue = $logQueueRef.get_Value()
            $encoding = [System.Text.Encoding]::ASCII
            $buffer = New-Object byte[] 4096
            $IAC = 255; $DONT = 254; $DO = 253; $WONT = 252; $WILL = 251

            while ($stream.CanRead) {
                try {
                    $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
                    if ($bytesRead -eq 0) { break }

                    $outputBuffer = New-Object System.IO.MemoryStream
                    for ($i = 0; $i -lt $bytesRead; $i++) {
                        if ($buffer[$i] -eq $IAC) { # Handle Telnet commands
                            $command = $buffer[++$i]; $option = $buffer[++$i]
                            if ($command -eq $DO) { $stream.Write(@($IAC, $WONT, $option), 0, 3) }
                            elseif ($command -eq $WILL) { $stream.Write(@($IAC, $DONT, $option), 0, 3) }
                        } else {
                            $outputBuffer.WriteByte($buffer[$i])
                        }
                    }

                    if ($outputBuffer.Length -gt 0) {
                        $text = $encoding.GetString($outputBuffer.ToArray())
                        Write-Host $text -NoNewline
                        if ($logQueue) {
                            $dataToLog = if ($rawLogData) { $text } else { Remove-AnsiEscapeSequences $text }
                            $logQueue.Enqueue([PSCustomObject]@{Source = 'Server'; Data = $dataToLog })
                        }
                    }
                } catch { break }
            }
        } -ArgumentList ([ref]$stream), ([ref]$logger.Queue), $Config.RawLogData

        try { [Console]::TreatControlCAsInput = $true } catch { Write-Verbose "Could not set Console Mode: $_" }

        $inputHelpers = [Collections.Generic.Dictionary[ConsoleKey, String]]::new()
        $inputHelpers.Add("UpArrow", "$([char]27)[A"); $inputHelpers.Add("DownArrow", "$([char]27)[B")
        $inputHelpers.Add("RightArrow", "$([char]27)[C"); $inputHelpers.Add("LeftArrow", "$([char]27)[D")
        $inputHelpers.Add("Delete", $([char]127)); $inputHelpers.Add("Backspace", $([char]8))
        $inputHelpers.Add("Home", "$([char]27)[H"); $inputHelpers.Add("End", "$([char]27)[F")
        $inputHelpers.Add("PageUp", "$([char]27)[5~"); $inputHelpers.Add("PageDown", "$([char]27)[6~")
        $inputHelpers.Add("Insert", "$([char]27)[2~")

        Write-Host "--- Telnet Session Started. Press ESC in the console to exit. ---`n" -ForegroundColor Green

        if ($Config.AutoInput) {
            Write-Host "Sending auto-input..." -ForegroundColor Cyan; Start-Sleep -Seconds 1
            foreach ($line in $Config.AutoInput.Split("`n")) {
                $command = $line.Trim() + "`r`n"
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($command)
                $stream.Write($bytes, 0, $bytes.Length)
                if ($logger) { $logger.Queue.Enqueue([PSCustomObject]@{Source = 'User'; Data = $command }) }
                Start-Sleep -Milliseconds 200
            }
        }

        if ($Config.KeepAlive) {
            $keepAliveJob = Start-SessionKeepAlive -Stream $stream
        }

            $consoleInputBroken = $false
            while ($client.Connected -and $readerJob.State -in @('Running', 'NotStarted')) {
                if (-not $consoleInputBroken) {
                    try {
                        if ([Console]::KeyAvailable) {
                            $key = [Console]::ReadKey($true)
                            if ($key.Key -eq 'Escape') { break }

                            $output = if ($inputHelpers.ContainsKey($key.Key)) { $inputHelpers[$key.Key] } else { $key.KeyChar }
                            $bytes = [System.Text.Encoding]::ASCII.GetBytes($output)
                            $stream.Write($bytes, 0, $bytes.Length)

                            if ($logger -and $logUserInput) {
                                $dataToLog = if ($Config.RawLogData) { $output } else { Remove-AnsiEscapeSequences $output }
                                $logger.Queue.Enqueue([PSCustomObject]@{Source = 'User'; Data = $dataToLog })
                            }
                        }
                    } catch {
                        Write-Warning "Interactive console input not supported. Input disabled."
                        $consoleInputBroken = $true
                    }
                }
                Start-Sleep -Milliseconds 20
            }
        }
        catch {
             if (-not $autoRetry) { Write-Error "Telnet session failed: $_" }
        }
        finally {
            Write-Host "`n--- Telnet Session Closed. ---" -ForegroundColor Yellow
            if ($keepAliveJob) { Stop-SessionKeepAlive $keepAliveJob }
            if ($readerJob) { Stop-Job $readerJob | Remove-Job -Force }
            if ($logger) { Stop-SessionLogger $logger }
            if ($stream) { $stream.Close() }
            if ($client) { $client.Close() }
            try { [Console]::TreatControlCAsInput = $false } catch { }
        }
        
        # Session Ended Menu
        $action = Show-SessionEndedMenu
        if ($action -eq 'X') { return 'EXIT' }
        if ($action -eq 'E') { return }
        if ($action -eq 'R') { $autoRetry = $false }
        if ($action -eq 'A') { $autoRetry = $true }

    } while ($true)
}


#endregion Session Handlers

. "$PSScriptRoot\ui.ps1"


# --- Main Script Execution ---
while ($true) {
    # Clear-Host # Optional: uncomment to clear screen between sessions
    $global:ConnectionConfig = $null
    if ($WpfAvailable) {
        $dialogResult = Show-ConnectionConfigMenu_WPF -ScriptBaseDir $ScriptBaseDir -ProfilesFile $ProfilesFile
    }
    else {
        $dialogResult = Show-ConnectionConfigMenu
    }

    if (!$global:ConnectionConfig) {
        Write-Host "Operation cancelled. Exiting." -ForegroundColor Yellow
        break
    }

    Clear-Host
    $config = $global:ConnectionConfig

    # Set console properties
    $Host.UI.RawUI.WindowTitle = "$($config.Type) Session - $($config.Host)$($config.COMPort)"
    switch ($config.CursorSize) {
        "Small" { $Host.UI.RawUI.CursorSize = 25 }
        "Large" { $Host.UI.RawUI.CursorSize = 100 }
        default { $Host.UI.RawUI.CursorSize = 50 } # Normal
    }

    try {
        $result = switch ($config.Type) {
            "Serial" {
                Start-SerialSession -Config $config
            }
            "SSH" {
                Start-SshSession -Config $config
            }
            "Telnet" {
                Start-TelnetSession -Config $config
            }
        }
        if ($result -eq 'EXIT') { break }
    }
    catch {
        Write-Error "Failed to start session: $_"
        Read-Host "Press Enter to return to the menu."
    }
}

Write-Host "Script finished."