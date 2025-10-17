#region Type and Profile Setup
# Load necessary assemblies for GUI and serial port
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic
Add-Type -AssemblyName System
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

#endregion Profile Management Functions

#region Session Handlers

# Function to remove ANSI escape sequences from a string
function Remove-AnsiEscapeSequences {
    param([string]$textinput)
    if (-not $textinput) { return $textinput }

    $esc = [char]27
    # CSI, OSC, and other common escape patterns
    $pattern = "$esc\[[0-9;?]*[@-~]|$esc\][^\a\e]*([\a]|\e\\)|$esc."
    return $textinput -replace $pattern, ''
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
        param($path, $queue, $stopRef, $obfuscate)

        $passwordPromptDetected = $false
        $passwordPromptRegex = 'password:|passphrase for|enter password'

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
                        Add-Content -Path $path -Value $dataToLog -NoNewline -Encoding UTF8
                    }
                    elseif ($logEntry.Source -eq 'User') {
                        if ($passwordPromptDetected) {
                            $obfuscatedData = '*' * $dataToLog.Length
                            Add-Content -Path $path -Value $obfuscatedData -NoNewline -Encoding UTF8
                            # Reset after user hits enter
                            if ($dataToLog -match "[\r\n]") {
                                $passwordPromptDetected = $false
                            }
                        }
                        else {
                            Add-Content -Path $path -Value $dataToLog -NoNewline -Encoding UTF8
                        }
                    }
                }
                else {
                    Add-Content -Path $path -Value $dataToLog -NoNewline -Encoding UTF8
                }
            }
            Start-Sleep -Milliseconds 100
        }
    }

    # Create and start the runspace
    $runspace = [powershell]::Create()
    $runspace.AddScript($loggerScript).AddArgument($LogFilePath).AddArgument($logQueue).AddArgument($stopFlag).AddArgument($ObfuscatePasswords.IsPresent) | Out-Null
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
        [System.IO.Ports.SerialPort]$Port,
        [PSCustomObject]$Config
    )

    [Console]::TreatControlCAsInput = $true
    $logger = $null
    $keepAliveJob = $null
    $receiveEvent = $null

    try {
        # Apply terminal colors if forced
        if ($Config.ForceTerminalColors) {
            $Host.UI.RawUI.ForegroundColor = $Config.TextColor
            $Host.UI.RawUI.BackgroundColor = $Config.BackgroundColor
            Clear-Host
        }
        
		$host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size ($host.UI.RawUI.BufferSize.Width, 10000)
		
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
                    $dataToLog = if ($cfg.RawLogData) { $data } else { Remove-AnsiEscapeSequences $data }
                    $log.Queue.Enqueue([PSCustomObject]@{Source = 'Server'; Data = $dataToLog })
                }
            }
            catch { Write-Warning "Event handler error: $_" }
        } -MessageData ([PSCustomObject]@{Port = $Port; Logger = $logger; Config = $Config })

        # Main loop for user input
        while ($true) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq 'Escape') { break }

                $output = if ($inputHelpers.ContainsKey($key.Key)) { $inputHelpers[$key.Key] } else { $key.KeyChar }
                $port.Write($output)

                if ($logger) {
                    $dataToLog = if ($Config.RawLogData) { $output } else { Remove-AnsiEscapeSequences $output }
                    $logger.Queue.Enqueue([PSCustomObject]@{Source = 'User'; Data = $dataToLog })
                }
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

function Start-SshSession {
    param(
        [PSCustomObject]$Config
    )

    $poshSession = $null
    $client = $null
    $shellStream = $null
    $logger = $null

    try {
        # Apply terminal colors if forced
        if ($Config.ForceTerminalColors) {
            $Host.UI.RawUI.ForegroundColor = $Config.TextColor
            $Host.UI.RawUI.BackgroundColor = $Config.BackgroundColor
            Clear-Host
        }
        # Always increase buffer for better scrollback
        $host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size ($host.UI.RawUI.BufferSize.Width, 10000)

        if ($Config.BackgroundLogging) {
            $logger = Start-SessionLogger -LogFilePath $Config.LogFilePath -RawSessionData:$Config.RawLogData -ObfuscatePasswords:$Config.ObfuscatePasswords
        }

        Write-Host "Connecting to $($Config.Host) on port $($Config.SshPort)..." -ForegroundColor Cyan
        $user = if ($Config.User) { $Config.User } else { Read-Host "Enter SSH username" }
        $securePassword = Read-Host "Enter SSH password for '$user'" -AsSecureString
        $credential = New-Object System.Management.Automation.PSCredential ($user, $securePassword)

        if (-not $credential) { throw "User cancelled the credential prompt." }

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

        $termWidth = if ($Host.UI.RawUI.WindowSize.Width -gt 0) { $Host.UI.RawUI.WindowSize.Width } else { 80 }
        $termHeight = if ($Host.UI.RawUI.WindowSize.Height -gt 0) { $Host.UI.RawUI.WindowSize.Height } else { 24 }
        $shellStream = $client.CreateShellStream("xterm-256color", $termWidth, $termHeight, 0, 0, 4096)

        [Console]::TreatControlCAsInput = $true
        
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
                if ($logger) { $logger.Queue.Enqueue([PSCustomObject]@{Source = 'User'; Data = $command }) }
                Start-Sleep -Milliseconds 200
            }
        }

        # Main interactive loop
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

                if ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    if ($key.Key -eq 'Escape') { break }

                    $output = if ($inputHelpers.ContainsKey($key.Key)) { $inputHelpers[$key.Key] } else { $key.KeyChar }
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($output)
                    $shellStream.Write($bytes, 0, $bytes.Length)
                    $shellStream.Flush()

                    # BUGFIX: Do NOT log user's keypress here. The server echo will be logged instead,
                    # preventing double characters in the log file.
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
        Write-Error "SSH session failed: $($_.Exception.Message)"
        if ($_.Exception.InnerException) { Write-Error "Inner Exception: $($_.Exception.InnerException.Message)" }
        Read-Host "Press Enter to continue..."
    }
    finally {
        Write-Host "`n--- SSH Session Closed. ---" -ForegroundColor Yellow
        if ($logger) { Stop-SessionLogger $logger }
        if ($shellStream) { $shellStream.Dispose() }
        if ($poshSession) { Remove-SSHSession -SSHSession $poshSession }
        [Console]::TreatControlCAsInput = $false
    }
}

function Start-TelnetSession {
    param(
        [PSCustomObject]$Config
    )

    $client = New-Object System.Net.Sockets.TcpClient
    $stream = $null
    $logger = $null
    $keepAliveJob = $null
    $readerJob = $null

    try {
        # Apply terminal colors if forced
        if ($Config.ForceTerminalColors) {
            $Host.UI.RawUI.ForegroundColor = $Config.TextColor
            $Host.UI.RawUI.BackgroundColor = $Config.BackgroundColor
            Clear-Host
        }
		
		$host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size ($host.UI.RawUI.BufferSize.Width, 10000)
        
        if ($Config.BackgroundLogging) {
            $logger = Start-SessionLogger -LogFilePath $Config.LogFilePath -RawSessionData:$Config.RawLogData -ObfuscatePasswords:$Config.ObfuscatePasswords
        }

        Write-Host "Connecting to $($Config.Host) on port $($Config.TelnetPort)..." -ForegroundColor Cyan
        $client.Connect($Config.Host, $Config.TelnetPort)
        $stream = $client.GetStream()

        # Start a background job to read from the stream
        $readerJob = Start-Job -InitializationScript ${function:Remove-AnsiEscapeSequences} -ScriptBlock {
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

        while ($client.Connected -and $readerJob.State -in @('Running', 'NotStarted')) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq 'Escape') { break }

                $output = if ($inputHelpers.ContainsKey($key.Key)) { $inputHelpers[$key.Key] } else { $key.KeyChar }
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($output)
                $stream.Write($bytes, 0, $bytes.Length)

                if ($logger) {
                    $dataToLog = if ($Config.RawLogData) { $output } else { Remove-AnsiEscapeSequences $output }
                    $logger.Queue.Enqueue([PSCustomObject]@{Source = 'User'; Data = $dataToLog })
                }
            }
            Start-Sleep -Milliseconds 20
        }
    }
    catch { Write-Error "Telnet session failed: $_" }
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
    [ConsoleUtils]::ShowWindow($consoleHandle, 0) # Hide console

    $form = New-Object Windows.Forms.Form
    $form.Text = "Connection Configuration"
    $form.FormBorderStyle = 'Sizable'
    $form.AutoScaleMode = 'Dpi'
    $form.AutoSize = $false
    $form.MinimumSize = New-Object System.Drawing.Size(750, 710)
    $form.MaximumSize = New-Object System.Drawing.Size(99999, 710)
    $form.AutoSizeMode = 'GrowOnly'
    $form.StartPosition = "CenterScreen"
    $form.Padding = 10

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
    $mainLayout.AutoSize = $false
    $mainLayout.ColumnCount = 2
    $mainLayout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'Percent', 50)) | Out-Null
    $mainLayout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'Percent', 50)) | Out-Null
    $form.Controls.Add($mainLayout)

    # --- Profile Controls (Row 0) ---
    $gbProfile = New-Object Windows.Forms.GroupBox; $gbProfile.Text = "Profile"; $gbProfile.Dock = 'Fill'
    $mainLayout.Controls.Add($gbProfile, 0, 0); $mainLayout.SetColumnSpan($gbProfile, 2)
    
    $profileTlp = New-Object Windows.Forms.TableLayoutPanel; $profileTlp.Dock = 'Fill'; $profileTlp.AutoSize = $true; $profileTlp.Padding = 5
    $profileTlp.ColumnCount = 4 # only add controls to 4 columns (0, 1, 2, 3)
    $profileTlp.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'AutoSize')) | Out-Null # Select Profile:
    $profileTlp.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'Percent', 100)) | Out-Null # ComboBox (Dropdown)
    $gbProfile.Controls.Add($profileTlp)

    $profileTlp.Controls.Add((New-Label "Select Profile:"), 0, 0)
    $cbProfiles = New-Object Windows.Forms.ComboBox; $cbProfiles.Dock = 'Fill'; $cbProfiles.Items.AddRange((Get-ProfileList)); $cbProfiles.DropDownStyle = 'DropDown'
    $profileTlp.Controls.Add($cbProfiles, 1, 0)
    $btnSaveProfile = New-Object Windows.Forms.Button; $btnSaveProfile.Text = "Save" # REMOVE Anchor = 'None'
    $profileTlp.Controls.Add($btnSaveProfile, 2, 0)
    $btnDeleteProfile = New-Object Windows.Forms.Button; $btnDeleteProfile.Text = "Delete" # REMOVE Anchor = 'None'
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
    $btnRefreshPorts = New-Object Windows.Forms.Button; $btnRefreshPorts.Text = "Refresh"; $btnRefreshPorts.AutoSize = $true
    $portTlp = New-Object Windows.Forms.TableLayoutPanel; $portTlp.Dock = 'Fill'; $portTlp.ColumnCount=1
    $portTlp.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'Percent', 100)) | Out-Null
    $portTlp.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'AutoSize')) | Out-Null
    $portTlp.Controls.AddRange(@($cbPort, $btnRefreshPorts))
    $pnlSerial.Controls.Add($portTlp, 1, 0)
    
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
    $gbCommon = New-Object Windows.Forms.GroupBox; $gbCommon.Text = "Terminal and Logging"; $gbCommon.Dock = 'Fill'
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
    $btnBrowseLog = New-Object Windows.Forms.Button; $btnBrowseLog.Text = "..."; $btnBrowseLog.AutoSize = $true
    $logFileTlp = New-Object Windows.Forms.TableLayoutPanel; $logFileTlp.Dock = 'Fill'; $logFileTlp.ColumnCount=2
    $logFileTlp.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'Percent', 100)) | Out-Null
    $logFileTlp.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle 'AutoSize')) | Out-Null
    $logFileTlp.Controls.AddRange(@($txtLogFilePath, $btnBrowseLog))
    $commonTlp.Controls.Add($logFileTlp, 1, 6)
    
    $commonTlp.Controls.Add((New-Label "Log Raw Stream Data:"), 0, 7); $chkRawLogData = New-Object Windows.Forms.CheckBox; $chkRawLogData.Anchor = 'Left'; $commonTlp.Controls.Add($chkRawLogData, 1, 7)
    $commonTlp.Controls.Add((New-Label "Obfuscate Passwords:"), 0, 8); $chkObfuscate = New-Object Windows.Forms.CheckBox; $chkObfuscate.Anchor = 'Left'; $commonTlp.Controls.Add($chkObfuscate, 1, 8)

    # --- Bottom Buttons (Row 2) ---
    $buttonsFlow = New-Object Windows.Forms.FlowLayoutPanel
    $buttonsFlow.Dock = 'Fill'
    $buttonsFlow.FlowDirection = 'RightToLeft'
    $mainLayout.Controls.Add($buttonsFlow, 0, 2); $mainLayout.SetColumnSpan($buttonsFlow, 2)
    $btnConnect = New-Object Windows.Forms.Button; $btnConnect.Text = "Connect"; $btnConnect.DialogResult = [Windows.Forms.DialogResult]::OK; $btnConnect.Width = 100; $btnConnect.Height = 30
    $btnCancel = New-Object Windows.Forms.Button; $btnCancel.Text = "Cancel"; $btnCancel.DialogResult = [Windows.Forms.DialogResult]::Cancel; $btnCancel.Width = 100; $btnCancel.Height = 30
    $buttonsFlow.Controls.AddRange(@($btnCancel, $btnConnect))

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
        $pnlSerial.Visible = $rbSerial.Checked; $pnlSsh.Visible = $rbSsh.Checked; $pnlTelnet.Visible = $rbTelnet.Checked
    }
    $rbSerial.add_CheckedChanged($UpdateFormForType); $rbSsh.add_CheckedChanged($UpdateFormForType); $rbTelnet.add_CheckedChanged($UpdateFormForType)

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


# --- Main Script Execution ---
while ($true) {
    # Clear-Host # Optional: uncomment to clear screen between sessions
    $global:ConnectionConfig = $null
    $dialogResult = Show-ConnectionConfigMenu

    if ($dialogResult -ne [Windows.Forms.DialogResult]::OK -or !$global:ConnectionConfig) {
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
        switch ($config.Type) {
            "Serial" {
                if ([string]::IsNullOrWhiteSpace($config.COMPort)) { throw "No COM Port selected." }
                $port = New-Object System.IO.Ports.SerialPort($config.COMPort, $config.BaudRate, $config.Parity, $config.DataBits, $config.StopBits)
                $port.Handshake = $config.Handshake
                $port.DtrEnable = $config.DtrEnable
                $port.Open()
                Start-SerialSession -Port $port -Config $config
                $port.Close()
            }
            "SSH" {
                Start-SshSession -Config $config
            }
            "Telnet" {
                Start-TelnetSession -Config $config
            }
        }
    }
    catch {
        Write-Error "Failed to start session: $_"
        Read-Host "Press Enter to return to the menu."
    }

    $choice = Read-Host "`nSession ended. Start a new connection? (Y/N)"
    if ($choice -ne 'y') {
        break
    }
}

Write-Host "Script finished."

