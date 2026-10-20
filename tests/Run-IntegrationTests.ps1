<#
.SYNOPSIS
    PSTerm integration tests: real transports, real processes.

.DESCRIPTION
    Run-Tests.ps1 covers the emulator in isolation. This suite exercises the parts
    that only fail when a real process is on the other end - the pseudo-console
    plumbing, session lifecycle and logging.

    Several of these guard bugs that were genuinely hard to find:
      * A pseudo-console client inherits the parent's standard handles unless they
        are explicitly suppressed, and then writes to PSTerm's stdout instead of
        the terminal. Everything else looks correct, including the attach.
      * conhost keeps the output pipe open for as long as the HPCON is held, so
        session end must be detected from the process, not from EOF.

.EXAMPLE
    powershell -NoProfile -File tests\Run-IntegrationTests.ps1
#>
[CmdletBinding()]
param([switch]$FailFast)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'src\Bootstrap.ps1')
Initialize-PSTermCore -Root $root

$script:Passed = 0
$script:Failed = 0
$script:Failures = New-Object System.Collections.Generic.List[string]

function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try {
        & $Body
        $script:Passed++
        Write-Host "  PASS  $Name" -ForegroundColor DarkGreen
    }
    catch {
        $script:Failed++
        $msg = "  FAIL  $Name`n        $($_.Exception.Message)"
        $script:Failures.Add($msg)
        Write-Host $msg -ForegroundColor Red
        if ($FailFast) { throw }
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Because = '')
    if (-not $Condition) { throw "expected true: $Because" }
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Because = '')
    if ($Expected -ne $Actual) { throw "expected '$Expected' but got '$Actual' $Because" }
}

# Build a headless session around a hosted command.
function New-HeadlessSession {
    param([string]$CommandLine, [int]$Cols = 80, [int]$Rows = 25)

    $term = New-Object PSTerm.Vt.TerminalEmulator($Cols, $Rows, 500)
    $sink = New-Object PSTerm.EmulatorSink($term)
    $dec  = New-Object PSTerm.Vt.StreamDecoder([PSTerm.Vt.TerminalEncoding]::Utf8)
    $be   = New-Object PSTerm.Backends.ConPtyBackend($CommandLine, $null, 'test')
    $be.SetInitialSize($Cols, $Rows)
    $session = New-Object PSTerm.TerminalSession($be, $sink, $term, $dec)
    [pscustomobject]@{ Session = $session; Terminal = $term; Backend = $be }
}

function Get-AllText {
    param($Terminal)
    $sb = New-Object System.Text.StringBuilder
    for ($a = 0; $a -lt $Terminal.Screen.TotalLines; $a++) {
        [void]$sb.AppendLine($Terminal.Screen.GetLineText($a))
    }
    $sb.ToString()
}

Write-Host "`nPSTerm integration tests" -ForegroundColor Cyan
Write-Host ("-" * 60)

# ------------------------------------------------------- environment --------

Write-Host "`nEnvironment" -ForegroundColor Yellow

$ptySupported = [PSTerm.Backends.ConPtyBackend]::IsSupported
$sshPath = [PSTerm.Backends.ConPtyCommands]::FindSsh()

Test-Case 'pseudo-console API is available' {
    Assert-True $ptySupported 'Windows 10 1809 or later is required for SSH and local shell tabs'
}

Test-Case 'the in-box OpenSSH client is present' {
    Assert-True ([bool]$sshPath) 'ssh.exe not found; install the OpenSSH Client optional feature'
}

Write-Host "    ssh.exe: $sshPath" -ForegroundColor DarkGray

# --------------------------------------------------------- pty plumbing -----

Write-Host "`nPseudo-console transport" -ForegroundColor Yellow

if (-not $ptySupported) {
    Write-Host "  SKIP  pty tests (no pseudo-console support)" -ForegroundColor DarkYellow
}
else {

Test-Case 'hosted process output reaches the terminal, not PSTerm stdout' {
    # The regression this guards: with the parent's standard handles inherited,
    # the child writes to our stdout and the terminal stays completely blank.
    $h = New-HeadlessSession "$env:WINDIR\system32\cmd.exe /c echo INTEGRATION_MARKER"
    try {
        $h.Session.Connect()
        Assert-True ($h.Session.WaitForClose(10000)) 'session should end when the command finishes'
        $text = Get-AllText $h.Terminal
        Assert-True ($text -match 'INTEGRATION_MARKER') "terminal did not receive the output. Got: $($text.Trim())"
    }
    finally { $h.Session.Dispose() }
}

Test-Case 'input is delivered and echoed back' {
    $h = New-HeadlessSession "$env:WINDIR\system32\cmd.exe /q"
    try {
        $h.Session.Connect()
        Start-Sleep -Milliseconds 700
        $h.Session.Send("echo ROUNDTRIP_OK`r")
        Start-Sleep -Milliseconds 900
        $text = Get-AllText $h.Terminal
        Assert-True ($text -match 'ROUNDTRIP_OK') "no echo of the sent command. Got: $($text.Trim())"
    }
    finally { $h.Session.Dispose() }
}

Test-Case 'session end is reported promptly when the process exits' {
    # conhost holds the output pipe open while we hold the HPCON, so this can only
    # work if the backend watches the process rather than waiting for EOF.
    $h = New-HeadlessSession "$env:WINDIR\system32\cmd.exe /q"
    try {
        $h.Session.Connect()
        Start-Sleep -Milliseconds 600
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $h.Session.Send("exit`r")
        $closed = $h.Session.WaitForClose(8000)
        $sw.Stop()
        Assert-True $closed "the session never reported closing (waited $($sw.ElapsedMilliseconds) ms)"
        Assert-True (-not $h.Session.IsConnected) 'IsConnected should be false after close'
    }
    finally { $h.Session.Dispose() }
}

Test-Case 'the hosted process exit code is reported' {
    $h = New-HeadlessSession "$env:WINDIR\system32\cmd.exe /c exit 42"
    $script:code = $null
    try {
        $h.Session.Connect()
        Assert-True ($h.Session.WaitForClose(10000)) 'session should end'
        # Read the property rather than catching the event: a PowerShell handler
        # cannot be invoked on the backend's own thread.
        Assert-True $h.Session.HasClosed 'HasClosed should be set'
        Assert-Equal 42 $h.Session.ExitCode
    }
    finally { $h.Session.Dispose() }
}

Test-Case 'resize is accepted while connected' {
    $h = New-HeadlessSession "$env:WINDIR\system32\cmd.exe /q"
    try {
        $h.Session.Connect()
        Start-Sleep -Milliseconds 500
        $h.Session.Resize(120, 40)
        $h.Terminal.Resize(120, 40)
        Assert-Equal 120 $h.Terminal.Cols
        Assert-Equal 40 $h.Terminal.Rows
        Assert-True $h.Session.IsConnected 'resize must not drop the session'
    }
    finally { $h.Session.Dispose() }
}

Test-Case 'disposing a live session terminates the hosted process' {
    $h = New-HeadlessSession "$env:WINDIR\system32\cmd.exe /q"
    $h.Session.Connect()
    Start-Sleep -Milliseconds 500
    $h.Session.Dispose()
    Assert-True (-not $h.Session.IsConnected) 'session should be closed after Dispose'
}

}   # end pty tests

# ------------------------------------------------------- ssh command line ---

Write-Host "`nSSH command line construction" -ForegroundColor Yellow

Test-Case 'a basic SSH command line is well formed' {
    $o = New-Object PSTerm.Backends.SshLaunchOptions
    $o.Host = 'router1.example.net'
    $o.User = 'admin'
    $cmd = [PSTerm.Backends.ConPtyCommands]::BuildSshCommandLine($o)
    Assert-True ($cmd -match 'ssh\.exe') 'should invoke ssh.exe'
    Assert-True ($cmd -match '-t -t') 'should force a PTY'
    Assert-True ($cmd -match 'admin@router1\.example\.net') "user@host missing from: $cmd"
    Assert-True ($cmd -notmatch '\s-p\s') 'port 22 should not be passed explicitly'
}

Test-Case 'a non-default port, key file and jump host are passed through' {
    $o = New-Object PSTerm.Backends.SshLaunchOptions
    $o.Host = 'sw1'; $o.User = 'ops'; $o.Port = 2222
    $o.IdentityFile = 'C:\keys\id_ed25519'
    $o.ProxyJump = 'bastion.example.net'
    $cmd = [PSTerm.Backends.ConPtyCommands]::BuildSshCommandLine($o)
    Assert-True ($cmd -match '-p 2222') "port missing from: $cmd"
    Assert-True ($cmd -match 'id_ed25519') "identity file missing from: $cmd"
    Assert-True ($cmd -match '-J ') "proxy jump missing from: $cmd"
}

Test-Case 'legacy algorithms are opt-in, not the default' {
    $o = New-Object PSTerm.Backends.SshLaunchOptions
    $o.Host = 'oldswitch'
    $modern = [PSTerm.Backends.ConPtyCommands]::BuildSshCommandLine($o)
    Assert-True ($modern -notmatch 'diffie-hellman-group1-sha1') 'legacy KEX must be off by default'

    $o.AllowLegacyAlgorithms = $true
    $legacy = [PSTerm.Backends.ConPtyCommands]::BuildSshCommandLine($o)
    Assert-True ($legacy -match 'diffie-hellman-group1-sha1') 'legacy KEX should be offered when asked for'
    Assert-True ($legacy -match 'ssh-rsa') 'legacy host key algorithms should be offered when asked for'
}

Test-Case 'keep-alive becomes ServerAliveInterval' {
    $o = New-Object PSTerm.Backends.SshLaunchOptions
    $o.Host = 'h'; $o.KeepAliveSeconds = 30
    $cmd = [PSTerm.Backends.ConPtyCommands]::BuildSshCommandLine($o)
    Assert-True ($cmd -match 'ServerAliveInterval=30') "keep-alive missing from: $cmd"
}

Test-Case 'paths containing spaces are quoted' {
    $o = New-Object PSTerm.Backends.SshLaunchOptions
    $o.Host = 'h'; $o.IdentityFile = 'C:\my keys\id_rsa'
    $cmd = [PSTerm.Backends.ConPtyCommands]::BuildSshCommandLine($o)
    Assert-True ($cmd -match '"C:\\my keys\\id_rsa"') "identity file not quoted in: $cmd"
}

# ------------------------------------------------------------- logging ------

Write-Host "`nSession logging" -ForegroundColor Yellow

$logDir = Join-Path ([System.IO.Path]::GetTempPath()) ("psterm-tests-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $logDir -Force | Out-Null

function New-Tokens {
    param([hashtable]$Pairs)
    $d = New-Object 'System.Collections.Generic.Dictionary[string,string]'
    foreach ($k in $Pairs.Keys) { $d[$k] = [string]$Pairs[$k] }
    $d
}

try {

Test-Case 'path templates expand host, session and date tokens' {
    $tokens = New-Tokens @{ host = 'core-sw1'; session = 'Lab' }
    $expanded = [PSTerm.Io.SessionLogger]::ExpandTemplate('C:\logs\{host}\{session}-{date}.log', $tokens)
    Assert-True ($expanded -match 'core-sw1') "host token not expanded: $expanded"
    Assert-True ($expanded -match 'Lab')      "session token not expanded: $expanded"
    Assert-True ($expanded -match '\d{4}-\d{2}-\d{2}') "date token not expanded: $expanded"
}

Test-Case 'characters illegal in a filename are replaced' {
    $tokens = New-Tokens @{ host = 'a/b:c*d' }
    $expanded = [PSTerm.Io.SessionLogger]::ExpandTemplate('C:\logs\{host}.log', $tokens)
    # Only the substituted token is sanitised; the drive colon must survive.
    $leaf = Split-Path -Leaf $expanded
    Assert-Equal 'a_b_c_d.log' $leaf
    Assert-True ($expanded.StartsWith('C:\logs')) "the template's own path was mangled: $expanded"
}

Test-Case 'unknown tokens are dropped rather than left as braces' {
    $expanded = [PSTerm.Io.SessionLogger]::ExpandTemplate('C:\logs\{nosuch}x.log', (New-Tokens @{}))
    Assert-True ($expanded -notmatch '[{}]') "braces left behind: $expanded"
}

Test-Case 'plain text logging strips escape sequences' {
    $path = Join-Path $logDir 'plain.log'
    $opts = New-Object PSTerm.Io.SessionLoggerOptions
    $opts.PathTemplate = $path
    $opts.Format = [PSTerm.Io.LogFormat]::PlainText
    $logger = New-Object PSTerm.Io.SessionLogger($opts, (New-Tokens @{}))
    $esc = [char]27
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("${esc}[31mRED${esc}[0m plain`r`n")
    $logger.WriteFromHost($bytes, 0, $bytes.Length)
    $logger.Close()
    $content = Get-Content -Raw -LiteralPath $path
    Assert-True ($content -match 'RED plain') "expected text missing. Got: '$content'"
    Assert-True ($content -notmatch "$esc") 'escape sequences should be stripped'
}

Test-Case 'raw logging preserves the bytes exactly' {
    $path = Join-Path $logDir 'raw.log'
    $opts = New-Object PSTerm.Io.SessionLoggerOptions
    $opts.PathTemplate = $path
    $opts.Format = [PSTerm.Io.LogFormat]::Raw
    $logger = New-Object PSTerm.Io.SessionLogger($opts, (New-Tokens @{}))
    $esc = [char]27
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("${esc}[31mRED")
    $logger.WriteFromHost($bytes, 0, $bytes.Length)
    $logger.Close()
    $content = Get-Content -Raw -LiteralPath $path
    Assert-True ($content -match "$esc\[31m") 'raw mode must keep escape sequences'
}

Test-Case 'timestamped logging prefixes each line' {
    $path = Join-Path $logDir 'stamped.log'
    $opts = New-Object PSTerm.Io.SessionLoggerOptions
    $opts.PathTemplate = $path
    $opts.Format = [PSTerm.Io.LogFormat]::Timestamped
    $logger = New-Object PSTerm.Io.SessionLogger($opts, (New-Tokens @{}))
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("first`r`nsecond`r`n")
    $logger.WriteFromHost($bytes, 0, $bytes.Length)
    $logger.Close()
    $lines = @(Get-Content -LiteralPath $path | Where-Object { $_.Trim() })
    Assert-True ($lines.Count -ge 2) "expected two lines, got $($lines.Count)"
    foreach ($l in $lines) {
        Assert-True ($l -match '^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}') "line not timestamped: '$l'"
    }
}

Test-Case 'typed passwords are masked after a password prompt' {
    $path = Join-Path $logDir 'masked.log'
    $opts = New-Object PSTerm.Io.SessionLoggerOptions
    $opts.PathTemplate = $path
    $opts.IncludeInput = $true
    $opts.MaskPasswords = $true
    $logger = New-Object PSTerm.Io.SessionLogger($opts, (New-Tokens @{}))

    $prompt = [System.Text.Encoding]::UTF8.GetBytes("admin@sw1's password: ")
    $logger.WriteFromHost($prompt, 0, $prompt.Length)
    Start-Sleep -Milliseconds 300
    $secret = [System.Text.Encoding]::UTF8.GetBytes("hunter2`r")
    $logger.WriteFromUser($secret, 0, $secret.Length)
    $logger.Close()

    $content = Get-Content -Raw -LiteralPath $path
    Assert-True ($content -notmatch 'hunter2') "the password was written to the log: '$content'"
    Assert-True ($content -match '\*{7}') "expected masking asterisks. Got: '$content'"
}

Test-Case 'backspace is applied so logs show the final command' {
    $path = Join-Path $logDir 'backspace.log'
    $opts = New-Object PSTerm.Io.SessionLoggerOptions
    $opts.PathTemplate = $path
    $logger = New-Object PSTerm.Io.SessionLogger($opts, (New-Tokens @{}))
    # "shwo" + two backspaces leaves "sh", then "ow ver" gives "show ver".
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("shwo`b`bow ver")
    $logger.WriteFromHost($bytes, 0, $bytes.Length)
    $logger.Close()
    $content = Get-Content -Raw -LiteralPath $path
    Assert-True ($content -match 'show ver') "backspaces not applied. Got: '$content'"
}

Test-Case 'an escape sequence split across two writes does not leak' {
    $path = Join-Path $logDir 'split.log'
    $opts = New-Object PSTerm.Io.SessionLoggerOptions
    $opts.PathTemplate = $path
    $logger = New-Object PSTerm.Io.SessionLogger($opts, (New-Tokens @{}))
    $esc = [char]27
    $a = [System.Text.Encoding]::UTF8.GetBytes("${esc}[3")
    $b = [System.Text.Encoding]::UTF8.GetBytes("1mVISIBLE")
    $logger.WriteFromHost($a, 0, $a.Length)
    Start-Sleep -Milliseconds 300
    $logger.WriteFromHost($b, 0, $b.Length)
    $logger.Close()
    $content = Get-Content -Raw -LiteralPath $path
    Assert-True ($content -match 'VISIBLE') "text lost. Got: '$content'"
    Assert-True ($content -notmatch '1m') "the tail of the split sequence leaked into the log: '$content'"
}

}
finally {
    Remove-Item -LiteralPath $logDir -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------- summary ---

Write-Host ""
Write-Host ("-" * 60)
$total = $script:Passed + $script:Failed
if ($script:Failed -eq 0) {
    Write-Host "All $total integration tests passed." -ForegroundColor Green
    exit 0
}
else {
    Write-Host "$($script:Failed) of $total integration tests FAILED." -ForegroundColor Red
    Write-Host ""
    foreach ($f in $script:Failures) { Write-Host $f -ForegroundColor Red }
    exit 1
}
