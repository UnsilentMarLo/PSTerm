<#
.SYNOPSIS
    PSTerm core test suite.

.DESCRIPTION
    Feeds byte and character streams through the terminal emulator and asserts the
    resulting screen. Deliberately dependency-free (no Pester) so it runs on a bare
    Windows machine, offline, on both Windows PowerShell 5.1 and PowerShell 7.

.EXAMPLE
    powershell -NoProfile -File tests\Run-Tests.ps1
#>
[CmdletBinding()]
param(
    [switch]$FailFast
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'src\Bootstrap.ps1')
Initialize-PSTermCore -Root $root

# ---------------------------------------------------------------- harness ----

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

function Assert-Equal {
    param($Expected, $Actual, [string]$Because = '')
    if ($Expected -ne $Actual) {
        $e = if ($null -eq $Expected) { '<null>' } else { "'$Expected'" }
        $a = if ($null -eq $Actual)   { '<null>' } else { "'$Actual'" }
        throw "expected $e but got $a $Because"
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Because = '')
    if (-not $Condition) { throw "expected true: $Because" }
}

# Build an emulator and feed it text.
function New-Term {
    param([int]$Cols = 20, [int]$Rows = 5, [int]$Scrollback = 100)
    New-Object PSTerm.Vt.TerminalEmulator($Cols, $Rows, $Scrollback)
}

function Write-Term {
    param($Term, [string]$Text)
    $Term.Write($Text)
}

# Visible row as trimmed text.
function Get-Row {
    param($Term, [int]$Row)
    $screen = $Term.Screen
    $abs = $screen.HistoryCount + $Row
    $screen.GetLineText($abs)
}

function Get-ScreenText {
    param($Term)
    $lines = @()
    for ($r = 0; $r -lt $Term.Rows; $r++) { $lines += (Get-Row $Term $r) }
    ($lines -join "`n")
}

$ESC = [char]27

Write-Host "`nPSTerm core tests" -ForegroundColor Cyan
Write-Host ("-" * 60)

# ------------------------------------------------------------ printing -------

Write-Host "`nPrinting and wrapping" -ForegroundColor Yellow

Test-Case 'plain text lands on row 0' {
    $t = New-Term
    Write-Term $t 'hello'
    Assert-Equal 'hello' (Get-Row $t 0)
    Assert-Equal 5 $t.CursorX
}

Test-Case 'CR LF moves to the next line' {
    $t = New-Term
    Write-Term $t "one`r`ntwo"
    Assert-Equal 'one' (Get-Row $t 0)
    Assert-Equal 'two' (Get-Row $t 1)
}

Test-Case 'bare LF does not return the carriage (no NewLineMode)' {
    $t = New-Term
    Write-Term $t "abc`ndef"
    Assert-Equal 'abc' (Get-Row $t 0)
    # Column is preserved, so 'def' starts at column 3.
    Assert-Equal '   def' (Get-Row $t 1)
}

Test-Case 'autowrap is deferred at the right margin' {
    $t = New-Term -Cols 5 -Rows 3
    Write-Term $t '12345'
    # After the 5th character the cursor stays on row 0 with wrap pending.
    Assert-Equal 0 $t.CursorY
    Write-Term $t '6'
    Assert-Equal '12345' (Get-Row $t 0)
    Assert-Equal '6' (Get-Row $t 1)
}

Test-Case 'autowrap off overwrites the last column' {
    $t = New-Term -Cols 5 -Rows 3
    Write-Term $t "$ESC[?7l"      # DECAWM off
    Write-Term $t '1234567'
    Assert-Equal 0 $t.CursorY
    Assert-Equal '12347' (Get-Row $t 0)
}

Test-Case 'backspace steps back and overwrites' {
    $t = New-Term
    Write-Term $t "abc`b`bX"
    Assert-Equal 'aXc' (Get-Row $t 0)
}

# ------------------------------------------------------- cursor addressing ---

Write-Host "`nCursor addressing" -ForegroundColor Yellow

Test-Case 'CUP positions the cursor (1-based)' {
    $t = New-Term
    Write-Term $t "$ESC[3;5Hx"
    Assert-Equal '    x' (Get-Row $t 2)
}

Test-Case 'CUP with omitted parameters homes the cursor' {
    $t = New-Term
    Write-Term $t "line0`r`nline1"
    Write-Term $t "$ESC[HX"
    Assert-Equal 'Xine0' (Get-Row $t 0)
}

Test-Case 'CUU/CUD/CUF/CUB move relatively' {
    $t = New-Term
    Write-Term $t "$ESC[5;10H"      # row 4, col 9
    Write-Term $t "$ESC[2A"         # up 2   -> row 2
    Write-Term $t "$ESC[3D"         # left 3 -> col 6
    Write-Term $t 'Z'
    Assert-Equal '      Z' (Get-Row $t 2)
}

Test-Case 'cursor movement clamps at screen edges' {
    $t = New-Term
    Write-Term $t "$ESC[999;999Hx"
    Assert-Equal 4 $t.CursorY
    # The cursor parks on the last column with wrap pending; it never sits past it.
    Assert-Equal 19 $t.CursorX
}

Test-Case 'VPA and CHA set row and column independently' {
    $t = New-Term
    Write-Term $t "$ESC[3d"    # row 2
    Write-Term $t "$ESC[7G"    # col 6
    Write-Term $t 'Q'
    Assert-Equal '      Q' (Get-Row $t 2)
}

# ------------------------------------------------------------- erasing ------

Write-Host "`nErasing" -ForegroundColor Yellow

Test-Case 'EL 0 erases from the cursor to end of line' {
    $t = New-Term
    Write-Term $t 'abcdefgh'
    Write-Term $t "$ESC[1;4H$ESC[0K"
    Assert-Equal 'abc' (Get-Row $t 0)
}

Test-Case 'EL 1 erases from line start to the cursor' {
    $t = New-Term
    Write-Term $t 'abcdefgh'
    Write-Term $t "$ESC[1;4H$ESC[1K"
    Assert-Equal '    efgh' (Get-Row $t 0)
}

Test-Case 'ED 2 clears the whole screen' {
    $t = New-Term
    Write-Term $t "aaa`r`nbbb`r`nccc"
    Write-Term $t "$ESC[2J"
    Assert-Equal '' (Get-ScreenText $t).Replace("`n", '')
}

Test-Case 'ECH erases n characters in place' {
    $t = New-Term
    Write-Term $t 'abcdefgh'
    Write-Term $t "$ESC[1;3H$ESC[3X"
    Assert-Equal 'ab   fgh' (Get-Row $t 0)
}

# ------------------------------------------------------- scroll regions -----

Write-Host "`nScroll regions and line editing" -ForegroundColor Yellow

Test-Case 'DECSTBM confines scrolling to the region' {
    $t = New-Term -Cols 10 -Rows 5
    Write-Term $t "r0`r`nr1`r`nr2`r`nr3`r`nr4"
    Write-Term $t "$ESC[2;4r"       # region = rows 1..3
    Write-Term $t "$ESC[4;1H"       # bottom of the region
    Write-Term $t "`n"              # scrolls the region only
    Assert-Equal 'r0' (Get-Row $t 0)   # untouched
    Assert-Equal 'r2' (Get-Row $t 1)   # scrolled up
    Assert-Equal 'r3' (Get-Row $t 2)
    Assert-Equal ''   (Get-Row $t 3)   # blanked
    Assert-Equal 'r4' (Get-Row $t 4)   # untouched
}

Test-Case 'DECSTBM homes the cursor' {
    $t = New-Term
    Write-Term $t "$ESC[2;4r"
    Assert-Equal 0 $t.CursorY
    Assert-Equal 0 $t.CursorX
}

Test-Case 'IL inserts blank lines within the region' {
    $t = New-Term -Cols 10 -Rows 4
    Write-Term $t "a`r`nb`r`nc"
    Write-Term $t "$ESC[2;1H$ESC[1L"
    Assert-Equal 'a' (Get-Row $t 0)
    Assert-Equal ''  (Get-Row $t 1)
    Assert-Equal 'b' (Get-Row $t 2)
}

Test-Case 'DL deletes lines and pulls the rest up' {
    $t = New-Term -Cols 10 -Rows 4
    Write-Term $t "a`r`nb`r`nc"
    Write-Term $t "$ESC[2;1H$ESC[1M"
    Assert-Equal 'a' (Get-Row $t 0)
    Assert-Equal 'c' (Get-Row $t 1)
}

Test-Case 'ICH and DCH shift within the line' {
    $t = New-Term
    Write-Term $t 'abcdef'
    Write-Term $t "$ESC[1;3H$ESC[2@"
    Assert-Equal 'ab  cdef' (Get-Row $t 0)
    $t2 = New-Term
    Write-Term $t2 'abcdef'
    Write-Term $t2 "$ESC[1;3H$ESC[2P"
    Assert-Equal 'abef' (Get-Row $t2 0)
}

Test-Case 'RI at the top of the region scrolls down' {
    $t = New-Term -Cols 10 -Rows 3
    Write-Term $t "x`r`ny`r`nz"
    Write-Term $t "$ESC[1;1H${ESC}M"
    Assert-Equal ''  (Get-Row $t 0)
    Assert-Equal 'x' (Get-Row $t 1)
}

# ------------------------------------------------- DEC line drawing ---------

Write-Host "`nDEC Special Graphics (vendor menu rendering)" -ForegroundColor Yellow

Test-Case 'ESC ( 0 switches G0 to the line-drawing set' {
    $t = New-Term
    Write-Term $t "$ESC(0lqqqk"
    # l q q q k  ->  upper-left, three horizontals, upper-right
    Assert-Equal "$([char]0x250C)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2510)" (Get-Row $t 0)
}

Test-Case 'SO/SI shift between G1 and G0 mid-line' {
    $t = New-Term
    # Designate G1 as line drawing, then shift in and out around a label.
    Write-Term $t "$ESC)0"
    Write-Term $t "$([char]14)x$([char]15)OK$([char]14)x"
    Assert-Equal "$([char]0x2502)OK$([char]0x2502)" (Get-Row $t 0)
}

Test-Case 'ESC ( B restores ASCII' {
    $t = New-Term
    Write-Term $t "$ESC(0q$ESC(Bq"
    Assert-Equal "$([char]0x2500)q" (Get-Row $t 0)
}

Test-Case 'UK charset maps hash to sterling' {
    $t = New-Term
    Write-Term $t "$ESC(A#"
    Assert-Equal ([char]0x00A3).ToString() (Get-Row $t 0)
}

# ------------------------------------------------------- alternate screen ---

Write-Host "`nAlternate screen" -ForegroundColor Yellow

Test-Case '1049 switches to a blank alternate screen and back' {
    $t = New-Term
    Write-Term $t 'primary content'
    Write-Term $t "$ESC[?1049h"
    Assert-True $t.IsAlternateScreen 'should be on the alternate screen'
    Assert-Equal '' (Get-Row $t 0)
    Write-Term $t 'alt content'
    Assert-Equal 'alt content' (Get-Row $t 0)
    Write-Term $t "$ESC[?1049l"
    Assert-True (-not $t.IsAlternateScreen) 'should be back on the primary screen'
    Assert-Equal 'primary content' (Get-Row $t 0)
}

Test-Case 'alternate screen keeps no scrollback' {
    $t = New-Term -Cols 10 -Rows 2
    Write-Term $t "$ESC[?1049h"
    Write-Term $t "a`r`nb`r`nc`r`nd"
    Assert-Equal 0 $t.Screen.HistoryCount
}

# --------------------------------------------------------------- SGR --------

Write-Host "`nRendition" -ForegroundColor Yellow

Test-Case 'SGR sets and resets bold' {
    $t = New-Term
    Write-Term $t "$ESC[1mB$ESC[0mN"
    $bold  = $t.Screen.GetCell(0, 0)
    $norm  = $t.Screen.GetCell(0, 1)
    $boldBit = [int][PSTerm.Vt.CellFlags]::Bold
    Assert-True (([int]$bold.Flags -band $boldBit) -ne 0) 'first cell bold'
    Assert-True (([int]$norm.Flags -band $boldBit) -eq 0) 'second cell not bold'
}

Test-Case 'SGR 31 sets an indexed foreground' {
    $t = New-Term
    Write-Term $t "$ESC[31mR"
    $c = $t.Screen.GetCell(0, 0)
    Assert-True $c.Fg.IsIndexed 'foreground is indexed'
    Assert-Equal 1 $c.Fg.Index
}

Test-Case 'SGR 38;5;n sets a 256-colour foreground' {
    $t = New-Term
    Write-Term $t "$ESC[38;5;196mX"
    $c = $t.Screen.GetCell(0, 0)
    Assert-Equal 196 $c.Fg.Index
}

Test-Case 'SGR 38;2;r;g;b sets a truecolor foreground' {
    $t = New-Term
    Write-Term $t "$ESC[38;2;10;20;30mX"
    $c = $t.Screen.GetCell(0, 0)
    Assert-True $c.Fg.IsRgb 'foreground is rgb'
    Assert-Equal 10 $c.Fg.R
    Assert-Equal 20 $c.Fg.G
    Assert-Equal 30 $c.Fg.B
}

Test-Case 'SGR 48;2 colon sub-parameter form does not corrupt the screen' {
    $t = New-Term
    # Some hosts emit the colon form; it must be consumed, not printed.
    Write-Term $t "$ESC[48:2::10:20:30mX"
    Assert-Equal 'X' (Get-Row $t 0)
}

Test-Case 'bright colour codes 90-97 map to the upper palette' {
    $t = New-Term
    Write-Term $t "$ESC[92mX"
    Assert-Equal 10 $t.Screen.GetCell(0, 0).Fg.Index
}

# ------------------------------------------------------------- encoding -----

Write-Host "`nEncoding" -ForegroundColor Yellow

Test-Case 'UTF-8 split across two reads decodes intact' {
    # This is the v1 mojibake bug: 'ä' is 0xC3 0xA4 and was split by the 4 KB read.
    $dec = New-Object PSTerm.Vt.StreamDecoder([PSTerm.Vt.TerminalEncoding]::Utf8)
    $t = New-Term

    $n = 0
    $chars = $dec.Decode([byte[]]@(0x61, 0xC3), 0, 2, [ref]$n)
    $t.Write($chars, 0, $n)
    $chars = $dec.Decode([byte[]]@(0xA4, 0x62), 0, 2, [ref]$n)
    $t.Write($chars, 0, $n)

    Assert-Equal "a$([char]0x00E4)b" (Get-Row $t 0)
}

Test-Case 'invalid UTF-8 becomes a replacement char, not a dropped byte' {
    $dec = New-Object PSTerm.Vt.StreamDecoder([PSTerm.Vt.TerminalEncoding]::Utf8)
    $t = New-Term
    $n = 0
    $chars = $dec.Decode([byte[]]@(0x41, 0xFF, 0x42), 0, 3, [ref]$n)
    $t.Write($chars, 0, $n)
    $row = Get-Row $t 0
    Assert-Equal 3 $row.Length "got '$row'"
    Assert-Equal 'A' $row[0]
    Assert-Equal 'B' $row[2]
}

Test-Case 'Latin-1 maps every byte to the same code point' {
    $dec = New-Object PSTerm.Vt.StreamDecoder([PSTerm.Vt.TerminalEncoding]::Latin1)
    $t = New-Term
    $n = 0
    $chars = $dec.Decode([byte[]]@(0xE4), 0, 1, [ref]$n)
    $t.Write($chars, 0, $n)
    Assert-Equal ([char]0x00E4).ToString() (Get-Row $t 0)
}

# ------------------------------------------------- malformed input ----------

Write-Host "`nMalformed and hostile input" -ForegroundColor Yellow

Test-Case 'truncated CSI does not swallow following text' {
    $t = New-Term
    # A sequence cut short by a new ESC: the parser must abandon it, not hang.
    Write-Term $t "$ESC[12$ESC[1;1HOK"
    Assert-Equal 'OK' (Get-Row $t 0)
}

Test-Case 'unknown CSI final byte is discarded silently' {
    $t = New-Term
    Write-Term $t "$ESC[1;2;3{visible"
    Assert-Equal 'visible' (Get-Row $t 0)
}

Test-Case 'CAN aborts a sequence in progress' {
    $t = New-Term
    Write-Term $t "$ESC[1;1$([char]24)text"
    Assert-Equal 'text' (Get-Row $t 0)
}

Test-Case 'enormous parameter values are clamped, not overflowed' {
    $t = New-Term
    Write-Term $t "$ESC[99999999999999999999;1Hx"
    Assert-Equal 4 $t.CursorY   # clamped to the last row
}

Test-Case 'unterminated OSC does not consume the rest of the session' {
    $t = New-Term
    Write-Term $t "$ESC]0;title$ESC[1;1Hafter"
    Assert-Equal 'after' (Get-Row $t 0)
}

Test-Case 'OSC terminated by BEL sets the title' {
    $t = New-Term
    $script:title = $null
    $handler = [Action[string]]{ param($s) $script:title = $s }
    $t.add_TitleChanged($handler)
    Write-Term $t "$ESC]0;my-router$([char]7)"
    Assert-Equal 'my-router' $script:title
}

Test-Case 'NUL bytes in the stream are ignored' {
    $t = New-Term
    Write-Term $t "a$([char]0)b"
    Assert-Equal 'ab' (Get-Row $t 0)
}

# ----------------------------------------------------------- scrollback -----

Write-Host "`nScrollback" -ForegroundColor Yellow

Test-Case 'lines scrolled off the top enter history' {
    $t = New-Term -Cols 10 -Rows 3 -Scrollback 50
    for ($i = 0; $i -lt 6; $i++) { Write-Term $t "line$i`r`n" }
    Assert-True ($t.Screen.HistoryCount -ge 3) "history was $($t.Screen.HistoryCount)"
    Assert-Equal 'line0' $t.Screen.GetLineText(0)
}

Test-Case 'history is capped at the configured limit' {
    $t = New-Term -Cols 10 -Rows 3 -Scrollback 5
    for ($i = 0; $i -lt 40; $i++) { Write-Term $t "l$i`r`n" }
    Assert-True ($t.Screen.HistoryCount -le 5) "history was $($t.Screen.HistoryCount)"
}

Test-Case 'ED 3 clears the scrollback' {
    $t = New-Term -Cols 10 -Rows 3 -Scrollback 50
    for ($i = 0; $i -lt 10; $i++) { Write-Term $t "l$i`r`n" }
    Write-Term $t "$ESC[3J"
    Assert-Equal 0 $t.Screen.HistoryCount
}

# --------------------------------------------------------------- resize -----

Write-Host "`nResize" -ForegroundColor Yellow

Test-Case 'narrowing truncates without losing other rows' {
    $t = New-Term -Cols 20 -Rows 4
    Write-Term $t "abcdefghij`r`nklmno"
    $t.Resize(5, 4)
    Assert-Equal 'abcde' (Get-Row $t 0)
    Assert-Equal 'klmno' (Get-Row $t 1)
}

Test-Case 'growing the height pulls lines back out of history' {
    $t = New-Term -Cols 10 -Rows 3 -Scrollback 50
    for ($i = 0; $i -lt 6; $i++) { Write-Term $t "l$i`r`n" }
    $before = $t.Screen.HistoryCount
    $t.Resize(10, 6)
    Assert-True ($t.Screen.HistoryCount -lt $before) 'history should shrink as rows grow'
}

Test-Case 'resize keeps the cursor inside the grid' {
    $t = New-Term -Cols 20 -Rows 10
    Write-Term $t "$ESC[9;18Hx"
    $t.Resize(5, 3)
    Assert-True ($t.CursorY -lt 3) "cursor row $($t.CursorY)"
    Assert-True ($t.CursorX -lt 5) "cursor col $($t.CursorX)"
}

# ---------------------------------------------------------------- reports ---

Write-Host "`nDevice reports" -ForegroundColor Yellow

Test-Case 'DSR 6 reports the cursor position' {
    $t = New-Term
    $script:reply = ''
    $t.add_Respond([Action[string]]{ param($s) $script:reply += $s })
    Write-Term $t "$ESC[3;7H$ESC[6n"
    Assert-Equal "$ESC[3;7R" $script:reply
}

Test-Case 'DA1 identifies as a VT220-class terminal' {
    $t = New-Term
    $script:reply = ''
    $t.add_Respond([Action[string]]{ param($s) $script:reply += $s })
    Write-Term $t "$ESC[c"
    Assert-True ($script:reply.StartsWith("$ESC[?62;")) "got '$($script:reply)'"
}

Test-Case 'DSR 5 reports terminal OK' {
    $t = New-Term
    $script:reply = ''
    $t.add_Respond([Action[string]]{ param($s) $script:reply += $s })
    Write-Term $t "$ESC[5n"
    Assert-Equal "$ESC[0n" $script:reply
}

# ------------------------------------------------------------ key encoding --

Write-Host "`nKey encoding" -ForegroundColor Yellow

$ke = New-Object PSTerm.Vt.KeyEncoder(( New-Object PSTerm.Vt.KeyEncoderSettings ))
$K = [PSTerm.Vt.TermKey]
$M = [PSTerm.Vt.TermModifiers]

Test-Case 'Escape reaches the device (v1 stole it for quit)' {
    Assert-Equal "$ESC" ($ke.Encode($K::Escape, [char]0, $M::None, $false, $false))
}

Test-Case 'arrows use CSI normally and SS3 in application mode' {
    Assert-Equal "$ESC[A"  ($ke.Encode($K::Up, [char]0, $M::None, $false, $false))
    Assert-Equal "${ESC}OA" ($ke.Encode($K::Up, [char]0, $M::None, $true,  $false))
}

Test-Case 'modified arrows use the CSI 1;m form even in application mode' {
    Assert-Equal "$ESC[1;5A" ($ke.Encode($K::Up, [char]0, $M::Control, $true, $false))
    Assert-Equal "$ESC[1;2A" ($ke.Encode($K::Up, [char]0, $M::Shift,   $false, $false))
}

Test-Case 'backspace mode is selectable' {
    $s = New-Object PSTerm.Vt.KeyEncoderSettings
    $s.Backspace = [PSTerm.Vt.BackspaceMode]::Delete
    $d = New-Object PSTerm.Vt.KeyEncoder($s)
    Assert-Equal "$([char]0x7F)" ($d.Encode($K::Backspace, [char]0, $M::None, $false, $false))

    $s2 = New-Object PSTerm.Vt.KeyEncoderSettings
    $s2.Backspace = [PSTerm.Vt.BackspaceMode]::Backspace
    $b = New-Object PSTerm.Vt.KeyEncoder($s2)
    Assert-Equal "$([char]8)" ($b.Encode($K::Backspace, [char]0, $M::None, $false, $false))
}

Test-Case 'Home and End use the xterm forms' {
    Assert-Equal "$ESC[H" ($ke.Encode($K::Home, [char]0, $M::None, $false, $false))
    Assert-Equal "$ESC[F" ($ke.Encode($K::End,  [char]0, $M::None, $false, $false))
}

Test-Case 'Delete sends CSI 3 tilde' {
    Assert-Equal "$ESC[3~" ($ke.Encode($K::Delete, [char]0, $M::None, $false, $false))
}

Test-Case 'function keys F1-F4 use SS3, F5+ use CSI tilde' {
    Assert-Equal "${ESC}OP"  ($ke.Encode($K::F1, [char]0, $M::None, $false, $false))
    Assert-Equal "$ESC[15~" ($ke.Encode($K::F5, [char]0, $M::None, $false, $false))
    Assert-Equal "$ESC[24~" ($ke.Encode($K::F12, [char]0, $M::None, $false, $false))
}

Test-Case 'VT220 function key mode changes F1-F4' {
    $s = New-Object PSTerm.Vt.KeyEncoderSettings
    $s.FunctionKeys = [PSTerm.Vt.FunctionKeyMode]::Vt220
    $v = New-Object PSTerm.Vt.KeyEncoder($s)
    Assert-Equal "$ESC[11~" ($v.Encode($K::F1, [char]0, $M::None, $false, $false))
}

Test-Case 'Ctrl+letter produces the control code' {
    Assert-Equal "$([char]3)"  ($ke.Encode($K::Char, 'c', $M::Control, $false, $false))
    Assert-Equal "$([char]26)" ($ke.Encode($K::Char, 'z', $M::Control, $false, $false))
}

Test-Case 'Ctrl+punctuation produces the classic codes' {
    Assert-Equal "$ESC"        ($ke.Encode($K::Char, '[',  $M::Control, $false, $false))
    Assert-Equal "$([char]29)" ($ke.Encode($K::Char, ']',  $M::Control, $false, $false))
    Assert-Equal "$([char]28)" ($ke.Encode($K::Char, '\',  $M::Control, $false, $false))
    Assert-Equal "$([char]0)"  ($ke.Encode($K::Space, ' ', $M::Control, $false, $false))
}

Test-Case 'Alt prefixes with ESC' {
    Assert-Equal "${ESC}x" ($ke.Encode($K::Char, 'x', $M::Alt, $false, $false))
}

Test-Case 'Shift+Tab sends back-tab' {
    Assert-Equal "$ESC[Z" ($ke.Encode($K::Tab, [char]0, $M::Shift, $false, $false))
}

Test-Case 'keypad changes in application mode' {
    Assert-Equal '5'       ($ke.Encode($K::Keypad5, [char]0, $M::None, $false, $false))
    Assert-Equal "${ESC}Ou" ($ke.Encode($K::Keypad5, [char]0, $M::None, $false, $true))
}

Test-Case 'SGR mouse encoding works past column 223' {
    $enc = [PSTerm.Vt.KeyEncoder]::EncodeMouse(
        [PSTerm.Vt.MouseMode]::Click, [PSTerm.Vt.MouseEncoding]::Sgr,
        0, $true, 300, 5, $M::None)
    Assert-Equal "$ESC[<0;301;6M" $enc
}

Test-Case 'X10 mouse encoding refuses coordinates it cannot express' {
    $enc = [PSTerm.Vt.KeyEncoder]::EncodeMouse(
        [PSTerm.Vt.MouseMode]::Click, [PSTerm.Vt.MouseEncoding]::X10,
        0, $true, 300, 5, $M::None)
    Assert-Equal $null $enc
}

# ------------------------------------------------------------- selection ----

Write-Host "`nText extraction" -ForegroundColor Yellow

Test-Case 'wrapped lines copy back as one logical line' {
    $t = New-Term -Cols 5 -Rows 4
    Write-Term $t 'abcdefgh'
    $text = $t.Screen.GetText(0, 0, 1, 3, $false)
    Assert-Equal 'abcdefgh' $text
}

Test-Case 'hard-wrapped lines keep their newline' {
    $t = New-Term -Cols 10 -Rows 4
    Write-Term $t "ab`r`ncd"
    $text = $t.Screen.GetText(0, 0, 1, 2, $false)
    Assert-Equal "ab`r`ncd" $text
}

Test-Case 'rectangular selection takes the same columns from each row' {
    $t = New-Term -Cols 10 -Rows 4
    Write-Term $t "12345`r`nabcde`r`nvwxyz"
    $text = $t.Screen.GetText(0, 1, 2, 4, $true)
    Assert-Equal "234`r`nbcd`r`nwxy" $text
}


# ------------------------------------------------------ telnet protocol ----

Write-Host "`nTelnet protocol" -ForegroundColor Yellow

$IAC=255; $DONT=254; $DO=253; $WONT=252; $WILL=251; $SB=250; $SE=240; $NOP=241
$O_BIN=0; $O_ECHO=1; $O_SGA=3; $O_TTYPE=24; $O_NAWS=31

function New-Telnet {
    param([switch]$NoBinary)
    $cfg = New-Object PSTerm.Backends.TelnetSettings
    $cfg.Host = 'test'
    if ($NoBinary) { $cfg.Binary = $false }
    $be = New-Object PSTerm.Backends.TelnetBackend($cfg)
    $ms = New-Object System.IO.MemoryStream
    $be.TestCaptureOutput($ms)
    [pscustomobject]@{ Backend = $be; Sink = $ms }
}

function Get-Sent { param($T) ,$T.Sink.ToArray() }

function Assert-Contains3 {
    param([byte[]]$Bytes, [int]$A, [int]$B, [int]$C, [string]$Label)
    for ($i = 0; $i -le $Bytes.Length - 3; $i++) {
        if ($Bytes[$i] -eq $A -and $Bytes[$i+1] -eq $B -and $Bytes[$i+2] -eq $C) { return }
    }
    throw "expected $Label in the telnet stream; got: $(($Bytes | ForEach-Object { $_ }) -join ',')"
}

function Invoke-Telnet {
    # NOTE: the parameter cannot be called $Input - that is PowerShell's automatic
    # pipeline-enumerator variable and binding to it silently yields an enumerator.
    param($T, [byte[]]$Bytes)
    $out = New-Object byte[] 8192
    $n = $T.Backend.TestProcessIncoming($Bytes, $Bytes.Length, $out)
    if ($n -le 0) { return '' }
    [System.Text.Encoding]::ASCII.GetString($out, 0, $n)
}

Test-Case 'plain data passes through untouched' {
    $t = New-Telnet
    Assert-Equal 'hello' (Invoke-Telnet $t ([byte[]][char[]]'hello'))
}

Test-Case 'a doubled IAC becomes one literal 0xFF data byte' {
    $t = New-Telnet
    $out = New-Object byte[] 64
    $n = $t.Backend.TestProcessIncoming([byte[]]@(65, $IAC, $IAC, 66), 4, $out)
    Assert-Equal 3 $n
    Assert-Equal 65 $out[0]
    Assert-Equal 255 $out[1]
    Assert-Equal 66 $out[2]
}

Test-Case 'negotiation commands are stripped from the data stream' {
    $t = New-Telnet
    Assert-Equal 'AB' (Invoke-Telnet $t ([byte[]]@(65, $IAC, $WILL, $O_ECHO, 66)))
}

Test-Case 'sub-negotiation is stripped from the data stream' {
    $t = New-Telnet
    $bytes = [byte[]]@(65, $IAC, $SB, $O_TTYPE, 1, $IAC, $SE, 66)
    Assert-Equal 'AB' (Invoke-Telnet $t $bytes)
}

Test-Case 'a command split across two reads is still handled' {
    # The v1 parser had no state, so a sequence straddling a read corrupted output.
    $t = New-Telnet
    $first  = Invoke-Telnet $t ([byte[]]@(65, $IAC))
    $second = Invoke-Telnet $t ([byte[]]@($WILL, $O_ECHO, 66))
    Assert-Equal 'A' $first
    Assert-Equal 'B' $second
}

Test-Case 'active negotiation offers the options equipment needs' {
    # v1 offered none of these, which is why vendor gear misbehaved.
    $t = New-Telnet
    $t.Backend.TestStartNegotiation()
    $sent = Get-Sent $t
    Assert-Contains3 $sent $IAC $WILL $O_TTYPE 'WILL TERMINAL-TYPE'
    Assert-Contains3 $sent $IAC $WILL $O_NAWS  'WILL NAWS'
    Assert-Contains3 $sent $IAC $DO   $O_SGA   'DO SUPPRESS-GO-AHEAD'
    Assert-Contains3 $sent $IAC $DO   $O_ECHO  'DO ECHO'
    Assert-Contains3 $sent $IAC $WILL $O_BIN   'WILL BINARY'
}

Test-Case 'WILL ECHO from the host is accepted with DO ECHO' {
    $t = New-Telnet
    [void](Invoke-Telnet $t ([byte[]]@($IAC, $WILL, $O_ECHO)))
    Assert-Contains3 (Get-Sent $t) $IAC $DO $O_ECHO 'DO ECHO'
    Assert-True $t.Backend.RemoteEcho 'remote echo should be recorded'
}

Test-Case 'an unsupported option is refused, not accepted blindly' {
    $t = New-Telnet
    [void](Invoke-Telnet $t ([byte[]]@($IAC, $WILL, 99)))
    Assert-Contains3 (Get-Sent $t) $IAC $DONT 99 'DONT for an unknown option'
}

Test-Case 'DO TERMINAL-TYPE is answered with WILL' {
    $t = New-Telnet
    [void](Invoke-Telnet $t ([byte[]]@($IAC, $DO, $O_TTYPE)))
    Assert-Contains3 (Get-Sent $t) $IAC $WILL $O_TTYPE 'WILL TERMINAL-TYPE'
}

Test-Case 'the terminal type is reported when the host asks for it' {
    $t = New-Telnet
    [void](Invoke-Telnet $t ([byte[]]@($IAC, $DO, $O_TTYPE)))
    [void](Invoke-Telnet $t ([byte[]]@($IAC, $SB, $O_TTYPE, 1, $IAC, $SE)))
    $sent = [System.Text.Encoding]::ASCII.GetString((Get-Sent $t))
    Assert-True ($sent -match 'xterm-256color') "terminal type not sent; got '$sent'"
}

Test-Case 'the window size is sent after NAWS is agreed' {
    $t = New-Telnet
    $t.Backend.SetInitialSize(132, 43)
    [void](Invoke-Telnet $t ([byte[]]@($IAC, $DO, $O_NAWS)))
    $sent = Get-Sent $t
    # IAC SB NAWS 0 132 0 43 IAC SE
    Assert-Contains3 $sent $IAC $SB $O_NAWS 'NAWS sub-negotiation'
    $found = $false
    for ($i = 0; $i -le $sent.Length - 7; $i++) {
        if ($sent[$i] -eq $IAC -and $sent[$i+1] -eq $SB -and $sent[$i+2] -eq $O_NAWS -and
            $sent[$i+3] -eq 0 -and $sent[$i+4] -eq 132 -and $sent[$i+5] -eq 0 -and $sent[$i+6] -eq 43) { $found = $true }
    }
    Assert-True $found 'NAWS should carry 132x43 as big-endian 16-bit values'
}

Test-Case 'a resize re-sends the window size' {
    $t = New-Telnet
    [void](Invoke-Telnet $t ([byte[]]@($IAC, $DO, $O_NAWS)))
    $before = (Get-Sent $t).Length
    $t.Backend.Resize(100, 30)
    Assert-True ((Get-Sent $t).Length -gt $before) 'resize should put a NAWS update on the wire'
}

Test-Case 'a 0xFF byte in user input is escaped' {
    $t = New-Telnet
    $t.Backend.TestWriteEscaped([byte[]]@(65, 255, 66))
    $sent = Get-Sent $t
    Assert-Equal 4 $sent.Length
    Assert-Equal 255 $sent[1]
    Assert-Equal 255 $sent[2]
}

Test-Case 'binary mode can be declined by configuration' {
    $t = New-Telnet -NoBinary
    $t.Backend.TestStartNegotiation()
    $sent = Get-Sent $t
    $hasBinary = $false
    for ($i = 0; $i -le $sent.Length - 3; $i++) {
        if ($sent[$i] -eq $IAC -and $sent[$i+1] -eq $WILL -and $sent[$i+2] -eq $O_BIN) { $hasBinary = $true }
    }
    Assert-True (-not $hasBinary) 'binary should not be offered when disabled'
}

Test-Case 'a NOP command is consumed without producing data' {
    $t = New-Telnet
    Assert-Equal 'AB' (Invoke-Telnet $t ([byte[]]@(65, $IAC, $NOP, 66)))
}

Test-Case 'a WONT for an option that was never on is not answered' {
    # Answering it is what lets two ends that both answer everything loop forever.
    $t = New-Telnet
    [void](Invoke-Telnet $t ([byte[]]@($IAC, $WONT, 99)))
    Assert-Equal 0 (Get-Sent $t).Length
}

Test-Case 'an unsupported option is refused once, however often it is offered' {
    $t = New-Telnet
    [void](Invoke-Telnet $t ([byte[]]@($IAC, $WILL, 99)))
    [void](Invoke-Telnet $t ([byte[]]@($IAC, $WILL, 99)))
    Assert-Equal 3 (Get-Sent $t).Length
}

Test-Case 'a WONT after the option was agreed is acknowledged' {
    $t = New-Telnet
    [void](Invoke-Telnet $t ([byte[]]@($IAC, $WILL, $O_ECHO)))
    [void](Invoke-Telnet $t ([byte[]]@($IAC, $WONT, $O_ECHO)))
    Assert-Contains3 (Get-Sent $t) $IAC $DONT $O_ECHO 'DONT ECHO'
    Assert-True (-not $t.Backend.RemoteEcho) 'remote echo should be cleared'
}

Test-Case 'the host answering our own requests is not answered in turn' {
    $t = New-Telnet
    $t.Backend.TestStartNegotiation()
    $before = (Get-Sent $t).Length
    # The host agrees to everything we asked for.
    [void](Invoke-Telnet $t ([byte[]]@(
        $IAC, $WILL, $O_SGA,  $IAC, $DO, $O_SGA,
        $IAC, $WILL, $O_ECHO, $IAC, $DO, $O_TTYPE,
        $IAC, $WILL, $O_BIN,  $IAC, $DO, $O_BIN)))
    Assert-Equal $before (Get-Sent $t).Length 'agreeing to a request must not produce a further reply'
}

Test-Case 'a host refusing our request is not answered' {
    $t = New-Telnet
    $t.Backend.TestStartNegotiation()
    $before = (Get-Sent $t).Length
    [void](Invoke-Telnet $t ([byte[]]@($IAC, $WONT, $O_ECHO, $IAC, $DONT, $O_TTYPE)))
    Assert-Equal $before (Get-Sent $t).Length
}

# ------------------------------------------------- Ctrl and Alt key path ----

Write-Host "`nCtrl and Alt keys" -ForegroundColor Yellow

$KC = [System.Windows.Forms.Keys]
$TC = [PSTerm.Render.TerminalControl]

Test-Case 'Ctrl+letter is translated to the letter, for the encoder to turn into a control code' {
    Assert-Equal 'c' ($TC::ModifiedKeyChar($KC::C, $M::Control))
    Assert-Equal 'z' ($TC::ModifiedKeyChar($KC::Z, $M::Control -bor $M::Shift))
    Assert-Equal "$([char]3)" ($ke.Encode($K::Char, $TC::ModifiedKeyChar($KC::C, $M::Control), $M::Control, $false, $false))
}

Test-Case 'Alt+letter keeps its case and gets the ESC prefix' {
    Assert-Equal 'f' ($TC::ModifiedKeyChar($KC::F, $M::Alt))
    Assert-Equal 'F' ($TC::ModifiedKeyChar($KC::F, $M::Alt -bor $M::Shift))
    Assert-Equal "${ESC}f" ($ke.Encode($K::Char, 'f', $M::Alt, $false, $false))
}

Test-Case 'Ctrl+Alt is AltGr and is left to produce its character' {
    Assert-Equal ([char]0) ($TC::ModifiedKeyChar($KC::Q, $M::Control -bor $M::Alt))
    Assert-Equal ([char]0) ($TC::ModifiedKeyChar($KC::D7, $M::Control -bor $M::Alt))
}

Test-Case 'Ctrl+Space is NUL, Alt+Space is left to Windows' {
    Assert-Equal ' ' ($TC::ModifiedKeyChar($KC::Space, $M::Control))
    Assert-Equal ([char]0) ($TC::ModifiedKeyChar($KC::Space, $M::Alt))
}

Test-Case 'only the Ctrl+digits that have a control code are translated' {
    Assert-Equal '2' ($TC::ModifiedKeyChar($KC::D2, $M::Control))
    Assert-Equal '8' ($TC::ModifiedKeyChar($KC::D8, $M::Control))
    Assert-Equal ([char]0) ($TC::ModifiedKeyChar($KC::D1, $M::Control))
    Assert-Equal ([char]0) ($TC::ModifiedKeyChar($KC::D9, $M::Control))
}

Test-Case 'a plain key is not a modified key' {
    Assert-Equal ([char]0) ($TC::ModifiedKeyChar($KC::C, $M::None))
    Assert-Equal ([char]0) ($TC::ModifiedKeyChar($KC::ControlKey, $M::Control))
}

# ------------------------------------------------------------------ paste ---

Write-Host "`nPaste" -ForegroundColor Yellow

Test-Case 'pasted text cannot carry the escape that ends a bracketed paste' {
    $hostile = "ls${ESC}[201~; rm -rf ~"
    $clean = $TC::StripPasteControls($hostile)
    Assert-True ($clean -notmatch "$ESC") 'ESC must not survive'
    Assert-Equal 'ls[201~; rm -rf ~' $clean
}

Test-Case 'tabs and line breaks survive paste sanitising, other controls do not' {
    $text = "a`tb`rc$([char]3)$([char]127)d"
    Assert-Equal "a`tb`rcd" ($TC::StripPasteControls($text))
}

Test-Case 'ordinary text is returned untouched' {
    # Built from code points: Windows PowerShell reads a BOM-less script as ANSI.
    $text = "plain text, $([char]0x00FC)n$([char]0x00EF)code $([char]0x2713)"
    Assert-Equal $text ($TC::StripPasteControls($text))
}

# ---------------------------------------------------------------- summary ---


Write-Host ""
Write-Host ("-" * 60)
$total = $script:Passed + $script:Failed
if ($script:Failed -eq 0) {
    Write-Host "All $total tests passed." -ForegroundColor Green
    exit 0
}
else {
    Write-Host "$($script:Failed) of $total tests FAILED." -ForegroundColor Red
    Write-Host ""
    foreach ($f in $script:Failures) { Write-Host $f -ForegroundColor Red }
    exit 1
}
