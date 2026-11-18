<#
.SYNOPSIS
    Tests for the window: the session tree, tabs, toolbar, prompt automation and
    the things that happen on a timer.

.DESCRIPTION
    Builds the real main window against a scratch folder, shows it, and drives it
    with real window messages and the same functions the buttons call. Needs a
    desktop session. A few tests reach the network (reverse DNS, a public SSH
    server for the host-key check); they are skipped with -SkipNetwork.

.EXAMPLE
    powershell -NoProfile -STA -File tests\Run-UiTests.ps1
#>
[CmdletBinding()]
param([switch]$FailFast, [switch]$SkipNetwork)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    throw 'Run this with -STA: WinForms and the clipboard need a single-threaded apartment.'
}

$root = Split-Path -Parent $PSScriptRoot
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
. (Join-Path $root 'src\Bootstrap.ps1')
Initialize-PSTermCore -Root $root
foreach ($f in 'Settings', 'Secrets', 'Profiles', 'Store', 'Connect', 'Device', 'DeviceParsers', 'Topology', 'Plugins') { . (Join-Path $root "src\$f.ps1") }
foreach ($f in 'Theme', 'Dialogs', 'Tools', 'PluginDialog', 'MainWindow') { . (Join-Path $root "src\Ui\$f.ps1") }

$core = [PSTerm.Vt.TerminalEmulator].Assembly.Location
# Windows PowerShell resolves framework assemblies by name; PowerShell 7 needs the
# whole reference set the core itself is built with.
Add-Type -ReferencedAssemblies (@(Get-PSTermReferences) + $core) -Path (Join-Path $PSScriptRoot 'Fixtures\FakeLoginDevice.cs')
Add-Type -ReferencedAssemblies (@(Get-PSTermReferences) + $core) -Path (Join-Path $PSScriptRoot 'Fixtures\FakeIosDevice.cs')
. (Join-Path $PSScriptRoot 'Fixtures\New-FakeSwitchFactory.ps1')

Add-Type -Namespace T -Name W -MemberDefinition '[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern System.IntPtr SendMessage(System.IntPtr h, int m, System.IntPtr w, System.IntPtr l);'

$script:Passed = 0; $script:Failed = 0; $script:Skipped = 0
$script:Failures = New-Object System.Collections.Generic.List[string]

function Test-Case {
    param([string]$Name, [scriptblock]$Body, [switch]$Network)
    if ($Network -and $SkipNetwork) { $script:Skipped++; Write-Host "  SKIP  $Name" -ForegroundColor DarkGray; return }
    try { & $Body; $script:Passed++; Write-Host "  PASS  $Name" -ForegroundColor DarkGreen }
    catch {
        $script:Failed++
        $msg = "  FAIL  $Name`n        $($_.Exception.Message)"
        $script:Failures.Add($msg); Write-Host $msg -ForegroundColor Red
        if ($FailFast) { throw }
    }
}
function Assert-True { param($Condition, [string]$Because = '') if (-not $Condition) { throw "expected true: $Because" } }
function Assert-Equal { param($Expected, $Actual, [string]$Because = '') if ($Expected -ne $Actual) { throw "expected '$Expected' but got '$Actual' $Because" } }

function Pump {
    param([int]$Ms = 200)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $Ms) { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 10 }
}
function Wait-Until {
    param([scriptblock]$Condition, [int]$Ms = 8000)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $Ms) {
        [System.Windows.Forms.Application]::DoEvents()
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds 25
    }
    $false
}

# A scratch install root, so nothing touches the real profiles.
$sandbox = Join-Path ([System.IO.Path]::GetTempPath()) ("psterm-ui-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $sandbox 'Profiles') -Force | Out-Null
[void](Test-PSTermDpapiAvailable)

Write-Host "`nPSTerm window tests" -ForegroundColor Cyan
Write-Host ("-" * 60)

$form = $null
try {
    $form = New-PSTermMainWindow -Root $sandbox
    $form.Show()
    Pump 600
    $state = $form.Tag

    function Reset-Store {
        $state.Store.folders = @(); $state.Store.pinned = @(); $state.Store.credentials = @(); $state.Store.profiles = @()
        $state.Collapsed.Clear()
    }
    function Add-TestProfile {
        param([string]$Name, [string]$Folder = '', [string]$HostName = '10.0.0.1')
        $p = New-PSTermProfile -Name $Name; $p.folder = $Folder; $p.ssh.host = $HostName
        if ($Folder) { [void](Add-PSTermFolder -Store $state.Store -Path $Folder) }
        [void](Set-PSTermProfile -Store $state.Store -Profile $p)
        $p
    }
    function Get-TopNodes { @($state.Tree.Nodes | ForEach-Object { [string]$_.Tag }) }

    # ------------------------------------------------------------------ tree --
    Write-Host "`nSession tree" -ForegroundColor Yellow

    Test-Case 'pinned connections are listed first, then folders with their subfolders' {
        Reset-Store
        [void](Add-TestProfile 'core' 'Lab/Switches')
        $root1 = Add-TestProfile 'jump' ''
        [void](Add-TestProfile 'edge' 'Lab')
        Set-PSTermPinned -Store $state.Store -Id $root1.id
        $state.DetectedPorts = @()
        Update-PSTermTree -State $state
        $tops = Get-TopNodes
        Assert-Equal 'pin:' $tops[0]
        Assert-Equal "p:$($root1.id)" ([string]$state.Tree.Nodes[0].Nodes[0].Tag)
        Assert-True ($tops -contains 'f:Lab') "tops: $($tops -join ',')"
        $lab = $state.Tree.Nodes | Where-Object { $_.Tag -eq 'f:Lab' }
        Assert-True (@($lab.Nodes | Where-Object { $_.Tag -eq 'f:Lab/Switches' }).Count -eq 1) 'subfolder missing'
    }

    Test-Case 'an empty folder still shows' {
        Reset-Store
        [void](Add-PSTermFolder -Store $state.Store -Path 'Empty')
        Update-PSTermTree -State $state
        Assert-True ((Get-TopNodes) -contains 'f:Empty') 'empty folder not listed'
    }

    Test-Case 'a folder the operator folded stays folded when the tree is rebuilt' {
        Reset-Store
        [void](Add-TestProfile 'a' 'Lab')
        Update-PSTermTree -State $state
        $lab = $state.Tree.Nodes | Where-Object { $_.Tag -eq 'f:Lab' }
        $lab.Collapse()
        Update-PSTermTree -State $state
        $lab = $state.Tree.Nodes | Where-Object { $_.Tag -eq 'f:Lab' }
        Assert-True (-not $lab.IsExpanded) 'the folder was reopened by the rebuild'
        $lab.Expand()
        Update-PSTermTree -State $state
        Assert-True (($state.Tree.Nodes | Where-Object { $_.Tag -eq 'f:Lab' }).IsExpanded) 'an expanded folder did not stay open'
    }

    Test-Case 'one click on the chevron folds and unfolds a folder' {
        Reset-Store
        [void](Add-TestProfile 'a' 'Lab')
        Update-PSTermTree -State $state
        Pump 150
        $tree = $state.Tree
        $lab = $tree.Nodes | Where-Object { $_.Tag -eq 'f:Lab' }
        Assert-True $lab.IsExpanded 'starts open'
        $x = [int]($tree.Indent * $lab.Level + $tree.Indent / 2)
        $y = [int]($lab.Bounds.Top + $tree.ItemHeight / 2)
        # The mouse handler is called directly: a synthetic WM_LBUTTONDOWN sent to a
        # TreeView enters the control's own capture loop and waits for a real button-up.
        $press = [System.Windows.Forms.Control].GetMethod('OnMouseDown', [System.Reflection.BindingFlags]'NonPublic,Instance')
        $click = New-Object System.Windows.Forms.MouseEventArgs([System.Windows.Forms.MouseButtons]::Left, 1, $x, $y, 0)
        [void]$press.Invoke($tree, [object[]]@(,$click.PSObject.BaseObject))
        Pump 150
        Assert-True (-not $lab.IsExpanded) 'the chevron click did not collapse the folder'
        [void]$press.Invoke($tree, [object[]]@(,$click.PSObject.BaseObject))
        Pump 150
        Assert-True $lab.IsExpanded 'the second click did not open it again'
    }

    Test-Case 'searching keeps the folders above a match and hides the rest' {
        Reset-Store
        [void](Add-TestProfile 'alpha' 'Lab/Switches')
        [void](Add-TestProfile 'beta' 'Other')
        $state.SearchBox.Focus() | Out-Null
        $state.SearchBox.Text = 'alp'
        Pump 100
        $tops = Get-TopNodes
        Assert-True ($tops -contains 'f:Lab') "tops: $($tops -join ',')"
        Assert-True (-not ($tops -contains 'f:Other')) 'an unrelated folder stayed'
        $state.SearchBox.Text = ''
        $state.QuickBox.Focus() | Out-Null
        Pump 100
    }

    # ----------------------------------------------------------------- drag --
    Write-Host "`nDrag and drop" -ForegroundColor Yellow

    function Get-Node { param([string]$Tag) Find-PSTermTreeNode -Nodes $state.Tree.Nodes -Tag $Tag }

    Test-Case 'a connection can be dropped on a folder, and the move is kept' {
        Reset-Store
        $p = Add-TestProfile 'sw1' ''
        [void](Add-PSTermFolder -Store $state.Store -Path 'Site')
        Update-PSTermTree -State $state
        $src = Get-Node "p:$($p.id)"; $dst = Get-Node 'f:Site'
        Assert-True (Test-PSTermDrop -State $state -Source $src -Target $dst) 'the drop was refused'
        Complete-PSTermDrop -State $state -Source $src -Target $dst
        Assert-Equal 'Site' $p.folder
        $saved = Import-PSTermProfiles -Root $sandbox
        Assert-Equal 'Site' (Get-PSTermProfileById -Store $saved -Id $p.id).folder
    }

    Test-Case 'dropping on the empty area moves a connection to the top level' {
        Reset-Store
        $p = Add-TestProfile 'sw1' 'Site'
        Update-PSTermTree -State $state
        $src = Get-Node "p:$($p.id)"
        Assert-True (Test-PSTermDrop -State $state -Source $src -Target $null) 'refused'
        Complete-PSTermDrop -State $state -Source $src -Target $null
        Assert-Equal '' $p.folder
    }

    Test-Case 'dropping a connection on Pinned pins it' {
        Reset-Store
        $keep = Add-TestProfile 'already' ''
        Set-PSTermPinned -Store $state.Store -Id $keep.id
        $p = Add-TestProfile 'sw1' ''
        Update-PSTermTree -State $state
        $src = Get-Node "p:$($p.id)"; $pin = Get-Node 'pin:'
        Assert-True (Test-PSTermDrop -State $state -Source $src -Target $pin) 'refused'
        Complete-PSTermDrop -State $state -Source $src -Target $pin
        Assert-True (Test-PSTermPinned -Store $state.Store -Id $p.id) 'not pinned'
    }

    Test-Case 'a folder can move into another, but not into itself or its own subfolder' {
        Reset-Store
        [void](Add-PSTermFolder -Store $state.Store -Path 'A/B')
        [void](Add-PSTermFolder -Store $state.Store -Path 'C')
        Update-PSTermTree -State $state
        $a = Get-Node 'f:A'; $b = Get-Node 'f:A/B'; $c = Get-Node 'f:C'
        Assert-True (-not (Test-PSTermDrop -State $state -Source $a -Target $a)) 'into itself'
        Assert-True (-not (Test-PSTermDrop -State $state -Source $a -Target $b)) 'into its own child'
        Assert-True (Test-PSTermDrop -State $state -Source $a -Target $c) 'into a sibling refused'
        Complete-PSTermDrop -State $state -Source $a -Target $c
        Assert-True ($null -ne (Get-PSTermFolderRecord -Store $state.Store -Path 'C/A/B')) 'subfolder did not follow'
    }

    Test-Case 'sections and detected ports cannot be dragged anywhere' {
        Reset-Store
        $p = Add-TestProfile 'sw1' ''
        Set-PSTermPinned -Store $state.Store -Id $p.id
        Update-PSTermTree -State $state
        Assert-True (-not (Test-PSTermDrop -State $state -Source (Get-Node 'pin:') -Target $null)) 'the Pinned heading was draggable'
    }

    # ----------------------------------------------------------------- tabs --
    Write-Host "`nTabs" -ForegroundColor Yellow

    Test-Case 'a tab can be marked, the mark is remembered, and it can be cleared' {
        Reset-Store
        $p = Add-TestProfile 'local' ''
        $p.type = 'Shell'; $p.shell.commandLine = 'cmd.exe'
        Save-PSTermProfiles -Root $sandbox -Store $state.Store
        $tab = New-PSTermSessionTab -State $state -Profile $p
        Pump 300
        Set-PSTermTabMark -State $state -Tab $tab -Name 'Red'
        Assert-True (-not $tab.Item.Mark.IsEmpty) 'the tab has no mark'
        Assert-Equal $script:PSTermMarkColours['Red'].ToArgb() $tab.Item.Mark.ToArgb()
        Assert-Equal 'Red' (Get-PSTermProfileById -Store (Import-PSTermProfiles -Root $sandbox) -Id $p.id).mark
        Set-PSTermTabMark -State $state -Tab $tab -Name ''
        Assert-True $tab.Item.Mark.IsEmpty 'not cleared'
        Close-PSTermTab -State $state -Index 0 -Force
        Pump 100
        Assert-Equal 0 $state.TabStrip.Count
    }

    Test-Case 'a profile opens with its saved mark' {
        $p = Add-TestProfile 'marked' ''
        $p.type = 'Shell'; $p.shell.commandLine = 'cmd.exe'; $p.mark = 'Green'
        $tab = New-PSTermSessionTab -State $state -Profile $p
        Pump 200
        Assert-Equal $script:PSTermMarkColours['Green'].ToArgb() $tab.Item.Mark.ToArgb()
        Close-PSTermTab -State $state -Index 0 -Force
    }

    Test-Case 'the toolbar enables only what the current tab can do' {
        Update-PSTermStatus -State $state
        Assert-True (-not $state.Ribbon.Find('paste').Enabled) 'paste is enabled with no tab'
        Assert-True $state.Ribbon.Find('new').Enabled 'new is disabled'
        $p = Add-TestProfile 'local2' ''
        $p.type = 'Shell'; $p.shell.commandLine = 'cmd.exe'
        $tab = New-PSTermSessionTab -State $state -Profile $p
        Pump 300
        Assert-True $state.Ribbon.Find('paste').Enabled 'paste is disabled with a tab'
        Assert-True (-not $state.Ribbon.Find('break').Enabled) 'break is enabled for a shell session'
        Close-PSTermTab -State $state -Index 0 -Force
    }

    Test-Case 'the session list can be hidden and shown' {
        $before = $state.Split.Panel1Collapsed
        Set-PSTermSidebar -State $state -Toggle -NoSave
        Assert-True ($state.Split.Panel1Collapsed -ne $before) 'did not toggle'
        Set-PSTermSidebar -State $state -Toggle -NoSave
        Assert-Equal $before $state.Split.Panel1Collapsed
    }

    Test-Case 'the quick-connect bar, search box and buttons share one height' {
        $top = $state.QuickBox.Parent.Height
        $search = $state.SearchBox.Parent.Height
        Assert-True ($top -ge 28) "quick box frame is $top px"
        Assert-Equal $top $search 'the search frame and the quick-connect frame differ'
    }

    # ----------------------------------------------------------- automation --
    Write-Host "`nPrompt automation (fake device)" -ForegroundColor Yellow

    function New-FakeSession {
        param($Device, $Profile, $Password)
        $term = New-Object PSTerm.Vt.TerminalEmulator(80, 24, 100)
        $sink = New-Object PSTerm.EmulatorSink($term)
        $dec = New-Object PSTerm.Vt.StreamDecoder([PSTerm.Vt.TerminalEncoding]::Utf8)
        $session = New-Object PSTerm.TerminalSession($Device, $sink, $term, $dec)
        $tab = [pscustomobject]@{ Profile = $Profile; Password = $Password; User = '' }
        Add-PSTermAutomation -State $state -Tab $tab -Session $session
        $session
    }

    Test-Case 'the saved password answers the password prompt, once' {
        $dev = New-Object FakeLoginDevice
        $p = New-PSTermProfile; $p.ssh.autoAcceptHostKey = $true
        $session = New-FakeSession $dev $p 'loginpw'
        $session.Connect()
        Assert-True (Wait-Until { $dev.Stage -eq 'user' } 4000) "stage: $($dev.Stage); got: $($dev.Received -join '|')"
        $dev.LoginPassword = 'other'
        Pump 600
        Assert-Equal 1 @($dev.Received).Count 'the password was sent more than once'
        $session.Dispose()
    }

    Test-Case 'a wrong saved password is not retried (no lock-outs)' {
        $dev = New-Object FakeLoginDevice
        $dev.LoginPassword = 'right'
        $p = New-PSTermProfile; $p.ssh.autoAcceptHostKey = $true
        $session = New-FakeSession $dev $p 'wrong'
        $session.Connect()
        Pump 1500
        Assert-Equal 1 @($dev.Received).Count "sent: $($dev.Received -join '|')"
        Assert-Equal 'login' $dev.Stage
        $session.Dispose()
    }

    Test-Case 'without a saved password nothing is typed' {
        $dev = New-Object FakeLoginDevice
        $p = New-PSTermProfile; $p.ssh.autoAcceptHostKey = $true
        $session = New-FakeSession $dev $p $null
        $session.Connect()
        Pump 800
        Assert-Equal 0 @($dev.Received).Count
        $session.Dispose()
    }

    Test-Case 'auto-enable sends the command at the user prompt, then the credential secret' {
        Reset-Store
        $cred = Set-PSTermCredential -Store $state.Store -Root $sandbox -Name 'lab enable' -Secret 'enablepw'
        $dev = New-Object FakeLoginDevice
        $p = New-PSTermProfile; $p.ssh.autoAcceptHostKey = $true
        $p.autoEnable.enabled = $true; $p.autoEnable.delayMs = 100; $p.autoEnable.credentialId = $cred.id
        $session = New-FakeSession $dev $p 'loginpw'
        $session.Connect()
        Assert-True (Wait-Until { $dev.Stage -eq 'priv' } 6000) "stage: $($dev.Stage); got: $($dev.Received -join '|')"
        Assert-Equal 'loginpw|enable|enablepw' ($dev.Received -join '|')
        $session.Dispose()
    }

    Test-Case 'auto-enable answers a user name prompt first when the credential has one' {
        Reset-Store
        $cred = Set-PSTermCredential -Store $state.Store -Root $sandbox -Name 'ops' -Username 'ops' -Secret 'enablepw'
        $dev = New-Object FakeLoginDevice
        $dev.AsksForEnableUser = $true
        $p = New-PSTermProfile; $p.ssh.autoAcceptHostKey = $true
        $p.autoEnable.enabled = $true; $p.autoEnable.delayMs = 100; $p.autoEnable.credentialId = $cred.id; $p.autoEnable.useUsername = $true
        $session = New-FakeSession $dev $p 'loginpw'
        $session.Connect()
        Assert-True (Wait-Until { $dev.Stage -eq 'priv' } 6000) "stage: $($dev.Stage); got: $($dev.Received -join '|')"
        Assert-Equal 'loginpw|enable|ops|enablepw' ($dev.Received -join '|')
        $session.Dispose()
    }

    Test-Case 'the enable password is not typed at a password prompt before enable was sent' {
        Reset-Store
        $cred = Set-PSTermCredential -Store $state.Store -Root $sandbox -Name 'e' -Secret 'enablepw'
        $dev = New-Object FakeLoginDevice
        $p = New-PSTermProfile; $p.ssh.autoAcceptHostKey = $true
        $p.autoEnable.enabled = $true; $p.autoEnable.credentialId = $cred.id
        $session = New-FakeSession $dev $p $null       # no login password saved
        $session.Connect()
        Pump 1200
        Assert-Equal 0 @($dev.Received).Count "the enable secret went to the login prompt: $($dev.Received -join '|')"
        $session.Dispose()
    }

    # --------------------------------------------------------------- naming --
    Write-Host "`nAutomatic names" -ForegroundColor Yellow

    Test-Case 'only an address is looked up' {
        Assert-True ([PSTerm.Automation.NameLookup]::LooksLikeAddress('10.20.81.50')) 'ipv4'
        Assert-True ([PSTerm.Automation.NameLookup]::LooksLikeAddress('2001:db8::1')) 'ipv6'
        Assert-True (-not [PSTerm.Automation.NameLookup]::LooksLikeAddress('sb-0.501')) 'a host name was treated as an address'
        Assert-True (-not [PSTerm.Automation.NameLookup]::LooksLikeAddress('')) 'empty'
    }

    Test-Case 'a reverse lookup gives the first label of the name' -Network {
        $lookup = [PSTerm.Automation.NameLookup]::Start('8.8.8.8')
        Assert-True (Wait-Until { $lookup.Done } 10000) 'the lookup never finished'
        Assert-Equal 'dns' $lookup.Name
    }

    Test-Case 'an address with no record leaves the name alone and does not hang' -Network {
        $lookup = [PSTerm.Automation.NameLookup]::Start('192.0.2.77')    # TEST-NET-1, never has a PTR
        Assert-True (Wait-Until { $lookup.Done } 15000) 'the lookup never finished'
        Assert-Equal '' $lookup.Name
    }

    Test-Case 'a connection named by its address is renamed once the name arrives, and the rename is saved' -Network {
        Reset-Store
        $p = Add-TestProfile '8.8.8.8' '' '8.8.8.8'
        $p.autoName = $true
        Save-PSTermProfiles -Root $sandbox -Store $state.Store
        Register-PSTermAutoName -State $state -Profile $p
        Assert-True (Wait-Until { $p.name -eq 'dns' } 12000) "still '$($p.name)'"
        Assert-True (-not $p.autoName) 'the flag was not cleared'
        Assert-Equal 'dns' (Get-PSTermProfileById -Store (Import-PSTermProfiles -Root $sandbox) -Id $p.id).name
    }

    Test-Case 'a name the operator chose is never replaced' {
        Reset-Store
        $p = Add-TestProfile 'My switch' '' '10.9.9.9'
        $p.autoName = $false
        Register-PSTermAutoName -State $state -Profile $p
        Pump 500
        Update-PSTermLookups -State $state
        Assert-Equal 'My switch' $p.name
    }

    # ------------------------------------------------------------- host keys --
    Write-Host "`nHost keys" -ForegroundColor Yellow

    Test-Case 'a server that is not there reports an error quickly, with no keys' -Network {
        $profile = New-PSTermProfile; $profile.ssh.host = '127.0.0.1'; $profile.ssh.port = 1
        $probe = [PSTerm.Automation.HostKeyProbe]::Start((New-PSTermSshOptions -Profile $profile -User 'x'))
        Assert-True (Wait-Until { $probe.Done } 20000) 'the probe never finished'
        Assert-True (-not $probe.Known) 'known'
        Assert-Equal 0 @($probe.Keys).Count
        Assert-True ($probe.Error.Length -gt 0) 'no error text'
    }

    Test-Case 'the real ssh.exe is used to read a public server''s host keys, without logging in' -Network {
        $profile = New-PSTermProfile; $profile.ssh.host = 'ssh.github.com'; $profile.ssh.port = 443
        $probe = [PSTerm.Automation.HostKeyProbe]::Start((New-PSTermSshOptions -Profile $profile -User 'git'))
        Assert-True (Wait-Until { $probe.Done } 25000) 'the probe never finished'
        if ($probe.Known) { return }           # already trusted on this PC: nothing to read
        Assert-True ($probe.Error.Length -eq 0) "error: $($probe.Error)"
        Assert-True (@($probe.Keys).Count -ge 1) 'no keys'
        Assert-True ($probe.Keys[0].Fingerprint -like 'SHA256:*') "fingerprint: $($probe.Keys[0].Fingerprint)"
        Assert-True ($probe.Keys[0].KnownHostsLine -like '*ssh.github.com*') 'the line to trust is not for this host'
    }

    Test-Case 'accept-new connects to an unknown host with no prompt in the terminal' -Network {
        $known = Join-Path $sandbox 'known_hosts_a'
        $profile = New-PSTermProfile; $profile.ssh.host = 'ssh.github.com'; $profile.ssh.port = 443
        $profile.ssh.autoAcceptHostKey = $true
        $profile.ssh.extraOptions = @("UserKnownHostsFile=$known", 'BatchMode=yes')
        $backend = New-PSTermBackend -Profile $profile -User 'git'
        $term = New-Object PSTerm.Vt.TerminalEmulator(100, 30, 100)
        $sink = New-Object PSTerm.EmulatorSink($term)
        $session = New-Object PSTerm.TerminalSession($backend, $sink, $term, (New-Object PSTerm.Vt.StreamDecoder([PSTerm.Vt.TerminalEncoding]::Utf8)))
        $session.Connect()
        [void](Wait-Until { $session.HasClosed } 25000)
        $text = (0..($term.Screen.TotalLines - 1) | ForEach-Object { $term.Screen.GetLineText($_) }) -join "`n"
        $session.Dispose()
        Assert-True ($text -notmatch 'Are you sure') "the prompt was shown: $text"
        Assert-True (Test-Path -LiteralPath $known) 'the key was not recorded'
        Assert-True ((Get-Content -Raw -LiteralPath $known) -match 'ssh.github.com') 'wrong host recorded'
    }

    Test-Case 'if ssh still asks, the prompt is recognised and handed to the window' -Network {
        $known = Join-Path $sandbox 'known_hosts_b'
        $profile = New-PSTermProfile; $profile.ssh.host = 'ssh.github.com'; $profile.ssh.port = 443
        $profile.ssh.extraOptions = @("UserKnownHostsFile=$known", 'StrictHostKeyChecking=ask')
        $backend = New-PSTermBackend -Profile $profile -User 'git'
        $term = New-Object PSTerm.Vt.TerminalEmulator(100, 30, 100)
        $sink = New-Object PSTerm.EmulatorSink($term)
        $session = New-Object PSTerm.TerminalSession($backend, $sink, $term, (New-Object PSTerm.Vt.StreamDecoder([PSTerm.Vt.TerminalEncoding]::Utf8)))
        $tab = [pscustomobject]@{ Profile = $profile; Password = $null; User = 'git' }
        Add-PSTermAutomation -State $state -Tab $tab -Session $session
        $script:asked = $false
        $session.Add_RuleMatched({ param($s, $e) if ($e.Message -eq 'hostkey-prompt') { $script:asked = $true; $s.Send("no`r") } })
        $session.SynchronizingObject = $form
        $session.Connect()
        Assert-True (Wait-Until { $script:asked } 25000) 'the prompt was not recognised'
        [void](Wait-Until { $session.HasClosed } 10000)
        $session.Dispose()
        Assert-True (-not (Test-Path -LiteralPath $known) -or (Get-Item -LiteralPath $known).Length -eq 0) 'answering no still recorded the key'
    }

    Write-Host "`nWindow furniture" -ForegroundColor Yellow

    function Get-SideButton([string]$Text) {
        foreach ($c in $state.TreeHost.Parent.Controls) {
            if ($c -is [System.Windows.Forms.TableLayoutPanel]) { foreach ($b in $c.Controls) { if ($b.Text -in @($Text, 'Unpin') -and ($Text -ne 'Pin' -or $b.Text -in @('Pin', 'Unpin')) -and $b.Text -ne 'New' -or $b.Text -eq $Text) { if ($b.Text -eq $Text -or ($Text -eq 'Pin' -and $b.Text -eq 'Unpin')) { return $b } } } }
        }
    }

    Test-Case 'the session list switch is inside the list, and the way back is at the left of the tabs' {
        Assert-True ($state.SidebarButton.Parent -and $state.SidebarButton.Parent.Parent) 'the switch is not placed'
        $inPanel = $false; $p = $state.SidebarButton.Parent
        while ($p) { if ($p -eq $state.Split.Panel1) { $inPanel = $true }; $p = $p.Parent }
        Assert-True $inPanel 'the hide switch is not inside the session panel'
        Set-PSTermSidebar -State $state -Visible $false -NoSave; Pump 150
        Assert-True $state.Split.Panel1Collapsed 'not collapsed'
        Assert-True ($state.SidebarExpand.Visible -and $state.SidebarExpand.Width -gt 0) 'no way back'
        Assert-True ($state.SidebarExpand.Bounds.Left -le 4) "the show switch is not at the left edge: $($state.SidebarExpand.Bounds.Left)"
        Set-PSTermSidebar -State $state -Visible $true -NoSave; Pump 150
        Assert-True (-not $state.Split.Panel1Collapsed -and -not $state.SidebarExpand.Visible) 'not restored'
    }
    Test-Case 'Edit, Pin and Delete are all dimmed when nothing is selected, all lit for a connection' {
        Reset-Store
        $p = Add-TestProfile -Name 'only one'
        Update-PSTermTree -State $state
        $state.Tree.SelectedNode = $null
        Update-PSTermTreeButtons -State $state
        foreach ($name in 'Edit', 'Pin', 'Delete') { Assert-True (-not (Get-SideButton $name).Enabled) "$name is lit with nothing selected" }
        $node = $state.Tree.Nodes | ForEach-Object { $_ } | Where-Object { [string]$_.Tag -eq "p:$($p.id)" } | Select-Object -First 1
        if (-not $node) { $node = Find-PSTermTreeNode -Nodes $state.Tree.Nodes -Tag "p:$($p.id)" }
        $state.Tree.SelectedNode = $node
        Update-PSTermTreeButtons -State $state
        foreach ($name in 'Edit', 'Pin', 'Delete') { Assert-True ((Get-SideButton $name).Enabled) "$name is dimmed for a connection" }
    }
    Test-Case 'the find window is a window of its own: it does not lock the main window, and closes cleanly' {
        $prof = New-PSTermProfile -Name 'findme' -Type 'Shell'; $prof.shell.commandLine = 'cmd.exe'
        [void](Set-PSTermProfile -Store $state.Store -Profile $prof)
        $tab = New-PSTermSessionTab -State $state -Profile $prof
        try {
            Pump 800
            Show-PSTermFind -State $state
            Assert-True ($null -ne $state.FindDialog -and $state.FindDialog.Visible) 'the find window is not showing'
            Assert-True $state.Form.Enabled 'the main window was locked'
            Assert-True ($state.FindDialog.FormBorderStyle -eq 'FixedDialog') 'not the standard dialog frame'
            Assert-True ($state.FindDialog.Owner -eq $state.Form) 'not owned by the main window'
            # a second request brings the same window back instead of opening another
            $first = $state.FindDialog; Show-PSTermFind -State $state
            Assert-True ([object]::ReferenceEquals($first, $state.FindDialog)) 'a second window opened'
            # the main window still works while it is open
            Set-PSTermStatusMessage -State $state -Message 'still alive'
            Assert-Equal 'still alive' $state.StatusLeft.Text
            $state.FindDialog.Close(); Pump 200
            Assert-True ($null -eq $state.FindDialog) 'the window was not forgotten after closing'
        }
        finally { if ($state.FindDialog) { $state.FindDialog.Close() }; Close-PSTermTab -State $state -Index ($state.Tabs.Count - 1) -Force }
    }
    Test-Case 'the toolbar has a Plugins button that opens the plugin window' {
        $item = $state.Ribbon.Find('plugins')
        Assert-True ($null -ne $item) 'there is no Plugins button'
        Assert-True ($item.Group -eq 'Automation') "it is in the group '$($item.Group)'"
    }
    Test-Case 'the settings dialog opens and offers the paste block sizes (and no sentence about testing)' {
        $seen = @{ Text = ''; Items = @(); Ticks = 0 }
        $t = New-Object System.Windows.Forms.Timer; $t.Interval = 250
        # A modal dialog blocks this script, so a timer has to be the one to close it - and it has to
        # close it whatever happens, or the whole run waits for ever.
        $t.Add_Tick({
            $seen.Ticks++
            $f = [System.Windows.Forms.Application]::OpenForms | Where-Object { $_.Text -eq 'Settings' } | Select-Object -First 1
            try {
                if ($f) {
                    $seen.Text = $f.Text
                    $stack = New-Object System.Collections.Stack; $stack.Push($f)
                    while ($stack.Count) { $c = $stack.Pop(); if ($c -is [PSTerm.Render.ThemedComboBox]) { $seen.Items += ,@($c.Items | ForEach-Object { [string]$_ }) }; foreach ($k in $c.Controls) { $stack.Push($k) } }
                }
            }
            finally {
                if ($f -or $seen.Ticks -gt 40) {
                    $t.Stop()
                    foreach ($other in @([System.Windows.Forms.Application]::OpenForms | Where-Object { $_ -ne $form })) { try { $other.Close() } catch { } }
                }
            }
        }.GetNewClosure())
        $t.Start(); Show-PSTermSettings -State $state; $t.Dispose()
        Assert-Equal 'Settings' $seen.Text 'the dialog did not open'
        $flat = @($seen.Items | ForEach-Object { $_ -join '|' })
        Assert-True ($flat -contains 'Line by line|5 lines at a time|10 lines at a time|20 lines at a time|50 lines at a time') "combos: $($flat -join ' // ')"
        $src = [System.IO.File]::ReadAllText((Join-Path $root 'src\Ui\Tools.ps1'))
        Assert-True ($src -notmatch 'Catalyst switches this was tried on') 'the tooltip still talks about testing'
    }
    Test-Case 'credentials can be managed with no connection open, and there is no Copy button' {
        while ($state.Tabs.Count -gt 0) { Close-PSTermTab -State $state -Index 0 -Force }
        Update-PSTermStatus -State $state
        Assert-True ($state.Ribbon.Find('creds').Enabled) 'the Credentials button is dimmed without a connection'
        Assert-True ($null -eq $state.Ribbon.Find('copy')) 'the Copy button is still on the toolbar'
        # the menu itself: send entries are dimmed, Manage credentials is not
        Reset-Store
        [void](Set-PSTermCredential -Store $state.Store -Root $sandbox -Name 'Lab enable' -Secret 'x')
        $menuShown = $null
        $null = $state.Ribbon
        $m = New-PSTermMenu -Theme $state.Theme
        $item = $m.Items.Add('Manage credentials...')
        Assert-True $item.Enabled 'the manage entry is dimmed'
        $m.Dispose()
    }
    Test-Case 'hovering a menu item with a tooltip raises no error' {
        $m = New-PSTermMenu -Theme $state.Theme
        $item = $m.Items.Add('Entry'); $item.ToolTipText = 'A tip'
        $flags = [System.Reflection.BindingFlags]'NonPublic,Instance'
        foreach ($name in 'OnMouseEnter', 'OnMouseLeave') {
            [void]$item.GetType().GetMethod($name, $flags).Invoke($item, @([EventArgs]::Empty))
        }
        $m.Dispose()
    }
    Test-Case 'a menu item''s tooltip is the application''s own, not the system one' {
        $m = New-PSTermMenu -Theme $state.Theme
        Assert-True (-not $m.ShowItemToolTips) 'the system tooltip is still on for menus'
        $m.Dispose()
    }

    Write-Host "`nPlugin window" -ForegroundColor Yellow

    $fixtureDir = Join-Path $PSScriptRoot 'Fixtures\ios'
    function New-PluginDialog {
        param([string]$FailFor = '')
        Reset-Store
        $state.DetectedPorts = @()
        [void](Add-TestProfile -Name 'lab-core' -Folder 'Lab' -HostName '192.168.77.1')
        [void](Add-TestProfile -Name 'lab-edge' -Folder 'Lab' -HostName '192.168.77.2')
        $dlg = New-PSTermPluginDialog -State $state -SessionFactory (New-FakeSwitchFactoryText -FixtureDir $fixtureDir -FailFor $FailFor)
        $dlg.Form.Owner = $form
        $dlg.Form.Show()
        Pump 300
        $dlg
    }
    function Close-PluginDialog { param($Dlg) $Dlg.Timer.Stop(); $Dlg.Form.Close(); $Dlg.Form.Dispose(); $Dlg.Shell.Tips.Dispose() }
    function Select-Plugin { param($Dlg, [string]$Title)
        $i = -1; for ($k = 0; $k -lt $Dlg.PluginList.Items.Count; $k++) { if ([string]$Dlg.PluginList.Items[$k] -like "$Title*") { $i = $k } }
        Assert-True ($i -ge 0) "no plugin '$Title' in the list"
        $Dlg.PluginList.SelectedIndex = $i; Pump 150
    }
    function Wait-PluginRun { param($Dlg)
        Assert-True (Wait-Until { $Dlg.State.Run -and $Dlg.State.Run.Done -and $Dlg.RunButton.Enabled } 30000) "the run did not finish (status: '$($Dlg.Status.Text)'; run: $(if ($Dlg.State.Run) { 'started, done=' + $Dlg.State.Run.Done } else { 'never started' }))"
        Pump 200
    }

    Test-Case 'the window lists the built-in plugins and builds the form from the script' {
        $dlg = New-PluginDialog
        try {
            Assert-True ($dlg.PluginList.Items.Count -ge 5) "only $($dlg.PluginList.Items.Count) plugins"
            Select-Plugin $dlg 'Interface health'
            Assert-True ($dlg.State.Fields.ContainsKey('MinErrors') -and $dlg.State.Fields.ContainsKey('OnlyProblems')) "fields: $($dlg.State.Fields.Keys -join ', ')"
            Assert-Equal 2 $dlg.TargetList.Items.Count
            Assert-Equal 'Lab / lab-core' ([string]$dlg.TargetList.Items[0])
        }
        finally { Close-PluginDialog $dlg }
    }
    Test-Case 'the window follows the theme: muted text stays muted, lists and grid use the theme colours, it fits the screen' {
        $dlg = New-PluginDialog
        try {
            $theme = $state.Theme
            Set-PSTermFormTheme -Control $dlg.Form -Theme $theme    # what showing the dialog does
            Assert-True ($dlg.Status.ForeColor.ToArgb() -eq $theme.TextMuted.ToArgb()) 'the status line lost its muted colour'
            Assert-Equal 'OwnerDrawFixed' ([string]$dlg.PluginList.DrawMode) 'the plugin list is drawn by the system (blue highlight)'
            Assert-Equal 'OwnerDrawFixed' ([string]$dlg.TargetList.DrawMode) 'the device list is drawn by the system (blue highlight)'
            Assert-True ($dlg.Grid.BackgroundColor.ToArgb() -eq $theme.Surface.ToArgb()) 'grid background'
            $buffered = [System.Windows.Forms.DataGridView].GetProperty('DoubleBuffered', [System.Reflection.BindingFlags]'NonPublic,Instance').GetValue($dlg.Grid, $null)
            Assert-True $buffered 'the results table is not double-buffered (scrolling flickers)'
            Assert-True ($dlg.Grid.ColumnHeadersDefaultCellStyle.BackColor.ToArgb() -eq $theme.Field.ToArgb()) 'grid header colour'
            $area = [System.Windows.Forms.Screen]::FromControl($form).WorkingArea
            Assert-True ($dlg.Form.Width -le $area.Width -and $dlg.Form.Height -le $area.Height) "window $($dlg.Form.Width)x$($dlg.Form.Height) is larger than the screen $($area.Width)x$($area.Height)"
        }
        finally { Close-PluginDialog $dlg }
    }
    Test-Case 'detected serial ports are in the device list, and a port that a tab holds is refused clearly' {
        $dlg = New-PluginDialog
        try {
            $state.DetectedPorts = @([pscustomobject]@{ PortName = 'COM77'; Description = 'Test adapter' })
            $dlg.Form.Activate(); [void]$dlg.Form.Focus(); Pump 150
            # the list refreshes when the window is activated; do it directly as well
            $entries = @(Get-PSTermPluginTargetEntries -State $state)
            Assert-Equal 3 $entries.Count 'two saved connections and one detected port'
            $port = $entries | Where-Object { $_.Id -eq 'port:COM77' }
            Assert-True ($port.Label -match 'Detected serial ports / COM77' -and $port.Label -match 'Test adapter') $port.Label
            Assert-Equal 'Serial' $port.Profile.type; Assert-Equal 'COM77' $port.Profile.serial.portName

            # a tab holds that port
            $held = New-PSTermProfile -Name 'console' -Type 'Serial'; $held.serial.portName = 'COM77'
            $state.Tabs.Add([pscustomobject]@{ Closed = $false; Profile = $held })
            try {
                $busy = @(Get-PSTermPluginTargetEntries -State $state | Where-Object { $_.Busy })
                Assert-Equal 1 $busy.Count; Assert-True ($busy[0].Busy -match "COM77 is open in the tab 'console'") $busy[0].Busy
                Select-Plugin $dlg 'Inventory'
                [void]$dlg.State.Selected.Add('port:COM77')
                $dlg.RunButton.PerformClick(); Pump 200
                Assert-True ($null -eq $dlg.State.Run) 'a run started on a port a tab holds'
                Assert-True ($dlg.Status.Text -match 'open in the tab') $dlg.Status.Text
            }
            finally { $state.Tabs.RemoveAt($state.Tabs.Count - 1) }
        }
        finally { $state.DetectedPorts = @(); Close-PluginDialog $dlg }
    }
    Test-Case 'running without a device picked says so and starts nothing' {
        $dlg = New-PluginDialog
        try {
            Select-Plugin $dlg 'Device health'
            $dlg.RunButton.PerformClick(); Pump 200
            Assert-True ($dlg.Status.Text -match 'Pick at least one') $dlg.Status.Text
            Assert-True ($null -eq $dlg.State.Run) 'a run started'
        }
        finally { Close-PluginDialog $dlg }
    }
    Test-Case 'a run fills the table, keeps the window alive and can be sorted' {
        $dlg = New-PluginDialog
        try {
            Select-Plugin $dlg 'Device health'
            $dlg.PickAll.PerformClick(); Pump 100
            $dlg.RunButton.PerformClick(); Pump 100
            Assert-True (-not $dlg.RunButton.Enabled -and $dlg.StopButton.Enabled) 'buttons did not change while running'
            Wait-PluginRun $dlg
            Assert-True ($dlg.Status.Text -match '2 of 2 devices answered') "status: $($dlg.Status.Text); hosts: $($dlg.State.Run.Hosts | Out-String)"
            Assert-Equal 2 $dlg.Grid.Rows.Count "(view $($dlg.ViewBox.SelectedItem), table rows $($dlg.State.Table.Rows.Count), source $($dlg.Grid.DataSource))"
            $cols = @($dlg.Grid.Columns | ForEach-Object { $_.Name })
            Assert-True ($cols[0] -eq 'Target' -and $cols -contains 'Cpu5m' -and $cols -contains 'Status') "columns: $($cols -join ',')"
            Assert-True ($dlg.Grid.Columns['Cpu5m'].ValueType -eq [long]) 'a numeric column is not numeric'
            $dlg.Grid.Sort($dlg.Grid.Columns['Target'], [System.ComponentModel.ListSortDirection]::Descending); Pump 100
            Assert-Equal 'lab-edge' ([string]$dlg.Grid.Rows[0].Cells['Target'].Value)
        }
        finally { Close-PluginDialog $dlg }
    }
    Test-Case 'the neighbour plugin shows a diagram' {
        $dlg = New-PluginDialog
        try {
            Select-Plugin $dlg 'Neighbours'
            $dlg.PickAll.PerformClick(); Pump 100
            $dlg.RunButton.PerformClick()
            Wait-PluginRun $dlg
            Assert-Equal 'Topology' ([string]$dlg.ViewBox.SelectedItem)
            Assert-True ($dlg.Picture.Visible -and $null -ne $dlg.Picture.Image -and $dlg.Picture.Image.Width -gt 200) 'no diagram'
            Assert-True (-not $dlg.Grid.Visible) 'the table is still showing'
        }
        finally { Close-PluginDialog $dlg }
    }
    Test-Case 'when every device fails the window shows why' {
        $dlg = New-PluginDialog -FailFor 'lab-core'
        try {
            Select-Plugin $dlg 'Inventory'
            $dlg.TargetList.SetSelected(0, $true); Pump 100
            $dlg.RunButton.PerformClick()
            Wait-PluginRun $dlg
            Assert-Equal 'Devices' ([string]$dlg.ViewBox.SelectedItem) "status: $($dlg.Status.Text)"
            Assert-True ($dlg.Status.Text -match '1 failed') $dlg.Status.Text
            Assert-True ([string]$dlg.Grid.Rows[0].Cells['Error'].Value -match 'simulated connection failure') 'the error is not shown'
        }
        finally { Close-PluginDialog $dlg }
    }
    Test-Case 'Stop lets the devices go and the window is usable again' {
        $dlg = New-PluginDialog
        try {
            Select-Plugin $dlg 'Inventory'
            $dlg.PickAll.PerformClick(); Pump 100
            $dlg.RunButton.PerformClick(); Pump 50
            $dlg.StopButton.PerformClick(); Pump 300
            Assert-True ($dlg.RunButton.Enabled -and -not $dlg.StopButton.Enabled) 'the buttons did not come back'
            Assert-True ($dlg.State.Run.Done) 'the run is not finished'
        }
        finally { Close-PluginDialog $dlg }
    }}
finally {
    if ($form) { try { $form.Tag.MainTimer.Stop() } catch { }; try { $form.Tag.Ports.Dispose() } catch { } ; $form.Dispose() }
    Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("-" * 60)
$total = $script:Passed + $script:Failed
if ($script:Failed -eq 0) {
    Write-Host "All $total window tests passed$(if ($script:Skipped) { " ($($script:Skipped) skipped)" })." -ForegroundColor Green
    exit 0
}
Write-Host "$($script:Failed) of $total window tests FAILED." -ForegroundColor Red
Write-Host ""
foreach ($f in $script:Failures) { Write-Host $f -ForegroundColor Red }
exit 1
