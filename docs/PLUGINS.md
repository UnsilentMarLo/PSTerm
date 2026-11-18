# Writing a plugin

A plugin is a folder with two files. It runs **once per device**; PSTerm runs it for every
device you pick, up to ten at the same time, and puts the rows together.

```
Plugins\
  my-check\
    plugin.json
    main.ps1
```

Your own plugins live in a `Plugins` folder next to `PSTerm.ps1`. The ones that ship with
PSTerm are in `src\Plugins` and are good examples.

## main.ps1

The `param()` block is the form. Every parameter except `$Session` and `$Target` becomes a
field: a switch or `[bool]` is a check box, a number is a number box, `[ValidateSet(...)]` is
a drop-down, `[string[]]` is a multi-line box, anything else is a text box. The default value
is the field's starting value, and the comment-based help of the script (`.PARAMETER Name`)
is the tool tip.

```powershell
<#
.PARAMETER MinErrors
    An interface is marked when one of its error counters has reached this number.
#>
param(
    [Parameter(Mandatory)]$Session,   # the open session: required
    $Target,                          # optional: Name, Address and Type of the device
    [switch]$OnlyProblems,
    [int]$MinErrors = 1
)

$device = Get-PSTermSessionHostname -Session $Session
$r = Invoke-PSTermCommand $Session 'show interfaces' -TimeoutSec 100 -ThrowOnError

foreach ($i in ConvertFrom-PSTermIosInterfaces $r.Lines) {
    if ($OnlyProblems -and $i.InErrors -lt $MinErrors) { continue }
    [pscustomobject][ordered]@{ Device = $device; Interface = $i.Interface; InErrors = $i.InErrors }
}
```

Whatever the script returns becomes rows: one object per row, one property per column. The
host adds a `Target` column (the connection's name) at the front. Numbers stay numbers, so the
table sorts properly; lists are joined with commas.

What a script can use:

| | |
|---|---|
| `Invoke-PSTermCommand $Session 'show ...'` | runs a command and waits for the prompt. Returns `Lines`, `Text`, `Succeeded`, `Error`, `TimedOut`. `-ThrowOnError` fails the device when the command is refused |
| `Get-PSTermSessionHostname -Session $Session` | the device's own name, read from its prompt |
| `ConvertFrom-PSTermIosVersion`, `...Inventory`, `...Interfaces`, `...InterfaceStatus`, `...Transceiver`, `...Cdp`, `...Lldp`, `...Cpu`, `...Memory` | turn the text of a `show` command into objects (`src\DeviceParsers.ps1`) |
| `Get-PSTermShortPort`, `Get-PSTermShortName` | `GigabitEthernet0/10` becomes `Gi0/10`; `sw1.example.net` becomes `sw1` |

Throwing an error fails that device only, with your message in the *Devices* view.

## plugin.json

```json
{
  "title": "My check",
  "description": "One sentence shown under the plugin's name.",
  "version": "1.0",
  "timeoutSec": 120,
  "enter": true,
  "topology": false,
  "parameters": {
    "MinErrors": { "label": "Errors that count as a problem", "tip": "Optional; overrides the help text" }
  }
}
```

| Field | Meaning |
|---|---|
| `title`, `description`, `version` | what the window shows |
| `script` | the script's file name; `main.ps1` if left out. Must be in the plugin's own folder |
| `timeoutSec` | how long one device may take, counted from when it starts. It is stopped when it runs over |
| `enter` | go to privileged mode after login (default `true`) |
| `topology` | the rows are neighbour rows (`Device`, `LocalPort`, `RemoteDevice`, `RemotePort`, ...); the window offers a diagram |
| `access` | `read` (the only value that runs today) |
| `parameters` | a nicer label or a tip for a form field, by parameter name |

## What a plugin cannot do

* **Change a device.** The session is read-only: the engine refuses everything that is not
  `show`, `ping`, `traceroute`, `terminal length|width N`, `dir`, `more` or `verify`, and a
  `show` piped to `redirect`, `tee` or `append`, whatever the script does. `$Session.SendRaw`
  throws. Refused commands appear in the run's log as `(refused)`.
* **See a password.** PSTerm resolves the quick credential and logs in; the script gets an
  open session.

## What a plugin *can* do, and the approval

A plugin is PowerShell code and it runs on your computer with your rights - the read-only
session limits what it can do to a *device*, not to your machine. So a plugin that is not part
of PSTerm asks for approval the first time it runs, showing where it came from. The approval is
for exactly those files (a hash); change a byte and it asks again. Run only plugins you trust.

## Where the logs are

`Logs\plugins\<date>-<plugin>.log`: who ran it, the hash of the files, the parameters, and per
device its status, time, and every command that was sent. The window's *Open log* button opens
the last one.

## From a script

The window is a thin layer over a few functions (`src\Plugins.ps1`), usable without it:

```powershell
$plugin = Get-PSTermPlugin -Root $root -Id 'device-health'
$run = Invoke-PSTermPlugin -Plugin $plugin -Target $profiles -Store $store -Root $root `
        -Credential 'lab login' -EnableCredential 'lab enable' -ThrottleLimit 10
$run.Rows | Export-Csv health.csv -NoTypeInformation
$run.Hosts          # how each device went
```
