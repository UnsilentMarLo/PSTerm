# PSTerm - where it is going

## Decisions

| Question | Decision | What follows |
|---|---|---|
| Windows PowerShell 5.1 and 7 | **Both.** | PSTerm's own runspace pool is the one implementation (it behaves the same on both). `ForEach-Object -Parallel` can be added behind the same interface if it measures faster. |
| Third-party SSH library | **No.** PSTerm stays independent and downloads nothing. | Headless sessions run the in-box `ssh.exe` inside a pseudo-console - the same thing a tab does - and answer its prompts with the prompt engine. Proven against real switches (below). |
| Plugin credentials | **The existing quick credentials.** | No second vault. A plugin names a credential; PSTerm resolves the secret and gives it to the session, never to the script. |
| Command packs | **Dropped**, together with command validation and reading the Cisco PDF. | Too much work for too little certainty. Nothing in PSTerm depends on knowing the whole command tree. |
| Walking the command tree with `?` | **Dropped**, as too slow. | |
| `show parser dump` | **Does not exist** on the lab switches (see below). | Nothing builds on it. |
| What a plugin may do to a device | **Look, not touch - enforced by the engine.** | A plugin session refuses every command that is not a look-only command, so no script can reconfigure a device. Plugins that change things come later, with a dry run, a permission prompt and the audit log. |
| Constrained language mode for plugins | **Not now.** | A PowerShell plugin can already do anything to the PC that the user can. What protects the PC is an approval that names the exact files (a hash) and asks again when they change. Constrained language would need the host API as compiled cmdlets; it is a possible later step, not a promise. |

### `show parser dump`

Tried on both lab switches over their consoles:

| Switch | Software | `show parser dump exec` |
|---|---|---|
| Catalyst 3560-CX (WS-C3560CX-8PC-S) | IOS 15.2(7)E3 | `Command accepted, but obsolete, parser dumper has been deprecated` |
| Catalyst Micro (CMICR-4PS) | IOS 15.2(8)E3 | the same message |

`show parser ?` on both lists only `csb`, `macro`, `memory`, `statistics` and `view`. There
is no one-shot dump on IOS 15.2.

---

## What exists now

**Device drivers** (`src\Drivers\*.json`) - a family of devices described as data: prompts,
pager, errors, the questions a command can end in, the enable and save and rollback commands.
Cisco IOS / IOS XE is the first. A file in a `Drivers` folder next to `PSTerm.ps1` overrides
the built-in one of the same name.

**Device sessions** (`DeviceSession`, and `Connect-PSTermDevice`, `Invoke-PSTermCommand`) -
send a command, wait for the prompt, get the output back as text. The same code works over a
serial port, Telnet and SSH. It:

- decides a command is finished when the prompt is showing *and* the device has gone quiet;
- switches the pager off, and answers it if it appears anyway;
- looks past messages a device prints on its own (a log line, a shutdown banner), which
  otherwise hide the prompt;
- never answers a "yes/no" with *yes* unless told to, and answers a question it finds left
  over at login with *no*;
- never retries a refused password.

**Safe apply** (`Send-PSTermConfig -Safe`) - arms `reload in N`, applies the lines, and only
cancels the timer once the change is confirmed good. It stops at the first line the device
refuses. It answers "no" to the "save before reloading?" question, because saving would
bake the half-made change into the very configuration the rollback returns to.

**Configuration copies** (`Save-PSTermConfigBackup`) - dated files, with the lines that change
by themselves removed, and a report of exactly which lines were added or removed since the
last copy.

**Plugin host** (`src\Plugins.ps1`, `src\Ui\PluginDialog.ps1`) - a plugin is a folder with a
`plugin.json` and a script written for one device; the script's `param()` block becomes the form.
PSTerm runs it for every chosen device in its own runspace pool (ten at once by default, the same
code on Windows PowerShell 5.1 and 7), with a time limit per device, a cancel button, a
read-only session, credentials from the quick credentials, an approval by file hash for plugins
that are not shipped with PSTerm, and a log of every command sent. Five read-only plugins ship:
device health, interface health, transceiver levels, inventory, and neighbours with a topology
diagram (SVG and PNG). How to write one: [PLUGINS.md](PLUGINS.md).

**Parsers** (`src\DeviceParsers.ps1`) - `show version`, `inventory`, `interfaces`, `interfaces
status`, `interfaces transceiver`, CDP and LLDP detail, CPU and memory, into objects. Written
against output captured from the lab switches (`tests\Fixtures\ios`); a line they cannot read is
skipped, never guessed at. The transceiver parser is tested on a hand-made sample only: the lab
switches have no optics.

**Paced paste** - optionally feeds a pasted block to the device a few lines at a time (line by
line, or blocks of 5, 10, 20 or 50), waiting for the prompt each time (Settings, "Paced paste":
Off, Serial or All). Off by default: see the measurements below.

### Verified on the lab switches

Both switches were connected (PC - 3560-CX port 1, 3560-CX port 10 - Catalyst Micro port 1),
configured over serial with management addresses, a DHCP server on the 3560-CX, and SSH.

| | Result |
|---|---|
| Host-key probe over SSH with legacy algorithms | key read in 0.9 s, no login attempt made |
| Login with a saved password over SSH (pseudo-console) | works; command output has the same shape as over the serial console |
| `show running-config` over SSH | 111 lines in 0.4 s; first and last lines correct |
| CDP | `lab-edge` seen on the core's Gig 0/10 |
| Pager (`terminal length 24`) over serial | handled; output has no `--More--`, no stray keys |
| Safe apply, healthy change | applied, timer cancelled, change kept |
| Safe apply, refused line | stops at that line, later lines not sent, timer cancelled |
| Safe apply, way in declared gone | timer left running; the switch reloaded by itself and came back on its saved configuration with none of the unsaved change |
| Logging a real session through `--More--` | no `More`, no backspace characters, no pager keys in the file |
| Plugins on both switches and over SSH, in one run | Device health, inventory, interface health and neighbours each returned the right rows for the core (by serial and by SSH at the same time) and the edge; the topology drew the cable Gi0/10 - Gi1/0/1 |
| A plugin trying `configure terminal` and `hostname` on the edge | refused by the engine; the hostname unchanged |
| Replacing 40 VLANs by pasting 82 lines, raw | 40 of 40, 9 s, no errors |
| The same paste, paced | 40 of 40, 24 s, no errors |

On these switches a plain paste lost nothing, even when it began with a slow command, so
paced paste costs two to three times the time and showed no benefit here. It is kept as an
option for a console that does drop characters, and is off by default.

One thing the pacer taught: after a configuration change IOS prints `%SYS-5-CONFIG_I`
*after* the prompt and does not redraw the prompt, so a cursor sitting on that line is still
at a prompt. Both the pacer and the device engine now look past such lines.

---

## What to build next

1. **Rollouts**: a template with `{{variables}}` and a table of values (plain substitution,
   never PowerShell string expansion, so a spreadsheet cell cannot run code), plan → dry run →
   apply, a canary host first, safe apply on every host, a table of results. This is the first
   plugin kind with `access: write`: the host gains a write session that is only handed out
   after a dry run and a permission prompt, and every command goes to the audit log.
2. **Presets**: the driver mechanism, plus a "Device preset" choice in the connection and
   folder editors, and a suggestion when a banner or prompt matches. Cisco first; another
   vendor is added only after its quirks are confirmed on a real device.
3. **Read-only configuration view** (blocks, interface table, diff against a saved copy),
   then editable forms for a short list of features. Everything that writes goes through safe
   apply and a dry run.
4. **Plugin extras**: a scheduled run (a health board that refreshes), a crawl that follows CDP
   neighbours to devices that were not selected, and a table-of-values input for plugins.

SNMP (a v2c client is about 500 lines of C#, no dependencies) and a TFTP/HTTP listener for
pushing images are accelerators for later, once the command-line path is solid.

### Safety rules for plugins

* A plugin session is read-only in the engine (`DeviceSession.MakeReadOnly`): an allow-list of
  look-only commands, a deny-list for the ways a `show` can still write, and no raw input. It
  can be switched on, never off.
* The script never receives a password; the host logs in and hands over a session.
* A plugin that is not shipped with PSTerm needs an approval that names its exact files.
* Anything that writes (later) needs a dry run, a permission prompt and the audit log.
* What is *not* protected: the PC. A plugin is PowerShell and runs with the user's rights.

---
## Notes

- A switch can stay busy long after the PC has finished sending (deleting 40 VLANs took it
  minutes). Any code that sends further commands has to wait for the prompt, not for a fixed
  time.
- A question the device asked ("Save? [yes/no]") can be followed by a log line it printed on
  its own, so the question is not always the line under the cursor. The device engine finds
  the last line that is not console noise, answers each question once, and sends one bare
  Enter if a command ends with a banner instead of a prompt (`reload in N` does).
- A serial port closed a moment ago can still report "access denied" when reopened at once;
  the serial backend retries for two seconds.
- A USB console (the 3560-CX's own USB port) prints a "media type" message when it is opened,
  sometimes in the middle of whatever is being printed, which cuts a line in two. A command result
  says when it saw such a message (`NoiseSeen`), and a configuration copy is taken again when it
  did. The console is also woken more than once at login, because the first key can arrive before
  the console is listening.
- Terminal drawing: the back buffer is a GDI DIB section that GDI draws text into directly and
  that is copied to the window with BitBlt, only for the rows that changed. A GDI+ bitmap has to
  be copied in and out of a device context for every frame of text, which cost about 70 ms on a
  large high-DPI window and made typing lag. The cell width is measured with the same GDI font
  the text is drawn with, and every glyph is placed on its cell (ExtTextOut with explicit
  advances), so the cursor cannot drift away from the text however the font rounds its size.
- A plugin run is stopped without waiting for anything: the sessions are abandoned (the transport
  is closed on another thread) and the pool is released by a background runspace. PowerShell's
  own Stop, Dispose and pool Close all wait for a worker that is stuck in a serial port or a
  login, which froze the window for minutes.
- PowerShell's `@($list)` throws "Argument types do not match" on a `List[object]`, and an
  `if` expression unrolls a DataTable into its rows; both bit the plugin host and window.
- `$null` passed to a .NET method from PowerShell arrives as an empty string; the C# side
  treats an empty password as "none".
