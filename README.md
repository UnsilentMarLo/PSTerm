# PSTerm

A serial, SSH and Telnet terminal written in PowerShell, with a real VT/xterm
emulator and a tabbed GUI. Copy the folder to a Windows machine and run it — no
installer, no runtime to deploy, no third-party binaries.

```
PSTerm.cmd
```

That is the whole install. The first launch compiles the native core with the C#
compiler that already ships with Windows and caches it; later launches are
instant.

---

## Why it exists

PuTTY is still the default for console work, and it is very good at the part that
matters most — terminal emulation. It is also a session manager with a flat list,
no tabs, and logging you have to remember to turn on before you connect. The
tools that fix the interface usually do it by wrapping PuTTY, or by shipping a
large application that has to be installed.

PSTerm aims at both halves: emulation faithful enough for equipment consoles, in
an interface built the way a terminal would be designed today, in a folder you can
put on a share or a USB stick.

## What it does

**Connections**

| | |
|---|---|
| **SSH** | Runs the OpenSSH client that ships with Windows inside a pseudo-console. Public key and agent authentication, certificates, `ProxyJump` bastions, `~/.ssh/config`, and every cipher OpenSSH supports. Legacy key exchange and ciphers for older equipment are a per-profile switch. |
| **Serial** | Any baud rate, data bits, parity, stop bits and flow control. DTR/RTS control, break signal, modem status lines, and automatic recovery when a USB console adapter is unplugged and put back. |
| **Telnet** | Proper RFC 854/856/857/858/1073/1091 negotiation: SGA, ECHO, binary mode, terminal type and window size. |
| **Local** | `cmd`, PowerShell, WSL or any console program in a tab. |

**Terminal**

- xterm/VT220 emulation: cursor addressing, scroll regions, alternate screen,
  insert and delete, tab stops, origin and autowrap modes, device reports.
- DEC Special Graphics, so vendor box-drawing menus render as tables rather than
  letter soup. Box and block characters are drawn geometrically, so the strokes
  join exactly at any font size or display scaling.
- 16, 256 and 24-bit colour; bold, faint, italic, underline, inverse, strike.
- UTF-8, Latin-1, ASCII or the OEM code page, decoded across read boundaries.
- Scrollback with search, block and rectangular selection, copy-on-select,
  bracketed paste, mouse reporting.
- One key map with the switches equipment actually disagrees about exposed as
  settings — including **Backspace sends BS or DEL**, the fix for the classic
  "my backspace prints `^H` on this box".

**Interface**

- A toolbar with icons and captions, grouped like a Word ribbon: new, reconnect,
  duplicate, close; copy, paste, select all; find, clear scrollback, reset
  terminal, serial break; quick credentials; import and export; the session list
  and the theme. Every button and every field has a tooltip.
- Tabs with a close button, a connection-state dot, a `+` that opens the connection
  editor, and a **colour mark** (right-click a tab) to flag how important it is.
- Quick-connect bar: type `admin@switch1`, `host:2222`, `telnet ts1 2004`,
  `COM3:115200` or `cmd` and press Enter.
- Command palette on `Ctrl+Shift+P`.
- Session tree with **folders and subfolders**, a search box, a **Pinned** section,
  drag and drop (connections into folders, folders into folders, onto Pinned), a
  chevron that folds with one click, and right-click menus on folders, connections,
  tabs and the empty list. Hover a folder for `+` (new connection in it) and a
  connection for its pin.
- `<` at the left of the top bar (or `Ctrl+B`) folds the session list away.
- **Folder settings**: right-click a folder. Every new connection created in it
  starts with that folder's user, password, ports, terminal, logging and
  auto-enable settings. Existing connections are not rewritten.
- **Serial ports appear by themselves**: plug in a console cable and its COM port is
  listed under *Detected serial ports*, with the adapter's name; double-click to open
  it. Nothing is saved unless you choose *Save as connection*.
- Import from a **CSV file** (a NetBox IP export works as it is, German headers
  included), from a PSTerm `.psterm` session file, from the PuTTY registry and from
  `~/.ssh/config`. Export a connection, a folder or everything to a `.psterm` file to
  back it up or share it - passwords are never included.
- Dark and light themes, with matching title bars; DPI-aware at any display scaling.

**Logging in**

- **SSH user**: never guessed. A connection with no user (and no folder or global
  default) asks for one, instead of letting `ssh` quietly send your Windows account
  name to the device.
- **Password** on a connection or a folder, with Show/Hide. It is stored encrypted
  with DPAPI for your Windows account (`Profiles\credentials.dat`), never in
  `profiles.json`, and typed once at the first password prompt - a wrong one is not
  retried, so it cannot lock the account out.
- **Host keys** are asked about in a dialog with the fingerprints, before the session
  starts, not at a `yes/no` prompt inside the terminal. *Accept new host keys
  automatically* (per connection or per folder) skips the question; a key that later
  *changes* is still refused.
- **Quick credentials** (toolbar): named secrets, with an optional user name, that
  you can send into the terminal with one click - an enable password, say.
- **Auto-enable**: when the device shows its `>` prompt, send `enable` (or any
  command) after a delay and answer the password prompt - and the user name prompt,
  if the device asks for one - from a quick credential.
- **Names fill themselves in**: enter only an IP address and leave the name as it is;
  PSTerm names the connection from a reverse DNS lookup, or failing that from the
  device's own prompt once it has connected.

**Scripting devices**

The same engine that answers prompts in a tab can be driven from a script, over a serial
port, Telnet or SSH, with no window:

```powershell
$s = Connect-PSTermDevice -Profile $profile -Store $store -Root $root -Credential 'lab login' -EnableCredential 'lab enable' -Enter
(Invoke-PSTermCommand $s 'show version | include uptime').Lines
Send-PSTermConfig -Session $s -Line 'interface vlan 1', 'description uplink' -Safe -Verify { Test-Connection $addr -Quiet } -Save
Save-PSTermConfigBackup -Session $s -Folder .\Backups -Name 'core-sw1'
```

A command ends when the device's prompt is showing and it has gone quiet; the pager is
dealt with; a line the device refuses is reported in the device's own words. `-Safe` arms
`reload in N` first and cancels it only if the change left the device reachable, so a
change that cuts the way in undoes itself. `Backups` keeps dated copies and says which lines
changed. Devices are described by a driver file (`src\Drivers\cisco-ios.json`).
Pasting several lines can be fed to the device a few at a time, waiting for its prompt each
time (Settings, *Paced paste*: Off, Serial or All; and *Paste in blocks of*: line by line, 5, 10,
20 or 50 lines). Off by default; turn it on for a console that drops characters when a block
arrives at full speed.

**Plugins**

*Plugins...* in the menu opens a window that runs a small script against many devices at
once and shows what comes back as a table you can sort and save as CSV. Pick a plugin, fill in
its form, pick devices (or a whole folder with the filter), and Run. Five ship with PSTerm,
all read-only:

| Plugin | What it gives you |
|---|---|
| Device health | one row per device: processor, memory, uptime, last restart, ports connected or in trouble |
| Interface health | link state, speed and error counters per interface, with CRC, drops and half duplex marked |
| Transceiver levels | light levels, temperature and voltage of optical modules, with alarm marks and a low-light check |
| Inventory | model, serial number, software version (or one row per part) |
| Neighbours and topology | CDP and LLDP neighbours; with several devices selected, a diagram of the links, saved as SVG or PNG |

The window is opened by the **Plugins** button on the toolbar (or the menu). Its device list holds
your saved connections and the serial ports PSTerm has detected; a port that a tab already has
open is marked, because a port can be opened only once.

Up to ten devices are asked at once (a field in the window); a device that fails or runs past
its time limit is reported and the others carry on. A plugin is read-only because the session
it gets refuses anything that is not a look-only command (`show`, `ping`, ...) - that check is
in the engine, not in the plugin, so a plugin cannot reconfigure a device whatever it contains.
It never sees a password: PSTerm logs in with the quick credential you choose and hands the
plugin an open session. Every run leaves a log of what was sent to which device
(`Logs\plugins`). Write your own: [docs/PLUGINS.md](docs/PLUGINS.md).

**Logging**

Plain-text logs are what was on the screen: a device that draws and then erases
text - Cisco's `--More--` is the classic - leaves no debris, and the key that
answers the pager is left out too. Per-line timestamps, raw or plain text,
size-based rotation (`name.1.log`, `name.2.log`...), and templated paths
so every device writes its own dated file with no per-session setup:

```
Logs\{host}\{name}-{date}.log
```

Supported tokens: `{name}`, `{host}`, `{user}`, `{port}`, `{date}`, `{time}`,
`{datetime}`. Passwords typed after a password prompt are masked in every format,
raw included. A second tab that would write to a file already in use takes a
numbered name (`name-2.log`) rather than going unlogged.

---

## Requirements

| | |
|---|---|
| Windows | 10 1809 or later, or Server 2019+. Earlier versions run serial and Telnet; SSH and local shells need the pseudo-console API. |
| PowerShell | Windows PowerShell 5.1 (in the box on every supported Windows) or PowerShell 7. |
| SSH | The in-box OpenSSH client. Present by default; if it has been removed, add it under **Settings → System → Optional features → OpenSSH Client**. |

Nothing is downloaded, at install time or at runtime.

Run `PSTerm.ps1 -NoWindow` for an installation check that reports exactly which of
the above are present.

---

## Keyboard

| | |
|---|---|
| `Ctrl+Shift+P` | Command palette |
| `Ctrl+Shift+T` | Focus the quick-connect bar |
| `Ctrl+Shift+W` | Close tab |
| `Ctrl+Shift+R` | Reconnect tab |
| `Ctrl+Shift+L` | Clear scrollback |
| `Ctrl+Shift+F` | Find in scrollback |
| `Ctrl+Tab` / `Ctrl+Shift+Tab` | Next / previous tab |
| `Ctrl+Shift+1`…`9` | Go to tab |
| `Ctrl+Shift+C` / `Ctrl+Shift+V` | Copy and paste |
| `Shift+PgUp` / `Shift+PgDn` | Scroll back |
| `Ctrl+B` | Show or hide the session list (outside a terminal) |
| Right-click in a terminal | Copy the selection, or paste when nothing is selected |

Application commands sit on `Ctrl+Shift`. Everything else - Escape, function keys,
Alt, and every plain `Ctrl` combination (`Ctrl+R` reverse search, `Ctrl+W`, `Ctrl+L`,
`Ctrl+C`...) - goes to the device, not to the application.

Pasting several lines into a terminal that has not asked for bracketed paste asks
for confirmation first, because each line break runs a command. Turn that off with
`"confirmMultilinePaste": false` in `Profiles\settings.json`. Control characters,
including the escape sequence that ends a bracketed paste, are stripped from pasted
text.

---

## Where things are kept

```
Profiles\profiles.json      saved connections
Profiles\settings.json      application settings
Profiles\credentials.dat    DPAPI-encrypted store, current user and machine only
                            (not yet used to log in - see below)
Logs\psterm-errors.log     unexpected errors, if any
Logs\                       session logs, unless a profile says otherwise
bin\                        compiled core, regenerated whenever the source changes
```

Everything lives in the install folder, so the whole thing is portable. Secrets
deliberately are not: DPAPI ties them to the Windows account that created them, so
copying the folder to another machine carries the connections but not the
passwords.

PSTerm does not store or send passwords today: `ssh` and the device ask in the
terminal, and the credential store exists for a later release. Do not put a password
in a profile's auto-input lines - that file is plain text. Use an SSH key.

`Profiles\profiles.json` is not tracked by git, since it holds your real hostnames.
PSTerm creates a starter file on first run.

An existing v1 `profiles.json` is migrated automatically on first run, and the
original is kept as `profiles.json.v1-backup`.

---

## Command line

```powershell
.\PSTerm.ps1                          # open the window
.\PSTerm.ps1 -Connect admin@core-sw1  # open a session straight away
.\PSTerm.ps1 -Connect "COM3:115200"
.\PSTerm.ps1 -NoWindow                # installation check, no UI
.\PSTerm.ps1 -Rebuild                 # force the core to recompile
```

---

## How it is put together

```
PSTerm.ps1          bootstrap: find the folder, load the core, show the window
src/Bootstrap.ps1   compile-or-load, cached on a hash of the sources
src/Core/           C#, compiled at runtime - the entire data path
  Vt/               parser, screen buffer, character sets, key encoding
  Render/           terminal control, palette, tab strip, box drawing
  Backends/         ConPTY/SSH, serial, telnet behind one interface
  Interop/          pseudo-console P/Invoke
  Io/               session logging
src/Ui/             PowerShell: window, dialogs, theme
tests/              three suites, no test framework required
build/              packaging and optional code signing
```

The rule that shapes the design: **PowerShell never touches a byte of session
data.** Everything between the wire and the screen is C#, compiled at runtime from
source that ships in the repository. PowerShell builds the interface and manages
configuration.

That is not only about speed. Transports deliver data on their own reader threads,
and a PowerShell script block invoked as a delegate from a native thread has no
runspace to run in — it hangs rather than running. Keeping the data path in C# and
marshalling events to the UI thread is what makes the design work at all.

### Working on it

The core must stay within **C# 5**. Windows PowerShell 5.1 compiles it through the
.NET Framework CodeDom provider, which is the C# 5 compiler: string interpolation,
`?.`, expression-bodied members and `nameof` will not build there. Anything under
`src/Core` is subject to this; `src/Ui` is PowerShell and is not.

```powershell
powershell -NoProfile -File tests\Run-AllTests.ps1 -BothEditions
```

Three suites: the emulator in isolation, the profile and connection layer, and
integration tests that drive real processes and pseudo-consoles. The core is
recompiled automatically whenever a `.cs` file changes.

Serial is the one area the tests cannot reach without hardware. Verifying it needs
a real adapter or a `com0com` virtual pair.

### Packaging

```powershell
.\build\Build.ps1 -Zip          # a folder and a .zip, ready to hand over
.\build\Build.ps1 -Exe          # also a single .exe (needs ps2exe installed)
.\build\Sign-PSTerm.ps1         # optional Authenticode signing
```

The build pre-compiles the core, leaves out development files, and never includes
the packager's own profiles or credentials. It works entirely offline.

---

## Licence

GPLv3. See [LICENSE](LICENSE).
