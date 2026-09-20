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

- Tabs with a close button and a connection-state dot.
- Quick-connect bar: type `admin@switch1`, `host:2222`, `telnet ts1 2004`,
  `COM3:115200` or `cmd` and press Enter.
- Command palette on `Ctrl+K`.
- Session tree with **folders** and a search box.
- Import from the PuTTY registry and from `~/.ssh/config`.
- Dark and light themes; DPI-aware at any display scaling.

**Logging**

Per-line timestamps, raw or plain text, size-based rotation, and templated paths
so every device writes its own dated file with no per-session setup:

```
Logs\{host}\{name}-{date}.log
```

Supported tokens: `{name}`, `{host}`, `{user}`, `{port}`, `{date}`, `{time}`,
`{datetime}`. Passwords typed after a password prompt are masked.

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
| `Ctrl+K` | Command palette |
| `Ctrl+T` | Focus the quick-connect bar |
| `Ctrl+W` | Close tab |
| `Ctrl+R` | Reconnect tab |
| `Ctrl+L` | Clear scrollback |
| `Ctrl+F` | Find in scrollback |
| `Ctrl+Tab` | Next tab |
| `Ctrl+1`…`9` | Go to tab |
| `Ctrl+Shift+C` / `Ctrl+Shift+V` | Copy and paste |
| `Shift+PgUp` / `Shift+PgDn` | Scroll back |

Escape, function keys, Alt and every control combination go to the device, not to
the application.

---

## Where things are kept

```
Profiles\profiles.json      saved connections
Profiles\settings.json      application settings
Profiles\credentials.dat    DPAPI-encrypted, current user and machine only
Logs\                       session logs, unless a profile says otherwise
bin\                        compiled core, regenerated whenever the source changes
```

Everything lives in the install folder, so the whole thing is portable. Secrets
deliberately are not: DPAPI ties them to the Windows account that created them, so
copying the folder to another machine carries the connections but not the
passwords.

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
