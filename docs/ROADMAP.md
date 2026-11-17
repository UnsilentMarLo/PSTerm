# PSTerm - where it could go

Recommendations for the three larger ideas: command-reference awareness, device
presets, and plugins. They share more than they differ, so the order matters more
than any one idea.

## The one thing underneath all three: a device driver

Every idea needs PSTerm to *understand a device*, not just display it:

| Needed by | What it needs to know |
|---|---|
| Presets | defaults for backspace, encoding, serial speed, legacy algorithms; what the prompts look like |
| Command reference | which mode the device is in, which command set applies |
| Plugins | when a command has finished, how to turn the pager off, how to enter privileged mode, what an error looks like, how to save |

So the first piece to build is a small, data-driven **device driver**: a JSON file per
family (Cisco IOS / IOS XE, NX-OS, ASA, Lancom, ...) holding

- prompt grammar: regexes for user, privileged, config, config-sub-mode prompts, and the
  mode each one means;
- pager handling (`terminal length 0`, or answering `--More--`), and how to detect it;
- login and enable flow (the Expect rules PSTerm already has - `auto-enable` is the first
  instance of this);
- error patterns (`% Invalid input`, `% Ambiguous command`, `% Incomplete command`);
- save and rollback commands (`write memory`, `configure replace`, `reload in`);
- terminal quirks (backspace, line endings, break behaviour, serial defaults);
- secrets that must be masked in logs (`secret 5 ...`, `password 7 ...`, SNMP communities).

Folder default settings (already built) are the mechanism for applying one: a driver is
"folder defaults + a prompt grammar". I would ship Cisco first - it is the one I can
describe with confidence - and treat every other vendor as something to confirm against
real hardware before it ships, rather than writing quirks from memory.

---

## 1. Command reference: validation, autocomplete, browser, visual editor

### What the PDF can and cannot give

I looked at the Catalyst 9200 reference you attached. It is 2,000 pages and about 970
command entries. Each entry has a syntax block in Cisco's notation
(`switchport mode {access | dynamic {auto | desirable} | trunk}`), the **command mode**
("Interface configuration"), the default, and the release it appeared in. Those parts
extract cleanly. The parameter descriptions are laid out as tables in columns and extract
badly, so descriptions would be approximate.

Two further problems:

- **Windows has no PDF text extractor.** `pdftotext` (Poppler) read this file well, but
  PSTerm cannot assume it is installed, and reading PDF text without a library is a large
  job of its own.
- **Cisco's documents are copyrighted.** PSTerm should ship the *builder* and let each
  user convert the document they downloaded, never ship the converted data.

### The device itself is a better source

The CLI help (`?`) on the connected device is exact for that hardware and that release,
which is the problem you described (3560-CX vs 9200-CX vs a modular core). I recommend
two sources feeding **one pack format**:

1. **Learn from the device**: walk the command tree with `?` from each mode, slowly, in a
   throwaway session. Slow but exact; run once per platform and release.
2. **Import from the reference**: gives descriptions, defaults and release history that
   `?` does not.

Some IOS releases also have a hidden `show parser dump` that prints the tree in one go.
That is worth trying on your 3560-CX, but I have not verified it and would not build on it.

A pack lives in `Commands\<platform>\<release>.json`, is chosen per connection (or per
folder), and PSTerm can suggest one by reading `show version` after login.

### Validation and autocomplete: where it can and cannot work

PSTerm does not own the input line - the device does. Its echo, history recall (Up
arrow), and its own Tab completion all change the line without PSTerm typing anything.
Tracking keystrokes locally will drift. What does work is to **read the line from the
terminal screen**, after the prompt, which is always the truth.

- **Ghost hints** under the cursor from the pack: the next keywords, the argument type,
  the one-line help. Read-only, cannot get in the way.
- **A check when Enter is pressed**: validate the line on screen against the pack and
  show a badge. Warn, do not block - the pack can be wrong or out of date.
- **Pasted blocks, validated line by line before anything is sent.** This is where I
  would start. A mistake in a 200-line paste is expensive and the paste is one event PSTerm
  fully controls.
- Needs: mode tracking from the prompt (`(config-if)#`), IOS's unambiguous-prefix rule
  (`sh int` is valid), and the `no` / `default` forms.

### Command browser

A tree of the pack with search, the syntax, the mode, the default, and "insert into the
terminal". Straightforward once the pack exists.

### Visual config editor

I would be careful with the scope. "A form for every command" produces thousands of
forms nobody wants. What is realistic, in order:

1. A **read-only structured view** of `show running-config` (blocks, interface table,
   search, diff against a saved copy). Low risk, immediately useful.
2. **Editable views for a curated set**: interfaces, VLANs, SVIs, STP, SNMP, AAA, ACLs.
3. Editing produces a *diff* - the minimal commands including the `no` forms - which is
   shown before anything is sent, with undo, redo and reset-to-default operating on the
   model rather than on the device.

The traps: IOS hides default values in `running-config` (`show running-config all` has
them), and ordering matters in some sections.

### Safe apply

Do not rely on `write memory` alone. IOS already has what is needed:

| Mechanism | Use |
|---|---|
| `configure terminal revert timer <min>` then `configure confirm` | Roll back automatically unless confirmed. Needs the archive feature; check it on each platform. |
| `reload in <min>` then `reload cancel` | Works on everything. Because running is not yet saved, the reload comes back with the old config. |
| `copy running-config flash:...` before the change, `configure replace flash:... force` after | Explicit full rollback. |

Recommended flow: back up → arm the timer → push the diff → **PSTerm opens a second,
independent connection to the management address** and checks it still answers →
cancel the timer → save. PSTerm confirming reachability itself is safer than asking
a person to click. Over a serial console the timer is not needed, because the console
cannot be cut off by the change.

### Suggested order

pack format and the "learn from device" builder → paste validation → ghost hints → command
browser → read-only config view → editable views with safe apply.

---

## 2. Device presets

Yes, and cheaply: a preset is a device driver (above) plus folder defaults. I would
put a **Device preset** drop-down in the connection editor and the folder editor, make
presets plain JSON files in `Presets\` that users can copy and edit, and offer a
suggestion when a banner or prompt matches a known family.

Start with Cisco IOS / IOS XE and NX-OS, and add each other vendor only once its quirks have
been confirmed on a real device.

---

## 3. Plugins

### Do not invent a language

PowerShell is already the host language and your power users know it. A plugin should be
**a PowerShell script with a manifest**, not a new scripting language:

- The script's `param()` block describes its inputs for free: types, validation, help,
  defaults. PSTerm turns it into a form, as `Show-Command` does.
- A small `plugin.json` adds what a `param()` block cannot say: a **table or range input**
  (hostnames and addresses, `10.1.1.1-10.1.1.40`, a pasted column), a
  **credential picker**, and the **result view** (table, status board, graph, text) with
  its columns and which exports to offer (CSV, JSON, HTML, SVG, PNG).
- Declared **permissions**: reads only, writes configuration, may enable a service
  temporarily, opens serial ports. PSTerm shows them before the first run.

### The host API the script sees

```
Connect-PSTermDevice   -Address -Credential -Driver        # SSH, Telnet or COM port
Invoke-PSTermCommand   $session 'show version'              # waits for the prompt, handles the pager
Send-PSTermConfig      $session $lines -Safe               # the safe-apply flow above
Write-PSTermResult     @{ Host=...; State=...; Detail=... } # one table row
Get-PSTermCredential   'lab enable'
ConvertFrom-PSTermTable $text                               # show interfaces status, cdp neighbors detail, ...
```

### Headless sessions: the foundation

Driving a visible terminal for fifty switches at once is the wrong tool. The plugin host
needs **headless sessions**: `ssh.exe` with its input and output piped instead of attached
to a pseudo-console, driven by the same prompt engine PSTerm already uses for auto-login
and auto-enable. Passwords can be supplied with `SSH_ASKPASS`. A runspace pool runs N
sessions at once (default 10), with per-host timeouts and a log file per host. I would
build this before any plugin, because plugins, safe apply and "learn from device" all
stand on it - and because it makes everything testable without hardware.

PowerShell 7's `ForEach-Object -Parallel` does not exist on 5.1, which PSTerm supports, so
the runspace pool should be PSTerm's own.

### Your three examples

- **Roll out a standard config to many switches.** The 80% case needs no code: a *template
  with variables* (`hostname {{name}}`, `ip address {{mgmt}} 255.255.255.0`) and a table of
  values. Substitution should be plain `{{name}}`, not PowerShell string expansion, so a
  value from a spreadsheet can never run code. Flow: **plan → dry run → apply**, with a
  canary (first host alone, then the rest), per-host results, safe apply on every host,
  and a table at the end - online/offline, config applied, saved, error text, export.
  The first run of any plugin that writes should be a dry run by default.
- **Physical-issue board.** Read-only, so it is the safest first plugin to ship:
  `show interfaces` counters, `show interfaces status`, transceiver levels, flap counts from
  `show logging`; thresholds decide which ports matter; the result is a traffic-light board.
- **CDP/LLDP topology.** A breadth-first walk of `show cdp neighbors detail`: connect to each
  neighbour's management address, remember device IDs to stop loops, limit the depth. The
  result is nodes and links, drawn as SVG (written directly - no library needed) with
  PNG, SVG and two CSV files (devices, links) as exports.

### SNMP, TFTP/HTTP, SCP

- **SNMP** has no client on Windows any more. A v2c GET/WALK is about 500 lines of C# with no
  dependencies; v3 adds authentication and privacy but .NET has the cryptography. It makes
  counters and neighbour tables much faster across many hosts, but needs SNMP enabled on
  the device. "Enable temporarily" is a configuration change, so it must go through safe
  apply and be undone in a `finally`. I would do CLI first and SNMP later as a read-only
  accelerator.
- **File transfer:** `scp.exe` ships with OpenSSH. For pushing images or configs to a
  device, a small TFTP or HTTP listener inside PSTerm that the device pulls from
  (`copy http://... flash:`) is simpler and more reliable than pushing.

### Safety

A plugin is code. Run untrusted ones in PowerShell's constrained language mode with the host
API as the only way out; allow full language only for signed plugins (the repository already
has a signing script). Writes need the dry run, the permission prompt, and an audit log.

### Suggested order

headless sessions and prompt engine → plugin host, manifest, table result and exports →
**read-only** plugins (health board, topology) → templates and rollouts with safe apply →
SNMP and file-transfer accelerators.

---

## Overall order I would build in

1. Device driver and presets (small, and everything else leans on it)
2. Headless sessions with the prompt engine
3. Plugin host, then read-only plugins
4. Command packs, paste validation, command browser
5. Config view, then editing with safe apply, then write-capable plugins

Reasoning: reading from devices is low-risk and delivers value early; anything that writes
should only arrive together with the dry run and the safe-apply flow.

## Things I would want your decision on

- Are Windows PowerShell 5.1 and 7 both targets for plugins? (5.1 rules out `-Parallel`.)
- A third-party SSH library (SSH.NET is MIT licensed) would make headless sessions simpler than
  `ssh.exe` with `SSH_ASKPASS`, at the cost of PSTerm's "nothing is downloaded" rule.
- Where plugin credentials should come from: the existing quick credentials, or a
  separate vault.
- Whether converted command packs may be shared inside your organisation, which is a
  question for whoever owns the Cisco licence terms.
