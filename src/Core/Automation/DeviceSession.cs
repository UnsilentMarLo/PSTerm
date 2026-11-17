// PSTerm - DeviceSession.cs
// A session with a network device that is driven by code rather than by a person:
// send a command, wait for the device to finish, get its output back as text.
//
// It sits on any transport (a serial port, Telnet, or ssh in a pseudo-console), so
// the same script works on all of them. Nothing here draws anything: the output is
// read into lines the way a log would be (see LineAssembler), and the device's own
// prompt, which the driver describes, is what says a command has finished.
//
// What makes it dependable rather than merely working:
//  * "Finished" is the prompt AND a short quiet period, so a line that merely looks
//    like a prompt in the middle of output does not end a command early.
//  * The pager is switched off at the start and answered if it appears anyway.
//  * A command that never finishes returns what it has, flagged as timed out,
//    instead of hanging the script.
//  * Login is answered at most once per prompt: a wrong password is not retried.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using PSTerm.Backends;
using PSTerm.Io;
using PSTerm.Vt;

namespace PSTerm.Automation
{
    /// <summary>What a family of devices looks like from outside. Plain data, loaded
    /// from a JSON file so a new vendor needs no code.</summary>
    public sealed class DeviceDriver
    {
        public string Name = "generic";

        /// <summary>The unfinished last line is a prompt when this matches it.</summary>
        public string PromptPattern = @"^[\w.\-/()+@:~ ]*[>#$]\s*$";
        public string UserPromptPattern = @">\s*$";
        public string PrivilegedPromptPattern = @"#\s*$";
        public string ConfigPromptPattern = @"\(config[^)]*\)#\s*$";

        public string PagerPattern = @"--More--\s*$";
        public string PagerKey = " ";
        public string DisablePagerCommand = "";

        /// <summary>A line of output that means the device refused the command.</summary>
        public string ErrorPattern = @"^%\s";

        /// <summary>Questions a command can end in: answered when asked to.</summary>
        /// <summary>"[confirm]": answered with Enter when the caller allows it.</summary>
        public string ConfirmPattern = @"\[confirm\]\s*$";
        /// <summary>"[yes/no]": answered with YesNoReply, which is "no" unless the caller
        /// says otherwise - a device asking whether to save before reloading must not be
        /// told yes by accident.</summary>
        public string YesNoPattern = @"\[yes/no\]:?\s*$";

        /// <summary>
        /// A line the device prints by itself, not in answer to anything (a console log
        /// message, a shutdown banner). It can land straight after a prompt and, left
        /// unconsidered, hides the prompt from whoever is waiting for it.
        /// </summary>
        public string NoisePattern = @"^\*?[A-Za-z]{3}\s+\d+\s+[\d:.]+:\s*%|^\*{3}|^%\S";

        public string PasswordPromptPattern = @"(password|passphrase|passcode)[^:\r\n]*:\s*$";
        public string UserNamePromptPattern = @"(user ?name|login)[^:\r\n]*:\s*$";

        public string EnableCommand = "enable";
        public string ConfigureCommand = "configure terminal";
        public string EndConfigCommand = "end";
        public string SaveCommand = "write memory";
        /// <summary>{minutes} is replaced.</summary>
        public string ReloadInCommand = "reload in {minutes}";
        public string ReloadCancelCommand = "reload cancel";
    }

    public sealed class CommandResult
    {
        public string Command = "";
        public string[] Lines = new string[0];
        public string Prompt = "";
        public bool TimedOut;
        /// <summary>The first line of output that matched the driver's error pattern.</summary>
        public string Error = "";
        public bool Succeeded { get { return !TimedOut && Error.Length == 0; } }
        public string Text { get { return string.Join("\n", Lines); } }
    }

    public sealed class DeviceSession : IDisposable
    {
        private readonly ITerminalBackend _backend;
        private readonly StreamDecoder _decoder;
        private readonly DeviceDriver _driver;
        private readonly Regex _noise, _prompt, _user, _privileged, _config, _pager, _error, _confirm, _yesNo, _passwordPrompt, _userPrompt;

        private readonly object _gate = new object();
        private readonly LineAssembler _assembler = new LineAssembler();
        private readonly List<string> _lines = new List<string>();
        private readonly List<string> _scratch = new List<string>();
        private int _lastDataTick = Environment.TickCount;
        private readonly ManualResetEvent _signal = new ManualResetEvent(false);
        private volatile bool _closed;
        private int _seq;      // counts chunks received, so "something arrived since" can be asked
        private string _closeReason = "";

        public event EventHandler Closed;

        public DeviceSession(ITerminalBackend backend, DeviceDriver driver, TerminalEncoding encoding)
        {
            if (backend == null) throw new ArgumentNullException("backend");
            _backend = backend;
            _driver = driver ?? new DeviceDriver();
            _decoder = new StreamDecoder(encoding);

            RegexOptions o = RegexOptions.IgnoreCase;
            _noise = new Regex(_driver.NoisePattern, RegexOptions.None);
            _prompt = new Regex(_driver.PromptPattern, o);
            _user = new Regex(_driver.UserPromptPattern, o);
            _privileged = new Regex(_driver.PrivilegedPromptPattern, o);
            _config = new Regex(_driver.ConfigPromptPattern, o);
            _pager = new Regex(_driver.PagerPattern, o);
            _error = new Regex(_driver.ErrorPattern, RegexOptions.None);
            _confirm = new Regex(_driver.ConfirmPattern, o);
            _yesNo = new Regex(_driver.YesNoPattern, o);
            _passwordPrompt = new Regex(_driver.PasswordPromptPattern, o);
            _userPrompt = new Regex(_driver.UserNamePromptPattern, o);

            _backend.DataReceived += OnData;
            _backend.Closed += OnClosed;
        }

        public DeviceDriver Driver { get { return _driver; } }
        public bool IsClosed { get { return _closed; } }
        public string CloseReason { get { return _closeReason; } }

        /// <summary>
        /// The prompt the device is at: the line being written when it is one, otherwise
        /// the last real line before any messages the device printed on its own.
        /// </summary>
        private string EffectivePrompt()
        {
            lock (_gate)
            {
                string pending = _assembler.Pending.Trim();
                if (pending.Length > 0 && !_noise.IsMatch(pending)) return pending;

                for (int i = _lines.Count - 1; i >= 0 && i >= _lines.Count - 12; i--)
                {
                    string line = _lines[i].Trim();
                    if (line.Length == 0 || _noise.IsMatch(line)) continue;
                    return _prompt.IsMatch(line) ? line : "";
                }
                return pending;
            }
        }

        /// <summary>
        /// The last line that is not console noise, and where it is: the line being written,
        /// or the newest finished one. A question the device asked can be followed by a log
        /// line it printed on its own, so the question is not always the line under the cursor.
        /// </summary>
        private string LastRealLine(out int index)
        {
            lock (_gate)
            {
                string pending = _assembler.Pending.Trim();
                index = _lines.Count;
                if (pending.Length > 0 && !_noise.IsMatch(pending)) return pending;
                for (int i = _lines.Count - 1; i >= 0 && i >= _lines.Count - 12; i--)
                {
                    string line = _lines[i].Trim();
                    if (line.Length == 0 || _noise.IsMatch(line)) continue;
                    index = i;
                    return line;
                }
                index = -1;
                return pending;
            }
        }

        /// <summary>The prompt the device is showing (or last showed).</summary>
        public string Prompt { get { return EffectivePrompt(); } }

        /// <summary>User, Privileged, Config or Unknown, from the prompt.</summary>
        public string Mode
        {
            get
            {
                string p = Prompt;
                if (p.Length == 0) return "Unknown";
                if (_config.IsMatch(p)) return "Config";
                if (_privileged.IsMatch(p)) return "Privileged";
                if (_user.IsMatch(p)) return "User";
                return "Unknown";
            }
        }

        // =====================================================================
        // Wire side
        // =====================================================================

        private void OnData(object sender, DataReceivedEventArgs e)
        {
            int count;
            char[] chars;
            lock (_gate)
            {
                chars = _decoder.Decode(e.Buffer, e.Offset, e.Count, out count);
                if (count > 0)
                {
                    _scratch.Clear();
                    _assembler.Feed(new string(chars, 0, count), _scratch);
                    _lines.AddRange(_scratch);
                    _lastDataTick = Environment.TickCount;
                    _seq++;
                }
            }
            _signal.Set();
        }

        private void OnClosed(object sender, BackendClosedEventArgs e)
        {
            _closed = true;
            _closeReason = e.Reason ?? "";
            _signal.Set();
            EventHandler h = Closed;
            if (h != null) h(this, EventArgs.Empty);
        }

        public void Connect()
        {
            _backend.Connect();
        }

        private void Write(string text)
        {
            byte[] bytes = _decoder.Encode(text);
            _backend.Write(bytes, 0, bytes.Length);
        }

        /// <summary>Send text exactly as given, with no wait.</summary>
        public void SendRaw(string text) { Write(text); }

        // =====================================================================
        // Waiting
        // =====================================================================

        private int QuietMs { get { lock (_gate) { return unchecked(Environment.TickCount - _lastDataTick); } } }

        private string PendingNow { get { lock (_gate) { return _assembler.Pending; } } }

        private int Seq { get { lock (_gate) { return _seq; } } }

        private bool PendingIsPager { get { lock (_gate) { return _assembler.PendingIsPager; } } }

        /// <summary>
        /// Wait until the device is showing a prompt and has gone quiet. Returns false
        /// on timeout or when the session closes.
        /// </summary>
        public bool WaitForPrompt(int timeoutMs)
        {
            return WaitForPromptCore(timeoutMs, false, 0);
        }

        private bool WaitForPromptCore(int timeoutMs, bool autoConfirm, int minSeq)
        {
            return WaitForPromptCore(timeoutMs, autoConfirm, minSeq, "no");
        }

        private bool WaitForPromptCore(int timeoutMs, bool autoConfirm, int minSeq, string yesNoReply)
        {
            int start = Environment.TickCount;
            int lastNudge = start;
            int answeredIndex = -2;             // the line of the question we last answered
            bool nudgedAfterAnswer = false;
            while (unchecked(Environment.TickCount - start) < timeoutMs)
            {
                if (_closed) return false;

                // Right after a command goes out the old prompt is still on the line.
                // Nothing counts until the device has said something new (its echo).
                if (minSeq >= 0 && Seq <= minSeq) { WaitForChange(30); continue; }

                string pending = PendingNow;
                int quiet = QuietMs;

                if (PendingIsPager)
                {
                    if (quiet >= 60) { Write(_driver.PagerKey); WaitForChange(400); }
                    continue;
                }

                int questionIndex = -1;
                string question = "";
                if (autoConfirm) question = LastRealLine(out questionIndex);
                if (autoConfirm && quiet >= 150 && questionIndex != answeredIndex)
                {
                    if (_confirm.IsMatch(question)) { answeredIndex = questionIndex; Write("\r"); WaitForChange(400); continue; }
                    if (_yesNo.IsMatch(question)) { answeredIndex = questionIndex; Write(yesNoReply + "\r"); WaitForChange(400); continue; }
                }

                // Some commands (reload in N) answer a confirmation with a banner and do not draw
                // the prompt again. If nothing but console noise has followed the question we
                // answered, the command is over: one bare Enter brings the prompt back.
                if (autoConfirm && answeredIndex != -2 && !nudgedAfterAnswer && quiet >= 1500 && questionIndex == answeredIndex)
                {
                    nudgedAfterAnswer = true;
                    Write("\r");
                    WaitForChange(400);
                    continue;
                }

                // Before a command goes out, a screen left blank by an asynchronous message
                // (a syslog line, a "SHUTDOWN ABORTED" banner) gets a bare Enter to redraw the
                // prompt. Never while a command is running: there a blank line is just a
                // command that has nothing to say yet.
                if (minSeq < 0 && quiet >= 700 && EffectivePrompt().Length == 0 &&
                    unchecked(Environment.TickCount - lastNudge) > 1500)
                {
                    lastNudge = Environment.TickCount;
                    Write("\r");
                    WaitForChange(300);
                    continue;
                }

                // A prompt ends the command only once the device has stopped talking.
                string effective = EffectivePrompt();
                if (quiet >= 120 && effective.Length > 0 && _prompt.IsMatch(effective)) return true;

                WaitForChange(50);
            }
            return false;
        }

        private void WaitForChange(int ms)
        {
            _signal.Reset();
            _signal.WaitOne(ms);
        }

        // =====================================================================
        // Login
        // =====================================================================

        /// <summary>
        /// Get to a usable prompt: answer a user name and password prompt (each at
        /// most once), wake a console that is waiting for a key, and optionally enter
        /// privileged mode. Returns an empty string on success, otherwise why not.
        /// </summary>
        public string Open(string user, string password, string enablePassword, bool enter, int timeoutMs)
        {
            int start = Environment.TickCount;
            bool sentUser = false, sentPassword = false, sentEnable = false, enableAsked = false, wokeConsole = false, answeredLeftover = false;

            while (unchecked(Environment.TickCount - start) < timeoutMs)
            {
                if (_closed) return "The connection closed" + (_closeReason.Length > 0 ? ": " + _closeReason : ".");

                // A console left in the middle of paged output is waiting for a key.
                if (PendingIsPager && QuietMs >= 100) { Write(_driver.PagerKey); WaitForChange(300); continue; }

                string pending = EffectivePrompt();

                // Only act on what the device has finished saying.
                if (QuietMs < 150) { WaitForChange(60); continue; }

                // A question left unanswered by whoever was here before. "No" is the answer that
                // changes nothing.
                if ((_yesNo.IsMatch(pending) || _confirm.IsMatch(pending)) && !answeredLeftover)
                {
                    // For a [confirm] anything but a bare Enter declines, so "n" cancels.
                    answeredLeftover = true;
                    Write(_yesNo.IsMatch(pending) ? "no\r" : "n\r");
                    WaitForChange(400);
                    continue;
                }

                if (_passwordPrompt.IsMatch(pending))
                {
                    if (!sentPassword && !enableAsked)
                    {
                        if (string.IsNullOrEmpty(password)) return "The device asks for a password and none is saved.";
                        sentPassword = true; Write(password + "\r"); WaitForChange(300); continue;
                    }
                    if (enableAsked && !sentEnable)
                    {
                        if (string.IsNullOrEmpty(enablePassword)) return "The device asks for an enable password and none is saved.";
                        sentEnable = true; Write(enablePassword + "\r"); WaitForChange(300); continue;
                    }
                    // Asked again after an answer: it was refused, and is not tried twice.
                    return enableAsked ? "The enable password was refused." : "The password was refused.";
                }

                if (_userPrompt.IsMatch(pending) && !sentUser && !string.IsNullOrEmpty(user))
                {
                    sentUser = true; Write(user + "\r"); WaitForChange(300); continue;
                }

                if (_prompt.IsMatch(pending))
                {
                    if (enter && !enableAsked && _user.IsMatch(pending))
                    {
                        enableAsked = true;
                        Write(_driver.EnableCommand + "\r");
                        WaitForChange(400);
                        continue;
                    }
                    break;
                }

                if (pending.Length == 0 && !wokeConsole && QuietMs >= 400)
                {
                    // A serial console showing nothing is usually waiting for a key.
                    wokeConsole = true;
                    Write("\r");
                    WaitForChange(500);
                    continue;
                }

                WaitForChange(60);
            }

            string mode = Mode;
            if (mode == "Unknown") return "No prompt appeared (the last line was: " + Prompt + ").";
            if (enter && mode == "User") return "Could not enter privileged mode.";
            return "";
        }
        // =====================================================================
        // Commands
        // =====================================================================

        /// <summary>Send a command and return what it printed.</summary>
        public CommandResult Invoke(string command, int timeoutMs)
        {
            return Invoke(command, timeoutMs, false);
        }

        public CommandResult Invoke(string command, int timeoutMs, bool autoConfirm)
        {
            return Invoke(command, timeoutMs, autoConfirm, "no");
        }

        /// <summary>
        /// With <paramref name="autoConfirm"/>, a "[confirm]" is answered with Enter and a
        /// "[yes/no]" with <paramref name="yesNoReply"/>.
        /// </summary>
        public CommandResult Invoke(string command, int timeoutMs, bool autoConfirm, string yesNoReply)
        {
            if (command == null) command = "";
            int first;

            // Let the device finish whatever it was doing before the command goes in.
            WaitForPromptCore(3000, false, -1);
            int seq;
            lock (_gate) { first = _lines.Count; seq = _seq; }

            Write(command + "\r");
            bool finished = WaitForPromptCore(timeoutMs, autoConfirm, seq, yesNoReply);

            CommandResult result = new CommandResult();
            result.Command = command;
            result.TimedOut = !finished;

            lock (_gate)
            {
                List<string> output = new List<string>();
                for (int i = first; i < _lines.Count; i++) output.Add(_lines[i]);

                // The first line is the prompt with the command echoed after it.
                if (output.Count > 0) output.RemoveAt(0);

                result.Lines = output.ToArray();
                result.Prompt = EffectivePrompt();
            }

            foreach (string line in result.Lines)
            {
                if (_error.IsMatch(line)) { result.Error = line.Trim(); break; }
            }

            // Output is trimmed of the blank lines a device puts around it.
            int s = 0, e = result.Lines.Length - 1;
            while (s <= e && result.Lines[s].Trim().Length == 0) s++;
            while (e >= s && result.Lines[e].Trim().Length == 0) e--;
            if (s > 0 || e < result.Lines.Length - 1)
            {
                string[] trimmed = new string[Math.Max(0, e - s + 1)];
                Array.Copy(result.Lines, s, trimmed, 0, trimmed.Length);
                result.Lines = trimmed;
            }
            return result;
        }

        /// <summary>Turn the pager off, as the driver says.</summary>
        public void DisablePager()
        {
            if (_driver.DisablePagerCommand.Length > 0) Invoke(_driver.DisablePagerCommand, 5000);
        }

        public void Dispose()
        {
            _backend.DataReceived -= OnData;
            _backend.Closed -= OnClosed;
            try { _backend.Dispose(); } catch (Exception) { }
            _signal.Close();
        }
    }
}
