// PSTerm - TerminalSession.cs
// Wires a transport to a terminal: bytes in, decoded and parsed; keys out,
// encoded and written. Logging taps the same path.
//
// This class exists so that no PowerShell code ever sits in the data path.
// Backends raise DataReceived on their own reader thread, and a PowerShell
// script block invoked as a delegate from a native background thread has no
// runspace to run in - it hangs or is dropped. Everything between the wire and
// the screen is therefore C#, and the events PSTerm exposes to the UI layer are
// marshalled onto the UI thread first.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Text.RegularExpressions;
using PSTerm.Automation;
using PSTerm.Backends;
using PSTerm.Io;
using PSTerm.Vt;

namespace PSTerm
{
    /// <summary>Anything that can accept decoded characters. Implemented by the
    /// terminal control, and by a bare emulator for headless use and tests.</summary>
    public interface ITerminalSink
    {
        void Feed(char[] buffer, int offset, int count);
        object SyncRoot { get; }
    }

    /// <summary>A sink backed by an emulator with no UI, for tests and scripted sessions.</summary>
    public sealed class EmulatorSink : ITerminalSink
    {
        private readonly TerminalEmulator _term;
        private readonly object _sync = new object();

        public EmulatorSink(TerminalEmulator term)
        {
            if (term == null) throw new ArgumentNullException("term");
            _term = term;
        }

        public TerminalEmulator Terminal { get { return _term; } }
        public object SyncRoot { get { return _sync; } }

        public void Feed(char[] buffer, int offset, int count)
        {
            lock (_sync) { _term.Write(buffer, offset, count); }
        }
    }

    public class SessionClosedEventArgs : EventArgs
    {
        public readonly string Reason;
        public readonly int? ExitCode;
        public SessionClosedEventArgs(string reason, int? exitCode) { Reason = reason; ExitCode = exitCode; }
    }

    public class SessionMessageEventArgs : EventArgs
    {
        public readonly string Message;
        public SessionMessageEventArgs(string message) { Message = message; }
    }

    public sealed class TerminalSession : IDisposable
    {
        private readonly ITerminalBackend _backend;
        private readonly ITerminalSink _sink;
        private readonly StreamDecoder _decoder;
        private readonly TerminalEmulator _term;

        private SessionLogger _logger;
        private ISynchronizeInvoke _marshal;
        private volatile bool _hasClosed;
        private int? _exitCode;
        private string _closeReason;
        private string _title;
        private readonly ManualResetEvent _closedEvent = new ManualResetEvent(false);
        private int _disposed;
        private int _lastDataTick = Environment.TickCount;
        private int _dataChunks;

        /// <summary>Raised on the UI thread when the session ends.</summary>
        public event EventHandler<SessionClosedEventArgs> SessionClosed;
        /// <summary>Raised on the UI thread when the link comes up. A transport that
        /// connects in the background raises it some time after Connect() returns.</summary>
        public event EventHandler<SessionMessageEventArgs> Connected;
        /// <summary>Raised on the UI thread for progress messages.</summary>
        public event EventHandler<SessionMessageEventArgs> StatusChanged;
        /// <summary>Raised on the UI thread when the host sets the window title.</summary>
        public event EventHandler<SessionMessageEventArgs> TitleChanged;

        public TerminalSession(ITerminalBackend backend, ITerminalSink sink,
                               TerminalEmulator term, StreamDecoder decoder)
        {
            if (backend == null) throw new ArgumentNullException("backend");
            if (sink == null) throw new ArgumentNullException("sink");
            if (term == null) throw new ArgumentNullException("term");

            _backend = backend;
            _sink = sink;
            _term = term;
            _decoder = decoder != null ? decoder : new StreamDecoder(TerminalEncoding.Utf8);

            _backend.DataReceived += OnBackendData;
            _backend.Closed += OnBackendClosed;
            _backend.Status += OnBackendStatus;
            _term.TitleChanged += OnTitle;
        }

        public ITerminalBackend Backend { get { return _backend; } }
        public TerminalEmulator Terminal { get { return _term; } }
        public StreamDecoder Decoder { get { return _decoder; } }
        public bool IsConnected { get { return _backend.IsConnected; } }
        public string Description { get { return _backend.Description; } }

        /// <summary>True once the session has ended.</summary>
        public bool HasClosed { get { return _hasClosed; } }
        /// <summary>Exit code of the hosted process, when there was one.</summary>
        public int? ExitCode { get { return _exitCode; } }
        /// <summary>Why the session ended, or null for a clean close.</summary>
        public string CloseReason { get { return _closeReason; } }
        /// <summary>How many chunks of host output have arrived. Lets a script tell
        /// whether anything has been heard since it last sent something.</summary>
        public int DataChunks { get { return Volatile.Read(ref _dataChunks); } }
        /// <summary>Milliseconds since the host last sent anything.</summary>
        public int IdleMilliseconds { get { return unchecked(Environment.TickCount - _lastDataTick); } }
        /// <summary>The most recent title the host asked for.</summary>
        public string Title { get { return _title; } }

        /// <summary>
        /// The object used to marshal events onto the UI thread. Set this to the
        /// terminal control (or the form) before connecting when there is a UI.
        /// </summary>
        public ISynchronizeInvoke SynchronizingObject
        {
            get { return _marshal; }
            set { _marshal = value; }
        }

        public SessionLogger Logger
        {
            get { return _logger; }
            set { _logger = value; }
        }

        public void Connect()
        {
            _backend.Connect();
        }

        // =====================================================================
        // Wire -> screen
        // =====================================================================

        private void OnBackendData(object sender, DataReceivedEventArgs e)
        {
            _lastDataTick = Environment.TickCount;
            Interlocked.Increment(ref _dataChunks);

            SessionLogger logger = _logger;
            if (logger != null) logger.WriteFromHost(e.Buffer, e.Offset, e.Count);

            int charCount;
            char[] chars = _decoder.Decode(e.Buffer, e.Offset, e.Count, out charCount);
            if (charCount > 0)
            {
                _sink.Feed(chars, 0, charCount);

                ExpectEngine expect = _expect;
                if (expect != null) expect.Feed(chars, 0, charCount);
            }
        }

        // =====================================================================
        // Paced sending
        // =====================================================================

        private int _pacing;
        private volatile bool _cancelPacing;

        /// <summary>True while a pasted block is being fed to the device line by line.</summary>
        public bool IsPacing { get { return Volatile.Read(ref _pacing) != 0; } }

        /// <summary>Raised on the UI thread with a progress or result message.</summary>
        public event EventHandler<SessionMessageEventArgs> PacingMessage;

        /// <summary>Stop a paced paste after the line in flight.</summary>
        public void CancelPaced() { _cancelPacing = true; }

        /// <summary>
        /// Send several lines one at a time, waiting for the device to answer each one
        /// before the next goes out. A serial console has no flow control to speak of:
        /// pasted at full speed, a block of configuration can overrun it and arrive with
        /// characters missing - silently, and in a configuration. Returns at once; the
        /// work runs on a worker thread.
        /// </summary>
        public void SendPaced(string text)
        {
            if (string.IsNullOrEmpty(text)) return;

            List<string> lines = new List<string>(text.Replace("\r\n", "\r").Replace("\n", "\r").Split(new char[] { (char)13 }));
            bool endsWithBreak = text.EndsWith("\r") || text.EndsWith("\n");
            if (endsWithBreak && lines.Count > 0) lines.RemoveAt(lines.Count - 1);

            if (lines.Count <= 1)
            {
                Send(text);
                return;
            }

            if (Interlocked.Exchange(ref _pacing, 1) != 0)
            {
                // A paste is already running: this one waits its turn behind it.
                ThreadPool.QueueUserWorkItem(delegate
                {
                    while (IsPacing && !_hasClosed) Thread.Sleep(100);
                    SendPaced(text);
                });
                return;
            }

            _cancelPacing = false;
            ThreadPool.QueueUserWorkItem(delegate { RunPaced(lines, endsWithBreak); });
        }

        private void RunPaced(List<string> lines, bool lastLineEnds)
        {
            int sent = 0;
            string outcome = "Pasted " + lines.Count.ToString() + " lines.";
            try
            {
                for (int i = 0; i < lines.Count; i++)
                {
                    if (_cancelPacing) { outcome = "Paste stopped after " + sent.ToString() + " of " + lines.Count.ToString() + " lines."; break; }
                    if (_hasClosed) { outcome = "The session ended after " + sent.ToString() + " of " + lines.Count.ToString() + " lines."; break; }

                    bool last = (i == lines.Count - 1);
                    int seq = Volatile.Read(ref _dataChunks);
                    Send(lines[i] + ((!last || lastLineEnds) ? "\r" : ""));
                    sent++;

                    if (!last || lastLineEnds) WaitForDevice(seq);
                    if (!last && (i % 5) == 4) RaisePacing("Pasting: " + sent.ToString() + " of " + lines.Count.ToString() + " lines...");
                }
            }
            catch (Exception ex) { outcome = "The paste failed: " + ex.Message; }
            finally { Interlocked.Exchange(ref _pacing, 0); }
            RaisePacing(outcome);
        }

        /// <summary>
        /// Wait for the device to answer the line just sent: some output, then quiet, then
        /// a cursor line that looks like a prompt. A command that takes a while to finish
        /// (generating a key) shows nothing at the cursor until it does, so it is waited
        /// for, up to a limit, rather than answered by the next line piling in.
        /// </summary>
        private void WaitForDevice(int seq)
        {
            int start = Environment.TickCount;

            // The echo of what was just sent.
            while (Volatile.Read(ref _dataChunks) == seq && unchecked(Environment.TickCount - start) < 4000)
            {
                if (_cancelPacing || _hasClosed) return;
                Thread.Sleep(10);
            }

            while (unchecked(Environment.TickCount - start) < 45000)
            {
                if (_cancelPacing || _hasClosed) return;
                if (IdleMilliseconds >= 200 && CursorLineLooksLikePrompt()) return;
                Thread.Sleep(20);
            }
        }

        private static readonly Regex NoiseLine = new Regex(new DeviceDriver().NoisePattern);

        /// <summary>
        /// True when the device is waiting at a prompt. A device may print a log message
        /// straight after its prompt without drawing the prompt again, so a cursor sitting
        /// on such a line counts if the last real line above it looks like a prompt.
        /// </summary>
        public bool IsAtPrompt()
        {
            lock (_sink.SyncRoot)
            {
                ScreenBuffer screen = _term.Screen;
                int abs = screen.HistoryCount + _term.CursorY;
                for (int k = 0; k < 10 && abs - k >= 0; k++)
                {
                    int row = abs - k;
                    if (row >= screen.TotalLines) continue;
                    string line = screen.GetLineText(row).TrimEnd();
                    if (line.Length == 0)
                    {
                        // An empty cursor line is a device still working; an empty line above
                        // a log message is just spacing.
                        if (k == 0) return false;
                        continue;
                    }
                    if (NoiseLine.IsMatch(line.TrimStart())) continue;
                    return EndsLikePrompt(line);
                }
                return false;
            }
        }

        private static bool EndsLikePrompt(string line)
        {
            char c = line[line.Length - 1];
            // > # ] : ? ) $
            return c == (char)62 || c == (char)35 || c == (char)93 || c == (char)58 || c == (char)63 || c == (char)41 || c == (char)36;
        }

        private bool CursorLineLooksLikePrompt() { return IsAtPrompt(); }

        private void RaisePacing(string message)
        {
            RaiseOnUi(new Action(delegate
            {
                EventHandler<SessionMessageEventArgs> h = PacingMessage;
                if (h != null) h(this, new SessionMessageEventArgs(message));
            }));
        }

        // =====================================================================
        // Prompt automation
        // =====================================================================

        private ExpectEngine _expect;

        /// <summary>Raised on the UI thread when a rule added with notify set matches.
        /// The message is the rule's name.</summary>
        public event EventHandler<SessionMessageEventArgs> RuleMatched;

        /// <summary>The prompt-answering engine, created on first use.</summary>
        public ExpectEngine Expect
        {
            get
            {
                if (_expect == null) _expect = new ExpectEngine(Send);
                return _expect;
            }
        }

        /// <summary>
        /// Answer a prompt. <paramref name="pattern"/> is a regular expression matched
        /// against the line the host is waiting on; <paramref name="reply"/> is sent
        /// after <paramref name="delayMs"/>. Written for PowerShell callers, which
        /// cannot construct a rule with a callback of their own.
        /// </summary>
        public void AddRule(string name, string pattern, string reply, int delayMs, bool once,
                            bool armed, int expireAfterMs, string[] arms, bool notify)
        {
            ExpectRule rule = new ExpectRule();
            rule.Name = name;
            rule.Pattern = new Regex(pattern, RegexOptions.IgnoreCase);
            rule.Reply = reply;
            rule.DelayMs = delayMs;
            rule.Once = once;
            rule.Armed = armed;
            rule.ExpireAfterMs = expireAfterMs;
            rule.Arms = arms ?? new string[0];

            if (notify)
            {
                rule.OnMatch = delegate(ExpectRule r, string line)
                {
                    string ruleName = r.Name;
                    RaiseOnUi(new Action(delegate
                    {
                        EventHandler<SessionMessageEventArgs> h = RuleMatched;
                        if (h != null) h(this, new SessionMessageEventArgs(ruleName));
                    }));
                };
            }

            Expect.Add(rule);
        }

        // =====================================================================
        // Keyboard -> wire
        // =====================================================================

        /// <summary>Send text to the host. Used by the control's Input event and by
        /// scripted input such as a profile's login sequence.</summary>
        public void Send(string text)
        {
            if (string.IsNullOrEmpty(text)) return;
            byte[] bytes = _decoder.Encode(text);
            SendBytes(bytes, 0, bytes.Length);
        }

        public void SendBytes(byte[] data, int offset, int count)
        {
            if (data == null || count <= 0) return;

            SessionLogger logger = _logger;
            if (logger != null) logger.WriteFromUser(data, offset, count);

            _backend.Write(data, offset, count);
        }

        public void Resize(int cols, int rows)
        {
            _backend.Resize(cols, rows);
        }

        // =====================================================================
        // Lifecycle
        // =====================================================================

        private void OnBackendStatus(object sender, BackendStatusEventArgs e)
        {
            bool connected = e.Connected;
            RaiseOnUi(new Action(delegate
            {
                EventHandler<SessionMessageEventArgs> h = StatusChanged;
                if (h != null) h(this, new SessionMessageEventArgs(e.Message));

                if (connected)
                {
                    EventHandler<SessionMessageEventArgs> up = Connected;
                    if (up != null) up(this, new SessionMessageEventArgs(e.Message));
                }
            }));
        }

        private void OnTitle(string title)
        {
            _title = title;
            RaiseOnUi(new Action(delegate
            {
                EventHandler<SessionMessageEventArgs> h = TitleChanged;
                if (h != null) h(this, new SessionMessageEventArgs(title));
            }));
        }

        private void OnBackendClosed(object sender, BackendClosedEventArgs e)
        {
            SessionLogger logger = _logger;
            if (logger != null) logger.Close();

            // Record the outcome before signalling, so anything woken by
            // WaitForClose can read it immediately rather than racing the event.
            _exitCode = e.ExitCode;
            _closeReason = e.Reason;
            _hasClosed = true;

            _closedEvent.Set();

            RaiseOnUi(new Action(delegate
            {
                EventHandler<SessionClosedEventArgs> h = SessionClosed;
                if (h != null) h(this, new SessionClosedEventArgs(e.Reason, e.ExitCode));
            }));
        }

        /// <summary>
        /// Invoke on the UI thread when there is one. Handlers written in PowerShell
        /// can only run there, so this must not be bypassed.
        /// </summary>
        private void RaiseOnUi(Action action)
        {
            ISynchronizeInvoke target = _marshal;
            if (target != null && target.InvokeRequired)
            {
                try { target.BeginInvoke(action, null); return; }
                catch (ObjectDisposedException) { return; }
                catch (InvalidOperationException) { return; }
            }
            try { action.DynamicInvoke(null); }
            catch (Exception) { }
        }

        /// <summary>Block until the session closes. Returns false on timeout.</summary>
        public bool WaitForClose(int millisecondsTimeout)
        {
            return _closedEvent.WaitOne(millisecondsTimeout);
        }

        public void Disconnect()
        {
            try { _backend.Disconnect(); }
            catch (Exception) { }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

            _backend.DataReceived -= OnBackendData;
            _backend.Closed -= OnBackendClosed;
            _backend.Status -= OnBackendStatus;
            _term.TitleChanged -= OnTitle;

            try { _backend.Dispose(); }
            catch (Exception) { }

            SessionLogger logger = _logger;
            if (logger != null) { logger.Close(); _logger = null; }

            _closedEvent.Close();
        }
    }
}
