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
using System.Text;
using System.Threading;
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
        public int DataChunks { get { return Thread.VolatileRead(ref _dataChunks); } }
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
            if (charCount > 0) _sink.Feed(chars, 0, charCount);
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
