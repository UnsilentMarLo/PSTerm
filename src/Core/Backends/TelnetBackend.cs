// PSTerm - TelnetBackend.cs
// Telnet transport with real option negotiation.
//
// v1's Telnet was non-functional: the reader ran in Start-Job, a separate
// process, so its output never reached the screen, and a live NetworkStream
// cannot be marshalled across that boundary anyway. Its negotiation refused
// every option outright (DO -> WONT, WILL -> DONT), which is a serious
// compatibility problem in its own right - equipment that never gets SGA or
// ECHO agreed will line-buffer, double-echo or simply not respond, and without
// NAWS the far end never learns the window size.
//
// This implements the options that matter for equipment consoles:
//   RFC 854 (base), 856 (binary), 857 (echo), 858 (suppress go ahead),
//   1073 (window size), 1091 (terminal type).
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace PSTerm.Backends
{
    public sealed class TelnetSettings
    {
        public string Host = "";
        public int Port = 23;

        /// <summary>Terminal type reported to the host via RFC 1091.</summary>
        public string TerminalType = "xterm-256color";

        /// <summary>Negotiate options actively rather than only responding.</summary>
        public bool ActiveNegotiation = true;

        /// <summary>Offer 8-bit binary transmission, needed for UTF-8 output.</summary>
        public bool Binary = true;

        /// <summary>Send IAC NOP periodically to hold idle sessions open. 0 disables.</summary>
        public int KeepAliveSeconds = 0;

        public int ConnectTimeoutMs = 10000;
    }

    public sealed class TelnetBackend : ITerminalBackend
    {
        // RFC 854 commands
        private const byte IAC = 255;
        private const byte DONT = 254;
        private const byte DO = 253;
        private const byte WONT = 252;
        private const byte WILL = 251;
        private const byte SB = 250;
        private const byte GA = 249;
        private const byte NOP = 241;
        private const byte SE = 240;

        // Options
        private const byte OPT_BINARY = 0;
        private const byte OPT_ECHO = 1;
        private const byte OPT_SGA = 3;
        private const byte OPT_STATUS = 5;
        private const byte OPT_TTYPE = 24;
        private const byte OPT_NAWS = 31;
        private const byte OPT_TSPEED = 32;
        private const byte OPT_LINEMODE = 34;
        private const byte OPT_NEWENV = 39;

        private const byte TTYPE_IS = 0;
        private const byte TTYPE_SEND = 1;

        private readonly TelnetSettings _settings;
        private TcpClient _client;
        private NetworkStream _stream;
        private Thread _readerThread;
        private Timer _keepAliveTimer;
        private volatile bool _closing;
        private int _closeRaised;

        private int _cols = 80;
        private int _rows = 24;

        // Negotiation state, so an option is only answered once and loops cannot form.
        private readonly HashSet<byte> _weWill = new HashSet<byte>();
        private readonly HashSet<byte> _theyWill = new HashSet<byte>();
        private readonly HashSet<byte> _weRefused = new HashSet<byte>();
        private readonly HashSet<byte> _theyRefused = new HashSet<byte>();

        // Options we have asked for and are waiting on. RFC 1143: the answer to our
        // own request is not itself answered, or two ends that both follow the rule
        // would acknowledge each other forever.
        private readonly HashSet<byte> _askedWill = new HashSet<byte>();
        private readonly HashSet<byte> _askedDo = new HashSet<byte>();

        // The sets above are written by the reader thread and read by the UI thread
        // (Resize, RemoteEcho). Held only to touch them, never across a socket write.
        private readonly object _optionLock = new object();

        // Sub-negotiation accumulator
        private readonly List<byte> _subNegotiation = new List<byte>();

        private enum ParseState { Data, Iac, Negotiate, SubNeg, SubNegIac }
        private ParseState _state = ParseState.Data;
        private byte _pendingCommand;

        public event EventHandler<DataReceivedEventArgs> DataReceived;
        public event EventHandler<BackendClosedEventArgs> Closed;
        public event EventHandler<BackendStatusEventArgs> Status;

        public TelnetBackend(TelnetSettings settings)
        {
            if (settings == null) throw new ArgumentNullException("settings");
            _settings = settings;
        }

        public bool IsConnected
        {
            get { return _client != null && _client.Connected && !_closing; }
        }

        public string Description
        {
            get { return "telnet " + _settings.Host + ":" + _settings.Port.ToString(); }
        }

        /// <summary>True once the host has agreed to echo, so the UI can show local echo state.</summary>
        public bool RemoteEcho { get { lock (_optionLock) { return _theyWill.Contains(OPT_ECHO); } } }

        public void SetInitialSize(int cols, int rows)
        {
            if (cols > 0) _cols = cols;
            if (rows > 0) _rows = rows;
        }

        /// <summary>
        /// Starts connecting and returns at once. The attempt - name lookup included,
        /// which cannot be interrupted - runs on the reader thread, because this is
        /// called from the UI thread and an unreachable host would otherwise freeze the
        /// window for the whole timeout. A failure is reported as the session closing,
        /// with the reason.
        /// </summary>
        public void Connect()
        {
            if (_readerThread != null) return;

            RaiseStatus("Connecting to " + _settings.Host + ":" + _settings.Port.ToString() + "...");

            _readerThread = new Thread(ConnectAndRead);
            _readerThread.IsBackground = true;
            _readerThread.Name = "PSTerm telnet reader";
            _readerThread.Start();
        }

        private void ConnectAndRead()
        {
            try
            {
                OpenSocket();
            }
            catch (Exception ex)
            {
                // Disconnect() closes the socket under a pending connect, which lands
                // here as an exception nobody needs to hear about.
                if (!_closing)
                    RaiseClosed("Could not connect to " + _settings.Host + ":" +
                                _settings.Port.ToString() + ": " + ex.Message, null);
                return;
            }

            if (_closing) return;

            // Negotiation is sent before the first read so the option bookkeeping is
            // complete by the time the host's answers are parsed.
            if (_settings.ActiveNegotiation) StartNegotiation();

            if (_settings.KeepAliveSeconds > 0)
            {
                int period = _settings.KeepAliveSeconds * 1000;
                _keepAliveTimer = new Timer(OnKeepAlive, null, period, period);
            }

            RaiseConnected("Connected to " + _settings.Host + ":" + _settings.Port.ToString());
            ReadLoop();
        }

        private void OpenSocket()
        {
            TcpClient client = new TcpClient();
            client.NoDelay = true;     // interactive traffic: latency beats throughput
            _client = client;          // visible to Disconnect(), which can abort the attempt

            IAsyncResult ar = client.BeginConnect(_settings.Host, _settings.Port, null, null);
            if (!ar.AsyncWaitHandle.WaitOne(_settings.ConnectTimeoutMs))
            {
                try { client.Close(); } catch (Exception) { }
                throw new IOException("timed out after " +
                                      (_settings.ConnectTimeoutMs / 1000).ToString() + " seconds");
            }
            client.EndConnect(ar);

            _stream = client.GetStream();
        }

        /// <summary>
        /// Offer the options a terminal should offer. v1 offered none, which is why
        /// devices behaved oddly: without SGA agreed they stay in half-duplex
        /// line mode, and without NAWS full-screen tools size themselves wrongly.
        /// </summary>
        private void StartNegotiation()
        {
            AskWill(OPT_TTYPE);
            AskWill(OPT_NAWS);
            AskDo(OPT_SGA);
            AskWill(OPT_SGA);
            AskDo(OPT_ECHO);
            if (_settings.Binary)
            {
                AskWill(OPT_BINARY);
                AskDo(OPT_BINARY);
            }
        }

        private void AskWill(byte option)
        {
            lock (_optionLock) { _askedWill.Add(option); }
            SendCommand(WILL, option);
        }

        private void AskDo(byte option)
        {
            lock (_optionLock) { _askedDo.Add(option); }
            SendCommand(DO, option);
        }

        private void OnKeepAlive(object state)
        {
            // IAC NOP is the correct idle probe. v1 sent a bare NUL byte, which is
            // not a telnet command at all and corrupts the data stream.
            if (!IsConnected) return;
            try { WriteRaw(new byte[] { IAC, NOP }, 0, 2); }
            catch (Exception) { }
        }

        // =====================================================================
        // Reading and protocol handling
        // =====================================================================

        private void ReadLoop()
        {
            byte[] buffer = new byte[8192];
            byte[] output = new byte[8192];
            string reason = null;

            try
            {
                while (!_closing)
                {
                    int read = _stream.Read(buffer, 0, buffer.Length);
                    if (read <= 0) break;       // the peer closed the connection

                    int outLen = ProcessIncoming(buffer, read, output);
                    if (outLen > 0)
                    {
                        EventHandler<DataReceivedEventArgs> handler = DataReceived;
                        if (handler != null) handler(this, new DataReceivedEventArgs(output, 0, outLen));
                    }
                }
            }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
            catch (SocketException ex) { reason = ex.Message; }
            catch (Exception ex) { reason = ex.Message; }

            RaiseClosed(reason, null);
        }

        /// <summary>
        /// Strip telnet protocol bytes and answer negotiation, returning the length
        /// of the application data left in <paramref name="output"/>. The parser is
        /// a state machine because a command can straddle a read boundary.
        /// </summary>
        private int ProcessIncoming(byte[] input, int length, byte[] output)
        {
            int outLen = 0;

            for (int i = 0; i < length; i++)
            {
                byte b = input[i];

                switch (_state)
                {
                    case ParseState.Data:
                        if (b == IAC) _state = ParseState.Iac;
                        else output[outLen++] = b;
                        break;

                    case ParseState.Iac:
                        if (b == IAC)
                        {
                            // Escaped 0xFF: a literal data byte.
                            output[outLen++] = IAC;
                            _state = ParseState.Data;
                        }
                        else if (b == DO || b == DONT || b == WILL || b == WONT)
                        {
                            _pendingCommand = b;
                            _state = ParseState.Negotiate;
                        }
                        else if (b == SB)
                        {
                            _subNegotiation.Clear();
                            _state = ParseState.SubNeg;
                        }
                        else
                        {
                            // NOP, GA, and the other two-byte commands need no reply.
                            _state = ParseState.Data;
                        }
                        break;

                    case ParseState.Negotiate:
                        HandleNegotiation(_pendingCommand, b);
                        _state = ParseState.Data;
                        break;

                    case ParseState.SubNeg:
                        if (b == IAC) _state = ParseState.SubNegIac;
                        else if (_subNegotiation.Count < 256) _subNegotiation.Add(b);
                        break;

                    case ParseState.SubNegIac:
                        if (b == SE)
                        {
                            HandleSubNegotiation();
                            _state = ParseState.Data;
                        }
                        else if (b == IAC)
                        {
                            if (_subNegotiation.Count < 256) _subNegotiation.Add(IAC);
                            _state = ParseState.SubNeg;
                        }
                        else
                        {
                            _state = ParseState.SubNeg;
                        }
                        break;
                }
            }

            return outLen;
        }

        private void HandleNegotiation(byte command, byte option)
        {
            // Decide under the lock, answer outside it: a socket write must never be
            // made while holding it.
            byte reply = 0;
            bool sendWindowSize = false;

            lock (_optionLock)
            {
                switch (command)
                {
                    case WILL:
                        // The host offers to do something.
                        if (option == OPT_ECHO || option == OPT_SGA ||
                            (option == OPT_BINARY && _settings.Binary) || option == OPT_STATUS)
                        {
                            if (_theyWill.Add(option))
                            {
                                // WILL in answer to our DO is the answer; only an
                                // unprompted WILL gets a reply.
                                if (!_askedDo.Remove(option)) reply = DO;
                            }
                        }
                        else if (_theyRefused.Add(option))
                        {
                            reply = DONT;
                        }
                        break;

                    case WONT:
                        _theyRefused.Remove(option);
                        _askedDo.Remove(option);
                        // Acknowledge only a change of state. Replying to a WONT for an
                        // option that was never on is what starts a loop with a server
                        // that answers every DONT.
                        if (_theyWill.Remove(option)) reply = DONT;
                        break;

                    case DO:
                        // The host asks us to do something.
                        if (option == OPT_TTYPE || option == OPT_NAWS || option == OPT_SGA ||
                            (option == OPT_BINARY && _settings.Binary))
                        {
                            if (_weWill.Add(option))
                            {
                                if (!_askedWill.Remove(option)) reply = WILL;
                                // NAWS carries no useful meaning until a size is sent.
                                if (option == OPT_NAWS) sendWindowSize = true;
                            }
                        }
                        else if (_weRefused.Add(option))
                        {
                            reply = WONT;
                        }
                        break;

                    case DONT:
                        _weRefused.Remove(option);
                        _askedWill.Remove(option);
                        if (_weWill.Remove(option)) reply = WONT;
                        break;
                }
            }

            if (reply != 0) SendCommand(reply, option);
            if (sendWindowSize) SendWindowSize();
        }

        private void HandleSubNegotiation()
        {
            if (_subNegotiation.Count < 1) return;
            byte option = _subNegotiation[0];

            if (option == OPT_TTYPE && _subNegotiation.Count >= 2 && _subNegotiation[1] == TTYPE_SEND)
            {
                SendTerminalType();
            }
            else if (option == OPT_TSPEED && _subNegotiation.Count >= 2 && _subNegotiation[1] == TTYPE_SEND)
            {
                SendTerminalSpeed();
            }
        }

        private void SendTerminalType()
        {
            string type = string.IsNullOrEmpty(_settings.TerminalType) ? "xterm" : _settings.TerminalType;
            byte[] name = Encoding.ASCII.GetBytes(type);

            byte[] message = new byte[6 + name.Length];
            int n = 0;
            message[n++] = IAC; message[n++] = SB; message[n++] = OPT_TTYPE; message[n++] = TTYPE_IS;
            Array.Copy(name, 0, message, n, name.Length); n += name.Length;
            message[n++] = IAC; message[n++] = SE;
            WriteRaw(message, 0, n);
        }

        private void SendTerminalSpeed()
        {
            byte[] speed = Encoding.ASCII.GetBytes("38400,38400");
            byte[] message = new byte[6 + speed.Length];
            int n = 0;
            message[n++] = IAC; message[n++] = SB; message[n++] = OPT_TSPEED; message[n++] = TTYPE_IS;
            Array.Copy(speed, 0, message, n, speed.Length); n += speed.Length;
            message[n++] = IAC; message[n++] = SE;
            WriteRaw(message, 0, n);
        }

        /// <summary>RFC 1073 NAWS. Dimensions are 16-bit big-endian and must be IAC-escaped.</summary>
        private void SendWindowSize()
        {
            lock (_optionLock) { if (!_weWill.Contains(OPT_NAWS)) return; }

            List<byte> message = new List<byte>(16);
            message.Add(IAC); message.Add(SB); message.Add(OPT_NAWS);
            AppendEscaped(message, (byte)((_cols >> 8) & 0xFF));
            AppendEscaped(message, (byte)(_cols & 0xFF));
            AppendEscaped(message, (byte)((_rows >> 8) & 0xFF));
            AppendEscaped(message, (byte)(_rows & 0xFF));
            message.Add(IAC); message.Add(SE);

            byte[] bytes = message.ToArray();
            WriteRaw(bytes, 0, bytes.Length);
        }

        private static void AppendEscaped(List<byte> target, byte value)
        {
            target.Add(value);
            if (value == IAC) target.Add(IAC);   // a 0xFF dimension byte must be doubled
        }

        private void SendCommand(byte command, byte option)
        {
            try { WriteRaw(new byte[] { IAC, command, option }, 0, 3); }
            catch (Exception) { }
        }

        // =====================================================================
        // Writing
        // =====================================================================

        public void Write(byte[] data, int offset, int count)
        {
            if (!IsConnected || count <= 0) return;

            // Any 0xFF in user data must be doubled, or the host reads it as IAC.
            bool needsEscaping = false;
            for (int i = 0; i < count; i++)
            {
                if (data[offset + i] == IAC) { needsEscaping = true; break; }
            }

            try
            {
                if (!needsEscaping)
                {
                    WriteRaw(data, offset, count);
                    return;
                }

                byte[] escaped = new byte[count * 2];
                int n = 0;
                for (int i = 0; i < count; i++)
                {
                    byte b = data[offset + i];
                    escaped[n++] = b;
                    if (b == IAC) escaped[n++] = IAC;
                }
                WriteRaw(escaped, 0, n);
            }
            catch (IOException ex)
            {
                RaiseClosed(ex.Message, null);
            }
            catch (ObjectDisposedException) { }
        }

        private readonly object _writeLock = new object();

        private void WriteRaw(byte[] data, int offset, int count)
        {
            if (_testCapture != null)
            {
                lock (_writeLock) { _testCapture.Write(data, offset, count); }
                return;
            }

            NetworkStream stream = _stream;
            if (stream == null) return;
            // Negotiation replies come from the reader thread while keystrokes come
            // from the UI thread; interleaving them would corrupt a command sequence.
            lock (_writeLock)
            {
                stream.Write(data, offset, count);
                stream.Flush();
            }
        }

        public void Resize(int cols, int rows)
        {
            if (cols > 0) _cols = cols;
            if (rows > 0) _rows = rows;
            // SendWindowSize already declines unless NAWS was agreed, and writing
            // with no socket is a no-op, so no connection check is needed here.
            SendWindowSize();
        }

        // =====================================================================
        // Shutdown
        // =====================================================================

        public void Disconnect()
        {
            if (_closing) return;
            _closing = true;

            if (_keepAliveTimer != null)
            {
                try { _keepAliveTimer.Dispose(); } catch (Exception) { }
                _keepAliveTimer = null;
            }

            try { if (_stream != null) _stream.Close(); } catch (Exception) { }
            try { if (_client != null) _client.Close(); } catch (Exception) { }

            if (_readerThread != null && _readerThread.IsAlive)
                _readerThread.Join(1000);

            RaiseClosed(null, null);
        }

        private void RaiseStatus(string message)
        {
            EventHandler<BackendStatusEventArgs> h = Status;
            if (h != null) h(this, new BackendStatusEventArgs(message));
        }

        private void RaiseConnected(string message)
        {
            EventHandler<BackendStatusEventArgs> h = Status;
            if (h != null) h(this, new BackendStatusEventArgs(message, true));
        }

        private void RaiseClosed(string reason, int? exitCode)
        {
            if (Interlocked.Exchange(ref _closeRaised, 1) != 0) return;
            _closing = true;
            EventHandler<BackendClosedEventArgs> h = Closed;
            if (h != null) h(this, new BackendClosedEventArgs(reason, exitCode));
        }

        public void Dispose()
        {
            Disconnect();
            _stream = null;
            _client = null;
        }

        // =====================================================================
        // Test surface
        // =====================================================================

        private Stream _testCapture;

        /// <summary>
        /// Divert everything this backend would put on the wire into a stream, so
        /// negotiation can be verified without a server. Test use only.
        /// </summary>
        public void TestCaptureOutput(Stream sink) { _testCapture = sink; }

        /// <summary>
        /// Run bytes through the protocol parser without a socket. Used by the tests
        /// to verify negotiation and IAC handling.
        /// </summary>
        public int TestProcessIncoming(byte[] input, int length, byte[] output)
        {
            return ProcessIncoming(input, length, output);
        }

        /// <summary>Drive negotiation as if the connection had just opened.</summary>
        public void TestStartNegotiation() { StartNegotiation(); }

        /// <summary>Encode and send user data through the IAC-escaping path.</summary>
        public void TestWriteEscaped(byte[] data)
        {
            bool needsEscaping = false;
            for (int i = 0; i < data.Length; i++) { if (data[i] == IAC) { needsEscaping = true; break; } }
            if (!needsEscaping) { WriteRaw(data, 0, data.Length); return; }

            byte[] escaped = new byte[data.Length * 2];
            int n = 0;
            for (int i = 0; i < data.Length; i++)
            {
                escaped[n++] = data[i];
                if (data[i] == IAC) escaped[n++] = IAC;
            }
            WriteRaw(escaped, 0, n);
        }
    }
}
