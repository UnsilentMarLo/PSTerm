// PSTerm - SerialBackend.cs
// Serial port transport.
//
// v1 used SerialPort's DataReceived event via Register-ObjectEvent and wrote to
// the console from the event handler. That put a PowerShell runspace in the hot
// path and interleaved badly with the input loop. This uses a dedicated reader
// thread and hands raw bytes to the session, which decodes them.
//
// Also adds what console work actually needs and v1 did not have: a working
// handshake and DTR/RTS setting (RTSEnable was in the profile but never read),
// a break signal, and recovery when a USB serial adapter is unplugged and
// plugged back in mid-session.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.IO;
using System.IO.Ports;
using System.Threading;

namespace PSTerm.Backends
{
    public sealed class SerialSettings
    {
        public string PortName = "COM1";
        public int BaudRate = 9600;
        public int DataBits = 8;
        public Parity Parity = Parity.None;
        public StopBits StopBits = StopBits.One;
        public Handshake Handshake = Handshake.None;

        /// <summary>Assert DTR. Many USB console adapters need this to transmit.</summary>
        public bool DtrEnable = true;
        /// <summary>Assert RTS. Required by some devices even without RTS/CTS flow control.</summary>
        public bool RtsEnable = true;

        /// <summary>Reopen the port automatically if the adapter disappears and returns.</summary>
        public bool ReconnectOnDisconnect = true;
        public int ReconnectIntervalMs = 1000;

        public string Describe()
        {
            string parity;
            switch (Parity)
            {
                case Parity.Even: parity = "E"; break;
                case Parity.Odd: parity = "O"; break;
                case Parity.Mark: parity = "M"; break;
                case Parity.Space: parity = "S"; break;
                default: parity = "N"; break;
            }
            string stop;
            switch (StopBits)
            {
                case StopBits.Two: stop = "2"; break;
                case StopBits.OnePointFive: stop = "1.5"; break;
                default: stop = "1"; break;
            }
            return PortName + " " + BaudRate.ToString() + " " +
                   DataBits.ToString() + parity + stop;
        }
    }

    public sealed class SerialBackend : ITerminalBackend
    {
        private readonly SerialSettings _settings;
        private SerialPort _port;
        private Thread _readerThread;
        private volatile bool _closing;
        private int _closeRaised;
        private volatile bool _portOpen;

        public event EventHandler<DataReceivedEventArgs> DataReceived;
        public event EventHandler<BackendClosedEventArgs> Closed;
        public event EventHandler<BackendStatusEventArgs> Status;

        public SerialBackend(SerialSettings settings)
        {
            if (settings == null) throw new ArgumentNullException("settings");
            _settings = settings;
        }

        public bool IsConnected { get { return _portOpen && !_closing; } }
        public string Description { get { return _settings.Describe(); } }
        public SerialSettings Settings { get { return _settings; } }

        /// <summary>Port names currently present, newest adapters included.</summary>
        public static string[] GetPortNames()
        {
            try { return SerialPort.GetPortNames(); }
            catch (Exception) { return new string[0]; }
        }

        public void Connect()
        {
            if (_port != null) return;

            OpenPort();

            _readerThread = new Thread(ReadLoop);
            _readerThread.IsBackground = true;
            _readerThread.Name = "PSTerm serial reader";
            _readerThread.Start();
        }

        private void OpenPort()
        {
            SerialPort port = new SerialPort(
                _settings.PortName, _settings.BaudRate, _settings.Parity,
                _settings.DataBits, _settings.StopBits);

            port.Handshake = _settings.Handshake;
            port.DtrEnable = _settings.DtrEnable;
            port.RtsEnable = _settings.RtsEnable;

            // A read timeout is what lets the reader thread notice _closing and a
            // vanished adapter instead of blocking forever.
            port.ReadTimeout = 250;
            port.WriteTimeout = 2000;
            port.ReadBufferSize = 16384;

            port.Open();

            _port = port;
            _portOpen = true;
            RaiseConnected("Connected to " + _settings.Describe());
        }

        private void ReadLoop()
        {
            byte[] buffer = new byte[4096];

            while (!_closing)
            {
                try
                {
                    SerialPort port = _port;
                    if (port == null) throw new IOException("The serial port is closed.");
                    int read = port.Read(buffer, 0, buffer.Length);
                    if (read > 0)
                    {
                        EventHandler<DataReceivedEventArgs> handler = DataReceived;
                        if (handler != null) handler(this, new DataReceivedEventArgs(buffer, 0, read));
                    }
                }
                catch (TimeoutException)
                {
                    // Normal: the line was simply idle.
                }
                catch (Exception ex)
                {
                    if (_closing) break;

                    // The adapter was unplugged, or the driver faulted. Unplugging a
                    // USB console cable mid-session is routine in the field, so the
                    // session waits for it to come back rather than dying.
                    _portOpen = false;
                    ClosePortQuietly();

                    if (!_settings.ReconnectOnDisconnect)
                    {
                        RaiseClosed("The serial port was disconnected: " + ex.Message, null);
                        return;
                    }

                    RaiseStatus("Lost " + _settings.PortName + "; waiting for it to return...");
                    if (!WaitForPortAndReopen()) return;
                }
            }

            RaiseClosed(null, null);
        }

        private bool WaitForPortAndReopen()
        {
            while (!_closing)
            {
                Thread.Sleep(_settings.ReconnectIntervalMs);
                if (_closing) return false;

                bool present = false;
                foreach (string name in GetPortNames())
                {
                    if (string.Equals(name, _settings.PortName, StringComparison.OrdinalIgnoreCase))
                    {
                        present = true;
                        break;
                    }
                }
                if (!present) continue;

                try
                {
                    OpenPort();
                    RaiseConnected("Reconnected to " + _settings.PortName);
                    return true;
                }
                catch (Exception)
                {
                    // The device node is back but not ready yet; keep waiting.
                }
            }
            return false;
        }

        public void Write(byte[] data, int offset, int count)
        {
            // Take the port once: the reader thread nulls _port when the adapter
            // vanishes, and that can happen between the check and the write.
            SerialPort port = _port;
            if (!_portOpen || _closing || count <= 0 || port == null) return;
            try
            {
                port.Write(data, offset, count);
            }
            catch (TimeoutException)
            {
                // A full hardware buffer with flow control asserted. Dropping the
                // keystroke is better than blocking the UI thread.
                RaiseStatus("Write timed out; the device is not accepting data (check flow control).");
            }
            catch (InvalidOperationException) { }
            catch (UnauthorizedAccessException)
            {
                // Windows reports a yanked USB adapter this way. The reader thread
                // notices the same fault and handles the recovery.
            }
            catch (IOException ex)
            {
                RaiseStatus("Write failed: " + ex.Message);
            }
        }

        /// <summary>
        /// Send a serial break. Some equipment uses it to interrupt a boot sequence
        /// or drop to a ROM monitor, and there is no other way to produce it.
        /// </summary>
        public void SendBreak(int milliseconds)
        {
            SerialPort port = _port;
            if (!_portOpen || port == null) return;
            try
            {
                port.BreakState = true;
                Thread.Sleep(milliseconds > 0 ? milliseconds : 250);
                port.BreakState = false;
            }
            catch (InvalidOperationException) { }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        public void SetSignal(bool dtr, bool rts)
        {
            SerialPort port = _port;
            if (!_portOpen || port == null) return;
            try
            {
                port.DtrEnable = dtr;
                port.RtsEnable = rts;
                _settings.DtrEnable = dtr;
                _settings.RtsEnable = rts;
            }
            catch (InvalidOperationException) { }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        /// <summary>Current modem status lines, for a status bar.</summary>
        public bool TryGetSignals(out bool cts, out bool dsr, out bool cd)
        {
            cts = dsr = cd = false;
            SerialPort port = _port;
            if (!_portOpen || port == null) return false;
            try
            {
                cts = port.CtsHolding;
                dsr = port.DsrHolding;
                cd = port.CDHolding;
                return true;
            }
            catch (InvalidOperationException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
            catch (IOException) { return false; }
        }

        /// <summary>A serial line has no window size; nothing to report.</summary>
        public void Resize(int cols, int rows) { }

        public void Disconnect()
        {
            if (_closing) return;
            _closing = true;

            ClosePortQuietly();

            if (_readerThread != null && _readerThread.IsAlive)
                _readerThread.Join(1000);

            RaiseClosed(null, null);
        }

        private void ClosePortQuietly()
        {
            SerialPort port = _port;
            if (port == null) return;
            try { if (port.IsOpen) port.Close(); }
            catch (Exception) { }
            try { port.Dispose(); }
            catch (Exception) { }
            _port = null;
            _portOpen = false;
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
        }
    }
}
