// PSTerm - ITerminalBackend.cs
// The single interface every transport implements. Serial, Telnet and anything
// hosted in a pseudo-console all look identical to the terminal control, which
// is what lets one renderer, one key map and one logger serve all of them.
//
// C# 5 only - see Cell.cs for why.

using System;

namespace PSTerm.Backends
{
    public class DataReceivedEventArgs : EventArgs
    {
        public readonly byte[] Buffer;
        public readonly int Offset;
        public readonly int Count;

        public DataReceivedEventArgs(byte[] buffer, int offset, int count)
        {
            Buffer = buffer;
            Offset = offset;
            Count = count;
        }
    }

    public class BackendClosedEventArgs : EventArgs
    {
        /// <summary>Null for a clean close, otherwise why the session ended.</summary>
        public readonly string Reason;
        /// <summary>Process exit code where the transport has one, otherwise null.</summary>
        public readonly int? ExitCode;

        public BackendClosedEventArgs(string reason, int? exitCode)
        {
            Reason = reason;
            ExitCode = exitCode;
        }
    }

    public class BackendStatusEventArgs : EventArgs
    {
        public readonly string Message;
        public BackendStatusEventArgs(string message) { Message = message; }
    }

    public interface ITerminalBackend : IDisposable
    {
        /// <summary>Raised on a background thread as bytes arrive. The buffer is
        /// reused after the handler returns, so consume it synchronously.</summary>
        event EventHandler<DataReceivedEventArgs> DataReceived;

        /// <summary>Raised once when the session ends, for any reason.</summary>
        event EventHandler<BackendClosedEventArgs> Closed;

        /// <summary>Progress and diagnostic messages to show in the session, such as
        /// "Connecting to ..." or a reconnect notice.</summary>
        event EventHandler<BackendStatusEventArgs> Status;

        bool IsConnected { get; }

        /// <summary>Short human-readable identity, e.g. "COM3 @ 115200" or "ssh core-sw1".</summary>
        string Description { get; }

        /// <summary>Open the connection. Throws on failure.</summary>
        void Connect();

        void Write(byte[] data, int offset, int count);

        /// <summary>Tell the far end the window size changed. A no-op for transports
        /// that have no concept of one.</summary>
        void Resize(int cols, int rows);

        /// <summary>Close cleanly. Safe to call more than once.</summary>
        void Disconnect();
    }
}
