// PSTerm - ConPtyBackend.cs
// Hosts a console program inside a pseudo-console we own.
//
// This is the SSH transport (it runs Windows' in-box ssh.exe) and, with a
// different command line, the local shell transport as well - cmd, PowerShell,
// WSL or anything else the operator wants in a tab.
//
// Running ssh.exe rather than linking an SSH library is a deliberate trade:
// it removes 4.7 MB of vendored third-party binaries from the repository and
// inherits public-key and agent authentication, certificates, ProxyJump
// bastions, ~/.ssh/config and every cipher OpenSSH supports, none of which v1
// had.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.IO;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using PSTerm.Interop;

namespace PSTerm.Backends
{
    public sealed class ConPtyBackend : ITerminalBackend
    {
        private readonly string _commandLine;
        private readonly string _workingDirectory;
        private readonly string _description;

        private PseudoConsole _console;
        private FileStream _input;
        private FileStream _output;
        private Thread _readerThread;
        private Thread _exitWatcher;
        private volatile bool _closing;
        private int _closeRaised;

        private int _cols = 80;
        private int _rows = 24;

        public event EventHandler<DataReceivedEventArgs> DataReceived;
        public event EventHandler<BackendClosedEventArgs> Closed;
        public event EventHandler<BackendStatusEventArgs> Status;

        public ConPtyBackend(string commandLine, string workingDirectory, string description)
        {
            if (string.IsNullOrEmpty(commandLine)) throw new ArgumentNullException("commandLine");
            _commandLine = commandLine;
            _workingDirectory = workingDirectory;
            _description = string.IsNullOrEmpty(description) ? commandLine : description;
        }

        public bool IsConnected
        {
            get { return _console != null && !_closing; }
        }

        public string Description { get { return _description; } }

        /// <summary>
        /// True when this Windows build has the pseudo-console API (1809+).
        /// Checked before offering SSH or local shell sessions.
        /// </summary>
        public static bool IsSupported { get { return PseudoConsole.IsSupported; } }

        public void SetInitialSize(int cols, int rows)
        {
            if (cols > 0) _cols = cols;
            if (rows > 0) _rows = rows;
        }

        public void Connect()
        {
            if (_console != null) return;

            if (!PseudoConsole.IsSupported)
            {
                throw new PlatformNotSupportedException(
                    "This Windows version has no pseudo-console support (Windows 10 1809 or later is required). " +
                    "Serial and Telnet sessions still work.");
            }

            RaiseStatus("Starting " + _description + "...");

            _console = new PseudoConsole();
            _console.Start(_commandLine, _workingDirectory, _cols, _rows);

            // FileStream over the pipe handles gives buffered, cancellable IO and
            // ties handle lifetime to the stream.
            _input = new FileStream(_console.InputWrite, FileAccess.Write, 4096, false);
            _output = new FileStream(_console.OutputRead, FileAccess.Read, 4096, false);

            _readerThread = new Thread(ReadLoop);
            _readerThread.IsBackground = true;
            _readerThread.Name = "PSTerm ConPTY reader";
            _readerThread.Start();

            // The end of the session has to be detected from the hosted process,
            // not from the pipe. conhost stays alive - and the output pipe stays
            // open - for as long as we hold the pseudo-console handle, so waiting
            // for EOF on the reader would never report that ssh or the shell exited.
            _exitWatcher = new Thread(WatchForExit);
            _exitWatcher.IsBackground = true;
            _exitWatcher.Name = "PSTerm ConPTY exit watcher";
            _exitWatcher.Start();
        }

        private void WatchForExit()
        {
            try { _console.WaitForExit(); }
            catch (Exception) { return; }

            if (_closing) return;

            // Let conhost emit the client's final frame before the pipes go away,
            // so the last lines of a session are not lost.
            Thread.Sleep(150);

            int? exitCode = null;
            int code;
            if (_console != null && _console.TryGetExitCode(out code)) exitCode = code;

            // Raise before disposing. Disposing unblocks the reader, which would
            // otherwise reach RaiseClosed first - with the console already gone and
            // therefore no exit code to report. Whichever call arrives second is a
            // no-op, so the one carrying the exit code has to be the one in front.
            RaiseClosed(null, exitCode);

            // Closing the pseudo-console is what finally gives the reader its EOF.
            try { if (_console != null) _console.Dispose(); }
            catch (Exception) { }
        }

        private void ReadLoop()
        {
            byte[] buffer = new byte[8192];
            string reason = null;

            try
            {
                while (!_closing)
                {
                    int read = _output.Read(buffer, 0, buffer.Length);
                    if (read <= 0) break;       // the pseudo-console closed: the child exited

                    EventHandler<DataReceivedEventArgs> handler = DataReceived;
                    if (handler != null) handler(this, new DataReceivedEventArgs(buffer, 0, read));
                }
            }
            catch (IOException)
            {
                // Expected when the pipe is torn down from the other side.
            }
            catch (ObjectDisposedException)
            {
                // Expected during Disconnect().
            }
            catch (Exception ex)
            {
                reason = ex.Message;
            }

            int? exitCode = null;
            if (_console != null)
            {
                int code;
                if (_console.TryGetExitCode(out code)) exitCode = code;
            }

            RaiseClosed(reason, exitCode);
        }

        public void Write(byte[] data, int offset, int count)
        {
            if (_input == null || _closing || count <= 0) return;
            try
            {
                _input.Write(data, offset, count);
                _input.Flush();
            }
            catch (IOException)
            {
                RaiseClosed("The connection was closed.", null);
            }
            catch (ObjectDisposedException) { }
        }

        public void Resize(int cols, int rows)
        {
            _cols = cols;
            _rows = rows;
            if (_console != null) _console.Resize(cols, rows);
        }

        public void Disconnect()
        {
            if (_closing) return;
            _closing = true;

            // Closing the pseudo-console lets the client shut down on its own and
            // flush its final output; only kill it if it refuses to go.
            if (_console != null)
            {
                try { _console.Dispose(); }
                catch (Exception) { }
            }

            if (_readerThread != null && _readerThread.IsAlive)
            {
                if (!_readerThread.Join(1500))
                {
                    if (_console != null) _console.Kill();
                    _readerThread.Join(500);
                }
            }

            if (_exitWatcher != null && _exitWatcher.IsAlive) _exitWatcher.Join(500);

            DisposeStreams();
            RaiseClosed(null, null);
        }

        private void DisposeStreams()
        {
            if (_input != null) { try { _input.Dispose(); } catch (Exception) { } _input = null; }
            if (_output != null) { try { _output.Dispose(); } catch (Exception) { } _output = null; }
        }

        private void RaiseStatus(string message)
        {
            EventHandler<BackendStatusEventArgs> h = Status;
            if (h != null) h(this, new BackendStatusEventArgs(message));
        }

        private void RaiseClosed(string reason, int? exitCode)
        {
            // The reader thread and Disconnect() can both get here; only the first wins.
            if (Interlocked.Exchange(ref _closeRaised, 1) != 0) return;
            _closing = true;

            EventHandler<BackendClosedEventArgs> h = Closed;
            if (h != null) h(this, new BackendClosedEventArgs(reason, exitCode));
        }

        public void Dispose()
        {
            Disconnect();
            if (_console != null) { try { _console.Dispose(); } catch (Exception) { } _console = null; }
        }
    }

    /// <summary>
    /// Builds the command lines PSTerm hosts in a pseudo-console, and locates the
    /// OpenSSH client that ships with Windows.
    /// </summary>
    public static class ConPtyCommands
    {
        /// <summary>
        /// Full path to the in-box OpenSSH client, or null if it is not installed.
        /// It is an optional Windows feature: present by default on Windows 10 1809+
        /// and Windows 11, but it can be removed.
        /// </summary>
        public static string FindSsh()
        {
            string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            string candidate = Path.Combine(system32, "OpenSSH\\ssh.exe");
            if (File.Exists(candidate)) return candidate;

            // Sysnative lets a 32-bit host reach the real System32 on 64-bit Windows.
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            candidate = Path.Combine(windows, "Sysnative\\OpenSSH\\ssh.exe");
            if (File.Exists(candidate)) return candidate;

            return FindOnPath("ssh.exe");
        }

        public static string FindSftp()
        {
            string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            string candidate = Path.Combine(system32, "OpenSSH\\sftp.exe");
            if (File.Exists(candidate)) return candidate;
            return FindOnPath("sftp.exe");
        }

        public static string FindOnPath(string exeName)
        {
            string path = Environment.GetEnvironmentVariable("PATH");
            if (string.IsNullOrEmpty(path)) return null;

            foreach (string dir in path.Split(';'))
            {
                if (string.IsNullOrEmpty(dir)) continue;
                try
                {
                    string candidate = Path.Combine(dir.Trim(), exeName);
                    if (File.Exists(candidate)) return candidate;
                }
                catch (ArgumentException)
                {
                    // A malformed PATH entry. Skip it.
                }
            }
            return null;
        }

        /// <summary>Quote an argument for a Windows command line.</summary>
        public static string Quote(string value)
        {
            if (string.IsNullOrEmpty(value)) return "\"\"";
            if (value.IndexOfAny(new char[] { ' ', '\t', '"' }) < 0) return value;
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        /// <summary>
        /// Build an ssh.exe command line. Options are passed with -o so a saved
        /// profile can override ~/.ssh/config without editing it.
        /// </summary>
        public static string BuildSshCommandLine(SshLaunchOptions options)
        {
            if (options == null) throw new ArgumentNullException("options");

            string ssh = FindSsh();
            if (ssh == null)
                throw new FileNotFoundException(
                    "The Windows OpenSSH client (ssh.exe) was not found. Install it from " +
                    "Settings > System > Optional features > OpenSSH Client, then try again.");

            StringBuilder sb = new StringBuilder();
            sb.Append(Quote(ssh));

            // Force a PTY: without it, a device that offers only a shell channel
            // will not give a usable interactive session.
            sb.Append(" -t -t");

            if (options.Port > 0 && options.Port != 22)
                sb.Append(" -p ").Append(options.Port.ToString());

            if (!string.IsNullOrEmpty(options.IdentityFile))
                sb.Append(" -i ").Append(Quote(options.IdentityFile));

            if (!string.IsNullOrEmpty(options.ProxyJump))
                sb.Append(" -J ").Append(Quote(options.ProxyJump));

            if (options.ForwardAgent)
                sb.Append(" -A");

            if (options.Compression)
                sb.Append(" -C");

            // Older network equipment often speaks only legacy algorithms. These are
            // off by default and enabled per-profile, so the default stays modern.
            if (options.AllowLegacyAlgorithms)
            {
                sb.Append(" -o ").Append(Quote("KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1"));
                sb.Append(" -o ").Append(Quote("HostKeyAlgorithms=+ssh-rsa,ssh-dss"));
                sb.Append(" -o ").Append(Quote("PubkeyAcceptedAlgorithms=+ssh-rsa"));
                sb.Append(" -o ").Append(Quote("Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc"));
                sb.Append(" -o ").Append(Quote("MACs=+hmac-sha1"));
            }

            if (options.KeepAliveSeconds > 0)
            {
                sb.Append(" -o ").Append(Quote("ServerAliveInterval=" + options.KeepAliveSeconds.ToString()));
                sb.Append(" -o ").Append(Quote("ServerAliveCountMax=3"));
            }

            foreach (string extra in options.ExtraOptions)
            {
                if (!string.IsNullOrEmpty(extra))
                    sb.Append(" -o ").Append(Quote(extra));
            }

            sb.Append(' ');
            if (!string.IsNullOrEmpty(options.User))
                sb.Append(Quote(options.User + "@" + options.Host));
            else
                sb.Append(Quote(options.Host));

            if (!string.IsNullOrEmpty(options.RemoteCommand))
                sb.Append(' ').Append(options.RemoteCommand);

            return sb.ToString();
        }
    }

    public sealed class SshLaunchOptions
    {
        public string Host;
        public string User;
        public int Port = 22;
        public string IdentityFile;
        public string ProxyJump;
        public string RemoteCommand;
        public bool ForwardAgent;
        public bool Compression;
        public bool AllowLegacyAlgorithms;
        public int KeepAliveSeconds;
        public System.Collections.Generic.List<string> ExtraOptions =
            new System.Collections.Generic.List<string>();
    }
}
