// PSTerm - SessionLogger.cs
// Asynchronous session logging.
//
// v1 ran the logger in a PowerShell runspace fed by a synchronised Queue and
// called Add-Content per chunk, which reopened the file for every write. This
// keeps one handle open and drains a lock-free queue on a single writer thread,
// so logging costs the session nothing.
//
// Features v1 lacked and PuTTY still lacks: per-line timestamps, templated file
// names so each device writes its own dated file, and size-based rotation.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;

namespace PSTerm.Io
{
    public enum LogFormat
    {
        /// <summary>Printable text with escape sequences removed. The default.</summary>
        PlainText,
        /// <summary>Every byte exactly as it arrived, escape sequences included.</summary>
        Raw,
        /// <summary>Plain text with a timestamp at the start of each line.</summary>
        Timestamped
    }

    public sealed class SessionLoggerOptions
    {
        /// <summary>Path template. Supports {host}, {session}, {user}, {port},
        /// {date}, {time} and {datetime}.</summary>
        public string PathTemplate;
        public LogFormat Format = LogFormat.PlainText;
        /// <summary>Also record what the operator typed, not just what the host sent.</summary>
        public bool IncludeInput = false;
        /// <summary>Append to an existing file instead of replacing it.</summary>
        public bool Append = true;
        /// <summary>Roll over to a new file past this many bytes. 0 disables rotation.</summary>
        public long MaxBytes = 0;
        /// <summary>Replace typed characters with asterisks after a password prompt.</summary>
        public bool MaskPasswords = true;
        public string TimestampFormat = "yyyy-MM-dd HH:mm:ss.fff";

        public SessionLoggerOptions Clone()
        {
            SessionLoggerOptions c = new SessionLoggerOptions();
            c.PathTemplate = PathTemplate;
            c.Format = Format;
            c.IncludeInput = IncludeInput;
            c.Append = Append;
            c.MaxBytes = MaxBytes;
            c.MaskPasswords = MaskPasswords;
            c.TimestampFormat = TimestampFormat;
            return c;
        }
    }

    public sealed class SessionLogger : IDisposable
    {
        private readonly SessionLoggerOptions _options;
        private readonly Queue<Entry> _queue = new Queue<Entry>();
        private readonly object _queueLock = new object();
        private readonly AutoResetEvent _signal = new AutoResetEvent(false);
        private readonly Thread _writer;

        private volatile bool _stopping;
        private StreamWriter _stream;
        private string _path;
        private string _basePath;
        private long _written;
        private int _rotation;
        private bool _atLineStart = true;
        private bool _expectingPassword;
        private string _promptTail = string.Empty;
        private int _closed;

        // Escape-sequence state is kept per stream. Host output and typed input are
        // separate byte streams that interleave in the queue, so a sequence that is
        // half-received on one must not be completed by bytes from the other.
        private int _hostStripState;
        private int _userStripState;
        private int _promptStripState;

        private struct Entry
        {
            public byte[] Data;
            public int Count;
            public bool FromUser;
        }

        /// <summary>Prompts that mean the next typed characters are a secret.
        /// Matched case-insensitively against host output.</summary>
        private static readonly string[] PasswordPrompts = new string[]
        {
            "password:", "password for", "passphrase for", "passphrase:",
            "enter password", "'s password", "enable password",
            "tacacs password", "old password", "new password",
            "current password", "secret:"
        };

        public string Path { get { return _path; } }
        public bool IsOpen { get { return _stream != null; } }

        public SessionLogger(SessionLoggerOptions options, IDictionary<string, string> tokens)
        {
            if (options == null) throw new ArgumentNullException("options");
            _options = options.Clone();

            _path = ExpandTemplate(_options.PathTemplate, tokens);
            OpenFile();
            _basePath = _path;

            _writer = new Thread(WriteLoop);
            _writer.IsBackground = true;
            _writer.Name = "PSTerm session logger";
            _writer.Start();
        }

        /// <summary>
        /// Expand a path template. Tera Term's best feature and the one PuTTY users
        /// most often ask for: every device writes to its own dated file with no
        /// per-session setup.
        /// </summary>
        public static string ExpandTemplate(string template, IDictionary<string, string> tokens)
        {
            if (string.IsNullOrEmpty(template)) return null;

            DateTime now = DateTime.Now;
            StringBuilder sb = new StringBuilder(template);

            sb.Replace("{date}", now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
            sb.Replace("{time}", now.ToString("HH-mm-ss", CultureInfo.InvariantCulture));
            sb.Replace("{datetime}", now.ToString("yyyy-MM-dd_HH-mm-ss", CultureInfo.InvariantCulture));

            if (tokens != null)
            {
                foreach (KeyValuePair<string, string> kv in tokens)
                {
                    string value = SanitiseForPath(kv.Value);
                    sb.Replace("{" + kv.Key + "}", value);
                }
            }

            // Any token the caller did not supply is dropped rather than left as
            // literal braces, which are invalid in a Windows path.
            string result = sb.ToString();
            int open;
            while ((open = result.IndexOf('{')) >= 0)
            {
                int close = result.IndexOf('}', open);
                if (close < 0) break;
                result = result.Remove(open, close - open + 1);
            }

            return result;
        }

        private static string SanitiseForPath(string value)
        {
            if (string.IsNullOrEmpty(value)) return "unknown";
            char[] invalid = System.IO.Path.GetInvalidFileNameChars();
            StringBuilder sb = new StringBuilder(value.Length);
            foreach (char c in value)
                sb.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
            return sb.ToString();
        }

        private void OpenFile()
        {
            if (string.IsNullOrEmpty(_path)) return;

            string dir = System.IO.Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            FileMode mode = _options.Append ? FileMode.Append : FileMode.Create;
            string wanted = _path;
            FileStream fs = null;

            // Two tabs to the same device on the same day expand to the same file name.
            // The second cannot share it - and must not truncate it - so it takes the
            // next free numbered name instead of silently not logging at all.
            for (int attempt = 1; fs == null; attempt++)
            {
                try
                {
                    fs = new FileStream(_path, mode, FileAccess.Write, FileShare.Read, 8192);
                }
                catch (IOException ex)
                {
                    if (!IsSharingViolation(ex) || attempt >= 50) throw;
                    _path = Numbered(wanted, attempt + 1);
                }
            }

            _written = fs.Length;

            // UTF-8 without a BOM: a log is often tailed or grepped by other tools.
            _stream = new StreamWriter(fs, new UTF8Encoding(false));
            _stream.AutoFlush = false;
        }

        private static bool IsSharingViolation(IOException ex)
        {
            // ERROR_SHARING_VIOLATION (32) and ERROR_LOCK_VIOLATION (33).
            int code = System.Runtime.InteropServices.Marshal.GetHRForException(ex) & 0xFFFF;
            return code == 32 || code == 33;
        }

        private static string Numbered(string path, int number)
        {
            string dir = System.IO.Path.GetDirectoryName(path);
            string name = System.IO.Path.GetFileNameWithoutExtension(path);
            string ext = System.IO.Path.GetExtension(path);
            return System.IO.Path.Combine(dir ?? string.Empty,
                name + "-" + number.ToString(CultureInfo.InvariantCulture) + ext);
        }

        private void Rotate()
        {
            if (_stream == null) return;
            _stream.Flush();
            _stream.Dispose();
            _stream = null;

            // Always derived from the original name, so the files read x.1.log,
            // x.2.log, x.3.log rather than x.1.2.3.log - and never one that already
            // exists, which a previous run may have left behind.
            string dir = System.IO.Path.GetDirectoryName(_basePath);
            string name = System.IO.Path.GetFileNameWithoutExtension(_basePath);
            string ext = System.IO.Path.GetExtension(_basePath);
            string rotated;
            do
            {
                _rotation++;
                rotated = System.IO.Path.Combine(dir ?? string.Empty,
                    name + "." + _rotation.ToString(CultureInfo.InvariantCulture) + ext);
            }
            while (File.Exists(rotated));

            _path = rotated;
            _written = 0;
            _options.Append = false;
            OpenFile();
        }

        // =====================================================================
        // Producer side - called from the session's data path
        // =====================================================================

        public void WriteFromHost(byte[] data, int offset, int count)
        {
            Enqueue(data, offset, count, false);
        }

        public void WriteFromUser(byte[] data, int offset, int count)
        {
            if (!_options.IncludeInput) return;
            Enqueue(data, offset, count, true);
        }

        private void Enqueue(byte[] data, int offset, int count, bool fromUser)
        {
            if (_stopping || _stream == null || count <= 0) return;

            // The caller reuses its buffer, so the bytes must be copied.
            Entry entry = new Entry();
            entry.Data = new byte[count];
            Buffer.BlockCopy(data, offset, entry.Data, 0, count);
            entry.Count = count;
            entry.FromUser = fromUser;

            lock (_queueLock) { _queue.Enqueue(entry); }
            _signal.Set();
        }

        // =====================================================================
        // Consumer side - the writer thread
        // =====================================================================

        private void WriteLoop()
        {
            System.Text.Decoder hostDecoder = new UTF8Encoding(false, false).GetDecoder();
            System.Text.Decoder userDecoder = new UTF8Encoding(false, false).GetDecoder();
            char[] chars = new char[8192];

            while (true)
            {
                _signal.WaitOne(250);

                while (true)
                {
                    Entry entry;
                    lock (_queueLock)
                    {
                        if (_queue.Count == 0) break;
                        entry = _queue.Dequeue();
                    }

                    try { WriteEntry(entry, hostDecoder, userDecoder, ref chars); }
                    catch (IOException) { /* disk full or the file vanished; keep the session alive */ }
                    catch (ObjectDisposedException) { return; }
                }

                if (_stream != null)
                {
                    try { _stream.Flush(); }
                    catch (IOException) { }
                    catch (ObjectDisposedException) { return; }
                }

                if (_stopping)
                {
                    lock (_queueLock) { if (_queue.Count == 0) break; }
                }
            }
        }

        private void WriteEntry(Entry entry, System.Text.Decoder hostDecoder,
                                System.Text.Decoder userDecoder, ref char[] chars)
        {
            if (_stream == null) return;

            System.Text.Decoder decoder = entry.FromUser ? userDecoder : hostDecoder;

            if (_options.Format == LogFormat.Raw)
            {
                byte[] data = entry.Data;

                if (_options.MaskPasswords)
                {
                    if (entry.FromUser)
                    {
                        // The file stays byte-exact except for the secret itself.
                        if (_expectingPassword) data = MaskBytes(entry.Data, entry.Count);
                    }
                    else
                    {
                        // Raw mode still has to know when a password prompt went by.
                        int needed = entry.Count * 2 + 8;
                        if (chars.Length < needed) chars = new char[needed];
                        int n = decoder.GetChars(entry.Data, 0, entry.Count, chars, 0);
                        if (n > 0)
                            TrackPasswordPrompt(StripEscapes(new string(chars, 0, n), ref _promptStripState));
                    }
                }

                // Raw mode writes the bytes untouched, so the file can be replayed
                // through a terminal later and render exactly as it did live.
                _stream.Flush();
                _stream.BaseStream.Write(data, 0, entry.Count);
                _written += entry.Count;
                RotateIfNeeded();
                return;
            }

            int capacity = entry.Count * 2 + 8;
            if (chars.Length < capacity) chars = new char[capacity];
            int charCount = decoder.GetChars(entry.Data, 0, entry.Count, chars, 0);
            if (charCount <= 0) return;

            string text = new string(chars, 0, charCount);

            if (entry.FromUser)
            {
                text = StripEscapes(text, ref _userStripState);
                if (_options.MaskPasswords && _expectingPassword) text = MaskInput(text);
            }
            else
            {
                text = StripEscapes(text, ref _hostStripState);
                TrackPasswordPrompt(text);
            }

            if (text.Length == 0) return;

            if (_options.Format == LogFormat.Timestamped) WriteTimestamped(text);
            else WritePlain(text);

            RotateIfNeeded();
        }

        private void WritePlain(string text)
        {
            _stream.Write(text);
            _written += text.Length;
        }

        private void WriteTimestamped(string text)
        {
            string stamp = DateTime.Now.ToString(_options.TimestampFormat, CultureInfo.InvariantCulture);

            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];

                if (_atLineStart && c != '\r' && c != '\n')
                {
                    _stream.Write('[');
                    _stream.Write(stamp);
                    _stream.Write("] ");
                    _written += stamp.Length + 3;
                    _atLineStart = false;
                }

                _stream.Write(c);
                _written++;

                if (c == '\n') _atLineStart = true;
            }
        }

        private void RotateIfNeeded()
        {
            if (_options.MaxBytes > 0 && _written >= _options.MaxBytes) Rotate();
        }

        /// <summary>
        /// Watch host output for a password prompt so typed input can be masked.
        /// Heuristic by nature: it errs toward masking, because a false positive
        /// costs a few asterisks and a false negative writes a password to disk.
        /// </summary>
        private void TrackPasswordPrompt(string hostText)
        {
            if (!_options.MaskPasswords) return;

            // Only the line the cursor is on can be a prompt, and it may arrive in
            // pieces ("Passw" then "ord:"), so the unfinished line is carried over.
            string combined = (_promptTail + hostText).ToLowerInvariant();
            int newline = combined.LastIndexOfAny(new char[] { '\n', '\r' });
            string line = newline >= 0 ? combined.Substring(newline + 1) : combined;

            bool prompt = false;
            foreach (string candidate in PasswordPrompts)
            {
                if (line.Contains(candidate)) { prompt = true; break; }
            }

            if (prompt) _expectingPassword = true;
            else if (newline >= 0) _expectingPassword = false;   // output moved past the prompt

            _promptTail = line.Length > 64 ? line.Substring(line.Length - 64) : line;
        }

        private string MaskInput(string typed)
        {
            StringBuilder sb = new StringBuilder(typed.Length);
            foreach (char c in typed)
            {
                if (c == '\r' || c == '\n') { sb.Append(c); _expectingPassword = false; }
                else if (c < 0x20) sb.Append(c);
                else sb.Append('*');
            }
            return sb.ToString();
        }

        private byte[] MaskBytes(byte[] typed, int count)
        {
            byte[] masked = new byte[count];
            for (int i = 0; i < count; i++)
            {
                byte b = typed[i];
                if (b == (byte)'\r' || b == (byte)'\n') { masked[i] = b; _expectingPassword = false; }
                else if (b < 0x20) masked[i] = b;
                else masked[i] = (byte)'*';
            }
            return masked;
        }

        /// <summary>
        /// Remove escape sequences for the text log formats. Unlike v1's regex this
        /// runs a small state machine, so a sequence split across two chunks does
        /// not leak its tail into the file.
        /// </summary>
        private static string StripEscapes(string text, ref int state)
        {
            StringBuilder sb = new StringBuilder(text.Length);

            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];

                switch (state)
                {
                    case 0: // ground
                        if (c == '\x1b') { state = 1; }
                        else if (c == '\x07') { /* bell: drop */ }
                        else if (c == '\b')
                        {
                            // Backspace is applied rather than recorded, so a log of an
                            // edited command line reads as the final text.
                            if (sb.Length > 0) sb.Length--;
                        }
                        else if (c >= 0x20 || c == '\r' || c == '\n' || c == '\t') sb.Append(c);
                        break;

                    case 1: // after ESC
                        if (c == '[') state = 2;
                        else if (c == ']') state = 3;
                        else if (c == 'P' || c == 'X' || c == '^' || c == '_') state = 3;
                        else if (c == '(' || c == ')' || c == '*' || c == '+' || c == '#' || c == '%') state = 4;
                        else state = 0;
                        break;

                    case 2: // CSI: consume until a final byte
                        if (c >= 0x40 && c <= 0x7E) state = 0;
                        break;

                    case 3: // string sequence: consume until BEL or ST
                        if (c == '\x07') state = 0;
                        else if (c == '\x1b') state = 5;
                        else if (c == '\x9c') state = 0;
                        break;

                    case 4: // single intermediate then one more byte
                        state = 0;
                        break;

                    case 5: // ESC seen inside a string sequence
                        state = (c == '\\') ? 0 : 3;
                        break;
                }
            }

            return sb.ToString();
        }

        // =====================================================================
        // Shutdown
        // =====================================================================

        public void Close()
        {
            if (Interlocked.Exchange(ref _closed, 1) != 0) return;

            _stopping = true;
            _signal.Set();

            if (_writer != null && _writer.IsAlive) _writer.Join(2000);

            if (_stream != null)
            {
                try { _stream.Flush(); _stream.Dispose(); }
                catch (IOException) { }
                catch (ObjectDisposedException) { }
                _stream = null;
            }

            // A writer still alive after the grace period is stuck on a slow disk. It
            // waits on this event, so closing it underneath would crash the process.
            if (_writer == null || !_writer.IsAlive)
            {
                try { _signal.Close(); }
                catch (ObjectDisposedException) { }
            }
        }

        public void Dispose() { Close(); }
    }
}
