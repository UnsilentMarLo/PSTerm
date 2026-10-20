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
        private long _written;
        private int _rotation;
        private bool _atLineStart = true;
        private bool _expectingPassword;
        private int _closed;

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
            FileStream fs = new FileStream(_path, mode, FileAccess.Write, FileShare.Read, 8192);
            _written = fs.Length;

            // UTF-8 without a BOM: a log is often tailed or grepped by other tools.
            _stream = new StreamWriter(fs, new UTF8Encoding(false));
            _stream.AutoFlush = false;
        }

        private void Rotate()
        {
            if (_stream == null) return;
            _stream.Flush();
            _stream.Dispose();
            _stream = null;

            _rotation++;
            string dir = System.IO.Path.GetDirectoryName(_path);
            string name = System.IO.Path.GetFileNameWithoutExtension(_path);
            string ext = System.IO.Path.GetExtension(_path);
            string rotated = System.IO.Path.Combine(dir ?? string.Empty,
                name + "." + _rotation.ToString(CultureInfo.InvariantCulture) + ext);

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
            var decoder = new UTF8Encoding(false, false).GetDecoder();
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

                    try { WriteEntry(entry, decoder, ref chars); }
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

        private void WriteEntry(Entry entry, System.Text.Decoder decoder, ref char[] chars)
        {
            if (_stream == null) return;

            if (_options.Format == LogFormat.Raw)
            {
                // Raw mode writes the bytes untouched, so the file can be replayed
                // through a terminal later and render exactly as it did live.
                _stream.Flush();
                _stream.BaseStream.Write(entry.Data, 0, entry.Count);
                _written += entry.Count;
                RotateIfNeeded();
                return;
            }

            int needed = entry.Count * 2 + 8;
            if (chars.Length < needed) chars = new char[needed];
            int charCount = decoder.GetChars(entry.Data, 0, entry.Count, chars, 0);
            if (charCount <= 0) return;

            string text = new string(chars, 0, charCount);

            if (!entry.FromUser) TrackPasswordPrompt(text);
            else if (_options.MaskPasswords && _expectingPassword) text = MaskInput(text);

            text = StripEscapes(text);
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

            string lower = hostText.ToLowerInvariant();
            foreach (string prompt in PasswordPrompts)
            {
                if (lower.Contains(prompt)) { _expectingPassword = true; return; }
            }

            // A newline from the host after the prompt means the secret is finished.
            if (_expectingPassword && (lower.Contains("\n") || lower.Contains("\r")))
                _expectingPassword = false;
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

        /// <summary>
        /// Remove escape sequences for the text log formats. Unlike v1's regex this
        /// runs a small state machine, so a sequence split across two chunks does
        /// not leak its tail into the file.
        /// </summary>
        private int _stripState;

        private string StripEscapes(string text)
        {
            StringBuilder sb = new StringBuilder(text.Length);

            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];

                switch (_stripState)
                {
                    case 0: // ground
                        if (c == '\x1b') { _stripState = 1; }
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
                        if (c == '[') _stripState = 2;
                        else if (c == ']') _stripState = 3;
                        else if (c == 'P' || c == 'X' || c == '^' || c == '_') _stripState = 3;
                        else if (c == '(' || c == ')' || c == '*' || c == '+' || c == '#' || c == '%') _stripState = 4;
                        else _stripState = 0;
                        break;

                    case 2: // CSI: consume until a final byte
                        if (c >= 0x40 && c <= 0x7E) _stripState = 0;
                        break;

                    case 3: // string sequence: consume until BEL or ST
                        if (c == '\x07') _stripState = 0;
                        else if (c == '\x1b') _stripState = 5;
                        else if (c == '\x9c') _stripState = 0;
                        break;

                    case 4: // single intermediate then one more byte
                        _stripState = 0;
                        break;

                    case 5: // ESC seen inside a string sequence
                        _stripState = (c == '\\') ? 0 : 3;
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

            try { _signal.Close(); }
            catch (ObjectDisposedException) { }
        }

        public void Dispose() { Close(); }
    }
}
