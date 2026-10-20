// PSTerm - PasswordPrompt.cs
// Recognises a password prompt in host output, and answers one with a saved
// password.
//
// The recogniser is shared by the session logger, which uses it to mask what
// is typed next, and the responder, which uses it to decide when a saved
// password may be sent. Both live in C# for the same reason as the rest of
// the data path: they run on the transport's reader thread.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Text;

namespace PSTerm
{
    public static class PasswordPrompt
    {
        private static readonly string[] Phrases = new string[]
        {
            "password:", "password for", "passphrase for", "passphrase:",
            "enter password", "'s password", "enable password",
            "tacacs password", "old password", "new password",
            "current password", "secret:"
        };

        /// <summary>
        /// True when the line mentions a password prompt anywhere. Generous on
        /// purpose - the logger would rather mask too much than too little.
        /// </summary>
        public static bool LooksLikePrompt(string line)
        {
            if (string.IsNullOrEmpty(line)) return false;
            string lower = line.ToLowerInvariant();
            for (int i = 0; i < Phrases.Length; i++)
            {
                if (lower.Contains(Phrases[i])) return true;
            }
            return false;
        }

        /// <summary>
        /// True when the line is a prompt that is waiting for an answer: it names a
        /// password and ends in a colon. Stricter than LooksLikePrompt because the
        /// cost of a false positive here is sending a password somewhere it should
        /// not go ("Password: expired" in a banner is not a question).
        /// </summary>
        public static bool IsAwaitingAnswer(string line)
        {
            if (string.IsNullOrEmpty(line)) return false;
            string trimmed = line.TrimEnd();
            if (trimmed.Length == 0 || trimmed[trimmed.Length - 1] != ':') return false;
            return LooksLikePrompt(trimmed);
        }
    }

    /// <summary>
    /// Sends one saved password, the first time the host asks for one.
    /// </summary>
    /// <remarks>
    /// Deliberately blunt, so it is predictable: one answer only, so a wrong password
    /// is never retried against an account that locks; and only within the first
    /// moments of the session, so a password for logging in is never offered to a
    /// later "sudo" or application prompt.
    /// </remarks>
    public sealed class PasswordResponder
    {
        private const int WindowMilliseconds = 45000;
        private const int MaxLine = 256;

        private readonly object _sync = new object();
        private char[] _secret;
        private readonly StringBuilder _line = new StringBuilder();
        private int _escape;                 // 0 ground, 1 after ESC, 2 CSI, 3 string sequence
        private int _firstData;
        private bool _started;

        public PasswordResponder(string password)
        {
            if (!string.IsNullOrEmpty(password)) _secret = password.ToCharArray();
        }

        public bool IsArmed
        {
            get { lock (_sync) { return _secret != null; } }
        }

        /// <summary>
        /// Feed host output. Returns the text to send (the password and a carriage
        /// return) when a prompt is waiting, otherwise null. At most once.
        /// </summary>
        public string Observe(char[] buffer, int offset, int count)
        {
            lock (_sync)
            {
                if (_secret == null) return null;

                if (!_started) { _started = true; _firstData = Environment.TickCount; }
                else if (unchecked(Environment.TickCount - _firstData) > WindowMilliseconds)
                {
                    Disarm();
                    return null;
                }

                for (int i = 0; i < count; i++) Consume(buffer[offset + i]);

                if (!PasswordPrompt.IsAwaitingAnswer(_line.ToString())) return null;

                string reply = new string(_secret) + "\r";
                Disarm();
                return reply;
            }
        }

        private void Disarm()
        {
            if (_secret != null) Array.Clear(_secret, 0, _secret.Length);
            _secret = null;
            _line.Length = 0;
        }

        /// <summary>Track the current line, ignoring escape sequences.</summary>
        private void Consume(char c)
        {
            switch (_escape)
            {
                case 1:
                    if (c == '[') _escape = 2;
                    else if (c == ']' || c == 'P' || c == 'X' || c == '^' || c == '_') _escape = 3;
                    else _escape = 0;
                    return;
                case 2:
                    if (c >= 0x40 && c <= 0x7E) _escape = 0;
                    return;
                case 3:
                    if (c == '\x07' || c == '\x9c') _escape = 0;
                    else if (c == '\x1b') _escape = 1;       // ESC \ ends the string
                    return;
            }

            if (c == '\x1b') { _escape = 1; return; }
            if (c == '\r' || c == '\n') { _line.Length = 0; return; }
            if (c < 0x20) return;

            _line.Append(c);
            if (_line.Length > MaxLine) _line.Remove(0, _line.Length - MaxLine);
        }
    }
}
