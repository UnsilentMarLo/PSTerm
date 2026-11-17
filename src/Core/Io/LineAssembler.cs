// PSTerm - LineAssembler.cs
// Turns a terminal output stream into the lines a person would have read.
//
// A device that redraws as it goes - Cisco's "--More--" is the classic - prints
// text and then takes it back with backspaces or cursor movement. Stripping the
// control characters and keeping everything else leaves the debris in a log:
//
//     " --More--  Queueing strategy: fifo"
//
// This keeps the current line as an array of cells with a cursor, applies the
// movements and erasures that affect it, and only hands a line over when it is
// finished. What comes out is what was on the screen.
//
// Only the line being written is modelled. Cursor movement between lines
// (CSI A/B, absolute row addressing) is ignored: a log is a transcript, not a
// screen.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Collections.Generic;
using System.Text;

namespace PSTerm.Io
{
    public sealed class LineAssembler
    {
        private readonly List<char> _cells = new List<char>(160);
        private int _col;
        // Cells before this index were already handed out as a partial line, so
        // they can no longer be rewritten.
        private int _committed;

        private int _state;                      // 0 ground, 1 ESC, 2 CSI, 3 string, 4 one more byte, 5 ESC in string
        private readonly StringBuilder _csi = new StringBuilder();

        private DateTime _lineStart = DateTime.MinValue;

        /// <summary>When the first character of the current line arrived.</summary>
        public DateTime LineStart { get { return _lineStart; } }

        /// <summary>True when nothing has been written on the current line.</summary>
        public bool IsEmpty { get { return _cells.Count <= _committed; } }

        /// <summary>The unfinished line, as it would be written if it ended now.</summary>
        public string Pending
        {
            get
            {
                if (_cells.Count <= _committed) return string.Empty;
                return TrimEnd(new string(_cells.ToArray(), _committed, _cells.Count - _committed));
            }
        }

        /// <summary>
        /// True while the unfinished line is a pager prompt. The device is waiting
        /// for a key, and is about to erase the prompt and carry on, so it must not
        /// be written out yet.
        /// </summary>
        public bool PendingIsPager
        {
            get
            {
                string p = Pending.TrimEnd();
                return p.EndsWith("--More--", StringComparison.Ordinal) ||
                       p.EndsWith("-- More --", StringComparison.Ordinal) ||
                       p.EndsWith("--(more)--", StringComparison.OrdinalIgnoreCase);
            }
        }

        /// <summary>
        /// Feed text. Each finished line is added to <paramref name="lines"/> without
        /// its terminator.
        /// </summary>
        public void Feed(string text, List<string> lines)
        {
            for (int i = 0; i < text.Length; i++) Step(text[i], lines);
        }

        /// <summary>
        /// Hand over the unfinished line without ending it. Returns null when there
        /// is nothing new. Later output continues the same line.
        /// </summary>
        public string TakePartial()
        {
            if (_cells.Count <= _committed) return null;
            string text = TrimEnd(new string(_cells.ToArray(), _committed, _cells.Count - _committed));
            // Trailing blanks are held back rather than lost: they may yet be followed
            // by text on this line.
            int keep = _cells.Count - _committed - text.Length;
            _committed = _cells.Count - keep;
            return text.Length == 0 ? null : text;
        }

        /// <summary>The rest of the line at the end of the session.</summary>
        public string TakeRemainder()
        {
            string text = _cells.Count <= _committed
                ? string.Empty
                : TrimEnd(new string(_cells.ToArray(), _committed, _cells.Count - _committed));
            _cells.Clear();
            _col = 0;
            _committed = 0;
            return text.Length == 0 ? null : text;
        }

        private void Step(char c, List<string> lines)
        {
            switch (_state)
            {
                case 0:
                    Ground(c, lines);
                    return;

                case 1: // after ESC
                    if (c == '[') { _state = 2; _csi.Length = 0; }
                    else if (c == ']' || c == 'P' || c == 'X' || c == '^' || c == '_') _state = 3;
                    else if (c == '(' || c == ')' || c == '*' || c == '+' || c == '#' || c == '%') _state = 4;
                    else _state = 0;
                    return;

                case 2: // CSI
                    if (c >= 0x40 && c <= 0x7E) { Csi(c); _state = 0; }
                    else if (_csi.Length < 32) _csi.Append(c);
                    return;

                case 3: // OSC / DCS: consume to BEL or ST
                    if (c == '\x07' || c == '\x9c') _state = 0;
                    else if (c == '\x1b') _state = 5;
                    return;

                case 4:
                    _state = 0;
                    return;

                case 5:
                    _state = (c == '\\') ? 0 : 3;
                    return;
            }
        }

        private void Ground(char c, List<string> lines)
        {
            switch (c)
            {
                case '\x1b': _state = 1; return;
                case '\n':
                    EndLine(lines);
                    return;
                case '\r':
                    _col = _committed;
                    return;
                case '\b':
                    if (_col > _committed) _col--;
                    return;
                case '\t':
                    {
                        int next = ((_col / 8) + 1) * 8;
                        while (_col < next) Put(' ');
                        return;
                    }
            }

            if (c < 0x20 || c == 0x7f) return;     // bell, NUL and the rest are not text
            Put(c);
        }

        private void Put(char c)
        {
            if (_cells.Count == 0 && _lineStart == DateTime.MinValue) _lineStart = DateTime.Now;
            while (_cells.Count < _col) _cells.Add(' ');
            if (_col < _cells.Count) _cells[_col] = c; else _cells.Add(c);
            _col++;
        }

        private void EndLine(List<string> lines)
        {
            string text = _cells.Count <= _committed
                ? string.Empty
                : TrimEnd(new string(_cells.ToArray(), _committed, _cells.Count - _committed));
            lines.Add(text);
            _cells.Clear();
            _col = 0;
            _committed = 0;
            _lineStart = DateTime.MinValue;
        }

        private void Csi(char final)
        {
            string body = _csi.ToString();
            if (body.Length > 0 && (body[0] == '?' || body[0] == '>' || body[0] == '=' || body[0] == '<')) return;

            int[] p = ParseParams(body);

            switch (final)
            {
                case 'C': // cursor forward
                    {
                        int n = Math.Max(1, p[0]);
                        while (n-- > 0) { Pad(); _col++; }
                        break;
                    }
                case 'D': // cursor back
                    _col = Math.Max(_committed, _col - Math.Max(1, p[0]));
                    break;
                case 'G': // cursor to column
                case '`':
                    _col = Math.Max(_committed, Math.Max(1, p[0]) - 1);
                    break;
                case 'H': // cursor position: only the column matters to a transcript
                case 'f':
                    _col = Math.Max(_committed, Math.Max(1, p[1]) - 1);
                    break;
                case 'K': // erase in line
                    if (p[0] <= 0) { Truncate(_col); }
                    else if (p[0] == 1) { for (int i = _committed; i <= _col && i < _cells.Count; i++) _cells[i] = ' '; }
                    else { for (int i = _committed; i < _cells.Count; i++) _cells[i] = ' '; }
                    break;
                case 'X': // erase characters
                    {
                        int n = Math.Max(1, p[0]);
                        for (int i = _col; i < _col + n && i < _cells.Count; i++) _cells[i] = ' ';
                        break;
                    }
                case 'P': // delete characters
                    {
                        int n = Math.Max(1, p[0]);
                        if (_col < _cells.Count) _cells.RemoveRange(_col, Math.Min(n, _cells.Count - _col));
                        break;
                    }
                case '@': // insert blanks
                    {
                        int n = Math.Max(1, p[0]);
                        Pad();
                        for (int i = 0; i < n; i++) _cells.Insert(_col, ' ');
                        break;
                    }
            }
        }

        private void Pad()
        {
            while (_cells.Count < _col) _cells.Add(' ');
        }

        private void Truncate(int from)
        {
            if (from < _committed) from = _committed;
            if (from < _cells.Count) _cells.RemoveRange(from, _cells.Count - from);
        }

        private static int[] ParseParams(string body)
        {
            int[] p = new int[] { 0, 0 };
            int index = 0, value = 0;
            bool any = false;
            for (int i = 0; i < body.Length && index < 2; i++)
            {
                char c = body[i];
                if (c >= '0' && c <= '9') { value = Math.Min(value * 10 + (c - '0'), 10000); any = true; }
                else if (c == ';') { p[index++] = any ? value : 0; value = 0; any = false; }
            }
            if (index < 2) p[index] = any ? value : 0;
            return p;
        }

        private static string TrimEnd(string s)
        {
            int n = s.Length;
            while (n > 0 && s[n - 1] == ' ') n--;
            return n == s.Length ? s : s.Substring(0, n);
        }
    }
}
