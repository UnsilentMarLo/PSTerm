// PSTerm - TerminalEmulator.cs
// Turns parsed VT events into screen operations. Targets xterm behaviour with a
// VT220 baseline, which is the combination real equipment expects.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Text;

namespace PSTerm.Vt
{
    /// <summary>Cursor + rendition state saved and restored by DECSC/DECRC.</summary>
    internal struct SavedCursor
    {
        public int X, Y;
        public Color Fg, Bg;
        public CellFlags Flags;
        public CharSetId G0, G1, G2, G3;
        public int Gl, Gr;
        public bool OriginMode;
        public bool PendingWrap;
        public bool Valid;
    }

    public sealed class TerminalEmulator : IVtSink
    {
        // ---- buffers ------------------------------------------------------
        private ScreenBuffer _primary;
        private ScreenBuffer _alternate;
        private ScreenBuffer _active;
        private bool _usingAlternate;

        // ---- pen ----------------------------------------------------------
        private Color _fg = Color.Default;
        private Color _bg = Color.Default;
        private CellFlags _flags = CellFlags.None;

        // ---- cursor & margins ---------------------------------------------
        private int _scrollTop;
        private int _scrollBottom;
        private bool _pendingWrap;          // deferred wrap at the right margin
        private SavedCursor _saved;
        private SavedCursor _savedAlt;

        // ---- character sets ------------------------------------------------
        private readonly CharSetId[] _g = new CharSetId[4];
        private int _gl = 0;                // locking shift: which G set maps to GL
        private int _gr = 2;
        private int _singleShift = -1;      // SS2/SS3: applies to the next character only

        // ---- modes ---------------------------------------------------------
        public bool ApplicationCursorKeys { get; private set; }   // DECCKM
        public bool ApplicationKeypad { get; private set; }       // DECKPAM
        public bool AutoWrap { get; private set; }                // DECAWM
        public bool OriginMode { get; private set; }              // DECOM
        public bool ReverseVideo { get; private set; }            // DECSCNM
        public bool CursorVisible { get; private set; }           // DECTCEM
        public bool BracketedPaste { get; private set; }          // 2004
        public bool InsertMode { get; private set; }              // IRM
        public bool NewLineMode { get; private set; }             // LNM
        public MouseMode Mouse { get; private set; }
        public MouseEncoding MouseEncode { get; private set; }
        public bool FocusReporting { get; private set; }          // 1004

        private bool[] _tabStops;

        // ---- output ---------------------------------------------------------
        private readonly VtParser _parser;
        private readonly StringBuilder _oscBuffer = new StringBuilder();

        /// <summary>Raised when the terminal must send bytes back to the host
        /// (device attributes, cursor position reports, and so on).</summary>
        public event Action<string> Respond;
        public event Action<string> TitleChanged;
        public event Action Bell;
        /// <summary>Raised after a chunk of input has been applied and the screen may need painting.</summary>
        public event Action Updated;

        public TerminalEmulator(int cols, int rows, int scrollback)
        {
            _primary = new ScreenBuffer(cols, rows, scrollback);
            _alternate = new ScreenBuffer(cols, rows, 0);
            _active = _primary;
            _parser = new VtParser(this);
            HardReset();
        }

        public ScreenBuffer Screen { get { return _active; } }
        public ScreenBuffer Primary { get { return _primary; } }
        public bool IsAlternateScreen { get { return _usingAlternate; } }
        public int Cols { get { return _active.Cols; } }
        public int Rows { get { return _active.Rows; } }
        public Color CurrentForeground { get { return _fg; } }
        public Color CurrentBackground { get { return _bg; } }

        public int CursorX { get { return _active.CursorX; } }
        public int CursorY { get { return _active.CursorY; } }

        /// <summary>The blank cell used when erasing, carrying the current background.</summary>
        private Cell BlankCell { get { return Cell.Blank(_fg, _bg, _flags); } }

        // =====================================================================
        // Input
        // =====================================================================

        public void Write(char[] buffer, int offset, int count)
        {
            _parser.Parse(buffer, offset, count);
            Action updated = Updated;
            if (updated != null) updated();
        }

        public void Write(string text)
        {
            _parser.Parse(text);
            Action updated = Updated;
            if (updated != null) updated();
        }

        private void Send(string s)
        {
            Action<string> respond = Respond;
            if (respond != null && !string.IsNullOrEmpty(s)) respond(s);
        }

        // =====================================================================
        // Reset
        // =====================================================================

        public void HardReset()
        {
            _fg = Color.Default;
            _bg = Color.Default;
            _flags = CellFlags.None;

            _g[0] = CharSetId.UsAscii;
            _g[1] = CharSetId.UsAscii;
            _g[2] = CharSetId.UsAscii;
            _g[3] = CharSetId.UsAscii;
            _gl = 0; _gr = 2; _singleShift = -1;

            ApplicationCursorKeys = false;
            ApplicationKeypad = false;
            AutoWrap = true;
            OriginMode = false;
            ReverseVideo = false;
            CursorVisible = true;
            BracketedPaste = false;
            InsertMode = false;
            NewLineMode = false;
            Mouse = MouseMode.Off;
            MouseEncode = MouseEncoding.X10;
            FocusReporting = false;

            _pendingWrap = false;
            _saved = new SavedCursor();
            _savedAlt = new SavedCursor();

            if (_usingAlternate) SwitchToPrimary(false);
            _primary.CursorX = 0; _primary.CursorY = 0;
            _alternate.CursorX = 0; _alternate.CursorY = 0;

            ResetTabStops();
            ResetScrollRegion();
            _parser.Reset();
            EraseInDisplay(2);
            _active.MarkAllDirty();
        }

        /// <summary>DECSTR - soft reset. Leaves the screen contents alone.</summary>
        private void SoftReset()
        {
            _fg = Color.Default;
            _bg = Color.Default;
            _flags = CellFlags.None;
            ApplicationCursorKeys = false;
            ApplicationKeypad = false;
            AutoWrap = true;
            OriginMode = false;
            CursorVisible = true;
            InsertMode = false;
            _pendingWrap = false;
            _saved = new SavedCursor();
            _g[0] = CharSetId.UsAscii; _g[1] = CharSetId.UsAscii;
            _g[2] = CharSetId.UsAscii; _g[3] = CharSetId.UsAscii;
            _gl = 0; _gr = 2; _singleShift = -1;
            ResetScrollRegion();
        }

        private void ResetScrollRegion()
        {
            _scrollTop = 0;
            _scrollBottom = _active.Rows - 1;
        }

        private void ResetTabStops()
        {
            _tabStops = new bool[Math.Max(_active.Cols, 1)];
            for (int i = 0; i < _tabStops.Length; i++) _tabStops[i] = (i % 8) == 0 && i != 0;
        }

        // =====================================================================
        // Resize
        // =====================================================================

        public void Resize(int cols, int rows)
        {
            if (cols < 1) cols = 1;
            if (rows < 1) rows = 1;
            if (cols == _active.Cols && rows == _active.Rows) return;

            Cell blank = BlankCell;
            int shift = _primary.Resize(cols, rows, blank);
            _alternate.Resize(cols, rows, blank);

            // When the primary buffer pulls lines back out of history the cursor moves
            // down with the content it belongs to.
            if (!_usingAlternate && shift != 0)
            {
                _primary.CursorY += shift;
                if (_primary.CursorY < 0) _primary.CursorY = 0;
                if (_primary.CursorY >= rows) _primary.CursorY = rows - 1;
            }

            ResetTabStops();
            // A scroll region that no longer fits is reset, as xterm does.
            if (_scrollBottom >= rows || _scrollTop >= _scrollBottom) ResetScrollRegion();
            _pendingWrap = false;
            _active.MarkAllDirty();
        }

        // =====================================================================
        // IVtSink - printing
        // =====================================================================

        public void Print(char ch)
        {
            CharSetId set = _g[_singleShift >= 0 ? _singleShift : _gl];
            _singleShift = -1;

            char glyph = CharSets.Translate(ch, set);

            // Combining marks attach to the previous cell instead of advancing.
            if (CharWidth.IsZeroWidth(glyph))
            {
                int px = _active.CursorX - 1;
                if (px >= 0)
                {
                    Line line = _active.GetRow(_active.CursorY);
                    if ((line.Cells[px].Flags & CellFlags.WideTrail) != 0 && px > 0) px--;
                    // Only the base character is retained; rendering a full combining
                    // sequence per cell is out of scope, but the mark must not consume a cell.
                    _active.MarkDirty(_active.CursorY);
                }
                return;
            }

            bool wide = CharWidth.IsWide(glyph);
            int width = wide ? 2 : 1;

            if (_pendingWrap && AutoWrap)
            {
                _active.GetRow(_active.CursorY).Wrapped = true;
                CarriageReturn();
                LineFeedInRegion();
                _pendingWrap = false;
            }

            // A wide glyph will not straddle the right margin: wrap first.
            if (_active.CursorX + width > _active.Cols)
            {
                if (AutoWrap)
                {
                    _active.GetRow(_active.CursorY).Wrapped = true;
                    CarriageReturn();
                    LineFeedInRegion();
                }
                else
                {
                    _active.CursorX = _active.Cols - width;
                    if (_active.CursorX < 0) _active.CursorX = 0;
                }
            }

            Line row = _active.GetRow(_active.CursorY);

            if (InsertMode)
            {
                ShiftRight(row, _active.CursorX, width);
            }

            Cell cell = new Cell();
            cell.Ch = glyph;
            cell.Fg = _fg;
            cell.Bg = _bg;
            cell.Flags = _flags | (wide ? CellFlags.WideLead : CellFlags.None);
            cell.LinkId = _currentLink;
            row.Cells[_active.CursorX] = cell;

            if (wide && _active.CursorX + 1 < _active.Cols)
            {
                Cell trail = cell;
                trail.Ch = '\0';
                trail.Flags = (_flags | CellFlags.WideTrail) & ~CellFlags.WideLead;
                row.Cells[_active.CursorX + 1] = trail;
            }

            _active.MarkDirty(_active.CursorY);
            _active.CursorX += width;

            if (_active.CursorX >= _active.Cols)
            {
                _active.CursorX = _active.Cols - 1;
                _pendingWrap = true;
            }
        }

        private static void ShiftRight(Line row, int from, int by)
        {
            for (int c = row.Cells.Length - 1; c >= from + by; c--)
                row.Cells[c] = row.Cells[c - by];
        }

        // =====================================================================
        // IVtSink - C0/C1 controls
        // =====================================================================

        public void Execute(char control)
        {
            switch (control)
            {
                case '\x07': // BEL
                    {
                        Action bell = Bell;
                        if (bell != null) bell();
                        break;
                    }
                case '\x08': // BS
                    if (_pendingWrap) { _pendingWrap = false; }
                    else if (_active.CursorX > 0)
                    {
                        _active.CursorX--;
                        // Step over the trailing half of a double-width glyph.
                        Line ln = _active.GetRow(_active.CursorY);
                        if (_active.CursorX > 0 && (ln.Cells[_active.CursorX].Flags & CellFlags.WideTrail) != 0)
                            _active.CursorX--;
                    }
                    break;
                case '\x09': // HT
                    HorizontalTab(1);
                    break;
                case '\x0A': // LF
                case '\x0B': // VT
                case '\x0C': // FF
                    LineFeedInRegion();
                    if (NewLineMode) CarriageReturn();
                    _pendingWrap = false;
                    break;
                case '\x0D': // CR
                    CarriageReturn();
                    _pendingWrap = false;
                    break;
                case '\x0E': // SO / LS1
                    _gl = 1;
                    break;
                case '\x0F': // SI / LS0
                    _gl = 0;
                    break;
                case '\x84': // IND
                    LineFeedInRegion();
                    break;
                case '\x85': // NEL
                    CarriageReturn();
                    LineFeedInRegion();
                    break;
                case '\x88': // HTS
                    SetTabStop(_active.CursorX);
                    break;
                case '\x8D': // RI
                    ReverseIndex();
                    break;
                case '\x8E': _singleShift = 2; break; // SS2
                case '\x8F': _singleShift = 3; break; // SS3
                default:
                    // NUL and other unhandled controls are discarded, as on real hardware.
                    break;
            }
        }

        private void CarriageReturn()
        {
            _active.CursorX = 0;
            _pendingWrap = false;
        }

        /// <summary>Line feed respecting the scroll region.</summary>
        private void LineFeedInRegion()
        {
            if (_active.CursorY == _scrollBottom)
                _active.ScrollUp(_scrollTop, _scrollBottom, 1, BlankCell);
            else if (_active.CursorY < _active.Rows - 1)
                _active.CursorY++;
            _pendingWrap = false;
        }

        private void ReverseIndex()
        {
            if (_active.CursorY == _scrollTop)
                _active.ScrollDown(_scrollTop, _scrollBottom, 1, BlankCell);
            else if (_active.CursorY > 0)
                _active.CursorY--;
            _pendingWrap = false;
        }

        // =====================================================================
        // Tabs
        // =====================================================================

        private void SetTabStop(int col)
        {
            if (col >= 0 && col < _tabStops.Length) _tabStops[col] = true;
        }

        private void HorizontalTab(int count)
        {
            for (int n = 0; n < count; n++)
            {
                int x = _active.CursorX + 1;
                while (x < _active.Cols && !(x < _tabStops.Length && _tabStops[x])) x++;
                _active.CursorX = Math.Min(x, _active.Cols - 1);
            }
            _pendingWrap = false;
        }

        private void BackTab(int count)
        {
            for (int n = 0; n < count; n++)
            {
                int x = _active.CursorX - 1;
                while (x > 0 && !(x < _tabStops.Length && _tabStops[x])) x--;
                _active.CursorX = Math.Max(x, 0);
            }
            _pendingWrap = false;
        }

        // =====================================================================
        // IVtSink - ESC dispatch
        // =====================================================================

        public void EscDispatch(string intermediates, char final)
        {
            if (intermediates.Length > 0)
            {
                char i0 = intermediates[0];

                // Character set designation: ESC ( ) * + <designator>
                int slot = -1;
                switch (i0)
                {
                    case '(': slot = 0; break;
                    case ')': slot = 1; break;
                    case '*': slot = 2; break;
                    case '+': slot = 3; break;
                }
                if (slot >= 0)
                {
                    _g[slot] = CharSets.FromDesignator(final);
                    return;
                }

                if (i0 == '#')
                {
                    if (final == '8') DecAlignmentTest();
                    return;
                }
                if (i0 == '%')
                {
                    // Character encoding selection (ESC % G = UTF-8). Decoding happens
                    // upstream in StreamDecoder; nothing to do at this layer.
                    return;
                }
                return;
            }

            switch (final)
            {
                case 'D': LineFeedInRegion(); break;                    // IND
                case 'E': CarriageReturn(); LineFeedInRegion(); break;  // NEL
                case 'H': SetTabStop(_active.CursorX); break;           // HTS
                case 'M': ReverseIndex(); break;                        // RI
                case 'N': _singleShift = 2; break;                      // SS2
                case 'O': _singleShift = 3; break;                      // SS3
                case '7': SaveCursor(); break;                          // DECSC
                case '8': RestoreCursor(); break;                       // DECRC
                case '=': ApplicationKeypad = true; break;              // DECKPAM
                case '>': ApplicationKeypad = false; break;             // DECKPNM
                case 'c': HardReset(); break;                           // RIS
                case 'n': _gl = 2; break;                               // LS2
                case 'o': _gl = 3; break;                               // LS3
                case '~': _gr = 1; break;                               // LS1R
                case '}': _gr = 2; break;                               // LS2R
                case '|': _gr = 3; break;                               // LS3R
                case '\\': break;                                       // ST, already handled
            }
        }

        /// <summary>DECALN - fill the screen with 'E'. Used by vttest and by some
        /// vendor self-tests to check alignment.</summary>
        private void DecAlignmentTest()
        {
            Cell e = new Cell();
            e.Ch = 'E';
            e.Fg = Color.Default;
            e.Bg = Color.Default;
            e.Flags = CellFlags.None;
            for (int r = 0; r < _active.Rows; r++)
                _active.GetRow(r).Fill(e);
            _active.CursorX = 0;
            _active.CursorY = 0;
            ResetScrollRegion();
            _active.MarkAllDirty();
        }

        private void SaveCursor()
        {
            SavedCursor s = new SavedCursor();
            s.X = _active.CursorX; s.Y = _active.CursorY;
            s.Fg = _fg; s.Bg = _bg; s.Flags = _flags;
            s.G0 = _g[0]; s.G1 = _g[1]; s.G2 = _g[2]; s.G3 = _g[3];
            s.Gl = _gl; s.Gr = _gr;
            s.OriginMode = OriginMode;
            s.PendingWrap = _pendingWrap;
            s.Valid = true;
            if (_usingAlternate) _savedAlt = s; else _saved = s;
        }

        private void RestoreCursor()
        {
            SavedCursor s = _usingAlternate ? _savedAlt : _saved;
            if (!s.Valid)
            {
                _active.CursorX = 0;
                _active.CursorY = 0;
                return;
            }
            _active.CursorX = Math.Min(s.X, _active.Cols - 1);
            _active.CursorY = Math.Min(s.Y, _active.Rows - 1);
            _fg = s.Fg; _bg = s.Bg; _flags = s.Flags;
            _g[0] = s.G0; _g[1] = s.G1; _g[2] = s.G2; _g[3] = s.G3;
            _gl = s.Gl; _gr = s.Gr;
            OriginMode = s.OriginMode;
            _pendingWrap = s.PendingWrap;
        }

        // =====================================================================
        // IVtSink - CSI dispatch
        // =====================================================================

        private static int Arg(int[] p, int count, int index, int fallback)
        {
            if (index >= count) return fallback;
            int v = p[index];
            return v < 0 ? fallback : v;
        }

        public void CsiDispatch(char prefix, int[] p, int count, string intermediates, char final)
        {
            // Private (DEC) sequences.
            if (prefix == '?')
            {
                switch (final)
                {
                    case 'h': SetDecModes(p, count, true); return;
                    case 'l': SetDecModes(p, count, false); return;
                    case 'n': DecDeviceStatus(Arg(p, count, 0, 0)); return;
                    case 'J': EraseInDisplay(Arg(p, count, 0, 0)); return;   // DECSED
                    case 'K': EraseInLine(Arg(p, count, 0, 0)); return;      // DECSEL
                    case 'c': Send("\x1b[?62;1;6;9;15;22c"); return;         // DA1 (secondary form)
                }
                return;
            }

            if (intermediates.Length > 0)
            {
                char i0 = intermediates[0];
                if (i0 == '!' && final == 'p') { SoftReset(); return; }      // DECSTR
                if (i0 == '"' && final == 'q') { return; }                    // DECSCA
                if (i0 == '$') { return; }                                    // DECRQM etc.
                if (i0 == ' ' && final == 'q') { return; }                    // DECSCUSR (cursor style)
                return;
            }

            switch (final)
            {
                // ---- cursor movement ----
                case 'A': MoveCursor(0, -Math.Max(1, Arg(p, count, 0, 1))); break;              // CUU
                case 'B': MoveCursor(0, Math.Max(1, Arg(p, count, 0, 1))); break;               // CUD
                case 'C': MoveCursor(Math.Max(1, Arg(p, count, 0, 1)), 0); break;               // CUF
                case 'D': MoveCursor(-Math.Max(1, Arg(p, count, 0, 1)), 0); break;              // CUB
                case 'E': CarriageReturn(); MoveCursor(0, Math.Max(1, Arg(p, count, 0, 1))); break;  // CNL
                case 'F': CarriageReturn(); MoveCursor(0, -Math.Max(1, Arg(p, count, 0, 1))); break; // CPL
                case 'G': case '`':                                                              // CHA / HPA
                    SetCursorX(Math.Max(1, Arg(p, count, 0, 1)) - 1);
                    break;
                case 'd':                                                                        // VPA
                    SetCursorY(Math.Max(1, Arg(p, count, 0, 1)) - 1);
                    break;
                case 'H': case 'f':                                                              // CUP / HVP
                    SetCursorY(Math.Max(1, Arg(p, count, 0, 1)) - 1);
                    SetCursorX(Math.Max(1, Arg(p, count, 1, 1)) - 1);
                    break;
                case 'I': HorizontalTab(Math.Max(1, Arg(p, count, 0, 1))); break;               // CHT
                case 'Z': BackTab(Math.Max(1, Arg(p, count, 0, 1))); break;                     // CBT

                // ---- erase ----
                case 'J': EraseInDisplay(Arg(p, count, 0, 0)); break;                           // ED
                case 'K': EraseInLine(Arg(p, count, 0, 0)); break;                              // EL
                case 'X': EraseChars(Math.Max(1, Arg(p, count, 0, 1))); break;                  // ECH

                // ---- insert / delete ----
                case 'L': InsertLines(Math.Max(1, Arg(p, count, 0, 1))); break;                 // IL
                case 'M': DeleteLines(Math.Max(1, Arg(p, count, 0, 1))); break;                 // DL
                case '@': InsertChars(Math.Max(1, Arg(p, count, 0, 1))); break;                 // ICH
                case 'P': DeleteChars(Math.Max(1, Arg(p, count, 0, 1))); break;                 // DCH

                // ---- scrolling ----
                case 'S': _active.ScrollUp(_scrollTop, _scrollBottom, Math.Max(1, Arg(p, count, 0, 1)), BlankCell); break;   // SU
                case 'T': _active.ScrollDown(_scrollTop, _scrollBottom, Math.Max(1, Arg(p, count, 0, 1)), BlankCell); break; // SD

                // ---- tabs ----
                case 'g': ClearTabStop(Arg(p, count, 0, 0)); break;                             // TBC

                // ---- modes ----
                case 'h': SetAnsiModes(p, count, true); break;                                  // SM
                case 'l': SetAnsiModes(p, count, false); break;                                 // RM

                // ---- rendition ----
                case 'm': ApplySgr(p, count); break;                                            // SGR

                // ---- reports ----
                case 'n': DeviceStatus(Arg(p, count, 0, 0)); break;                             // DSR
                case 'c':                                                                        // DA1
                    // "VT220 with 132 columns, selective erase, national replacement
                    // character sets and technical characters" - broadly compatible.
                    Send("\x1b[?62;1;6;9;15;22c");
                    break;

                // ---- scroll region ----
                case 'r':                                                                        // DECSTBM
                    {
                        int top = Math.Max(1, Arg(p, count, 0, 1)) - 1;
                        int bottom = Math.Max(1, Arg(p, count, 1, _active.Rows)) - 1;
                        if (bottom >= _active.Rows) bottom = _active.Rows - 1;
                        if (top < bottom)
                        {
                            _scrollTop = top;
                            _scrollBottom = bottom;
                            // DECSTBM homes the cursor (to the margin origin in origin mode).
                            _active.CursorX = 0;
                            _active.CursorY = OriginMode ? _scrollTop : 0;
                            _pendingWrap = false;
                        }
                        break;
                    }

                case 's': SaveCursor(); break;      // SCOSC (ANSI.SYS save cursor)
                case 'u': RestoreCursor(); break;   // SCORC

                case 't': WindowManipulation(p, count); break;
            }
        }

        // ---- cursor helpers -------------------------------------------------

        private int TopLimit { get { return OriginMode ? _scrollTop : 0; } }
        private int BottomLimit { get { return OriginMode ? _scrollBottom : _active.Rows - 1; } }

        private void MoveCursor(int dx, int dy)
        {
            if (dy != 0)
            {
                int y = _active.CursorY + dy;
                // Cursor movement clamps at the scroll region; it never scrolls.
                int top = (_active.CursorY >= _scrollTop) ? _scrollTop : 0;
                int bottom = (_active.CursorY <= _scrollBottom) ? _scrollBottom : _active.Rows - 1;
                if (y < top) y = top;
                if (y > bottom) y = bottom;
                _active.CursorY = y;
            }
            if (dx != 0)
            {
                int x = _active.CursorX + dx;
                if (x < 0) x = 0;
                if (x >= _active.Cols) x = _active.Cols - 1;
                _active.CursorX = x;
            }
            _pendingWrap = false;
        }

        private void SetCursorX(int x)
        {
            if (x < 0) x = 0;
            if (x >= _active.Cols) x = _active.Cols - 1;
            _active.CursorX = x;
            _pendingWrap = false;
        }

        private void SetCursorY(int y)
        {
            y += TopLimit;
            if (y < TopLimit) y = TopLimit;
            if (y > BottomLimit) y = BottomLimit;
            _active.CursorY = y;
            _pendingWrap = false;
        }

        // ---- erase ----------------------------------------------------------

        private void EraseInDisplay(int mode)
        {
            Cell blank = BlankCell;
            switch (mode)
            {
                case 0: // cursor to end of screen
                    _active.GetRow(_active.CursorY).Fill(_active.CursorX, _active.Cols, blank);
                    for (int r = _active.CursorY + 1; r < _active.Rows; r++) _active.GetRow(r).Fill(blank);
                    _active.MarkDirty(_active.CursorY, _active.Rows - 1);
                    break;
                case 1: // start of screen to cursor
                    for (int r = 0; r < _active.CursorY; r++) _active.GetRow(r).Fill(blank);
                    _active.GetRow(_active.CursorY).Fill(0, _active.CursorX + 1, blank);
                    _active.MarkDirty(0, _active.CursorY);
                    break;
                case 2: // whole screen
                case 3: // whole screen + scrollback
                    for (int r = 0; r < _active.Rows; r++) _active.GetRow(r).Fill(blank);
                    if (mode == 3) _active.ClearHistory();
                    _active.MarkAllDirty();
                    break;
            }
            _pendingWrap = false;
        }

        private void EraseInLine(int mode)
        {
            Cell blank = BlankCell;
            Line row = _active.GetRow(_active.CursorY);
            switch (mode)
            {
                case 0: row.Fill(_active.CursorX, _active.Cols, blank); break;
                case 1: row.Fill(0, _active.CursorX + 1, blank); break;
                case 2: row.Fill(blank); break;
            }
            _active.MarkDirty(_active.CursorY);
            _pendingWrap = false;
        }

        private void EraseChars(int n)
        {
            Line row = _active.GetRow(_active.CursorY);
            row.Fill(_active.CursorX, Math.Min(_active.CursorX + n, _active.Cols), BlankCell);
            _active.MarkDirty(_active.CursorY);
            _pendingWrap = false;
        }

        // ---- insert / delete ------------------------------------------------

        private void InsertLines(int n)
        {
            if (_active.CursorY < _scrollTop || _active.CursorY > _scrollBottom) return;
            _active.ScrollDown(_active.CursorY, _scrollBottom, n, BlankCell);
            _active.CursorX = 0;
            _pendingWrap = false;
        }

        private void DeleteLines(int n)
        {
            if (_active.CursorY < _scrollTop || _active.CursorY > _scrollBottom) return;
            _active.ScrollUp(_active.CursorY, _scrollBottom, n, BlankCell);
            _active.CursorX = 0;
            _pendingWrap = false;
        }

        private void InsertChars(int n)
        {
            Line row = _active.GetRow(_active.CursorY);
            int x = _active.CursorX;
            if (n > _active.Cols - x) n = _active.Cols - x;
            for (int c = _active.Cols - 1; c >= x + n; c--) row.Cells[c] = row.Cells[c - n];
            row.Fill(x, x + n, BlankCell);
            _active.MarkDirty(_active.CursorY);
            _pendingWrap = false;
        }

        private void DeleteChars(int n)
        {
            Line row = _active.GetRow(_active.CursorY);
            int x = _active.CursorX;
            if (n > _active.Cols - x) n = _active.Cols - x;
            for (int c = x; c < _active.Cols - n; c++) row.Cells[c] = row.Cells[c + n];
            row.Fill(_active.Cols - n, _active.Cols, BlankCell);
            _active.MarkDirty(_active.CursorY);
            _pendingWrap = false;
        }

        private void ClearTabStop(int mode)
        {
            if (mode == 0)
            {
                if (_active.CursorX < _tabStops.Length) _tabStops[_active.CursorX] = false;
            }
            else if (mode == 3)
            {
                for (int i = 0; i < _tabStops.Length; i++) _tabStops[i] = false;
            }
        }

        // ---- modes ------------------------------------------------------------

        private void SetAnsiModes(int[] p, int count, bool set)
        {
            for (int i = 0; i < count; i++)
            {
                switch (Arg(p, count, i, -1))
                {
                    case 4: InsertMode = set; break;   // IRM
                    case 20: NewLineMode = set; break; // LNM
                }
            }
        }

        private void SetDecModes(int[] p, int count, bool set)
        {
            for (int i = 0; i < count; i++)
            {
                int mode = Arg(p, count, i, -1);
                switch (mode)
                {
                    case 1: ApplicationCursorKeys = set; break;                 // DECCKM
                    case 3:                                                      // DECCOLM
                        // Switching 80/132 columns clears the screen and resets margins.
                        ResetScrollRegion();
                        EraseInDisplay(2);
                        _active.CursorX = 0; _active.CursorY = 0;
                        break;
                    case 5:                                                      // DECSCNM
                        if (ReverseVideo != set) { ReverseVideo = set; _active.MarkAllDirty(); }
                        break;
                    case 6:                                                      // DECOM
                        OriginMode = set;
                        _active.CursorX = 0;
                        _active.CursorY = set ? _scrollTop : 0;
                        break;
                    case 7: AutoWrap = set; break;                               // DECAWM
                    case 12: break;                                              // cursor blink
                    case 25: CursorVisible = set; break;                         // DECTCEM
                    case 1000: Mouse = set ? MouseMode.Click : MouseMode.Off; break;
                    case 1002: Mouse = set ? MouseMode.ButtonDrag : MouseMode.Off; break;
                    case 1003: Mouse = set ? MouseMode.AnyMotion : MouseMode.Off; break;
                    case 1004: FocusReporting = set; break;
                    case 1005: MouseEncode = set ? MouseEncoding.Utf8 : MouseEncoding.X10; break;
                    case 1006: MouseEncode = set ? MouseEncoding.Sgr : MouseEncoding.X10; break;
                    case 1015: MouseEncode = set ? MouseEncoding.Urxvt : MouseEncoding.X10; break;
                    case 1047: if (set) SwitchToAlternate(false); else SwitchToPrimary(true); break;
                    case 1048: if (set) SaveCursor(); else RestoreCursor(); break;
                    case 47:
                    case 1049:
                        if (set) SwitchToAlternate(true); else SwitchToPrimary(true);
                        break;
                    case 2004: BracketedPaste = set; break;
                }
            }
        }

        private void SwitchToAlternate(bool saveCursor)
        {
            if (_usingAlternate) return;
            if (saveCursor) SaveCursor();
            _usingAlternate = true;
            _active = _alternate;
            _active.CursorX = 0;
            _active.CursorY = 0;
            ResetScrollRegion();
            EraseInDisplay(2);
            _active.MarkAllDirty();
        }

        private void SwitchToPrimary(bool restoreCursor)
        {
            if (!_usingAlternate) return;
            _usingAlternate = false;
            _active = _primary;
            ResetScrollRegion();
            if (restoreCursor) RestoreCursor();
            _active.MarkAllDirty();
        }

        // ---- SGR ---------------------------------------------------------------

        private void ApplySgr(int[] p, int count)
        {
            if (count == 0)
            {
                _fg = Color.Default; _bg = Color.Default; _flags = CellFlags.None;
                return;
            }

            for (int i = 0; i < count; i++)
            {
                int code = Arg(p, count, i, 0);
                switch (code)
                {
                    case 0: _fg = Color.Default; _bg = Color.Default; _flags = CellFlags.None; break;
                    case 1: _flags |= CellFlags.Bold; break;
                    case 2: _flags |= CellFlags.Faint; break;
                    case 3: _flags |= CellFlags.Italic; break;
                    case 4: _flags |= CellFlags.Underline; break;
                    case 5: case 6: _flags |= CellFlags.Blink; break;
                    case 7: _flags |= CellFlags.Inverse; break;
                    case 8: _flags |= CellFlags.Invisible; break;
                    case 9: _flags |= CellFlags.Strikethrough; break;
                    case 21: _flags |= CellFlags.DoubleUnderline; break;
                    case 22: _flags &= ~(CellFlags.Bold | CellFlags.Faint); break;
                    case 23: _flags &= ~CellFlags.Italic; break;
                    case 24: _flags &= ~(CellFlags.Underline | CellFlags.DoubleUnderline); break;
                    case 25: _flags &= ~CellFlags.Blink; break;
                    case 27: _flags &= ~CellFlags.Inverse; break;
                    case 28: _flags &= ~CellFlags.Invisible; break;
                    case 29: _flags &= ~CellFlags.Strikethrough; break;

                    case 39: _fg = Color.Default; break;
                    case 49: _bg = Color.Default; break;

                    case 38: i = ExtendedColor(p, count, i, true); break;
                    case 48: i = ExtendedColor(p, count, i, false); break;

                    default:
                        if (code >= 30 && code <= 37) _fg = Color.FromIndex(code - 30);
                        else if (code >= 40 && code <= 47) _bg = Color.FromIndex(code - 40);
                        else if (code >= 90 && code <= 97) _fg = Color.FromIndex(code - 90 + 8);
                        else if (code >= 100 && code <= 107) _bg = Color.FromIndex(code - 100 + 8);
                        break;
                }
            }
        }

        /// <summary>
        /// SGR 38/48 extended colour. Handles both the 5;n (256 colour) and 2;r;g;b
        /// (truecolor) forms. Returns the index of the last consumed parameter.
        /// </summary>
        private int ExtendedColor(int[] p, int count, int i, bool foreground)
        {
            int kind = Arg(p, count, i + 1, -1);
            if (kind == 5)
            {
                int idx = Arg(p, count, i + 2, 0);
                Color c = Color.FromIndex(idx);
                if (foreground) _fg = c; else _bg = c;
                return i + 2;
            }
            if (kind == 2)
            {
                int r = Arg(p, count, i + 2, 0);
                int g = Arg(p, count, i + 3, 0);
                int b = Arg(p, count, i + 4, 0);
                Color c = Color.FromRgb(r, g, b);
                if (foreground) _fg = c; else _bg = c;
                return i + 4;
            }
            return i;
        }

        // ---- reports -------------------------------------------------------------

        private void DeviceStatus(int code)
        {
            if (code == 5)
            {
                Send("\x1b[0n"); // "terminal OK"
            }
            else if (code == 6)
            {
                // CPR: report is 1-based and relative to the origin when DECOM is set.
                int row = _active.CursorY - (OriginMode ? _scrollTop : 0) + 1;
                int col = _active.CursorX + 1;
                Send("\x1b[" + row.ToString() + ";" + col.ToString() + "R");
            }
        }

        private void DecDeviceStatus(int code)
        {
            if (code == 6)
            {
                int row = _active.CursorY - (OriginMode ? _scrollTop : 0) + 1;
                int col = _active.CursorX + 1;
                Send("\x1b[?" + row.ToString() + ";" + col.ToString() + ";1R");
            }
            else if (code == 15) Send("\x1b[?11n");  // no printer
            else if (code == 25) Send("\x1b[?21n");  // UDKs locked
            else if (code == 26) Send("\x1b[?27;1;0;0n"); // keyboard: North American
        }

        private void WindowManipulation(int[] p, int count)
        {
            int op = Arg(p, count, 0, 0);
            switch (op)
            {
                case 18: // report text area size in characters
                    Send("\x1b[8;" + _active.Rows.ToString() + ";" + _active.Cols.ToString() + "t");
                    break;
                case 19: // report screen size in characters
                    Send("\x1b[9;" + _active.Rows.ToString() + ";" + _active.Cols.ToString() + "t");
                    break;
                // Resize/move/raise requests from the host are deliberately ignored:
                // letting a remote device move the operator's window is hostile.
            }
        }

        // =====================================================================
        // IVtSink - OSC and DCS
        // =====================================================================

        private ushort _currentLink;

        public void OscDispatch(int code, string payload)
        {
            switch (code)
            {
                case 0:  // icon name + window title
                case 2:  // window title
                    {
                        Action<string> h = TitleChanged;
                        if (h != null) h(payload);
                        break;
                    }
                case 8:
                    // OSC 8 ;params; uri  - hyperlink start, empty uri ends it.
                    {
                        int sep = payload.IndexOf(';');
                        string uri = sep >= 0 ? payload.Substring(sep + 1) : string.Empty;
                        _currentLink = string.IsNullOrEmpty(uri) ? (ushort)0 : RegisterLink(uri);
                        break;
                    }
                case 10: Send("\x1b]10;rgb:ffff/ffff/ffff\x1b\\"); break; // report fg
                case 11: Send("\x1b]11;rgb:0000/0000/0000\x1b\\"); break; // report bg
                case 104: break; // reset palette
                // 4 (set palette) and 52 (clipboard) are intentionally not honoured:
                // a remote device should not be able to repaint the operator's theme or
                // read and write the local clipboard.
            }
        }

        private System.Collections.Generic.List<string> _links = new System.Collections.Generic.List<string>();

        private ushort RegisterLink(string uri)
        {
            int existing = _links.IndexOf(uri);
            if (existing >= 0) return (ushort)(existing + 1);
            if (_links.Count >= ushort.MaxValue - 1) return 0;
            _links.Add(uri);
            return (ushort)_links.Count;
        }

        public string GetLink(ushort id)
        {
            if (id == 0 || id > _links.Count) return null;
            return _links[id - 1];
        }

        public void DcsHook(char prefix, int[] p, int count, string intermediates, char final)
        {
            _oscBuffer.Length = 0;
        }

        public void DcsPut(char ch)
        {
            if (_oscBuffer.Length < 4096) _oscBuffer.Append(ch);
        }

        public void DcsUnhook()
        {
            // DECRQSS and Sixel are parsed but not acted on; consuming them cleanly is
            // what keeps them from corrupting the screen.
            _oscBuffer.Length = 0;
        }
    }

    public enum MouseMode { Off, Click, ButtonDrag, AnyMotion }
    public enum MouseEncoding { X10, Utf8, Sgr, Urxvt }
}
