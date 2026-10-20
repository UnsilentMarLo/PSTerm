// PSTerm - TerminalControl.cs
// The WinForms control that draws the terminal grid and collects input.
//
// Design notes:
//  * Painting is coalesced. The backend feeds the emulator from a reader thread
//    and only sets a flag; a timer on the UI thread repaints at most once per
//    frame. Without this, "cat bigfile" would queue one repaint per read.
//  * Rendering batches runs of cells that share attributes into single GDI text
//    calls, so a full 200x60 screen is a few hundred draws rather than 12000.
//  * All access to the emulator's screen is under SyncRoot, because the reader
//    thread writes to it while the UI thread paints.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

// See Palette.cs: PSTerm.Vt.Color would collide with System.Drawing.Color, so
// the terminal types are aliased in individually instead of importing the
// namespace. `Color` in this file always means System.Drawing.Color.
using Cell = PSTerm.Vt.Cell;
using CellFlags = PSTerm.Vt.CellFlags;
using Line = PSTerm.Vt.Line;
using ScreenBuffer = PSTerm.Vt.ScreenBuffer;
using TerminalEmulator = PSTerm.Vt.TerminalEmulator;
using KeyEncoder = PSTerm.Vt.KeyEncoder;
using KeyEncoderSettings = PSTerm.Vt.KeyEncoderSettings;
using TermKey = PSTerm.Vt.TermKey;
using TermModifiers = PSTerm.Vt.TermModifiers;
using MouseMode = PSTerm.Vt.MouseMode;

namespace PSTerm.Render
{
    /// <summary>Raised when the visible grid size changes, so the backend can tell the host.</summary>
    public class TerminalResizeEventArgs : EventArgs
    {
        public int Cols;
        public int Rows;
        public TerminalResizeEventArgs(int cols, int rows) { Cols = cols; Rows = rows; }
    }

    public class TerminalInputEventArgs : EventArgs
    {
        public string Text;
        public TerminalInputEventArgs(string text) { Text = text; }
    }

    /// <summary>Raised before multi-line text is pasted into a terminal that has not
    /// asked for bracketed paste, so the operator can cancel it.</summary>
    public class TerminalPasteEventArgs : EventArgs
    {
        public readonly string Text;
        public readonly int LineCount;
        public bool Cancel;
        public TerminalPasteEventArgs(string text, int lineCount) { Text = text; LineCount = lineCount; }
    }

    /// <summary>GDI entry points used by the batched text path.</summary>
    internal static class Gdi
    {
        internal const int TRANSPARENT = 1;

        [DllImport("gdi32.dll")]
        internal static extern int SetBkMode(IntPtr hdc, int mode);

        [DllImport("gdi32.dll")]
        internal static extern int SetTextColor(IntPtr hdc, int colorRef);

        [DllImport("gdi32.dll")]
        internal static extern IntPtr SelectObject(IntPtr hdc, IntPtr obj);

        [DllImport("gdi32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DeleteObject(IntPtr obj);

        [DllImport("gdi32.dll", CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ExtTextOut(IntPtr hdc, int x, int y, uint options,
                                               IntPtr rect, string text, uint count, IntPtr dx);

        /// <summary>GDI wants colours as 0x00BBGGRR, the reverse of ARGB.</summary>
        internal static int ToColorRef(Color c)
        {
            return c.R | (c.G << 8) | (c.B << 16);
        }
    }

    public sealed class TerminalControl : Control, PSTerm.ITerminalSink
    {
        // ---- model ---------------------------------------------------------
        private TerminalEmulator _term;
        private readonly object _sync = new object();
        private TerminalPalette _palette = new TerminalPalette();
        private KeyEncoder _keys = new KeyEncoder(new KeyEncoderSettings());

        // ---- metrics --------------------------------------------------------
        private Font _font;
        private Font _boldFont;
        private Font _italicFont;
        private Font _boldItalicFont;
        private int _cellWidth = 8;
        private int _cellHeight = 16;
        private int _baselineOffset;
        private bool _metricsValid;

        /// <summary>One run of text, queued during the paint and drawn in a batch.</summary>
        private struct TextRun
        {
            public int X;
            public int Y;
            public string Text;
            public Font Font;
            public Color Colour;
        }

        // Text is collected while the rest of the frame is drawn, then written in
        // one pass. Every TextRenderer.DrawText call checks an HDC out of the
        // Graphics and back again, and a screen with frequent colour changes
        // produces hundreds of runs: that handover, not the drawing, was the
        // bulk of the frame time.
        private readonly List<TextRun> _pendingText = new List<TextRun>(512);
        private readonly Dictionary<Font, IntPtr> _hFontCache = new Dictionary<Font, IntPtr>();

        // ---- painting -------------------------------------------------------
        // Brushes and pens are cached by colour. A full repaint draws a run per
        // change of attribute - on a busy screen well over a thousand - and
        // allocating a GDI object for each was the bulk of the frame time.
        private readonly Dictionary<int, SolidBrush> _brushCache = new Dictionary<int, SolidBrush>();
        private readonly Dictionary<int, Pen> _penCache = new Dictionary<int, Pen>();

        private readonly Timer _renderTimer;
        private volatile bool _needsPaint;
        private Bitmap _backBuffer;
        private bool _backBufferValid;

        // ---- viewport / scrollback -------------------------------------------
        private int _scrollOffset;           // lines scrolled back from the live bottom
        private ThinScrollBar _scrollBar;
        private bool _updatingScrollBar;

        // ---- selection ------------------------------------------------------
        private bool _selecting;
        private bool _hasSelection;
        private bool _rectangularSelection;
        private int _selAnchorAbs, _selAnchorCol;
        private int _selEndAbs, _selEndCol;

        // ---- cursor ---------------------------------------------------------
        private bool _cursorOn = true;
        private int _paintedCursorRow = -1;
        private readonly Timer _blinkTimer;
        private bool _hostFocused;

        public event EventHandler<TerminalInputEventArgs> Input;
        public event EventHandler<TerminalResizeEventArgs> TerminalResized;
        public event EventHandler<EventArgs> BellRang;
        public event EventHandler<TerminalInputEventArgs> TitleChanged;
        public event EventHandler<TerminalPasteEventArgs> PasteRequested;

        public TerminalControl()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint |
                     ControlStyles.UserPaint |
                     ControlStyles.Opaque |
                     ControlStyles.ResizeRedraw |
                     ControlStyles.Selectable, true);
            // Our own back buffer is used, so the framework's is redundant.
            SetStyle(ControlStyles.OptimizedDoubleBuffer, false);

            TabStop = true;
            BackColor = _palette.Background;

            // Order matters. SetFont measures text, measuring can realise the
            // window handle, and OnHandleCreated calls straight back into
            // RecalculateGrid - so the emulator and the scroll bar have to exist
            // before the first call that might create a handle.
            _term = new TerminalEmulator(80, 24, 5000);
            HookEmulator(_term);

            // A slim owner-drawn bar rather than VScrollBar, which is a system
            // control that ignores BackColor and stays light beside a dark grid.
            _scrollBar = new ThinScrollBar();
            _scrollBar.Dock = DockStyle.Right;
            _scrollBar.Visible = false;
            _scrollBar.ValueChanged += OnScrollBarChanged;
            Controls.Add(_scrollBar);

            SetFont(new Font("Consolas", 10.5f, FontStyle.Regular, GraphicsUnit.Point));

            _renderTimer = new Timer();
            _renderTimer.Interval = 16;          // ~60 fps ceiling
            _renderTimer.Tick += OnRenderTick;
            _renderTimer.Start();

            _blinkTimer = new Timer();
            _blinkTimer.Interval = 530;
            _blinkTimer.Tick += OnBlinkTick;
            _blinkTimer.Start();
        }

        // =====================================================================
        // Public surface
        // =====================================================================

        private SolidBrush GetBrush(Color colour)
        {
            int key = colour.ToArgb();
            SolidBrush brush;
            if (_brushCache.TryGetValue(key, out brush)) return brush;

            // The palette is bounded, but a device emitting truecolor is not, so
            // the cache is dropped rather than allowed to grow without limit.
            if (_brushCache.Count > 512) { DisposeCaches(); }

            brush = new SolidBrush(colour);
            _brushCache[key] = brush;
            return brush;
        }

        private Pen GetPen(Color colour)
        {
            int key = colour.ToArgb();
            Pen pen;
            if (_penCache.TryGetValue(key, out pen)) return pen;

            if (_penCache.Count > 512)
            {
                foreach (Pen p in _penCache.Values) p.Dispose();
                _penCache.Clear();
            }

            pen = new Pen(colour);
            _penCache[key] = pen;
            return pen;
        }

        private void DisposeCaches()
        {
            foreach (SolidBrush b in _brushCache.Values) b.Dispose();
            _brushCache.Clear();
            foreach (Pen p in _penCache.Values) p.Dispose();
            _penCache.Clear();
            DisposeFontHandles();
        }

        private void DisposeFontHandles()
        {
            foreach (IntPtr h in _hFontCache.Values)
            {
                if (h != IntPtr.Zero) Gdi.DeleteObject(h);
            }
            _hFontCache.Clear();
        }

        private IntPtr GetFontHandle(Font font)
        {
            IntPtr handle;
            if (_hFontCache.TryGetValue(font, out handle)) return handle;
            handle = font.ToHfont();
            _hFontCache[font] = handle;
            return handle;
        }

        /// <summary>
        /// Write every queued run through a single device context.
        /// </summary>
        private void FlushText(Graphics g)
        {
            if (_pendingText.Count == 0) return;

            IntPtr hdc = g.GetHdc();
            try
            {
                Gdi.SetBkMode(hdc, Gdi.TRANSPARENT);

                Font currentFont = null;
                int currentColour = -1;
                IntPtr previousFont = IntPtr.Zero;
                bool first = true;

                for (int i = 0; i < _pendingText.Count; i++)
                {
                    TextRun run = _pendingText[i];

                    if (!ReferenceEquals(run.Font, currentFont))
                    {
                        IntPtr selected = Gdi.SelectObject(hdc, GetFontHandle(run.Font));
                        if (first) { previousFont = selected; first = false; }
                        currentFont = run.Font;
                    }

                    int colour = Gdi.ToColorRef(run.Colour);
                    if (colour != currentColour)
                    {
                        Gdi.SetTextColor(hdc, colour);
                        currentColour = colour;
                    }

                    Gdi.ExtTextOut(hdc, run.X, run.Y, 0, IntPtr.Zero,
                                   run.Text, (uint)run.Text.Length, IntPtr.Zero);
                }

                if (previousFont != IntPtr.Zero) Gdi.SelectObject(hdc, previousFont);
            }
            finally
            {
                g.ReleaseHdc(hdc);
                _pendingText.Clear();
            }
        }

        public TerminalEmulator Terminal { get { return _term; } }

        /// <summary>Lock this around any access to the emulator from another thread.</summary>
        public object SyncRoot { get { return _sync; } }

        public TerminalPalette Palette
        {
            get { return _palette; }
            set
            {
                if (value == null) return;
                _palette = value;
                BackColor = _palette.Background;
                if (_scrollBar != null) _scrollBar.ApplyTheme(BuildScrollBarTheme());
                DisposeCaches();
                InvalidateAll();
            }
        }

        /// <summary>
        /// The key-to-bytes map. Named KeyMap rather than Keys because a member
        /// called Keys would shadow System.Windows.Forms.Keys throughout the class.
        /// </summary>
        public KeyEncoder KeyMap
        {
            get { return _keys; }
            set { if (value != null) _keys = value; }
        }

        public int Cols { get { return _term.Cols; } }
        public int Rows { get { return _term.Rows; } }

        /// <summary>
        /// Colours for the scroll bar, derived from the terminal palette so it
        /// belongs to the session rather than to the application chrome.
        /// </summary>
        private ControlTheme BuildScrollBarTheme()
        {
            ControlTheme t = new ControlTheme();
            t.Background = _palette.Background;
            bool dark = TerminalPalette.Luminance(_palette.Background) < 0.5;
            t.Border = TerminalPalette.Blend(_palette.Foreground, _palette.Background, dark ? 0.30 : 0.35);
            t.BorderStrong = TerminalPalette.Blend(_palette.Foreground, _palette.Background, dark ? 0.55 : 0.60);
            t.IsDark = dark;
            return t;
        }

        /// <summary>Number of scrollback lines currently scrolled into view.</summary>
        public int ScrollOffset { get { return _scrollOffset; } }

        public bool HasSelection { get { return _hasSelection; } }

        /// <summary>Feed decoded characters from the transport. Safe to call from any thread.</summary>
        public void Feed(char[] buffer, int offset, int count)
        {
            lock (_sync)
            {
                _term.Write(buffer, offset, count);
                // Output pins the view to the bottom, which is what every terminal
                // does and what users expect when a device starts talking.
                if (_scrollOffset != 0) _scrollOffset = 0;
            }
            _needsPaint = true;
        }

        public void Feed(string text)
        {
            lock (_sync)
            {
                _term.Write(text);
                if (_scrollOffset != 0) _scrollOffset = 0;
            }
            _needsPaint = true;
        }

        public void SetFont(Font font)
        {
            if (font == null) return;

            DisposeFonts();
            _font = font;
            _metricsValid = false;
            _boldFont = new Font(font, FontStyle.Bold);
            _italicFont = new Font(font, FontStyle.Italic);
            _boldItalicFont = new Font(font, FontStyle.Bold | FontStyle.Italic);

            MeasureCell();
            RecalculateGrid();
            InvalidateAll();
        }

        public Font TerminalFont { get { return _font; } }
        public int CellWidth { get { return _cellWidth; } }
        public int CellHeight { get { return _cellHeight; } }

        /// <summary>Reset the terminal and clear the scrollback.</summary>
        public void ResetTerminal()
        {
            lock (_sync)
            {
                _term.HardReset();
                _term.Primary.ClearHistory();
                _scrollOffset = 0;
            }
            ClearSelection();
            InvalidateAll();
        }

        public void ClearScrollback()
        {
            lock (_sync)
            {
                _term.Primary.ClearHistory();
                _scrollOffset = 0;
            }
            InvalidateAll();
        }

        // =====================================================================
        // Emulator wiring
        // =====================================================================

        private void HookEmulator(TerminalEmulator term)
        {
            term.Respond += OnTerminalRespond;
            term.Bell += OnTerminalBell;
            term.TitleChanged += OnTerminalTitle;
        }

        private void OnTerminalRespond(string s)
        {
            RaiseInput(s);
        }

        private void OnTerminalBell()
        {
            EventHandler<EventArgs> h = BellRang;
            if (h != null) BeginInvokeSafe(new MethodInvoker(delegate { h(this, EventArgs.Empty); }));
        }

        private void OnTerminalTitle(string title)
        {
            EventHandler<TerminalInputEventArgs> h = TitleChanged;
            if (h != null)
                BeginInvokeSafe(new MethodInvoker(delegate { h(this, new TerminalInputEventArgs(title)); }));
        }

        private void BeginInvokeSafe(Delegate d)
        {
            try
            {
                if (IsHandleCreated && !IsDisposed) BeginInvoke(d);
            }
            catch (ObjectDisposedException) { }
            catch (InvalidOperationException) { }
        }

        private void RaiseInput(string text)
        {
            if (string.IsNullOrEmpty(text)) return;
            EventHandler<TerminalInputEventArgs> h = Input;
            if (h == null) return;

            // Keystrokes arrive on the UI thread and are sent straight through.
            // Terminal replies (device attributes, cursor position reports) do not:
            // they are produced inside Feed(), on the transport's reader thread.
            // Handlers may be PowerShell script blocks, which cannot run on a
            // thread with no runspace - the session would hang rather than answer.
            if (InvokeRequired)
            {
                BeginInvokeSafe(new MethodInvoker(delegate
                {
                    EventHandler<TerminalInputEventArgs> inner = Input;
                    if (inner != null) inner(this, new TerminalInputEventArgs(text));
                }));
                return;
            }

            h(this, new TerminalInputEventArgs(text));
        }

        // =====================================================================
        // Metrics and layout
        // =====================================================================

        /// <summary>
        /// Work out the cell size from the font.
        ///
        /// This has to be measured against the same device context the text is
        /// later drawn into. A run of cells is drawn as a single string and relies
        /// on the font's own advance carrying each glyph to the next cell, so if
        /// the measured width and the drawn advance disagree the columns drift:
        /// measuring without a Graphics picks up the system DPI rather than the
        /// control's, which on a scaled display gave a cell twice as wide as the
        /// glyphs and put the cursor in the wrong column.
        ///
        /// The control has no handle during construction, so measurement is
        /// deferred and redone at first paint.
        /// </summary>
        private void MeasureCell()
        {
            if (_font == null) return;

            TextFormatFlags flags = TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix;
            Size proposed = new Size(short.MaxValue, short.MaxValue);
            Size size;

            if (IsHandleCreated)
            {
                using (Graphics g = CreateGraphics())
                {
                    size = TextRenderer.MeasureText(g, "W", _font, proposed, flags);
                    _cellHeight = Math.Max(1, (int)Math.Ceiling(_font.GetHeight(g)));
                }
                _metricsValid = true;
            }
            else
            {
                // Provisional only; corrected once there is a real device context.
                size = TextRenderer.MeasureText("W", _font, proposed, flags);
                _cellHeight = Math.Max(1, _font.Height);
                _metricsValid = false;
            }

            _cellWidth = Math.Max(1, size.Width);
            _baselineOffset = 0;
        }

        private void RecalculateGrid()
        {
            if (_term == null || _cellWidth <= 0 || _cellHeight <= 0) return;

            int usableWidth = ClientSize.Width - (_scrollBar != null && _scrollBar.Visible ? _scrollBar.Width : 0);
            int cols = Math.Max(1, usableWidth / _cellWidth);
            int rows = Math.Max(1, ClientSize.Height / _cellHeight);

            bool changed;
            lock (_sync)
            {
                changed = (cols != _term.Cols || rows != _term.Rows);
                if (changed) _term.Resize(cols, rows);
            }

            if (changed)
            {
                _backBufferValid = false;
                EventHandler<TerminalResizeEventArgs> h = TerminalResized;
                if (h != null) h(this, new TerminalResizeEventArgs(cols, rows));
            }

            UpdateScrollBar();
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            DisposeBackBuffer();
            RecalculateGrid();
            _needsPaint = true;
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            MeasureCell();
            RecalculateGrid();
        }

        // =====================================================================
        // Scrollback
        // =====================================================================

        private void UpdateScrollBar()
        {
            if (_scrollBar == null || _term == null) return;

            int history;
            lock (_sync) { history = _term.IsAlternateScreen ? 0 : _term.Primary.HistoryCount; }

            bool needed = history > 0;
            if (_scrollBar.Visible != needed)
            {
                _scrollBar.Visible = needed;
                // Showing or hiding the bar changes the usable width, so the grid
                // has to be recomputed - but only once, guarded by the flag.
                if (!_updatingScrollBar)
                {
                    _updatingScrollBar = true;
                    try { RecalculateGrid(); }
                    finally { _updatingScrollBar = false; }
                }
            }
            if (!needed) return;

            _updatingScrollBar = true;
            try
            {
                _scrollBar.Minimum = 0;
                _scrollBar.Maximum = history;
                _scrollBar.LargeChange = Math.Max(1, _term.Rows);
                _scrollBar.SmallChange = 1;
                int value = history - _scrollOffset;
                _scrollBar.Value = Math.Max(0, Math.Min(_scrollBar.Maximum, value));
            }
            finally { _updatingScrollBar = false; }
        }

        private void OnScrollBarChanged(object sender, EventArgs e)
        {
            if (_updatingScrollBar) return;
            int history;
            lock (_sync) { history = _term.Primary.HistoryCount; }
            _scrollOffset = Math.Max(0, history - _scrollBar.Value);
            InvalidateAll();
        }

        public void ScrollLines(int delta)
        {
            int history;
            lock (_sync) { history = _term.IsAlternateScreen ? 0 : _term.Primary.HistoryCount; }
            int next = _scrollOffset + delta;
            if (next < 0) next = 0;
            if (next > history) next = history;
            if (next == _scrollOffset) return;
            _scrollOffset = next;
            UpdateScrollBar();
            InvalidateAll();
        }

        public void ScrollToBottom()
        {
            if (_scrollOffset == 0) return;
            _scrollOffset = 0;
            UpdateScrollBar();
            InvalidateAll();
        }

        protected override void OnMouseWheel(MouseEventArgs e)
        {
            base.OnMouseWheel(e);

            bool mouseReported;
            lock (_sync) { mouseReported = _term.Mouse != MouseMode.Off; }

            if (mouseReported && !_term.IsAlternateScreen)
            {
                // Applications that ask for mouse events get wheel as buttons 64/65.
                SendWheelAsButtons(e);
                return;
            }
            if (mouseReported && _term.IsAlternateScreen)
            {
                SendWheelAsButtons(e);
                return;
            }

            int lines = SystemInformation.MouseWheelScrollLines;
            if (lines <= 0) lines = 3;
            ScrollLines(e.Delta > 0 ? lines : -lines);
        }

        private void SendWheelAsButtons(MouseEventArgs e)
        {
            int button = e.Delta > 0 ? 64 : 65;
            int col, row;
            if (!TryHitTest(e.Location, out col, out row)) return;
            string seq = KeyEncoder.EncodeMouse(_term.Mouse, _term.MouseEncode, button, true,
                                                col, row, CurrentModifiers());
            RaiseInput(seq);
        }

        // =====================================================================
        // Painting
        // =====================================================================

        private void OnRenderTick(object sender, EventArgs e)
        {
            if (!_needsPaint) return;
            _needsPaint = false;
            Invalidate();
        }

        private void OnBlinkTick(object sender, EventArgs e)
        {
            if (!_hostFocused || _term == null) return;
            bool visible;
            lock (_sync) { visible = _term.CursorVisible; }
            if (!visible) return;
            _cursorOn = !_cursorOn;
            InvalidateCursorRow();
        }

        private void InvalidateCursorRow()
        {
            lock (_sync)
            {
                if (_term == null) return;
                _term.Screen.MarkDirty(_term.CursorY);
            }
            _needsPaint = true;
        }

        private void InvalidateAll()
        {
            lock (_sync) { _term.Screen.MarkAllDirty(); }
            _backBufferValid = false;
            _needsPaint = true;
        }

        private void DisposeBackBuffer()
        {
            if (_backBuffer != null)
            {
                _backBuffer.Dispose();
                _backBuffer = null;
            }
            _backBufferValid = false;
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            // Everything is covered by OnPaint; painting the background first would
            // just cause flicker.
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            if (_term == null || _font == null) return;

            // The handle exists by now, so any provisional metrics taken during
            // construction can be replaced with correctly scaled ones.
            if (!_metricsValid)
            {
                MeasureCell();
                RecalculateGrid();
                _backBufferValid = false;
            }

            int width = ClientSize.Width;
            int height = ClientSize.Height;
            if (width <= 0 || height <= 0) return;

            if (_backBuffer == null || _backBuffer.Width != width || _backBuffer.Height != height)
            {
                DisposeBackBuffer();
                _backBuffer = new Bitmap(width, height);
                _backBufferValid = false;
            }

            using (Graphics g = Graphics.FromImage(_backBuffer))
            {
                g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
                g.SmoothingMode = SmoothingMode.None;
                g.PixelOffsetMode = PixelOffsetMode.Half;
                RenderScreen(g, !_backBufferValid);
            }
            _backBufferValid = true;

            e.Graphics.DrawImageUnscaled(_backBuffer, 0, 0);
        }

        private void RenderScreen(Graphics g, bool full)
        {
            int rows, cols;
            bool reversed;

            lock (_sync)
            {
                ScreenBuffer screen = _term.Screen;
                rows = screen.Rows;
                cols = screen.Cols;
                reversed = _term.ReverseVideo;

                int historyCount = _term.IsAlternateScreen ? 0 : _term.Primary.HistoryCount;
                int topAbs = historyCount + 0 - _scrollOffset;

                if (full)
                    g.FillRectangle(GetBrush(_palette.Background), 0, 0, ClientSize.Width, ClientSize.Height);

                // The row the cursor was last drawn on must be repainted even when
                // the model did not change there, or the block it left behind
                // stays on the back buffer.
                if (_paintedCursorRow >= 0 && _paintedCursorRow != _term.CursorY)
                    screen.MarkDirty(_paintedCursorRow);
                screen.MarkDirty(_term.CursorY);

                for (int row = 0; row < rows; row++)
                {
                    if (!full && !screen.IsDirty(row) && _scrollOffset == 0) continue;

                    int abs = topAbs + row;
                    Line line = (abs >= 0 && abs < screen.TotalLines)
                        ? screen.GetAbsolute(abs)
                        : null;

                    RenderRow(g, row, abs, line, cols, reversed);
                }

                // All queued text is written here, in one device context.
                FlushText(g);

                screen.ClearDamage();

                // The cursor is drawn last so it sits on top of the cell it occupies,
                // and only when the live view is showing.
                if (_scrollOffset == 0 && _term.CursorVisible && (_cursorOn || !_hostFocused))
                {
                    RenderCursor(g, reversed);
                    _paintedCursorRow = _term.CursorY;
                }
                else
                {
                    _paintedCursorRow = -1;
                }
            }
        }

        private void RenderRow(Graphics g, int row, int abs, Line line, int cols, bool reversed)
        {
            int y = row * _cellHeight;

            if (line == null)
            {
                g.FillRectangle(GetBrush(_palette.Background), 0, y, ClientSize.Width, _cellHeight);
                return;
            }

            // Pass 1: backgrounds, merged into runs.
            int c = 0;
            while (c < cols)
            {
                Color fore, back;
                ResolveAt(line, abs, c, reversed, out fore, out back);
                int start = c;
                c++;
                while (c < cols)
                {
                    Color f2, b2;
                    ResolveAt(line, abs, c, reversed, out f2, out b2);
                    if (b2 != back) break;
                    c++;
                }
                g.FillRectangle(GetBrush(back), start * _cellWidth, y, (c - start) * _cellWidth, _cellHeight);
            }

            // Fill any pixels past the last column (window not an exact multiple).
            int gridRight = cols * _cellWidth;
            if (gridRight < ClientSize.Width)
            {
                g.FillRectangle(GetBrush(_palette.Background), gridRight, y, ClientSize.Width - gridRight, _cellHeight);
            }

            // Pass 2: glyph runs sharing font and colour.
            c = 0;
            StringBuilder run = new StringBuilder(cols);
            while (c < cols)
            {
                Cell cell = line.Cells[c];
                if ((cell.Flags & CellFlags.WideTrail) != 0) { c++; continue; }

                Color fore, back;
                ResolveAt(line, abs, c, reversed, out fore, out back);

                // Box-drawing and block characters are drawn geometrically rather
                // than as glyphs, so their strokes meet exactly at cell edges. A
                // font's glyphs are built for the em box, not the terminal cell,
                // and leave hairline gaps in every table a device draws.
                if (BoxDrawing.IsBoxDrawing(cell.Ch))
                {
                    Rectangle box = new Rectangle(c * _cellWidth, y, _cellWidth, _cellHeight);
                    if (BoxDrawing.Draw(g, cell.Ch, box, fore)) { c++; continue; }
                }

                Font font = FontFor(cell.Flags);

                int start = c;
                run.Length = 0;
                run.Append(cell.Ch == '\0' ? ' ' : cell.Ch);
                CellFlags styleFlags = cell.Flags;
                c++;

                while (c < cols)
                {
                    Cell next = line.Cells[c];
                    if ((next.Flags & CellFlags.WideTrail) != 0) { c++; continue; }
                    if (BoxDrawing.IsBoxDrawing(next.Ch)) break;

                    Color f2, b2;
                    ResolveAt(line, abs, c, reversed, out f2, out b2);
                    if (f2 != fore || FontFor(next.Flags) != font) break;
                    // Underline and strikethrough are drawn per run, so they must match.
                    if ((next.Flags & (CellFlags.Underline | CellFlags.DoubleUnderline | CellFlags.Strikethrough)) !=
                        (styleFlags & (CellFlags.Underline | CellFlags.DoubleUnderline | CellFlags.Strikethrough))) break;

                    run.Append(next.Ch == '\0' ? ' ' : next.Ch);
                    c++;
                }

                DrawRun(g, run.ToString(), start, y, fore, font, styleFlags, c - start);
            }
        }

        private void DrawRun(Graphics g, string text, int startCol, int y, Color fore, Font font,
                             CellFlags flags, int cellSpan)
        {
            if (text.Length == 0) return;

            int x = startCol * _cellWidth;

            bool allBlank = true;
            for (int i = 0; i < text.Length; i++)
            {
                if (text[i] != ' ') { allBlank = false; break; }
            }

            if (!allBlank)
            {
                // Queued rather than drawn here; FlushText writes them all through
                // one device context at the end of the frame.
                TextRun run = new TextRun();
                run.X = x;
                run.Y = y + _baselineOffset;
                run.Text = text;
                run.Font = font;
                run.Colour = fore;
                _pendingText.Add(run);
            }

            int runWidth = cellSpan * _cellWidth;

            if ((flags & CellFlags.Underline) != 0)
            {
                g.DrawLine(GetPen(fore), x, y + _cellHeight - 2, x + runWidth, y + _cellHeight - 2);
            }
            if ((flags & CellFlags.DoubleUnderline) != 0)
            {
                Pen p = GetPen(fore);
                g.DrawLine(p, x, y + _cellHeight - 3, x + runWidth, y + _cellHeight - 3);
                g.DrawLine(p, x, y + _cellHeight - 1, x + runWidth, y + _cellHeight - 1);
            }
            if ((flags & CellFlags.Strikethrough) != 0)
            {
                g.DrawLine(GetPen(fore), x, y + _cellHeight / 2, x + runWidth, y + _cellHeight / 2);
            }
        }

        private Font FontFor(CellFlags flags)
        {
            bool bold = (flags & CellFlags.Bold) != 0;
            bool italic = (flags & CellFlags.Italic) != 0;
            if (bold && italic) return _boldItalicFont;
            if (bold) return _boldFont;
            if (italic) return _italicFont;
            return _font;
        }

        private void ResolveAt(Line line, int abs, int col, bool reversed, out Color fore, out Color back)
        {
            Cell cell = line.Cells[col];
            _palette.Resolve(cell, reversed, out fore, out back);

            if (_hasSelection && IsSelected(abs, col))
            {
                back = _palette.SelectionBackground;
                if (!_palette.SelectionForeground.IsEmpty) fore = _palette.SelectionForeground;
                else if (ContrastTooLow(fore, back)) fore = PickReadable(back);
            }
        }

        private static bool ContrastTooLow(Color fore, Color back)
        {
            return Math.Abs(TerminalPalette.Luminance(fore) - TerminalPalette.Luminance(back)) < 0.25;
        }

        private static Color PickReadable(Color background)
        {
            return TerminalPalette.Luminance(background) > 0.5 ? Color.Black : Color.White;
        }

        private void RenderCursor(Graphics g, bool reversed)
        {
            int cx = _term.CursorX;
            int cy = _term.CursorY;
            if (cx < 0 || cy < 0 || cy >= _term.Rows) return;

            int x = cx * _cellWidth;
            int y = cy * _cellHeight;

            if (!_hostFocused)
            {
                // Unfocused terminals show a hollow box, the xterm convention, so it
                // is obvious at a glance which pane has the keyboard.
                g.DrawRectangle(GetPen(_palette.CursorColor), x, y, _cellWidth - 1, _cellHeight - 1);
                return;
            }

            g.FillRectangle(GetBrush(_palette.CursorColor), x, y, _cellWidth, _cellHeight);

            Cell cell = _term.Screen.GetCell(cy, cx);
            char ch = cell.Ch == '\0' ? ' ' : cell.Ch;
            if (ch != ' ')
            {
                TextRun run = new TextRun();
                run.X = x;
                run.Y = y + _baselineOffset;
                run.Text = ch.ToString();
                run.Font = FontFor(cell.Flags);
                run.Colour = _palette.CursorTextColor;
                _pendingText.Add(run);
                FlushText(g);
            }
        }

        // =====================================================================
        // Focus
        // =====================================================================

        protected override void OnGotFocus(EventArgs e)
        {
            base.OnGotFocus(e);
            _hostFocused = true;
            _cursorOn = true;
            bool report;
            lock (_sync) { report = _term.FocusReporting; }
            if (report) RaiseInput("\x1b[I");
            InvalidateCursorRow();
        }

        protected override void OnLostFocus(EventArgs e)
        {
            base.OnLostFocus(e);
            _hostFocused = false;
            bool report;
            lock (_sync) { report = _term.FocusReporting; }
            if (report) RaiseInput("\x1b[O");
            InvalidateCursorRow();
        }

        // =====================================================================
        // Keyboard
        // =====================================================================

        protected override bool IsInputKey(System.Windows.Forms.Keys keyData)
        {
            // Claim the navigation and tab keys; without this WinForms would consume
            // them for focus traversal and they would never reach the device.
            return true;
        }

        protected override bool ProcessDialogKey(System.Windows.Forms.Keys keyData)
        {
            // Same reason: Escape and Tab must not be treated as dialog keys.
            return false;
        }

        private static TermModifiers CurrentModifiers()
        {
            TermModifiers m = TermModifiers.None;
            System.Windows.Forms.Keys mod = Control.ModifierKeys;
            if ((mod & System.Windows.Forms.Keys.Shift) != 0) m |= TermModifiers.Shift;
            if ((mod & System.Windows.Forms.Keys.Control) != 0) m |= TermModifiers.Control;
            if ((mod & System.Windows.Forms.Keys.Alt) != 0) m |= TermModifiers.Alt;
            return m;
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            base.OnKeyDown(e);

            TermModifiers mods = CurrentModifiers();

            // Local editing shortcuts, claimed before the device sees them.
            if ((mods & TermModifiers.Control) != 0 && (mods & TermModifiers.Shift) != 0)
            {
                switch (e.KeyCode)
                {
                    case System.Windows.Forms.Keys.C: CopySelection(); e.Handled = true; e.SuppressKeyPress = true; return;
                    case System.Windows.Forms.Keys.V: PasteClipboard(); e.Handled = true; e.SuppressKeyPress = true; return;
                }
            }

            if ((mods & TermModifiers.Shift) != 0)
            {
                if (e.KeyCode == System.Windows.Forms.Keys.PageUp)
                {
                    ScrollLines(_term.Rows - 1); e.Handled = true; e.SuppressKeyPress = true; return;
                }
                if (e.KeyCode == System.Windows.Forms.Keys.PageDown)
                {
                    ScrollLines(-(_term.Rows - 1)); e.Handled = true; e.SuppressKeyPress = true; return;
                }
                if (e.KeyCode == System.Windows.Forms.Keys.Insert)
                {
                    PasteClipboard(); e.Handled = true; e.SuppressKeyPress = true; return;
                }
            }

            TermKey key = MapKey(e.KeyCode);
            char ch = '\0';
            if (key == TermKey.None)
            {
                // A plain character is handled in OnKeyPress. Ctrl+key and Alt+key are
                // not: Windows delivers little or nothing useful for them there, so the
                // key code is translated here instead.
                ch = ModifiedKeyChar(e.KeyCode, mods);
                if (ch == '\0') return;
                key = ch == ' ' ? TermKey.Space : TermKey.Char;
            }

            bool appCursor, appKeypad;
            lock (_sync)
            {
                appCursor = _term.ApplicationCursorKeys;
                appKeypad = _term.ApplicationKeypad;
            }

            string seq = _keys.Encode(key, ch, mods, appCursor, appKeypad);
            if (seq != null)
            {
                ScrollToBottom();
                RaiseInput(seq);
                e.Handled = true;
                e.SuppressKeyPress = true;
            }
        }

        protected override void OnKeyPress(KeyPressEventArgs e)
        {
            base.OnKeyPress(e);

            char ch = e.KeyChar;
            TermModifiers mods = CurrentModifiers();

            bool ctrl = (mods & TermModifiers.Control) != 0;
            bool alt = (mods & TermModifiers.Alt) != 0;

            // Ctrl+letter and the Ctrl+digit codes were sent from OnKeyDown, which
            // suppresses this event. What can still arrive with Ctrl held is Ctrl plus
            // punctuation - Ctrl+[, Ctrl+], Ctrl+\ - which the keyboard layout has
            // already translated into the matching control character.
            if (ctrl && !alt && ch < 0x20)
            {
                bool cursorKeys, keypad;
                lock (_sync)
                {
                    cursorKeys = _term.ApplicationCursorKeys;
                    keypad = _term.ApplicationKeypad;
                }
                string control = _keys.Encode(TermKey.Char, ch, TermModifiers.None, cursorKeys, keypad);
                if (control != null)
                {
                    ScrollToBottom();
                    RaiseInput(control);
                }
                e.Handled = true;
                return;
            }

            // Enter, Tab, Escape and Backspace are keys, not characters, and were sent
            // from OnKeyDown.
            if (ch == '\r' || ch == '\n' || ch == '\t' || ch == '\x1b' || ch == '\b') { e.Handled = true; return; }

            bool appCursor, appKeypad;
            lock (_sync)
            {
                appCursor = _term.ApplicationCursorKeys;
                appKeypad = _term.ApplicationKeypad;
            }

            // Ctrl and Alt together is how Windows reports AltGr, which produces an
            // ordinary character on many layouts (@ { [ ] \ on a German keyboard), so
            // it must go through unmodified. Alt on its own keeps its meta meaning.
            TermModifiers passMods = mods & ~TermModifiers.Control;
            if (ctrl) passMods &= ~TermModifiers.Alt;
            string seq = _keys.Encode(TermKey.Char, ch, passMods, appCursor, appKeypad);
            if (seq != null)
            {
                ScrollToBottom();
                RaiseInput(seq);
            }
            e.Handled = true;
        }

        /// <summary>
        /// The character a key stands for when Ctrl or Alt is held, or NUL when the key
        /// should be left to OnKeyPress. Only letters, digits and Space are translated;
        /// punctuation depends on the keyboard layout and arrives in OnKeyPress already
        /// translated by Windows.
        /// </summary>
        public static char ModifiedKeyChar(System.Windows.Forms.Keys keyCode, TermModifiers mods)
        {
            bool ctrl = (mods & TermModifiers.Control) != 0;
            bool alt = (mods & TermModifiers.Alt) != 0;
            bool shift = (mods & TermModifiers.Shift) != 0;

            // Exactly one of the two: Ctrl+Alt is AltGr and produces characters.
            if (ctrl == alt) return '\0';

            if (keyCode >= System.Windows.Forms.Keys.A && keyCode <= System.Windows.Forms.Keys.Z)
            {
                char letter = (char)('a' + (keyCode - System.Windows.Forms.Keys.A));
                // Ctrl+letter is the same code either way; Alt+Shift+letter is a capital.
                return (shift && alt) ? char.ToUpperInvariant(letter) : letter;
            }

            // Ctrl+Space is NUL. Alt+Space belongs to the window's system menu.
            if (keyCode == System.Windows.Forms.Keys.Space) return ctrl ? ' ' : '\0';

            if (keyCode >= System.Windows.Forms.Keys.D0 && keyCode <= System.Windows.Forms.Keys.D9 && !shift)
            {
                char digit = (char)('0' + (keyCode - System.Windows.Forms.Keys.D0));
                // Ctrl+2..8 are the classic NUL, ESC, FS, GS, RS and US codes; the other
                // digits have no control code, so Ctrl leaves them alone.
                if (ctrl && (digit < '2' || digit > '8')) return '\0';
                return digit;
            }

            return '\0';
        }

        private static TermKey MapKey(System.Windows.Forms.Keys k)
        {
            switch (k)
            {
                case System.Windows.Forms.Keys.Up: return TermKey.Up;
                case System.Windows.Forms.Keys.Down: return TermKey.Down;
                case System.Windows.Forms.Keys.Left: return TermKey.Left;
                case System.Windows.Forms.Keys.Right: return TermKey.Right;
                case System.Windows.Forms.Keys.Home: return TermKey.Home;
                case System.Windows.Forms.Keys.End: return TermKey.End;
                case System.Windows.Forms.Keys.Insert: return TermKey.Insert;
                case System.Windows.Forms.Keys.Delete: return TermKey.Delete;
                case System.Windows.Forms.Keys.PageUp: return TermKey.PageUp;
                case System.Windows.Forms.Keys.PageDown: return TermKey.PageDown;
                case System.Windows.Forms.Keys.Back: return TermKey.Backspace;
                case System.Windows.Forms.Keys.Tab: return TermKey.Tab;
                case System.Windows.Forms.Keys.Return: return TermKey.Enter;
                case System.Windows.Forms.Keys.Escape: return TermKey.Escape;
                case System.Windows.Forms.Keys.F1: return TermKey.F1;
                case System.Windows.Forms.Keys.F2: return TermKey.F2;
                case System.Windows.Forms.Keys.F3: return TermKey.F3;
                case System.Windows.Forms.Keys.F4: return TermKey.F4;
                case System.Windows.Forms.Keys.F5: return TermKey.F5;
                case System.Windows.Forms.Keys.F6: return TermKey.F6;
                case System.Windows.Forms.Keys.F7: return TermKey.F7;
                case System.Windows.Forms.Keys.F8: return TermKey.F8;
                case System.Windows.Forms.Keys.F9: return TermKey.F9;
                case System.Windows.Forms.Keys.F10: return TermKey.F10;
                case System.Windows.Forms.Keys.F11: return TermKey.F11;
                case System.Windows.Forms.Keys.F12: return TermKey.F12;
                case System.Windows.Forms.Keys.NumPad0: return TermKey.Keypad0;
                case System.Windows.Forms.Keys.NumPad1: return TermKey.Keypad1;
                case System.Windows.Forms.Keys.NumPad2: return TermKey.Keypad2;
                case System.Windows.Forms.Keys.NumPad3: return TermKey.Keypad3;
                case System.Windows.Forms.Keys.NumPad4: return TermKey.Keypad4;
                case System.Windows.Forms.Keys.NumPad5: return TermKey.Keypad5;
                case System.Windows.Forms.Keys.NumPad6: return TermKey.Keypad6;
                case System.Windows.Forms.Keys.NumPad7: return TermKey.Keypad7;
                case System.Windows.Forms.Keys.NumPad8: return TermKey.Keypad8;
                case System.Windows.Forms.Keys.NumPad9: return TermKey.Keypad9;
                case System.Windows.Forms.Keys.Multiply: return TermKey.KeypadStar;
                case System.Windows.Forms.Keys.Add: return TermKey.KeypadPlus;
                case System.Windows.Forms.Keys.Subtract: return TermKey.KeypadMinus;
                case System.Windows.Forms.Keys.Divide: return TermKey.KeypadSlash;
                case System.Windows.Forms.Keys.Decimal: return TermKey.KeypadDot;
                default: return TermKey.None;
            }
        }

        // =====================================================================
        // Mouse and selection
        // =====================================================================

        private bool TryHitTest(Point p, out int col, out int row)
        {
            col = _cellWidth > 0 ? p.X / _cellWidth : 0;
            row = _cellHeight > 0 ? p.Y / _cellHeight : 0;
            if (col < 0) col = 0;
            if (row < 0) row = 0;
            if (col >= _term.Cols) col = _term.Cols - 1;
            if (row >= _term.Rows) row = _term.Rows - 1;
            return true;
        }

        private int AbsRowFor(int screenRow)
        {
            int history;
            lock (_sync) { history = _term.IsAlternateScreen ? 0 : _term.Primary.HistoryCount; }
            return history - _scrollOffset + screenRow;
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            Focus();

            int col, row;
            TryHitTest(e.Location, out col, out row);

            bool mouseReported;
            lock (_sync) { mouseReported = _term.Mouse != MouseMode.Off; }

            // Shift always forces local selection, so text stays selectable even in
            // full-screen applications that grab the mouse.
            bool forceLocal = (Control.ModifierKeys & System.Windows.Forms.Keys.Shift) != 0;

            if (mouseReported && !forceLocal)
            {
                int button = e.Button == MouseButtons.Left ? 0 : e.Button == MouseButtons.Middle ? 1 : 2;
                RaiseInput(KeyEncoder.EncodeMouse(_term.Mouse, _term.MouseEncode, button, true,
                                                  col, row, CurrentModifiers()));
                return;
            }

            if (e.Button == MouseButtons.Middle)
            {
                PasteClipboard();
                return;
            }

            if (e.Button == MouseButtons.Left)
            {
                _selecting = true;
                _rectangularSelection = (Control.ModifierKeys & System.Windows.Forms.Keys.Alt) != 0;
                _selAnchorAbs = AbsRowFor(row);
                _selAnchorCol = col;
                _selEndAbs = _selAnchorAbs;
                _selEndCol = col;
                _hasSelection = false;
                InvalidateAll();
            }
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);

            if (!_selecting)
            {
                bool motionReported;
                lock (_sync) { motionReported = _term.Mouse == MouseMode.AnyMotion; }
                if (motionReported)
                {
                    int c2, r2;
                    TryHitTest(e.Location, out c2, out r2);
                    RaiseInput(KeyEncoder.EncodeMouse(_term.Mouse, _term.MouseEncode, 32, true,
                                                      c2, r2, CurrentModifiers()));
                }
                return;
            }

            int col, row;
            TryHitTest(e.Location, out col, out row);

            // Dragging past the top or bottom edge scrolls the view.
            if (e.Y < 0) ScrollLines(1);
            else if (e.Y > ClientSize.Height) ScrollLines(-1);

            _selEndAbs = AbsRowFor(row);
            _selEndCol = col;
            _hasSelection = (_selEndAbs != _selAnchorAbs || _selEndCol != _selAnchorCol);
            InvalidateAll();
        }

        protected override void OnMouseUp(MouseEventArgs e)
        {
            base.OnMouseUp(e);

            bool mouseReported;
            lock (_sync) { mouseReported = _term.Mouse != MouseMode.Off; }
            bool forceLocal = (Control.ModifierKeys & System.Windows.Forms.Keys.Shift) != 0;

            if (mouseReported && !forceLocal && !_selecting)
            {
                int col, row;
                TryHitTest(e.Location, out col, out row);
                int button = e.Button == MouseButtons.Left ? 0 : e.Button == MouseButtons.Middle ? 1 : 2;
                RaiseInput(KeyEncoder.EncodeMouse(_term.Mouse, _term.MouseEncode, button, false,
                                                  col, row, CurrentModifiers()));
                return;
            }

            if (_selecting)
            {
                _selecting = false;
                // Copy-on-select: the behaviour PuTTY and xterm users expect. The
                // clipboard is only touched when a real span was dragged.
                if (_hasSelection && CopyOnSelect) CopySelection();
            }
        }

        protected override void OnMouseDoubleClick(MouseEventArgs e)
        {
            base.OnMouseDoubleClick(e);
            if (e.Button != MouseButtons.Left) return;

            int col, row;
            TryHitTest(e.Location, out col, out row);
            SelectWordAt(AbsRowFor(row), col);
        }

        /// <summary>Copy text to the clipboard as soon as a selection is made.</summary>
        public bool CopyOnSelect = true;

        /// <summary>Characters treated as part of a word for double-click selection.</summary>
        public string WordCharacters = "_-.:/\\~?=&%+@#";

        private bool IsWordChar(char c)
        {
            return char.IsLetterOrDigit(c) || WordCharacters.IndexOf(c) >= 0;
        }

        private void SelectWordAt(int abs, int col)
        {
            lock (_sync)
            {
                ScreenBuffer screen = _term.Screen;
                if (abs < 0 || abs >= screen.TotalLines) return;
                Line line = screen.GetAbsolute(abs);
                if (col < 0 || col >= line.Cells.Length) return;
                if (!IsWordChar(line.Cells[col].Ch)) return;

                int start = col, end = col;
                while (start > 0 && IsWordChar(line.Cells[start - 1].Ch)) start--;
                while (end + 1 < line.Cells.Length && IsWordChar(line.Cells[end + 1].Ch)) end++;

                _selAnchorAbs = abs; _selAnchorCol = start;
                _selEndAbs = abs; _selEndCol = end + 1;
                _rectangularSelection = false;
                _hasSelection = true;
            }
            if (CopyOnSelect) CopySelection();
            InvalidateAll();
        }

        private bool IsSelected(int abs, int col)
        {
            int startAbs = _selAnchorAbs, startCol = _selAnchorCol;
            int endAbs = _selEndAbs, endCol = _selEndCol;

            if (startAbs > endAbs || (startAbs == endAbs && startCol > endCol))
            {
                int t = startAbs; startAbs = endAbs; endAbs = t;
                t = startCol; startCol = endCol; endCol = t;
            }

            if (abs < startAbs || abs > endAbs) return false;

            if (_rectangularSelection)
            {
                int lo = Math.Min(startCol, endCol);
                int hi = Math.Max(startCol, endCol);
                return col >= lo && col < hi;
            }

            if (abs == startAbs && abs == endAbs) return col >= startCol && col < endCol;
            if (abs == startAbs) return col >= startCol;
            if (abs == endAbs) return col < endCol;
            return true;
        }

        public void ClearSelection()
        {
            if (!_hasSelection) return;
            _hasSelection = false;
            InvalidateAll();
        }

        public void SelectAll()
        {
            lock (_sync)
            {
                ScreenBuffer screen = _term.Screen;
                _selAnchorAbs = 0; _selAnchorCol = 0;
                _selEndAbs = screen.TotalLines - 1;
                _selEndCol = screen.Cols;
                _rectangularSelection = false;
                _hasSelection = true;
            }
            InvalidateAll();
        }

        public string GetSelectedText()
        {
            if (!_hasSelection) return string.Empty;
            lock (_sync)
            {
                return _term.Screen.GetText(_selAnchorAbs, _selAnchorCol,
                                            _selEndAbs, _selEndCol, _rectangularSelection);
            }
        }

        public void CopySelection()
        {
            string text = GetSelectedText();
            if (string.IsNullOrEmpty(text)) return;
            try { Clipboard.SetText(text); }
            catch (System.Runtime.InteropServices.ExternalException)
            {
                // Another process had the clipboard open. Nothing useful to do.
            }
        }

        public void PasteClipboard()
        {
            string text;
            try
            {
                if (!Clipboard.ContainsText()) return;
                text = Clipboard.GetText();
            }
            catch (System.Runtime.InteropServices.ExternalException) { return; }

            if (string.IsNullOrEmpty(text)) return;
            PasteText(text);
        }

        public void PasteText(string text)
        {
            // Normalise line endings: a device expects CR, not the CRLF that comes
            // off the Windows clipboard, and a stray LF would double-space input.
            text = text.Replace("\r\n", "\r").Replace("\n", "\r");

            // Anything else that is a control character has no business in pasted
            // text. The one that matters is ESC: a clipboard carrying ESC[201~ would
            // end a bracketed paste early and let the rest run as typed commands.
            text = StripPasteControls(text);
            if (text.Length == 0) return;

            bool bracketed;
            lock (_sync) { bracketed = _term.BracketedPaste; }

            // A pasted line break is an Enter keypress. Bracketed paste lets the remote
            // application hold the text back; without it every line runs immediately,
            // so give the operator the chance to say no.
            if (!bracketed)
            {
                int lines = 1;
                foreach (char c in text) { if (c == '\r') lines++; }
                if (text[text.Length - 1] == '\r') lines--;

                EventHandler<TerminalPasteEventArgs> confirm = PasteRequested;
                if (lines > 1 && confirm != null)
                {
                    TerminalPasteEventArgs args = new TerminalPasteEventArgs(text, lines);
                    confirm(this, args);
                    if (args.Cancel) return;
                }
            }

            ScrollToBottom();

            if (bracketed)
            {
                // Bracketed paste lets the remote application tell pasted text from
                // typed text, which is what stops editors auto-indenting a paste.
                RaiseInput("\x1b[200~" + text + "\x1b[201~");
            }
            else
            {
                RaiseInput(text);
            }
        }

        /// <summary>Remove control characters other than Tab and CR from pasted text.</summary>
        public static string StripPasteControls(string text)
        {
            StringBuilder sb = null;
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                bool drop = (c < 0x20 && c != '\t' && c != '\r') || c == 0x7f || (c >= 0x80 && c < 0xa0);
                if (drop)
                {
                    if (sb == null) sb = new StringBuilder(text, 0, i, text.Length);
                }
                else if (sb != null)
                {
                    sb.Append(c);
                }
            }
            return sb == null ? text : sb.ToString();
        }

        // =====================================================================
        // Search
        // =====================================================================

        /// <summary>
        /// Find text in the scrollback, searching upward from the current view.
        /// Returns the absolute line number, or -1.
        /// </summary>
        public int FindInScrollback(string needle, int fromAbs, bool forward, bool matchCase)
        {
            if (string.IsNullOrEmpty(needle)) return -1;
            StringComparison cmp = matchCase ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;

            lock (_sync)
            {
                ScreenBuffer screen = _term.Screen;
                int total = screen.TotalLines;
                if (total == 0) return -1;

                int step = forward ? 1 : -1;
                int abs = fromAbs;
                for (int n = 0; n < total; n++)
                {
                    abs += step;
                    if (abs < 0) abs = total - 1;
                    if (abs >= total) abs = 0;

                    if (screen.GetLineText(abs).IndexOf(needle, cmp) >= 0) return abs;
                }
            }
            return -1;
        }

        /// <summary>Scroll so that the given absolute line is visible.</summary>
        public void ScrollToLine(int abs)
        {
            int history, rows;
            lock (_sync)
            {
                history = _term.IsAlternateScreen ? 0 : _term.Primary.HistoryCount;
                rows = _term.Rows;
            }
            int desiredOffset = history - abs + rows / 2;
            if (desiredOffset < 0) desiredOffset = 0;
            if (desiredOffset > history) desiredOffset = history;
            _scrollOffset = desiredOffset;
            UpdateScrollBar();
            InvalidateAll();
        }

        // =====================================================================
        // Cleanup
        // =====================================================================

        private void DisposeFonts()
        {
            // The GDI handles were made from these fonts and must go with them.
            DisposeFontHandles();

            if (_boldFont != null) { _boldFont.Dispose(); _boldFont = null; }
            if (_italicFont != null) { _italicFont.Dispose(); _italicFont = null; }
            if (_boldItalicFont != null) { _boldItalicFont.Dispose(); _boldItalicFont = null; }
            if (_font != null) { _font.Dispose(); _font = null; }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_renderTimer != null) { _renderTimer.Stop(); _renderTimer.Dispose(); }
                if (_blinkTimer != null) { _blinkTimer.Stop(); _blinkTimer.Dispose(); }
                DisposeBackBuffer();
                DisposeFonts();
                DisposeCaches();
            }
            base.Dispose(disposing);
        }
    }
}
