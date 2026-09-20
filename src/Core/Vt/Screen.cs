// PSTerm - Screen.cs
// The cell grid, scrollback ring and damage tracking.
// C# 5 only - see Cell.cs for why.

using System;
using System.Text;

namespace PSTerm.Vt
{
    /// <summary>One row of cells. Lines are reference types so that scrolling
    /// rotates references instead of copying cell data.</summary>
    public sealed class Line
    {
        public Cell[] Cells;
        /// <summary>True when the line was filled to the right margin and the next
        /// line is a logical continuation. Used for selection and copy.</summary>
        public bool Wrapped;

        public Line(int cols, Cell fill)
        {
            Cells = new Cell[cols];
            for (int i = 0; i < cols; i++) Cells[i] = fill;
            Wrapped = false;
        }

        public void Fill(Cell fill)
        {
            for (int i = 0; i < Cells.Length; i++) Cells[i] = fill;
            Wrapped = false;
        }

        public void Fill(int from, int toExclusive, Cell fill)
        {
            if (from < 0) from = 0;
            if (toExclusive > Cells.Length) toExclusive = Cells.Length;
            for (int i = from; i < toExclusive; i++) Cells[i] = fill;
        }

        /// <summary>Resize without reflow: keep what fits, pad the rest.</summary>
        public void Resize(int cols, Cell fill)
        {
            if (Cells.Length == cols) return;
            Cell[] next = new Cell[cols];
            int copy = Math.Min(cols, Cells.Length);
            Array.Copy(Cells, next, copy);
            for (int i = copy; i < cols; i++) next[i] = fill;
            Cells = next;
            if (cols < Cells.Length) Wrapped = false;
        }

        /// <summary>Index one past the last non-blank cell, for trimming on copy.</summary>
        public int TrimmedLength()
        {
            int n = Cells.Length;
            while (n > 0)
            {
                Cell c = Cells[n - 1];
                if (c.Ch != ' ' && c.Ch != '\0') break;
                // A cell with a non-default background is visually meaningful; keep it.
                if (!c.Bg.IsDefault) break;
                n--;
            }
            return n;
        }
    }

    /// <summary>
    /// A grid of <see cref="Rows"/> visible lines plus (optionally) scrollback history,
    /// stored in a ring buffer. The visible screen is always the last <see cref="Rows"/>
    /// entries of the ring.
    /// </summary>
    public sealed class ScreenBuffer
    {
        private Line[] _ring;
        private int _start;      // ring index of the oldest line
        private int _count;      // number of live lines (history + visible)
        private int _cols;
        private int _rows;
        private readonly int _scrollbackMax;

        private bool[] _dirty;
        private bool _allDirty;

        public int CursorX;
        public int CursorY;

        public ScreenBuffer(int cols, int rows, int scrollbackMax)
        {
            if (cols < 1) cols = 1;
            if (rows < 1) rows = 1;
            if (scrollbackMax < 0) scrollbackMax = 0;

            _cols = cols;
            _rows = rows;
            _scrollbackMax = scrollbackMax;

            _ring = new Line[rows + scrollbackMax];
            _start = 0;
            _count = rows;
            for (int i = 0; i < rows; i++) _ring[i] = new Line(cols, Cell.Empty);

            _dirty = new bool[rows];
            _allDirty = true;
        }

        public int Cols { get { return _cols; } }
        public int Rows { get { return _rows; } }
        /// <summary>Number of lines scrolled off the top and still retained.</summary>
        public int HistoryCount { get { return _count - _rows; } }
        public int TotalLines { get { return _count; } }

        // ---- damage -------------------------------------------------------

        public bool AllDirty { get { return _allDirty; } }

        public void MarkDirty(int row)
        {
            if (row >= 0 && row < _rows) _dirty[row] = true;
        }

        public void MarkDirty(int fromRow, int toRowInclusive)
        {
            if (fromRow < 0) fromRow = 0;
            if (toRowInclusive >= _rows) toRowInclusive = _rows - 1;
            for (int r = fromRow; r <= toRowInclusive; r++) _dirty[r] = true;
        }

        public void MarkAllDirty() { _allDirty = true; }

        public bool IsDirty(int row)
        {
            if (_allDirty) return true;
            return row >= 0 && row < _rows && _dirty[row];
        }

        public void ClearDamage()
        {
            _allDirty = false;
            Array.Clear(_dirty, 0, _dirty.Length);
        }

        // ---- line access --------------------------------------------------

        private int RingIndex(int absolute)
        {
            return (_start + absolute) % _ring.Length;
        }

        /// <summary>Line by absolute index: 0 is the oldest retained history line.</summary>
        public Line GetAbsolute(int absolute)
        {
            if (absolute < 0) absolute = 0;
            if (absolute >= _count) absolute = _count - 1;
            return _ring[RingIndex(absolute)];
        }

        /// <summary>Line by visible screen row, 0 being the top of the viewport.</summary>
        public Line GetRow(int row)
        {
            if (row < 0) row = 0;
            if (row >= _rows) row = _rows - 1;
            return _ring[RingIndex(HistoryCount + row)];
        }

        public Cell GetCell(int row, int col)
        {
            Line line = GetRow(row);
            if (col < 0 || col >= line.Cells.Length) return Cell.Empty;
            return line.Cells[col];
        }

        public void SetCell(int row, int col, Cell cell)
        {
            if (row < 0 || row >= _rows || col < 0 || col >= _cols) return;
            GetRow(row).Cells[col] = cell;
            MarkDirty(row);
        }

        // ---- scrolling ----------------------------------------------------

        private void PushHistory(Line line)
        {
            if (_scrollbackMax == 0) return;
            if (_count < _ring.Length)
            {
                // Ring has room: the caller appends at the end, nothing to evict.
                return;
            }
            // Full: the oldest line is dropped by advancing _start.
            _start = (_start + 1) % _ring.Length;
            _count--;
        }

        /// <summary>
        /// Scroll the region [top,bottom] up by n lines. When the region is the whole
        /// screen the displaced lines enter the scrollback.
        /// </summary>
        public void ScrollUp(int top, int bottom, int n, Cell blank)
        {
            if (n <= 0) return;
            if (top < 0) top = 0;
            if (bottom >= _rows) bottom = _rows - 1;
            if (top > bottom) return;

            int regionHeight = bottom - top + 1;
            if (n >= regionHeight)
            {
                // Everything in the region is replaced by blanks.
                if (top == 0 && bottom == _rows - 1) { for (int i = 0; i < regionHeight; i++) ScrollWholeScreenUp(blank); }
                else { for (int r = top; r <= bottom; r++) GetRow(r).Fill(blank); }
                MarkDirty(top, bottom);
                return;
            }

            if (top == 0 && bottom == _rows - 1 && _scrollbackMax > 0)
            {
                for (int i = 0; i < n; i++) ScrollWholeScreenUp(blank);
                MarkAllDirty();
                return;
            }

            // Rotate line references inside the region.
            Line[] saved = new Line[n];
            for (int i = 0; i < n; i++) saved[i] = GetRow(top + i);
            for (int r = top; r + n <= bottom; r++)
                SetRowRef(r, GetRow(r + n));
            for (int i = 0; i < n; i++)
            {
                Line reused = saved[i];
                reused.Fill(blank);
                SetRowRef(bottom - n + 1 + i, reused);
            }
            MarkDirty(top, bottom);
        }

        /// <summary>Scroll the full screen up by one, retiring the top line into history.</summary>
        private void ScrollWholeScreenUp(Cell blank)
        {
            Line recycled;
            if (_count < _ring.Length)
            {
                // Ring still has spare slots: append a fresh line at the bottom.
                recycled = new Line(_cols, blank);
                _ring[RingIndex(_count)] = recycled;
                _count++;
            }
            else
            {
                // Ring is full: the oldest history line is evicted and reused as the
                // new bottom line. No allocation in steady state.
                recycled = _ring[_start];
                _start = (_start + 1) % _ring.Length;
                recycled.Fill(blank);
                recycled.Resize(_cols, blank);
                _ring[RingIndex(_count - 1)] = recycled;
            }
        }

        private void SetRowRef(int row, Line line)
        {
            _ring[RingIndex(HistoryCount + row)] = line;
        }

        /// <summary>Scroll the region [top,bottom] down by n lines (reverse index / IL).</summary>
        public void ScrollDown(int top, int bottom, int n, Cell blank)
        {
            if (n <= 0) return;
            if (top < 0) top = 0;
            if (bottom >= _rows) bottom = _rows - 1;
            if (top > bottom) return;

            int regionHeight = bottom - top + 1;
            if (n >= regionHeight)
            {
                for (int r = top; r <= bottom; r++) GetRow(r).Fill(blank);
                MarkDirty(top, bottom);
                return;
            }

            Line[] saved = new Line[n];
            for (int i = 0; i < n; i++) saved[i] = GetRow(bottom - n + 1 + i);
            for (int r = bottom; r - n >= top; r--)
                SetRowRef(r, GetRow(r - n));
            for (int i = 0; i < n; i++)
            {
                Line reused = saved[i];
                reused.Fill(blank);
                SetRowRef(top + i, reused);
            }
            MarkDirty(top, bottom);
        }

        // ---- resize -------------------------------------------------------

        /// <summary>
        /// Resize the grid. Lines are truncated or padded but not reflowed, matching
        /// xterm/PuTTY behaviour; reflow would re-wrap device output that was laid out
        /// for a fixed width, which is worse for console work than leaving it alone.
        /// Returns the number of lines the cursor was pushed by.
        /// </summary>
        public int Resize(int cols, int rows, Cell blank)
        {
            if (cols < 1) cols = 1;
            if (rows < 1) rows = 1;
            if (cols == _cols && rows == _rows) return 0;

            int cursorShift = 0;

            if (cols != _cols)
            {
                for (int i = 0; i < _count; i++)
                    _ring[RingIndex(i)].Resize(cols, blank);
                _cols = cols;
            }

            if (rows != _rows)
            {
                int newCapacity = rows + _scrollbackMax;
                Line[] next = new Line[newCapacity];

                if (rows > _rows)
                {
                    // Growing: pull lines back out of history if we have any, else add blanks
                    // at the bottom. Pulling from history is what users expect when they
                    // enlarge the window after output has scrolled past.
                    int grow = rows - _rows;
                    int fromHistory = Math.Min(grow, HistoryCount);
                    cursorShift = fromHistory;
                    int needNew = grow - fromHistory;
                    for (int i = 0; i < needNew; i++)
                    {
                        if (_count < _ring.Length)
                        {
                            _ring[RingIndex(_count)] = new Line(cols, blank);
                            _count++;
                        }
                    }
                }
                else
                {
                    // Shrinking: the top lines of the viewport move into history.
                    int shrink = _rows - rows;
                    cursorShift = -shrink;
                }

                // Compact the ring into the new array, dropping the oldest lines that
                // no longer fit within scrollback + rows.
                int keep = Math.Min(_count, newCapacity);
                int skip = _count - keep;
                for (int i = 0; i < keep; i++)
                    next[i] = _ring[RingIndex(skip + i)];
                for (int i = keep; i < newCapacity; i++)
                    next[i] = null;

                _ring = next;
                _start = 0;
                _count = keep;
                _rows = rows;

                // Guarantee at least `rows` live lines.
                while (_count < _rows)
                {
                    _ring[_count] = new Line(cols, blank);
                    _count++;
                }

                _dirty = new bool[rows];
            }

            if (CursorY >= _rows) CursorY = _rows - 1;
            if (CursorX >= _cols) CursorX = _cols - 1;
            if (CursorY < 0) CursorY = 0;
            if (CursorX < 0) CursorX = 0;

            MarkAllDirty();
            return cursorShift;
        }

        // ---- text extraction ----------------------------------------------

        /// <summary>
        /// Extract plain text between two absolute positions, honouring soft-wrap so a
        /// wrapped command line copies back as one logical line.
        /// </summary>
        public string GetText(int startAbs, int startCol, int endAbs, int endCol, bool rectangular)
        {
            if (startAbs > endAbs || (startAbs == endAbs && startCol > endCol))
            {
                int t = startAbs; startAbs = endAbs; endAbs = t;
                t = startCol; startCol = endCol; endCol = t;
            }

            StringBuilder sb = new StringBuilder();
            for (int abs = startAbs; abs <= endAbs && abs < _count; abs++)
            {
                Line line = GetAbsolute(abs);
                int from, to;

                if (rectangular)
                {
                    from = Math.Min(startCol, endCol);
                    to = Math.Max(startCol, endCol);
                }
                else
                {
                    from = (abs == startAbs) ? startCol : 0;
                    to = (abs == endAbs) ? endCol : line.Cells.Length;
                }

                if (from < 0) from = 0;
                if (to > line.Cells.Length) to = line.Cells.Length;

                // Trim trailing blanks on full-line spans so copied blocks are not padded.
                int limit = to;
                if (!rectangular && abs != endAbs)
                {
                    int trimmed = line.TrimmedLength();
                    if (trimmed < limit) limit = trimmed;
                }

                for (int c = from; c < limit; c++)
                {
                    Cell cell = line.Cells[c];
                    if ((cell.Flags & CellFlags.WideTrail) != 0) continue;
                    sb.Append(cell.Ch == '\0' ? ' ' : cell.Ch);
                }

                bool last = (abs == endAbs);
                if (!last && !(line.Wrapped && !rectangular))
                    sb.Append("\r\n");
            }
            return sb.ToString();
        }

        /// <summary>Plain text of one absolute line, used by the logger and by search.</summary>
        public string GetLineText(int absolute)
        {
            Line line = GetAbsolute(absolute);
            int n = line.TrimmedLength();
            StringBuilder sb = new StringBuilder(n);
            for (int c = 0; c < n; c++)
            {
                Cell cell = line.Cells[c];
                if ((cell.Flags & CellFlags.WideTrail) != 0) continue;
                sb.Append(cell.Ch == '\0' ? ' ' : cell.Ch);
            }
            return sb.ToString();
        }

        /// <summary>Drop all scrollback history, keeping the visible screen.</summary>
        public void ClearHistory()
        {
            int history = HistoryCount;
            if (history <= 0) return;
            _start = RingIndex(history);
            _count = _rows;
            MarkAllDirty();
        }
    }
}
