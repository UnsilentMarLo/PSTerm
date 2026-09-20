// PSTerm - TabStrip.cs
// An owner-drawn tab strip.
//
// WinForms' TabControl paints the strip behind its tabs with the system visual
// style and ignores BackColor, so a dark application ends up with a white band
// across the top. It also has no per-tab close button, which people expect from
// anything with tabs.
//
// This draws the whole strip, supports a close affordance per tab, a "new tab"
// button, a connection-state dot, and scrolls when tabs overflow.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Windows.Forms;

namespace PSTerm.Render
{
    public enum TabState
    {
        Connecting,
        Connected,
        Disconnected,
        Failed
    }

    public sealed class TabStripItem
    {
        public string Title = "";
        /// <summary>Extra detail shown on hover.</summary>
        public string Tooltip = "";
        public TabState State = TabState.Connecting;
        /// <summary>Anything the host wants to associate with this tab.</summary>
        public object Tag;

        internal Rectangle Bounds;
        internal Rectangle CloseBounds;
    }

    public class TabStripEventArgs : EventArgs
    {
        public readonly TabStripItem Item;
        public readonly int Index;
        public TabStripEventArgs(TabStripItem item, int index) { Item = item; Index = index; }
    }

    public sealed class TabStrip : Control
    {
        private readonly List<TabStripItem> _items = new List<TabStripItem>();
        private int _selectedIndex = -1;
        private int _hoverIndex = -1;
        private int _hoverCloseIndex = -1;
        private bool _hoverNewTab;
        private int _scrollOffset;

        // Colours, set by the host from the application theme.
        public Color StripBackground = Color.FromArgb(24, 26, 32);
        public Color TabBackground = Color.FromArgb(24, 26, 32);
        public Color ActiveTabBackground = Color.FromArgb(31, 34, 42);
        public Color HoverTabBackground = Color.FromArgb(38, 42, 52);
        public Color TextColor = Color.FromArgb(222, 226, 234);
        public Color MutedTextColor = Color.FromArgb(140, 148, 162);
        public Color AccentColor = Color.FromArgb(91, 174, 255);
        public Color BorderColor = Color.FromArgb(55, 60, 72);
        public Color ConnectedColor = Color.FromArgb(111, 224, 111);
        public Color DisconnectedColor = Color.FromArgb(140, 148, 162);
        public Color FailedColor = Color.FromArgb(255, 85, 85);

        public int MaxTabWidth = 220;
        public int MinTabWidth = 90;

        /// <summary>Show a close affordance on each tab. Off when the strip is
        /// used to switch pages in a dialog rather than to hold sessions.</summary>
        public bool ShowCloseButtons = true;
        /// <summary>Show the trailing new-session button.</summary>
        public bool ShowNewTabButton = true;
        /// <summary>Show the connection-state dot.</summary>
        public bool ShowStateDots = true;
        /// <summary>Size tabs to their widest label instead of filling the strip.</summary>
        public bool SizeToContent = false;

        private const int NewTabButtonWidth = 30;

        private ToolTip _toolTip;

        public event EventHandler<TabStripEventArgs> SelectedChanged;
        public event EventHandler<TabStripEventArgs> CloseRequested;
        public event EventHandler NewTabRequested;

        public TabStrip()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint |
                     ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer |
                     ControlStyles.ResizeRedraw, true);
            Height = 30;
            Dock = DockStyle.Top;

            _toolTip = new ToolTip();
            _toolTip.InitialDelay = 600;
            _toolTip.ReshowDelay = 200;
        }

        public IList<TabStripItem> Items { get { return _items; } }
        public int Count { get { return _items.Count; } }

        public int SelectedIndex
        {
            get { return _selectedIndex; }
            set
            {
                int next = value;
                if (next < -1) next = -1;
                if (next >= _items.Count) next = _items.Count - 1;
                if (next == _selectedIndex) return;

                _selectedIndex = next;
                EnsureVisible(_selectedIndex);
                Invalidate();

                EventHandler<TabStripEventArgs> h = SelectedChanged;
                if (h != null)
                {
                    TabStripItem item = (_selectedIndex >= 0) ? _items[_selectedIndex] : null;
                    h(this, new TabStripEventArgs(item, _selectedIndex));
                }
            }
        }

        public TabStripItem SelectedItem
        {
            get { return (_selectedIndex >= 0 && _selectedIndex < _items.Count) ? _items[_selectedIndex] : null; }
        }

        public TabStripItem Add(string title, object tag)
        {
            TabStripItem item = new TabStripItem();
            item.Title = title;
            item.Tag = tag;
            _items.Add(item);
            Invalidate();
            SelectedIndex = _items.Count - 1;
            return item;
        }

        public void RemoveAt(int index)
        {
            if (index < 0 || index >= _items.Count) return;
            _items.RemoveAt(index);

            if (_items.Count == 0)
            {
                _selectedIndex = -1;
            }
            else if (_selectedIndex >= _items.Count)
            {
                _selectedIndex = _items.Count - 1;
            }

            // Re-announce the selection: the tab at this index is a different one now.
            EventHandler<TabStripEventArgs> h = SelectedChanged;
            if (h != null)
            {
                TabStripItem item = (_selectedIndex >= 0) ? _items[_selectedIndex] : null;
                h(this, new TabStripEventArgs(item, _selectedIndex));
            }
            Invalidate();
        }

        public int IndexOf(TabStripItem item) { return _items.IndexOf(item); }

        // =====================================================================
        // Layout
        // =====================================================================

        private int TrailingWidth
        {
            get { return ShowNewTabButton ? NewTabButtonWidth : 0; }
        }

        private int TabWidth
        {
            get
            {
                if (_items.Count == 0) return MaxTabWidth;

                if (SizeToContent)
                {
                    // The widest label sets the width for all of them, so the
                    // strip does not shuffle as the selection moves.
                    int widest = MinTabWidth;
                    using (Graphics g = CreateGraphics())
                    {
                        foreach (TabStripItem item in _items)
                        {
                            Size size = TextRenderer.MeasureText(g, item.Title, Font,
                                new Size(int.MaxValue, int.MaxValue), TextFormatFlags.NoPrefix);
                            int needed = size.Width + 28;
                            if (needed > widest) widest = needed;
                        }
                    }
                    return Math.Min(widest, MaxTabWidth);
                }

                int available = Math.Max(0, Width - TrailingWidth);
                int ideal = available / _items.Count;
                if (ideal > MaxTabWidth) ideal = MaxTabWidth;
                if (ideal < MinTabWidth) ideal = MinTabWidth;
                return ideal;
            }
        }

        private void LayoutTabs()
        {
            int width = TabWidth;
            int x = -_scrollOffset;
            int closeSize = 16;

            for (int i = 0; i < _items.Count; i++)
            {
                TabStripItem item = _items[i];
                item.Bounds = new Rectangle(x, 0, width, Height);
                item.CloseBounds = new Rectangle(
                    x + width - closeSize - 6,
                    (Height - closeSize) / 2,
                    closeSize, closeSize);
                x += width;
            }
        }

        private void EnsureVisible(int index)
        {
            if (index < 0 || index >= _items.Count) return;

            int width = TabWidth;
            int left = index * width;
            int right = left + width;
            int viewport = Math.Max(0, Width - TrailingWidth);

            if (left - _scrollOffset < 0) _scrollOffset = left;
            else if (right - _scrollOffset > viewport) _scrollOffset = right - viewport;

            int maxScroll = Math.Max(0, _items.Count * width - viewport);
            if (_scrollOffset > maxScroll) _scrollOffset = maxScroll;
            if (_scrollOffset < 0) _scrollOffset = 0;
        }

        private Rectangle NewTabBounds
        {
            get
            {
                if (!ShowNewTabButton) return Rectangle.Empty;
                return new Rectangle(Width - NewTabButtonWidth, 0, NewTabButtonWidth, Height);
            }
        }

        // =====================================================================
        // Painting
        // =====================================================================

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            using (SolidBrush back = new SolidBrush(StripBackground))
                g.FillRectangle(back, ClientRectangle);

            LayoutTabs();

            Rectangle clip = new Rectangle(0, 0, Math.Max(0, Width - TrailingWidth), Height);
            Region saved = g.Clip;
            g.SetClip(clip);

            for (int i = 0; i < _items.Count; i++)
            {
                if (_items[i].Bounds.Right < 0 || _items[i].Bounds.Left > clip.Right) continue;
                DrawTab(g, _items[i], i);
            }

            g.Clip = saved;

            if (ShowNewTabButton) DrawNewTabButton(g);

            using (Pen border = new Pen(BorderColor))
                g.DrawLine(border, 0, Height - 1, Width, Height - 1);
        }

        private void DrawTab(Graphics g, TabStripItem item, int index)
        {
            bool selected = (index == _selectedIndex);
            bool hovered = (index == _hoverIndex);

            Color back = selected ? ActiveTabBackground : (hovered ? HoverTabBackground : TabBackground);
            using (SolidBrush brush = new SolidBrush(back))
                g.FillRectangle(brush, item.Bounds);

            // The active tab is marked with a rule along its top edge, which reads
            // faster at a glance than a shape or border change.
            if (selected)
            {
                using (SolidBrush accent = new SolidBrush(AccentColor))
                    g.FillRectangle(accent, item.Bounds.Left, 0, item.Bounds.Width, 2);
            }

            using (Pen divider = new Pen(BorderColor))
                g.DrawLine(divider, item.Bounds.Right - 1, 6, item.Bounds.Right - 1, Height - 7);

            int textLeft = item.Bounds.Left + 12;

            if (ShowStateDots)
            {
                // A state dot makes a dead session obvious without reading the label.
                int dotSize = 7;
                Rectangle dot = new Rectangle(item.Bounds.Left + 10, (Height - dotSize) / 2, dotSize, dotSize);
                Color dotColor;
                switch (item.State)
                {
                    case TabState.Connected: dotColor = ConnectedColor; break;
                    case TabState.Failed: dotColor = FailedColor; break;
                    case TabState.Disconnected: dotColor = DisconnectedColor; break;
                    default: dotColor = AccentColor; break;
                }
                if (item.State == TabState.Disconnected)
                {
                    using (Pen pen = new Pen(dotColor, 1.4f)) g.DrawEllipse(pen, dot);
                }
                else
                {
                    using (SolidBrush brush = new SolidBrush(dotColor)) g.FillEllipse(brush, dot);
                }
                textLeft = dot.Right + 8;
            }

            int textRight = ShowCloseButtons ? (item.CloseBounds.Left - 4) : (item.Bounds.Right - 10);
            if (textRight > textLeft)
            {
                using (StringFormat format = new StringFormat())
                {
                    format.Alignment = StringAlignment.Near;
                    format.LineAlignment = StringAlignment.Center;
                    format.Trimming = StringTrimming.EllipsisCharacter;
                    format.FormatFlags = StringFormatFlags.NoWrap;

                    Color textColor = selected ? TextColor : MutedTextColor;
                    using (SolidBrush brush = new SolidBrush(textColor))
                    {
                        RectangleF rect = new RectangleF(textLeft, 0, textRight - textLeft, Height);
                        g.DrawString(item.Title, Font, brush, rect, format);
                    }
                }
            }

            // The close cross appears on hover or on the active tab, so a row of
            // inactive tabs is not a row of crosses.
            if (ShowCloseButtons && (selected || hovered))
            {
                bool closeHot = (index == _hoverCloseIndex);
                if (closeHot)
                {
                    using (SolidBrush brush = new SolidBrush(Color.FromArgb(60, 255, 255, 255)))
                        g.FillEllipse(brush, item.CloseBounds);
                }

                Color crossColor = closeHot ? TextColor : MutedTextColor;
                using (Pen pen = new Pen(crossColor, 1.3f))
                {
                    Rectangle c = item.CloseBounds;
                    int pad = 5;
                    g.DrawLine(pen, c.Left + pad, c.Top + pad, c.Right - pad, c.Bottom - pad);
                    g.DrawLine(pen, c.Right - pad, c.Top + pad, c.Left + pad, c.Bottom - pad);
                }
            }
        }

        private void DrawNewTabButton(Graphics g)
        {
            Rectangle bounds = NewTabBounds;

            using (SolidBrush brush = new SolidBrush(_hoverNewTab ? HoverTabBackground : StripBackground))
                g.FillRectangle(brush, bounds);

            Color color = _hoverNewTab ? TextColor : MutedTextColor;
            using (Pen pen = new Pen(color, 1.5f))
            {
                int cx = bounds.Left + bounds.Width / 2;
                int cy = bounds.Top + bounds.Height / 2;
                g.DrawLine(pen, cx - 5, cy, cx + 5, cy);
                g.DrawLine(pen, cx, cy - 5, cx, cy + 5);
            }
        }

        // =====================================================================
        // Mouse
        // =====================================================================

        private int HitTest(Point location, out bool onClose)
        {
            onClose = false;
            LayoutTabs();

            if (ShowNewTabButton && location.X >= Width - NewTabButtonWidth) return -1;

            for (int i = 0; i < _items.Count; i++)
            {
                if (!_items[i].Bounds.Contains(location)) continue;
                bool showsClose = ShowCloseButtons && (i == _selectedIndex || i == _hoverIndex);
                onClose = showsClose && _items[i].CloseBounds.Contains(location);
                return i;
            }
            return -1;
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);

            bool onClose;
            int index = HitTest(e.Location, out onClose);
            bool onNewTab = NewTabBounds.Contains(e.Location);

            if (index != _hoverIndex || onClose != (_hoverCloseIndex == index) || onNewTab != _hoverNewTab)
            {
                _hoverIndex = index;
                _hoverCloseIndex = onClose ? index : -1;
                _hoverNewTab = onNewTab;
                Invalidate();

                string tip = "";
                if (onNewTab) tip = "New session";
                else if (index >= 0) tip = string.IsNullOrEmpty(_items[index].Tooltip) ? _items[index].Title : _items[index].Tooltip;
                if (_toolTip.GetToolTip(this) != tip) _toolTip.SetToolTip(this, tip);
            }
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            _hoverIndex = -1;
            _hoverCloseIndex = -1;
            _hoverNewTab = false;
            Invalidate();
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);

            if (NewTabBounds.Contains(e.Location) && e.Button == MouseButtons.Left)
            {
                EventHandler h = NewTabRequested;
                if (h != null) h(this, EventArgs.Empty);
                return;
            }

            bool onClose;
            int index = HitTest(e.Location, out onClose);
            if (index < 0) return;

            // Middle-click closes anywhere on the tab, as in a browser.
            if (ShowCloseButtons && (e.Button == MouseButtons.Middle || (e.Button == MouseButtons.Left && onClose)))
            {
                RaiseClose(index);
                return;
            }

            if (e.Button == MouseButtons.Left) SelectedIndex = index;
        }

        private void RaiseClose(int index)
        {
            if (index < 0 || index >= _items.Count) return;
            EventHandler<TabStripEventArgs> h = CloseRequested;
            if (h != null) h(this, new TabStripEventArgs(_items[index], index));
        }

        protected override void OnMouseWheel(MouseEventArgs e)
        {
            base.OnMouseWheel(e);
            if (_items.Count == 0) return;
            SelectedIndex = Math.Max(0, Math.Min(_items.Count - 1,
                _selectedIndex + (e.Delta > 0 ? -1 : 1)));
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _toolTip != null) { _toolTip.Dispose(); _toolTip = null; }
            base.Dispose(disposing);
        }
    }
}
