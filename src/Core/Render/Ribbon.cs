// PSTerm - Ribbon.cs
// A toolbar with an icon above each caption and the buttons gathered into labelled
// groups, in the manner of Microsoft Word's ribbon, plus the small pieces it shares
// with the rest of the interface: the icon font and a tooltip that follows the theme.
//
// Icons are glyphs from the icon font Windows ships (Segoe Fluent Icons on Windows
// 11, Segoe MDL2 Assets on Windows 10), so there are no image files to carry and
// they scale with the display. Where neither font is installed a plain letter is
// drawn instead, so a button is never blank.
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
    /// <summary>The icon font, resolved once.</summary>
    public static class IconFont
    {
        private static string _family;
        private static bool _resolved;

        public static string Family
        {
            get
            {
                if (_resolved) return _family;
                _resolved = true;
                using (InstalledFontCollection fonts = new InstalledFontCollection())
                {
                    foreach (string wanted in new string[] { "Segoe Fluent Icons", "Segoe MDL2 Assets" })
                    {
                        foreach (FontFamily f in fonts.Families)
                        {
                            if (string.Equals(f.Name, wanted, StringComparison.OrdinalIgnoreCase))
                            {
                                _family = f.Name;
                                return _family;
                            }
                        }
                    }
                }
                _family = null;
                return null;
            }
        }

        public static bool Available { get { return Family != null; } }

        public static Font Create(float pixelSize)
        {
            string family = Family;
            if (family == null) return null;
            try { return new Font(family, pixelSize, FontStyle.Regular, GraphicsUnit.Pixel); }
            catch (Exception) { return null; }
        }

        /// <summary>Draw a glyph centred in a rectangle.</summary>
        public static void Draw(Graphics g, string glyph, string fallback, Rectangle bounds, Color colour, float pixelSize)
        {
            using (Font font = Create(pixelSize))
            {
                string text = (font != null) ? glyph : fallback;
                Font use = font;
                bool ownFont = false;
                if (use == null)
                {
                    use = new Font(FontFamily.GenericSansSerif, pixelSize * 0.8f, FontStyle.Bold, GraphicsUnit.Pixel);
                    ownFont = true;
                }
                try
                {
                    TextRenderer.DrawText(g, text, use, bounds, colour,
                        TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter |
                        TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
                }
                finally { if (ownFont) use.Dispose(); }
            }
        }
    }

    /// <summary>A tooltip drawn in the application's colours. The system one is
    /// light and would be the last white thing on a dark window.</summary>
    public sealed class ThemedToolTip : IDisposable
    {
        private readonly ToolTip _tip = new ToolTip();
        private Color _back = Color.FromArgb(32, 35, 43);
        private Color _border = Color.FromArgb(58, 63, 76);
        private Color _text = Color.FromArgb(228, 231, 238);

        public ThemedToolTip()
        {
            _tip.OwnerDraw = true;
            _tip.InitialDelay = 450;
            _tip.ReshowDelay = 150;
            _tip.AutoPopDelay = 12000;
            _tip.Popup += OnPopup;
            _tip.Draw += OnDraw;
        }

        public void Apply(ControlTheme theme)
        {
            if (theme == null) return;
            _back = theme.Surface;
            _border = theme.BorderStrong;
            _text = theme.Text;
        }

        public void SetTip(Control control, string text)
        {
            if (control == null) return;
            _tip.SetToolTip(control, text ?? "");
        }

        /// <summary>Show a tip at a position inside a control, for items that are not controls.</summary>
        public void ShowAt(Control owner, string text, Point location)
        {
            if (owner == null || string.IsNullOrEmpty(text)) return;
            _pending = text;
            _tip.Show(text, owner, location, 12000);
        }

        public void Hide(Control owner)
        {
            if (owner != null) _tip.Hide(owner);
        }

        private void OnPopup(object sender, PopupEventArgs e)
        {
            string text = _tip.GetToolTip(e.AssociatedControl);
            if (string.IsNullOrEmpty(text)) text = _pending;
            Font font = e.AssociatedControl != null ? e.AssociatedControl.Font : SystemFonts.MessageBoxFont;
            Size size = TextRenderer.MeasureText(text ?? "", font,
                new Size(420, int.MaxValue), TextFormatFlags.NoPrefix | TextFormatFlags.WordBreak);
            e.ToolTipSize = new Size(size.Width + 18, size.Height + 12);
        }

        private string _pending;

        private void OnDraw(object sender, DrawToolTipEventArgs e)
        {
            using (SolidBrush brush = new SolidBrush(_back))
                e.Graphics.FillRectangle(brush, e.Bounds);
            using (Pen pen = new Pen(_border))
                e.Graphics.DrawRectangle(pen, 0, 0, e.Bounds.Width - 1, e.Bounds.Height - 1);

            Font font = e.AssociatedControl != null ? e.AssociatedControl.Font : SystemFonts.MessageBoxFont;
            Rectangle text = Rectangle.Inflate(e.Bounds, -8, -5);
            TextRenderer.DrawText(e.Graphics, e.ToolTipText, font, text, _text,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter |
                TextFormatFlags.NoPrefix | TextFormatFlags.WordBreak);
        }

        public void Dispose()
        {
            _tip.Popup -= OnPopup;
            _tip.Draw -= OnDraw;
            _tip.Dispose();
        }
    }

    // =========================================================================
    // Ribbon
    // =========================================================================

    public sealed class RibbonItem
    {
        public string Key = "";
        public string Text = "";
        /// <summary>Icon-font character.</summary>
        public string Glyph = "";
        /// <summary>Letter drawn when no icon font is installed.</summary>
        public string Fallback = "?";
        public string Tip = "";
        public string Group = "";
        public bool Enabled = true;
        /// <summary>Shows a drop-down arrow; the host opens a menu when clicked.</summary>
        public bool DropDown = false;
        /// <summary>A toggle that stays pressed while on.</summary>
        public bool Toggle = false;
        public bool Checked = false;

        internal Rectangle Bounds;
    }

    public class RibbonEventArgs : EventArgs
    {
        public readonly RibbonItem Item;
        /// <summary>Where a drop-down menu should open, in screen coordinates.</summary>
        public readonly Point MenuLocation;
        public RibbonEventArgs(RibbonItem item, Point menuLocation) { Item = item; MenuLocation = menuLocation; }
    }

    public sealed class RibbonBar : Control
    {
        private readonly List<RibbonItem> _items = new List<RibbonItem>();
        private RibbonItem _hot;
        private RibbonItem _pressed;
        private readonly ThemedToolTip _tips = new ThemedToolTip();
        private ControlTheme _theme = new ControlTheme();

        private int _iconSize;
        private int _padX;
        private int _gap;

        public event EventHandler<RibbonEventArgs> ItemClicked;

        public RibbonBar()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            Dock = DockStyle.Top;
            TabStop = false;
        }

        public IList<RibbonItem> Items { get { return _items; } }

        public void ApplyTheme(ControlTheme theme)
        {
            if (theme == null) return;
            _theme = theme;
            _tips.Apply(theme);
            Invalidate();
        }

        public RibbonItem Find(string key)
        {
            foreach (RibbonItem item in _items)
                if (string.Equals(item.Key, key, StringComparison.OrdinalIgnoreCase)) return item;
            return null;
        }

        public RibbonItem Add(string group, string key, string text, string glyph, string fallback, string tip)
        {
            RibbonItem item = new RibbonItem();
            item.Group = group; item.Key = key; item.Text = text;
            item.Glyph = glyph; item.Fallback = fallback; item.Tip = tip;
            _items.Add(item);
            Invalidate();
            return item;
        }

        public void SetEnabled(string key, bool enabled)
        {
            RibbonItem item = Find(key);
            if (item != null && item.Enabled != enabled) { item.Enabled = enabled; Invalidate(); }
        }

        /// <summary>The height needed for the current font.</summary>
        public int PreferredBarHeight()
        {
            int line = Font.Height;
            return (int)(line * 1.9) + line + (int)(line * 1.0) + 10;
        }

        // ---- layout ---------------------------------------------------------

        private void LayoutItems()
        {
            int line = Font.Height;
            _iconSize = (int)(line * 1.7);
            _padX = (int)(line * 0.7);
            _gap = (int)(line * 0.5);

            int captionHeight = (int)(line * 1.0) + 4;
            int buttonTop = 4;
            int buttonHeight = Height - captionHeight - buttonTop - 2;

            int x = _gap;
            string group = null;
            int groupStart = x;

            foreach (RibbonItem item in _items)
            {
                if (group != null && item.Group != group)
                {
                    x += _gap;      // space for the divider
                    groupStart = x;
                }
                group = item.Group;

                Size text = TextRenderer.MeasureText(item.Text, Font, new Size(int.MaxValue, int.MaxValue),
                    TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
                int width = Math.Max(text.Width + (item.DropDown ? (int)(line * 0.9) : 0), _iconSize) + _padX * 2;
                item.Bounds = new Rectangle(x, buttonTop, width, buttonHeight);
                x += width + 2;
            }
        }

        // ---- painting -------------------------------------------------------

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.None;
            using (SolidBrush back = new SolidBrush(_theme.Surface))
                g.FillRectangle(back, ClientRectangle);

            LayoutItems();

            int line = Font.Height;
            int captionHeight = (int)(line * 1.0) + 4;
            Font captionFont = new Font(Font.FontFamily, Math.Max(6.5f, Font.SizeInPoints * 0.82f), FontStyle.Regular, GraphicsUnit.Point);

            try
            {
                // Group captions and the dividers between groups.
                int i = 0;
                while (i < _items.Count)
                {
                    int j = i;
                    while (j + 1 < _items.Count && _items[j + 1].Group == _items[i].Group) j++;

                    Rectangle first = _items[i].Bounds, last = _items[j].Bounds;
                    Rectangle caption = new Rectangle(first.Left, Height - captionHeight - 1, last.Right - first.Left, captionHeight);
                    TextRenderer.DrawText(g, _items[i].Group, captionFont, caption, _theme.TextMuted,
                        TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter |
                        TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);

                    if (j + 1 < _items.Count)
                    {
                        int dx = last.Right + _gap - 1;
                        using (Pen pen = new Pen(_theme.Border))
                            g.DrawLine(pen, dx, 8, dx, Height - 8);
                    }
                    i = j + 1;
                }

                foreach (RibbonItem item in _items) DrawItem(g, item);
            }
            finally { captionFont.Dispose(); }

            using (Pen border = new Pen(_theme.Border))
                g.DrawLine(border, 0, Height - 1, Width, Height - 1);
        }

        private void DrawItem(Graphics g, RibbonItem item)
        {
            bool hot = ReferenceEquals(item, _hot) && item.Enabled;
            bool down = ReferenceEquals(item, _pressed) && item.Enabled;

            if (down || item.Checked)
            {
                using (SolidBrush brush = new SolidBrush(_theme.Selection))
                    g.FillRectangle(brush, item.Bounds);
            }
            else if (hot)
            {
                using (SolidBrush brush = new SolidBrush(_theme.FieldHover))
                    g.FillRectangle(brush, item.Bounds);
            }
            if (hot || item.Checked)
            {
                using (Pen pen = new Pen(_theme.Border))
                    g.DrawRectangle(pen, item.Bounds.Left, item.Bounds.Top, item.Bounds.Width - 1, item.Bounds.Height - 1);
            }

            Color ink = item.Enabled ? _theme.Text : _theme.TextDisabled;
            Color accent = item.Enabled ? _theme.Accent : _theme.TextDisabled;

            Rectangle icon = new Rectangle(item.Bounds.Left, item.Bounds.Top + 4, item.Bounds.Width, _iconSize);
            IconFont.Draw(g, item.Glyph, item.Fallback, icon, accent, _iconSize * 0.82f);

            Rectangle label = new Rectangle(item.Bounds.Left, icon.Bottom + 2, item.Bounds.Width, item.Bounds.Bottom - icon.Bottom - 3);
            TextFormatFlags flags = TextFormatFlags.HorizontalCenter | TextFormatFlags.Top |
                                    TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine;
            if (item.DropDown)
            {
                // Caption with a small chevron after it.
                Size text = TextRenderer.MeasureText(item.Text, Font, new Size(int.MaxValue, int.MaxValue),
                    TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix);
                int arrow = (int)(Font.Height * 0.75);
                int total = text.Width + arrow;
                int left = label.Left + (label.Width - total) / 2;
                TextRenderer.DrawText(g, item.Text, Font, new Point(left, label.Top), ink,
                    TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix);
                IconFont.Draw(g, "", "v", new Rectangle(left + text.Width + 1, label.Top, arrow, Font.Height),
                    ink, Font.Height * 0.62f);
            }
            else
            {
                TextRenderer.DrawText(g, item.Text, Font, label, ink, flags);
            }
        }

        // ---- mouse ----------------------------------------------------------

        private RibbonItem HitTest(Point p)
        {
            foreach (RibbonItem item in _items) if (item.Bounds.Contains(p)) return item;
            return null;
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            RibbonItem hit = HitTest(e.Location);
            if (!ReferenceEquals(hit, _hot))
            {
                _hot = hit;
                Invalidate();
                _tips.Hide(this);
                if (hit != null && !string.IsNullOrEmpty(hit.Tip))
                    _tips.ShowAt(this, hit.Tip, new Point(hit.Bounds.Left, hit.Bounds.Bottom + 4));
            }
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            _hot = null;
            _pressed = null;
            _tips.Hide(this);
            Invalidate();
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            if (e.Button != MouseButtons.Left) return;
            RibbonItem hit = HitTest(e.Location);
            if (hit != null && hit.Enabled)
            {
                _pressed = hit;
                _tips.Hide(this);
                Invalidate();
            }
        }

        protected override void OnMouseUp(MouseEventArgs e)
        {
            base.OnMouseUp(e);
            RibbonItem pressed = _pressed;
            _pressed = null;
            Invalidate();

            if (pressed == null || e.Button != MouseButtons.Left) return;
            if (!ReferenceEquals(pressed, HitTest(e.Location)) || !pressed.Enabled) return;

            if (pressed.Toggle) pressed.Checked = !pressed.Checked;

            EventHandler<RibbonEventArgs> h = ItemClicked;
            if (h != null)
            {
                Point menu = PointToScreen(new Point(pressed.Bounds.Left, pressed.Bounds.Bottom));
                h(this, new RibbonEventArgs(pressed, menu));
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _tips.Dispose();
            base.Dispose(disposing);
        }
    }
}
