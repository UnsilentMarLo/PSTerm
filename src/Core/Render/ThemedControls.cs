// PSTerm - ThemedControls.cs
// Owner-drawn WinForms controls that actually honour a dark theme.
//
// WinForms has no theming of its own. Setting BackColor on a ComboBox, CheckBox
// or ContextMenuStrip changes only the parts the framework paints; the rest is
// drawn by the system visual style and stays light, which is why a "dark" form
// ends up with white drop-down buttons, white check boxes and a white gutter
// down the side of every menu.
//
// Windows does expose dark variants of the common controls through undocumented
// uxtheme ordinals (SetPreferredAppMode, AllowDarkModeForWindow). They are not
// dependable across builds - they did not take effect on the machine this was
// developed against - so the pieces that matter are drawn here instead. The
// result is identical on every Windows version and needs no undocumented API.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace PSTerm.Render
{
    /// <summary>
    /// The colours these controls share. One instance is built from the
    /// application theme and handed to every control.
    /// </summary>
    public sealed class ControlTheme
    {
        public Color Background = Color.FromArgb(24, 26, 32);
        public Color Surface = Color.FromArgb(31, 34, 42);
        public Color Field = Color.FromArgb(38, 42, 52);
        public Color FieldHover = Color.FromArgb(46, 51, 63);
        public Color Border = Color.FromArgb(55, 60, 72);
        public Color BorderStrong = Color.FromArgb(82, 90, 106);
        public Color Text = Color.FromArgb(222, 226, 234);
        public Color TextMuted = Color.FromArgb(140, 148, 162);
        public Color TextDisabled = Color.FromArgb(104, 110, 122);
        public Color Accent = Color.FromArgb(91, 174, 255);
        public Color AccentText = Color.FromArgb(16, 18, 22);
        public Color Selection = Color.FromArgb(47, 79, 127);
        public bool IsDark = true;
    }

    // =========================================================================
    // Form
    // =========================================================================

    /// <summary>
    /// A form that paints without flicker and can request a dark title bar.
    /// </summary>
    /// <remarks>
    /// WS_EX_COMPOSITED makes Windows buffer the whole window, including child
    /// controls. That is what stops combo boxes and menus flickering as they
    /// repaint on hover: WinForms' own double buffering only covers a control's
    /// own surface, never the seams between siblings.
    /// </remarks>
    public class ThemedForm : Form
    {
        private bool _composited = true;

        /// <summary>Buffer the entire window. Off only if a child needs to paint
        /// at high frequency and the extra copy shows.</summary>
        public bool CompositedPainting
        {
            get { return _composited; }
            set
            {
                if (_composited == value) return;
                _composited = value;
                if (IsHandleCreated) RecreateHandle();
            }
        }

        protected override CreateParams CreateParams
        {
            get
            {
                CreateParams cp = base.CreateParams;
                if (_composited) cp.ExStyle |= NativeTheme.WS_EX_COMPOSITED;
                return cp;
            }
        }

        public ThemedForm()
        {
            // Sizes are computed from the UI font, so WinForms must not apply a
            // second scaling pass of its own on top.
            AutoScaleMode = AutoScaleMode.None;
            Font = NativeTheme.GetUiFont();
        }

        /// <summary>Ask the desktop window manager for a dark title bar.</summary>
        public void SetDarkTitleBar(bool dark)
        {
            NativeTheme.SetDarkTitleBar(this, dark);
        }
    }

    /// <summary>A panel that does not flicker, for use as a container.</summary>
    public class ThemedPanel : Panel
    {
        public ThemedPanel()
        {
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint |
                     ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        }
    }

    // =========================================================================
    // Combo box
    // =========================================================================

    /// <summary>
    /// A combo box drawn in theme colours, including the drop-down button and
    /// the list, neither of which respond to BackColor on their own.
    /// </summary>
    public class ThemedComboBox : ComboBox
    {
        private ControlTheme _theme = new ControlTheme();
        private bool _hover;
        private bool _dropped;

        public ThemedComboBox()
        {
            // Owner-drawing the items is what makes the drop-down list dark; the
            // framework would otherwise paint it with system colours.
            DrawMode = DrawMode.OwnerDrawFixed;
            FlatStyle = FlatStyle.Flat;
            ApplyTheme(_theme);
        }

        public ControlTheme Theme { get { return _theme; } }

        public void ApplyTheme(ControlTheme theme)
        {
            if (theme == null) return;
            _theme = theme;
            BackColor = theme.Field;
            ForeColor = theme.Text;
            Invalidate();
        }

        protected override void OnMouseEnter(EventArgs e) { base.OnMouseEnter(e); _hover = true; Invalidate(); }
        protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); _hover = false; Invalidate(); }
        protected override void OnDropDown(EventArgs e) { base.OnDropDown(e); _dropped = true; Invalidate(); }
        protected override void OnDropDownClosed(EventArgs e) { base.OnDropDownClosed(e); _dropped = false; Invalidate(); }

        protected override void OnDrawItem(DrawItemEventArgs e)
        {
            if (e.Bounds.Width <= 0 || e.Bounds.Height <= 0) return;

            // The same callback paints both the closed control's text area and
            // each row of the open list; ComboBoxEdit distinguishes them.
            bool isEditArea = (e.State & DrawItemState.ComboBoxEdit) != 0;
            bool isSelected = (e.State & DrawItemState.Selected) != 0 && !isEditArea;

            Color back = isSelected ? _theme.Selection : _theme.Field;
            Color fore = Enabled ? _theme.Text : _theme.TextDisabled;

            using (SolidBrush brush = new SolidBrush(back))
                e.Graphics.FillRectangle(brush, e.Bounds);

            if (e.Index >= 0 && e.Index < Items.Count)
            {
                string text = GetItemText(Items[e.Index]);
                Rectangle textBounds = new Rectangle(
                    e.Bounds.Left + 4, e.Bounds.Top, e.Bounds.Width - 8, e.Bounds.Height);
                TextRenderer.DrawText(e.Graphics, text, Font, textBounds, fore,
                    TextFormatFlags.Left | TextFormatFlags.VerticalCenter |
                    TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis);
            }
        }

        protected override void WndProc(ref Message m)
        {
            base.WndProc(ref m);

            // The drop-down button and the control border are drawn by the system
            // visual style regardless of BackColor, so they are painted over once
            // the framework has finished.
            //
            // WM_PRINTCLIENT is handled as well as WM_PAINT: that is the path
            // DrawToBitmap and printing take, and without it the control renders
            // correctly on screen but with a white button everywhere else.
            if (Width <= 0 || Height <= 0) return;

            if (m.Msg == NativeTheme.WM_PAINT)
            {
                using (Graphics g = Graphics.FromHwnd(Handle)) { DrawChrome(g); }
            }
            else if (m.Msg == NativeTheme.WM_PRINTCLIENT || m.Msg == NativeTheme.WM_PRINT)
            {
                if (m.WParam != IntPtr.Zero)
                {
                    using (Graphics g = Graphics.FromHdc(m.WParam)) { DrawChrome(g); }
                }
            }
        }

        private void DrawChrome(Graphics g)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;

            int buttonWidth = Math.Max(16, (int)(Height * 0.9));
            Rectangle button = new Rectangle(Width - buttonWidth - 1, 1, buttonWidth, Height - 2);

            Color buttonBack = (_hover || _dropped) ? _theme.FieldHover : _theme.Field;
            using (SolidBrush brush = new SolidBrush(buttonBack))
                g.FillRectangle(brush, button);

            // A chevron rather than a filled triangle: that is the current
            // Windows affordance and it reads better at small sizes.
            Color arrow = Enabled ? _theme.TextMuted : _theme.TextDisabled;
            if (_hover || _dropped) arrow = _theme.Text;

            float cx = button.Left + button.Width / 2f;
            float cy = button.Top + button.Height / 2f;
            float w = Math.Max(3f, button.Width * 0.22f);
            float h = w * 0.55f;

            using (Pen pen = new Pen(arrow, Math.Max(1.2f, Height / 18f)))
            {
                pen.StartCap = LineCap.Round;
                pen.EndCap = LineCap.Round;
                pen.LineJoin = LineJoin.Round;
                g.DrawLines(pen, new PointF[] {
                    new PointF(cx - w, cy - h / 2f),
                    new PointF(cx,     cy + h / 2f),
                    new PointF(cx + w, cy - h / 2f)
                });
            }

            g.SmoothingMode = SmoothingMode.None;
            Color border = (_hover || _dropped || Focused) ? _theme.BorderStrong : _theme.Border;
            using (Pen pen = new Pen(border))
                g.DrawRectangle(pen, 0, 0, Width - 1, Height - 1);
        }
    }

    // =========================================================================
    // Check box
    // =========================================================================

    /// <summary>
    /// A fully owner-drawn check box. The system glyph is a white square that no
    /// property can recolour, which is the most obvious light element left on an
    /// otherwise dark form.
    /// </summary>
    public class ThemedCheckBox : CheckBox
    {
        private ControlTheme _theme = new ControlTheme();
        private bool _hover;

        public ThemedCheckBox()
        {
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint |
                     ControlStyles.UserPaint | ControlStyles.SupportsTransparentBackColor, true);
            BackColor = Color.Transparent;
            AutoSize = true;
        }

        public void ApplyTheme(ControlTheme theme)
        {
            if (theme == null) return;
            _theme = theme;
            ForeColor = theme.Text;
            Invalidate();
        }

        protected override void OnMouseEnter(EventArgs e) { base.OnMouseEnter(e); _hover = true; Invalidate(); }
        protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); _hover = false; Invalidate(); }

        public override Size GetPreferredSize(Size proposedSize)
        {
            Size text = TextRenderer.MeasureText(Text, Font, new Size(int.MaxValue, int.MaxValue),
                                                 TextFormatFlags.NoPrefix);
            int box = BoxSize;
            return new Size(box + 8 + text.Width + 2, Math.Max(box, text.Height) + 4);
        }

        private int BoxSize { get { return Math.Max(13, (int)Math.Round(Font.Height * 0.95)); } }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            Color parentBack = (Parent != null) ? Parent.BackColor : _theme.Background;
            using (SolidBrush brush = new SolidBrush(parentBack))
                g.FillRectangle(brush, ClientRectangle);

            int size = BoxSize;
            Rectangle box = new Rectangle(1, (Height - size) / 2, size, size);

            if (Checked)
            {
                using (SolidBrush brush = new SolidBrush(Enabled ? _theme.Accent : _theme.TextDisabled))
                    g.FillRectangle(brush, box);

                // Check glyph drawn as two strokes, so it stays crisp at any size.
                using (Pen pen = new Pen(_theme.AccentText, Math.Max(1.6f, size / 8f)))
                {
                    pen.StartCap = LineCap.Round;
                    pen.EndCap = LineCap.Round;
                    pen.LineJoin = LineJoin.Round;
                    float l = box.Left, t = box.Top, s = size;
                    g.DrawLines(pen, new PointF[] {
                        new PointF(l + s * 0.24f, t + s * 0.52f),
                        new PointF(l + s * 0.43f, t + s * 0.72f),
                        new PointF(l + s * 0.77f, t + s * 0.30f)
                    });
                }
            }
            else
            {
                using (SolidBrush brush = new SolidBrush(_hover ? _theme.FieldHover : _theme.Field))
                    g.FillRectangle(brush, box);
                using (Pen pen = new Pen(_hover ? _theme.BorderStrong : _theme.Border))
                    g.DrawRectangle(pen, box.Left, box.Top, box.Width - 1, box.Height - 1);
            }

            g.SmoothingMode = SmoothingMode.None;

            Rectangle textBounds = new Rectangle(box.Right + 7, 0, Width - box.Right - 8, Height);
            TextRenderer.DrawText(g, Text, Font, textBounds,
                Enabled ? ForeColor : _theme.TextDisabled,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter |
                TextFormatFlags.NoPrefix | TextFormatFlags.WordEllipsis);

            if (Focused && ShowFocusCues)
            {
                using (Pen pen = new Pen(_theme.BorderStrong) { DashStyle = DashStyle.Dot })
                    g.DrawRectangle(pen, textBounds.Left - 2, 1, textBounds.Width, Height - 3);
            }
        }
    }

    // =========================================================================
    // Tree view
    // =========================================================================

    /// <summary>
    /// A tree drawn in theme colours.
    /// </summary>
    /// <remarks>
    /// TreeView paints its selection highlight, expander glyphs and scroll bars
    /// with the system visual style and ignores BackColor, so a dark panel ends
    /// up with a white selection bar and a white scroll bar. Everything inside
    /// the client area is drawn here; the horizontal scroll bar is suppressed
    /// outright with TVS_NOHSCROLL and long labels are ellipsised instead, which
    /// is better behaviour for a session list anyway.
    /// </remarks>
    public class ThemedTreeView : TreeView
    {
        private const int TVS_NOHSCROLL = 0x8000;

        private ControlTheme _theme = new ControlTheme();
        private TreeNode _hotNode;

        /// <summary>
        /// Pixels at the right that are clipped from view.
        /// </summary>
        /// <remarks>
        /// The host makes this control wider than its container so the system
        /// vertical scroll bar, which cannot be themed, falls outside the clip.
        /// Text has to be laid out against the visible edge or the ellipsis is
        /// placed off-screen and labels simply end mid-word.
        /// </remarks>
        public int RightInset = 0;

        public ThemedTreeView()
        {
            DrawMode = TreeViewDrawMode.OwnerDrawAll;
            FullRowSelect = true;
            HideSelection = false;
            ShowLines = false;
            ShowRootLines = false;
            ShowPlusMinus = true;      // keeps the native hit-test for the expander
            BorderStyle = BorderStyle.None;
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint, true);
        }

        protected override CreateParams CreateParams
        {
            get
            {
                CreateParams cp = base.CreateParams;
                cp.Style |= TVS_NOHSCROLL;
                return cp;
            }
        }

        public void ApplyTheme(ControlTheme theme)
        {
            if (theme == null) return;
            _theme = theme;
            BackColor = theme.Surface;
            ForeColor = theme.Text;
            LineColor = theme.Border;
            Invalidate();
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            TreeNode node = GetNodeAt(0, e.Y);
            if (!ReferenceEquals(node, _hotNode))
            {
                _hotNode = node;
                Invalidate();
            }
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            if (_hotNode != null) { _hotNode = null; Invalidate(); }
        }

        protected override void OnDrawNode(DrawTreeNodeEventArgs e)
        {
            e.DrawDefault = false;

            if (e.Node == null || e.Bounds.Height <= 0) return;

            // Full-width row, so selection spans the panel rather than hugging
            // the text the way the default drawing does.
            Rectangle row = new Rectangle(0, e.Bounds.Top, Width - RightInset, e.Bounds.Height);

            bool selected = (e.State & TreeNodeStates.Selected) != 0;
            bool hot = ReferenceEquals(e.Node, _hotNode);
            bool isFolder = (e.Node.Tag == null);

            Color back = selected ? _theme.Selection : (hot ? _theme.FieldHover : _theme.Surface);
            using (SolidBrush brush = new SolidBrush(back))
                e.Graphics.FillRectangle(brush, row);

            int indent = Indent * e.Node.Level;
            int glyphSize = Math.Max(8, e.Bounds.Height / 2);
            int textLeft = indent + Indent;

            if (e.Node.Nodes.Count > 0)
            {
                DrawExpander(e.Graphics,
                    new Rectangle(indent + (Indent - glyphSize) / 2,
                                  e.Bounds.Top + (e.Bounds.Height - glyphSize) / 2,
                                  glyphSize, glyphSize),
                    e.Node.IsExpanded,
                    selected ? _theme.Text : _theme.TextMuted);
            }

            // A folder is a heading, so it is muted; a connection is the thing
            // the operator is actually looking for.
            Color fore = selected ? _theme.Text : (isFolder ? _theme.TextMuted : _theme.Text);

            int visibleRight = Width - RightInset;
            Rectangle textBounds = new Rectangle(
                textLeft, e.Bounds.Top, Math.Max(10, visibleRight - textLeft - 8), e.Bounds.Height);

            TextRenderer.DrawText(e.Graphics, e.Node.Text, Font, textBounds, fore,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter |
                TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis);
        }

        private static void DrawExpander(Graphics g, Rectangle bounds, bool expanded, Color colour)
        {
            SmoothingMode saved = g.SmoothingMode;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            float cx = bounds.Left + bounds.Width / 2f;
            float cy = bounds.Top + bounds.Height / 2f;
            float r = bounds.Width * 0.26f;

            using (Pen pen = new Pen(colour, Math.Max(1.3f, bounds.Width / 9f)))
            {
                pen.StartCap = LineCap.Round;
                pen.EndCap = LineCap.Round;
                pen.LineJoin = LineJoin.Round;

                if (expanded)
                {
                    g.DrawLines(pen, new PointF[] {
                        new PointF(cx - r, cy - r * 0.5f),
                        new PointF(cx,     cy + r * 0.5f),
                        new PointF(cx + r, cy - r * 0.5f)
                    });
                }
                else
                {
                    g.DrawLines(pen, new PointF[] {
                        new PointF(cx - r * 0.5f, cy - r),
                        new PointF(cx + r * 0.5f, cy),
                        new PointF(cx - r * 0.5f, cy + r)
                    });
                }
            }

            g.SmoothingMode = saved;
        }

        // ---- scrolling ------------------------------------------------------
        // The vertical scroll bar is a system control that cannot be themed, so
        // the host clips it out of view and drives these instead.

        /// <summary>Number of rows currently on show, counting expanded children.</summary>
        public int VisibleNodeCount
        {
            get
            {
                int count = 0;
                TreeNode node = (Nodes.Count > 0) ? Nodes[0] : null;
                while (node != null) { count++; node = node.NextVisibleNode; }
                return count;
            }
        }

        /// <summary>Rows that fit in the client area.</summary>
        public int RowsPerPage
        {
            get
            {
                int rowHeight = Math.Max(1, ItemHeight);
                return Math.Max(1, ClientSize.Height / rowHeight);
            }
        }

        public int TopNodeIndex
        {
            get
            {
                TreeNode top = TopNode;
                if (top == null) return 0;
                int index = 0;
                TreeNode node = (Nodes.Count > 0) ? Nodes[0] : null;
                while (node != null && !ReferenceEquals(node, top)) { index++; node = node.NextVisibleNode; }
                return index;
            }
            set
            {
                int target = Math.Max(0, value);
                TreeNode node = (Nodes.Count > 0) ? Nodes[0] : null;
                for (int i = 0; i < target && node != null; i++) node = node.NextVisibleNode;
                if (node != null) TopNode = node;
            }
        }
    }

    // =========================================================================
    // Menus
    // =========================================================================

    /// <summary>
    /// Renderer for context menus and tool strips.
    /// </summary>
    /// <remarks>
    /// The default professional renderer paints a light "image margin" gutter
    /// down the left of every menu and uses system highlight colours, both of
    /// which look wrong against a dark window and can leave highlighted text
    /// unreadable.
    /// </remarks>
    public class ThemedMenuRenderer : ToolStripProfessionalRenderer
    {
        private readonly ControlTheme _theme;

        public ThemedMenuRenderer(ControlTheme theme)
            : base(new ThemedColorTable(theme != null ? theme : new ControlTheme()))
        {
            _theme = theme != null ? theme : new ControlTheme();
            RoundedEdges = false;
        }

        protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e)
        {
            using (SolidBrush brush = new SolidBrush(_theme.Surface))
                e.Graphics.FillRectangle(brush, e.AffectedBounds);
        }

        protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e)
        {
            using (Pen pen = new Pen(_theme.Border))
                e.Graphics.DrawRectangle(pen, 0, 0,
                    e.ToolStrip.Width - 1, e.ToolStrip.Height - 1);
        }

        protected override void OnRenderImageMargin(ToolStripRenderEventArgs e)
        {
            // Deliberately filled with the menu background instead of the default
            // gradient gutter: nothing here uses icons.
            using (SolidBrush brush = new SolidBrush(_theme.Surface))
                e.Graphics.FillRectangle(brush, e.AffectedBounds);
        }

        protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e)
        {
            Rectangle bounds = new Rectangle(2, 0, e.Item.Width - 4, e.Item.Height);

            if (!e.Item.Enabled) return;

            if (e.Item.Selected || (e.Item as ToolStripMenuItem) != null && ((ToolStripMenuItem)e.Item).DropDown.Visible)
            {
                using (SolidBrush brush = new SolidBrush(_theme.Selection))
                    e.Graphics.FillRectangle(brush, bounds);
            }
        }

        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
        {
            // The base renderer picks a system colour here, which is what made
            // the highlighted item unreadable.
            if (!e.Item.Enabled) e.TextColor = _theme.TextDisabled;
            else if (e.Item.Selected) e.TextColor = _theme.Text;
            else e.TextColor = _theme.Text;
            base.OnRenderItemText(e);
        }

        protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e)
        {
            int y = e.Item.Height / 2;
            using (Pen pen = new Pen(_theme.Border))
                e.Graphics.DrawLine(pen, 8, y, e.Item.Width - 8, y);
        }

        protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e)
        {
            e.ArrowColor = _theme.TextMuted;
            base.OnRenderArrow(e);
        }
    }

    internal sealed class ThemedColorTable : ProfessionalColorTable
    {
        private readonly ControlTheme _theme;
        public ThemedColorTable(ControlTheme theme) { _theme = theme; UseSystemColors = false; }

        public override Color ToolStripDropDownBackground { get { return _theme.Surface; } }
        public override Color MenuBorder { get { return _theme.Border; } }
        public override Color MenuItemBorder { get { return _theme.Selection; } }
        public override Color MenuItemSelected { get { return _theme.Selection; } }
        public override Color MenuItemSelectedGradientBegin { get { return _theme.Selection; } }
        public override Color MenuItemSelectedGradientEnd { get { return _theme.Selection; } }
        public override Color MenuItemPressedGradientBegin { get { return _theme.Selection; } }
        public override Color MenuItemPressedGradientEnd { get { return _theme.Selection; } }
        public override Color ImageMarginGradientBegin { get { return _theme.Surface; } }
        public override Color ImageMarginGradientMiddle { get { return _theme.Surface; } }
        public override Color ImageMarginGradientEnd { get { return _theme.Surface; } }
        public override Color SeparatorDark { get { return _theme.Border; } }
        public override Color SeparatorLight { get { return _theme.Border; } }
    }

    // =========================================================================
    // Scroll bar
    // =========================================================================

    /// <summary>
    /// A slim vertical scroll bar drawn in theme colours.
    /// </summary>
    /// <remarks>
    /// WinForms' VScrollBar is a system control: it ignores BackColor entirely
    /// and stays light, which beside a dark terminal is the most obvious thing
    /// left on screen. The public surface mirrors VScrollBar so it can be used
    /// in its place.
    /// </remarks>
    public sealed class ThinScrollBar : Control
    {
        private ControlTheme _theme = new ControlTheme();
        private int _minimum;
        private int _maximum = 100;
        private int _value;
        private int _largeChange = 10;
        private int _smallChange = 1;

        private bool _hover;
        private bool _dragging;
        private int _dragOffset;

        public event EventHandler ValueChanged;

        public ThinScrollBar()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            Width = 12;
            Dock = DockStyle.Right;
        }

        public void ApplyTheme(ControlTheme theme)
        {
            if (theme == null) return;
            _theme = theme;
            Invalidate();
        }

        public int Minimum
        {
            get { return _minimum; }
            set { _minimum = value; Clamp(); Invalidate(); }
        }

        public int Maximum
        {
            get { return _maximum; }
            set { _maximum = value; Clamp(); Invalidate(); }
        }

        public int LargeChange
        {
            get { return _largeChange; }
            set { _largeChange = Math.Max(1, value); Clamp(); Invalidate(); }
        }

        public int SmallChange
        {
            get { return _smallChange; }
            set { _smallChange = Math.Max(1, value); }
        }

        public int Value
        {
            get { return _value; }
            set
            {
                int next = value;
                if (next < _minimum) next = _minimum;
                if (next > ValueLimit) next = ValueLimit;
                if (next == _value) return;
                _value = next;
                Invalidate();
                EventHandler h = ValueChanged;
                if (h != null) h(this, EventArgs.Empty);
            }
        }

        /// <summary>Highest settable value: the last page starts here.</summary>
        private int ValueLimit
        {
            get { return Math.Max(_minimum, _maximum - _largeChange + 1); }
        }

        private void Clamp()
        {
            if (_maximum < _minimum) _maximum = _minimum;
            if (_value > ValueLimit) _value = ValueLimit;
            if (_value < _minimum) _value = _minimum;
        }

        private int Range { get { return Math.Max(1, ValueLimit - _minimum); } }

        private Rectangle ThumbBounds
        {
            get
            {
                int track = Math.Max(1, Height);
                int span = Math.Max(1, _maximum - _minimum + 1);
                int thumb = (int)(track * (_largeChange / (float)span));
                int minThumb = Math.Max(24, Width * 2);
                if (thumb < minThumb) thumb = minThumb;
                if (thumb > track) thumb = track;

                float fraction = (_value - _minimum) / (float)Range;
                int top = (int)((track - thumb) * fraction);
                return new Rectangle(0, top, Width, thumb);
            }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            using (SolidBrush brush = new SolidBrush(_theme.Background))
                g.FillRectangle(brush, ClientRectangle);

            if (_maximum - _minimum < _largeChange) return;   // nothing to scroll

            g.SmoothingMode = SmoothingMode.AntiAlias;

            Rectangle thumb = ThumbBounds;
            int inset = _hover || _dragging ? 2 : 3;
            Rectangle visual = new Rectangle(
                thumb.Left + inset, thumb.Top + 2,
                Math.Max(2, thumb.Width - inset * 2), Math.Max(6, thumb.Height - 4));

            Color colour = (_hover || _dragging) ? _theme.BorderStrong : _theme.Border;
            using (SolidBrush brush = new SolidBrush(colour))
            using (GraphicsPath path = RoundedRect(visual, visual.Width / 2f))
                g.FillPath(brush, path);

            g.SmoothingMode = SmoothingMode.None;
        }

        private static GraphicsPath RoundedRect(Rectangle r, float radius)
        {
            GraphicsPath path = new GraphicsPath();
            float d = Math.Max(1f, radius * 2f);
            if (d > r.Height) d = r.Height;
            if (d > r.Width) d = r.Width;
            path.AddArc(r.Left, r.Top, d, d, 180, 90);
            path.AddArc(r.Right - d, r.Top, d, d, 270, 90);
            path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            path.AddArc(r.Left, r.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }

        protected override void OnMouseEnter(EventArgs e) { base.OnMouseEnter(e); _hover = true; Invalidate(); }
        protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); _hover = false; Invalidate(); }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            if (e.Button != MouseButtons.Left) return;

            Rectangle thumb = ThumbBounds;
            if (thumb.Contains(e.Location))
            {
                _dragging = true;
                _dragOffset = e.Y - thumb.Top;
            }
            else
            {
                // Clicking the track pages toward the click, as a scroll bar should.
                Value += (e.Y < thumb.Top) ? -_largeChange : _largeChange;
            }
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            if (!_dragging) return;

            int track = Math.Max(1, Height - ThumbBounds.Height);
            float fraction = (e.Y - _dragOffset) / (float)track;
            if (fraction < 0) fraction = 0;
            if (fraction > 1) fraction = 1;
            Value = _minimum + (int)Math.Round(fraction * Range);
        }

        protected override void OnMouseUp(MouseEventArgs e)
        {
            base.OnMouseUp(e);
            _dragging = false;
            Invalidate();
        }
    }

    // =========================================================================
    // Native helpers
    // =========================================================================

    public static class NativeTheme
    {
        internal const int WM_PAINT = 0x000F;
        internal const int WM_PRINT = 0x0317;
        internal const int WM_PRINTCLIENT = 0x0318;
        internal const int WS_EX_COMPOSITED = 0x02000000;

        private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
        private const int DWMWA_USE_IMMERSIVE_DARK_MODE_PRE_20H1 = 19;

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
        private static extern int SetWindowTheme(IntPtr hwnd, string appName, string idList);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetProcessDpiAwarenessContext(IntPtr value);

        [DllImport("shcore.dll", SetLastError = true)]
        private static extern int SetProcessDpiAwareness(int awareness);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetProcessDPIAware();

        // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
        private static readonly IntPtr PerMonitorAwareV2 = new IntPtr(-4);
        private const int ProcessPerMonitorDpiAware = 2;

        /// <summary>
        /// Declare the process DPI aware, and report which level was accepted.
        /// </summary>
        /// <remarks>
        /// Without this Windows renders the window at 96 DPI and bitmap-stretches
        /// the result, so every glyph is resampled: text looks soft and subpixel
        /// antialiasing is destroyed. It is the single biggest thing affecting how
        /// the interface looks on a scaled display.
        ///
        /// Must be called before the process creates its first window. Windows
        /// PowerShell cannot do this through Application.SetHighDpiMode, which
        /// only exists on .NET Core, and a script host has no application
        /// manifest to declare it in - hence the direct calls, newest first.
        /// </remarks>
        public static string EnableDpiAwareness()
        {
            try
            {
                if (SetProcessDpiAwarenessContext(PerMonitorAwareV2)) return "per-monitor-v2";
            }
            catch (EntryPointNotFoundException) { }
            catch (DllNotFoundException) { }

            try
            {
                if (SetProcessDpiAwareness(ProcessPerMonitorDpiAware) == 0) return "per-monitor";
            }
            catch (EntryPointNotFoundException) { }
            catch (DllNotFoundException) { }

            try
            {
                if (SetProcessDPIAware()) return "system";
            }
            catch (EntryPointNotFoundException) { }
            catch (DllNotFoundException) { }

            return "none";
        }

        /// <summary>
        /// The font Windows itself uses for UI. Taking it from the system rather
        /// than naming a face and size is what makes the interface follow the
        /// user's display scaling and text-size settings.
        /// </summary>
        public static Font GetUiFont()
        {
            try
            {
                if (SystemFonts.MessageBoxFont != null)
                    return (Font)SystemFonts.MessageBoxFont.Clone();
            }
            catch (Exception) { }

            try { return new Font("Segoe UI", 9f); }
            catch (Exception) { return new Font(FontFamily.GenericSansSerif, 9f); }
        }

        /// <summary>
        /// Scale factor derived from the UI font rather than from a DPI reading.
        ///
        /// Segoe UI 9pt is 15px tall at 100%. Deriving the factor from the font
        /// the system actually handed us works whether the process is DPI aware
        /// (the font comes back larger) or not (Windows scales the whole window
        /// and the factor correctly stays 1).
        /// </summary>
        public static float GetScale(Font font)
        {
            if (font == null) return 1f;
            float scale = font.Height / 15f;
            if (scale < 1f) scale = 1f;
            if (scale > 4f) scale = 4f;
            return scale;
        }

        public static void SetDarkTitleBar(Form form, bool dark)
        {
            if (form == null || !form.IsHandleCreated) return;
            int value = dark ? 1 : 0;
            try
            {
                if (DwmSetWindowAttribute(form.Handle, DWMWA_USE_IMMERSIVE_DARK_MODE, ref value, sizeof(int)) != 0)
                    DwmSetWindowAttribute(form.Handle, DWMWA_USE_IMMERSIVE_DARK_MODE_PRE_20H1, ref value, sizeof(int));
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }
        }

        /// <summary>
        /// Ask for the dark variant of a control's scroll bars. This is the one
        /// piece that cannot be drawn here, because the scroll bars belong to the
        /// control's own window. It is a no-op where the theme does not exist.
        /// </summary>
        public static void UseDarkScrollBars(Control control)
        {
            if (control == null || !control.IsHandleCreated) return;
            try { SetWindowTheme(control.Handle, "DarkMode_Explorer", null); }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }
        }
    }
}
