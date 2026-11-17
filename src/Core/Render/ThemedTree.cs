// PSTerm - ThemedTree.cs
// The session list: a tree drawn in theme colours, with the interactions a list of
// connections needs - a chevron that folds a folder with one click, hover buttons
// (add a connection to a folder, pin a connection), drag and drop, and right-click
// that selects what it is over.
//
// TreeView paints its selection highlight, expander glyphs and scroll bars with the
// system visual style and ignores BackColor, so a dark panel ends up with a white
// selection bar and a white scroll bar. Everything inside the client area is drawn
// here; the horizontal scroll bar is suppressed outright with TVS_NOHSCROLL and
// long labels are ellipsised instead, which is better behaviour for a session list
// anyway.
//
// Node tags carry what a node is, as text: "p:<id>" a connection, "f:<path>" a
// folder, "pin:" the Pinned section, "ports:" the detected-ports section and
// "com:<name>" a port inside it. The host builds them; this class only reads the
// prefix to know which buttons to offer.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace PSTerm.Render
{
    public class TreeNodeEventArgs : EventArgs
    {
        public readonly TreeNode Node;
        public readonly Point ScreenLocation;
        public TreeNodeEventArgs(TreeNode node, Point screenLocation) { Node = node; ScreenLocation = screenLocation; }
    }

    public class TreeDropEventArgs : EventArgs
    {
        public readonly TreeNode Source;
        /// <summary>The node under the pointer, or null for the empty area.</summary>
        public readonly TreeNode Target;
        /// <summary>Set by the host in DropQuery: whether the drop would be accepted.</summary>
        public bool Allowed;
        public TreeDropEventArgs(TreeNode source, TreeNode target) { Source = source; Target = target; }
    }

    public class TreeButtonEventArgs : EventArgs
    {
        public readonly TreeNode Node;
        /// <summary>"add" on a folder, "pin" on a connection.</summary>
        public readonly string Button;
        public TreeButtonEventArgs(TreeNode node, string button) { Node = node; Button = button; }
    }

    public class ThemedTreeView : TreeView
    {
        private const int TVS_NOHSCROLL = 0x8000;
        private const int WM_VSCROLL = 0x0115;

        [DllImport("user32.dll")]
        private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

        private ControlTheme _theme = new ControlTheme();
        private TreeNode _hotNode;
        private string _hotButton;
        private TreeNode _dropTarget;
        private bool _blockToggle;
        private readonly ThemedToolTip _tips = new ThemedToolTip();
        private string _shownTip;

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

        /// <summary>Ids of pinned connections, so their pin shows filled.</summary>
        public readonly HashSet<string> PinnedIds = new HashSet<string>();

        public event EventHandler<TreeNodeEventArgs> NodeContext;
        public event EventHandler<TreeButtonEventArgs> NodeButtonClicked;
        public event EventHandler<TreeDropEventArgs> DropQuery;
        public event EventHandler<TreeDropEventArgs> DropCompleted;

        public ThemedTreeView()
        {
            DrawMode = TreeViewDrawMode.OwnerDrawAll;
            FullRowSelect = true;
            HideSelection = false;
            ShowLines = false;
            ShowRootLines = false;
            ShowPlusMinus = false;     // the chevron is drawn and handled here
            BorderStyle = BorderStyle.None;
            AllowDrop = true;
            ShowNodeToolTips = false;
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
            _tips.Apply(theme);
            BackColor = theme.Surface;
            ForeColor = theme.Text;
            LineColor = theme.Border;
            Invalidate();
        }

        // =====================================================================
        // What a node is
        // =====================================================================

        private static string TagOf(TreeNode node)
        {
            return node != null && node.Tag != null ? node.Tag.ToString() : "";
        }

        public static bool IsFolder(TreeNode node) { return TagOf(node).StartsWith("f:", StringComparison.Ordinal); }
        public static bool IsProfile(TreeNode node) { return TagOf(node).StartsWith("p:", StringComparison.Ordinal); }
        public static bool IsSection(TreeNode node)
        {
            string t = TagOf(node);
            return t == "pin:" || t == "ports:";
        }

        // =====================================================================
        // Geometry
        // =====================================================================

        private int VisibleRight { get { return Width - RightInset; } }
        private int ButtonSize { get { return Math.Max(16, ItemHeight - 6); } }

        private Rectangle ChevronRect(TreeNode node)
        {
            int indent = Indent * node.Level;
            int size = Math.Max(10, ItemHeight / 2);
            return new Rectangle(indent + (Indent - size) / 2, node.Bounds.Top + (ItemHeight - size) / 2, size, size);
        }

        private Rectangle ButtonRect(TreeNode node)
        {
            int size = ButtonSize;
            return new Rectangle(VisibleRight - size - 6, node.Bounds.Top + (ItemHeight - size) / 2, size, size);
        }

        private string ButtonFor(TreeNode node)
        {
            if (IsFolder(node)) return "add";
            if (IsProfile(node)) return "pin";
            return null;
        }

        private bool ButtonVisible(TreeNode node)
        {
            string button = ButtonFor(node);
            if (button == null) return false;
            if (ReferenceEquals(node, _hotNode) || ReferenceEquals(node, SelectedNode)) return true;
            // A pinned connection always shows its pin.
            return button == "pin" && PinnedIds.Contains(TagOf(node).Substring(2));
        }

        // =====================================================================
        // Drawing
        // =====================================================================

        protected override void OnDrawNode(DrawTreeNodeEventArgs e)
        {
            e.DrawDefault = false;
            if (e.Node == null || e.Bounds.Height <= 0) return;

            Graphics g = e.Graphics;
            TreeNode node = e.Node;
            Rectangle row = new Rectangle(0, e.Bounds.Top, VisibleRight, e.Bounds.Height);

            bool selected = (e.State & TreeNodeStates.Selected) != 0;
            bool hot = ReferenceEquals(node, _hotNode);
            bool folder = IsFolder(node);
            bool section = IsSection(node);

            Color back = selected ? _theme.Selection : (hot ? _theme.FieldHover : _theme.Surface);
            using (SolidBrush brush = new SolidBrush(back))
                g.FillRectangle(brush, row);

            // The row a drag would land on.
            if (ReferenceEquals(node, _dropTarget))
            {
                using (SolidBrush tint = new SolidBrush(Color.FromArgb(70, _theme.Accent)))
                    g.FillRectangle(tint, row);
                using (Pen pen = new Pen(_theme.Accent, 2f))
                    g.DrawRectangle(pen, row.Left + 1, row.Top + 1, row.Width - 3, row.Height - 3);
            }

            int indent = Indent * node.Level;
            int textLeft = indent + Indent;

            if (node.Nodes.Count > 0)
                DrawChevron(g, ChevronRect(node), node.IsExpanded, selected ? _theme.Text : _theme.TextMuted);

            // A leading glyph for the special sections.
            if (section)
            {
                string glyph = TagOf(node) == "pin:" ? "" : "";
                IconFont.Draw(g, glyph, TagOf(node) == "pin:" ? "*" : "#",
                    new Rectangle(textLeft - 2, row.Top, ItemHeight - 4, row.Height), _theme.Accent, ItemHeight * 0.5f);
                textLeft += ItemHeight - 4;
            }
            else if (TagOf(node).StartsWith("com:", StringComparison.Ordinal))
            {
                IconFont.Draw(g, "", "#", new Rectangle(textLeft - 2, row.Top, ItemHeight - 4, row.Height),
                    _theme.Success, ItemHeight * 0.5f);
                textLeft += ItemHeight - 4;
            }

            Color fore = selected ? _theme.Text : ((folder || section) ? _theme.TextMuted : _theme.Text);

            int right = VisibleRight - 8;
            if (ButtonVisible(node)) right = ButtonRect(node).Left - 4;

            Rectangle textBounds = new Rectangle(textLeft, e.Bounds.Top, Math.Max(10, right - textLeft), e.Bounds.Height);
            TextRenderer.DrawText(g, node.Text, section ? BoldFont() : Font, textBounds, fore,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter |
                TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis);

            if (ButtonVisible(node)) DrawButton(g, node);
        }

        private Font _bold;
        private Font BoldFont()
        {
            if (_bold == null || _bold.FontFamily.Name != Font.FontFamily.Name)
            {
                if (_bold != null) _bold.Dispose();
                _bold = new Font(Font, FontStyle.Bold);
            }
            return _bold;
        }

        private void DrawButton(Graphics g, TreeNode node)
        {
            Rectangle r = ButtonRect(node);
            string button = ButtonFor(node);
            bool over = ReferenceEquals(node, _hotNode) && _hotButton == button;

            if (over)
            {
                using (SolidBrush brush = new SolidBrush(_theme.Border))
                using (GraphicsPath path = Round(r, 4))
                {
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    g.FillPath(brush, path);
                    g.SmoothingMode = SmoothingMode.None;
                }
            }

            Color ink = over ? _theme.Text : _theme.TextMuted;
            if (button == "add")
            {
                IconFont.Draw(g, "", "+", r, ink, r.Height * 0.6f);
            }
            else
            {
                bool pinned = PinnedIds.Contains(TagOf(node).Substring(2));
                // Filled pin when pinned (E840), outline otherwise (E718).
                IconFont.Draw(g, pinned ? "" : "", pinned ? "*" : "o", r,
                    pinned ? _theme.Accent : ink, r.Height * 0.6f);
            }
        }

        private static GraphicsPath Round(Rectangle r, int radius)
        {
            GraphicsPath path = new GraphicsPath();
            int d = radius * 2;
            path.AddArc(r.Left, r.Top, d, d, 180, 90);
            path.AddArc(r.Right - d, r.Top, d, d, 270, 90);
            path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            path.AddArc(r.Left, r.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }

        private static void DrawChevron(Graphics g, Rectangle bounds, bool expanded, Color colour)
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

        // =====================================================================
        // Mouse
        // =====================================================================

        private TreeNode NodeAtRow(Point p)
        {
            // GetNodeAt(0, y) would miss a click right of the text; rows are full width.
            return GetNodeAt(0, p.Y);
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            TreeNode node = NodeAtRow(e.Location);
            string button = null;
            if (node != null && ButtonFor(node) != null && ButtonVisible(node) && ButtonRect(node).Contains(e.Location))
                button = ButtonFor(node);

            if (!ReferenceEquals(node, _hotNode) || button != _hotButton)
            {
                _hotNode = node;
                _hotButton = button;
                Invalidate();

                string tip = null;
                if (button == "add") tip = "New connection in this folder";
                else if (button == "pin") tip = PinnedIds.Contains(TagOf(node).Substring(2)) ? "Unpin this connection" : "Pin this connection";
                if (tip != _shownTip)
                {
                    _tips.Hide(this);
                    _shownTip = tip;
                    if (tip != null) _tips.ShowAt(this, tip, new Point(Math.Max(0, e.X - 40), node.Bounds.Bottom + 2));
                }
            }
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            if (_hotNode != null) { _hotNode = null; _hotButton = null; Invalidate(); }
            _tips.Hide(this);
            _shownTip = null;
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            TreeNode node = NodeAtRow(e.Location);

            if (node != null && e.Button == MouseButtons.Right)
            {
                SelectedNode = node;
                base.OnMouseDown(e);
                return;
            }

            if (node != null && e.Button == MouseButtons.Left)
            {
                // The chevron folds on a single click. The native double-click that
                // can follow would fold it straight back, so that one is swallowed.
                if (node.Nodes.Count > 0 && ChevronHit(node, e.Location))
                {
                    if (e.Clicks == 1) { if (node.IsExpanded) node.Collapse(); else node.Expand(); }
                    else _blockToggle = true;
                    SelectedNode = node;
                    return;
                }

                if (ButtonFor(node) != null && ButtonVisible(node) && ButtonRect(node).Contains(e.Location))
                {
                    SelectedNode = node;
                    EventHandler<TreeButtonEventArgs> h = NodeButtonClicked;
                    if (h != null) h(this, new TreeButtonEventArgs(node, ButtonFor(node)));
                    return;
                }
            }

            base.OnMouseDown(e);
        }

        private bool ChevronHit(TreeNode node, Point p)
        {
            Rectangle r = ChevronRect(node);
            r.Inflate(Indent / 2, 0);
            return r.Contains(p);
        }

        protected override void OnBeforeExpand(TreeViewCancelEventArgs e)
        {
            if (_blockToggle) { e.Cancel = true; _blockToggle = false; return; }
            base.OnBeforeExpand(e);
        }

        protected override void OnBeforeCollapse(TreeViewCancelEventArgs e)
        {
            if (_blockToggle) { e.Cancel = true; _blockToggle = false; return; }
            base.OnBeforeCollapse(e);
        }

        protected override void OnMouseUp(MouseEventArgs e)
        {
            base.OnMouseUp(e);
            _blockToggle = false;

            if (e.Button == MouseButtons.Right)
            {
                EventHandler<TreeNodeEventArgs> h = NodeContext;
                if (h != null) h(this, new TreeNodeEventArgs(NodeAtRow(e.Location), PointToScreen(e.Location)));
            }
        }

        // =====================================================================
        // Drag and drop
        // =====================================================================

        protected override void OnItemDrag(ItemDragEventArgs e)
        {
            base.OnItemDrag(e);
            TreeNode node = e.Item as TreeNode;
            if (node == null || e.Button != MouseButtons.Left) return;
            // Sections and detected ports are not the operator's to move.
            if (!IsProfile(node) && !IsFolder(node)) return;

            SelectedNode = node;
            DoDragDrop(node, DragDropEffects.Move);
            SetDropTarget(null);
        }

        protected override void OnDragOver(DragEventArgs e)
        {
            base.OnDragOver(e);

            TreeNode source = e.Data.GetData(typeof(TreeNode)) as TreeNode;
            if (source == null) { e.Effect = DragDropEffects.None; return; }

            Point client = PointToClient(new Point(e.X, e.Y));
            AutoScroll(client);

            TreeNode target = NodeAtRow(client);
            TreeDropEventArgs args = new TreeDropEventArgs(source, target);
            EventHandler<TreeDropEventArgs> query = DropQuery;
            if (query != null) query(this, args);

            if (args.Allowed)
            {
                e.Effect = DragDropEffects.Move;
                SetDropTarget(target);
                // Hovering a closed folder opens it, so a drop can reach what is inside.
                if (target != null && IsFolder(target) && !target.IsExpanded && target.Nodes.Count > 0)
                {
                    DateTime now = DateTime.UtcNow;
                    if (!ReferenceEquals(_hoverFolder, target)) { _hoverFolder = target; _hoverSince = now; }
                    else if ((now - _hoverSince).TotalMilliseconds > 700) target.Expand();
                }
            }
            else
            {
                e.Effect = DragDropEffects.None;
                SetDropTarget(null);
            }
        }

        private TreeNode _hoverFolder;
        private DateTime _hoverSince;

        protected override void OnDragLeave(EventArgs e)
        {
            base.OnDragLeave(e);
            SetDropTarget(null);
        }

        protected override void OnDragDrop(DragEventArgs e)
        {
            base.OnDragDrop(e);
            TreeNode source = e.Data.GetData(typeof(TreeNode)) as TreeNode;
            Point client = PointToClient(new Point(e.X, e.Y));
            TreeNode target = NodeAtRow(client);
            SetDropTarget(null);
            if (source == null) return;

            TreeDropEventArgs args = new TreeDropEventArgs(source, target);
            EventHandler<TreeDropEventArgs> query = DropQuery;
            if (query != null) query(this, args);
            if (!args.Allowed) return;

            EventHandler<TreeDropEventArgs> done = DropCompleted;
            if (done != null) done(this, args);
        }

        private void SetDropTarget(TreeNode node)
        {
            if (ReferenceEquals(node, _dropTarget)) return;
            _dropTarget = node;
            Invalidate();
        }

        /// <summary>Scroll while a drag is held near the top or bottom edge.</summary>
        private void AutoScroll(Point client)
        {
            int edge = ItemHeight;
            if (client.Y < edge) SendMessage(Handle, WM_VSCROLL, (IntPtr)0, IntPtr.Zero);          // SB_LINEUP
            else if (client.Y > ClientSize.Height - edge) SendMessage(Handle, WM_VSCROLL, (IntPtr)1, IntPtr.Zero);   // SB_LINEDOWN
        }

        // =====================================================================
        // Scrolling
        // =====================================================================
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

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _tips.Dispose();
                if (_bold != null) _bold.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
