// PSTerm - FieldFrame.cs
// A text box in a frame of its own, so it can be any height.
//
// A single-line TextBox takes its height from its font and ignores attempts to
// make it taller, which left the quick-connect bar and the session search box
// shorter than the buttons beside them. This is a themed frame of whatever height
// the layout wants, with an unbordered TextBox centred inside it.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Drawing;
using System.Windows.Forms;

namespace PSTerm.Render
{
    public sealed class FieldFrame : Control
    {
        private readonly TextBox _input = new TextBox();
        private ControlTheme _theme = new ControlTheme();
        private bool _focused;

        public FieldFrame()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            _input.BorderStyle = BorderStyle.None;
            _input.GotFocus += delegate { _focused = true; Invalidate(); };
            _input.LostFocus += delegate { _focused = false; Invalidate(); };
            Controls.Add(_input);
            TabStop = false;
        }

        /// <summary>The text box inside. Subscribe to its events and read its Text.</summary>
        public TextBox Input { get { return _input; } }

        public void ApplyTheme(ControlTheme theme)
        {
            if (theme == null) return;
            _theme = theme;
            _input.BackColor = theme.Field;
            BackColor = theme.Field;
            Invalidate();
        }

        protected override void OnFontChanged(EventArgs e)
        {
            base.OnFontChanged(e);
            _input.Font = Font;
            PlaceInput();
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            PlaceInput();
        }

        private void PlaceInput()
        {
            int pad = Math.Max(6, Font.Height / 2);
            _input.Font = Font;
            _input.Left = pad;
            _input.Width = Math.Max(10, Width - pad * 2);
            _input.Top = Math.Max(0, (Height - _input.Height) / 2);
        }

        protected override void OnGotFocus(EventArgs e)
        {
            base.OnGotFocus(e);
            _input.Focus();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            using (SolidBrush back = new SolidBrush(_theme.Field))
                e.Graphics.FillRectangle(back, ClientRectangle);
            using (Pen pen = new Pen(_focused ? _theme.Accent : _theme.Border))
                e.Graphics.DrawRectangle(pen, 0, 0, Width - 1, Height - 1);
        }
    }
}
