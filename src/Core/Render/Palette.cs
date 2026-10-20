// PSTerm - Palette.cs
// Colour resolution for the terminal grid.
//
// v1 could only express the 16 [ConsoleColor] names. This resolves the full
// xterm 256-colour palette and 24-bit truecolor, with the 16 base colours
// themable.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Drawing;

// PSTerm.Vt also defines a Color (a palette slot, not an RGB value), so the
// namespace is not imported wholesale: inside this file `Color` always means
// System.Drawing.Color and the terminal's own types are brought in by alias.
using Cell = PSTerm.Vt.Cell;
using CellFlags = PSTerm.Vt.CellFlags;
using VtColor = PSTerm.Vt.Color;

namespace PSTerm.Render
{
    public sealed class TerminalPalette
    {
        private readonly Color[] _table = new Color[256];

        public Color Foreground;
        public Color Background;
        public Color CursorColor;
        public Color CursorTextColor;
        public Color SelectionBackground;
        public Color SelectionForeground;

        /// <summary>When true, SGR bold also selects the bright colour variant for
        /// indexed colours 0-7, as most terminals do.</summary>
        public bool BoldIsBright = true;

        /// <summary>Dim SGR 2 by blending toward the background instead of ignoring it.</summary>
        public double FaintAlpha = 0.55;

        public TerminalPalette()
        {
            LoadDefaultDark();
        }

        public Color this[int index]
        {
            get
            {
                if (index < 0) index = 0;
                if (index > 255) index = 255;
                return _table[index];
            }
            set
            {
                if (index >= 0 && index <= 255) _table[index] = value;
            }
        }

        /// <summary>
        /// Fill entries 16-255 with the standard xterm layout: a 6x6x6 colour cube
        /// followed by a 24-step grey ramp. Only 0-15 are theme-defined.
        /// </summary>
        private void FillExtended()
        {
            int[] steps = new int[] { 0, 95, 135, 175, 215, 255 };
            int i = 16;
            for (int r = 0; r < 6; r++)
                for (int g = 0; g < 6; g++)
                    for (int b = 0; b < 6; b++)
                        _table[i++] = Color.FromArgb(steps[r], steps[g], steps[b]);

            for (int s = 0; s < 24; s++)
            {
                int v = 8 + s * 10;
                _table[i++] = Color.FromArgb(v, v, v);
            }
        }

        public void LoadDefaultDark()
        {
            // A balanced dark theme: the ANSI 16 are readable on a near-black
            // background without the eye-watering saturation of the classic VGA set.
            SetBase(
                "#1E1E1E", "#CC3333", "#4FAF4F", "#C7A93B",
                "#3B8EEA", "#B267C9", "#38A8A8", "#CCCCCC",
                "#666666", "#FF5555", "#6FE06F", "#F2D25C",
                "#5BAEFF", "#D08FE6", "#4FD6D6", "#FFFFFF");

            Background = ColorFromHex("#12141A");
            Foreground = ColorFromHex("#D6DAE3");
            CursorColor = ColorFromHex("#E6B450");
            CursorTextColor = ColorFromHex("#12141A");
            SelectionBackground = ColorFromHex("#2F4F7F");
            SelectionForeground = Color.Empty;   // keep the cell's own foreground
            FillExtended();
        }

        public void LoadDefaultLight()
        {
            SetBase(
                "#FFFFFF", "#C41A16", "#007400", "#996800",
                "#0B5FD6", "#9B2393", "#007373", "#3B3B3B",
                "#B0B0B0", "#E0402F", "#1A9E1A", "#C79400",
                "#2E7FE6", "#C048B8", "#12A0A0", "#1A1A1A");

            Background = ColorFromHex("#FBFBFD");
            Foreground = ColorFromHex("#1F2328");
            CursorColor = ColorFromHex("#0B5FD6");
            CursorTextColor = ColorFromHex("#FFFFFF");
            SelectionBackground = ColorFromHex("#B5D5FF");
            SelectionForeground = Color.Empty;
            FillExtended();
        }

        private void SetBase(params string[] hex)
        {
            for (int i = 0; i < 16 && i < hex.Length; i++)
                _table[i] = ColorFromHex(hex[i]);
        }

        public static Color ColorFromHex(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return Color.Black;
            string s = hex.TrimStart('#');
            try
            {
                if (s.Length == 6)
                {
                    return Color.FromArgb(
                        Convert.ToInt32(s.Substring(0, 2), 16),
                        Convert.ToInt32(s.Substring(2, 2), 16),
                        Convert.ToInt32(s.Substring(4, 2), 16));
                }
                if (s.Length == 3)
                {
                    int r = Convert.ToInt32(new string(s[0], 2), 16);
                    int g = Convert.ToInt32(new string(s[1], 2), 16);
                    int b = Convert.ToInt32(new string(s[2], 2), 16);
                    return Color.FromArgb(r, g, b);
                }
            }
            catch (FormatException) { }
            catch (OverflowException) { }
            return Color.Black;
        }

        public static string ColorToHex(Color c)
        {
            return "#" + c.R.ToString("X2") + c.G.ToString("X2") + c.B.ToString("X2");
        }

        /// <summary>
        /// Resolve a cell to concrete foreground and background colours, applying
        /// inverse video, bold-brightening, faint and the screen-wide reverse mode.
        /// </summary>
        public void Resolve(Cell cell, bool screenReversed, out Color fore, out Color back)
        {
            CellFlags flags = cell.Flags;

            fore = ResolveSlot(cell.Fg, true);
            back = ResolveSlot(cell.Bg, false);

            if (BoldIsBright && (flags & CellFlags.Bold) != 0 &&
                cell.Fg.IsIndexed && cell.Fg.Index < 8)
            {
                fore = _table[cell.Fg.Index + 8];
            }

            if ((flags & CellFlags.Faint) != 0)
                fore = Blend(fore, back, FaintAlpha);

            bool inverse = (flags & CellFlags.Inverse) != 0;
            if (screenReversed) inverse = !inverse;
            if (inverse)
            {
                Color tmp = fore;
                fore = back;
                back = tmp;
            }

            if ((flags & CellFlags.Invisible) != 0)
                fore = back;
        }

        private Color ResolveSlot(VtColor slot, bool isForeground)
        {
            if (slot.IsDefault) return isForeground ? Foreground : Background;
            if (slot.IsRgb) return Color.FromArgb(slot.R, slot.G, slot.B);
            return _table[slot.Index];
        }

        public static Color Blend(Color a, Color b, double weightOfA)
        {
            if (weightOfA < 0) weightOfA = 0;
            if (weightOfA > 1) weightOfA = 1;
            double w = weightOfA, iw = 1 - w;
            return Color.FromArgb(
                (int)(a.R * w + b.R * iw),
                (int)(a.G * w + b.G * iw),
                (int)(a.B * w + b.B * iw));
        }

        /// <summary>Relative luminance, used to pick readable overlay colours.</summary>
        public static double Luminance(Color c)
        {
            return (0.2126 * c.R + 0.7152 * c.G + 0.0722 * c.B) / 255.0;
        }
    }
}
