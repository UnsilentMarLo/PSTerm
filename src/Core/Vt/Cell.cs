// PSTerm - Cell.cs
// One character cell of the terminal grid.
//
// NOTE: this project targets C# 5 so that Add-Type can compile it with the
// .NET Framework CodeDom compiler under Windows PowerShell 5.1. Do not use
// string interpolation, null-conditional operators, expression-bodied members,
// nameof, auto-property initializers or tuples anywhere in src/Core.

using System;

namespace PSTerm.Vt
{
    /// <summary>Text attribute flags. Colours are stored separately on the cell.</summary>
    [Flags]
    public enum CellFlags : ushort
    {
        None = 0,
        Bold = 1 << 0,
        Faint = 1 << 1,
        Italic = 1 << 2,
        Underline = 1 << 3,
        Blink = 1 << 4,
        Inverse = 1 << 5,
        Invisible = 1 << 6,
        Strikethrough = 1 << 7,
        DoubleUnderline = 1 << 8,
        /// <summary>Left half of a double-width (CJK) glyph.</summary>
        WideLead = 1 << 9,
        /// <summary>Right half of a double-width glyph; carries no glyph of its own.</summary>
        WideTrail = 1 << 10,
        /// <summary>Cell was written by the DEC Special Graphics set (already translated).</summary>
        FromLineDrawing = 1 << 11,
        /// <summary>Cell is part of a hyperlink (OSC 8).</summary>
        Hyperlink = 1 << 12
    }

    /// <summary>
    /// A colour slot. Either a palette index (0-255) or a 24-bit RGB value, or
    /// "default" meaning the theme's foreground/background should be used.
    /// Packed into a single int so a Cell stays small and blittable.
    /// </summary>
    public struct Color : IEquatable<Color>
    {
        // Encoding: kind in the high byte, value in the low 24 bits.
        private const int KindDefault = 0;
        private const int KindIndexed = 1;
        private const int KindRgb = 2;

        private readonly int _packed;

        private Color(int kind, int value)
        {
            _packed = (kind << 24) | (value & 0xFFFFFF);
        }

        public static readonly Color Default = new Color(KindDefault, 0);

        public static Color FromIndex(int index)
        {
            if (index < 0) index = 0;
            if (index > 255) index = 255;
            return new Color(KindIndexed, index);
        }

        public static Color FromRgb(int r, int g, int b)
        {
            return new Color(KindRgb, ((r & 0xFF) << 16) | ((g & 0xFF) << 8) | (b & 0xFF));
        }

        public bool IsDefault { get { return (_packed >> 24) == KindDefault; } }
        public bool IsIndexed { get { return (_packed >> 24) == KindIndexed; } }
        public bool IsRgb { get { return (_packed >> 24) == KindRgb; } }

        public int Index { get { return _packed & 0xFFFFFF; } }
        public int R { get { return (_packed >> 16) & 0xFF; } }
        public int G { get { return (_packed >> 8) & 0xFF; } }
        public int B { get { return _packed & 0xFF; } }

        public bool Equals(Color other) { return _packed == other._packed; }
        public override bool Equals(object obj) { return obj is Color && Equals((Color)obj); }
        public override int GetHashCode() { return _packed; }
        public static bool operator ==(Color a, Color b) { return a._packed == b._packed; }
        public static bool operator !=(Color a, Color b) { return a._packed != b._packed; }
    }

    /// <summary>
    /// A single grid cell. Kept as a struct in a flat array: for an 80x25 screen with
    /// 10k scrollback that is ~8 MB, and it avoids per-cell GC pressure entirely.
    /// </summary>
    public struct Cell : IEquatable<Cell>
    {
        public char Ch;
        public Color Fg;
        public Color Bg;
        public CellFlags Flags;
        /// <summary>Index into the screen's hyperlink table, or 0 for none.</summary>
        public ushort LinkId;

        public static readonly Cell Empty = MakeEmpty();

        private static Cell MakeEmpty()
        {
            Cell c = new Cell();
            c.Ch = ' ';
            c.Fg = Color.Default;
            c.Bg = Color.Default;
            c.Flags = CellFlags.None;
            c.LinkId = 0;
            return c;
        }

        /// <summary>A blank cell carrying the given pen, used when erasing with SGR background set.</summary>
        public static Cell Blank(Color fg, Color bg, CellFlags flags)
        {
            Cell c = new Cell();
            c.Ch = ' ';
            c.Fg = fg;
            c.Bg = bg;
            // Erased cells keep colour and inverse/underline-style background-affecting bits only.
            c.Flags = flags & (CellFlags.Inverse | CellFlags.Blink);
            c.LinkId = 0;
            return c;
        }

        public bool HasSameAttributes(Cell other)
        {
            return Fg == other.Fg && Bg == other.Bg && Flags == other.Flags && LinkId == other.LinkId;
        }

        public bool Equals(Cell other)
        {
            return Ch == other.Ch && HasSameAttributes(other);
        }

        public override bool Equals(object obj) { return obj is Cell && Equals((Cell)obj); }

        public override int GetHashCode()
        {
            return Ch.GetHashCode() ^ Fg.GetHashCode() ^ (Bg.GetHashCode() << 1) ^ ((int)Flags << 2);
        }
    }
}
