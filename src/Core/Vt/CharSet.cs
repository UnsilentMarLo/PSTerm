// PSTerm - CharSet.cs
// DEC national and Special Graphics character sets, plus character width.
//
// The Special Graphics set is why vendor equipment menus (Cisco, HP, DEC-style
// setup screens) rendered as letter soup in PSTerm v1: those UIs draw their
// boxes by shifting into the line-drawing set with SO/SI or ESC ( 0, and v1's
// regex stripper discarded the shift and left the raw ASCII behind.
//
// C# 5 only - see Cell.cs for why.

namespace PSTerm.Vt
{
    public enum CharSetId
    {
        UsAscii,        // ESC ( B
        DecSpecial,     // ESC ( 0  - line drawing
        Uk,             // ESC ( A
        DecSupplemental,// ESC ( <
        DecTechnical    // ESC ( >
    }

    public static class CharSets
    {
        /// <summary>
        /// DEC Special Graphics: ASCII 0x5F..0x7E map to line-drawing and symbol glyphs.
        /// Index 0 corresponds to 0x5F.
        /// </summary>
        private static readonly char[] DecSpecialGraphics = new char[]
        {
            ' ', // _ blank
            '◆', // ` diamond
            '▒', // a checkerboard / shaded block
            '␉', // b HT symbol
            '␌', // c FF symbol
            '␍', // d CR symbol
            '␊', // e LF symbol
            '°', // f degree
            '±', // g plus/minus
            '␤', // h NL symbol
            '␋', // i VT symbol
            '┘', // j lower-right corner
            '┐', // k upper-right corner
            '┌', // l upper-left corner
            '└', // m lower-left corner
            '┼', // n crossing lines
            '⎺', // o horizontal scan line 1
            '⎻', // p horizontal scan line 3
            '─', // q horizontal line
            '⎼', // r horizontal scan line 7
            '⎽', // s horizontal scan line 9
            '├', // t left tee
            '┤', // u right tee
            '┴', // v bottom tee
            '┬', // w top tee
            '│', // x vertical line
            '≤', // y less than or equal
            '≥', // z greater than or equal
            'π', // { pi
            '≠', // | not equal
            '£', // } sterling
            '·'  // ~ centered dot
        };

        public static CharSetId FromDesignator(char designator)
        {
            switch (designator)
            {
                case '0':
                case '2': return CharSetId.DecSpecial;
                case 'A': return CharSetId.Uk;
                case '<': return CharSetId.DecSupplemental;
                case '>': return CharSetId.DecTechnical;
                default: return CharSetId.UsAscii;
            }
        }

        /// <summary>Translate a printable character through the active character set.</summary>
        public static char Translate(char ch, CharSetId set)
        {
            switch (set)
            {
                case CharSetId.DecSpecial:
                    if (ch >= 0x5F && ch <= 0x7E) return DecSpecialGraphics[ch - 0x5F];
                    return ch;

                case CharSetId.Uk:
                    // The only difference from ASCII: # becomes the sterling sign.
                    if (ch == '#') return '£';
                    return ch;

                default:
                    return ch;
            }
        }
    }

    public static class CharWidth
    {
        /// <summary>
        /// True for East Asian Wide and Fullwidth characters, which occupy two cells.
        /// Covers the ranges that actually occur in terminal output; this is not a
        /// complete Unicode table but handles CJK, Hangul, Kana and fullwidth forms.
        /// </summary>
        public static bool IsWide(char ch)
        {
            int c = ch;
            if (c < 0x1100) return false;

            return (c >= 0x1100 && c <= 0x115F) ||   // Hangul Jamo initial
                   (c >= 0x2E80 && c <= 0x303E) ||   // CJK radicals, Kangxi, CJK symbols
                   (c >= 0x3041 && c <= 0x33FF) ||   // Hiragana .. CJK compatibility
                   (c >= 0x3400 && c <= 0x4DBF) ||   // CJK extension A
                   (c >= 0x4E00 && c <= 0x9FFF) ||   // CJK unified ideographs
                   (c >= 0xA000 && c <= 0xA4CF) ||   // Yi
                   (c >= 0xAC00 && c <= 0xD7A3) ||   // Hangul syllables
                   (c >= 0xF900 && c <= 0xFAFF) ||   // CJK compatibility ideographs
                   (c >= 0xFE10 && c <= 0xFE19) ||   // Vertical forms
                   (c >= 0xFE30 && c <= 0xFE6F) ||   // CJK compatibility forms
                   (c >= 0xFF00 && c <= 0xFF60) ||   // Fullwidth forms
                   (c >= 0xFFE0 && c <= 0xFFE6);     // Fullwidth signs
        }

        /// <summary>
        /// True for zero-width characters: combining marks and format controls.
        /// These attach to the preceding cell rather than advancing the cursor.
        /// </summary>
        public static bool IsZeroWidth(char ch)
        {
            int c = ch;
            if (c == 0x200B || c == 0x200C || c == 0x200D) return true; // ZWSP/ZWNJ/ZWJ
            if (c == 0xFEFF) return true;                               // BOM / ZWNBSP
            return (c >= 0x0300 && c <= 0x036F) ||   // combining diacriticals
                   (c >= 0x1AB0 && c <= 0x1AFF) ||
                   (c >= 0x1DC0 && c <= 0x1DFF) ||
                   (c >= 0x20D0 && c <= 0x20FF) ||   // combining marks for symbols
                   (c >= 0xFE00 && c <= 0xFE0F) ||   // variation selectors
                   (c >= 0xFE20 && c <= 0xFE2F);     // combining half marks
        }
    }
}
