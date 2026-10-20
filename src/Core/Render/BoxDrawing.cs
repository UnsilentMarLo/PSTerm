// PSTerm - BoxDrawing.cs
// Draws Unicode box-drawing and block characters geometrically instead of as
// glyphs.
//
// Why bother: a font's box-drawing glyphs are designed for the em box, not for
// the terminal's cell, so at most sizes the vertical strokes stop short of the
// cell edge and a drawn table shows hairline gaps at every row boundary. That
// matters here more than in a general terminal, because equipment menus - the
// exact output PSTerm is meant to handle well - are drawn almost entirely out of
// these characters. Drawing them to the cell rectangle makes the joins exact at
// any font, size and DPI, and also covers fonts that lack the glyphs entirely.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Drawing;
using System.Drawing.Drawing2D;

namespace PSTerm.Render
{
    public static class BoxDrawing
    {
        // Stroke weights at each compass point of a cell.
        private const byte N = 0;   // none
        private const byte L = 1;   // light
        private const byte H = 2;   // heavy
        private const byte D = 3;   // double

        /// <summary>
        /// Line weights for U+2500..U+256C as (up, right, down, left).
        /// Index is codepoint - 0x2500. Entries left at zero are handled
        /// separately or fall back to the font.
        /// </summary>
        private static readonly byte[,] LineTable = BuildLineTable();

        private static byte[,] BuildLineTable()
        {
            byte[,] t = new byte[0x80, 4];

            // Helper is not available in a static initialiser in C# 5, so the
            // table is filled positionally: [index, 0]=up, 1=right, 2=down, 3=left.
            Action<int, byte, byte, byte, byte> set = delegate(int cp, byte up, byte right, byte down, byte left)
            {
                int i = cp - 0x2500;
                t[i, 0] = up; t[i, 1] = right; t[i, 2] = down; t[i, 3] = left;
            };

            // Straight lines
            set(0x2500, N, L, N, L);   // ─
            set(0x2501, N, H, N, H);   // ━
            set(0x2502, L, N, L, N);   // │
            set(0x2503, H, N, H, N);   // ┃

            // Corners, light and heavy mixes (U+250C..U+251F)
            set(0x250C, N, L, L, N);   // ┌
            set(0x250D, N, H, L, N);
            set(0x250E, N, L, H, N);
            set(0x250F, N, H, H, N);
            set(0x2510, N, N, L, L);   // ┐
            set(0x2511, N, N, L, H);
            set(0x2512, N, N, H, L);
            set(0x2513, N, N, H, H);
            set(0x2514, L, L, N, N);   // └
            set(0x2515, L, H, N, N);
            set(0x2516, H, L, N, N);
            set(0x2517, H, H, N, N);
            set(0x2518, L, N, N, L);   // ┘
            set(0x2519, L, N, N, H);
            set(0x251A, H, N, N, L);
            set(0x251B, H, N, N, H);

            // Left tee (U+251C..U+2523)
            set(0x251C, L, L, L, N);   // ├
            set(0x251D, L, H, L, N);
            set(0x251E, H, L, L, N);
            set(0x251F, L, L, H, N);
            set(0x2520, H, L, H, N);
            set(0x2521, H, H, L, N);
            set(0x2522, L, H, H, N);
            set(0x2523, H, H, H, N);

            // Right tee (U+2524..U+252B)
            set(0x2524, L, N, L, L);   // ┤
            set(0x2525, L, N, L, H);
            set(0x2526, H, N, L, L);
            set(0x2527, L, N, H, L);
            set(0x2528, H, N, H, L);
            set(0x2529, H, N, L, H);
            set(0x252A, L, N, H, H);
            set(0x252B, H, N, H, H);

            // Top tee (U+252C..U+2533)
            set(0x252C, N, L, L, L);   // ┬
            set(0x252D, N, L, L, H);
            set(0x252E, N, H, L, L);
            set(0x252F, N, H, L, H);
            set(0x2530, N, L, H, L);
            set(0x2531, N, L, H, H);
            set(0x2532, N, H, H, L);
            set(0x2533, N, H, H, H);

            // Bottom tee (U+2534..U+253B)
            set(0x2534, L, L, N, L);   // ┴
            set(0x2535, L, L, N, H);
            set(0x2536, L, H, N, L);
            set(0x2537, L, H, N, H);
            set(0x2538, H, L, N, L);
            set(0x2539, H, L, N, H);
            set(0x253A, H, H, N, L);
            set(0x253B, H, H, N, H);

            // Cross (U+253C..U+254B)
            set(0x253C, L, L, L, L);   // ┼
            set(0x253D, L, L, L, H);
            set(0x253E, L, H, L, L);
            set(0x253F, L, H, L, H);
            set(0x2540, H, L, L, L);
            set(0x2541, L, L, H, L);
            set(0x2542, H, L, H, L);
            set(0x2543, H, L, L, H);
            set(0x2544, H, H, L, L);
            set(0x2545, L, L, H, H);
            set(0x2546, L, H, H, L);
            set(0x2547, H, H, L, H);
            set(0x2548, L, H, H, H);
            set(0x2549, H, L, H, H);
            set(0x254A, H, H, H, L);
            set(0x254B, H, H, H, H);

            // Double lines (U+2550..U+256C)
            set(0x2550, N, D, N, D);   // ═
            set(0x2551, D, N, D, N);   // ║
            set(0x2552, N, D, L, N);
            set(0x2553, N, L, D, N);
            set(0x2554, N, D, D, N);   // ╔
            set(0x2555, N, N, L, D);
            set(0x2556, N, N, D, L);
            set(0x2557, N, N, D, D);   // ╗
            set(0x2558, L, D, N, N);
            set(0x2559, D, L, N, N);
            set(0x255A, D, D, N, N);   // ╚
            set(0x255B, L, N, N, D);
            set(0x255C, D, N, N, L);
            set(0x255D, D, N, N, D);   // ╝
            set(0x255E, L, D, L, N);
            set(0x255F, D, L, D, N);
            set(0x2560, D, D, D, N);   // ╠
            set(0x2561, L, N, L, D);
            set(0x2562, D, N, D, L);
            set(0x2563, D, N, D, D);   // ╣
            set(0x2564, N, D, L, D);
            set(0x2565, N, L, D, L);
            set(0x2566, N, D, D, D);   // ╦
            set(0x2567, L, D, N, D);
            set(0x2568, D, L, N, L);
            set(0x2569, D, D, N, D);   // ╩
            set(0x256A, L, D, L, D);
            set(0x256B, D, L, D, L);
            set(0x256C, D, D, D, D);   // ╬

            // Half lines (U+2574..U+257B)
            set(0x2574, N, N, N, L);   // ╴
            set(0x2575, L, N, N, N);   // ╵
            set(0x2576, N, L, N, N);   // ╶
            set(0x2577, N, N, L, N);   // ╷
            set(0x2578, N, N, N, H);
            set(0x2579, H, N, N, N);
            set(0x257A, N, H, N, N);
            set(0x257B, N, N, H, N);

            // Mixed light/heavy straight lines
            set(0x257C, N, H, N, L);   // ╼
            set(0x257D, L, N, H, N);   // ╽
            set(0x257E, N, L, N, H);   // ╾
            set(0x257F, H, N, L, N);   // ╿

            return t;
        }

        /// <summary>True when this character is drawn here rather than by the font.</summary>
        public static bool IsBoxDrawing(char ch)
        {
            int c = ch;
            if (c >= 0x2500 && c <= 0x257F) return true;   // box drawing
            if (c >= 0x2580 && c <= 0x259F) return true;   // block elements
            return false;
        }

        /// <summary>
        /// Draw one box-drawing or block character into <paramref name="cell"/>.
        /// Returns false when the character is not one this can draw, so the
        /// caller can fall back to the font.
        /// </summary>
        public static bool Draw(Graphics g, char ch, Rectangle cell, Color color)
        {
            int c = ch;

            if (c >= 0x2580 && c <= 0x259F) return DrawBlock(g, c, cell, color);

            if (c < 0x2500 || c > 0x257F) return false;

            // Dashed lines: drawn as their solid equivalents with a dash pattern.
            if (c >= 0x2504 && c <= 0x250B) return DrawDashed(g, c, cell, color);

            // Rounded corners
            if (c >= 0x256D && c <= 0x2570) return DrawRoundedCorner(g, c, cell, color);

            // Diagonals
            if (c >= 0x2571 && c <= 0x2573) return DrawDiagonal(g, c, cell, color);

            int index = c - 0x2500;
            byte up = LineTable[index, 0];
            byte right = LineTable[index, 1];
            byte down = LineTable[index, 2];
            byte left = LineTable[index, 3];

            if (up == 0 && right == 0 && down == 0 && left == 0) return false;

            DrawLines(g, cell, color, up, right, down, left);
            return true;
        }

        private static float LightWidth(Rectangle cell)
        {
            // Roughly a tenth of the cell, at least one pixel, and odd-ish so the
            // stroke sits centred on the cell midline.
            return Math.Max(1f, (float)Math.Round(cell.Height / 12.0));
        }

        private static float HeavyWidth(Rectangle cell)
        {
            return Math.Max(2f, LightWidth(cell) * 2f);
        }

        private static void DrawLines(Graphics g, Rectangle cell, Color color,
                                      byte up, byte right, byte down, byte left)
        {
            // Snapped to whole pixels: anti-aliased half-pixel strokes look soft
            // and, worse, leave visible seams where cells meet.
            SmoothingMode saved = g.SmoothingMode;
            g.SmoothingMode = SmoothingMode.None;

            float cx = cell.Left + cell.Width / 2f;
            float cy = cell.Top + cell.Height / 2f;

            using (SolidBrush brush = new SolidBrush(color))
            {
                DrawArm(g, brush, cell, cx, cy, up, 0, true);
                DrawArm(g, brush, cell, cx, cy, down, 1, true);
                DrawArm(g, brush, cell, cx, cy, left, 2, false);
                DrawArm(g, brush, cell, cx, cy, right, 3, false);
            }

            g.SmoothingMode = saved;
        }

        /// <summary>
        /// Draw one arm from the cell centre to an edge. Arms always run to the
        /// edge, which is what makes adjacent cells join without a seam.
        /// </summary>
        private static void DrawArm(Graphics g, Brush brush, Rectangle cell,
                                    float cx, float cy, byte weight, int direction, bool vertical)
        {
            if (weight == 0) return;

            float thickness = (weight == H) ? HeavyWidth(cell) : LightWidth(cell);

            if (weight == D)
            {
                // A double line is two light strokes either side of the centre.
                float light = LightWidth(cell);
                float gap = Math.Max(light, (float)Math.Round(cell.Height / 8.0));
                DrawArmStroke(g, brush, cell, cx - gap, cy - gap, light, direction, vertical);
                DrawArmStroke(g, brush, cell, cx + gap, cy + gap, light, direction, vertical);
                return;
            }

            DrawArmStroke(g, brush, cell, cx, cy, thickness, direction, vertical);
        }

        private static void DrawArmStroke(Graphics g, Brush brush, Rectangle cell,
                                          float cx, float cy, float thickness,
                                          int direction, bool vertical)
        {
            int t = Math.Max(1, (int)Math.Round(thickness));

            if (vertical)
            {
                int x = (int)Math.Round(cx - t / 2f);
                if (direction == 0)      // up: from the top edge down to the centre
                    g.FillRectangle(brush, x, cell.Top, t, (int)Math.Round(cy) - cell.Top + t);
                else                      // down
                    g.FillRectangle(brush, x, (int)Math.Round(cy), t, cell.Bottom - (int)Math.Round(cy));
            }
            else
            {
                int y = (int)Math.Round(cy - t / 2f);
                if (direction == 2)      // left
                    g.FillRectangle(brush, cell.Left, y, (int)Math.Round(cx) - cell.Left + t, t);
                else                      // right
                    g.FillRectangle(brush, (int)Math.Round(cx), y, cell.Right - (int)Math.Round(cx), t);
            }
        }

        private static bool DrawDashed(Graphics g, int codepoint, Rectangle cell, Color color)
        {
            // 2504-2507 are horizontal (triple/quadruple dash), 2508-250B vertical.
            bool horizontal = codepoint <= 0x2507;
            bool heavy = (codepoint == 0x2505 || codepoint == 0x2507 ||
                          codepoint == 0x2509 || codepoint == 0x250B);
            int dashes = (codepoint == 0x2504 || codepoint == 0x2505 ||
                          codepoint == 0x2508 || codepoint == 0x2509) ? 3 : 4;

            float thickness = heavy ? HeavyWidth(cell) : LightWidth(cell);
            int t = Math.Max(1, (int)Math.Round(thickness));

            using (SolidBrush brush = new SolidBrush(color))
            {
                if (horizontal)
                {
                    int y = cell.Top + cell.Height / 2 - t / 2;
                    float segment = cell.Width / (float)(dashes * 2 - 1);
                    for (int i = 0; i < dashes; i++)
                    {
                        int x = cell.Left + (int)(i * segment * 2);
                        g.FillRectangle(brush, x, y, (int)Math.Ceiling(segment), t);
                    }
                }
                else
                {
                    int x = cell.Left + cell.Width / 2 - t / 2;
                    float segment = cell.Height / (float)(dashes * 2 - 1);
                    for (int i = 0; i < dashes; i++)
                    {
                        int y = cell.Top + (int)(i * segment * 2);
                        g.FillRectangle(brush, x, y, t, (int)Math.Ceiling(segment));
                    }
                }
            }
            return true;
        }

        private static bool DrawRoundedCorner(Graphics g, int codepoint, Rectangle cell, Color color)
        {
            float thickness = LightWidth(cell);
            float cx = cell.Left + cell.Width / 2f;
            float cy = cell.Top + cell.Height / 2f;
            float radius = Math.Min(cell.Width, cell.Height) / 2f;

            SmoothingMode saved = g.SmoothingMode;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            using (Pen pen = new Pen(color, thickness))
            using (GraphicsPath path = new GraphicsPath())
            {
                switch (codepoint)
                {
                    case 0x256D: // down and right
                        path.AddArc(cx, cy, radius * 2, radius * 2, 180, 90);
                        path.AddLine(cx + radius, cell.Bottom, cx + radius, cell.Bottom);
                        g.DrawArc(pen, cx - radius, cy, radius * 2, radius * 2, 0, -90);
                        g.DrawLine(pen, cx, cell.Bottom, cx, cy + radius);
                        g.DrawLine(pen, cx + radius, cy, cell.Right, cy);
                        break;
                    case 0x256E: // down and left
                        g.DrawArc(pen, cx - radius, cy, radius * 2, radius * 2, 180, 90);
                        g.DrawLine(pen, cx, cell.Bottom, cx, cy + radius);
                        g.DrawLine(pen, cell.Left, cy, cx - radius, cy);
                        break;
                    case 0x256F: // up and left
                        g.DrawArc(pen, cx - radius, cy - radius * 2, radius * 2, radius * 2, 90, 90);
                        g.DrawLine(pen, cx, cell.Top, cx, cy - radius);
                        g.DrawLine(pen, cell.Left, cy, cx - radius, cy);
                        break;
                    case 0x2570: // up and right
                        g.DrawArc(pen, cx, cy - radius * 2, radius * 2, radius * 2, 90, 90);
                        g.DrawLine(pen, cx, cell.Top, cx, cy - radius);
                        g.DrawLine(pen, cx + radius, cy, cell.Right, cy);
                        break;
                    default:
                        g.SmoothingMode = saved;
                        return false;
                }
            }

            g.SmoothingMode = saved;
            return true;
        }

        private static bool DrawDiagonal(Graphics g, int codepoint, Rectangle cell, Color color)
        {
            SmoothingMode saved = g.SmoothingMode;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            using (Pen pen = new Pen(color, LightWidth(cell)))
            {
                if (codepoint == 0x2571 || codepoint == 0x2573)
                    g.DrawLine(pen, cell.Left, cell.Bottom, cell.Right, cell.Top);
                if (codepoint == 0x2572 || codepoint == 0x2573)
                    g.DrawLine(pen, cell.Left, cell.Top, cell.Right, cell.Bottom);
            }

            g.SmoothingMode = saved;
            return true;
        }

        /// <summary>
        /// Block elements U+2580..U+259F: half blocks, eighth blocks, shades and
        /// quadrants. Drawn as rectangles so progress bars and shaded panels line
        /// up exactly, with no gaps between adjacent cells.
        /// </summary>
        private static bool DrawBlock(Graphics g, int codepoint, Rectangle cell, Color color)
        {
            SmoothingMode saved = g.SmoothingMode;
            g.SmoothingMode = SmoothingMode.None;

            try
            {
                // Shades are drawn by blending toward the background instead of
                // stippling, which stays even at any cell size.
                if (codepoint >= 0x2591 && codepoint <= 0x2593)
                {
                    double alpha = (codepoint == 0x2591) ? 0.25 : (codepoint == 0x2592) ? 0.5 : 0.75;
                    using (SolidBrush brush = new SolidBrush(Color.FromArgb((int)(alpha * 255), color)))
                        g.FillRectangle(brush, cell);
                    return true;
                }

                using (SolidBrush brush = new SolidBrush(color))
                {
                    int w = cell.Width, h = cell.Height;
                    int l = cell.Left, t = cell.Top;

                    // Upper eighths (2580 is the upper half)
                    if (codepoint == 0x2580) { g.FillRectangle(brush, l, t, w, Round(h / 2.0)); return true; }

                    // Lower eighths: 2581 = 1/8 .. 2588 = full
                    if (codepoint >= 0x2581 && codepoint <= 0x2588)
                    {
                        int eighths = codepoint - 0x2580;
                        int height = Round(h * eighths / 8.0);
                        g.FillRectangle(brush, l, cell.Bottom - height, w, height);
                        return true;
                    }

                    // Left eighths: 2589 = 7/8 .. 258F = 1/8
                    if (codepoint >= 0x2589 && codepoint <= 0x258F)
                    {
                        int eighths = 8 - (codepoint - 0x2588);
                        g.FillRectangle(brush, l, t, Round(w * eighths / 8.0), h);
                        return true;
                    }

                    if (codepoint == 0x2590) { int half = Round(w / 2.0); g.FillRectangle(brush, cell.Right - half, t, half, h); return true; }

                    // Right eighths 2594 (upper 1/8) and 2595 (right 1/8)
                    if (codepoint == 0x2594) { g.FillRectangle(brush, l, t, w, Round(h / 8.0)); return true; }
                    if (codepoint == 0x2595) { int e = Round(w / 8.0); g.FillRectangle(brush, cell.Right - e, t, e, h); return true; }
                    if (codepoint == 0x2596) { g.FillRectangle(brush, l, t + h / 2, w / 2, h - h / 2); return true; }
                    if (codepoint == 0x2597) { g.FillRectangle(brush, l + w / 2, t + h / 2, w - w / 2, h - h / 2); return true; }
                    if (codepoint == 0x2598) { g.FillRectangle(brush, l, t, w / 2, h / 2); return true; }
                    if (codepoint == 0x2599) { g.FillRectangle(brush, l, t, w / 2, h); g.FillRectangle(brush, l, t + h / 2, w, h - h / 2); return true; }
                    if (codepoint == 0x259A) { g.FillRectangle(brush, l, t, w / 2, h / 2); g.FillRectangle(brush, l + w / 2, t + h / 2, w - w / 2, h - h / 2); return true; }
                    if (codepoint == 0x259B) { g.FillRectangle(brush, l, t, w, h / 2); g.FillRectangle(brush, l, t, w / 2, h); return true; }
                    if (codepoint == 0x259C) { g.FillRectangle(brush, l, t, w, h / 2); g.FillRectangle(brush, l + w / 2, t, w - w / 2, h); return true; }
                    if (codepoint == 0x259D) { g.FillRectangle(brush, l + w / 2, t, w - w / 2, h / 2); return true; }
                    if (codepoint == 0x259E) { g.FillRectangle(brush, l + w / 2, t, w - w / 2, h / 2); g.FillRectangle(brush, l, t + h / 2, w / 2, h - h / 2); return true; }
                    if (codepoint == 0x259F) { g.FillRectangle(brush, l + w / 2, t, w - w / 2, h); g.FillRectangle(brush, l, t + h / 2, w, h - h / 2); return true; }
                }
                return false;
            }
            finally
            {
                g.SmoothingMode = saved;
            }
        }

        private static int Round(double value)
        {
            int result = (int)Math.Round(value);
            return result < 1 ? 1 : result;
        }
    }
}
