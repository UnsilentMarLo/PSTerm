// PSTerm - FontProbe.cs
// Finds the installed fixed-pitch font families once, off the UI thread.
//
// The profile editor lists them, and finding them means creating and measuring
// every installed family. Done in a PowerShell loop on the UI thread that cost
// several seconds each time a dialog opened and froze the whole window. Here it
// is compiled code, run once on a background thread at start-up, with the result
// cached for every later dialog.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Text;
using System.Threading;
using System.Windows.Forms;

namespace PSTerm.Render
{
    public static class FontProbe
    {
        private static readonly object Gate = new object();
        private static string[] _cached;
        private static Thread _worker;

        /// <summary>Begin the search in the background. Cheap to call repeatedly.</summary>
        public static void Warm()
        {
            lock (Gate)
            {
                if (_cached != null || _worker != null) return;
                _worker = new Thread(delegate() { Compute(); });
                _worker.IsBackground = true;
                _worker.Name = "PSTerm font probe";
                _worker.Start();
            }
        }

        /// <summary>
        /// The fixed-pitch families, sorted. Returns the cached list at once when the
        /// background search has finished; otherwise waits for it, which is no worse
        /// than doing the work here.
        /// </summary>
        public static string[] GetMonospaceFamilies()
        {
            Thread worker;
            lock (Gate)
            {
                if (_cached != null) return _cached;
                worker = _worker;
            }

            if (worker != null) worker.Join();
            else Compute();

            lock (Gate) { return _cached ?? new string[] { "Consolas" }; }
        }

        private static void Compute()
        {
            List<string> found = new List<string>();
            try
            {
                using (InstalledFontCollection collection = new InstalledFontCollection())
                {
                    Size box = new Size(1000, 100);
                    TextFormatFlags flags = TextFormatFlags.NoPadding;

                    foreach (FontFamily family in collection.Families)
                    {
                        try
                        {
                            if (!family.IsStyleAvailable(FontStyle.Regular)) continue;

                            // A proportional face makes the grid unusable, so measure two
                            // glyphs of very different width and keep only families where
                            // they match.
                            using (Font font = new Font(family, 10))
                            {
                                int wide = TextRenderer.MeasureText("W", font, box, flags).Width;
                                int thin = TextRenderer.MeasureText("i", font, box, flags).Width;
                                if (wide == thin) found.Add(family.Name);
                            }
                        }
                        catch (Exception) { }
                    }
                }
            }
            catch (Exception) { }

            if (found.Count == 0) found.Add("Consolas");
            found.Sort(StringComparer.OrdinalIgnoreCase);

            lock (Gate) { _cached = found.ToArray(); }
        }
    }
}
