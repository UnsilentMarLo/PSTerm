// PSTerm - StreamDecoder.cs
// Stateful byte -> char decoding for the session stream.
//
// PSTerm v1 called Encoding.UTF8.GetString() on each 4 KB read, which corrupts
// any multi-byte sequence that happens to straddle a read boundary - the cause
// of intermittent mojibake on busy sessions. A Decoder carries the partial
// sequence across calls, so a character split over two reads still arrives intact.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Text;

namespace PSTerm.Vt
{
    /// <summary>How raw session bytes are turned into text.</summary>
    public enum TerminalEncoding
    {
        /// <summary>UTF-8, with invalid bytes shown as U+FFFD rather than dropped.</summary>
        Utf8,
        /// <summary>ISO-8859-1: every byte maps to the code point of the same value.
        /// The safe choice for equipment that emits raw 8-bit data.</summary>
        Latin1,
        /// <summary>Strict 7-bit; the high bit is stripped. Some legacy gear needs this.</summary>
        Ascii,
        /// <summary>The system's OEM code page, for DOS-era devices drawing CP437 boxes.</summary>
        Oem
    }

    public sealed class StreamDecoder
    {
        private Encoding _encoding;
        private Decoder _decoder;
        private TerminalEncoding _kind;
        private char[] _charBuffer = new char[8192];

        public StreamDecoder(TerminalEncoding kind)
        {
            SetEncoding(kind);
        }

        public TerminalEncoding Kind { get { return _kind; } }

        public void SetEncoding(TerminalEncoding kind)
        {
            _kind = kind;
            switch (kind)
            {
                case TerminalEncoding.Latin1:
                    _encoding = Encoding.GetEncoding(28591);
                    break;
                case TerminalEncoding.Ascii:
                    _encoding = Encoding.ASCII;
                    break;
                case TerminalEncoding.Oem:
                    try { _encoding = Encoding.GetEncoding(437); }
                    catch (ArgumentException) { _encoding = Encoding.GetEncoding(28591); }
                    break;
                default:
                    // Replacement fallback: a malformed byte becomes U+FFFD instead of
                    // throwing or silently vanishing, so a corrupt line stays readable.
                    _encoding = Encoding.GetEncoding(
                        "utf-8",
                        EncoderFallback.ReplacementFallback,
                        DecoderFallback.ReplacementFallback);
                    break;
            }
            _decoder = _encoding.GetDecoder();
        }

        /// <summary>Discard any partial multi-byte sequence. Call on reconnect.</summary>
        public void Reset()
        {
            _decoder.Reset();
        }

        /// <summary>
        /// Decode a chunk. The returned array is reused between calls; consume it
        /// before the next call. <paramref name="charCount"/> receives the length.
        /// </summary>
        public char[] Decode(byte[] bytes, int offset, int count, out int charCount)
        {
            int needed = _encoding.GetMaxCharCount(count);
            if (_charBuffer.Length < needed) _charBuffer = new char[needed];
            charCount = _decoder.GetChars(bytes, offset, count, _charBuffer, 0, false);
            return _charBuffer;
        }

        /// <summary>Encode text for sending back to the host.</summary>
        public byte[] Encode(string text)
        {
            if (_kind == TerminalEncoding.Ascii)
            {
                // Map anything non-ASCII to '?' rather than emitting a multi-byte
                // sequence a 7-bit device cannot interpret.
                byte[] outBytes = new byte[text.Length];
                for (int i = 0; i < text.Length; i++)
                {
                    char c = text[i];
                    outBytes[i] = c < 0x80 ? (byte)c : (byte)'?';
                }
                return outBytes;
            }
            return _encoding.GetBytes(text);
        }
    }
}
