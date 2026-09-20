// PSTerm - KeyEncoder.cs
// Turns key presses into the bytes a terminal actually sends.
//
// PSTerm v1 had three separate, mutually inconsistent key maps (Backspace was
// 0x08 on Serial/Telnet but 0x7F on SSH, Home/End sent sequences no terminal
// uses, F-keys and modifiers did not exist) and it stole Escape for "quit", so
// ESC could never reach the device. This is one correct map, with the handful of
// switches that real equipment actually disagrees about exposed as settings.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Text;

namespace PSTerm.Vt
{
    /// <summary>UI-independent key identity, so this layer never references WinForms.</summary>
    public enum TermKey
    {
        None,
        Char,
        Up, Down, Right, Left,
        Home, End, Insert, Delete, PageUp, PageDown,
        Backspace, Tab, Enter, Escape, Space,
        F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12,
        F13, F14, F15, F16, F17, F18, F19, F20,
        // Numeric keypad, which differs in application keypad mode.
        KeypadEnter, KeypadPlus, KeypadMinus, KeypadStar, KeypadSlash, KeypadDot,
        Keypad0, Keypad1, Keypad2, Keypad3, Keypad4,
        Keypad5, Keypad6, Keypad7, Keypad8, Keypad9
    }

    [Flags]
    public enum TermModifiers
    {
        None = 0,
        Shift = 1,
        Alt = 2,
        Control = 4
    }

    /// <summary>What Backspace sends. The single most common source of
    /// "my backspace prints ^H on this box" complaints.</summary>
    public enum BackspaceMode
    {
        /// <summary>0x7F. Correct for Linux, most modern gear, and xterm's default.</summary>
        Delete,
        /// <summary>0x08. Correct for many Cisco IOS, DOS and legacy serial devices.</summary>
        Backspace
    }

    /// <summary>Which encoding the function keys use.</summary>
    public enum FunctionKeyMode
    {
        /// <summary>xterm: F1-F4 send SS3 P..S. The broadest-compatibility default.</summary>
        Xterm,
        /// <summary>VT220: F1-F4 send CSI 11~..14~. Needed by some DEC-lineage equipment.</summary>
        Vt220,
        /// <summary>Linux console: F1-F5 send CSI [A..[E.</summary>
        LinuxConsole
    }

    public sealed class KeyEncoderSettings
    {
        public BackspaceMode Backspace = BackspaceMode.Delete;
        public FunctionKeyMode FunctionKeys = FunctionKeyMode.Xterm;
        /// <summary>When true Alt+key sends ESC before the key (xterm "meta sends escape").</summary>
        public bool AltSendsEscape = true;
        /// <summary>Swap the effect of Backspace and Ctrl+Backspace.</summary>
        public bool CtrlBackspaceSendsOpposite = true;
        /// <summary>Send CR LF instead of CR for Enter. Rarely wanted outside raw serial.</summary>
        public bool EnterSendsCrLf = false;
    }

    public sealed class KeyEncoder
    {
        private readonly KeyEncoderSettings _settings;

        public KeyEncoder(KeyEncoderSettings settings)
        {
            _settings = settings != null ? settings : new KeyEncoderSettings();
        }

        public KeyEncoderSettings Settings { get { return _settings; } }

        /// <summary>
        /// Encode a key press. Returns null when the key produces no output, which
        /// lets the caller treat it as a local shortcut instead.
        /// </summary>
        public string Encode(TermKey key, char ch, TermModifiers mods, bool applicationCursor, bool applicationKeypad)
        {
            bool ctrl = (mods & TermModifiers.Control) != 0;
            bool alt = (mods & TermModifiers.Alt) != 0;
            bool shift = (mods & TermModifiers.Shift) != 0;

            string body = EncodeCore(key, ch, mods, applicationCursor, applicationKeypad);
            if (body == null) return null;

            // Alt/Meta prefixes the sequence with ESC. Applied last so it also
            // covers function keys and control characters.
            if (alt && _settings.AltSendsEscape && body.Length > 0 && body[0] != '\x1b')
                return "\x1b" + body;

            return body;
        }

        private string EncodeCore(TermKey key, char ch, TermModifiers mods, bool appCursor, bool appKeypad)
        {
            bool ctrl = (mods & TermModifiers.Control) != 0;
            bool shift = (mods & TermModifiers.Shift) != 0;

            switch (key)
            {
                case TermKey.Char:
                    return EncodeChar(ch, ctrl);

                case TermKey.Space:
                    // Ctrl+Space is the conventional way to send NUL.
                    return ctrl ? "\0" : " ";

                case TermKey.Enter:
                    if (ctrl) return "\n";
                    return _settings.EnterSendsCrLf ? "\r\n" : "\r";

                case TermKey.Tab:
                    if (shift) return "\x1b[Z";          // CBT / back-tab
                    return "\t";

                case TermKey.Escape:
                    // Escape is an ordinary key that reaches the device. v1 stole it for "quit".
                    return "\x1b";

                case TermKey.Backspace:
                    {
                        bool useDelete = _settings.Backspace == BackspaceMode.Delete;
                        if (ctrl && _settings.CtrlBackspaceSendsOpposite) useDelete = !useDelete;
                        return useDelete ? "\x7f" : "\b";
                    }

                // ---- cursor keys: SS3 in application mode, CSI otherwise ----
                case TermKey.Up: return CursorKey('A', mods, appCursor);
                case TermKey.Down: return CursorKey('B', mods, appCursor);
                case TermKey.Right: return CursorKey('C', mods, appCursor);
                case TermKey.Left: return CursorKey('D', mods, appCursor);
                case TermKey.Home: return CursorKey('H', mods, appCursor);
                case TermKey.End: return CursorKey('F', mods, appCursor);

                // ---- editing keys: always the CSI n ~ form ----
                case TermKey.Insert: return TildeKey(2, mods);
                case TermKey.Delete: return TildeKey(3, mods);
                case TermKey.PageUp: return TildeKey(5, mods);
                case TermKey.PageDown: return TildeKey(6, mods);

                // ---- function keys ----
                case TermKey.F1: return FunctionKey(1, mods);
                case TermKey.F2: return FunctionKey(2, mods);
                case TermKey.F3: return FunctionKey(3, mods);
                case TermKey.F4: return FunctionKey(4, mods);
                case TermKey.F5: return TildeKey(15, mods);
                case TermKey.F6: return TildeKey(17, mods);
                case TermKey.F7: return TildeKey(18, mods);
                case TermKey.F8: return TildeKey(19, mods);
                case TermKey.F9: return TildeKey(20, mods);
                case TermKey.F10: return TildeKey(21, mods);
                case TermKey.F11: return TildeKey(23, mods);
                case TermKey.F12: return TildeKey(24, mods);
                case TermKey.F13: return TildeKey(25, mods);
                case TermKey.F14: return TildeKey(26, mods);
                case TermKey.F15: return TildeKey(28, mods);
                case TermKey.F16: return TildeKey(29, mods);
                case TermKey.F17: return TildeKey(31, mods);
                case TermKey.F18: return TildeKey(32, mods);
                case TermKey.F19: return TildeKey(33, mods);
                case TermKey.F20: return TildeKey(34, mods);

                // ---- keypad ----
                case TermKey.KeypadEnter: return appKeypad ? "\x1bOM" : (_settings.EnterSendsCrLf ? "\r\n" : "\r");
                case TermKey.KeypadPlus: return appKeypad ? "\x1bOk" : "+";
                case TermKey.KeypadMinus: return appKeypad ? "\x1bOm" : "-";
                case TermKey.KeypadStar: return appKeypad ? "\x1bOj" : "*";
                case TermKey.KeypadSlash: return appKeypad ? "\x1bOo" : "/";
                case TermKey.KeypadDot: return appKeypad ? "\x1bOn" : ".";
                case TermKey.Keypad0: return appKeypad ? "\x1bOp" : "0";
                case TermKey.Keypad1: return appKeypad ? "\x1bOq" : "1";
                case TermKey.Keypad2: return appKeypad ? "\x1bOr" : "2";
                case TermKey.Keypad3: return appKeypad ? "\x1bOs" : "3";
                case TermKey.Keypad4: return appKeypad ? "\x1bOt" : "4";
                case TermKey.Keypad5: return appKeypad ? "\x1bOu" : "5";
                case TermKey.Keypad6: return appKeypad ? "\x1bOv" : "6";
                case TermKey.Keypad7: return appKeypad ? "\x1bOw" : "7";
                case TermKey.Keypad8: return appKeypad ? "\x1bOx" : "8";
                case TermKey.Keypad9: return appKeypad ? "\x1bOy" : "9";

                default:
                    return null;
            }
        }

        /// <summary>
        /// Ctrl+letter maps to the matching control code. The punctuation cases are
        /// the ones people actually rely on: Ctrl+[ to escape, Ctrl+] for telnet,
        /// Ctrl+\ to quit, Ctrl+_ for undo in emacs.
        /// </summary>
        private static string EncodeChar(char ch, bool ctrl)
        {
            if (!ctrl) return ch.ToString();

            if (ch >= 'a' && ch <= 'z') return ((char)(ch - 'a' + 1)).ToString();
            if (ch >= 'A' && ch <= 'Z') return ((char)(ch - 'A' + 1)).ToString();

            switch (ch)
            {
                case '@': case ' ': return "\0";
                case '[': return "\x1b";
                case '\\': return "\x1c";
                case ']': return "\x1d";
                case '^': case '6': return "\x1e";
                case '_': case '-': case '/': return "\x1f";
                case '?': return "\x7f";
                case '2': return "\0";
                case '3': return "\x1b";
                case '4': return "\x1c";
                case '5': return "\x1d";
                case '7': case '8': return "\x1f";
            }
            // Ctrl with a key that has no control code sends the plain character.
            return ch.ToString();
        }

        /// <summary>
        /// xterm modifier parameter: 1 + (shift 1, alt 2, ctrl 4).
        /// Returns 1 when no modifier is held, which callers treat as "omit".
        /// </summary>
        private static int ModifierParam(TermModifiers mods)
        {
            int m = 1;
            if ((mods & TermModifiers.Shift) != 0) m += 1;
            if ((mods & TermModifiers.Alt) != 0) m += 2;
            if ((mods & TermModifiers.Control) != 0) m += 4;
            return m;
        }

        private string CursorKey(char final, TermModifiers mods, bool appCursor)
        {
            int m = ModifierParam(mods);

            // Alt is delivered as an ESC prefix by Encode(), so it must not also
            // appear in the modifier parameter.
            if (_settings.AltSendsEscape && (mods & TermModifiers.Alt) != 0)
                m -= 2;

            if (m > 1)
            {
                // Modified cursor keys always use the CSI form, even in application mode.
                return "\x1b[1;" + m.ToString() + final;
            }
            return appCursor ? ("\x1bO" + final) : ("\x1b[" + final);
        }

        private string TildeKey(int number, TermModifiers mods)
        {
            int m = ModifierParam(mods);
            if (_settings.AltSendsEscape && (mods & TermModifiers.Alt) != 0) m -= 2;

            if (m > 1)
                return "\x1b[" + number.ToString() + ";" + m.ToString() + "~";
            return "\x1b[" + number.ToString() + "~";
        }

        private string FunctionKey(int n, TermModifiers mods)
        {
            int m = ModifierParam(mods);
            if (_settings.AltSendsEscape && (mods & TermModifiers.Alt) != 0) m -= 2;

            switch (_settings.FunctionKeys)
            {
                case FunctionKeyMode.Vt220:
                    return TildeKey(10 + n, mods);   // F1..F4 -> CSI 11~..14~

                case FunctionKeyMode.LinuxConsole:
                    return "\x1b[" + ((char)('A' + n - 1)).ToString();

                default:
                    {
                        char final = (char)('P' + n - 1);   // P Q R S
                        if (m > 1) return "\x1b[1;" + m.ToString() + final.ToString();
                        return "\x1bO" + final.ToString();
                    }
            }
        }

        /// <summary>
        /// Encode a mouse event for the active reporting mode. Returns null when
        /// mouse reporting is off or the event is not reportable.
        /// </summary>
        public static string EncodeMouse(MouseMode mode, MouseEncoding encoding,
                                         int button, bool press, int col, int row,
                                         TermModifiers mods)
        {
            if (mode == MouseMode.Off) return null;

            int b = button;
            if ((mods & TermModifiers.Shift) != 0) b += 4;
            if ((mods & TermModifiers.Alt) != 0) b += 8;
            if ((mods & TermModifiers.Control) != 0) b += 16;

            int c = col + 1;
            int r = row + 1;

            if (encoding == MouseEncoding.Sgr)
            {
                // SGR (1006) is the only encoding that works past column 223, which is
                // why it is preferred whenever the host enables it.
                return "\x1b[<" + b.ToString() + ";" + c.ToString() + ";" + r.ToString() +
                       (press ? "M" : "m");
            }

            if (encoding == MouseEncoding.Urxvt)
            {
                return "\x1b[" + (b + 32).ToString() + ";" + c.ToString() + ";" + r.ToString() + "M";
            }

            // X10/UTF-8: coordinates are offset by 32 and cannot exceed 223.
            if (!press) b = 3;
            if (c > 223 || r > 223) return null;
            StringBuilder sb = new StringBuilder(6);
            sb.Append('\x1b').Append('[').Append('M');
            sb.Append((char)(b + 32));
            sb.Append((char)(c + 32));
            sb.Append((char)(r + 32));
            return sb.ToString();
        }
    }
}
