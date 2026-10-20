// PSTerm - VtParser.cs
// DEC ANSI-compatible escape sequence parser, following Paul Williams' state
// machine (vt100.net/emu/dec_ansi_parser).
//
// This replaces the regex-stripping approach of PSTerm v1. The difference
// matters: a state machine consumes malformed, truncated and interleaved
// sequences the way a real terminal does, which is precisely the behaviour that
// makes output from arbitrary vendor equipment render correctly.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Text;

namespace PSTerm.Vt
{
    /// <summary>Receives the parser's decoded events.</summary>
    public interface IVtSink
    {
        /// <summary>A printable character.</summary>
        void Print(char ch);
        /// <summary>A C0 or C1 control character.</summary>
        void Execute(char control);
        /// <summary>ESC with optional intermediates, e.g. ESC ( B.</summary>
        void EscDispatch(string intermediates, char final);
        /// <summary>CSI sequence. Params are -1 where omitted.</summary>
        void CsiDispatch(char prefix, int[] parameters, int paramCount, string intermediates, char final);
        /// <summary>OSC string, already split at the first ';' into code and payload.</summary>
        void OscDispatch(int code, string payload);
        /// <summary>DCS sequence start.</summary>
        void DcsHook(char prefix, int[] parameters, int paramCount, string intermediates, char final);
        /// <summary>DCS payload character.</summary>
        void DcsPut(char ch);
        /// <summary>DCS sequence end.</summary>
        void DcsUnhook();
    }

    public sealed class VtParser
    {
        private enum State
        {
            Ground,
            Escape,
            EscapeIntermediate,
            CsiEntry,
            CsiParam,
            CsiIntermediate,
            CsiIgnore,
            DcsEntry,
            DcsParam,
            DcsIntermediate,
            DcsPassthrough,
            DcsIgnore,
            OscString,
            SosPmApcString
        }

        private const int MaxParams = 32;
        // Guards against a runaway OSC on a noisy serial line eating memory.
        private const int MaxStringLength = 8192;

        private readonly IVtSink _sink;

        private State _state = State.Ground;
        private readonly int[] _params = new int[MaxParams];
        private int _paramCount;
        private bool _paramPending;       // a digit has been seen for the current param
        private char _prefix;             // CSI private marker: < = > ?
        private readonly StringBuilder _intermediates = new StringBuilder(4);
        private readonly StringBuilder _stringBuffer = new StringBuilder(64);
        private bool _stringOverflow;

        public VtParser(IVtSink sink)
        {
            if (sink == null) throw new ArgumentNullException("sink");
            _sink = sink;
        }

        /// <summary>Reset to ground state, abandoning any partial sequence.</summary>
        public void Reset()
        {
            _state = State.Ground;
            Clear();
        }

        private void Clear()
        {
            _paramCount = 0;
            _paramPending = false;
            _prefix = '\0';
            _intermediates.Length = 0;
            _stringBuffer.Length = 0;
            _stringOverflow = false;
            for (int i = 0; i < MaxParams; i++) _params[i] = -1;
        }

        public void Parse(char[] buffer, int offset, int count)
        {
            int end = offset + count;
            for (int i = offset; i < end; i++) Feed(buffer[i]);
        }

        public void Parse(string s)
        {
            for (int i = 0; i < s.Length; i++) Feed(s[i]);
        }

        // ---- parameter helpers -------------------------------------------

        private void ParamDigit(char ch)
        {
            if (_paramCount == 0) _paramCount = 1;
            if (_paramCount > MaxParams) return;
            int idx = _paramCount - 1;
            int cur = _params[idx];
            if (cur < 0) cur = 0;
            // Clamp rather than overflow: a device sending CSI 999999999 m should not wrap.
            if (cur < 100000000) cur = cur * 10 + (ch - '0');
            _params[idx] = cur;
            _paramPending = true;
        }

        private void ParamSeparator()
        {
            if (_paramCount == 0) _paramCount = 1;
            if (_paramCount < MaxParams) _paramCount++;
            _paramPending = false;
        }

        // ---- character classification ------------------------------------

        private static bool IsC0(char c) { return c <= 0x1F; }
        private static bool IsIntermediate(char c) { return c >= 0x20 && c <= 0x2F; }
        private static bool IsParamChar(char c) { return c >= 0x30 && c <= 0x39; }
        private static bool IsFinal(char c) { return c >= 0x40 && c <= 0x7E; }
        private static bool IsCsiPrefix(char c) { return c >= 0x3C && c <= 0x3F; }

        /// <summary>C0 controls that execute regardless of the current state.</summary>
        private bool HandleAnywhere(char ch)
        {
            switch (ch)
            {
                case '\x18': // CAN
                case '\x1A': // SUB
                    _state = State.Ground;
                    Clear();
                    return true;
                case '\x1B': // ESC
                    if (_state == State.OscString) _sink.OscDispatch(-1, _stringBuffer.ToString());
                    if (_state == State.DcsPassthrough) _sink.DcsUnhook();
                    _state = State.Escape;
                    Clear();
                    return true;
                case '\x9B': // 8-bit CSI
                    _state = State.CsiEntry;
                    Clear();
                    return true;
                case '\x9D': // 8-bit OSC
                    _state = State.OscString;
                    Clear();
                    return true;
                case '\x90': // 8-bit DCS
                    _state = State.DcsEntry;
                    Clear();
                    return true;
                case '\x9C': // ST
                    FinishString();
                    return true;
            }
            return false;
        }

        private void FinishString()
        {
            if (_state == State.OscString) DispatchOsc();
            else if (_state == State.DcsPassthrough) _sink.DcsUnhook();
            _state = State.Ground;
            Clear();
        }

        private void DispatchOsc()
        {
            string s = _stringBuffer.ToString();
            int code = -1;
            string payload = s;
            int sep = s.IndexOf(';');
            if (sep >= 0)
            {
                int parsed;
                if (int.TryParse(s.Substring(0, sep), out parsed)) code = parsed;
                payload = s.Substring(sep + 1);
            }
            else
            {
                int parsed;
                if (int.TryParse(s, out parsed)) { code = parsed; payload = string.Empty; }
            }
            _sink.OscDispatch(code, payload);
        }

        // ---- the machine --------------------------------------------------

        private void Feed(char ch)
        {
            // Inside string states only a few controls are special; everything else is payload.
            if (_state == State.OscString || _state == State.SosPmApcString || _state == State.DcsPassthrough)
            {
                if (ch == '\x1B' || ch == '\x9C' || ch == '\x18' || ch == '\x1A')
                {
                    // BEL also terminates OSC (xterm convention), handled below.
                    if (HandleAnywhere(ch)) return;
                }
                if (_state == State.OscString && ch == '\x07') { FinishString(); return; }

                if (_state == State.DcsPassthrough)
                {
                    _sink.DcsPut(ch);
                }
                else if (_state == State.OscString)
                {
                    if (_stringBuffer.Length < MaxStringLength) _stringBuffer.Append(ch);
                    else _stringOverflow = true;
                }
                // SosPmApcString: silently discarded.
                return;
            }

            if (HandleAnywhere(ch)) return;

            switch (_state)
            {
                case State.Ground:
                    if (IsC0(ch)) _sink.Execute(ch);
                    else if (ch >= 0x80 && ch <= 0x9F) _sink.Execute(ch);
                    else _sink.Print(ch);
                    break;

                case State.Escape:
                    if (IsC0(ch)) { _sink.Execute(ch); break; }
                    if (IsIntermediate(ch))
                    {
                        _intermediates.Append(ch);
                        _state = State.EscapeIntermediate;
                        break;
                    }
                    switch (ch)
                    {
                        case '[': _state = State.CsiEntry; break;
                        case ']': _state = State.OscString; break;
                        case 'P': _state = State.DcsEntry; break;
                        case 'X': // SOS
                        case '^': // PM
                        case '_': // APC
                            _state = State.SosPmApcString;
                            break;
                        default:
                            _sink.EscDispatch(string.Empty, ch);
                            _state = State.Ground;
                            Clear();
                            break;
                    }
                    break;

                case State.EscapeIntermediate:
                    if (IsC0(ch)) { _sink.Execute(ch); break; }
                    if (IsIntermediate(ch)) { _intermediates.Append(ch); break; }
                    _sink.EscDispatch(_intermediates.ToString(), ch);
                    _state = State.Ground;
                    Clear();
                    break;

                case State.CsiEntry:
                    if (IsC0(ch)) { _sink.Execute(ch); break; }
                    if (IsParamChar(ch)) { ParamDigit(ch); _state = State.CsiParam; break; }
                    if (ch == ';') { ParamSeparator(); _state = State.CsiParam; break; }
                    if (ch == ':') { _state = State.CsiIgnore; break; }
                    if (IsCsiPrefix(ch)) { _prefix = ch; _state = State.CsiParam; break; }
                    if (IsIntermediate(ch)) { _intermediates.Append(ch); _state = State.CsiIntermediate; break; }
                    if (IsFinal(ch)) { DispatchCsi(ch); break; }
                    _state = State.CsiIgnore;
                    break;

                case State.CsiParam:
                    if (IsC0(ch)) { _sink.Execute(ch); break; }
                    if (IsParamChar(ch)) { ParamDigit(ch); break; }
                    if (ch == ';') { ParamSeparator(); break; }
                    // Sub-parameters (SGR 38:2:...) are consumed but not split out; the
                    // colon form is accepted so the sequence does not corrupt the screen.
                    if (ch == ':') { ParamSeparator(); break; }
                    if (IsCsiPrefix(ch)) { _state = State.CsiIgnore; break; }
                    if (IsIntermediate(ch)) { _intermediates.Append(ch); _state = State.CsiIntermediate; break; }
                    if (IsFinal(ch)) { DispatchCsi(ch); break; }
                    _state = State.CsiIgnore;
                    break;

                case State.CsiIntermediate:
                    if (IsC0(ch)) { _sink.Execute(ch); break; }
                    if (IsIntermediate(ch)) { _intermediates.Append(ch); break; }
                    if (IsFinal(ch)) { DispatchCsi(ch); break; }
                    _state = State.CsiIgnore;
                    break;

                case State.CsiIgnore:
                    if (IsC0(ch)) { _sink.Execute(ch); break; }
                    if (IsFinal(ch)) { _state = State.Ground; Clear(); }
                    break;

                case State.DcsEntry:
                    if (IsParamChar(ch)) { ParamDigit(ch); _state = State.DcsParam; break; }
                    if (ch == ';') { ParamSeparator(); _state = State.DcsParam; break; }
                    if (IsCsiPrefix(ch)) { _prefix = ch; _state = State.DcsParam; break; }
                    if (IsIntermediate(ch)) { _intermediates.Append(ch); _state = State.DcsIntermediate; break; }
                    if (IsFinal(ch)) { HookDcs(ch); break; }
                    _state = State.DcsIgnore;
                    break;

                case State.DcsParam:
                    if (IsParamChar(ch)) { ParamDigit(ch); break; }
                    if (ch == ';' || ch == ':') { ParamSeparator(); break; }
                    if (IsIntermediate(ch)) { _intermediates.Append(ch); _state = State.DcsIntermediate; break; }
                    if (IsFinal(ch)) { HookDcs(ch); break; }
                    _state = State.DcsIgnore;
                    break;

                case State.DcsIntermediate:
                    if (IsIntermediate(ch)) { _intermediates.Append(ch); break; }
                    if (IsFinal(ch)) { HookDcs(ch); break; }
                    _state = State.DcsIgnore;
                    break;

                case State.DcsIgnore:
                    // Consumed until ST, handled by HandleAnywhere.
                    break;
            }
        }

        private void DispatchCsi(char final)
        {
            int count = _paramCount;
            // A trailing ';' means one more (empty) parameter.
            if (count > 0 && !_paramPending && _params[count - 1] < 0) { /* keep as omitted */ }
            _sink.CsiDispatch(_prefix, _params, count, _intermediates.ToString(), final);
            _state = State.Ground;
            Clear();
        }

        private void HookDcs(char final)
        {
            _sink.DcsHook(_prefix, _params, _paramCount, _intermediates.ToString(), final);
            _state = State.DcsPassthrough;
        }

        /// <summary>True when an oversized string sequence was truncated.</summary>
        public bool LastStringTruncated { get { return _stringOverflow; } }
    }
}
