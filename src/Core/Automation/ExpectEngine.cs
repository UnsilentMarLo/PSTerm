// PSTerm - ExpectEngine.cs
// Answers prompts for the operator: a saved password at "Password:", the enable
// command once a switch shows its ">" prompt, and so on.
//
// The engine watches the decoded host output (escape sequences removed) for the
// text a prompt ends with, and when a rule matches it sends the rule's reply after
// an optional delay. Rules fire once by default, so a password saved for the login
// is never sent a second time to a later prompt that merely looks the same.
//
// Replies go through the session, so they are logged like anything typed - and the
// logger masks whatever is typed after a password prompt.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace PSTerm.Automation
{
    public sealed class ExpectRule
    {
        public string Name = "";
        /// <summary>Matched against the end of the output received so far.</summary>
        public Regex Pattern;
        /// <summary>Text to send. May be null for a rule that only reports.</summary>
        public string Reply;
        public int DelayMs = 0;
        public bool Once = true;
        /// <summary>The rule is ignored until this many milliseconds after it was
        /// armed have not yet passed. 0 means no limit.</summary>
        public int ExpireAfterMs = 0;
        /// <summary>Rules that start disarmed are switched on by another rule.</summary>
        public bool Armed = true;
        /// <summary>Raised when the rule matches (on a worker thread).</summary>
        public Action<ExpectRule, string> OnMatch;
        /// <summary>Names of rules this one arms when it fires.</summary>
        public string[] Arms = new string[0];

        internal bool Fired;
        internal int ArmedTick;
    }

    public sealed class ExpectEngine
    {
        private readonly List<ExpectRule> _rules = new List<ExpectRule>();
        private readonly object _lock = new object();
        private readonly StringBuilder _tail = new StringBuilder();
        private int _escapeState;
        private readonly Action<string> _send;

        private const int MaxTail = 1024;

        public ExpectEngine(Action<string> send)
        {
            if (send == null) throw new ArgumentNullException("send");
            _send = send;
        }

        public void Add(ExpectRule rule)
        {
            if (rule == null) return;
            lock (_lock)
            {
                if (rule.Armed) rule.ArmedTick = Environment.TickCount;
                _rules.Add(rule);
            }
        }

        public void Arm(string name)
        {
            lock (_lock)
            {
                foreach (ExpectRule r in _rules)
                {
                    if (string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase))
                    {
                        r.Armed = true;
                        r.Fired = false;
                        r.ArmedTick = Environment.TickCount;
                    }
                }
            }
        }

        public bool HasRules { get { lock (_lock) { return _rules.Count > 0; } } }

        public void Clear()
        {
            lock (_lock) { _rules.Clear(); _tail.Length = 0; }
        }

        /// <summary>Feed decoded host output. Called on the transport's thread.</summary>
        public void Feed(char[] buffer, int offset, int count)
        {
            if (!HasRules) return;

            List<ExpectRule> matched = null;
            string line;

            lock (_lock)
            {
                for (int i = offset; i < offset + count; i++) Append(buffer[i]);
                if (_tail.Length > MaxTail) _tail.Remove(0, _tail.Length - MaxTail);

                // Only the unfinished last line can be a prompt waiting for an answer.
                string all = _tail.ToString();
                int nl = all.LastIndexOfAny(new char[] { '\n', '\r' });
                line = nl >= 0 ? all.Substring(nl + 1) : all;
                if (line.Length == 0) return;

                foreach (ExpectRule rule in _rules)
                {
                    if (!rule.Armed || (rule.Once && rule.Fired)) continue;
                    if (rule.ExpireAfterMs > 0 &&
                        unchecked(Environment.TickCount - rule.ArmedTick) > rule.ExpireAfterMs)
                    {
                        rule.Armed = false;
                        continue;
                    }
                    if (rule.Pattern == null || !rule.Pattern.IsMatch(line)) continue;

                    rule.Fired = true;
                    if (matched == null) matched = new List<ExpectRule>();
                    matched.Add(rule);
                }

                // A matched prompt is consumed, so the same text is not answered twice.
                if (matched != null) _tail.Length = 0;
            }

            if (matched == null) return;
            foreach (ExpectRule rule in matched) Fire(rule, line);
        }

        private void Fire(ExpectRule rule, string line)
        {
            foreach (string name in rule.Arms) Arm(name);

            Action<ExpectRule, string> callback = rule.OnMatch;
            if (callback != null)
            {
                try { callback(rule, line); } catch (Exception) { }
            }

            if (rule.Reply == null) return;

            string reply = rule.Reply;
            if (rule.DelayMs <= 0)
            {
                Send(reply);
                return;
            }

            // The timer is held by the closure until it fires, then disposed.
            Timer timer = null;
            timer = new Timer(delegate(object state)
            {
                try { Send(reply); }
                finally { if (timer != null) timer.Dispose(); }
            }, null, rule.DelayMs, Timeout.Infinite);
        }

        private void Send(string text)
        {
            try { _send(text); } catch (Exception) { }
        }

        // Escape sequences are removed on the way in, so a prompt painted with colour
        // (or by a pseudo-console) is still recognised.
        private void Append(char c)
        {
            switch (_escapeState)
            {
                case 0:
                    if (c == '\x1b') { _escapeState = 1; return; }
                    if (c == '\b')
                    {
                        if (_tail.Length > 0 && _tail[_tail.Length - 1] != '\n' && _tail[_tail.Length - 1] != '\r')
                            _tail.Length--;
                        return;
                    }
                    if (c == '\x07' || (c < 0x20 && c != '\r' && c != '\n' && c != '\t')) return;
                    _tail.Append(c);
                    return;
                case 1:
                    if (c == '[') _escapeState = 2;
                    else if (c == ']' || c == 'P' || c == 'X' || c == '^' || c == '_') _escapeState = 3;
                    else if (c == '(' || c == ')' || c == '*' || c == '+' || c == '#' || c == '%') _escapeState = 4;
                    else _escapeState = 0;
                    return;
                case 2:
                    if (c >= 0x40 && c <= 0x7E) _escapeState = 0;
                    return;
                case 3:
                    if (c == '\x07' || c == '\x9c') _escapeState = 0;
                    else if (c == '\x1b') _escapeState = 5;
                    return;
                case 4:
                    _escapeState = 0;
                    return;
                case 5:
                    _escapeState = (c == '\\') ? 0 : 3;
                    return;
            }
        }
    }
}
