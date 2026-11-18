// A small simulated IOS device for tests: modes and prompts, enable, a pager, errors,
// the "save? / proceed?" questions of "reload in", and asynchronous console messages.
// It only has to behave like the real thing where DeviceSession can tell the difference.
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using PSTerm.Backends;

public class FakeIosDevice : ITerminalBackend
{
    public event EventHandler<DataReceivedEventArgs> DataReceived;
    public event EventHandler<BackendClosedEventArgs> Closed;
    public event EventHandler<BackendStatusEventArgs> Status;

    public string Hostname = "sw1";
    public string EnableSecret = "enablepw";
    public bool RequireLoginPassword = false;
    public string LoginPassword = "loginpw";
    public int PageLength = 24;
    public bool Dirty = false;           // unsaved changes
    public bool ReloadArmed = false;
    public readonly List<string> Received = new List<string>();
    public readonly List<long> ReceivedTicks = new List<long>();
    public readonly List<string> ConfigLines = new List<string>();
    /// <summary>Output for exact commands ("show version"), as the lines a real device would print.</summary>
    public readonly Dictionary<string, string> Canned = new Dictionary<string, string>();
    public int CannedDelayMs = 0;

    private string _mode = "user";       // user, priv, config, config-if
    private string _stage = "";           // "", login, enable-pw, reload-save, reload-confirm, paging
    private List<string> _pageLines;
    private readonly StringBuilder _line = new StringBuilder();
    private readonly object _gate = new object();
    private bool _up;

    public bool IsConnected { get { return _up; } }
    public string Description { get { return "fake ios"; } }
    public string Mode { get { return _mode; } }

    private string Prompt
    {
        get
        {
            switch (_mode)
            {
                case "priv": return Hostname + "#";
                case "config": return Hostname + "(config)#";
                case "config-if": return Hostname + "(config-if)#";
                default: return Hostname + ">";
            }
        }
    }

    public void Connect()
    {
        _up = true;
        if (Status != null) Status(this, new BackendStatusEventArgs("up", true));
        if (RequireLoginPassword) { _stage = "login"; Emit("\r\nPassword: "); }
        else Emit("\r\n" + Prompt);
    }

    public void Emit(string s)
    {
        byte[] b = Encoding.ASCII.GetBytes(s);
        ThreadPool.QueueUserWorkItem(delegate
        {
            lock (_gate) { if (DataReceived != null) DataReceived(this, new DataReceivedEventArgs(b, 0, b.Length)); }
        });
    }

    /// <summary>A console log message arriving on its own, then the prompt redrawn or not.</summary>
    public void Syslog(string text, bool redrawPrompt)
    {
        Emit("\r\n" + text + "\r\n" + (redrawPrompt ? Prompt : ""));
    }

    public void Write(byte[] data, int offset, int count)
    {
        StringBuilder echo = new StringBuilder();
        for (int i = 0; i < count; i++)
        {
            char c = (char)data[offset + i];

            if (_stage == "paging")
            {
                // A key at --More-- : space gives a page, q stops.
                echo.Append(new string('\b', 10) + new string(' ', 10) + new string('\b', 10));
                if (c == 'q') { _stage = ""; _pageLines = null; echo.Append(Prompt); }
                else NextPage(echo);
                continue;
            }

            if (c == '\r')
            {
                string text = _line.ToString().Trim();
                _line.Length = 0;
                lock (Received) { Received.Add(text); ReceivedTicks.Add(Environment.TickCount); }
                echo.Append("\r\n");
                Dispatch(text, echo);
            }
            else if (c == '\b' || c == 0x7f)
            {
                if (_line.Length > 0) { _line.Length--; echo.Append("\b \b"); }
            }
            else if (c >= 0x20 && c < 0x7f)
            {
                _line.Append(c);
                if (_stage != "login" && _stage != "enable-pw") echo.Append(c);
            }
        }
        if (echo.Length > 0) Emit(echo.ToString());
    }

    private void Dispatch(string text, StringBuilder o)
    {
        switch (_stage)
        {
            case "login":
                if (text == LoginPassword) { _stage = ""; o.Append(Prompt); }
                else o.Append("Password: ");
                return;
            case "enable-pw":
                if (text == EnableSecret) { _stage = ""; _mode = "priv"; o.Append(Prompt); }
                else { _stage = ""; o.Append("% Access denied\r\n" + Prompt); }
                return;
            case "reload-save":
                if (text == "no" || text == "yes") { _stage = "reload-confirm"; o.Append("Reload scheduled in a few minutes by console\r\nProceed with reload? [confirm]"); }
                else o.Append("% Please answer 'yes' or 'no'.\r\nSystem configuration has been modified. Save? [yes/no]: ");
                return;
            case "reload-confirm":
                _stage = "";
                if (text.Length == 0) { ReloadArmed = true; o.Append(Prompt); }
                else o.Append(Prompt);
                return;
        }

        if (text.Length == 0) { o.Append(Prompt); return; }

        string[] w = text.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
        string cmd = w[0];

        // A command that takes a while: the echo is immediate, the prompt comes later.
        if (cmd == "slow" || (cmd == "show" && w.Length == 2 && w[1] == "slow"))
        {
            ThreadPool.QueueUserWorkItem(delegate { Thread.Sleep(1500); Emit(Prompt); });
            return;
        }
        if (cmd == "enable" && _mode == "user") { _stage = "enable-pw"; o.Append("Password: "); return; }
        if (cmd == "terminal" && w.Length == 3 && w[1] == "length") { PageLength = int.Parse(w[2]); o.Append(Prompt); return; }

        if (cmd == "configure" && _mode == "priv") { _mode = "config"; o.Append("Enter configuration commands, one per line.  End with CNTL/Z.\r\n" + Prompt); return; }
        if (cmd == "end" && _mode.StartsWith("config")) { _mode = "priv"; o.Append(Prompt); return; }
        if (cmd == "exit" && _mode == "config-if") { _mode = "config"; o.Append(Prompt); return; }

        if (_mode == "config" || _mode == "config-if")
        {
            if (cmd == "hostname" && w.Length == 2) { Hostname = w[1]; Dirty = true; ConfigLines.Add(text); o.Append(Prompt); return; }
            if (cmd == "interface") { _mode = "config-if"; o.Append(Prompt); return; }
            if (cmd == "description" || cmd == "ip" || cmd == "no" || cmd == "shutdown") { Dirty = true; ConfigLines.Add(text); o.Append(Prompt); return; }
            o.Append("% Invalid input detected at '^' marker.\r\n\r\n" + Prompt);
            return;
        }

        if (_mode == "priv" && Canned.ContainsKey(text))
        {
            _pageLines = new List<string>(Canned[text].Replace("\r\n", "\n").TrimEnd(new char[] { (char)10 }).Split(new char[] { (char)10 }));
            if (CannedDelayMs > 0)
            {
                string[] snapshot = _pageLines.ToArray();
                _pageLines = null;
                ThreadPool.QueueUserWorkItem(delegate { Thread.Sleep(CannedDelayMs); Emit(string.Join("\r\n", snapshot) + "\r\n" + Prompt); });
                return;
            }
            NextPage(o, true);
            return;
        }

        if (_mode == "priv")
        {
            if (cmd == "reload" && w.Length >= 2 && w[1] == "in")
            {
                if (Dirty) { _stage = "reload-save"; o.Append("System configuration has been modified. Save? [yes/no]: "); }
                else { _stage = "reload-confirm"; o.Append("Reload scheduled in a few minutes by console\r\nProceed with reload? [confirm]"); }
                return;
            }
            if (cmd == "reload" && w.Length == 2 && w[1] == "cancel")
            {
                ReloadArmed = false;
                // The real device prints a banner a moment later and does not redraw the prompt.
                o.Append(Prompt);
                ThreadPool.QueueUserWorkItem(delegate { Thread.Sleep(150); Syslog("***\r\n*** --- SHUTDOWN ABORTED ---\r\n***\r\nNov 17 15:01:17.277: %SYS-5-SCHEDULED_RELOAD: Reload requested for 15:04:16", false); });
                return;
            }
            if (cmd == "write") { Dirty = false; o.Append("Building configuration...\r\n[OK]\r\n" + Prompt); return; }
            if (cmd == "show" && w.Length >= 2 && w[1] == "version") { o.Append("Cisco IOS Software, Version 15.2(7)E3\r\nsw1 uptime is 2 hours\r\n" + Prompt); return; }
            if (cmd == "show" && w.Length >= 2 && w[1] == "running-config")
            {
                _pageLines = new List<string>();
                _pageLines.Add("Building configuration...");
                _pageLines.Add("");
                _pageLines.Add("Current configuration : 1234 bytes");
                _pageLines.Add("hostname " + Hostname);
                for (int i = 1; i <= 80; i++) _pageLines.Add("interface GigabitEthernet0/" + i);
                foreach (string l in ConfigLines) _pageLines.Add(l);
                _pageLines.Add("end");
                NextPage(o, true);
                return;
            }
        }

        if (cmd == "show") { o.Append(Prompt); return; }
        o.Append("% Invalid input detected at '^' marker.\r\n\r\n" + Prompt);
    }

    private void NextPage(StringBuilder o) { NextPage(o, false); }

    private void NextPage(StringBuilder o, bool first)
    {
        int page = PageLength <= 0 ? int.MaxValue : PageLength;
        int shown = 0;
        while (_pageLines.Count > 0 && shown < page)
        {
            o.Append(_pageLines[0] + "\r\n");
            _pageLines.RemoveAt(0);
            shown++;
        }
        if (_pageLines.Count == 0) { _stage = ""; _pageLines = null; o.Append(Prompt); }
        else { _stage = "paging"; o.Append(" --More-- "); }
    }

    public string[] Sent { get { lock (Received) { return Received.ToArray(); } } }
    public void Resize(int cols, int rows) { }
    public void Disconnect() { if (!_up) return; _up = false; if (Closed != null) Closed(this, new BackendClosedEventArgs(null, null)); }
    public void Dispose() { Disconnect(); }
}
