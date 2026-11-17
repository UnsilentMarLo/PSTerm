// A pretend switch for tests: asks for a login password, shows a user prompt,
// asks for the enable password, then shows a privileged prompt. Records what it
// was sent.
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using PSTerm.Backends;

public class FakeLoginDevice : ITerminalBackend
{
    public event EventHandler<DataReceivedEventArgs> DataReceived;
    public event EventHandler<BackendClosedEventArgs> Closed;
    public event EventHandler<BackendStatusEventArgs> Status;

    public readonly List<string> Lines = new List<string>();
    private readonly StringBuilder _line = new StringBuilder();
    private string _stage = "login";
    private bool _up;
    private readonly object _gate = new object();

    public string LoginPassword = "loginpw";
    public string EnablePassword = "enablepw";
    public bool AsksForEnableUser = false;

    public bool IsConnected { get { return _up; } }
    public string Description { get { return "fake login device"; } }

    public void Connect()
    {
        _up = true;
        if (Status != null) Status(this, new BackendStatusEventArgs("up", true));
        Emit("\r\nFake device\r\n(admin@10.0.0.1) Password: ");
    }

    public void Emit(string s)
    {
        byte[] b = Encoding.ASCII.GetBytes(s);
        ThreadPool.QueueUserWorkItem(delegate
        {
            lock (_gate) { if (DataReceived != null) DataReceived(this, new DataReceivedEventArgs(b, 0, b.Length)); }
        });
    }

    public void Write(byte[] data, int offset, int count)
    {
        for (int i = 0; i < count; i++)
        {
            char c = (char)data[offset + i];
            if (c != '\r') { _line.Append(c); continue; }

            string text = _line.ToString();
            _line.Length = 0;
            lock (Lines) { Lines.Add(text); }

            if (_stage == "login")
            {
                if (text == LoginPassword) { _stage = "user"; Emit("\r\nswitch-lab>"); }
                else Emit("\r\nAccess denied\r\n(admin@10.0.0.1) Password: ");
            }
            else if (_stage == "user")
            {
                if (text == "enable")
                {
                    _stage = AsksForEnableUser ? "enable-user" : "enable-pw";
                    Emit(AsksForEnableUser ? "\r\nUsername: " : "\r\nPassword: ");
                }
                else Emit("\r\nswitch-lab>");
            }
            else if (_stage == "enable-user") { _stage = "enable-pw"; Emit("\r\nPassword: "); }
            else if (_stage == "enable-pw")
            {
                if (text == EnablePassword) { _stage = "priv"; Emit("\r\nswitch-lab#"); }
                else { _stage = "user"; Emit("\r\n% Access denied\r\nswitch-lab>"); }
            }
            else Emit("\r\nswitch-lab#");
        }
    }

    public string Stage { get { return _stage; } }
    public string[] Received { get { lock (Lines) { return Lines.ToArray(); } } }
    public void Resize(int cols, int rows) { }
    public void Disconnect() { if (!_up) return; _up = false; if (Closed != null) Closed(this, new BackendClosedEventArgs(null, null)); }
    public void Dispose() { Disconnect(); }
}
