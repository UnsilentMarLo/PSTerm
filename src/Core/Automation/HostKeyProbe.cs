// PSTerm - HostKeyProbe.cs
// Looks at an SSH server's host key before the session starts, so the operator is
// asked about an unknown fingerprint in a dialog instead of at a prompt inside the
// terminal - where it interrupts a login, an automated one especially.
//
// The probe runs the real ssh.exe with the connection's own options (so legacy
// algorithms, a jump host and a custom port all work, which a separate scanner
// cannot promise) but points it at a throwaway known_hosts file and trusts
// whatever it sees there. ssh writes the key to that file as soon as the key
// exchange is done, which is before any login is attempted; the probe reads it
// and stops ssh at that point, so the device never sees an authentication try.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using PSTerm.Backends;

namespace PSTerm.Automation
{
    public sealed class HostKeyInfo
    {
        public string KeyType = "";       // RSA, ED25519, ECDSA
        public string Fingerprint = "";   // SHA256:...
        public string Bits = "";
        public string KnownHostsLine = "";
    }

    public sealed class HostKeyProbe
    {
        public readonly string Host;
        public readonly int Port;

        private volatile bool _done;
        private volatile bool _known;
        private string _error = "";
        private readonly List<HostKeyInfo> _keys = new List<HostKeyInfo>();

        public bool Done { get { return _done; } }
        /// <summary>True when known_hosts already holds a key for this host.</summary>
        public bool Known { get { return _known; } }
        /// <summary>Why the keys could not be read, or empty.</summary>
        public string Error { get { return _error; } }
        public HostKeyInfo[] Keys { get { lock (_keys) { return _keys.ToArray(); } } }

        private HostKeyProbe(string host, int port)
        {
            Host = host;
            Port = port <= 0 ? 22 : port;
        }

        /// <summary>Start a probe on a worker thread and return at once.</summary>
        public static HostKeyProbe Start(SshLaunchOptions options)
        {
            HostKeyProbe probe = new HostKeyProbe(options.Host, options.Port);
            Thread t = new Thread(delegate() { probe.Run(options); });
            t.IsBackground = true;
            t.Name = "PSTerm host key probe";
            t.Start();
            return probe;
        }

        public static string KnownHostsPath
        {
            get
            {
                string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                return Path.Combine(Path.Combine(profile, ".ssh"), "known_hosts");
            }
        }

        private static string HostPattern(string host, int port)
        {
            return port == 22 ? host : "[" + host + "]:" + port.ToString();
        }

        private void Run(SshLaunchOptions options)
        {
            string temp = Path.Combine(Path.GetTempPath(), "psterm-knownhosts-" + Guid.NewGuid().ToString("N"));
            try
            {
                string keygen = SiblingTool("ssh-keygen");

                // Already trusted: nothing to ask.
                if (keygen != null && File.Exists(KnownHostsPath))
                {
                    string found;
                    int code = RunTool(keygen, "-F " + Quote(HostPattern(Host, Port)) + " -f " + Quote(KnownHostsPath), 8000, out found);
                    if (code == 0 && found.Trim().Length > 0) { _known = true; return; }
                }

                // The same connection, aimed at an empty known_hosts that it may fill.
                SshLaunchOptions probe = Clone(options);
                probe.RemoteCommand = null;
                probe.ExtraOptions.Add("UserKnownHostsFile=" + temp);
                probe.ExtraOptions.Add("GlobalKnownHostsFile=NUL");
                probe.ExtraOptions.Add("StrictHostKeyChecking=no");
                probe.ExtraOptions.Add("BatchMode=yes");
                probe.ExtraOptions.Add("PasswordAuthentication=no");
                probe.ExtraOptions.Add("KbdInteractiveAuthentication=no");
                probe.ExtraOptions.Add("ConnectTimeout=8");
                probe.ExtraOptions.Add("LogLevel=ERROR");

                string commandLine = ConPtyCommands.BuildSshCommandLine(probe);
                string exe, args;
                SplitCommandLine(commandLine, out exe, out args);

                ProcessStartInfo psi = new ProcessStartInfo(exe, args);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardInput = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;

                StringBuilder errors = new StringBuilder();
                using (Process p = Process.Start(psi))
                {
                    p.OutputDataReceived += delegate { };
                    p.ErrorDataReceived += delegate(object s, System.Diagnostics.DataReceivedEventArgs e)
                    {
                        if (e.Data != null) lock (errors) { errors.AppendLine(e.Data); }
                    };
                    p.BeginOutputReadLine();
                    p.BeginErrorReadLine();

                    // ssh stores the key once the exchange is done; stop it right there.
                    Stopwatch clock = Stopwatch.StartNew();
                    while (clock.ElapsedMilliseconds < 14000)
                    {
                        if (File.Exists(temp) && new FileInfo(temp).Length > 0) break;
                        if (p.HasExited) break;
                        Thread.Sleep(60);
                    }

                    // A moment for ssh to finish writing every key it was offered.
                    if (File.Exists(temp) && new FileInfo(temp).Length > 0) Thread.Sleep(120);

                    if (!p.HasExited)
                    {
                        try { p.Kill(); } catch (Exception) { }
                    }
                    p.WaitForExit(2000);
                }

                if (!File.Exists(temp) || new FileInfo(temp).Length == 0)
                {
                    string text;
                    lock (errors) { text = errors.ToString().Trim(); }
                    _error = text.Length > 0 ? text : "The server did not offer a host key.";
                    return;
                }

                string[] lines = File.ReadAllLines(temp);
                foreach (string raw in lines)
                {
                    string line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith("#")) continue;
                    HostKeyInfo info = Describe(keygen, line);
                    if (info != null) lock (_keys) { _keys.Add(info); }
                }

                if (Keys.Length == 0) _error = "The host key could not be read.";
            }
            catch (Exception ex)
            {
                _error = ex.Message;
            }
            finally
            {
                try { if (File.Exists(temp)) File.Delete(temp); } catch (Exception) { }
                _done = true;
            }
        }

        private static SshLaunchOptions Clone(SshLaunchOptions o)
        {
            SshLaunchOptions c = new SshLaunchOptions();
            c.Host = o.Host; c.User = o.User; c.Port = o.Port;
            c.IdentityFile = o.IdentityFile; c.ProxyJump = o.ProxyJump;
            c.RemoteCommand = o.RemoteCommand; c.ForwardAgent = false; c.Compression = false;
            c.AllowLegacyAlgorithms = o.AllowLegacyAlgorithms; c.KeepAliveSeconds = 0;
            foreach (string extra in o.ExtraOptions) c.ExtraOptions.Add(extra);
            return c;
        }

        private static void SplitCommandLine(string commandLine, out string exe, out string args)
        {
            if (commandLine.StartsWith("\""))
            {
                int end = commandLine.IndexOf('"', 1);
                exe = commandLine.Substring(1, end - 1);
                args = commandLine.Substring(end + 1).TrimStart();
            }
            else
            {
                int space = commandLine.IndexOf(' ');
                exe = commandLine.Substring(0, space);
                args = commandLine.Substring(space + 1);
            }
        }

        private static string SiblingTool(string name)
        {
            string ssh = ConPtyCommands.FindSsh();
            if (ssh != null)
            {
                string dir = Path.GetDirectoryName(ssh);
                string candidate = Path.Combine(dir, name + ".exe");
                if (File.Exists(candidate)) return candidate;
            }
            return null;
        }

        private static HostKeyInfo Describe(string keygen, string knownHostsLine)
        {
            if (keygen == null) return null;
            string temp = Path.Combine(Path.GetTempPath(), "psterm-hostkey-" + Guid.NewGuid().ToString("N") + ".pub");
            try
            {
                File.WriteAllText(temp, knownHostsLine + "\n", new UTF8Encoding(false));
                string output;
                if (RunTool(keygen, "-l -f " + Quote(temp), 8000, out output) != 0) return null;

                // "3072 SHA256:abc... host (RSA)"
                string[] parts = output.Trim().Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) return null;

                HostKeyInfo info = new HostKeyInfo();
                info.Bits = parts[0];
                info.Fingerprint = parts[1];
                info.KeyType = parts[parts.Length - 1].Trim('(', ')');
                info.KnownHostsLine = knownHostsLine;
                return info;
            }
            finally
            {
                try { File.Delete(temp); } catch (Exception) { }
            }
        }

        /// <summary>
        /// Trust the keys that were shown. They are appended to known_hosts, so the
        /// connection that follows finds the host already known and never prompts.
        /// </summary>
        public static void Trust(HostKeyProbe probe)
        {
            if (probe == null) return;
            string dir = Path.GetDirectoryName(KnownHostsPath);
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);

            StringBuilder sb = new StringBuilder();
            bool needsBreak = false;
            if (File.Exists(KnownHostsPath))
            {
                string existing = File.ReadAllText(KnownHostsPath);
                needsBreak = existing.Length > 0 && !existing.EndsWith("\n");
            }
            if (needsBreak) sb.Append('\n');
            foreach (HostKeyInfo key in probe.Keys) sb.Append(key.KnownHostsLine).Append('\n');
            File.AppendAllText(KnownHostsPath, sb.ToString(), new UTF8Encoding(false));
        }

        private static string Quote(string s)
        {
            return "\"" + s.Replace("\"", "\\\"") + "\"";
        }

        private static int RunTool(string exe, string args, int timeoutMs, out string output)
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.StandardOutputEncoding = Encoding.UTF8;

            using (Process p = Process.Start(psi))
            {
                // Standard error is drained so a chatty tool cannot block on a full pipe.
                p.ErrorDataReceived += delegate { };
                p.BeginErrorReadLine();

                StringBuilder sb = new StringBuilder();
                p.OutputDataReceived += delegate(object s, System.Diagnostics.DataReceivedEventArgs e)
                {
                    if (e.Data != null) lock (sb) { sb.AppendLine(e.Data); }
                };
                p.BeginOutputReadLine();

                if (!p.WaitForExit(timeoutMs))
                {
                    try { p.Kill(); } catch (Exception) { }
                    lock (sb) { output = sb.ToString(); }
                    return -1;
                }
                p.WaitForExit();
                lock (sb) { output = sb.ToString(); }
                return p.ExitCode;
            }
        }
    }
}
