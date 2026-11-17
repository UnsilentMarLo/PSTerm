// PSTerm - Watchers.cs
// Small background helpers the UI polls: reverse DNS, and serial ports coming and
// going. Both do their blocking work off the UI thread and only expose results.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Collections.Generic;
using System.IO.Ports;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Microsoft.Win32;

namespace PSTerm.Automation
{
    /// <summary>A reverse lookup that cannot freeze the window: Dns.GetHostEntry has
    /// no timeout, and an address with no PTR record can take many seconds.</summary>
    public sealed class NameLookup
    {
        private volatile bool _done;
        private string _name = "";

        public bool Done { get { return _done; } }
        /// <summary>The first label of the name found, or empty.</summary>
        public string Name { get { return _name; } }

        public static bool LooksLikeAddress(string text)
        {
            IPAddress ip;
            return !string.IsNullOrEmpty(text) && IPAddress.TryParse(text.Trim(), out ip);
        }

        public static NameLookup Start(string address)
        {
            NameLookup lookup = new NameLookup();
            ThreadPool.QueueUserWorkItem(delegate { lookup.Run(address); });
            return lookup;
        }

        private void Run(string address)
        {
            try
            {
                IPAddress ip;
                if (!IPAddress.TryParse(address.Trim(), out ip)) return;

                IPHostEntry entry = Dns.GetHostEntry(ip);
                string host = entry != null ? entry.HostName : "";
                if (string.IsNullOrEmpty(host) || host == ip.ToString()) return;

                int dot = host.IndexOf('.');
                _name = dot > 0 ? host.Substring(0, dot) : host;
            }
            catch (SocketException) { }
            catch (Exception) { }
            finally { _done = true; }
        }
    }

    public sealed class SerialPortInfo
    {
        public string PortName = "";
        public string Description = "";
    }

    /// <summary>
    /// Watches for serial ports appearing and disappearing, so a console cable that
    /// is plugged in can be offered at once. A version number changes whenever the
    /// set does, which is all the UI timer needs to check.
    /// </summary>
    public sealed class SerialPortWatcher : IDisposable
    {
        private readonly object _lock = new object();
        private SerialPortInfo[] _ports = new SerialPortInfo[0];
        private int _version;
        private Timer _timer;
        private int _busy;

        public int Version { get { return Volatile.Read(ref _version); } }

        public SerialPortInfo[] Ports
        {
            get { lock (_lock) { return (SerialPortInfo[])_ports.Clone(); } }
        }

        public void Start(int intervalMs)
        {
            if (_timer != null) return;
            _timer = new Timer(delegate { Poll(); }, null, 0, intervalMs);
        }

        private void Poll()
        {
            // A slow registry read must not pile up behind the next tick.
            if (Interlocked.Exchange(ref _busy, 1) != 0) return;
            try
            {
                string[] names;
                try { names = SerialPort.GetPortNames(); }
                catch (Exception) { return; }

                Array.Sort(names, ComparePorts);

                bool same;
                lock (_lock)
                {
                    same = names.Length == _ports.Length;
                    for (int i = 0; same && i < names.Length; i++)
                        if (!string.Equals(names[i], _ports[i].PortName, StringComparison.OrdinalIgnoreCase)) same = false;
                }
                if (same) return;

                Dictionary<string, string> friendly = ReadFriendlyNames();
                List<SerialPortInfo> list = new List<SerialPortInfo>();
                foreach (string name in names)
                {
                    SerialPortInfo info = new SerialPortInfo();
                    info.PortName = name;
                    string text;
                    info.Description = friendly.TryGetValue(name.ToUpperInvariant(), out text) ? text : "";
                    list.Add(info);
                }

                lock (_lock) { _ports = list.ToArray(); }
                Interlocked.Increment(ref _version);
            }
            finally { Interlocked.Exchange(ref _busy, 0); }
        }

        private static int ComparePorts(string a, string b)
        {
            int na, nb;
            bool pa = int.TryParse(a.Substring(Math.Min(3, a.Length)), out na);
            bool pb = int.TryParse(b.Substring(Math.Min(3, b.Length)), out nb);
            if (pa && pb) return na.CompareTo(nb);
            return string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>COM port -> what Windows calls the adapter, from the device
        /// registry. WMI would give the same answer a good deal more slowly.</summary>
        private static Dictionary<string, string> ReadFriendlyNames()
        {
            Dictionary<string, string> map = new Dictionary<string, string>();
            try
            {
                using (RegistryKey enumKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum"))
                {
                    if (enumKey == null) return map;
                    foreach (string bus in new string[] { "USB", "FTDIBUS", "BTHENUM", "ACPI", "PCI" })
                    {
                        using (RegistryKey busKey = enumKey.OpenSubKey(bus))
                        {
                            if (busKey == null) continue;
                            foreach (string device in busKey.GetSubKeyNames())
                            {
                                using (RegistryKey deviceKey = busKey.OpenSubKey(device))
                                {
                                    if (deviceKey == null) continue;
                                    foreach (string instance in deviceKey.GetSubKeyNames())
                                    {
                                        ReadInstance(deviceKey, instance, map);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception) { }
            return map;
        }

        private static void ReadInstance(RegistryKey deviceKey, string instance, Dictionary<string, string> map)
        {
            try
            {
                using (RegistryKey inst = deviceKey.OpenSubKey(instance))
                using (RegistryKey parameters = inst != null ? inst.OpenSubKey("Device Parameters") : null)
                {
                    if (parameters == null) return;
                    string port = parameters.GetValue("PortName") as string;
                    if (string.IsNullOrEmpty(port)) return;

                    string name = inst.GetValue("FriendlyName") as string;
                    if (string.IsNullOrEmpty(name))
                    {
                        name = inst.GetValue("DeviceDesc") as string;
                        int semi = name != null ? name.LastIndexOf(';') : -1;
                        if (semi >= 0) name = name.Substring(semi + 1);
                    }
                    if (string.IsNullOrEmpty(name)) return;

                    // "USB Serial Port (COM4)" - the port is shown beside it already.
                    int paren = name.LastIndexOf(" (COM", StringComparison.OrdinalIgnoreCase);
                    if (paren > 0) name = name.Substring(0, paren);
                    map[port.ToUpperInvariant()] = name;
                }
            }
            catch (Exception) { }
        }

        public void Dispose()
        {
            Timer t = _timer;
            _timer = null;
            if (t != null) t.Dispose();
        }
    }
}
