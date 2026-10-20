// PSTerm - ConPty.cs
// P/Invoke for the Windows pseudo-console API (Windows 10 1809 and later).
//
// This is the mechanism that lets PSTerm host a real console program - most
// importantly the OpenSSH client that ships with Windows - and read its output
// as a VT stream. It is the same approach Windows Terminal uses, and it is why
// PSTerm needs no third-party SSH library: ssh.exe brings public-key auth,
// agent support, certificates, ProxyJump and every modern cipher with it.
//
// C# 5 only - see Cell.cs for why.

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace PSTerm.Interop
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct COORD
    {
        public short X;
        public short Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STARTUPINFO
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    /// <summary>Owns a HPCON handle and closes it deterministically.</summary>
    internal sealed class SafePseudoConsoleHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafePseudoConsoleHandle() : base(true) { }

        public SafePseudoConsoleHandle(IntPtr handle) : base(true)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            // ClosePseudoConsole blocks until the client has drained its output,
            // which is what makes the final bytes of a session actually arrive.
            NativeMethods.ClosePseudoConsole(handle);
            return true;
        }
    }

    internal static class NativeMethods
    {
        internal const int STARTF_USESTDHANDLES = 0x00000100;
        internal const int EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        internal const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        internal static readonly IntPtr PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = (IntPtr)0x00020016;

        internal const int PSEUDOCONSOLE_INHERIT_CURSOR = 1;

        internal const uint INFINITE = 0xFFFFFFFF;
        internal const uint WAIT_OBJECT_0 = 0;

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int CreatePseudoConsole(
            COORD size, SafeFileHandle hInput, SafeFileHandle hOutput, uint dwFlags, out IntPtr phPC);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int ResizePseudoConsole(IntPtr hPC, COORD size);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern void ClosePseudoConsole(IntPtr hPC);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreatePipe(
            out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe,
            IntPtr lpPipeAttributes, int nSize);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
            int dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, uint dwFlags, IntPtr attribute, IntPtr lpValue,
            IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetExitCodeProcess(IntPtr hProcess, out int lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
    }

    /// <summary>
    /// A pseudo-console plus the process running inside it. Disposing tears down
    /// the console, the pipes and the process.
    /// </summary>
    internal sealed class PseudoConsole : IDisposable
    {
        private SafePseudoConsoleHandle _console;
        private IntPtr _attributeList = IntPtr.Zero;
        private PROCESS_INFORMATION _process;
        private bool _disposed;

        /// <summary>Write to this to send input to the hosted program.</summary>
        public SafeFileHandle InputWrite { get; private set; }
        /// <summary>Read from this to receive the program's VT output.</summary>
        public SafeFileHandle OutputRead { get; private set; }

        public IntPtr ProcessHandle { get { return _process.hProcess; } }
        public int ProcessId { get { return _process.dwProcessId; } }

        /// <summary>
        /// Returns true if the pseudo-console API exists on this Windows version.
        /// It was introduced in Windows 10 1809.
        /// </summary>
        public static bool IsSupported
        {
            get
            {
                try
                {
                    IntPtr module = LoadLibrary("kernel32.dll");
                    if (module == IntPtr.Zero) return false;
                    return GetProcAddress(module, "CreatePseudoConsole") != IntPtr.Zero;
                }
                catch (DllNotFoundException) { return false; }
                catch (EntryPointNotFoundException) { return false; }
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        /// <summary>
        /// Create the pseudo-console and launch <paramref name="commandLine"/> inside it.
        /// </summary>
        public void Start(string commandLine, string workingDirectory, int cols, int rows)
        {
            if (cols < 1) cols = 1;
            if (rows < 1) rows = 1;

            SafeFileHandle inputRead = null, outputWrite = null;
            try
            {
                SafeFileHandle inputWrite, outputRead;
                if (!NativeMethods.CreatePipe(out inputRead, out inputWrite, IntPtr.Zero, 0))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not create the input pipe.");
                if (!NativeMethods.CreatePipe(out outputRead, out outputWrite, IntPtr.Zero, 0))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not create the output pipe.");

                InputWrite = inputWrite;
                OutputRead = outputRead;

                COORD size;
                size.X = (short)cols;
                size.Y = (short)rows;

                IntPtr hpc;
                int hr = NativeMethods.CreatePseudoConsole(size, inputRead, outputWrite, 0, out hpc);
                if (hr != 0) throw new Win32Exception(hr, "CreatePseudoConsole failed.");
                _console = new SafePseudoConsoleHandle(hpc);

                StartProcess(commandLine, workingDirectory, hpc);

                // Only now release our copies of the pseudo-console's ends. The
                // documentation is explicit that this happens after CreateProcess:
                // dropping the reference count early can tear the session down
                // before the client has attached. Releasing them at all is still
                // required, or the read side never sees EOF when the child exits.
                inputRead.Dispose(); inputRead = null;
                outputWrite.Dispose(); outputWrite = null;
            }
            catch
            {
                if (inputRead != null) inputRead.Dispose();
                if (outputWrite != null) outputWrite.Dispose();
                Dispose();
                throw;
            }
        }

        private void StartProcess(string commandLine, string workingDirectory, IntPtr hpc)
        {
            STARTUPINFOEX startupInfo = new STARTUPINFOEX();
            startupInfo.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));

            // Attaching the child to the pseudo-console gives it a console, but it
            // does NOT stop CreateProcess from handing down this process's standard
            // handles. When PSTerm is launched from a console or with redirected
            // output, the child then writes to *our* stdout instead of the pty and
            // the terminal stays blank - everything else looks correct, including
            // the attach itself. Declaring null standard handles forces the child to
            // fall back to its console, which is the pseudo-console.
            //
            // Windows Terminal never hits this because a GUI process has no standard
            // handles to inherit in the first place.
            startupInfo.StartupInfo.dwFlags |= NativeMethods.STARTF_USESTDHANDLES;
            startupInfo.StartupInfo.hStdInput = IntPtr.Zero;
            startupInfo.StartupInfo.hStdOutput = IntPtr.Zero;
            startupInfo.StartupInfo.hStdError = IntPtr.Zero;

            // Ask for the required buffer size, then allocate and fill it. The first
            // call is expected to fail with ERROR_INSUFFICIENT_BUFFER.
            IntPtr size = IntPtr.Zero;
            NativeMethods.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);

            _attributeList = Marshal.AllocHGlobal(size.ToInt32());
            startupInfo.lpAttributeList = _attributeList;

            if (!NativeMethods.InitializeProcThreadAttributeList(_attributeList, 1, 0, ref size))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "InitializeProcThreadAttributeList failed.");

            if (!NativeMethods.UpdateProcThreadAttribute(
                    _attributeList, 0, NativeMethods.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                    hpc, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "UpdateProcThreadAttribute failed.");

            if (string.IsNullOrEmpty(workingDirectory)) workingDirectory = null;

            PROCESS_INFORMATION pi;
            bool ok = NativeMethods.CreateProcess(
                null,
                commandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                false,      // handles are inherited through the pseudo-console, not directly
                NativeMethods.EXTENDED_STARTUPINFO_PRESENT | NativeMethods.CREATE_UNICODE_ENVIRONMENT,
                IntPtr.Zero,
                workingDirectory,
                ref startupInfo,
                out pi);

            if (!ok)
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "Could not start '" + commandLine + "'.");

            _process = pi;
        }

        public void Resize(int cols, int rows)
        {
            if (_console == null || _console.IsInvalid || _console.IsClosed) return;
            if (cols < 1) cols = 1;
            if (rows < 1) rows = 1;

            COORD size;
            size.X = (short)cols;
            size.Y = (short)rows;
            NativeMethods.ResizePseudoConsole(_console.DangerousGetHandle(), size);
        }

        public bool TryGetExitCode(out int exitCode)
        {
            exitCode = 0;
            if (_process.hProcess == IntPtr.Zero) return false;
            return NativeMethods.GetExitCodeProcess(_process.hProcess, out exitCode);
        }

        /// <summary>Block until the hosted process exits.</summary>
        public void WaitForExit()
        {
            if (_process.hProcess == IntPtr.Zero) return;
            NativeMethods.WaitForSingleObject(_process.hProcess, NativeMethods.INFINITE);
        }

        public void Kill()
        {
            if (_process.hProcess == IntPtr.Zero) return;
            try { NativeMethods.TerminateProcess(_process.hProcess, 1); }
            catch (Exception) { }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            // Order matters: close the console first so the client drains and exits,
            // then release the pipes, then the process handles.
            if (_console != null) { _console.Dispose(); _console = null; }

            if (InputWrite != null) { InputWrite.Dispose(); InputWrite = null; }
            if (OutputRead != null) { OutputRead.Dispose(); OutputRead = null; }

            if (_attributeList != IntPtr.Zero)
            {
                NativeMethods.DeleteProcThreadAttributeList(_attributeList);
                Marshal.FreeHGlobal(_attributeList);
                _attributeList = IntPtr.Zero;
            }

            if (_process.hThread != IntPtr.Zero)
            {
                NativeMethods.CloseHandle(_process.hThread);
                _process.hThread = IntPtr.Zero;
            }
            if (_process.hProcess != IntPtr.Zero)
            {
                NativeMethods.CloseHandle(_process.hProcess);
                _process.hProcess = IntPtr.Zero;
            }
        }
    }
}
