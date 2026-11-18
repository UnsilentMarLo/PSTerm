// PSTerm - BackgroundRelease.cs
// Lets go of PowerShell pipelines and a runspace pool without making anybody wait.
//
// PowerShell's own Stop, Dispose and pool Close all wait for the pipelines they stop, and a
// pipeline that is blocked in a serial port or a login can take a long time to notice. Doing
// that on the window's thread freezes the window; doing it on a runspace of its own leaves a
// foreground thread behind that keeps the process alive after the window has closed. A
// thread-pool thread is neither: it is a background thread, so the process can exit while it
// is still waiting.
//
// Reflection, so no reference to the PowerShell assembly is needed (and the same code works
// on Windows PowerShell 5.1 and PowerShell 7).
//
// C# 5 only - see Cell.cs for why.

using System;
using System.Reflection;
using System.Threading;

namespace PSTerm.Automation
{
    public static class BackgroundRelease
    {
        /// <summary>Stop and dispose the pipelines, then close and dispose the pool, on a background thread.</summary>
        public static void Pipelines(object pool, object[] pipelines)
        {
            ThreadPool.QueueUserWorkItem(delegate
            {
                if (pipelines != null)
                {
                    foreach (object p in pipelines) { Call(p, "Stop"); Call(p, "Dispose"); }
                }
                Call(pool, "Close");
                Call(pool, "Dispose");
            });
        }

        private static void Call(object target, string method)
        {
            try
            {
                if (target == null) return;
                MethodInfo m = target.GetType().GetMethod(method, Type.EmptyTypes);
                if (m != null) m.Invoke(target, null);
            }
            catch (Exception) { }
        }
    }
}
