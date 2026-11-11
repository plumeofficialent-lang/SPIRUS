using System.Diagnostics;
using System.Runtime;
using System.Runtime.InteropServices;

namespace Vigie.Core;

/// <summary>
/// Rend au système la mémoire inutilisée : compactage complet du tas .NET, puis
/// réduction de l'empreinte mémoire du processus. Appelé quand SPIRUS retourne au repos.
/// </summary>
public static class MemoryTrim
{
    [DllImport("kernel32.dll")]
    private static extern bool SetProcessWorkingSetSize(IntPtr process, IntPtr min, IntPtr max);

    private static long _lastTicks;

    public static void Run()
    {
        try
        {
            GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
            GC.WaitForPendingFinalizers();
            using var me = Process.GetCurrentProcess();
            SetProcessWorkingSetSize(me.Handle, -1, -1);
            Interlocked.Exchange(ref _lastTicks, DateTime.UtcNow.Ticks);
        }
        catch { }
    }

    /// <summary>Lance un nettoyage si le dernier date de plus de <paramref name="interval"/>.</summary>
    public static void RunIfDue(TimeSpan interval)
    {
        if (DateTime.UtcNow.Ticks - Interlocked.Read(ref _lastTicks) >= interval.Ticks) Run();
    }
}
