using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Vigie.Core.Engine;

public sealed class ScanTarget
{
    public string Path { get; init; } = "";
    public int MaxDepth { get; init; } = int.MaxValue;
    public bool RiskyOnly { get; init; }
}

/// <summary>Analyse d'un ensemble de fichiers et de dossiers, en parallèle, avec pause et annulation.</summary>
public sealed class ScanJob
{
    private readonly ScanEngine _engine;
    private readonly List<ScanTarget> _targets;
    private readonly ManualResetEventSlim _running = new(true);
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<string, byte> _seen = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<ScanResult> _found = new();
    private readonly Stopwatch _clock = new();
    private long _scanned, _discovered, _bytes;
    private int _threats, _errors;
    private volatile bool _enumerationDone;
    private volatile string _current = "";

    public ScanKind Kind { get; }
    public bool IsPaused => !_running.IsSet;
    public bool IsCancelled => _cts.IsCancellationRequested;
    public event Action<ScanResult> ThreatFound;

    public ScanJob(ScanEngine engine, ScanKind kind, IEnumerable<ScanTarget> targets)
    {
        _engine = engine;
        Kind = kind;
        _targets = targets.ToList();
    }

    public void Pause() => _running.Reset();
    public void Resume() => _running.Set();
    public void Cancel() { _cts.Cancel(); _running.Set(); }

    public ScanProgress Snapshot() => new()
    {
        Scanned = Interlocked.Read(ref _scanned),
        Discovered = Interlocked.Read(ref _discovered),
        EnumerationDone = _enumerationDone,
        Threats = _threats,
        CurrentFile = _current,
        Elapsed = _clock.Elapsed,
        BytesScanned = Interlocked.Read(ref _bytes)
    };

    public Task<ScanSummary> RunAsync() => Task.Run(Run);

    private ScanSummary Run()
    {
        var ct = _cts.Token;
        _clock.Start();
        using var queue = new BlockingCollection<string>(20_000);
        var producer = Task.Run(() =>
        {
            try { foreach (var t in _targets) Enumerate(t, queue, ct); }
            catch (OperationCanceledException) { }
            finally { _enumerationDone = true; queue.CompleteAdding(); }
        });

        int workers = Math.Clamp(Environment.ProcessorCount / 2, 2, 6);
        var tasks = Enumerable.Range(0, workers)
            .Select(_ => Task.Factory.StartNew(() => Work(queue, ct), TaskCreationOptions.LongRunning))
            .Append(producer).ToArray();
        try { Task.WaitAll(tasks); } catch (AggregateException) { }
        _clock.Stop();
        _current = "";

        return new ScanSummary
        {
            Kind = Kind,
            FilesScanned = _scanned,
            ThreatCount = _threats,
            Errors = _errors,
            Duration = _clock.Elapsed,
            Cancelled = ct.IsCancellationRequested,
            Threats = _found.ToList()
        };
    }

    private static readonly string WinSxS = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "WinSxS");

    private void Enumerate(ScanTarget target, BlockingCollection<string> queue, CancellationToken ct)
    {
        if (File.Exists(target.Path)) { Add(target.Path, false, queue, ct); return; }
        if (!Directory.Exists(target.Path)) return;

        var opts = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint, RecurseSubdirectories = false };
        var stack = new Stack<(string Dir, int Depth)>();
        stack.Push((target.Path, 0));
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            _running.Wait(ct);
            var (dir, depth) = stack.Pop();
            if (_engine.IsExcluded(dir.TrimEnd('\\') + "\\") || dir.Equals(WinSxS, StringComparison.OrdinalIgnoreCase)) continue;
            try { foreach (var f in Directory.EnumerateFiles(dir, "*", opts)) Add(f, target.RiskyOnly, queue, ct); } catch { }
            if (depth < target.MaxDepth)
                try { foreach (var sub in Directory.EnumerateDirectories(dir, "*", opts)) stack.Push((sub, depth + 1)); } catch { }
        }
    }

    private void Add(string file, bool riskyOnly, BlockingCollection<string> queue, CancellationToken ct)
    {
        if (riskyOnly && !ScanEngine.IsRisky(file)) return;
        // Dédoublonnage seulement si les cibles peuvent se recouvrir (évite de garder
        // en mémoire le chemin de chaque fichier lors d'une analyse complète).
        if (_targets.Count > 1 && Kind != ScanKind.Full && !_seen.TryAdd(file, 0)) return;
        Interlocked.Increment(ref _discovered);
        queue.Add(file, ct);
    }

    private void Work(BlockingCollection<string> queue, CancellationToken ct)
    {
        Thread.CurrentThread.Priority = ThreadPriority.BelowNormal;
        try
        {
            foreach (var file in queue.GetConsumingEnumerable(ct))
            {
                _running.Wait(ct);
                _current = file;
                var r = _engine.ScanFile(file, ct);
                Interlocked.Increment(ref _scanned);
                Interlocked.Add(ref _bytes, r.Size);
                if (r.Verdict == Verdict.Error) Interlocked.Increment(ref _errors);
                if (r.IsThreat)
                {
                    Interlocked.Increment(ref _threats);
                    _found.Enqueue(r);
                    try { ThreatFound?.Invoke(r); } catch { }
                }
            }
        }
        catch (OperationCanceledException) { }
    }
}

/// <summary>Cibles prédéfinies des analyses rapide, complète et USB.</summary>
public static class ScanTargets
{
    public static string DownloadsFolder()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders");
            if (k?.GetValue("{374DE290-123F-4565-9164-39C4925E467B}") is string p && Directory.Exists(p)) return p;
        }
        catch { }
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
    }

    public static List<ScanTarget> Quick()
    {
        var list = new List<ScanTarget>();
        foreach (var p in RunningProcessImages()) list.Add(new ScanTarget { Path = p });
        foreach (var item in StartupItems.Enumerate())
            foreach (var f in item.Files) list.Add(new ScanTarget { Path = f });

        string Env(Environment.SpecialFolder f) => Environment.GetFolderPath(f);
        list.Add(new ScanTarget { Path = Env(Environment.SpecialFolder.Startup) });
        list.Add(new ScanTarget { Path = Env(Environment.SpecialFolder.CommonStartup) });
        list.Add(new ScanTarget { Path = DownloadsFolder(), MaxDepth = 4 });
        list.Add(new ScanTarget { Path = Env(Environment.SpecialFolder.DesktopDirectory), MaxDepth = 2, RiskyOnly = true });
        list.Add(new ScanTarget { Path = Path.GetTempPath(), MaxDepth = 3, RiskyOnly = true });
        list.Add(new ScanTarget { Path = Env(Environment.SpecialFolder.ApplicationData), MaxDepth = 3, RiskyOnly = true });
        list.Add(new ScanTarget { Path = Env(Environment.SpecialFolder.LocalApplicationData), MaxDepth = 2, RiskyOnly = true });
        list.Add(new ScanTarget { Path = Env(Environment.SpecialFolder.CommonApplicationData), MaxDepth = 2, RiskyOnly = true });
        list.Add(new ScanTarget { Path = Path.Combine(Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public"), MaxDepth = 3, RiskyOnly = true });
        return list;
    }

    public static List<ScanTarget> Full() =>
        DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
            .Select(d => new ScanTarget { Path = d.RootDirectory.FullName }).ToList();

    public static List<ScanTarget> Paths(IEnumerable<string> paths) =>
        paths.Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => new ScanTarget { Path = p }).ToList();

    public static IEnumerable<string> RunningProcessImages()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (p.Id <= 4) continue;
                var path = ProcessInfo.GetImagePath(p.Id);
                if (!string.IsNullOrEmpty(path)) set.Add(path);
            }
            catch { }
            finally { p.Dispose(); }
        }
        return set;
    }
}

public sealed class StartupItem
{
    public string Name { get; init; } = "";
    public string Command { get; init; } = "";
    public string Location { get; init; } = "";
    public List<string> Files { get; init; } = new();
}

/// <summary>Programmes lancés au démarrage (clés Run du registre et dossiers Démarrage).</summary>
public static class StartupItems
{
    private static readonly Regex PathPattern = new(@"[A-Za-z]:\\[^""<>|*?\r\n]+?\.(exe|dll|scr|com|bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1|lnk|cpl)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static List<StartupItem> Enumerate()
    {
        var items = new List<StartupItem>();
        void ReadKey(RegistryHive hive, RegistryView view, string sub, string label)
        {
            try
            {
                using var root = RegistryKey.OpenBaseKey(hive, view);
                using var key = root.OpenSubKey(sub);
                if (key == null) return;
                foreach (var name in key.GetValueNames())
                    if (key.GetValue(name) is string cmd && !string.IsNullOrWhiteSpace(cmd))
                        items.Add(new StartupItem { Name = string.IsNullOrEmpty(name) ? "(défaut)" : name, Command = cmd, Location = label, Files = ExtractFiles(cmd) });
            }
            catch { }
        }
        const string run = @"Software\Microsoft\Windows\CurrentVersion\Run";
        const string runOnce = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
        ReadKey(RegistryHive.CurrentUser, RegistryView.Default, run, "Registre utilisateur (Run)");
        ReadKey(RegistryHive.CurrentUser, RegistryView.Default, runOnce, "Registre utilisateur (RunOnce)");
        ReadKey(RegistryHive.LocalMachine, RegistryView.Registry64, run, "Registre système (Run)");
        ReadKey(RegistryHive.LocalMachine, RegistryView.Registry64, runOnce, "Registre système (RunOnce)");
        ReadKey(RegistryHive.LocalMachine, RegistryView.Registry32, run, "Registre système 32 bits (Run)");

        foreach (var (dir, label) in new[] {
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup), "Dossier Démarrage (utilisateur)"),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Dossier Démarrage (tous)") })
        {
            try
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var f in Directory.EnumerateFiles(dir))
                    if (!f.EndsWith("desktop.ini", StringComparison.OrdinalIgnoreCase))
                        items.Add(new StartupItem { Name = Path.GetFileName(f), Command = f, Location = label, Files = new() { f } });
            }
            catch { }
        }
        return items;
    }

    public static List<string> ExtractFiles(string command)
    {
        var expanded = Environment.ExpandEnvironmentVariables(command.Trim());
        var files = new List<string>();
        foreach (Match m in PathPattern.Matches(expanded))
        {
            var p = m.Value.Trim();
            if (File.Exists(p) && !files.Contains(p, StringComparer.OrdinalIgnoreCase)) files.Add(p);
        }
        return files;
    }
}
