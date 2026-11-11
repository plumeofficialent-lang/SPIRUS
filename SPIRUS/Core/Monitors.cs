using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Vigie.Core.Engine;

namespace Vigie.Core;

/// <summary>
/// Protection en temps réel : surveille les écritures sur tous les disques internes,
/// analyse chaque fichier dès qu'il est fini d'écrire, et repère les comportements de rançongiciel.
/// </summary>
public sealed class FileMonitor : IDisposable
{
    private readonly ScanEngine _engine;
    private readonly Func<AppSettings> _settings;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, (DateTime Last, int Tries)> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<(DateTime Time, int Weight, string Path)> _ransomEvents = new();
    private readonly string _profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private readonly string _dataDir = AppPaths.Normalize(AppPaths.DataDir);
    private Timer _timer;
    private int _busy;
    private DateTime _lastRansomAlert = DateTime.MinValue;
    private long _scanned;

    public bool Running { get; private set; }
    public long FilesScanned => Interlocked.Read(ref _scanned);
    public event Action<ScanResult> ThreatDetected;
    public event Action<string, string> RansomwareSuspected; // (message, dossier)

    public FileMonitor(ScanEngine engine, Func<AppSettings> settings)
    {
        _engine = engine;
        _settings = settings;
    }

    public void Start()
    {
        if (Running) return;
        foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady))
        {
            try
            {
                var w = new FileSystemWatcher(drive.RootDirectory.FullName)
                {
                    IncludeSubdirectories = true,
                    InternalBufferSize = 64 * 1024,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
                };
                w.Created += (_, e) => OnChange(e.FullPath, false);
                w.Changed += (_, e) => OnChange(e.FullPath, false);
                w.Renamed += (_, e) => { OnChange(e.FullPath, true); RansomRename(e.OldFullPath, e.FullPath); };
                w.Error += (_, _) => { };
                w.EnableRaisingEvents = true;
                _watchers.Add(w);
            }
            catch { }
        }
        _timer = new Timer(_ => Process(), null, 700, 700);
        Running = true;
    }

    public void Stop()
    {
        Running = false;
        _timer?.Dispose();
        _timer = null;
        foreach (var w in _watchers) { try { w.EnableRaisingEvents = false; w.Dispose(); } catch { } }
        _watchers.Clear();
        _pending.Clear();
    }

    private static readonly string[] PartialSuffixes = { ".tmp", ".crdownload", ".part", ".partial", ".download", ".opdownload", "~" };

    private void OnChange(string path, bool renamed)
    {
        if (path.StartsWith(_dataDir, StringComparison.OrdinalIgnoreCase)) return;
        var name = Path.GetFileName(path);
        if (name.StartsWith("~$") || PartialSuffixes.Any(s => path.EndsWith(s, StringComparison.OrdinalIgnoreCase))) return;
        if (!renamed) RansomNote(path, name);
        if (!_settings().RealTimeAllFileTypes && !ScanEngine.IsRisky(path) && !InEntryZone(path)) return;
        _pending[path] = (DateTime.UtcNow, 0);
    }

    /// <summary>Zones d'arrivée des fichiers (Téléchargements, Bureau) : tout y est analysé, quel que soit le type.</summary>
    private readonly string[] _entryZones =
    {
        AppPaths.Normalize(ScanTargets.DownloadsFolder()),
        AppPaths.Normalize(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory))
    };

    private bool InEntryZone(string path)
    {
        foreach (var zone in _entryZones)
            if (zone.Length > 3 && path.StartsWith(zone, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private void Process()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            var now = DateTime.UtcNow;
            foreach (var kv in _pending)
            {
                if ((now - kv.Value.Last).TotalMilliseconds < 1200) continue; // on attend la fin de l'écriture
                if (!_pending.TryRemove(kv.Key, out var v)) continue;
                if (!File.Exists(kv.Key) || _engine.IsExcluded(kv.Key)) continue;
                var r = _engine.ScanFile(kv.Key);
                Interlocked.Increment(ref _scanned);
                if (r.Verdict == Verdict.Error && v.Tries < 10 && r.Error.StartsWith("Fichier inaccessible"))
                {
                    _pending.TryAdd(kv.Key, (now, v.Tries + 1));
                    continue;
                }
                // Fichier de données repéré par une simple règle : ignoré en temps réel (voir Guardian).
                if (r.IsThreat && r.AutoActionSafe) ThreatDetected?.Invoke(r);
            }
            EvaluateRansomware();
        }
        catch { }
        finally { Interlocked.Exchange(ref _busy, 0); }
    }

    // ------------------------------------------------------------ anti-rançongiciel

    private static readonly HashSet<string> DocExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", ".odt", ".ods", ".jpg", ".jpeg", ".png",
        ".gif", ".bmp", ".mp3", ".mp4", ".mov", ".avi", ".zip", ".rar", ".7z", ".psd", ".csv", ".heic", ".raw", ".wav"
    };

    private static readonly HashSet<string> RansomExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".locked", ".encrypted", ".crypted", ".crypt", ".enc", ".locky", ".wncry", ".wnry", ".cerber", ".zepto", ".odin",
        ".crypz", ".cryp1", ".ryuk", ".conti", ".lockbit", ".djvu", ".stop", ".phobos", ".makop", ".dharma", ".id", ".pay2key"
    };

    private bool InUserData(string path) =>
        _settings().RansomwareGuardEnabled
        && path.StartsWith(_profile + "\\", StringComparison.OrdinalIgnoreCase)
        && path.IndexOf("\\AppData\\", StringComparison.OrdinalIgnoreCase) < 0;

    private void RansomRename(string oldPath, string newPath)
    {
        if (!InUserData(newPath)) return;
        var oldExt = Path.GetExtension(oldPath);
        var newExt = Path.GetExtension(newPath);
        if (string.Equals(oldExt, newExt, StringComparison.OrdinalIgnoreCase)) return;
        if (RansomExts.Contains(newExt)) _ransomEvents.Enqueue((DateTime.UtcNow, 3, newPath));
        else if (DocExts.Contains(oldExt) && !DocExts.Contains(newExt) && newExt != ".tmp" && newPath.StartsWith(oldPath, StringComparison.OrdinalIgnoreCase))
            _ransomEvents.Enqueue((DateTime.UtcNow, 1, newPath)); // extension inconnue ajoutée à un document
    }

    private void RansomNote(string path, string name)
    {
        if (!InUserData(path)) return;
        var n = name.ToLowerInvariant();
        bool note = (n.EndsWith(".txt") || n.EndsWith(".html") || n.EndsWith(".hta"))
                    && (n.Contains("decrypt") || n.Contains("restore_files") || n.Contains("recover") || n.Contains("how_to") || n.Contains("readme_for") || n.Contains("ransom") || n.Contains("_readme"));
        if (note) _ransomEvents.Enqueue((DateTime.UtcNow, 6, path));
    }

    private void EvaluateRansomware()
    {
        var limit = DateTime.UtcNow.AddSeconds(-15);
        while (_ransomEvents.TryPeek(out var e) && e.Time < limit) _ransomEvents.TryDequeue(out _);
        var events = _ransomEvents.ToArray();
        int weight = events.Sum(e => e.Weight);
        if (weight < 30 || (DateTime.UtcNow - _lastRansomAlert).TotalMinutes < 2) return;
        _lastRansomAlert = DateTime.UtcNow;
        var dir = events.GroupBy(e => Path.GetDirectoryName(e.Path)).OrderByDescending(g => g.Count()).First().Key;
        var exts = events.Select(e => Path.GetExtension(e.Path)).GroupBy(x => x).OrderByDescending(g => g.Count()).First().Key;
        RansomwareSuspected?.Invoke($"{events.Length} fichiers renommés ou chiffrés en quelques secondes (extension « {exts} »).", dir);
    }

    public void Dispose() => Stop();
}

/// <summary>Analyse chaque nouveau programme lancé sur l'ordinateur.</summary>
public sealed class ProcessMonitor : IDisposable
{
    private readonly ScanEngine _engine;
    private HashSet<int> _known = new();
    private Timer _timer;
    private int _busy;
    private bool _first = true;

    public bool Running { get; private set; }
    public event Action<ScanResult, int, string> ThreatDetected; // résultat, pid, nom du processus

    public ProcessMonitor(ScanEngine engine) => _engine = engine;

    public void Start()
    {
        if (Running) return;
        _first = true;
        _timer = new Timer(_ => Tick(), null, 1500, 2500);
        Running = true;
    }

    public void Stop()
    {
        Running = false;
        _timer?.Dispose();
        _timer = null;
        _known.Clear();
    }

    private void Tick()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            var current = new HashSet<int>();
            foreach (var p in System.Diagnostics.Process.GetProcesses())
            {
                using (p)
                {
                    current.Add(p.Id);
                    if (p.Id <= 4 || p.Id == Environment.ProcessId || _known.Contains(p.Id)) continue;
                    try
                    {
                        var path = ProcessInfo.GetImagePath(p.Id);
                        if (string.IsNullOrEmpty(path) || !File.Exists(path)) continue;
                        if (_first) Thread.Sleep(5); // analyse initiale en douceur
                        var r = _engine.ScanFile(path);
                        if (r.IsThreat) ThreatDetected?.Invoke(r, p.Id, p.ProcessName);
                    }
                    catch { }
                }
            }
            _known = current;
            if (_first) MemoryTrim.Run(); // l'analyse initiale de tous les programmes est terminée
            _first = false;
        }
        catch { }
        finally { Interlocked.Exchange(ref _busy, 0); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [DllImport("kernel32.dll")] private static extern bool GetProcessIoCounters(IntPtr process, out IoCounters counters);

    /// <summary>Repère le processus qui écrit le plus sur le disque (suspect en cas d'attaque de rançongiciel).</summary>
    public static (int Pid, string Name, string Path)? TopWriter(TimeSpan window)
    {
        Dictionary<int, ulong> Sample()
        {
            var d = new Dictionary<int, ulong>();
            foreach (var p in System.Diagnostics.Process.GetProcesses())
                using (p)
                    try { if (p.Id > 4 && p.Id != Environment.ProcessId && GetProcessIoCounters(p.Handle, out var c)) d[p.Id] = c.WriteBytes; } catch { }
            return d;
        }
        var a = Sample();
        Thread.Sleep(window);
        var b = Sample();
        var top = b.Where(kv => a.ContainsKey(kv.Key)).Select(kv => (Pid: kv.Key, Delta: kv.Value - a[kv.Key]))
            .OrderByDescending(x => x.Delta).FirstOrDefault();
        if (top.Delta < 512 * 1024) return null;
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(top.Pid);
            var path = ProcessInfo.GetImagePath(top.Pid) ?? "";
            if (path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase)) return null;
            return (top.Pid, proc.ProcessName, path);
        }
        catch { return null; }
    }

    public void Dispose() => Stop();
}

/// <summary>Détecte le branchement des clés USB et disques amovibles.</summary>
public sealed class UsbMonitor : IDisposable
{
    private HashSet<string> _known = new(StringComparer.OrdinalIgnoreCase);
    private Timer _timer;

    public bool Running { get; private set; }
    public event Action<DriveInfo> DriveArrived;

    public void Start()
    {
        if (Running) return;
        _known = Current().Select(d => d.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        _timer = new Timer(_ => Tick(), null, 2000, 2000);
        Running = true;
    }

    public void Stop()
    {
        Running = false;
        _timer?.Dispose();
        _timer = null;
    }

    private static List<DriveInfo> Current()
    {
        try { return DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Removable && d.IsReady).ToList(); }
        catch { return new(); }
    }

    private void Tick()
    {
        var now = Current();
        foreach (var d in now)
            if (!_known.Contains(d.Name)) DriveArrived?.Invoke(d);
        _known = now.Select(d => d.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    public void Dispose() => Stop();
}
