using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Vigie.Core.Engine;

namespace Vigie.Core;

/// <summary>
/// Quarantaine : le fichier est chiffré (il ne peut plus s'exécuter ni être détecté),
/// déplacé dans le dossier de SPIRUS, et peut être restauré ou supprimé définitivement.
/// </summary>
public sealed class QuarantineManager
{
    private readonly object _lock = new();
    private readonly List<QuarantineItem> _items = new();

    public event Action Changed;

    public QuarantineManager()
    {
        AppPaths.EnsureCreated();
        foreach (var meta in Directory.EnumerateFiles(AppPaths.QuarantineDir, "*.json"))
        {
            try
            {
                var item = JsonSerializer.Deserialize<QuarantineItem>(File.ReadAllText(meta));
                if (item != null && File.Exists(DataPath(item.Id))) _items.Add(item);
            }
            catch { }
        }
    }

    public IReadOnlyList<QuarantineItem> Items
    {
        get { lock (_lock) return _items.OrderByDescending(i => i.Date).ToList(); }
    }

    public int Count { get { lock (_lock) return _items.Count; } }

    private static string DataPath(string id) => Path.Combine(AppPaths.QuarantineDir, id + ".vq");
    private static string MetaPath(string id) => Path.Combine(AppPaths.QuarantineDir, id + ".json");

    public QuarantineItem Add(ScanResult threat, out string error)
    {
        error = null;
        var path = threat.Path;
        if (!File.Exists(path)) { error = "Le fichier n'existe plus."; return null; }

        var id = Guid.NewGuid().ToString("N");
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            using (var src = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var dst = new FileStream(DataPath(id), FileMode.CreateNew, FileAccess.Write))
                Transform(src, dst, key);
        }
        catch (Exception ex) { error = "Lecture impossible : " + ex.Message; TryDelete(DataPath(id)); return null; }

        if (!DeleteOriginal(path, out var delError))
        {
            TryDelete(DataPath(id));
            error = delError;
            return null;
        }

        var item = new QuarantineItem
        {
            Id = id, OriginalPath = path, ThreatName = threat.ThreatName, Category = threat.Category,
            Sha256 = threat.Sha256, Size = threat.Size, Date = DateTime.Now, Key = Convert.ToBase64String(key)
        };
        File.WriteAllText(MetaPath(id), JsonSerializer.Serialize(item));
        lock (_lock) _items.Add(item);
        Changed?.Invoke();
        return item;
    }

    private static bool DeleteOriginal(string path, out string error)
    {
        error = null;
        for (int attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                File.SetAttributes(path, FileAttributes.Normal);
                File.Delete(path);
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                error = "Accès refusé : relancez SPIRUS en administrateur pour neutraliser ce fichier.";
                return false;
            }
            catch (IOException)
            {
                // Fichier en cours d'utilisation : on arrête le programme correspondant.
                KillProcessesUsing(path);
                Thread.Sleep(400);
                error = "Le fichier est en cours d'utilisation.";
            }
        }
        return false;
    }

    public static int KillProcessesUsing(string path)
    {
        int killed = 0;
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (p.Id == Environment.ProcessId) continue;
                if (string.Equals(ProcessInfo.GetImagePath(p.Id), path, StringComparison.OrdinalIgnoreCase))
                {
                    p.Kill(true);
                    killed++;
                }
            }
            catch { }
            finally { p.Dispose(); }
        }
        return killed;
    }

    public bool Restore(QuarantineItem item, out string restoredPath, out string error)
    {
        restoredPath = item.OriginalPath;
        error = null;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(restoredPath)!);
            if (File.Exists(restoredPath))
                restoredPath = Path.Combine(Path.GetDirectoryName(restoredPath)!,
                    Path.GetFileNameWithoutExtension(restoredPath) + " (restauré)" + Path.GetExtension(restoredPath));
            using (var src = File.OpenRead(DataPath(item.Id)))
            using (var dst = new FileStream(restoredPath, FileMode.CreateNew, FileAccess.Write))
                Transform(src, dst, Convert.FromBase64String(item.Key));
            Remove(item);
            return true;
        }
        catch (Exception ex) { error = ex.Message; return false; }
    }

    public void Delete(QuarantineItem item) => Remove(item);

    private void Remove(QuarantineItem item)
    {
        TryDelete(DataPath(item.Id));
        TryDelete(MetaPath(item.Id));
        lock (_lock) _items.RemoveAll(i => i.Id == item.Id);
        Changed?.Invoke();
    }

    private static void Transform(Stream src, Stream dst, byte[] key)
    {
        var buf = new byte[1 << 16];
        long pos = 0;
        int n;
        while ((n = src.Read(buf, 0, buf.Length)) > 0)
        {
            for (int i = 0; i < n; i++, pos++) buf[i] ^= (byte)(key[pos & 31] ^ (byte)(pos >> 5));
            dst.Write(buf, 0, n);
        }
    }

    private static void TryDelete(string p) { try { if (File.Exists(p)) File.Delete(p); } catch { } }
}

/// <summary>Journal d'activité persistant (fichier JSON Lines).</summary>
public sealed class ActivityLog
{
    private readonly object _lock = new();
    private readonly List<LogEntry> _entries = new();

    public event Action<LogEntry> Added;

    public ActivityLog()
    {
        AppPaths.EnsureCreated();
        try
        {
            if (!File.Exists(AppPaths.JournalFile)) return;
            var lines = File.ReadAllLines(AppPaths.JournalFile);
            foreach (var line in lines.TakeLast(1000))
            {
                try { var e = JsonSerializer.Deserialize<LogEntry>(line); if (e != null) _entries.Add(e); } catch { }
            }
            if (lines.Length > 5000) File.WriteAllLines(AppPaths.JournalFile, lines.TakeLast(1000));
        }
        catch { }
    }

    public IReadOnlyList<LogEntry> Entries
    {
        get { lock (_lock) return _entries.AsEnumerable().Reverse().ToList(); }
    }

    public void Add(LogLevel level, string title, string detail = "")
    {
        var e = new LogEntry { Level = level, Title = title, Detail = detail ?? "" };
        lock (_lock)
        {
            _entries.Add(e);
            if (_entries.Count > 1500) _entries.RemoveRange(0, 500);
            try { File.AppendAllText(AppPaths.JournalFile, JsonSerializer.Serialize(e) + Environment.NewLine); } catch { }
        }
        Added?.Invoke(e);
    }

    public void Clear()
    {
        lock (_lock)
        {
            _entries.Clear();
            try { File.Delete(AppPaths.JournalFile); } catch { }
        }
    }
}
