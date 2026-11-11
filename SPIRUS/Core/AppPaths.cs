namespace Vigie.Core;

/// <summary>Emplacements des données de SPIRUS (%LocalAppData%\SPIRUS, ou SPIRUS_DATA si défini).</summary>
public static class AppPaths
{
    public static string DataDir { get; } = ResolveDataDir();
    public static string QuarantineDir => Path.Combine(DataDir, "Quarantaine");
    public static string SignaturesDir => Path.Combine(DataDir, "Signatures");
    public static string SettingsFile => Path.Combine(DataDir, "settings.json");
    public static string JournalFile => Path.Combine(DataDir, "journal.jsonl");
    public static string HashDbFile => Path.Combine(SignaturesDir, "hashes.txt");
    public static string CustomRulesFile => Path.Combine(SignaturesDir, "custom-rules.json");
    public static string AppDir => AppContext.BaseDirectory;

    private static string ResolveDataDir()
    {
        var overrideDir = Environment.GetEnvironmentVariable("SPIRUS_DATA");
        if (!string.IsNullOrWhiteSpace(overrideDir)) return Path.GetFullPath(overrideDir);
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var dir = Path.Combine(local, "SPIRUS");
        // Reprise des données de l'ancien nom de l'application (Vigie) : réglages, journal, quarantaine.
        var legacy = Path.Combine(local, "Vigie");
        try { if (!Directory.Exists(dir) && Directory.Exists(legacy)) Directory.Move(legacy, dir); } catch { }
        return dir;
    }

    public static void EnsureCreated()
    {
        Directory.CreateDirectory(DataDir);
        Directory.CreateDirectory(QuarantineDir);
        Directory.CreateDirectory(SignaturesDir);
    }

    /// <summary>Dossiers qui ne doivent jamais être analysés (SPIRUS lui-même et sa quarantaine).</summary>
    public static IEnumerable<string> SelfExclusions()
    {
        yield return Normalize(DataDir);
        yield return Normalize(AppDir);
    }

    public static string Normalize(string path)
    {
        try { path = Path.GetFullPath(path); } catch { }
        return path.TrimEnd('\\', '/') + "\\";
    }
}
