using System.Text.Json;

namespace Vigie.Core;

public sealed class AppSettings
{
    // Protection
    public bool RealTimeEnabled { get; set; } = true;
    public bool ProcessMonitorEnabled { get; set; } = true;
    public bool UsbMonitorEnabled { get; set; } = true;
    public bool UsbAutoScan { get; set; } = true;
    public bool RansomwareGuardEnabled { get; set; } = true;
    public bool AmsiEnabled { get; set; } = true;
    public bool ScanArchives { get; set; } = true;
    public bool RealTimeAllFileTypes { get; set; }
    public bool AutoQuarantine { get; set; } = true;
    public Sensitivity Sensitivity { get; set; } = Sensitivity.Normal;
    public int MaxFileSizeMB { get; set; } = 150;

    // Système
    public bool StartWithWindows { get; set; }
    public bool ContextMenuEnabled { get; set; }
    public bool MinimizeToTray { get; set; } = true;
    public bool Notifications { get; set; } = true;
    public bool TrayHintShown { get; set; }

    // Exclusions et fichiers autorisés
    public List<string> Exclusions { get; set; } = new();
    public List<string> AllowedHashes { get; set; } = new();

    // Signatures
    public string MalwareBazaarKey { get; set; } = "";
    public bool AutoUpdateSignatures { get; set; } = true;
    public DateTime? LastSignatureUpdate { get; set; }

    // Mises à jour de l'application (releases GitHub)
    public bool AutoUpdate { get; set; } = true;
    public DateTime? LastUpdateCheck { get; set; }
    public string LastRunVersion { get; set; } = "";

    // Analyse planifiée
    public bool ScheduledScanEnabled { get; set; }
    public int ScheduledScanHour { get; set; } = 12;
    public DateTime? LastScheduledScan { get; set; }

    // Statistiques
    public long TotalFilesScanned { get; set; }
    public long TotalThreatsBlocked { get; set; }
    public DateTime? LastScanDate { get; set; }
    public string LastScanKind { get; set; } = "";
    public int LastScanThreats { get; set; }
}

public static class SettingsStore
{
    private static readonly object Lock = new();
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(AppPaths.SettingsFile))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(AppPaths.SettingsFile)) ?? new AppSettings();
        }
        catch { }
        return new AppSettings();
    }

    public static void Save(AppSettings settings)
    {
        lock (Lock)
        {
            try
            {
                AppPaths.EnsureCreated();
                var tmp = AppPaths.SettingsFile + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(settings, Json));
                File.Move(tmp, AppPaths.SettingsFile, true);
            }
            catch { }
        }
    }
}
