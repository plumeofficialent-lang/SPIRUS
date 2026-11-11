using System.Collections.Concurrent;
using Vigie.Core.Engine;

namespace Vigie.Core;

public sealed class ThreatAlert
{
    public ScanResult Result { get; init; }
    public DetectionSource Source { get; init; }
    public bool Handled { get; set; }
    public string Error { get; set; }
    public int? Pid { get; init; }
    public string ProcessName { get; init; }

    // Alerte anti-rançongiciel
    public bool IsRansomware { get; init; }
    public string Message { get; init; }
    public string Folder { get; init; }
    public (int Pid, string Name, string Path)? Suspect { get; init; }
}

/// <summary>
/// Chef d'orchestre de SPIRUS : moteur, protections en temps réel, analyses, quarantaine,
/// planification et mises à jour. L'interface ne fait que s'abonner à ses événements.
/// </summary>
public sealed class Guardian : IDisposable
{
    private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _statsLock = new();
    private Timer _scheduler;
    private bool _updating;

    public AppSettings Settings { get; }
    public ScanEngine Engine { get; }
    public QuarantineManager Quarantine { get; }
    public ActivityLog Log { get; }
    public FileMonitor Files { get; }
    public ProcessMonitor Processes { get; }
    public UsbMonitor Usb { get; }
    public ScanJob CurrentJob { get; private set; }
    public ScanSummary LastSummary { get; private set; }
    public bool IsElevated { get; } = ProcessInfo.IsElevated();

    public event Action<ThreatAlert> Alert;
    public event Action StatusChanged;
    public event Action<ScanJob> ScanStarted;
    public event Action<ScanSummary> ScanCompleted;
    public event Action<DriveInfo> UsbArrived;
    /// <summary>Une nouvelle version a été trouvée ; le booléen indique si elle s'installe automatiquement.</summary>
    public event Action<UpdateInfo, bool> UpdateFound;

    /// <summary>Activé par l'application installée (désactivé pour les outils et les captures de test).</summary>
    public bool UpdatesEnabled { get; set; }
    /// <summary>Version précédente si SPIRUS vient d'être mis à jour, sinon null.</summary>
    public string JustUpdatedFrom { get; private set; }
    private readonly DateTime _startedAt = DateTime.Now;
    private bool _checkingUpdate;

    public Guardian()
    {
        AppPaths.EnsureCreated();
        Settings = SettingsStore.Load();
        Log = new ActivityLog();
        Engine = new ScanEngine(() => Settings);
        Quarantine = new QuarantineManager();
        Files = new FileMonitor(Engine, () => Settings);
        Processes = new ProcessMonitor(Engine);
        Usb = new UsbMonitor();

        Files.ThreatDetected += r => HandleThreat(r, DetectionSource.RealTime);
        Files.RansomwareSuspected += OnRansomware;
        Processes.ThreatDetected += (r, pid, name) => HandleThreat(r, DetectionSource.Process, pid, name);
        Usb.DriveArrived += OnDriveArrived;
    }

    public void Start()
    {
        ApplySettings(false);
        Log.Add(LogLevel.Info, "SPIRUS a démarré",
            $"{Engine.Rules.Rules.Count} règles, {Engine.Hashes.Count} empreintes. Moteur Windows (AMSI) : {(Engine.AmsiAvailable ? "disponible" : "indisponible")}.");
        if (!string.IsNullOrEmpty(Engine.Rules.LoadWarning)) Log.Add(LogLevel.Warning, "Règles personnalisées", Engine.Rules.LoadWarning);
        if (Settings.LastRunVersion != Updater.CurrentText)
        {
            if (!string.IsNullOrEmpty(Settings.LastRunVersion))
            {
                JustUpdatedFrom = Settings.LastRunVersion;
                Log.Add(LogLevel.Success, $"SPIRUS mis à jour en version {Updater.CurrentText}", $"Version précédente : {JustUpdatedFrom}");
            }
            Settings.LastRunVersion = Updater.CurrentText;
            Save();
        }
        _scheduler = new Timer(_ => SchedulerTick(), null, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(1));
    }

    /// <summary>Applique les réglages : démarre ou arrête chaque protection, puis enregistre.</summary>
    public void ApplySettings(bool save = true)
    {
        Toggle(Settings.RealTimeEnabled, Files.Running, Files.Start, Files.Stop);
        Toggle(Settings.ProcessMonitorEnabled, Processes.Running, Processes.Start, Processes.Stop);
        Toggle(Settings.UsbMonitorEnabled, Usb.Running, Usb.Start, Usb.Stop);
        Engine.ClearCache();
        if (save) SettingsStore.Save(Settings);
        StatusChanged?.Invoke();
    }

    private static void Toggle(bool wanted, bool running, Action start, Action stop)
    {
        if (wanted && !running) start();
        else if (!wanted && running) stop();
    }

    public void Save() => SettingsStore.Save(Settings);

    public bool FullyProtected => Settings.RealTimeEnabled && Settings.ProcessMonitorEnabled && Settings.RansomwareGuardEnabled;

    // ------------------------------------------------------------ analyses

    public ScanJob StartScan(ScanKind kind, IEnumerable<string> paths = null)
    {
        if (CurrentJob != null) return null;
        var targets = kind switch
        {
            ScanKind.Quick or ScanKind.Scheduled => ScanTargets.Quick(),
            ScanKind.Full => ScanTargets.Full(),
            _ => ScanTargets.Paths(paths ?? Array.Empty<string>())
        };
        var job = new ScanJob(Engine, kind, targets);
        job.ThreatFound += r =>
        {
            Log.Add(LogLevel.Threat, $"{r.VerdictLabel} : {r.ThreatName}", r.DisplayPath);
            if (r.Verdict == Verdict.Malicious && r.AutoActionSafe && Settings.AutoQuarantine) QuarantineThreat(r, out _);
        };
        CurrentJob = job;
        Log.Add(LogLevel.Info, $"{KindLabel(kind)} lancée", paths != null ? string.Join(", ", paths) : "");
        ScanStarted?.Invoke(job);

        job.RunAsync().ContinueWith(t =>
        {
            var s = t.IsCompletedSuccessfully ? t.Result : new ScanSummary { Kind = kind, Cancelled = true };
            Settings.TotalFilesScanned += s.FilesScanned;
            Settings.LastScanDate = DateTime.Now;
            Settings.LastScanKind = KindLabel(kind);
            Settings.LastScanThreats = s.ThreatCount;
            Save();
            LastSummary = s;
            CurrentJob = null;
            Log.Add(s.ThreatCount > 0 ? LogLevel.Warning : LogLevel.Success,
                $"{KindLabel(kind)} {(s.Cancelled ? "interrompue" : "terminée")}",
                $"{s.FilesScanned:N0} fichiers en {Format.Duration(s.Duration)} — {s.ThreatCount} menace(s).");
            ScanCompleted?.Invoke(s);
            StatusChanged?.Invoke();
            MemoryTrim.Run();
        });
        return job;
    }

    public static string KindLabel(ScanKind k) => k switch
    {
        ScanKind.Quick => "Analyse rapide",
        ScanKind.Full => "Analyse complète",
        ScanKind.Usb => "Analyse du périphérique USB",
        ScanKind.Scheduled => "Analyse planifiée",
        _ => "Analyse personnalisée"
    };

    // ------------------------------------------------------------ menaces

    private void HandleThreat(ScanResult r, DetectionSource source, int? pid = null, string processName = null)
    {
        // En temps réel, un fichier de données (base d'application, cache, journal, historique…) repéré
        // uniquement par une règle n'est pas une menace exécutable : on ne dérange pas l'utilisateur.
        // Les analyses manuelles continuent de le signaler, sans jamais le déplacer automatiquement.
        if (source == DetectionSource.RealTime && !r.AutoActionSafe) return;

        var key = r.Path + "|" + r.Sha256;
        if (_recentAlerts.TryGetValue(key, out var last) && (DateTime.Now - last).TotalSeconds < 60) return;
        _recentAlerts[key] = DateTime.Now;
        if (_recentAlerts.Count > 500) _recentAlerts.Clear();

        var origin = source == DetectionSource.Process ? $"Processus en cours : {processName} (PID {pid})" : "Protection en temps réel";
        Log.Add(LogLevel.Threat, $"{r.VerdictLabel} : {r.ThreatName}", $"{r.DisplayPath} — {origin}");

        var alert = new ThreatAlert { Result = r, Source = source, Pid = pid, ProcessName = processName };
        if (r.Verdict == Verdict.Malicious && r.AutoActionSafe && Settings.AutoQuarantine)
        {
            alert.Handled = QuarantineThreat(r, out var err);
            alert.Error = err;
        }
        Alert?.Invoke(alert);
    }

    public bool QuarantineThreat(ScanResult r, out string error)
    {
        var item = Quarantine.Add(r, out error);
        if (item == null)
        {
            Log.Add(LogLevel.Warning, "Échec de la mise en quarantaine", $"{r.Path} — {error}");
            return false;
        }
        lock (_statsLock) Settings.TotalThreatsBlocked++; // plusieurs analyses peuvent neutraliser en même temps
        Save();
        Log.Add(LogLevel.Success, "Menace mise en quarantaine", $"{r.ThreatName} — {r.Path}");
        StatusChanged?.Invoke();
        return true;
    }

    public void AllowFile(ScanResult r)
    {
        if (!string.IsNullOrEmpty(r.Sha256) && !Settings.AllowedHashes.Contains(r.Sha256, StringComparer.OrdinalIgnoreCase))
            Settings.AllowedHashes.Add(r.Sha256);
        Save();
        Engine.ClearCache();
        Log.Add(LogLevel.Info, "Fichier autorisé", r.Path);
    }

    public bool RestoreFromQuarantine(QuarantineItem item, out string error)
    {
        if (!Quarantine.Restore(item, out var restored, out error)) return false;
        if (!string.IsNullOrEmpty(item.Sha256) && !Settings.AllowedHashes.Contains(item.Sha256, StringComparer.OrdinalIgnoreCase))
            Settings.AllowedHashes.Add(item.Sha256);
        Save();
        Engine.ClearCache();
        Log.Add(LogLevel.Info, "Fichier restauré et autorisé", restored);
        return true;
    }

    private void OnRansomware(string message, string folder)
    {
        if (!Settings.RansomwareGuardEnabled) return;
        var suspect = ProcessMonitor.TopWriter(TimeSpan.FromSeconds(1));
        Log.Add(LogLevel.Threat, "Activité de rançongiciel suspectée", $"{message} Dossier : {folder}" + (suspect is { } s ? $" — Processus suspect : {s.Name} (PID {s.Pid})" : ""));
        Alert?.Invoke(new ThreatAlert { IsRansomware = true, Message = message, Folder = folder, Suspect = suspect, Source = DetectionSource.Ransomware });
    }

    private void OnDriveArrived(DriveInfo drive)
    {
        string label;
        try { label = string.IsNullOrEmpty(drive.VolumeLabel) ? drive.Name : $"{drive.VolumeLabel} ({drive.Name.TrimEnd('\\')})"; }
        catch { label = drive.Name; }
        Log.Add(LogLevel.Info, "Périphérique amovible détecté", label);
        UsbArrived?.Invoke(drive);
        if (Settings.UsbAutoScan && CurrentJob == null) StartScan(ScanKind.Usb, new[] { drive.RootDirectory.FullName });
    }

    // ------------------------------------------------------------ planification et mises à jour

    private void SchedulerTick()
    {
        try
        {
            var now = DateTime.Now;
            if (Settings.ScheduledScanEnabled && now.Hour == Settings.ScheduledScanHour && CurrentJob == null
                && Settings.LastScheduledScan?.Date != now.Date)
            {
                Settings.LastScheduledScan = now;
                Save();
                StartScan(ScanKind.Scheduled);
            }
            if (Settings.AutoUpdateSignatures && !string.IsNullOrWhiteSpace(Settings.MalwareBazaarKey)
                && (Settings.LastSignatureUpdate == null || (now - Settings.LastSignatureUpdate.Value).TotalHours >= 12))
                _ = UpdateSignaturesAsync();
            if (UpdatesEnabled && Settings.AutoUpdate && CurrentJob == null && (now - _startedAt).TotalMinutes >= 1
                && (Settings.LastUpdateCheck == null || (now - Settings.LastUpdateCheck.Value).TotalHours >= 6))
                _ = AutoUpdateAsync();
            if (CurrentJob == null && !_updating) MemoryTrim.RunIfDue(TimeSpan.FromMinutes(10));
        }
        catch { }
    }

    public async Task<string> UpdateSignaturesAsync()
    {
        if (_updating) return "Mise à jour déjà en cours.";
        _updating = true;
        try
        {
            var (added, total, error) = await SignatureUpdater.UpdateFromMalwareBazaarAsync(Settings.MalwareBazaarKey);
            Settings.LastSignatureUpdate = DateTime.Now;
            Save();
            if (error != null)
            {
                Log.Add(LogLevel.Warning, "Mise à jour des signatures impossible", error);
                return error;
            }
            ReloadSignatures();
            var msg = $"{added:N0} nouvelles empreintes ajoutées ({total:N0} au total).";
            Log.Add(LogLevel.Success, "Signatures mises à jour", msg);
            return msg;
        }
        finally { _updating = false; StatusChanged?.Invoke(); }
    }

    // ------------------------------------------------------------ mises à jour de SPIRUS

    public async Task<(UpdateInfo Info, string Error)> CheckForUpdateAsync()
    {
        if (_checkingUpdate) return (null, "Vérification déjà en cours.");
        _checkingUpdate = true;
        try
        {
            var info = await Updater.CheckAsync();
            Settings.LastUpdateCheck = DateTime.Now;
            Save();
            return (info, null);
        }
        catch (Exception ex) { return (null, "Impossible de joindre GitHub : " + ex.Message); }
        finally { _checkingUpdate = false; }
    }

    /// <summary>Télécharge, vérifie et lance l'installeur de la nouvelle version (SPIRUS redémarre).</summary>
    public async Task<string> InstallUpdateAsync(UpdateInfo info)
    {
        var v = info.Version.ToString(3);
        try
        {
            Log.Add(LogLevel.Info, $"Téléchargement de SPIRUS {v}", info.DownloadUrl);
            var installer = await Updater.DownloadAsync(info);
            Log.Add(LogLevel.Success, $"Installation de SPIRUS {v}", "Empreinte SHA-256 vérifiée. SPIRUS redémarre.");
            Save();
            Updater.Install(installer);
            return null;
        }
        catch (Exception ex)
        {
            Log.Add(LogLevel.Warning, "Mise à jour impossible", ex.Message);
            return ex.Message;
        }
    }

    private async Task AutoUpdateAsync()
    {
        var (info, _) = await CheckForUpdateAsync();
        if (info == null) return;
        UpdateFound?.Invoke(info, true);
        await Task.Delay(TimeSpan.FromSeconds(5));
        if (CurrentJob == null) await InstallUpdateAsync(info);
    }

    public void ReloadSignatures()
    {
        Engine.Reload();
        StatusChanged?.Invoke();
    }

    public void Dispose()
    {
        _scheduler?.Dispose();
        CurrentJob?.Cancel();
        Files.Dispose();
        Processes.Dispose();
        Usb.Dispose();
        Engine.Dispose();
        Save();
    }
}
