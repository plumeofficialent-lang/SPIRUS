namespace Vigie.Core;

public enum Verdict { Clean, Suspicious, Malicious, Skipped, Error }

public enum Sensitivity { Low, Normal, High }

/// <summary>Origine d'une détection (affichée dans le journal et les alertes).</summary>
public enum DetectionSource { ManualScan, RealTime, Process, Usb, Ransomware, Scheduled, ContextMenu }

public enum ScanKind { Quick, Full, Custom, Usb, Scheduled }

public sealed class ScanResult
{
    public string Path { get; set; } = "";
    /// <summary>Chemin affiché (pour une archive : « archive.zip ▸ dossier/fichier.exe »).</summary>
    public string DisplayPath { get; set; } = "";
    public Verdict Verdict { get; set; }
    public int Score { get; set; }
    public string ThreatName { get; set; } = "";
    public string Category { get; set; } = "";
    public string Engine { get; set; } = "";
    public List<string> Reasons { get; set; } = new();
    public string Sha256 { get; set; } = "";
    public long Size { get; set; }
    public bool Signed { get; set; }
    public string Error { get; set; } = "";

    /// <summary>
    /// Vrai si la mise en quarantaine automatique est sûre : contenu actif (programme, script,
    /// document, archive) ou menace confirmée par empreinte / moteur Windows.
    /// Un simple fichier de données n'est jamais déplacé sans votre accord.
    /// </summary>
    public bool AutoActionSafe { get; set; }

    public bool IsThreat => Verdict is Verdict.Suspicious or Verdict.Malicious;

    public string VerdictLabel => Verdict switch
    {
        Verdict.Malicious => "Menace",
        Verdict.Suspicious => "Suspect",
        Verdict.Skipped => "Ignoré",
        Verdict.Error => "Erreur",
        _ => "Sain"
    };

    public string ReasonsText => string.Join(" • ", Reasons);

    public static ScanResult Clean(string path) => new() { Path = path, DisplayPath = path, Verdict = Verdict.Clean };
}

public sealed class ScanProgress
{
    public long Scanned { get; init; }
    public long Discovered { get; init; }
    public bool EnumerationDone { get; init; }
    public int Threats { get; init; }
    public string CurrentFile { get; init; } = "";
    public TimeSpan Elapsed { get; init; }
    public long BytesScanned { get; init; }

    public double Percent => EnumerationDone && Discovered > 0 ? Math.Min(100.0, Scanned * 100.0 / Discovered) : -1;
}

public sealed class ScanSummary
{
    public ScanKind Kind { get; init; }
    public long FilesScanned { get; init; }
    public int ThreatCount { get; init; }
    public int Errors { get; init; }
    public TimeSpan Duration { get; init; }
    public bool Cancelled { get; init; }
    public DateTime Finished { get; init; } = DateTime.Now;
    public List<ScanResult> Threats { get; init; } = new();
}

public sealed class QuarantineItem
{
    public string Id { get; set; } = "";
    public string OriginalPath { get; set; } = "";
    public string ThreatName { get; set; } = "";
    public string Category { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public long Size { get; set; }
    public DateTime Date { get; set; }
    public string Key { get; set; } = "";

    public string FileName => System.IO.Path.GetFileName(OriginalPath);
    public string DateText => Date.ToString("dd/MM/yyyy HH:mm");
    public string SizeText => Format.Size(Size);
}

public enum LogLevel { Info, Success, Warning, Threat }

public sealed class LogEntry
{
    public DateTime Time { get; set; } = DateTime.Now;
    public LogLevel Level { get; set; }
    public string Title { get; set; } = "";
    public string Detail { get; set; } = "";

    public string TimeText => Time.ToString("dd/MM HH:mm:ss");
}

public static class Format
{
    public static string Size(long bytes)
    {
        string[] units = { "o", "Ko", "Mo", "Go", "To" };
        double v = bytes;
        int u = 0;
        while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
        return u == 0 ? $"{bytes} o" : $"{v:0.#} {units[u]}";
    }

    public static string Duration(TimeSpan t) =>
        t.TotalHours >= 1 ? $"{(int)t.TotalHours} h {t.Minutes:00} min" :
        t.TotalMinutes >= 1 ? $"{t.Minutes} min {t.Seconds:00} s" :
        $"{t.TotalSeconds:0.0} s";

    public static string Ago(DateTime? date)
    {
        if (date is null || date == DateTime.MinValue) return "Jamais";
        var d = DateTime.Now - date.Value;
        if (d.TotalMinutes < 1) return "À l'instant";
        if (d.TotalHours < 1) return $"Il y a {(int)d.TotalMinutes} min";
        if (d.TotalDays < 1) return $"Il y a {(int)d.TotalHours} h";
        if (d.TotalDays < 2) return "Hier";
        return $"Il y a {(int)d.TotalDays} jours";
    }
}
