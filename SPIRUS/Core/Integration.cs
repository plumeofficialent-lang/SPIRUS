using System.Text.RegularExpressions;
using Microsoft.Win32;
using Vigie.Core.Engine;

namespace Vigie.Core;

/// <summary>Mise à jour de la base d'empreintes depuis MalwareBazaar (abuse.ch) ou depuis un fichier.</summary>
public static class SignatureUpdater
{
    private static readonly Regex Quoted = new("\"([^\"]*)\"", RegexOptions.Compiled);
    private static readonly Regex Sha256 = new(@"\b[0-9a-fA-F]{64}\b", RegexOptions.Compiled);

    public static async Task<(int Added, int Total, string Error)> UpdateFromMalwareBazaarAsync(string authKey, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(authKey)) return (0, 0, "Aucune clé d'accès abuse.ch configurée.");
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(90) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("SPIRUS-Antivirus/1.0");
            var url = $"https://mb-api.abuse.ch/v2/files/exports/{Uri.EscapeDataString(authKey.Trim())}/recent.csv";
            using var resp = await http.GetAsync(url, ct);
            if (!resp.IsSuccessStatusCode)
                return (0, 0, $"Le serveur a répondu {(int)resp.StatusCode} ({resp.ReasonPhrase}). Vérifiez votre clé d'accès.");
            var text = await resp.Content.ReadAsStringAsync(ct);

            var entries = new List<(string Sha, string Name)>();
            foreach (var line in text.Split('\n'))
            {
                if (line.Length < 64 || line.TrimStart().StartsWith('#')) continue;
                var fields = Quoted.Matches(line).Select(m => m.Groups[1].Value.Trim()).ToList();
                var sha = fields.FirstOrDefault(f => f.Length == 64 && Sha256.IsMatch(f));
                if (sha == null) continue;
                var sig = fields.Count > 8 ? fields[8] : "";
                var type = fields.Count > 6 ? fields[6] : "";
                var name = !string.IsNullOrEmpty(sig) && sig != "n/a" ? $"Malware.{sig}" : !string.IsNullOrEmpty(type) && type != "n/a" ? $"Malware.Connu.{type}" : "Malware.Connu";
                entries.Add((sha.ToLowerInvariant(), name));
            }
            if (entries.Count == 0) return (0, 0, "La réponse ne contenait aucune empreinte exploitable.");
            var (added, total) = Merge(entries);
            return (added, total, null);
        }
        catch (Exception ex) { return (0, 0, "Échec du téléchargement : " + ex.Message); }
    }

    /// <summary>Importe toutes les empreintes SHA-256 trouvées dans un fichier texte ou CSV.</summary>
    public static (int Added, int Total, string Error) ImportFile(string path)
    {
        try
        {
            var entries = new List<(string, string)>();
            foreach (var line in File.ReadLines(path))
                foreach (Match m in Sha256.Matches(line)) entries.Add((m.Value.ToLowerInvariant(), "Malware.Importe"));
            if (entries.Count == 0) return (0, 0, "Aucune empreinte SHA-256 trouvée dans ce fichier.");
            var (added, total) = Merge(entries);
            return (added, total, null);
        }
        catch (Exception ex) { return (0, 0, ex.Message); }
    }

    private static (int Added, int Total) Merge(IEnumerable<(string Sha, string Name)> entries)
    {
        AppPaths.EnsureCreated();
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (File.Exists(AppPaths.HashDbFile))
            foreach (var line in File.ReadLines(AppPaths.HashDbFile))
            {
                if (line.Length < 64 || line[0] == '#') continue;
                int sep = line.IndexOf(';');
                map[sep > 0 ? line[..sep] : line] = sep > 0 ? line[(sep + 1)..] : "";
            }
        int before = map.Count;
        foreach (var (sha, name) in entries) map.TryAdd(sha, name);
        var tmp = AppPaths.HashDbFile + ".tmp";
        File.WriteAllLines(tmp, new[] { "# Base d'empreintes SPIRUS : sha256;nom" }.Concat(map.Select(kv => $"{kv.Key};{kv.Value}")));
        File.Move(tmp, AppPaths.HashDbFile, true);
        return (map.Count - before, map.Count);
    }
}

/// <summary>Intégration à Windows : démarrage automatique et menu contextuel de l'Explorateur.</summary>
public static class SystemIntegration
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "SPIRUS";
    private static readonly string[] MenuRoots = { @"Software\Classes\*\shell\VigieScan", @"Software\Classes\Directory\shell\VigieScan", @"Software\Classes\Drive\shell\VigieScan" };

    public static string ExePath => Environment.ProcessPath ?? "";

    public static void SetAutostart(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKey, true);
        if (enabled) key.SetValue(ValueName, $"\"{ExePath}\" --background");
        else key.DeleteValue(ValueName, false);
    }

    public static bool IsAutostartEnabled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKey);
        return key?.GetValue(ValueName) is string v && v.Contains(ExePath, StringComparison.OrdinalIgnoreCase);
    }

    public static void SetContextMenu(bool enabled)
    {
        foreach (var root in MenuRoots)
        {
            if (!enabled) { Registry.CurrentUser.DeleteSubKeyTree(root, false); continue; }
            using var key = Registry.CurrentUser.CreateSubKey(root, true);
            key.SetValue("MUIVerb", "Analyser avec SPIRUS");
            key.SetValue("Icon", $"\"{ExePath}\",0");
            using var cmd = key.CreateSubKey("command", true);
            cmd.SetValue("", $"\"{ExePath}\" --scan \"%1\"");
        }
    }

    /// <summary>Contenu du fichier de test inoffensif (construit à l'exécution pour ne pas figurer en clair dans le programme).</summary>
    public static string TestFileContent()
    {
        var parts = new[] { "ELIF", "TSET", "SURIVITNA", "SURIPS" };
        var marker = string.Join("-", parts.Select(p => new string(p.Reverse().ToArray())).Reverse());
        return $"Ceci est un fichier de test inoffensif pour SPIRUS Antivirus.\r\n{marker}\r\n";
    }
}
