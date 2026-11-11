using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Vigie.Core;

public sealed record UpdateInfo(Version Version, string Tag, string DownloadUrl, string Sha256, long Size, string Notes, string PageUrl);

/// <summary>
/// Mises à jour automatiques depuis les releases GitHub : on lit la dernière release publiée,
/// on télécharge son installeur, on vérifie son empreinte SHA-256, puis on l'exécute en silence.
/// </summary>
public static class Updater
{
    public const string Repository = "plumeofficialent-lang/SPIRUS";
    public const string AssetName = "SPIRUS-Setup.exe";
    public static string ReleasesPage => $"https://github.com/{Repository}/releases";

    public static Version Current
    {
        get
        {
            var v = typeof(Updater).Assembly.GetName().Version ?? new Version(1, 0, 0);
            return new Version(v.Major, v.Minor, Math.Max(0, v.Build));
        }
    }

    public static string CurrentText => Current.ToString(3);

    private static HttpClient CreateClient()
    {
        var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("SPIRUS-Antivirus", CurrentText));
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        return http;
    }

    /// <summary>Renvoie la mise à jour disponible, ou null si SPIRUS est à jour.</summary>
    public static async Task<UpdateInfo> CheckAsync(CancellationToken ct = default)
    {
        using var http = CreateClient();
        using var resp = await http.GetAsync($"https://api.github.com/repos/{Repository}/releases/latest", ct);
        if (resp.StatusCode == System.Net.HttpStatusCode.NotFound) return null; // aucune release publiée
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var root = doc.RootElement;
        var tag = root.GetProperty("tag_name").GetString() ?? "";
        if (!Version.TryParse(tag.TrimStart('v', 'V'), out var version)) return null;
        version = new Version(version.Major, version.Minor, Math.Max(0, version.Build));
        if (version <= Current) return null;

        var notes = root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
        foreach (var asset in root.GetProperty("assets").EnumerateArray())
        {
            if (!string.Equals(asset.GetProperty("name").GetString(), AssetName, StringComparison.OrdinalIgnoreCase)) continue;
            string sha = null;
            if (asset.TryGetProperty("digest", out var d) && d.GetString() is string digest && digest.StartsWith("sha256:"))
                sha = digest[7..].ToLowerInvariant();
            sha ??= Regex.Match(notes, @"SHA-?256\s*:\s*([0-9a-fA-F]{64})").Groups[1].Value.ToLowerInvariant() is { Length: 64 } s ? s : null;
            return new UpdateInfo(version, tag, asset.GetProperty("browser_download_url").GetString(), sha,
                asset.GetProperty("size").GetInt64(), notes, root.GetProperty("html_url").GetString());
        }
        return null;
    }

    /// <summary>Télécharge l'installeur et vérifie son empreinte SHA-256 avant de l'accepter.</summary>
    public static async Task<string> DownloadAsync(UpdateInfo update, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(update.Sha256))
            throw new InvalidOperationException("La release ne publie pas l'empreinte SHA-256 de l'installeur : mise à jour refusée par sécurité.");
        var dir = Path.Combine(Path.GetTempPath(), "SPIRUS-Update");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, $"SPIRUS-Setup-{update.Version.ToString(3)}.exe");

        using (var http = CreateClient())
        using (var src = await http.GetStreamAsync(update.DownloadUrl, ct))
        using (var dst = new FileStream(path, FileMode.Create, FileAccess.Write))
            await src.CopyToAsync(dst, ct);

        string actual;
        using (var fs = File.OpenRead(path)) actual = Convert.ToHexStringLower(await SHA256.HashDataAsync(fs, ct));
        if (actual != update.Sha256)
        {
            File.Delete(path);
            throw new InvalidOperationException("L'installeur téléchargé ne correspond pas à l'empreinte publiée : mise à jour annulée.");
        }
        return path;
    }

    /// <summary>Lance l'installeur en mode silencieux : il arrête SPIRUS, le remplace puis le relance.</summary>
    public static void Install(string installerPath) =>
        Process.Start(new ProcessStartInfo(installerPath, "--silent") { UseShellExecute = true });
}
