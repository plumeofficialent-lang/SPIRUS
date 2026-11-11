using System.Buffers;
using System.Collections.Concurrent;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Vigie.Core.Engine;

public sealed record Detection(string Name, string Category, int Score, string Engine, string Reason, bool Reducible);

/// <summary>
/// Moteur d'analyse de SPIRUS : empreintes connues, règles multi-motifs (Aho-Corasick),
/// heuristiques structurelles des exécutables, analyse des archives et renfort AMSI.
/// </summary>
public sealed class ScanEngine : IDisposable
{
    private const int InMemoryLimit = 4 * 1024 * 1024;

    /// <summary>Tampons réutilisés d'un fichier à l'autre : évite d'allouer des mégaoctets pour chaque analyse.</summary>
    private static readonly ArrayPool<byte> BufferPool = ArrayPool<byte>.Create(InMemoryLimit, 6);
    private const int MaxArchiveDepth = 2;
    private const string Suspect = "Comportement suspect";

    private readonly Func<AppSettings> _settings;
    private readonly AmsiScanner _amsi = new();
    private readonly ConcurrentDictionary<string, (long Size, DateTime Write, ScanResult Result)> _cache = new(StringComparer.OrdinalIgnoreCase);

    public RuleSet Rules { get; private set; }
    public HashDatabase Hashes { get; private set; }
    public bool AmsiAvailable => _amsi.Available;
    public int SignatureCount => Rules.Rules.Count + Hashes.Count;

    public ScanEngine(Func<AppSettings> settings)
    {
        _settings = settings;
        Reload();
    }

    public void Reload()
    {
        Rules = RuleSet.Load();
        Hashes = HashDatabase.Load(Rules);
        _cache.Clear();
    }

    public void ClearCache() => _cache.Clear();

    // ---------------------------------------------------------------- types de fichiers

    private static readonly HashSet<string> ScriptExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".wsc", ".hta", ".sct",
        ".sh", ".py", ".pyw", ".php", ".phtml", ".asp", ".aspx", ".jsp", ".inf", ".reg", ".url", ".scf", ".html", ".htm", ".svg"
    };

    private static readonly HashSet<string> OfficeExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".doc", ".docx", ".docm", ".dot", ".dotm", ".xls", ".xlsx", ".xlsm", ".xlsb", ".xla", ".xlam", ".ppt", ".pptx", ".pptm",
        ".potm", ".ppsm", ".rtf", ".odt", ".ods", ".one", ".pub"
    };

    private static readonly HashSet<string> DocumentExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".txt", ".mp3",
        ".mp4", ".avi", ".mkv", ".mov", ".wav", ".rtf", ".odt", ".csv", ".html", ".htm"
    };

    /// <summary>Extensions analysées par défaut par la protection en temps réel et l'analyse rapide.</summary>
    public static readonly HashSet<string> RiskyExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".ocx", ".msi", ".msix", ".appx", ".jar", ".lnk",
        ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".sct", ".reg", ".inf", ".url",
        ".zip", ".rar", ".7z", ".iso", ".img", ".vhd", ".vhdx", ".cab",
        ".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".doc", ".xls", ".ppt", ".rtf", ".pdf", ".one",
        ".php", ".py", ".pyw", ".html", ".htm", ".svg"
    };

    public static bool IsRisky(string path) => RiskyExts.Contains(Path.GetExtension(path));

    /// <summary>Types sans danger ignorés à l'intérieur des archives (classes Java, images, polices…).</summary>
    private static readonly HashSet<string> InertExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".class", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".ttf", ".otf", ".woff", ".woff2", ".properties",
        ".css", ".kotlin_module", ".mf", ".sf", ".rsa", ".dsa", ".map", ".po", ".mo", ".json", ".xml", ".md", ".yml", ".yaml"
    };

    private const FileKind AmsiKinds = FileKind.Script | FileKind.Lnk | FileKind.Office | FileKind.Pdf;

    /// <summary>En-tête d'un raccourci Windows : taille 0x4C puis CLSID {00021401-0000-0000-C000-000000000046}.</summary>
    private static readonly byte[] LnkMagic = { 0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46 };

    private static FileKind Classify(string ext, string name, ReadOnlySpan<byte> h)
    {
        if (h.Length >= 2 && h[0] == 'M' && h[1] == 'Z') return FileKind.Pe;
        if (h.Length >= 4 && h[0] == 'P' && h[1] == 'K' && h[2] == 3 && h[3] == 4)
            return OfficeExts.Contains(ext) ? FileKind.Archive | FileKind.Office : FileKind.Archive;
        if (h.Length >= 8 && h[0] == 0xD0 && h[1] == 0xCF && h[2] == 0x11 && h[3] == 0xE0) return FileKind.Office;
        if (h.Length >= 4 && h[0] == '%' && h[1] == 'P' && h[2] == 'D' && h[3] == 'F') return FileKind.Pdf;
        if (h.Length >= 5 && h[0] == '{' && h[1] == '\\' && h[2] == 'r' && h[3] == 't' && h[4] == 'f') return FileKind.Office;
        if (ext == ".lnk" || (h.Length >= 20 && h[..20].SequenceEqual(LnkMagic))) return FileKind.Lnk;
        if (name.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase)) return FileKind.Office;
        if (ScriptExts.Contains(ext)) return FileKind.Script;
        if (OfficeExts.Contains(ext)) return FileKind.Office;
        return FileKind.Other;
    }

    // ---------------------------------------------------------------- exclusions

    public bool IsExcluded(string path)
    {
        string full;
        try { full = Path.GetFullPath(path); } catch { return false; }
        foreach (var dir in AppPaths.SelfExclusions())
            if (full.StartsWith(dir, StringComparison.OrdinalIgnoreCase)) return true;
        foreach (var raw in _settings().Exclusions)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            var ex = raw.Trim();
            if (ex.StartsWith("*.")) { if (full.EndsWith(ex[1..], StringComparison.OrdinalIgnoreCase)) return true; continue; }
            if (string.Equals(full, ex.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return true;
            if (full.StartsWith(ex.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    // ---------------------------------------------------------------- point d'entrée

    public ScanResult ScanFile(string path, CancellationToken ct = default, bool useCache = true)
    {
        var settings = _settings();
        FileInfo fi;
        try
        {
            fi = new FileInfo(path);
            if (!fi.Exists) return Fail(path, Verdict.Error, "Fichier introuvable");
        }
        catch (Exception ex) { return Fail(path, Verdict.Error, ex.Message); }

        if (IsExcluded(fi.FullName)) return Fail(fi.FullName, Verdict.Skipped, "Exclu de l'analyse");
        int attrs = (int)fi.Attributes;
        if ((attrs & (0x1000 | 0x40000 | 0x400000)) != 0) return Fail(fi.FullName, Verdict.Skipped, "Fichier stocké en ligne (non téléchargé)");
        if (fi.Length > settings.MaxFileSizeMB * 1024L * 1024L) return Fail(fi.FullName, Verdict.Skipped, "Fichier trop volumineux");

        if (useCache && _cache.TryGetValue(fi.FullName, out var c) && c.Size == fi.Length && c.Write == fi.LastWriteTimeUtc)
            return c.Result;

        ScanResult result;
        try
        {
            using var fs = new FileStream(fi.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
            if (fs.Length <= InMemoryLimit)
            {
                int length = (int)fs.Length;
                var buffer = BufferPool.Rent(Math.Max(length, 1));
                try
                {
                    fs.ReadExactly(buffer, 0, length);
                    result = Analyze(new MemoryStream(buffer, 0, length, false), buffer, length, fi.FullName, fi.Name, 0, settings, ct);
                }
                finally { BufferPool.Return(buffer); }
            }
            else result = Analyze(fs, null, 0, fi.FullName, fi.Name, 0, settings, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (UnauthorizedAccessException) { return Fail(fi.FullName, Verdict.Error, "Accès refusé"); }
        catch (IOException ex) { return Fail(fi.FullName, Verdict.Error, "Fichier inaccessible : " + ex.Message); }
        catch (Exception ex) { return Fail(fi.FullName, Verdict.Error, ex.Message); }

        if (_cache.Count > 20_000) _cache.Clear();
        _cache[fi.FullName] = (fi.Length, fi.LastWriteTimeUtc, result);
        return result;
    }

    /// <summary>Analyse un contenu en mémoire (sans fichier sur le disque).</summary>
    public ScanResult ScanBytes(byte[] data, string name) =>
        Analyze(new MemoryStream(data, false), data, data.Length, null, name, 0, _settings(), CancellationToken.None);

    private static ScanResult Fail(string path, Verdict v, string error) =>
        new() { Path = path, DisplayPath = path, Verdict = v, Error = error };

    // ---------------------------------------------------------------- analyse

    private ScanResult Analyze(Stream s, byte[] buffer, int length, string fullPath, string name, int depth, AppSettings settings, CancellationToken ct)
    {
        var r = new ScanResult { Path = fullPath ?? name, DisplayPath = fullPath ?? name, Size = s.Length };
        string ext = Path.GetExtension(name).ToLowerInvariant();

        Span<byte> head = stackalloc byte[32];
        s.Position = 0;
        int headLen = s.Read(head);
        var kind = Classify(ext, name, head[..headLen]);

        // 1. Un seul passage : empreinte SHA-256 + recherche de tous les motifs
        var hits = new bool[Rules.Patterns.Count];
        int state = 0;
        using (var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            if (buffer != null)
            {
                sha.AppendData(buffer, 0, length);
                Rules.Automaton.Feed(ref state, buffer.AsSpan(0, length), hits);
            }
            else
            {
                s.Position = 0;
                var buf = ArrayPool<byte>.Shared.Rent(1 << 20);
                try
                {
                    int n;
                    while ((n = s.Read(buf, 0, buf.Length)) > 0)
                    {
                        ct.ThrowIfCancellationRequested();
                        sha.AppendData(buf, 0, n);
                        Rules.Automaton.Feed(ref state, buf.AsSpan(0, n), hits);
                    }
                }
                finally { ArrayPool<byte>.Shared.Return(buf); }
            }
            var hash = sha.GetHashAndReset();
            r.Sha256 = Convert.ToHexStringLower(hash);
            if (settings.AllowedHashes.Contains(r.Sha256, StringComparer.OrdinalIgnoreCase)) return r;

            var detections = new List<Detection>();
            if (Hashes.TryLookup(hash, out var known))
                detections.Add(new(known, "Logiciel malveillant connu", 100, "Signature", "Empreinte SHA-256 présente dans la base de menaces connues", false));

            foreach (var m in Rules.Evaluate(hits, kind, ext))
            {
                // Comme le standard EICAR : un fichier de test est petit. Un gros fichier qui contient
                // seulement le marqueur (index de recherche Windows, base de données, journal) n'en est pas un.
                if (m.Rule.IsTest && s.Length > 4096) continue;
                var shown = m.Matched.Where(p => !p.StartsWith("hex:")).Take(3).Select(p => $"« {p} »").ToList();
                var reason = m.Rule.Desc + (shown.Count > 0 ? $" ({string.Join(", ", shown)})" : "");
                detections.Add(new(m.Rule.Name, m.Rule.Category, m.Rule.Score, m.Rule.IsTest ? "Signature" : "Règle", reason, !m.Rule.IsTest));
            }

            // 2. Heuristiques
            PeInfo pe = null;
            if (kind == FileKind.Pe)
            {
                pe = PeAnalyzer.TryParse(s);
                if (pe != null && pe.IsDll && pe.EntryPoint == 0 && pe.ImportedFunctions.Count == 0 && !pe.IsDotNet)
                    detections.RemoveAll(d => d.Reducible); // DLL de ressources pures (traductions .mui…) : aucun code exécutable
                else if (pe != null) PeHeuristics(pe, detections);
            }
            NameHeuristics(name, ext, kind, detections);
            if (kind == FileKind.Lnk && s.Length > 64 * 1024)
                detections.Add(new("Heur.RaccourciVolumineux", "Raccourci piégé", 30, "Heuristique", "Raccourci anormalement volumineux (contenu caché)", true));
            if (fullPath != null) LocationHeuristics(fullPath, kind, detections);

            bool confirmed() => detections.Any(d => !d.Reducible);

            // 3. Renfort du moteur Windows (AMSI) pour les contenus interprétés : scripts, raccourcis, documents
            if (settings.AmsiEnabled && buffer != null && length <= 4 * 1024 * 1024 && (kind & AmsiKinds) != 0 && !confirmed()
                && _amsi.IsMalicious(buffer, length, fullPath ?? name))
                detections.Add(new("Windows.AMSI.Menace", "Détection Windows", 100, "AMSI", "Contenu signalé comme malveillant par le moteur antivirus de Windows (AMSI)", false));

            // 4. Contenu des archives (zip, documents Office, jar…)
            if ((kind & FileKind.Archive) != 0 && settings.ScanArchives && depth < MaxArchiveDepth && !confirmed())
            {
                var inner = ScanArchive(s, depth, settings, ct);
                if (inner != null)
                {
                    detections.Add(new(inner.ThreatName, inner.Category, inner.Score, inner.Engine, $"Dans l'archive : {inner.DisplayPath} — {inner.Reasons.FirstOrDefault()}", false));
                    r.DisplayPath = (fullPath ?? name) + " ▸ " + inner.DisplayPath;
                }
            }

            if (detections.Count == 0) return r;

            // 5. Réduction pour les programmes et scripts signés par un éditeur de confiance
            double factor = 1.0;
            bool signedScript = kind == FileKind.Script && buffer != null && buffer.AsSpan(0, length).IndexOf("# SIG # Begin signature block"u8) >= 0;
            // Gros scripts empaquetés (extensions d'éditeur, bibliothèques minifiées) : les scripts piégés sont petits.
            if (kind == FileKind.Script && r.Size > 512 * 1024) factor = 0.35;
            if ((pe != null || signedScript) && fullPath != null && detections.All(d => d.Reducible))
            {
                r.Signed = (signedScript || pe.HasEmbeddedSignature) && Authenticode.IsTrusted(fullPath);
                if (r.Signed) factor = 0.3;
                else if (fullPath.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase)) factor = 0.3; // applications du Microsoft Store (paquets signés)
                else if (fullPath.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase)) factor = 0.5;
            }

            var scored = detections
                .Select(d => d.Reducible ? d with { Score = (int)Math.Round(d.Score * factor) } : d)
                .OrderByDescending(d => d.Score).ToList();
            int total = Math.Min(100, scored[0].Score + (int)Math.Round(scored.Skip(1).Sum(d => d.Score) * 0.3));

            var (malicious, suspicious) = settings.Sensitivity switch
            {
                Sensitivity.Low => (90, 65),
                Sensitivity.High => (70, 40),
                _ => (80, 50)
            };
            r.Score = total;
            r.Verdict = total >= malicious ? Verdict.Malicious : total >= suspicious ? Verdict.Suspicious : Verdict.Clean;
            r.ThreatName = scored[0].Name;
            r.Category = scored[0].Category;
            r.Engine = scored[0].Engine;
            r.Reasons = scored.Select(d => d.Reason).Distinct().Take(6).ToList();
            r.AutoActionSafe = kind != FileKind.Other || !scored[0].Reducible;
            if (r.Signed) r.Reasons.Add("Signé numériquement par un éditeur de confiance");
            return r;
        }
    }

    private ScanResult ScanArchive(Stream s, int depth, AppSettings settings, CancellationToken ct)
    {
        try
        {
            s.Position = 0;
            using var zip = new ZipArchive(s, ZipArchiveMode.Read, leaveOpen: true);
            long total = 0;
            int count = 0;
            foreach (var e in zip.Entries)
            {
                ct.ThrowIfCancellationRequested();
                if (++count > 5000 || total > 256L * 1024 * 1024) break;
                if (e.FullName.EndsWith('/') || e.Length == 0 || e.Length > 32L * 1024 * 1024) continue;
                // On décompresse les éléments capables d'agir, ainsi que les petits fichiers de type non inerte
                var entryExt = Path.GetExtension(e.Name);
                bool worth = entryExt.Length == 0 || RiskyExts.Contains(entryExt) || e.Name.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase)
                             || (e.Length <= 256 * 1024 && !InertExts.Contains(entryExt));
                if (!worth) continue;
                if (e.CompressedLength > 0 && e.Length / e.CompressedLength > 250 && e.Length > 16L * 1024 * 1024) continue; // bombe de décompression
                total += e.Length;
                int length = (int)e.Length;
                bool pooled = length <= InMemoryLimit;
                var data = pooled ? BufferPool.Rent(length) : new byte[length];
                try
                {
                    try
                    {
                        using var es = e.Open();
                        es.ReadExactly(data, 0, length);
                    }
                    catch { continue; } // entrée chiffrée ou corrompue
                    var inner = Analyze(new MemoryStream(data, 0, length, false), data, length, null, e.FullName, depth + 1, settings, ct);
                    if (inner.IsThreat)
                    {
                        inner.DisplayPath = inner.DisplayPath.Replace('/', '\\');
                        return inner;
                    }
                }
                finally { if (pooled) BufferPool.Return(data); }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
        return null;
    }

    // ---------------------------------------------------------------- heuristiques

    private static readonly HashSet<string> PackerSections = new(StringComparer.OrdinalIgnoreCase)
    {
        "upx0", "upx1", "upx2", ".upx0", ".upx1", ".aspack", ".adata", ".nsp0", ".nsp1", ".nsp2", ".petite", ".mpress1",
        ".mpress2", ".themida", ".vmp0", ".vmp1", ".vmp2", ".enigma1", ".enigma2", ".packed", "pec1", "pec2", ".perplex",
        ".yp", ".mew", ".boom", ".ccg", ".charmve"
    };

    private static void PeHeuristics(PeInfo pe, List<Detection> d)
    {
        var packers = pe.Sections.Where(x => PackerSections.Contains(x.Name)).Select(x => x.Name).Distinct().ToList();
        if (packers.Count > 0)
            d.Add(new("Heur.Compresse", Suspect, 25, "Heuristique", $"Exécutable compressé ou protégé ({string.Join(", ", packers)})", true));

        var hot = pe.Sections.Where(x => x.Executable && x.RawSize >= 4096 && x.Entropy >= 7.4).ToList();
        if (hot.Count > 0)
            d.Add(new("Heur.CodeChiffre", Suspect, 25, "Heuristique", $"Code chiffré ou compressé (entropie {hot.Max(x => x.Entropy):0.00} / 8)", true));

        if (!pe.IsDll && pe.EntryPoint != 0 && pe.EntrySectionIndex < 0)
            d.Add(new("Heur.PointEntreeAnormal", Suspect, 30, "Heuristique", "Point d'entrée situé hors des sections du programme", true));
        else if (pe.EntrySectionIndex >= 0)
        {
            var es = pe.Sections[pe.EntrySectionIndex];
            if (es.Writable && es.Executable)
                d.Add(new("Heur.PointEntreeModifiable", Suspect, 20, "Heuristique", $"Le programme démarre dans une section modifiable ({es.Name})", true));
        }
        if (pe.Sections.Count(x => x.Writable && x.Executable) >= 2)
            d.Add(new("Heur.SectionsWX", Suspect, 10, "Heuristique", "Plusieurs sections à la fois modifiables et exécutables", true));

        if (pe.IsDotNet) return;
        var f = pe.ImportedFunctions;
        bool Has(params string[] names) => names.Any(f.Contains);

        if (f.Count == 0 && !pe.IsDll)
            d.Add(new("Heur.SansImports", Suspect, 15, "Heuristique", "Aucune fonction importée (imports masqués)", true));
        else if (f.Count <= 4 && Has("GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LdrGetProcedureAddress"))
            d.Add(new("Heur.ImportsDynamiques", Suspect, 20, "Heuristique", "Imports minimalistes : les fonctions sont résolues en cachette", true));

        if (Has("VirtualAllocEx", "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory") && Has("WriteProcessMemory", "NtWriteVirtualMemory")
            && Has("CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread"))
            d.Add(new("Heur.Injection", "Cheval de Troie", 45, "Heuristique", "Capable d'injecter du code dans d'autres programmes", true));

        if (Has("NtUnmapViewOfSection", "ZwUnmapViewOfSection") && Has("SetThreadContext", "Wow64SetThreadContext", "NtSetContextThread") && Has("ResumeThread", "NtResumeThread"))
            d.Add(new("Heur.ProcessHollowing", "Cheval de Troie", 50, "Heuristique", "Remplace le code d'un programme légitime en mémoire (process hollowing)", true));

        if (Has("SetWindowsHookExA", "SetWindowsHookExW") && Has("GetAsyncKeyState", "GetKeyboardState", "MapVirtualKeyA", "MapVirtualKeyW") && Has("GetForegroundWindow"))
            d.Add(new("Heur.Keylogger", "Enregistreur de frappe", 25, "Heuristique", "Surveille le clavier et la fenêtre active", true));

        if (Has("URLDownloadToFileA", "URLDownloadToFileW") && Has("WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW", "CreateProcessA", "CreateProcessW"))
            d.Add(new("Heur.Telechargeur", "Téléchargeur", 35, "Heuristique", "Télécharge un fichier depuis Internet puis l'exécute", true));

        if (Has("CryptEncrypt", "BCryptEncrypt") && Has("FindFirstFileW", "FindFirstFileExW", "FindFirstFileA") && Has("FindNextFileW", "FindNextFileA")
            && Has("MoveFileExW", "MoveFileW", "DeleteFileW"))
            d.Add(new("Heur.ChiffrementFichiers", "Rançongiciel", 20, "Heuristique", "Parcourt les dossiers et chiffre des fichiers", true));

        if (Has("MiniDumpWriteDump") && Has("OpenProcess") && Has("AdjustTokenPrivileges", "LookupPrivilegeValueW", "LookupPrivilegeValueA"))
            d.Add(new("Heur.VolIdentifiants", "Outil de piratage", 35, "Heuristique", "Peut copier la mémoire d'autres processus (vol d'identifiants)", true));
    }

    private static readonly Regex DoubleExtension = new(
        @"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|bmp|txt|rtf|mp3|mp4|avi|mkv|mov|wav|zip|rar|7z)[\s_]*\.(exe|scr|com|pif|bat|cmd|vbs|vbe|js|jse|wsf|hta|cpl|msi|ps1|jar)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static void NameHeuristics(string name, string ext, FileKind kind, List<Detection> d)
    {
        var file = Path.GetFileName(name);
        if (file.Contains('‮'))
            d.Add(new("Heur.NomTrompeur", "Leurre", 75, "Heuristique", "Le nom contient un caractère d'inversion qui masque la vraie extension", true));
        if (DoubleExtension.IsMatch(file))
            d.Add(new("Heur.DoubleExtension", "Leurre", 55, "Heuristique", $"Double extension trompeuse : fichier {ext} déguisé en document", true));
        if (kind == FileKind.Pe && DocumentExts.Contains(ext))
            d.Add(new("Heur.ProgrammeDeguise", "Leurre", 60, "Heuristique", $"Programme exécutable déguisé en fichier {ext}", true));
    }

    private static readonly string[] StartupDirs =
    {
        Environment.GetFolderPath(Environment.SpecialFolder.Startup),
        Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
    };

    private static void LocationHeuristics(string fullPath, FileKind kind, List<Detection> d)
    {
        if ((kind & (FileKind.Pe | FileKind.Script | FileKind.Lnk)) == 0) return;
        foreach (var dir in StartupDirs)
            if (!string.IsNullOrEmpty(dir) && fullPath.StartsWith(dir + "\\", StringComparison.OrdinalIgnoreCase))
                d.Add(new("Heur.Demarrage", Suspect, 15, "Heuristique", "Lancé automatiquement à l'ouverture de session", true));

        var origin = DownloadOrigin(fullPath);
        if (origin != null) d.Add(new("Heur.Internet", Suspect, 10, "Heuristique", origin, true));
    }

    /// <summary>Lit la « marque du Web » (flux Zone.Identifier) laissée par les navigateurs.</summary>
    public static string DownloadOrigin(string path)
    {
        try
        {
            var zone = path + ":Zone.Identifier";
            if (!File.Exists(zone)) return null;
            string id = null, host = null;
            foreach (var line in File.ReadLines(zone))
            {
                if (line.StartsWith("ZoneId=", StringComparison.OrdinalIgnoreCase)) id = line[7..].Trim();
                else if (line.StartsWith("HostUrl=", StringComparison.OrdinalIgnoreCase) && Uri.TryCreate(line[8..].Trim(), UriKind.Absolute, out var u)) host = u.Host;
            }
            if (id is not ("3" or "4")) return null;
            return string.IsNullOrEmpty(host) ? "Téléchargé depuis Internet" : $"Téléchargé depuis Internet ({host})";
        }
        catch { return null; }
    }

    public void Dispose() => _amsi.Dispose();
}
