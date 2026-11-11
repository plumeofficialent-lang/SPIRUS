using System.Buffers.Binary;
using System.IO.Compression;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Vigie.Core.Engine;

[Flags]
public enum FileKind
{
    None = 0, Pe = 1, Script = 2, Lnk = 4, Office = 8, Pdf = 16, Archive = 32, Other = 64,
    Any = Pe | Script | Lnk | Office | Pdf | Archive | Other
}

/// <summary>
/// Automate d'Aho-Corasick insensible à la casse ASCII : recherche simultanée de centaines
/// de motifs en un seul passage sur le flux d'octets, quel que soit leur nombre.
/// </summary>
public sealed class AhoCorasick
{
    private static readonly byte[] Fold = BuildFold();
    private readonly ushort[] _delta; // table de transitions compacte (2 octets par case)
    private readonly int[][] _outputs;

    public int StateCount { get; }

    private static byte[] BuildFold()
    {
        var t = new byte[256];
        for (int i = 0; i < 256; i++) t[i] = (byte)(i is >= 0x41 and <= 0x5A ? i + 0x20 : i);
        return t;
    }

    public AhoCorasick(IEnumerable<(byte[] Bytes, int Id)> patterns)
    {
        var go = new List<int[]> { NewRow() };
        var outs = new List<List<int>> { new() };
        foreach (var (bytes, id) in patterns)
        {
            if (bytes.Length == 0) continue;
            int s = 0;
            foreach (var raw in bytes)
            {
                int b = Fold[raw];
                if (go[s][b] < 0) { go[s][b] = go.Count; go.Add(NewRow()); outs.Add(new()); }
                s = go[s][b];
            }
            if (!outs[s].Contains(id)) outs[s].Add(id);
        }

        int n = go.Count;
        if (n > ushort.MaxValue) throw new InvalidOperationException("Trop de motifs de détection (règles personnalisées trop volumineuses).");
        StateCount = n;
        _delta = new ushort[n * 256];
        var fail = new int[n];
        var queue = new Queue<int>();
        for (int c = 0; c < 256; c++)
        {
            int t = go[0][c];
            if (t < 0) _delta[c] = 0;
            else { _delta[c] = (ushort)t; fail[t] = 0; queue.Enqueue(t); }
        }
        while (queue.Count > 0)
        {
            int s = queue.Dequeue();
            foreach (var id in outs[fail[s]]) if (!outs[s].Contains(id)) outs[s].Add(id);
            for (int c = 0; c < 256; c++)
            {
                int t = go[s][c];
                if (t < 0) _delta[s * 256 + c] = _delta[fail[s] * 256 + c];
                else
                {
                    _delta[s * 256 + c] = (ushort)t;
                    fail[t] = _delta[fail[s] * 256 + c];
                    queue.Enqueue(t);
                }
            }
        }
        _outputs = new int[n][];
        for (int i = 0; i < n; i++) _outputs[i] = outs[i].Count > 0 ? outs[i].ToArray() : null;
    }

    private static int[] NewRow() { var r = new int[256]; Array.Fill(r, -1); return r; }

    /// <summary>Fait avancer l'automate sur un bloc ; l'état est conservé entre les blocs.</summary>
    public void Feed(ref int state, ReadOnlySpan<byte> data, bool[] hits)
    {
        int s = state;
        var delta = _delta;
        var outputs = _outputs;
        var fold = Fold;
        foreach (var b in data)
        {
            s = delta[(s << 8) | fold[b]];
            var o = outputs[s];
            if (o != null) foreach (var id in o) hits[id] = true;
        }
        state = s;
    }
}

public sealed class RuleGroup
{
    public int Min { get; set; } = 1;
    public List<string> Of { get; set; } = new();
    [JsonIgnore] public int[] PatternIds { get; set; } = Array.Empty<int>();
}

public sealed class Rule
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Category { get; set; } = "";
    public string Desc { get; set; } = "";
    public int Score { get; set; }
    public List<string> Targets { get; set; } = new() { "any" };
    public List<RuleGroup> Groups { get; set; } = new();
    /// <summary>Motifs d'exception : si l'un d'eux est présent, la règle ne se déclenche pas.</summary>
    public List<string> Exclude { get; set; } = new();
    [JsonIgnore] public int[] ExcludeIds { get; set; } = Array.Empty<int>();
    /// <summary>Extensions visées (optionnel) : la règle ne s'applique qu'à ces types de fichiers.</summary>
    public List<string> Extensions { get; set; } = new();
    [JsonIgnore] public HashSet<string> ExtensionSet { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    [JsonIgnore] public FileKind TargetKinds { get; set; }
    [JsonIgnore] public bool IsTest => Category == "Test";
}

public sealed class HashEntry
{
    public string Sha256 { get; set; } = "";
    public string Name { get; set; } = "";
}

public sealed class RuleFile
{
    public string Version { get; set; } = "";
    public List<HashEntry> Hashes { get; set; } = new();
    public List<Rule> Rules { get; set; } = new();
}

public sealed record RuleMatch(Rule Rule, IReadOnlyList<string> Matched);

/// <summary>Ensemble de règles compilées (embarquées + règles personnalisées de l'utilisateur).</summary>
public sealed class RuleSet
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    public string Version { get; private set; } = "";
    public List<Rule> Rules { get; } = new();
    public List<HashEntry> Hashes { get; } = new();
    public List<string> Patterns { get; } = new();
    public AhoCorasick Automaton { get; private set; }
    public string LoadWarning { get; private set; } = "";

    public static RuleSet Load()
    {
        var set = new RuleSet();
        set.Merge(ReadEmbedded());
        try
        {
            if (File.Exists(AppPaths.CustomRulesFile))
                set.Merge(JsonSerializer.Deserialize<RuleFile>(File.ReadAllText(AppPaths.CustomRulesFile), Json));
        }
        catch (Exception ex) { set.LoadWarning = "Règles personnalisées ignorées : " + ex.Message; }
        set.Compile();
        return set;
    }

    private static RuleFile ReadEmbedded()
    {
        using var res = Assembly.GetExecutingAssembly().GetManifestResourceStream("Vigie.rules.vdb")
            ?? throw new InvalidOperationException("Base de signatures introuvable.");
        using var ms = new MemoryStream();
        res.CopyTo(ms);
        var packed = ms.ToArray();
        for (int i = 0; i < packed.Length; i++) packed[i] = (byte)(packed[i] ^ (byte)(0xA7 + i * 31));
        using var inflate = new DeflateStream(new MemoryStream(packed), CompressionMode.Decompress);
        return JsonSerializer.Deserialize<RuleFile>(inflate, Json)!;
    }

    private void Merge(RuleFile file)
    {
        if (file == null) return;
        if (string.IsNullOrEmpty(Version)) Version = file.Version;
        Hashes.AddRange(file.Hashes ?? new());
        foreach (var r in file.Rules ?? new())
        {
            Rules.RemoveAll(x => x.Id == r.Id);
            Rules.Add(r);
        }
    }

    private void Compile()
    {
        var index = new Dictionary<string, int>(StringComparer.Ordinal);
        var compiled = new List<(byte[], int)>();
        int[] Register(IEnumerable<string> patterns)
        {
            var ids = new List<int>();
            foreach (var p in patterns ?? Enumerable.Empty<string>())
            {
                if (string.IsNullOrEmpty(p)) continue;
                if (!index.TryGetValue(p, out int id))
                {
                    id = Patterns.Count;
                    Patterns.Add(p);
                    index[p] = id;
                    if (p.StartsWith("hex:", StringComparison.OrdinalIgnoreCase))
                        compiled.Add((Convert.FromHexString(p[4..].Replace(" ", "")), id));
                    else
                    {
                        compiled.Add((Encoding.UTF8.GetBytes(p), id));
                        compiled.Add((Encoding.Unicode.GetBytes(p), id)); // UTF-16 (scripts PowerShell, raccourcis, .NET)
                    }
                }
                ids.Add(id);
            }
            return ids.Distinct().ToArray();
        }

        foreach (var rule in Rules)
        {
            rule.TargetKinds = ParseTargets(rule.Targets);
            rule.ExcludeIds = Register(rule.Exclude);
            rule.ExtensionSet = new HashSet<string>((rule.Extensions ?? new()).Select(e => e.StartsWith('.') ? e : "." + e), StringComparer.OrdinalIgnoreCase);
            foreach (var g in rule.Groups)
            {
                g.PatternIds = Register(g.Of);
                g.Min = Math.Clamp(g.Min, 1, Math.Max(1, g.PatternIds.Length));
            }
        }
        Automaton = new AhoCorasick(compiled);
    }

    private static FileKind ParseTargets(IEnumerable<string> targets)
    {
        FileKind k = FileKind.None;
        foreach (var t in targets ?? Array.Empty<string>())
            k |= t.ToLowerInvariant() switch
            {
                "pe" => FileKind.Pe,
                "script" => FileKind.Script,
                "lnk" => FileKind.Lnk,
                "office" => FileKind.Office,
                "pdf" => FileKind.Pdf,
                "archive" => FileKind.Archive,
                "other" => FileKind.Other,
                _ => FileKind.Any
            };
        return k == FileKind.None ? FileKind.Any : k;
    }

    public List<RuleMatch> Evaluate(bool[] hits, FileKind kind, string extension)
    {
        var result = new List<RuleMatch>();
        foreach (var rule in Rules)
        {
            if ((rule.TargetKinds & kind) == 0) continue;
            if (rule.ExtensionSet.Count > 0 && !rule.ExtensionSet.Contains(extension ?? "")) continue;
            if (rule.ExcludeIds.Any(id => hits[id])) continue;
            var matched = new List<string>();
            bool ok = true;
            foreach (var g in rule.Groups)
            {
                int count = 0;
                foreach (var id in g.PatternIds)
                    if (hits[id]) { count++; matched.Add(Patterns[id]); }
                if (count < g.Min) { ok = false; break; }
            }
            if (ok && rule.Groups.Count > 0) result.Add(new RuleMatch(rule, matched));
        }
        return result;
    }
}

public readonly record struct Hash256(ulong A, ulong B, ulong C, ulong D) : IComparable<Hash256>
{
    public static Hash256 From(ReadOnlySpan<byte> h) => new(
        BinaryPrimitives.ReadUInt64BigEndian(h[..8]), BinaryPrimitives.ReadUInt64BigEndian(h[8..16]),
        BinaryPrimitives.ReadUInt64BigEndian(h[16..24]), BinaryPrimitives.ReadUInt64BigEndian(h[24..32]));

    public static bool TryParse(string hex, out Hash256 h)
    {
        h = default;
        hex = hex?.Trim().Trim('"') ?? "";
        if (hex.Length != 64) return false;
        try { h = From(Convert.FromHexString(hex)); return true; } catch { return false; }
    }

    public int CompareTo(Hash256 o)
    {
        int c = A.CompareTo(o.A); if (c != 0) return c;
        c = B.CompareTo(o.B); if (c != 0) return c;
        c = C.CompareTo(o.C); if (c != 0) return c;
        return D.CompareTo(o.D);
    }
}

/// <summary>Base compacte d'empreintes SHA-256 de logiciels malveillants connus (recherche dichotomique).</summary>
public sealed class HashDatabase
{
    private readonly Hash256[] _hashes;
    private readonly string[] _names;

    public int Count => _hashes.Length;

    private HashDatabase(Hash256[] hashes, string[] names) { _hashes = hashes; _names = names; }

    public static HashDatabase Load(RuleSet rules)
    {
        var map = new Dictionary<Hash256, string>();
        var intern = new Dictionary<string, string>();
        void Add(string hex, string name)
        {
            if (!Hash256.TryParse(hex, out var h)) return;
            name = string.IsNullOrWhiteSpace(name) ? "Malware.Connu" : name.Trim();
            if (!intern.TryGetValue(name, out var n)) intern[name] = n = name;
            map[h] = n;
        }
        foreach (var e in rules.Hashes) Add(e.Sha256, e.Name);
        try
        {
            if (File.Exists(AppPaths.HashDbFile))
                foreach (var line in File.ReadLines(AppPaths.HashDbFile))
                {
                    if (line.Length < 64 || line[0] == '#') continue;
                    int sep = line.IndexOf(';');
                    Add(sep > 0 ? line[..sep] : line, sep > 0 ? line[(sep + 1)..] : "");
                }
        }
        catch { }
        var keys = map.Keys.ToArray();
        Array.Sort(keys);
        return new HashDatabase(keys, keys.Select(k => map[k]).ToArray());
    }

    public bool TryLookup(ReadOnlySpan<byte> sha256, out string name)
    {
        int i = Array.BinarySearch(_hashes, Hash256.From(sha256));
        name = i >= 0 ? _names[i] : null;
        return i >= 0;
    }
}
