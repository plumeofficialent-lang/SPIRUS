using System.Buffers.Binary;
using System.Text;

namespace Vigie.Core.Engine;

public sealed class PeSection
{
    public string Name { get; init; } = "";
    public uint VirtualAddress { get; init; }
    public uint VirtualSize { get; init; }
    public uint RawSize { get; init; }
    public uint RawPointer { get; init; }
    public uint Characteristics { get; init; }
    public double Entropy { get; set; }
    public bool Executable => (Characteristics & 0x20000000) != 0 || (Characteristics & 0x20) != 0;
    public bool Writable => (Characteristics & 0x80000000) != 0;
}

public sealed class PeInfo
{
    public bool Is64 { get; set; }
    public bool IsDll { get; set; }
    public bool IsDotNet { get; set; }
    public bool HasEmbeddedSignature { get; set; }
    public uint EntryPoint { get; set; }
    public int EntrySectionIndex { get; set; } = -1;
    public List<PeSection> Sections { get; } = new();
    public HashSet<string> ImportedFunctions { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> ImportedDlls { get; } = new(StringComparer.OrdinalIgnoreCase);
    public long OverlaySize { get; set; }
}

/// <summary>Analyse structurelle d'un exécutable Windows (PE32 / PE32+).</summary>
public static class PeAnalyzer
{
    public static PeInfo TryParse(Stream s)
    {
        try { return Parse(s); } catch { return null; }
    }

    private static PeInfo Parse(Stream s)
    {
        long len = s.Length;
        if (len < 0x100) return null;
        var dos = ReadAt(s, 0, 64);
        if (dos[0] != 'M' || dos[1] != 'Z') return null;
        int lfanew = BinaryPrimitives.ReadInt32LittleEndian(dos.AsSpan(0x3C));
        if (lfanew <= 0 || lfanew > len - 24 || lfanew > 0x10000) return null;

        var nt = ReadAt(s, lfanew, 24);
        if (nt[0] != 'P' || nt[1] != 'E' || nt[2] != 0 || nt[3] != 0) return null;
        int nSections = BinaryPrimitives.ReadUInt16LittleEndian(nt.AsSpan(6));
        int optSize = BinaryPrimitives.ReadUInt16LittleEndian(nt.AsSpan(20));
        ushort characteristics = BinaryPrimitives.ReadUInt16LittleEndian(nt.AsSpan(22));
        if (nSections is 0 or > 96 || optSize < 96) return null;

        var info = new PeInfo { IsDll = (characteristics & 0x2000) != 0 };
        long optOff = lfanew + 24;
        var opt = ReadAt(s, optOff, optSize);
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(opt);
        info.Is64 = magic == 0x20B;
        info.EntryPoint = BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(16));
        int ddBase = info.Is64 ? 112 : 96;
        int nDirs = (int)Math.Min(16, BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(ddBase - 4)));
        (uint Rva, uint Size) Dir(int i) => i < nDirs && ddBase + i * 8 + 8 <= opt.Length
            ? (BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(ddBase + i * 8)), BinaryPrimitives.ReadUInt32LittleEndian(opt.AsSpan(ddBase + i * 8 + 4)))
            : (0u, 0u);

        var sec = ReadAt(s, optOff + optSize, nSections * 40);
        long endOfRaw = 0;
        for (int i = 0; i < nSections; i++)
        {
            var span = sec.AsSpan(i * 40, 40);
            var section = new PeSection
            {
                Name = Encoding.ASCII.GetString(span[..8]).TrimEnd('\0'),
                VirtualSize = BinaryPrimitives.ReadUInt32LittleEndian(span[8..]),
                VirtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(span[12..]),
                RawSize = BinaryPrimitives.ReadUInt32LittleEndian(span[16..]),
                RawPointer = BinaryPrimitives.ReadUInt32LittleEndian(span[20..]),
                Characteristics = BinaryPrimitives.ReadUInt32LittleEndian(span[36..])
            };
            info.Sections.Add(section);
            endOfRaw = Math.Max(endOfRaw, (long)section.RawPointer + section.RawSize);
            uint vsize = Math.Max(section.VirtualSize, section.RawSize);
            if (info.EntryPoint >= section.VirtualAddress && info.EntryPoint < section.VirtualAddress + vsize)
                info.EntrySectionIndex = i;
        }
        info.OverlaySize = Math.Max(0, len - endOfRaw);

        foreach (var section in info.Sections)
        {
            if (section.RawSize == 0 || section.RawPointer >= len) continue;
            int take = (int)Math.Min(Math.Min(section.RawSize, len - section.RawPointer), 4 * 1024 * 1024);
            section.Entropy = EntropyAt(s, section.RawPointer, take);
        }

        var security = Dir(4);
        info.HasEmbeddedSignature = security.Rva != 0 && security.Size > 8 && security.Rva < len;
        info.IsDotNet = Dir(14).Rva != 0;

        var imports = Dir(1);
        if (imports.Rva != 0) ReadImports(s, info, imports.Rva);
        return info;
    }

    private static void ReadImports(Stream s, PeInfo info, uint rva)
    {
        long off = RvaToOffset(info, rva);
        if (off < 0) return;
        int functions = 0;
        for (int d = 0; d < 256; d++)
        {
            var desc = ReadAt(s, off + d * 20, 20);
            if (desc.Length < 20) break;
            uint oft = BinaryPrimitives.ReadUInt32LittleEndian(desc);
            uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(desc.AsSpan(12));
            uint ft = BinaryPrimitives.ReadUInt32LittleEndian(desc.AsSpan(16));
            if (oft == 0 && nameRva == 0 && ft == 0) break;
            var dll = ReadAsciiz(s, RvaToOffset(info, nameRva));
            if (!string.IsNullOrEmpty(dll)) info.ImportedDlls.Add(dll);

            long thunkOff = RvaToOffset(info, oft != 0 ? oft : ft);
            if (thunkOff < 0) continue;
            int width = info.Is64 ? 8 : 4;
            for (int t = 0; t < 2048 && functions < 8192; t++)
            {
                var thunk = ReadAt(s, thunkOff + t * width, width);
                if (thunk.Length < width) break;
                ulong v = info.Is64 ? BinaryPrimitives.ReadUInt64LittleEndian(thunk) : BinaryPrimitives.ReadUInt32LittleEndian(thunk);
                if (v == 0) break;
                bool ordinal = info.Is64 ? (v & 0x8000000000000000UL) != 0 : (v & 0x80000000UL) != 0;
                if (ordinal) continue;
                var fn = ReadAsciiz(s, RvaToOffset(info, (uint)(v & 0x7FFFFFFF)) + 2);
                if (!string.IsNullOrEmpty(fn)) { info.ImportedFunctions.Add(fn); functions++; }
            }
        }
    }

    private static long RvaToOffset(PeInfo info, uint rva)
    {
        foreach (var sct in info.Sections)
        {
            uint size = Math.Max(sct.VirtualSize, sct.RawSize);
            if (rva >= sct.VirtualAddress && rva < sct.VirtualAddress + size)
                return (long)rva - sct.VirtualAddress + sct.RawPointer;
        }
        return rva < 0x1000 ? rva : -1;
    }

    private static string ReadAsciiz(Stream s, long off)
    {
        if (off < 0 || off >= s.Length) return null;
        var buf = ReadAt(s, off, 256);
        int end = Array.IndexOf(buf, (byte)0);
        if (end <= 0) return null;
        for (int i = 0; i < end; i++) if (buf[i] < 0x20 || buf[i] > 0x7E) return null;
        return Encoding.ASCII.GetString(buf, 0, end);
    }

    private static byte[] ReadAt(Stream s, long offset, int count)
    {
        if (offset < 0 || offset >= s.Length) return Array.Empty<byte>();
        count = (int)Math.Min(count, s.Length - offset);
        var buf = new byte[count];
        s.Position = offset;
        int read = 0;
        while (read < count)
        {
            int n = s.Read(buf, read, count - read);
            if (n <= 0) break;
            read += n;
        }
        return read == count ? buf : buf[..read];
    }

    /// <summary>Entropie d'une zone du fichier, lue par petits blocs (pas de copie de la section entière).</summary>
    private static double EntropyAt(Stream s, long offset, int count)
    {
        var counts = new int[256];
        Span<byte> chunk = stackalloc byte[16 * 1024];
        s.Position = offset;
        long total = 0;
        while (total < count)
        {
            int n = s.Read(chunk[..(int)Math.Min(chunk.Length, count - total)]);
            if (n <= 0) break;
            foreach (var b in chunk[..n]) counts[b]++;
            total += n;
        }
        return Entropy(counts, total);
    }

    public static double Entropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;
        Span<int> counts = stackalloc int[256];
        foreach (var b in data) counts[b]++;
        return Entropy(counts, data.Length);
    }

    public static double Entropy(ReadOnlySpan<int> counts, long total)
    {
        if (total == 0) return 0;
        double e = 0;
        foreach (var c in counts)
        {
            if (c == 0) continue;
            double p = (double)c / total;
            e -= p * Math.Log2(p);
        }
        return e;
    }
}
