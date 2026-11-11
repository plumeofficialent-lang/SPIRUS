using System.Runtime.InteropServices;
using System.Text;

namespace Vigie.Core.Engine;

/// <summary>Vérification des signatures numériques Authenticode via WinVerifyTrust.</summary>
public static class Authenticode
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [In] ref Guid action, ref WinTrustData data);

    /// <summary>Vrai si le fichier porte une signature Authenticode intégrée valide.</summary>
    public static bool IsTrusted(string path)
    {
        var fileInfo = new WinTrustFileInfo { cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(), pcwszFilePath = path };
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = 2,            // WTD_UI_NONE
                fdwRevocationChecks = 0,   // WTD_REVOKE_NONE
                dwUnionChoice = 1,         // WTD_CHOICE_FILE
                pFile = pFile,
                dwStateAction = 1,         // WTD_STATEACTION_VERIFY
                dwProvFlags = 0x1000 | 0x10 // cache uniquement, pas de vérification de révocation en ligne
            };
            var action = GenericVerifyV2;
            int result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            data.dwStateAction = 2;        // WTD_STATEACTION_CLOSE
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            return result == 0;
        }
        catch { return false; }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(pFile);
            Marshal.FreeHGlobal(pFile);
        }
    }
}

/// <summary>
/// Antimalware Scan Interface : soumet le contenu au moteur antivirus de Windows
/// (Microsoft Defender ou l'antivirus installé) en renfort du moteur de SPIRUS.
/// </summary>
public sealed class AmsiScanner : IDisposable
{
    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiInitialize(string appName, out IntPtr context);
    [DllImport("amsi.dll")]
    private static extern void AmsiUninitialize(IntPtr context);
    [DllImport("amsi.dll")]
    private static extern int AmsiOpenSession(IntPtr context, out IntPtr session);
    [DllImport("amsi.dll")]
    private static extern void AmsiCloseSession(IntPtr context, IntPtr session);
    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiScanBuffer(IntPtr context, byte[] buffer, uint length, string contentName, IntPtr session, out int result);

    private IntPtr _context;
    private readonly object _lock = new();

    public bool Available { get; }

    public AmsiScanner()
    {
        try { Available = AmsiInitialize("SPIRUS Antivirus", out _context) == 0 && _context != IntPtr.Zero; }
        catch { Available = false; }
    }

    /// <summary>Renvoie vrai si le moteur Windows considère le contenu comme malveillant.</summary>
    public bool IsMalicious(byte[] data, int length, string name)
    {
        if (!Available || length <= 0) return false;
        lock (_lock)
        {
            if (_context == IntPtr.Zero) return false;
            IntPtr session = IntPtr.Zero;
            try
            {
                AmsiOpenSession(_context, out session);
                int hr = AmsiScanBuffer(_context, data, (uint)length, name, session, out int result);
                return hr == 0 && result >= 32768; // AMSI_RESULT_DETECTED
            }
            catch { return false; }
            finally { if (session != IntPtr.Zero) AmsiCloseSession(_context, session); }
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (_context != IntPtr.Zero) { try { AmsiUninitialize(_context); } catch { } _context = IntPtr.Zero; }
        }
    }
}

public static class ProcessInfo
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW")]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref int size);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    /// <summary>Chemin complet de l'exécutable d'un processus (fonctionne sans droits administrateur pour la plupart des processus).</summary>
    public static string GetImagePath(int pid)
    {
        IntPtr h = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString(0, size) : null;
        }
        finally { CloseHandle(h); }
    }

    public static bool IsElevated()
    {
        using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }
}
