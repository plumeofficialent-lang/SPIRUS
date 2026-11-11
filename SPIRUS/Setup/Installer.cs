using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using Microsoft.Win32;

namespace Spirus.Setup;

public sealed class InstallOptions
{
    public bool Autostart { get; set; } = true;
    public bool ContextMenu { get; set; } = true;
    public bool DesktopShortcut { get; set; } = true;
}

/// <summary>Installation et désinstallation de SPIRUS pour l'utilisateur courant (sans droits administrateur).</summary>
public static class Installer
{
    public static string Version
    {
        get
        {
            var v = typeof(Installer).Assembly.GetName().Version ?? new System.Version(1, 0, 0);
            return $"{v.Major}.{v.Minor}.{Math.Max(0, v.Build)}";
        }
    }
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\SPIRUS";
    private static readonly string[] MenuRoots =
    {
        @"Software\Classes\*\shell\VigieScan", @"Software\Classes\Directory\shell\VigieScan", @"Software\Classes\Drive\shell\VigieScan"
    };

    private static string Local => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    public static string InstallDir => Path.Combine(Local, "Programs", "SPIRUS");
    public static string DataDir => Path.Combine(Local, "SPIRUS");
    public static string ExePath => Path.Combine(InstallDir, "SPIRUS.exe");
    public static string UninstallerPath => Path.Combine(InstallDir, "SPIRUS-Uninstall.exe");
    private static string StartMenuShortcut => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), "SPIRUS Antivirus.lnk");
    private static string DesktopShortcut => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "SPIRUS Antivirus.lnk");

    public static bool IsInstalled => File.Exists(ExePath);
    public static bool HasPayload => Assembly.GetExecutingAssembly().GetManifestResourceNames().Contains("payload/SPIRUS.exe");

    // ------------------------------------------------------------------ installation

    public static void Install(InstallOptions o, IProgress<(int, string)> progress)
    {
        if (!HasPayload) throw new InvalidOperationException("Ce programme d'installation est incomplet : il ne contient pas SPIRUS.");

        progress.Report((5, "Arrêt de SPIRUS s'il est en cours d'exécution…"));
        StopRunning();

        progress.Report((15, "Reprise d'une ancienne installation…"));
        MigrateLegacy();

        progress.Report((25, "Copie des fichiers…"));
        Directory.CreateDirectory(InstallDir);
        var asm = Assembly.GetExecutingAssembly();
        foreach (var name in asm.GetManifestResourceNames().Where(n => n.StartsWith("payload/")))
        {
            var target = Path.Combine(InstallDir, name["payload/".Length..]);
            Retry(() =>
            {
                using var src = asm.GetManifestResourceStream(name)!;
                using var dst = new FileStream(target, FileMode.Create, FileAccess.Write);
                src.CopyTo(dst);
            });
        }
        var self = Environment.ProcessPath;
        if (!string.IsNullOrEmpty(self) && !string.Equals(Path.GetFullPath(self), UninstallerPath, StringComparison.OrdinalIgnoreCase))
            Retry(() => File.Copy(self, UninstallerPath, true));

        progress.Report((55, "Création des raccourcis…"));
        CreateShortcut(StartMenuShortcut);
        if (o.DesktopShortcut) CreateShortcut(DesktopShortcut);
        else TryDelete(DesktopShortcut);

        progress.Report((70, "Intégration à Windows…"));
        using (var run = Registry.CurrentUser.CreateSubKey(RunKey, true))
        {
            if (o.Autostart) run.SetValue("SPIRUS", $"\"{ExePath}\" --background");
            else run.DeleteValue("SPIRUS", false);
        }
        foreach (var root in MenuRoots)
        {
            if (!o.ContextMenu) { Registry.CurrentUser.DeleteSubKeyTree(root, false); continue; }
            using var key = Registry.CurrentUser.CreateSubKey(root, true);
            key.SetValue("MUIVerb", "Analyser avec SPIRUS");
            key.SetValue("Icon", $"\"{ExePath}\",0");
            using var cmd = key.CreateSubKey("command", true);
            cmd.SetValue("", $"\"{ExePath}\" --scan \"%1\"");
        }
        RegisterUninstall();

        progress.Report((90, "Enregistrement des préférences…"));
        SaveSettings(o);
        progress.Report((100, "SPIRUS est installé."));
    }

    private static void RegisterUninstall()
    {
        long size = Directory.EnumerateFiles(InstallDir).Sum(f => new FileInfo(f).Length) / 1024;
        using var key = Registry.CurrentUser.CreateSubKey(UninstallKey, true);
        key.SetValue("DisplayName", "SPIRUS Antivirus");
        key.SetValue("DisplayVersion", Version);
        key.SetValue("Publisher", "SPIRUS");
        key.SetValue("DisplayIcon", $"\"{ExePath}\",0");
        key.SetValue("InstallLocation", InstallDir);
        key.SetValue("UninstallString", $"\"{UninstallerPath}\" --uninstall");
        key.SetValue("QuietUninstallString", $"\"{UninstallerPath}\" --uninstall --silent");
        key.SetValue("EstimatedSize", (int)size, RegistryValueKind.DWord);
        key.SetValue("NoModify", 1, RegistryValueKind.DWord);
        key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
        key.SetValue("InstallDate", DateTime.Now.ToString("yyyyMMdd"));
    }

    private static void SaveSettings(InstallOptions o)
    {
        Directory.CreateDirectory(DataDir);
        var file = Path.Combine(DataDir, "settings.json");
        JsonObject settings = null;
        try { if (File.Exists(file)) settings = JsonNode.Parse(File.ReadAllText(file)) as JsonObject; } catch { }
        settings ??= new JsonObject();
        settings["StartWithWindows"] = o.Autostart;
        settings["ContextMenuEnabled"] = o.ContextMenu;
        File.WriteAllText(file, settings.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }

    /// <summary>Remplace une installation sous l'ancien nom « Vigie » en conservant les données.</summary>
    private static void MigrateLegacy()
    {
        var legacyData = Path.Combine(Local, "Vigie");
        try
        {
            if (Directory.Exists(legacyData) && !File.Exists(Path.Combine(DataDir, "settings.json")))
            {
                Directory.CreateDirectory(DataDir);
                foreach (var entry in Directory.EnumerateFileSystemEntries(legacyData))
                {
                    var target = Path.Combine(DataDir, Path.GetFileName(entry));
                    if (Directory.Exists(entry)) { if (!Directory.Exists(target)) Directory.Move(entry, target); }
                    else File.Move(entry, target, true);
                }
                Directory.Delete(legacyData, true);
            }
        }
        catch { }
        using (var run = Registry.CurrentUser.OpenSubKey(RunKey, true)) run?.DeleteValue("Vigie", false);
        TryDelete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), "Vigie Antivirus.lnk"));
        TryDelete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Vigie Antivirus.lnk"));
        try { var old = Path.Combine(Local, "Programs", "Vigie"); if (Directory.Exists(old)) Directory.Delete(old, true); } catch { }
    }

    // ------------------------------------------------------------------ désinstallation

    public static void Uninstall(bool removeData, IProgress<(int, string)> progress)
    {
        progress.Report((10, "Arrêt de SPIRUS…"));
        StopRunning();

        progress.Report((35, "Suppression de l'intégration à Windows…"));
        using (var run = Registry.CurrentUser.OpenSubKey(RunKey, true)) run?.DeleteValue("SPIRUS", false);
        foreach (var root in MenuRoots) Registry.CurrentUser.DeleteSubKeyTree(root, false);
        Registry.CurrentUser.DeleteSubKeyTree(UninstallKey, false);
        TryDelete(StartMenuShortcut);
        TryDelete(DesktopShortcut);

        progress.Report((65, "Suppression des fichiers…"));
        var self = Environment.ProcessPath ?? "";
        if (Directory.Exists(InstallDir))
            foreach (var f in Directory.EnumerateFiles(InstallDir))
                if (!string.Equals(f, self, StringComparison.OrdinalIgnoreCase)) TryDelete(f);
        if (removeData)
        {
            progress.Report((85, "Suppression des réglages, du journal et de la quarantaine…"));
            try { if (Directory.Exists(DataDir)) Directory.Delete(DataDir, true); } catch { }
        }
        progress.Report((100, "SPIRUS a été désinstallé."));
    }

    /// <summary>Le désinstalleur ne peut pas s'effacer lui-même : un processus le fait juste après sa fermeture.</summary>
    public static void ScheduleSelfCleanup()
    {
        var self = Environment.ProcessPath ?? "";
        if (!self.StartsWith(InstallDir, StringComparison.OrdinalIgnoreCase)) return;
        Process.Start(new ProcessStartInfo("cmd.exe", $"/c ping 127.0.0.1 -n 3 > nul & del /f /q \"{self}\" & rmdir /q \"{InstallDir}\"")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            WorkingDirectory = Path.GetTempPath()
        });
    }

    // ------------------------------------------------------------------ outils

    private static void StopRunning()
    {
        foreach (var name in new[] { "SPIRUS", "Vigie" })
            foreach (var p in Process.GetProcessesByName(name))
                using (p)
                {
                    try
                    {
                        // Pas Kill(true) : lors d'une mise à jour, cet installeur est lui-même un enfant de SPIRUS.
                        if (p.HasExited) continue;
                        p.Kill();
                        p.WaitForExit(5000);
                    }
                    catch (Exception)
                    {
                        throw new InvalidOperationException(
                            "SPIRUS est lancé en mode administrateur et ne peut pas être arrêté automatiquement. " +
                            "Quittez-le (clic droit sur le bouclier près de l'horloge → Quitter SPIRUS), puis relancez l'installation.");
                    }
                }
    }

    private static void CreateShortcut(string path)
    {
        var type = Type.GetTypeFromProgID("WScript.Shell") ?? throw new InvalidOperationException("Création de raccourci impossible.");
        dynamic shell = Activator.CreateInstance(type);
        try
        {
            dynamic link = shell.CreateShortcut(path);
            link.TargetPath = ExePath;
            link.WorkingDirectory = InstallDir;
            link.IconLocation = ExePath + ",0";
            link.Description = "SPIRUS Antivirus";
            link.Save();
            Marshal.FinalReleaseComObject(link);
        }
        finally { Marshal.FinalReleaseComObject(shell); }
    }

    private static void Retry(Action action)
    {
        for (int i = 0; ; i++)
        {
            try { action(); return; }
            catch (IOException) when (i < 10) { Thread.Sleep(300); }
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    public static void Launch(bool background)
    {
        if (File.Exists(ExePath))
            Process.Start(new ProcessStartInfo(ExePath) { UseShellExecute = true, Arguments = background ? "--background" : "" });
    }
}
