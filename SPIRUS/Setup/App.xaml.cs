using System;
using System.IO;
using System.Linq;
using System.Windows;

namespace Spirus.Setup;

/// <summary>
/// SPIRUS-Setup.exe                      installation avec interface
/// SPIRUS-Setup.exe --silent             installation sans interface (options par défaut)
/// SPIRUS-Setup.exe --uninstall [--silent]  désinstallation
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        bool uninstall = e.Args.Contains("--uninstall");
        int snapIndex = Array.IndexOf(e.Args, "--snapshot");
        string snapshot = snapIndex >= 0 && snapIndex + 1 < e.Args.Length ? e.Args[snapIndex + 1] : null;

        if (e.Args.Contains("--silent"))
        {
            int code = 0;
            try
            {
                var progress = new Progress<(int, string)>(_ => { });
                if (uninstall) { Installer.Uninstall(false, progress); Installer.ScheduleSelfCleanup(); }
                else { Installer.Install(new InstallOptions(), progress); Installer.Launch(background: true); }
            }
            catch (Exception ex)
            {
                code = 1;
                try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "spirus-setup-erreur.txt"), ex.ToString()); } catch { }
            }
            Shutdown(code);
            return;
        }

        var window = new SetupWindow(uninstall);
        if (snapshot != null) _ = window.SnapshotAsync(snapshot);
        else window.Show();
    }
}
