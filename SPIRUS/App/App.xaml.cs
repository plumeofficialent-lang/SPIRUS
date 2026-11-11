using System;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Vigie.Core;

namespace Vigie.App;

public partial class App : Application
{
    private const string MutexName = @"Local\SPIRUS.Antivirus.Instance";
    private static readonly string PipeName = "SPIRUS.Antivirus." + Environment.UserName;

    private Mutex _mutex;
    private readonly CancellationTokenSource _pipeCts = new();
    private MainWindow _window;

    public static Guardian Guardian { get; private set; }
    public static TrayIcon Tray { get; private set; }
    public static App Instance => (App)Current;
    public static bool SnapshotMode { get; private set; }
    public static bool Exiting { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var args = e.Args;
        var snapshotDir = ArgValue(args, "--snapshot");
        SnapshotMode = snapshotDir != null;

        if (int.TryParse(ArgValue(args, "--wait-pid"), out int previousPid))
        {
            try { using var previous = System.Diagnostics.Process.GetProcessById(previousPid); previous.WaitForExit(15000); } catch { }
        }

        if (!SnapshotMode)
        {
            _mutex = new Mutex(true, MutexName, out bool owner);
            if (!owner)
            {
                ForwardToRunningInstance(args);
                Shutdown();
                return;
            }
        }

        ShutdownMode = ShutdownMode.OnExplicitShutdown;
        DispatcherUnhandledException += (_, ex) =>
        {
            ex.Handled = true;
            Guardian?.Log.Add(LogLevel.Warning, "Erreur interne de l'interface", ex.Exception.Message);
        };

        try
        {
            Boot(args, snapshotDir);
        }
        catch (Exception ex)
        {
            if (SnapshotMode) File.WriteAllText(Path.Combine(Path.GetTempPath(), "vigie-snapshot-crash.txt"), ex.ToString());
            else MessageBox.Show("SPIRUS n'a pas pu démarrer :\n\n" + ex, "SPIRUS Antivirus", MessageBoxButton.OK, MessageBoxImage.Error);
            Exiting = true;
            Shutdown(1);
        }
    }

    private void Boot(string[] args, string snapshotDir)
    {
        Guardian = new Guardian();
        Guardian.Alert += a => Dispatcher.BeginInvoke(() => Notifications.ShowThreat(a));
        Guardian.UsbArrived += d => Dispatcher.BeginInvoke(() => Notifications.ShowUsb(d));
        Guardian.ScanCompleted += s => Dispatcher.BeginInvoke(() =>
        {
            if (_window == null || !_window.IsVisible || _window.WindowState == WindowState.Minimized) Notifications.ShowScanSummary(s);
        });
        Guardian.StatusChanged += () => Dispatcher.BeginInvoke(() => Tray?.Refresh());
        Guardian.UpdatesEnabled = !SnapshotMode;
        Guardian.UpdateFound += (info, _) => Dispatcher.BeginInvoke(() =>
            Notifications.Info("Mise à jour de SPIRUS", $"Installation de la version {info.Version.ToString(3)}… SPIRUS redémarre dans quelques secondes."));
        Guardian.Start();
        if (Guardian.JustUpdatedFrom != null && !SnapshotMode)
            Dispatcher.BeginInvoke(() => Notifications.Info("SPIRUS est à jour", $"La version {Updater.CurrentText} est installée.", ToastKind.Success),
                System.Windows.Threading.DispatcherPriority.ApplicationIdle);

        if (SnapshotMode)
        {
            _window = CreateWindow();
            _ = Snapshot.RunAsync(_window, snapshotDir, ArgValue(args, "--page"));
            return;
        }

        Tray = new TrayIcon(Guardian);
        StartPipeServer();

        // En arrière-plan, la fenêtre n'est créée qu'au moment où l'on en a besoin.
        bool background = args.Contains("--background");
        if (!background) ShowMain();
        var scan = ArgValue(args, "--scan");
        if (scan != null) ScanPaths(new[] { scan });
    }

    private static string ArgValue(string[] args, string name)
    {
        int i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private MainWindow CreateWindow()
    {
        var window = new MainWindow(Guardian);
        window.Closed += (_, _) =>
        {
            if (_window == window) _window = null;
            // La fenêtre est détruite à la fermeture : on rend sa mémoire au système.
            if (!Exiting) Task.Delay(2000).ContinueWith(_ => MemoryTrim.Run());
        };
        return window;
    }

    public void ShowMain(string page = null)
    {
        if (Exiting) return;
        _window ??= CreateWindow();
        if (!_window.IsVisible) _window.Show();
        if (_window.WindowState == WindowState.Minimized) _window.WindowState = WindowState.Normal;
        _window.Activate();
        _window.Topmost = true;
        _window.Topmost = false;
        _window.Focus();
        if (page != null) _window.Navigate(page);
    }

    public void ScanPaths(string[] paths)
    {
        ShowMain("scan");
        _window?.StartScan(ScanKind.Custom, paths);
    }

    public void StartQuickScan()
    {
        ShowMain("scan");
        _window?.StartScan(ScanKind.Quick, null);
    }

    public void RestartElevated()
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!)
            {
                UseShellExecute = true,
                Verb = "runas",
                Arguments = $"--wait-pid {Environment.ProcessId}"
            });
            ExitApplication();
        }
        catch (System.ComponentModel.Win32Exception) { /* élévation refusée par l'utilisateur */ }
    }

    public void ExitApplication()
    {
        Exiting = true;
        _pipeCts.Cancel();
        Notifications.CloseAll();
        Tray?.Dispose();
        Guardian?.Dispose();
        try { _mutex?.ReleaseMutex(); } catch { }
        Shutdown();
    }

    // ------------------------------------------------------------ instance unique

    private static void ForwardToRunningInstance(string[] args)
    {
        try
        {
            using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.Out);
            client.Connect(2000);
            var scan = ArgValue(args, "--scan");
            var message = scan != null ? "scan\n" + scan : args.Contains("--background") ? "noop" : "show";
            var bytes = Encoding.UTF8.GetBytes(message);
            client.Write(bytes, 0, bytes.Length);
        }
        catch { }
    }

    private void StartPipeServer()
    {
        var ct = _pipeCts.Token;
        Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    using var server = new NamedPipeServerStream(PipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
                    await server.WaitForConnectionAsync(ct);
                    using var reader = new StreamReader(server, Encoding.UTF8);
                    var message = await reader.ReadToEndAsync(ct);
                    await Dispatcher.BeginInvoke(() =>
                    {
                        if (message.StartsWith("scan\n")) ScanPaths(new[] { message[5..] });
                        else if (message == "show") ShowMain();
                    });
                }
                catch (OperationCanceledException) { break; }
                catch { await Task.Delay(500); }
            }
        });
    }
}
