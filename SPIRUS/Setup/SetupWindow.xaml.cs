using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;

namespace Spirus.Setup;

public partial class SetupWindow : Window
{
    private readonly bool _uninstallMode;
    private bool _busy;
    private bool _finished;

    public SetupWindow(bool uninstallMode)
    {
        _uninstallMode = uninstallMode;
        InitializeComponent();
        VersionText.Text = $"Antivirus • version {Installer.Version}";
        LocationText.Text = $"Emplacement : {Installer.InstallDir} — aucun droit administrateur nécessaire.";
        if (Installer.IsInstalled) InstallLabel.Text = "Mettre à jour";
        if (uninstallMode)
        {
            HeaderText.Text = "DÉSINSTALLATION";
            Show(UninstallPanel);
        }
    }

    private void Show(FrameworkElement panel)
    {
        foreach (var p in new FrameworkElement[] { WelcomePanel, UninstallPanel, ProgressPanel, DonePanel, ErrorPanel })
            p.Visibility = p == panel ? Visibility.Visible : Visibility.Collapsed;
        panel.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220)));
    }

    private async void Install_Click(object sender, RoutedEventArgs e)
    {
        var options = new InstallOptions
        {
            Autostart = OptAutostart.IsChecked == true,
            ContextMenu = OptContextMenu.IsChecked == true,
            DesktopShortcut = OptDesktop.IsChecked == true
        };
        ProgressTitle.Text = Installer.IsInstalled ? "Mise à jour en cours…" : "Installation en cours…";
        if (await RunAsync(p => Installer.Install(options, p)))
        {
            DoneTitle.Text = "SPIRUS est installé";
            DoneText.Text = options.Autostart
                ? "SPIRUS protège maintenant votre ordinateur et démarrera avec Windows. Retrouvez-le près de l'horloge, dans le menu Démarrer ou sur le Bureau."
                : "SPIRUS est prêt. Retrouvez-le dans le menu Démarrer.";
            LaunchRow.Visibility = Visibility.Visible;
            Show(DonePanel);
        }
    }

    private async void Uninstall_Click(object sender, RoutedEventArgs e)
    {
        bool removeData = OptRemoveData.IsChecked == true;
        ProgressTitle.Text = "Désinstallation en cours…";
        if (await RunAsync(p => Installer.Uninstall(removeData, p)))
        {
            DoneTitle.Text = "SPIRUS a été désinstallé";
            DoneText.Text = removeData
                ? "Le programme et toutes ses données ont été supprimés."
                : "Vos réglages et votre journal sont conservés, au cas où vous réinstalleriez SPIRUS.";
            LaunchRow.Visibility = Visibility.Collapsed;
            Show(DonePanel);
        }
    }

    private async Task<bool> RunAsync(Action<IProgress<(int, string)>> work)
    {
        _busy = true;
        CloseButton.IsEnabled = false;
        Bar.BeginAnimation(System.Windows.Controls.Primitives.RangeBase.ValueProperty, null);
        Bar.Value = 0;
        StatusText.Text = "";
        Show(ProgressPanel);
        var progress = new Progress<(int Percent, string Text)>(p =>
        {
            Bar.BeginAnimation(System.Windows.Controls.Primitives.RangeBase.ValueProperty,
                new DoubleAnimation(p.Percent, TimeSpan.FromMilliseconds(250)));
            StatusText.Text = p.Text;
        });
        try
        {
            await Task.Run(() => work(progress));
            await Task.Delay(500);
            return true;
        }
        catch (Exception ex)
        {
            ErrorText.Text = ex.Message;
            Show(ErrorPanel);
            return false;
        }
        finally
        {
            _busy = false;
            CloseButton.IsEnabled = true;
        }
    }

    private void Retry_Click(object sender, RoutedEventArgs e) => Show(_uninstallMode ? UninstallPanel : WelcomePanel);

    private void Finish_Click(object sender, RoutedEventArgs e)
    {
        _finished = true;
        if (_uninstallMode) Installer.ScheduleSelfCleanup();
        else if (OptLaunch.IsChecked == true) Installer.Launch(background: false);
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        if (DonePanel.Visibility == Visibility.Visible) { Finish_Click(sender, e); return; }
        Close();
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        if (_busy) e.Cancel = true; // on n'interrompt pas une installation en cours
        else if (_uninstallMode && DonePanel.Visibility == Visibility.Visible && !_finished) Installer.ScheduleSelfCleanup();
        base.OnClosing(e);
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        var hwnd = new WindowInteropHelper(this).Handle;
        int dark = 1, round = 2;
        DwmSetWindowAttribute(hwnd, 20, ref dark, 4);
        DwmSetWindowAttribute(hwnd, 33, ref round, 4);
    }

    // ------------------------------------------------------------------ captures de vérification

    public async Task SnapshotAsync(string dir)
    {
        Directory.CreateDirectory(dir);
        WindowStartupLocation = WindowStartupLocation.Manual;
        Left = -5000;
        ShowActivated = false;
        Show();
        await Task.Delay(800);
        Render(Path.Combine(dir, _uninstallMode ? "desinstallation.png" : "accueil.png"));
        ProgressTitle.Text = "Installation en cours…";
        Show(ProgressPanel);
        Bar.Value = 62;
        StatusText.Text = "Création des raccourcis…";
        await Task.Delay(500);
        Render(Path.Combine(dir, "progression.png"));
        DoneText.Text = "SPIRUS protège maintenant votre ordinateur et démarrera avec Windows. Retrouvez-le près de l'horloge, dans le menu Démarrer ou sur le Bureau.";
        Show(DonePanel);
        await Task.Delay(500);
        Render(Path.Combine(dir, "termine.png"));
        _finished = true;
        Close();
    }

    private void Render(string file)
    {
        var content = (FrameworkElement)Content;
        var dpi = VisualTreeHelper.GetDpi(this);
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            var rect = new Rect(0, 0, content.ActualWidth, content.ActualHeight);
            dc.DrawRectangle(Background, null, rect);
            dc.DrawRectangle(new VisualBrush(content), null, rect);
        }
        var rtb = new RenderTargetBitmap((int)(content.ActualWidth * dpi.DpiScaleX), (int)(content.ActualHeight * dpi.DpiScaleY), dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
        rtb.Render(visual);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(rtb));
        using var fs = File.Create(file);
        encoder.Save(fs);
    }
}
