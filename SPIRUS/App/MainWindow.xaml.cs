using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using Vigie.App.Pages;
using Vigie.Core;

namespace Vigie.App;

public interface IPage
{
    void Refresh();
}

public partial class MainWindow : Window
{
    private readonly Guardian _g;
    private readonly DashboardPage _dashboard;
    private readonly ScanPage _scan;
    private readonly ProtectionPage _protection;
    private readonly QuarantinePage _quarantine;
    private readonly JournalPage _journal;
    private readonly SettingsPage _settings;
    private readonly DispatcherTimer _timer;
    private readonly Action _onStatus;
    private readonly Action<LogEntry> _onLog;
    private readonly Action _onQuarantine;
    private readonly Action<Vigie.Core.Engine.ScanJob> _onScanStarted;
    private readonly Action<ScanSummary> _onScanCompleted;

    public MainWindow(Guardian guardian)
    {
        _g = guardian;
        InitializeComponent();
        _dashboard = new DashboardPage(_g);
        _scan = new ScanPage(_g);
        _protection = new ProtectionPage(_g);
        _quarantine = new QuarantinePage(_g);
        _journal = new JournalPage(_g);
        _settings = new SettingsPage(_g);
        ShowPage(_dashboard);

        // Reprend une analyse en cours (lancée en arrière-plan) ou le dernier rapport avec menaces.
        if (_g.CurrentJob != null) _scan.Attach(_g.CurrentJob);
        else if (_g.LastSummary is { ThreatCount: > 0 } last && (DateTime.Now - last.Finished).TotalHours < 2) _scan.ShowSummary(last);

        _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();

        // Abonnements détachés à la fermeture : la fenêtre peut alors être libérée de la mémoire.
        _onStatus = () => Dispatcher.BeginInvoke(RefreshAll);
        _onLog = e => Dispatcher.BeginInvoke(() => { _dashboard.OnLog(); _journal.OnLog(e); });
        _onQuarantine = () => Dispatcher.BeginInvoke(() => { _quarantine.Refresh(); RefreshSidebar(); });
        _onScanStarted = job => Dispatcher.BeginInvoke(() => _scan.Attach(job));
        _onScanCompleted = s => Dispatcher.BeginInvoke(() => { _scan.Completed(s); _dashboard.Refresh(); });
        _g.StatusChanged += _onStatus;
        _g.Log.Added += _onLog;
        _g.Quarantine.Changed += _onQuarantine;
        _g.ScanStarted += _onScanStarted;
        _g.ScanCompleted += _onScanCompleted;
        Closed += (_, _) =>
        {
            _timer.Stop();
            _g.StatusChanged -= _onStatus;
            _g.Log.Added -= _onLog;
            _g.Quarantine.Changed -= _onQuarantine;
            _g.ScanStarted -= _onScanStarted;
            _g.ScanCompleted -= _onScanCompleted;
            StopPulse();
            PageHost.Content = null;
            if (!_g.Settings.MinimizeToTray && !App.Exiting && !App.SnapshotMode) App.Instance.ExitApplication();
        };

        ModeLabel.Text = _g.IsElevated ? "MODE ADMINISTRATEUR" : "";
        DragEnter += OnDragEnter;
        DragLeave += OnDragLeave;
        Drop += OnDrop;
        StateChanged += (_, _) =>
        {
            RootGrid.Margin = WindowState == WindowState.Maximized ? new Thickness(7) : new Thickness(0);
            MaxButton.Content = WindowState == WindowState.Maximized ? "" : "";
        };
        StartPulse();
        RefreshAll();
    }

    // ------------------------------------------------------------ navigation

    public void Navigate(string key)
    {
        var nav = key switch
        {
            "scan" => NavScan,
            "protection" => NavProtection,
            "quarantine" => NavQuarantine,
            "journal" => NavJournal,
            "settings" => NavSettings,
            _ => NavDashboard
        };
        if (nav.IsChecked == true) Nav_Checked(nav, null);
        else nav.IsChecked = true;
    }

    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        if (_dashboard == null) return;
        UserControl page = sender == NavScan ? _scan
            : sender == NavProtection ? _protection
            : sender == NavQuarantine ? _quarantine
            : sender == NavJournal ? _journal
            : sender == NavSettings ? _settings
            : _dashboard;
        ShowPage(page);
    }

    private void ShowPage(UserControl page)
    {
        if (page is IPage p) p.Refresh();
        if (PageHost.Content == page) return;
        PageHost.Content = page;
        var slide = new TranslateTransform(0, 14);
        page.RenderTransform = slide;
        page.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220)));
        slide.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(14, 0, TimeSpan.FromMilliseconds(300)) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } });
    }

    public void StartScan(ScanKind kind, string[] paths)
    {
        Navigate("scan");
        _scan.Start(kind, paths);
    }

    private void Tick()
    {
        if (!IsVisible) return;
        if (PageHost.Content == _scan) _scan.Tick();
        else if (PageHost.Content == _dashboard) _dashboard.Tick();
    }

    private void RefreshAll()
    {
        RefreshSidebar();
        if (PageHost.Content is IPage p) p.Refresh();
    }

    private void RefreshSidebar()
    {
        bool ok = _g.FullyProtected;
        var brush = (Brush)FindResource(ok ? "Accent" : "Warning");
        StatusDot.Fill = brush;
        StatusPulse.Fill = brush;
        SideStatus.Text = ok ? "Protection active" : "Protection incomplète";
        SideDetail.Text = ok ? $"{_g.Engine.SignatureCount:N0} signatures chargées" : "Des protections sont désactivées";
        int q = _g.Quarantine.Count;
        QuarantineBadge.Visibility = q > 0 ? Visibility.Visible : Visibility.Collapsed;
        QuarantineCount.Text = q.ToString();
    }

    private void StartPulse()
    {
        var scale = (ScaleTransform)StatusPulse.RenderTransform;
        var duration = TimeSpan.FromSeconds(1.8);
        var grow = new DoubleAnimation(1, 2.4, duration) { RepeatBehavior = RepeatBehavior.Forever };
        scale.BeginAnimation(ScaleTransform.ScaleXProperty, grow);
        scale.BeginAnimation(ScaleTransform.ScaleYProperty, grow);
        StatusPulse.BeginAnimation(OpacityProperty, new DoubleAnimation(0.55, 0, duration) { RepeatBehavior = RepeatBehavior.Forever });
    }

    private void StopPulse()
    {
        var scale = (ScaleTransform)StatusPulse.RenderTransform;
        scale.BeginAnimation(ScaleTransform.ScaleXProperty, null);
        scale.BeginAnimation(ScaleTransform.ScaleYProperty, null);
        StatusPulse.BeginAnimation(OpacityProperty, null);
    }

    // ------------------------------------------------------------ glisser-déposer

    private void OnDragEnter(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        e.Effects = DragDropEffects.Copy;
        DropOverlay.Visibility = Visibility.Visible;
    }

    private void OnDragLeave(object sender, DragEventArgs e)
    {
        var pos = e.GetPosition(this);
        if (pos.X <= 0 || pos.Y <= 0 || pos.X >= ActualWidth || pos.Y >= ActualHeight)
            DropOverlay.Visibility = Visibility.Collapsed;
    }

    private void OnDrop(object sender, DragEventArgs e)
    {
        DropOverlay.Visibility = Visibility.Collapsed;
        if (e.Data.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0)
            StartScan(ScanKind.Custom, files);
    }

    // ------------------------------------------------------------ fenêtre

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Maximize_Click(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        if (!_g.Settings.MinimizeToTray) { App.Instance.ExitApplication(); return; }
        Close();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        // La fenêtre est réellement fermée (et libérée) ; la protection continue dans la zone de notification.
        base.OnClosing(e);
        if (App.Exiting || App.SnapshotMode || !_g.Settings.MinimizeToTray) return;
        if (!_g.Settings.TrayHintShown)
        {
            App.Tray?.Balloon("SPIRUS veille toujours", "SPIRUS continue de vous protéger en arrière-plan. Cliquez sur le bouclier dans la zone de notification pour le rouvrir.");
            _g.Settings.TrayHintShown = true;
            _g.Save();
        }
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        var hwnd = new WindowInteropHelper(this).Handle;
        int dark = 1, round = 2, border = 0x001C1C1C, caption = 0x00000000;
        DwmSetWindowAttribute(hwnd, 20, ref dark, 4);     // mode sombre
        DwmSetWindowAttribute(hwnd, 33, ref round, 4);    // coins arrondis (Windows 11)
        DwmSetWindowAttribute(hwnd, 34, ref border, 4);   // couleur de bordure
        DwmSetWindowAttribute(hwnd, 35, ref caption, 4);  // couleur de légende
    }
}
