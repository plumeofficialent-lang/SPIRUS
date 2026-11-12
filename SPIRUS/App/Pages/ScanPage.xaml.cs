using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Microsoft.Win32;
using Vigie.Core;
using Vigie.Core.Engine;

namespace Vigie.App.Pages;

public sealed class ThreatItem : INotifyPropertyChanged
{
    private string _state = "";
    private bool _failed;

    public ScanResult Result { get; init; }
    public string ScoreText => $"score {Result.Score}/100";

    public string State
    {
        get => _state;
        set { _state = value; Changed(nameof(State)); Changed(nameof(Pending)); }
    }

    public bool Failed
    {
        get => _failed;
        set { _failed = value; Changed(nameof(Failed)); }
    }

    public bool Pending => string.IsNullOrEmpty(_state);

    public event PropertyChangedEventHandler PropertyChanged;
    private void Changed(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public partial class ScanPage : UserControl, IPage
{
    private readonly Guardian _g;
    private readonly ObservableCollection<ThreatItem> _threats = new();
    private readonly HashSet<ScanResult> _seen = new();
    private ScanJob _job;
    private ScanSummary _summary;
    private bool _spinning;

    public ScanPage(Guardian guardian)
    {
        _g = guardian;
        InitializeComponent();
        ThreatList.ItemsSource = _threats;
        Unloaded += (_, _) => SetSpinning(false); // pas d'animation quand la page n'est pas affichée
    }

    public void Refresh()
    {
        if (_job == null && _summary == null) ShowIdle();
        var s = _g.Settings;
        LastSummary.Text = s.LastScanDate == null ? "" :
            $"Dernière analyse : {s.LastScanKind} — {Format.Ago(s.LastScanDate).ToLowerInvariant()}, {s.LastScanThreats} menace(s) trouvée(s).";
    }

    // ------------------------------------------------------------ démarrage

    public void Start(ScanKind kind, string[] paths)
    {
        if (_g.CurrentJob != null)
        {
            if (_job != _g.CurrentJob) Attach(_g.CurrentJob);
            Notifications.Info("Analyse déjà en cours", "Attendez la fin de l'analyse actuelle ou arrêtez-la.", ToastKind.Warning);
            return;
        }
        _g.StartScan(kind, paths); // l'événement ScanStarted appelle Attach()
    }

    public void Attach(ScanJob job)
    {
        _job = job;
        _summary = null;
        _threats.Clear();
        _seen.Clear();
        job.ThreatFound += r => Dispatcher.BeginInvoke(() => AddThreat(r));

        IdlePanel.Visibility = Visibility.Collapsed;
        RunPanel.Visibility = Visibility.Visible;
        RunButtons.Visibility = Visibility.Visible;
        DoneButtons.Visibility = Visibility.Collapsed;
        NewScanButton.Visibility = Visibility.Collapsed;
        CleanMessage.Visibility = Visibility.Collapsed;
        DoneGlyph.Visibility = Visibility.Collapsed;
        PercentText.Visibility = PercentCaption.Visibility = Visibility.Visible;
        ProgressArc.Visibility = Visibility.Visible;
        CurrentLabel.Text = "FICHIER EN COURS";
        PauseLabel.Text = "Pause";
        PauseGlyph.Text = "";
        RunTitle.Text = Guardian.KindLabel(job.Kind) + " en cours";
        RunSubtitle.Text = "Vous pouvez continuer à utiliser votre ordinateur pendant l'analyse.";
        SetSpinning(true);
        Tick();
    }

    private void AddThreat(ScanResult r)
    {
        if (!_seen.Add(r)) return;
        var item = new ThreatItem { Result = r };
        if (!File.Exists(r.Path))
            item.State = r.Verdict == Verdict.Malicious && r.AutoActionSafe && _g.Settings.AutoQuarantine ? "Mis en quarantaine automatiquement" : "Déjà neutralisé ou supprimé";
        _threats.Add(item);
    }

    public void Tick()
    {
        if (_job == null) return;
        var p = _job.Snapshot();
        CountScanned.Text = p.Scanned.ToString("N0");
        CountThreats.Text = p.Threats.ToString();
        CountThreats.Foreground = (Brush)FindResource(p.Threats > 0 ? "Danger" : "Text");
        CountTime.Text = Format.Duration(p.Elapsed);
        CountSpeed.Text = p.Elapsed.TotalSeconds > 1 ? $"{p.Scanned / p.Elapsed.TotalSeconds:N0}/s" : "—";
        CurrentFile.Text = string.IsNullOrEmpty(p.CurrentFile) ? "Préparation…" : p.CurrentFile;

        if (p.Percent < 0)
        {
            SetSpinning(true);
            PercentText.Text = p.Discovered.ToString("N0");
            PercentCaption.Text = "FICHIERS TROUVÉS";
        }
        else
        {
            SetSpinning(false);
            ProgressArc.Data = Arc(p.Percent / 100.0);
            PercentText.Text = $"{p.Percent:0}%";
            PercentCaption.Text = $"SUR {p.Discovered:N0} FICHIERS";
        }
    }

    /// <summary>Réaffiche un rapport d'analyse (fenêtre rouverte après une analyse avec menaces).</summary>
    public void ShowSummary(ScanSummary s)
    {
        _threats.Clear();
        _seen.Clear();
        Completed(s);
    }

    public void Completed(ScanSummary s)
    {
        IdlePanel.Visibility = Visibility.Collapsed;
        RunPanel.Visibility = Visibility.Visible;
        foreach (var r in s.Threats) AddThreat(r);
        _summary = s;
        _job = null;
        SetSpinning(false);

        RunButtons.Visibility = Visibility.Collapsed;
        NewScanButton.Visibility = Visibility.Visible;
        PercentText.Visibility = PercentCaption.Visibility = Visibility.Collapsed;
        ProgressArc.Data = Arc(1);
        DoneGlyph.Visibility = Visibility.Visible;
        bool clean = s.ThreatCount == 0;
        DoneGlyph.Text = clean ? "" : "";
        DoneGlyph.Foreground = (Brush)FindResource(clean ? "Accent" : "Danger");
        ProgressArc.Stroke = (Brush)FindResource(clean ? "AccentGradient" : "DangerGradient");

        RunTitle.Text = s.Cancelled ? "Analyse interrompue" : clean ? "Aucune menace détectée" : $"{s.ThreatCount} menace(s) détectée(s)";
        RunSubtitle.Text = $"{Guardian.KindLabel(s.Kind)} — {s.FilesScanned:N0} fichiers examinés en {Format.Duration(s.Duration)}"
                           + (s.Errors > 0 ? $" ({s.Errors:N0} fichiers illisibles ou protégés)." : ".");
        CurrentLabel.Text = "Résultat";
        CurrentFile.Text = clean ? "Votre ordinateur est sain. SPIRUS continue de veiller en arrière-plan." : "Choisissez une action pour chaque élément ci-dessous.";
        CountScanned.Text = s.FilesScanned.ToString("N0");
        CountThreats.Text = s.ThreatCount.ToString();
        CountTime.Text = Format.Duration(s.Duration);
        CleanMessage.Visibility = clean ? Visibility.Visible : Visibility.Collapsed;
        UpdateDoneButtons();
    }

    private void UpdateDoneButtons()
    {
        bool pending = _threats.Any(t => t.Pending || t.Failed);
        DoneButtons.Visibility = _summary != null && pending ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ShowIdle()
    {
        IdlePanel.Visibility = Visibility.Visible;
        RunPanel.Visibility = Visibility.Collapsed;
    }

    private void SetSpinning(bool on)
    {
        if (on == _spinning) return;
        _spinning = on;
        if (on)
        {
            ProgressArc.Stroke = (Brush)FindResource("AccentGradient");
            ProgressArc.Data = Arc(0.28);
            ArcSpin.BeginAnimation(RotateTransform.AngleProperty, new DoubleAnimation(0, 360, TimeSpan.FromSeconds(1.1)) { RepeatBehavior = RepeatBehavior.Forever });
        }
        else
        {
            ArcSpin.BeginAnimation(RotateTransform.AngleProperty, null);
            ArcSpin.Angle = 0;
        }
    }

    private static Geometry Arc(double fraction)
    {
        const double r = 82, c = 88;
        fraction = Math.Clamp(fraction, 0, 1);
        if (fraction >= 0.9999) return new EllipseGeometry(new Point(c, c), r, r);
        if (fraction <= 0.0001) return Geometry.Empty;
        double angle = fraction * 360;
        double rad = (angle - 90) * Math.PI / 180;
        var fig = new PathFigure { StartPoint = new Point(c, c - r), IsClosed = false };
        fig.Segments.Add(new ArcSegment(new Point(c + r * Math.Cos(rad), c + r * Math.Sin(rad)), new Size(r, r), 0, angle > 180, SweepDirection.Clockwise, true));
        return new PathGeometry(new[] { fig });
    }

    // ------------------------------------------------------------ actions

    private void Quick_Click(object sender, RoutedEventArgs e) => Start(ScanKind.Quick, null);
    private void Full_Click(object sender, RoutedEventArgs e) => Start(ScanKind.Full, null);

    private void PickFolder_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { Title = "Choisir les dossiers à analyser", Multiselect = true };
        if (dlg.ShowDialog(Window.GetWindow(this)) == true) Start(ScanKind.Custom, dlg.FolderNames);
    }

    private void PickFiles_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Choisir les fichiers à analyser", Multiselect = true };
        if (dlg.ShowDialog(Window.GetWindow(this)) == true) Start(ScanKind.Custom, dlg.FileNames);
    }

    private void Pause_Click(object sender, RoutedEventArgs e)
    {
        if (_job == null) return;
        if (_job.IsPaused) { _job.Resume(); PauseLabel.Text = "Pause"; PauseGlyph.Text = ""; }
        else { _job.Pause(); PauseLabel.Text = "Reprendre"; PauseGlyph.Text = ""; }
    }

    private void Stop_Click(object sender, RoutedEventArgs e) => _job?.Cancel();

    private void NewScan_Click(object sender, RoutedEventArgs e)
    {
        _summary = null;
        _threats.Clear();
        Refresh();
        ShowIdle();
    }

    private void Quarantine_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is ThreatItem t) QuarantineItem(t);
        UpdateDoneButtons();
    }

    private void QuarantineItem(ThreatItem t)
    {
        if (_g.QuarantineThreat(t.Result, out var err)) { t.Failed = false; t.State = "Mis en quarantaine"; }
        else { t.Failed = true; t.State = err; }
    }

    private void Allow_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not ThreatItem t) return;
        _g.AllowFile(t.Result);
        t.Failed = false;
        t.State = "Autorisé : ne sera plus signalé";
        UpdateDoneButtons();
    }

    private void Locate_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not ThreatItem t) return;
        try
        {
            if (File.Exists(t.Result.Path)) Process.Start("explorer.exe", $"/select,\"{t.Result.Path}\"");
            else if (Directory.Exists(Path.GetDirectoryName(t.Result.Path))) Process.Start("explorer.exe", $"\"{Path.GetDirectoryName(t.Result.Path)}\"");
        }
        catch { }
    }

    private void QuarantineAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var t in _threats.Where(t => t.Pending || t.Failed).ToList()) QuarantineItem(t);
        UpdateDoneButtons();
    }
}
