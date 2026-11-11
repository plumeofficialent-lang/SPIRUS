using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Vigie.Core;

namespace Vigie.App.Pages;

public sealed class ModuleStatus
{
    public string Glyph { get; init; } = "";
    public string Name { get; init; } = "";
    public string Detail { get; init; } = "";
    public bool On { get; init; }
}

public partial class DashboardPage : UserControl, IPage
{
    private readonly Guardian _g;
    private string _heroState = "";

    public DashboardPage(Guardian guardian)
    {
        _g = guardian;
        InitializeComponent();
        // Les animations ne tournent que lorsque la page est affichée.
        Loaded += (_, _) => StartAnimations();
        Unloaded += (_, _) => StopAnimations();
        Refresh();
    }

    private void StopAnimations()
    {
        foreach (var ring in new[] { Ring1, Ring2 })
        {
            var scale = (ScaleTransform)ring.RenderTransform;
            scale.BeginAnimation(ScaleTransform.ScaleXProperty, null);
            scale.BeginAnimation(ScaleTransform.ScaleYProperty, null);
            ring.BeginAnimation(OpacityProperty, null);
        }
        ((RotateTransform)RingSpin.RenderTransform).BeginAnimation(RotateTransform.AngleProperty, null);
        ShieldGlow.BeginAnimation(System.Windows.Media.Effects.DropShadowEffect.BlurRadiusProperty, null);
    }

    private void StartAnimations()
    {
        var period = TimeSpan.FromSeconds(2.8);
        foreach (var (ring, delay) in new[] { (Ring1, 0.0), (Ring2, 1.4) })
        {
            var scale = (ScaleTransform)ring.RenderTransform;
            var grow = new DoubleAnimation(0.6, 1.0, period) { BeginTime = TimeSpan.FromSeconds(delay), RepeatBehavior = RepeatBehavior.Forever, EasingFunction = new SineEase { EasingMode = EasingMode.EaseOut } };
            scale.BeginAnimation(ScaleTransform.ScaleXProperty, grow);
            scale.BeginAnimation(ScaleTransform.ScaleYProperty, grow);
            ring.BeginAnimation(OpacityProperty, new DoubleAnimation(0.6, 0, period) { BeginTime = TimeSpan.FromSeconds(delay), RepeatBehavior = RepeatBehavior.Forever });
        }
        ((RotateTransform)RingSpin.RenderTransform).BeginAnimation(RotateTransform.AngleProperty,
            new DoubleAnimation(0, 360, TimeSpan.FromSeconds(30)) { RepeatBehavior = RepeatBehavior.Forever });
        ShieldGlow.BeginAnimation(System.Windows.Media.Effects.DropShadowEffect.BlurRadiusProperty,
            new DoubleAnimation(30, 56, TimeSpan.FromSeconds(2.2)) { AutoReverse = true, RepeatBehavior = RepeatBehavior.Forever, EasingFunction = new SineEase() });
    }

    public void Refresh()
    {
        var hour = DateTime.Now.Hour;
        Greeting.Text = $"{(hour < 5 || hour >= 18 ? "Bonsoir" : "Bonjour")} ! Voici l'état de la sécurité de votre ordinateur.";
        UpdateHero();

        var s = _g.Settings;
        long live = _g.Files.FilesScanned;
        StatScanned.Text = (s.TotalFilesScanned + live).ToString("N0");
        StatScannedSub.Text = $"dont {live:N0} en temps réel depuis le démarrage";
        StatBlocked.Text = s.TotalThreatsBlocked.ToString("N0");
        StatBlockedSub.Text = $"{_g.Quarantine.Count} fichier(s) en quarantaine";
        StatLast.Text = Format.Ago(s.LastScanDate);
        StatLastSub.Text = s.LastScanDate == null ? "Lancez votre première analyse" : $"{s.LastScanKind} — {s.LastScanThreats} menace(s)";
        StatSignatures.Text = _g.Engine.SignatureCount.ToString("N0");
        StatSignaturesSub.Text = $"{_g.Engine.Rules.Rules.Count} règles • mise à jour : {Format.Ago(s.LastSignatureUpdate).ToLowerInvariant()}";

        Modules.ItemsSource = BuildModules();
        RefreshActivity();
        AdminBanner.Visibility = _g.IsElevated ? Visibility.Collapsed : Visibility.Visible;
    }

    private List<ModuleStatus> BuildModules()
    {
        var s = _g.Settings;
        return new List<ModuleStatus>
        {
            new() { Glyph = "", Name = "Protection en temps réel", Detail = "Analyse chaque fichier créé ou modifié", On = s.RealTimeEnabled },
            new() { Glyph = "", Name = "Surveillance des programmes", Detail = "Vérifie chaque programme qui démarre", On = s.ProcessMonitorEnabled },
            new() { Glyph = "", Name = "Bouclier anti-rançongiciel", Detail = "Repère le chiffrement massif de vos fichiers", On = s.RansomwareGuardEnabled },
            new() { Glyph = "", Name = "Contrôle des clés USB", Detail = s.UsbAutoScan ? "Analyse automatique à l'insertion" : "Alerte à l'insertion", On = s.UsbMonitorEnabled },
            new() { Glyph = "", Name = "Moteur Windows (AMSI)", Detail = _g.Engine.AmsiAvailable ? "Deuxième avis du moteur de Windows" : "Indisponible sur ce système", On = s.AmsiEnabled && _g.Engine.AmsiAvailable }
        };
    }

    public void OnLog()
    {
        if (IsVisible) RefreshActivity();
    }

    private void RefreshActivity()
    {
        var entries = _g.Log.Entries.Take(5).ToList();
        Activity.ItemsSource = entries;
        NoActivity.Visibility = entries.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    public void Tick()
    {
        UpdateHero();
        StatScanned.Text = (_g.Settings.TotalFilesScanned + _g.Files.FilesScanned).ToString("N0");
    }

    private void UpdateHero()
    {
        var job = _g.CurrentJob;
        var s = _g.Settings;
        string state = job != null ? "scan" : _g.FullyProtected ? "ok" : "warn";

        if (state == "scan")
        {
            var p = job.Snapshot();
            HeroSubtitle.Text = $"{Guardian.KindLabel(job.Kind)} : {p.Scanned:N0} fichiers examinés, {p.Threats} menace(s) trouvée(s).";
        }
        else if (state == "ok")
        {
            HeroSubtitle.Text = "SPIRUS surveille en permanence vos fichiers, vos programmes et vos clés USB. "
                                + (s.LastScanDate == null ? "Lancez une première analyse pour vérifier votre ordinateur." : $"Dernière analyse : {Format.Ago(s.LastScanDate).ToLowerInvariant()}.");
        }
        if (state == _heroState) return;
        _heroState = state;

        bool warn = state == "warn";
        var solid = (Brush)FindResource(warn ? "Warning" : state == "scan" ? "Info" : "Accent");
        ShieldPath.Fill = (Brush)FindResource(warn ? "WarningGradient" : "AccentGradient");
        ShieldGlow.Color = warn ? Color.FromRgb(0xE0, 0xA0, 0x30) : Colors.White;
        GlowStop.Color = ShieldGlow.Color;
        ShieldMark.Data = Geometry.Parse(warn ? "M128,70 L128,142 M128,190 L128,191" : "M78,130 L114,166 L180,96");
        Ring1.Stroke = Ring2.Stroke = RingSpin.Stroke = solid;
        StatusChip.Background = (Brush)FindResource(warn ? "WarningSoft" : state == "scan" ? "InfoSoft" : "AccentSoft");
        StatusChipText.Foreground = solid;
        FixButton.Visibility = warn ? Visibility.Visible : Visibility.Collapsed;
        QuickLabel.Text = state == "scan" ? "Voir l'analyse" : "Analyse rapide";
        FullButton.Visibility = state == "scan" ? Visibility.Collapsed : Visibility.Visible;

        switch (state)
        {
            case "scan":
                StatusChipText.Text = "●  ANALYSE EN COURS";
                HeroTitle.Text = "Analyse en cours…";
                break;
            case "ok":
                StatusChipText.Text = "●  PROTECTION ACTIVE";
                HeroTitle.Text = "Vous êtes protégé";
                break;
            default:
                var off = BuildModules().Where(m => !m.On && m.Name != "Moteur Windows (AMSI)" && m.Name != "Contrôle des clés USB").Select(m => m.Name.ToLowerInvariant()).ToList();
                StatusChipText.Text = "●  PROTECTION INCOMPLÈTE";
                HeroTitle.Text = "Votre protection est incomplète";
                HeroSubtitle.Text = off.Count > 0 ? $"Désactivé : {string.Join(", ", off)}. Réactivez-les pour rester protégé." : "Certaines protections sont désactivées.";
                break;
        }
    }

    private void Quick_Click(object sender, RoutedEventArgs e)
    {
        if (_g.CurrentJob != null) App.Instance.ShowMain("scan");
        else App.Instance.StartQuickScan();
    }

    private void Full_Click(object sender, RoutedEventArgs e)
    {
        App.Instance.ShowMain("scan");
        if (Window.GetWindow(this) is MainWindow w) w.StartScan(ScanKind.Full, null);
    }

    private void Fix_Click(object sender, RoutedEventArgs e)
    {
        var s = _g.Settings;
        s.RealTimeEnabled = s.ProcessMonitorEnabled = s.RansomwareGuardEnabled = s.UsbMonitorEnabled = true;
        _g.ApplySettings();
        _g.Log.Add(LogLevel.Success, "Protections réactivées", "Toutes les protections sont de nouveau actives.");
    }

    private void Protection_Click(object sender, RoutedEventArgs e) => App.Instance.ShowMain("protection");
    private void Journal_Click(object sender, RoutedEventArgs e) => App.Instance.ShowMain("journal");
    private void Elevate_Click(object sender, RoutedEventArgs e) => App.Instance.RestartElevated();
}
