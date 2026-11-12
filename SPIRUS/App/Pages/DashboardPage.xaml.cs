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
        Refresh();
    }

    public void Refresh()
    {
        var today = DateTime.Now.ToString("dddd d MMMM", new System.Globalization.CultureInfo("fr-FR"));
        Greeting.Text = char.ToUpper(today[0]) + today[1..];
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
            HeroSubtitle.Text = "Fichiers, programmes et clés USB sous surveillance. "
                                + (s.LastScanDate == null ? "Lancez une première analyse pour vérifier votre ordinateur." : $"Dernière analyse : {Format.Ago(s.LastScanDate).ToLowerInvariant()}.");
        }
        if (state == _heroState) return;
        _heroState = state;

        bool warn = state == "warn";
        var solid = (Brush)FindResource(warn ? "Warning" : state == "scan" ? "Info" : "Accent");
        ShieldPath.Fill = solid;
        ShieldMark.Data = Geometry.Parse(warn ? "M128,70 L128,142 M128,190 L128,191" : state == "scan" ? "M128,84 L128,134 L160,152" : "M78,130 L114,166 L180,96");
        StatusChip.Background = (Brush)FindResource(warn ? "WarningSoft" : state == "scan" ? "InfoSoft" : "AccentSoft");
        StatusChipText.Foreground = solid;
        FixButton.Visibility = warn ? Visibility.Visible : Visibility.Collapsed;
        QuickLabel.Text = state == "scan" ? "Voir l'analyse" : "Analyse rapide";
        FullButton.Visibility = state == "scan" ? Visibility.Collapsed : Visibility.Visible;

        switch (state)
        {
            case "scan":
                StatusChipText.Text = "En cours";
                HeroTitle.Text = "Analyse en cours";
                break;
            case "ok":
                StatusChipText.Text = "Actif";
                HeroTitle.Text = "Votre ordinateur est protégé";
                break;
            default:
                var off = BuildModules().Where(m => !m.On && m.Name != "Moteur Windows (AMSI)" && m.Name != "Contrôle des clés USB").Select(m => m.Name.ToLowerInvariant()).ToList();
                StatusChipText.Text = "Incomplet";
                HeroTitle.Text = "Protection incomplète";
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
