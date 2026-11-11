using System;
using System.Windows;
using System.Windows.Controls;
using Vigie.Core;

namespace Vigie.App.Pages;

public partial class ProtectionPage : UserControl, IPage
{
    private readonly Guardian _g;
    private bool _loading;

    public ProtectionPage(Guardian guardian)
    {
        _g = guardian;
        InitializeComponent();
    }

    public void Refresh()
    {
        _loading = true;
        var s = _g.Settings;
        Rows.Children.Clear();

        Rows.Children.Add(UiKit.SectionTitle("Boucliers en temps réel"));
        Rows.Children.Add(UiKit.Toggle("", "Protection en temps réel",
            "Analyse chaque fichier dès qu'il est créé, téléchargé ou modifié, sur tous vos disques internes.",
            s.RealTimeEnabled, v => Set(() => s.RealTimeEnabled = v, v ? "Protection en temps réel activée" : "Protection en temps réel désactivée")));
        Rows.Children.Add(UiKit.Toggle("", "Surveillance des programmes",
            "Vérifie chaque programme au moment où il démarre, ainsi que ceux déjà en cours d'exécution.",
            s.ProcessMonitorEnabled, v => Set(() => s.ProcessMonitorEnabled = v, v ? "Surveillance des programmes activée" : "Surveillance des programmes désactivée")));
        Rows.Children.Add(UiKit.Toggle("", "Bouclier anti-rançongiciel",
            "Repère le chiffrement ou le renommage massif de vos documents et désigne le programme responsable.",
            s.RansomwareGuardEnabled, v => Set(() => s.RansomwareGuardEnabled = v, v ? "Bouclier anti-rançongiciel activé" : "Bouclier anti-rançongiciel désactivé")));
        Rows.Children.Add(UiKit.Toggle("", "Contrôle des périphériques USB",
            "Vous avertit dès qu'une clé USB ou un disque amovible est branché.",
            s.UsbMonitorEnabled, v => Set(() => s.UsbMonitorEnabled = v, null)));
        var usbAuto = UiKit.Toggle(null, "Analyser automatiquement les nouveaux périphériques",
            "Lance une analyse complète de la clé dès son insertion (fichiers autorun, programmes cachés…).",
            s.UsbAutoScan, v => Set(() => s.UsbAutoScan = v, null), s.UsbMonitorEnabled);
        usbAuto.Margin = new Thickness(56, 0, 0, 8);
        Rows.Children.Add(usbAuto);

        Rows.Children.Add(UiKit.SectionTitle("Moteur d'analyse"));
        Rows.Children.Add(UiKit.Toggle("", "Deuxième avis du moteur Windows (AMSI)",
            _g.Engine.AmsiAvailable
                ? "Soumet aussi les fichiers à risque au moteur antivirus intégré à Windows, en plus des signatures et heuristiques de SPIRUS."
                : "Indisponible : aucun moteur AMSI n'est enregistré sur ce système.",
            s.AmsiEnabled && _g.Engine.AmsiAvailable, v => Set(() => s.AmsiEnabled = v, null), _g.Engine.AmsiAvailable, "Info"));
        Rows.Children.Add(UiKit.Toggle("", "Analyse des archives",
            "Inspecte le contenu des fichiers ZIP, des documents Office et des archives Java, jusqu'à deux niveaux d'imbrication.",
            s.ScanArchives, v => Set(() => s.ScanArchives = v, null), true, "Info"));
        Rows.Children.Add(UiKit.Toggle("", "Analyser tous les types de fichiers en temps réel",
            "Par défaut, seuls les fichiers à risque (programmes, scripts, documents à macros, archives, raccourcis…) sont examinés à la volée.",
            s.RealTimeAllFileTypes, v => Set(() => s.RealTimeAllFileTypes = v, null), true, "Info"));
        Rows.Children.Add(UiKit.Toggle("", "Quarantaine automatique",
            "Neutralise immédiatement les menaces confirmées. Les fichiers seulement suspects vous sont toujours soumis.",
            s.AutoQuarantine, v => Set(() => s.AutoQuarantine = v, null), true, "Warning"));

        SensLow.IsChecked = s.Sensitivity == Sensitivity.Low;
        SensNormal.IsChecked = s.Sensitivity == Sensitivity.Normal;
        SensHigh.IsChecked = s.Sensitivity == Sensitivity.High;
        UpdateSensitivityText();
        _loading = false;
    }

    private void Set(Action apply, string logMessage)
    {
        if (_loading) return;
        apply();
        _g.ApplySettings();
        if (logMessage != null) _g.Log.Add(logMessage.Contains("désactivé") ? LogLevel.Warning : LogLevel.Success, logMessage);
    }

    private void Sensitivity_Checked(object sender, RoutedEventArgs e)
    {
        if (_loading || _g == null) return;
        _g.Settings.Sensitivity = sender == SensLow ? Sensitivity.Low : sender == SensHigh ? Sensitivity.High : Sensitivity.Normal;
        _g.ApplySettings();
        UpdateSensitivityText();
    }

    private void UpdateSensitivityText()
    {
        SensDescription.Text = _g.Settings.Sensitivity switch
        {
            Sensitivity.Low => "Ne signale que les menaces quasi certaines. Très peu de fausses alertes.",
            Sensitivity.High => "Paranoïaque : signale le moindre comportement inhabituel. Davantage de fausses alertes possibles.",
            _ => "Équilibre recommandé entre détection des menaces inconnues et fausses alertes."
        };
    }
}
