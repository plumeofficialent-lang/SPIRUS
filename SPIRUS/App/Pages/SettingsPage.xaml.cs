using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Vigie.Core;
using Vigie.Core.Engine;

namespace Vigie.App.Pages;

public partial class SettingsPage : UserControl, IPage
{
    private readonly Guardian _g;
    private static readonly int[] SizeSteps = { 25, 50, 100, 150, 250, 500, 1000 };

    public SettingsPage(Guardian guardian)
    {
        _g = guardian;
        InitializeComponent();
    }

    private AppSettings S => _g.Settings;

    public void Refresh()
    {
        var offset = Scroller.VerticalOffset;
        Rows.Children.Clear();

        // ---------------------------------------------------------------- Système
        Rows.Children.Add(UiKit.SectionTitle("Système"));
        Rows.Children.Add(UiKit.Toggle("", "Démarrer avec Windows",
            "SPIRUS se lance discrètement à l'ouverture de session et protège votre ordinateur en permanence.",
            SystemIntegration.IsAutostartEnabled(), v => Try(() => { SystemIntegration.SetAutostart(v); S.StartWithWindows = v; _g.Save(); })));
        Rows.Children.Add(UiKit.Toggle("", "Menu « Analyser avec SPIRUS » dans l'Explorateur",
            "Clic droit sur un fichier, un dossier ou un disque pour l'analyser (sous Windows 11 : « Afficher plus d'options »).",
            S.ContextMenuEnabled, v => Try(() => { SystemIntegration.SetContextMenu(v); S.ContextMenuEnabled = v; _g.Save(); })));
        Rows.Children.Add(UiKit.Toggle("", "Rester actif dans la zone de notification",
            "Fermer la fenêtre ne coupe pas la protection : SPIRUS continue de veiller près de l'horloge.",
            S.MinimizeToTray, v => { S.MinimizeToTray = v; _g.Save(); }));
        Rows.Children.Add(UiKit.Toggle("", "Notifications",
            "Affiche une alerte quand une menace est neutralisée, une analyse terminée ou une clé USB branchée. Les menaces qui demandent votre avis s'affichent toujours.",
            S.Notifications, v => { S.Notifications = v; _g.Save(); }));

        // ---------------------------------------------------------------- Planification
        Rows.Children.Add(UiKit.SectionTitle("Analyse planifiée"));
        Rows.Children.Add(UiKit.Toggle("", "Analyse rapide quotidienne",
            "Une analyse rapide est lancée automatiquement chaque jour à l'heure choisie.",
            S.ScheduledScanEnabled, v => { S.ScheduledScanEnabled = v; _g.Save(); }));
        Rows.Children.Add(UiKit.Row("", "Heure de l'analyse", "Si l'ordinateur est éteint à cette heure-là, l'analyse a lieu le lendemain.",
            Stepper($"{S.ScheduledScanHour:00} h 00", () => { S.ScheduledScanHour = (S.ScheduledScanHour + 23) % 24; _g.Save(); }, () => { S.ScheduledScanHour = (S.ScheduledScanHour + 1) % 24; _g.Save(); })));

        // ---------------------------------------------------------------- Signatures
        Rows.Children.Add(UiKit.SectionTitle("Signatures"));
        var rules = _g.Engine.Rules;
        var update = UiKit.Button("Mettre à jour", async (b, _) =>
        {
            if (string.IsNullOrWhiteSpace(S.MalwareBazaarKey))
            {
                Notifications.Info("Clé d'accès requise", "Saisissez d'abord votre clé abuse.ch gratuite ci-dessous.", ToastKind.Warning);
                return;
            }
            ((Button)b).IsEnabled = false;
            var msg = await _g.UpdateSignaturesAsync();
            Notifications.Info("Signatures", msg, msg.Contains("ajoutées") ? ToastKind.Success : ToastKind.Warning);
            Refresh();
        }, "Btn.Primary", "");
        Rows.Children.Add(UiKit.Row("", "Base de signatures",
            $"{rules.Rules.Count} règles comportementales (version {rules.Version}) et {_g.Engine.Hashes.Count:N0} empreintes de logiciels malveillants. Dernière mise à jour : {Format.Ago(S.LastSignatureUpdate).ToLowerInvariant()}.",
            update, "Warning"));

        var keyBox = new TextBox { Width = 290, Text = S.MalwareBazaarKey ?? "", ToolTip = "Clé d'accès (Auth-Key) abuse.ch" };
        keyBox.LostFocus += (_, _) => { S.MalwareBazaarKey = keyBox.Text.Trim(); _g.Save(); };
        var keyPanel = new StackPanel { Orientation = Orientation.Horizontal };
        keyPanel.Children.Add(keyBox);
        keyPanel.Children.Add(new Border { Width = 8 });
        keyPanel.Children.Add(UiKit.Button("Obtenir une clé", (_, _) => Open("https://auth.abuse.ch/"), "Btn.Ghost"));
        Rows.Children.Add(UiKit.Row("", "Clé d'accès MalwareBazaar (abuse.ch)",
            "Gratuite. Elle permet à SPIRUS de télécharger les empreintes des nouveaux logiciels malveillants repérés chaque jour dans le monde.", keyPanel, "Warning"));
        Rows.Children.Add(UiKit.Toggle("", "Mise à jour automatique",
            "Récupère les nouvelles empreintes deux fois par jour (nécessite la clé ci-dessus).",
            S.AutoUpdateSignatures, v => { S.AutoUpdateSignatures = v; _g.Save(); }, true, "Warning"));
        Rows.Children.Add(UiKit.Row("", "Importer une liste d'empreintes",
            "Fichier texte ou CSV contenant des empreintes SHA-256 (par exemple un export complet de MalwareBazaar).",
            UiKit.Button("Importer…", (_, _) => Import()), "Warning"));
        var customPanel = new StackPanel { Orientation = Orientation.Horizontal };
        customPanel.Children.Add(UiKit.Button("Ouvrir le dossier", (_, _) => Open(AppPaths.SignaturesDir)));
        customPanel.Children.Add(new Border { Width = 8 });
        customPanel.Children.Add(UiKit.Button("Recharger", (_, _) => { _g.ReloadSignatures(); Notifications.Info("Signatures rechargées", $"{_g.Engine.Rules.Rules.Count} règles actives." + (string.IsNullOrEmpty(_g.Engine.Rules.LoadWarning) ? "" : " " + _g.Engine.Rules.LoadWarning)); Refresh(); }));
        Rows.Children.Add(UiKit.Row("", "Règles personnalisées",
            "Ajoutez vos propres règles de détection dans « custom-rules.json » (même format que les règles intégrées).", customPanel, "Warning"));

        // ---------------------------------------------------------------- Exclusions
        Rows.Children.Add(UiKit.SectionTitle("Exclusions"));
        var addPanel = new StackPanel { Orientation = Orientation.Horizontal };
        addPanel.Children.Add(UiKit.Button("Dossier…", (_, _) => AddExclusion(true), "Btn.Secondary", ""));
        addPanel.Children.Add(new Border { Width = 8 });
        addPanel.Children.Add(UiKit.Button("Fichier…", (_, _) => AddExclusion(false), "Btn.Secondary", ""));
        Rows.Children.Add(UiKit.Row("", "Éléments exclus de l'analyse",
            S.Exclusions.Count == 0 ? "Aucune exclusion. N'excluez que des dossiers dont vous êtes sûr." : $"{S.Exclusions.Count} élément(s) ignoré(s) par toutes les analyses.", addPanel, "Info"));
        foreach (var ex in S.Exclusions.ToList())
        {
            var remove = UiKit.Button("Retirer", (_, _) => { S.Exclusions.Remove(ex); _g.ApplySettings(); Refresh(); }, "Btn.Ghost", "");
            var row = UiKit.Row(null, ex, null, remove);
            row.Margin = new Thickness(56, 0, 0, 8);
            Rows.Children.Add(row);
        }
        Rows.Children.Add(UiKit.Row("", "Fichiers autorisés",
            $"{S.AllowedHashes.Count} fichier(s) que vous avez explicitement autorisés ou restaurés ne sont plus signalés.",
            UiKit.Button("Réinitialiser", (_, _) => { S.AllowedHashes.Clear(); _g.ApplySettings(); Refresh(); }), "Info"));
        Rows.Children.Add(UiKit.Row("", "Taille maximale analysée",
            "Les fichiers plus volumineux (vidéos, images disque…) sont ignorés pour garder l'analyse rapide.",
            Stepper(Format.Size(S.MaxFileSizeMB * 1024L * 1024L),
                () => { S.MaxFileSizeMB = SizeSteps.LastOrDefault(x => x < S.MaxFileSizeMB, SizeSteps[0]); _g.ApplySettings(); },
                () => { S.MaxFileSizeMB = SizeSteps.FirstOrDefault(x => x > S.MaxFileSizeMB, SizeSteps[^1]); _g.ApplySettings(); }), "Info"));

        // ---------------------------------------------------------------- Outils
        Rows.Children.Add(UiKit.SectionTitle("Outils"));
        Rows.Children.Add(UiKit.Row("", "Tester la protection",
            "Crée dans Téléchargements un fichier de test totalement inoffensif : la protection en temps réel doit le neutraliser en quelques secondes.",
            UiKit.Button("Créer le fichier test", (_, _) => CreateTestFile(), "Btn.Primary")));
        Rows.Children.Add(UiKit.Row("", "Données de SPIRUS",
            "Réglages, journal, quarantaine chiffrée et signatures téléchargées.",
            UiKit.Button("Ouvrir le dossier", (_, _) => Open(AppPaths.DataDir))));

        // ---------------------------------------------------------------- Mises à jour
        Rows.Children.Add(UiKit.SectionTitle("Mises à jour"));
        var check = UiKit.Button("Rechercher une mise à jour", async (b, _) => await CheckUpdate((Button)b), "Btn.Secondary", "");
        Rows.Children.Add(UiKit.Row("", $"SPIRUS version {Updater.CurrentText}",
            $"Les nouvelles versions sont publiées sur GitHub ({Updater.Repository}). Dernière vérification : {Format.Ago(S.LastUpdateCheck).ToLowerInvariant()}.",
            check));
        Rows.Children.Add(UiKit.Toggle("", "Mises à jour automatiques",
            "SPIRUS vérifie les nouvelles versions toutes les 6 heures et les installe tout seul (empreinte SHA-256 vérifiée).",
            S.AutoUpdate, v => { S.AutoUpdate = v; _g.Save(); }));

        // ---------------------------------------------------------------- À propos
        Rows.Children.Add(UiKit.SectionTitle("À propos"));
        Rows.Children.Add(UiKit.Row("", $"SPIRUS Antivirus {Updater.CurrentText}",
            "Moteur multicouche : empreintes SHA-256, règles multi-motifs (Aho-Corasick), heuristiques des exécutables, analyse des archives et deuxième avis AMSI. "
            + "SPIRUS complète Microsoft Defender : gardez Defender activé.", null));

        Dispatcher.BeginInvoke(() => Scroller.ScrollToVerticalOffset(offset), System.Windows.Threading.DispatcherPriority.Loaded);
    }

    private async System.Threading.Tasks.Task CheckUpdate(Button button)
    {
        button.IsEnabled = false;
        var (info, error) = await _g.CheckForUpdateAsync();
        button.IsEnabled = true;
        if (error != null) { Notifications.Info("Vérification impossible", error, ToastKind.Warning); return; }
        if (info == null) { Notifications.Info("SPIRUS est à jour", $"Vous utilisez la dernière version ({Updater.CurrentText}).", ToastKind.Success); Refresh(); return; }
        new ToastWindow(ToastKind.Info, "", $"SPIRUS {info.Version.ToString(3)} est disponible",
            $"Vous avez la version {Updater.CurrentText}.", "SPIRUS redémarrera après l'installation.", 0,
            new ToastAction("Installer maintenant", () => { _ = _g.InstallUpdateAsync(info); return true; }, true),
            new ToastAction("Voir les nouveautés", () => { Open(info.PageUrl); return false; }),
            new ToastAction("Plus tard", () => true)).Present();
        Refresh();
    }

    private FrameworkElement Stepper(string value, Action minus, Action plus)
    {
        var panel = new StackPanel { Orientation = Orientation.Horizontal };
        panel.Children.Add(UiKit.Button("−", (_, _) => { minus(); Refresh(); }, "Btn.Secondary"));
        panel.Children.Add(new TextBlock { Text = value, MinWidth = 90, TextAlignment = TextAlignment.Center, VerticalAlignment = VerticalAlignment.Center, FontWeight = FontWeights.SemiBold, FontSize = 14 });
        panel.Children.Add(UiKit.Button("+", (_, _) => { plus(); Refresh(); }, "Btn.Secondary"));
        return panel;
    }

    private void Try(Action action)
    {
        try { action(); }
        catch (Exception ex) { Notifications.Info("Modification impossible", ex.Message, ToastKind.Danger); }
        Refresh();
    }

    private static void Open(string target)
    {
        try { Process.Start(new ProcessStartInfo(target) { UseShellExecute = true }); } catch { }
    }

    private void Import()
    {
        var dlg = new OpenFileDialog { Title = "Importer des empreintes SHA-256", Filter = "Listes d'empreintes (*.txt;*.csv)|*.txt;*.csv|Tous les fichiers|*.*" };
        if (dlg.ShowDialog(Window.GetWindow(this)) != true) return;
        var (added, total, error) = SignatureUpdater.ImportFile(dlg.FileName);
        if (error != null) { Notifications.Info("Importation impossible", error, ToastKind.Danger); return; }
        _g.ReloadSignatures();
        _g.Log.Add(LogLevel.Success, "Empreintes importées", $"{added:N0} nouvelles empreintes ({total:N0} au total).");
        Notifications.Info("Empreintes importées", $"{added:N0} nouvelles empreintes ({total:N0} au total).", ToastKind.Success);
        Refresh();
    }

    private void AddExclusion(bool folder)
    {
        string path = null;
        if (folder)
        {
            var dlg = new OpenFolderDialog { Title = "Dossier à exclure de l'analyse" };
            if (dlg.ShowDialog(Window.GetWindow(this)) == true) path = dlg.FolderName;
        }
        else
        {
            var dlg = new OpenFileDialog { Title = "Fichier à exclure de l'analyse" };
            if (dlg.ShowDialog(Window.GetWindow(this)) == true) path = dlg.FileName;
        }
        if (string.IsNullOrEmpty(path) || S.Exclusions.Contains(path, StringComparer.OrdinalIgnoreCase)) return;
        S.Exclusions.Add(path);
        _g.ApplySettings();
        _g.Log.Add(LogLevel.Info, "Exclusion ajoutée", path);
        Refresh();
    }

    private void CreateTestFile()
    {
        try
        {
            var path = Path.Combine(ScanTargets.DownloadsFolder(), $"spirus-test-{DateTime.Now:HHmmss}.txt");
            File.WriteAllText(path, SystemIntegration.TestFileContent());
            _g.Log.Add(LogLevel.Info, "Fichier de test créé", path);
            Notifications.Info("Fichier de test créé", _g.Settings.RealTimeEnabled
                ? "La protection en temps réel devrait le détecter dans quelques secondes."
                : "La protection en temps réel est désactivée : lancez une analyse pour le détecter.");
        }
        catch (Exception ex) { Notifications.Info("Création impossible", ex.Message, ToastKind.Danger); }
    }
}
