using System;
using System.Diagnostics;
using System.IO;
using Vigie.Core;

namespace Vigie.App;

/// <summary>Traduit les événements de SPIRUS en notifications à l'écran.</summary>
public static class Notifications
{
    private static Guardian G => App.Guardian;

    public static void ShowThreat(ThreatAlert a)
    {
        if (a.IsRansomware) { ShowRansomware(a); return; }
        var r = a.Result;
        string file = Path.GetFileName(r.Path);
        string where = a.Pid != null ? $"Programme en cours d'exécution : {a.ProcessName}" : r.DisplayPath;

        if (a.Handled)
        {
            if (!G.Settings.Notifications) return;
            new ToastWindow(ToastKind.Success, "", "Menace neutralisée",
                $"{r.ThreatName} a été mise en quarantaine.", where, 12,
                new ToastAction("Voir la quarantaine", () => { App.Instance.ShowMain("quarantine"); return true; }),
                new ToastAction("OK", () => true)).Present();
            return;
        }

        bool malicious = r.Verdict == Verdict.Malicious;
        ToastWindow toast = null;
        toast = new ToastWindow(malicious ? ToastKind.Danger : ToastKind.Warning, "",
            malicious ? "Menace détectée" : "Fichier suspect détecté",
            $"{r.ThreatName} — {file}",
            r.Reasons.Count > 0 ? r.Reasons[0] : where, 0,
            new ToastAction("Mettre en quarantaine", () =>
            {
                if (G.QuarantineThreat(r, out var err))
                {
                    Info("Menace neutralisée", $"{file} a été mis en quarantaine.", ToastKind.Success);
                    return true;
                }
                toast.ShowError(err);
                return false;
            }, true),
            new ToastAction("Autoriser", () => { G.AllowFile(r); return true; }),
            new ToastAction("Ignorer", () => true));
        if (!string.IsNullOrEmpty(a.Error)) toast.ShowError("Mise en quarantaine automatique impossible : " + a.Error);
        toast.Present();
    }

    private static void ShowRansomware(ThreatAlert a)
    {
        var detail = $"Dossier : {a.Folder}";
        if (a.Suspect is { } s) detail += $"\nProcessus suspect : {s.Name} (PID {s.Pid})";
        var actions = new System.Collections.Generic.List<ToastAction>();
        if (a.Suspect is { } sp)
            actions.Add(new ToastAction($"Arrêter {sp.Name}", () =>
            {
                try { using var p = Process.GetProcessById(sp.Pid); p.Kill(true); } catch { }
                G.Log.Add(LogLevel.Success, "Processus suspect arrêté", $"{sp.Name} (PID {sp.Pid}) {sp.Path}");
                if (!string.IsNullOrEmpty(sp.Path) && File.Exists(sp.Path))
                {
                    var r = G.Engine.ScanFile(sp.Path, useCache: false);
                    if (!r.IsThreat) { r.ThreatName = "Rançongiciel.Comportement"; r.Category = "Rançongiciel"; r.Verdict = Verdict.Suspicious; }
                    G.QuarantineThreat(r, out _);
                }
                Info("Processus arrêté", $"{sp.Name} a été arrêté et mis en quarantaine.", ToastKind.Success);
                return true;
            }, true));
        actions.Add(new ToastAction("Analyse rapide", () => { App.Instance.StartQuickScan(); return true; }, a.Suspect == null));
        actions.Add(new ToastAction("Ignorer", () => true));
        new ToastWindow(ToastKind.Danger, "", "Attaque de rançongiciel suspectée !", a.Message, detail, 0, actions.ToArray()).Present();
    }

    public static void ShowUsb(DriveInfo drive)
    {
        if (!G.Settings.Notifications) return;
        string label;
        try { label = string.IsNullOrEmpty(drive.VolumeLabel) ? drive.Name : $"{drive.VolumeLabel} ({drive.Name.TrimEnd('\\')})"; }
        catch { label = drive.Name; }
        bool auto = G.Settings.UsbAutoScan && G.CurrentJob?.Kind == ScanKind.Usb;
        new ToastWindow(ToastKind.Info, "", "Périphérique USB détecté", label,
            auto ? "Analyse automatique en cours…" : "Voulez-vous l'analyser ?", 10,
            auto
                ? new[] { new ToastAction("Voir l'analyse", () => { App.Instance.ShowMain("scan"); return true; }) }
                : new[] { new ToastAction("Analyser", () => { App.Instance.ScanPaths(new[] { drive.RootDirectory.FullName }); return true; }, true) }
        ).Present();
    }

    public static void ShowScanSummary(ScanSummary s)
    {
        if (!G.Settings.Notifications && s.ThreatCount == 0) return;
        var title = $"{Guardian.KindLabel(s.Kind)} {(s.Cancelled ? "interrompue" : "terminée")}";
        var msg = s.ThreatCount == 0 ? "Aucune menace trouvée." : $"{s.ThreatCount} menace(s) trouvée(s).";
        new ToastWindow(s.ThreatCount == 0 ? ToastKind.Success : ToastKind.Warning, s.ThreatCount == 0 ? "" : "",
            title, msg, $"{s.FilesScanned:N0} fichiers analysés en {Format.Duration(s.Duration)}", 10,
            new ToastAction("Voir le rapport", () => { App.Instance.ShowMain("scan"); return true; })).Present();
    }

    public static void Info(string title, string message, ToastKind kind = ToastKind.Info)
    {
        var glyph = kind switch { ToastKind.Success => "", ToastKind.Danger or ToastKind.Warning => "", _ => "" };
        new ToastWindow(kind, glyph, title, message, null, 6).Present();
    }

    public static void CloseAll() => ToastWindow.CloseAll();
}
