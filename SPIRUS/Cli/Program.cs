using System.Text;
using Vigie.Core;
using Vigie.Core.Engine;

Console.OutputEncoding = Encoding.UTF8;

if (args.Length == 0 || args[0] is "-h" or "--help" or "aide")
{
    Console.WriteLine("""
        SPIRUS Antivirus — analyseur en ligne de commande

          spirus-cli scan <fichier|dossier> [...]   Analyse les fichiers et dossiers indiqués
          spirus-cli quick                          Analyse rapide (zones à risque, démarrage, processus)
          spirus-cli test <dossier>                 Crée un fichier de test inoffensif détectable
          spirus-cli watch [secondes]               Protection en temps réel dans la console
          spirus-cli info                           Affiche l'état du moteur
          spirus-cli mem                            Diagnostic de la mémoire utilisée par le moteur
          spirus-cli update [--download]            Vérifie (et télécharge) la dernière version publiée

        Code de sortie : 0 = aucune menace, 1 = menace(s) trouvée(s), 2 = erreur.
        """);
    return 0;
}

var settings = SettingsStore.Load();
using var engine = new ScanEngine(() => settings);

switch (args[0].ToLowerInvariant())
{
    case "info":
        Console.WriteLine($"Règles      : {engine.Rules.Rules.Count} (version {engine.Rules.Version})");
        Console.WriteLine($"Motifs      : {engine.Rules.Patterns.Count} ({engine.Rules.Automaton.StateCount} états Aho-Corasick)");
        Console.WriteLine($"Empreintes  : {engine.Hashes.Count:N0}");
        Console.WriteLine($"AMSI        : {(engine.AmsiAvailable ? "disponible" : "indisponible")}");
        Console.WriteLine($"Données     : {AppPaths.DataDir}");
        return 0;

    case "test":
        var dir = args.Length > 1 ? args[1] : Environment.CurrentDirectory;
        var file = Path.Combine(dir, "spirus-test.txt");
        File.WriteAllText(file, SystemIntegration.TestFileContent());
        Console.WriteLine($"Fichier de test créé : {file}");
        return 0;

    case "scan":
    case "quick":
        var targets = args[0] == "quick" ? ScanTargets.Quick() : ScanTargets.Paths(args.Skip(1));
        if (targets.Count == 0) { Console.Error.WriteLine("Indiquez au moins un fichier ou dossier."); return 2; }
        var job = new ScanJob(engine, args[0] == "quick" ? ScanKind.Quick : ScanKind.Custom, targets);
        var printLock = new object();
        job.ThreatFound += r =>
        {
            lock (printLock)
            {
                Console.ForegroundColor = r.Verdict == Verdict.Malicious ? ConsoleColor.Red : ConsoleColor.Yellow;
                Console.WriteLine($"[{r.VerdictLabel.ToUpperInvariant()}] {r.ThreatName}  (score {r.Score}, {r.Engine})");
                Console.ResetColor();
                Console.WriteLine($"    {r.DisplayPath}");
                foreach (var reason in r.Reasons) Console.WriteLine($"    - {reason}");
            }
        };
        var summary = await job.RunAsync();
        Console.WriteLine();
        Console.WriteLine($"{summary.FilesScanned:N0} fichier(s) analysé(s) en {Format.Duration(summary.Duration)} — {summary.ThreatCount} menace(s), {summary.Errors} erreur(s).");
        return summary.ThreatCount > 0 ? 1 : 0;

    case "update":
        // Vérifie la dernière release GitHub ; avec --download, télécharge et contrôle l'installeur.
        Console.WriteLine($"Version installée : {Updater.CurrentText} — dépôt {Updater.Repository}");
        var update = await Updater.CheckAsync();
        if (update == null) { Console.WriteLine("SPIRUS est à jour."); return 0; }
        Console.WriteLine($"Nouvelle version : {update.Version.ToString(3)} ({update.Size / 1024:N0} Ko) — SHA-256 {update.Sha256 ?? "non publiée"}");
        if (args.Contains("--download")) Console.WriteLine($"Téléchargé et vérifié : {await Updater.DownloadAsync(update)}");
        return 0;

    case "mem":
        // Diagnostic : mémoire du moteur après l'analyse de tous les programmes en cours d'exécution.
        void Report(string step)
        {
            using var me = System.Diagnostics.Process.GetCurrentProcess();
            var gc = GC.GetGCMemoryInfo();
            Console.WriteLine($"{step,-28} tas .NET {GC.GetTotalMemory(false) / 1048576.0,6:0.0} Mo | engagé GC {gc.TotalCommittedBytes / 1048576.0,6:0.0} Mo | privé {me.PrivateMemorySize64 / 1048576.0,6:0.0} Mo | travail {me.WorkingSet64 / 1048576.0,6:0.0} Mo");
        }
        Report("Moteur chargé");
        foreach (var path in ScanTargets.RunningProcessImages()) engine.ScanFile(path);
        Report("Programmes analysés");
        MemoryTrim.Run();
        Report("Après nettoyage");
        return 0;

    case "watch":
        int seconds = args.Length > 1 && int.TryParse(args[1], out var n) ? n : 0;
        using (var monitor = new FileMonitor(engine, () => settings))
        {
            monitor.ThreatDetected += r => Console.WriteLine($"[TEMPS RÉEL] {r.VerdictLabel} : {r.ThreatName} — {r.DisplayPath}");
            monitor.RansomwareSuspected += (msg, folder) => Console.WriteLine($"[RANÇONGICIEL] {msg} Dossier : {folder}");
            monitor.Start();
            Console.WriteLine(seconds > 0 ? $"Surveillance en temps réel pendant {seconds} s…" : "Surveillance en temps réel (Ctrl+C pour arrêter)…");
            if (seconds > 0) await Task.Delay(TimeSpan.FromSeconds(seconds));
            else await Task.Delay(Timeout.Infinite);
            Console.WriteLine($"{monitor.FilesScanned} fichier(s) analysé(s) à la volée.");
        }
        return 0;

    default:
        Console.Error.WriteLine($"Commande inconnue : {args[0]}");
        return 2;
}
