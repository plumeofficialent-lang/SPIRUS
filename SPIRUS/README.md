# SPIRUS Antivirus

Antivirus pour Windows 10/11 avec protection permanente en arrière-plan, analyse de fichiers et de dossiers, et interface moderne.

## Installation

1. Double-cliquez sur **`SPIRUS-Setup.exe`** (aucun droit administrateur requis).
2. Choisissez vos options :
   - démarrage avec Windows ;
   - « Analyser avec SPIRUS » dans le clic droit ;
   - raccourci sur le Bureau.
3. Cliquez sur **Installer**. SPIRUS est copié dans `%LocalAppData%\Programs\SPIRUS`, apparaît dans le menu Démarrer et dans **Paramètres → Applications installées**, puis se place près de l'horloge (icône bouclier).

Relancer l'installeur sur un PC où SPIRUS est déjà installé le met à jour en conservant vos réglages.

**Désinstaller** : Paramètres Windows → Applications → Applications installées → SPIRUS Antivirus → Désinstaller. Une option permet d'effacer aussi les réglages, le journal et la quarantaine.

**Sans interface** : `SPIRUS-Setup.exe --silent` installe avec les options par défaut ; `--uninstall --silent` désinstalle.

SPIRUS a besoin du runtime **.NET 10 Desktop** (gratuit, Microsoft), déjà présent sur cette machine. Sur un autre PC, Windows propose de le télécharger au premier lancement s'il manque.

## Fonctionnalités

| Module | Rôle |
|---|---|
| **Protection en temps réel** | Surveille tous les disques internes et analyse chaque fichier à risque dès qu'il est écrit (dans Téléchargements et sur le Bureau : tous les fichiers). |
| **Surveillance des programmes** | Vérifie chaque programme au moment où il démarre, ainsi que ceux déjà lancés. |
| **Bouclier anti-rançongiciel** | Repère le renommage ou le chiffrement massif de vos documents et les notes de rançon. Il désigne le programme qui écrit le plus et propose de l'arrêter. |
| **Contrôle USB** | Alerte à l'insertion d'une clé et l'analyse automatiquement. |
| **Analyses** | Rapide (zones à risque, démarrage, processus), complète (tous les disques), personnalisée (fichiers ou dossiers). On peut aussi glisser-déposer dans la fenêtre ou passer par le clic droit. Les analyses se mettent en pause et peuvent être planifiées chaque jour. |
| **Quarantaine** | Le fichier est chiffré, donc inoffensif, et peut être restauré ou supprimé. |
| **Journal** | Historique filtrable de tout ce que SPIRUS a fait. |

### Le moteur de détection, en couches

1. **Empreintes SHA-256** de logiciels malveillants connus (base compacte, recherche dichotomique).
2. **Règles comportementales** : 35 règles (rançongiciels, téléchargeurs PowerShell/VBS, raccourcis piégés, voleurs de mots de passe, keyloggers, mineurs, chevaux de Troie, contournement d'AMSI, macros Office, PDF piégés…). Tous les motifs sont recherchés en un seul passage grâce à un automate d'**Aho-Corasick**, en ASCII et en UTF-16.
3. **Heuristiques des exécutables** : analyse PE (sections compressées ou chiffrées, entropie, point d'entrée anormal, imports d'injection de code, *process hollowing*, keylogger, téléchargeur…).
4. **Heuristiques de leurre** : double extension (`facture.pdf.exe`), caractère d'inversion RTLO, programme déguisé en image, raccourci anormalement gros.
5. **Archives** : contenu des ZIP, documents Office et JAR, sur deux niveaux, avec protection contre les bombes de décompression.
6. **Deuxième avis AMSI** : les scripts et documents sont aussi soumis au moteur antivirus de Windows.
7. **Réduction des faux positifs** : les programmes et scripts signés par un éditeur de confiance (Authenticode) voient leur score fortement réduit, tout comme les gros scripts empaquetés (extensions d'éditeur, bibliothèques).
8. **Garde-fou** : un simple fichier de données (base d'une application, cache, journal) n'est jamais mis en quarantaine automatiquement. SPIRUS vous demande d'abord, sauf menace confirmée par empreinte ou par le moteur Windows.

Testé sur cette machine : System32 (20 447 fichiers en 8 s) et Program Files (154 660 fichiers en 4 min 25 s), **sans aucun faux positif** après réglage.

## Tester la protection

Dans **Paramètres → Outils**, cliquez sur **Créer le fichier test**. Un fichier inoffensif (l'équivalent maison du test EICAR) est déposé dans Téléchargements : la protection en temps réel doit le mettre en quarantaine en une à deux secondes.

## Mettre à jour les signatures

1. Créez une clé gratuite sur <https://auth.abuse.ch/>.
2. Collez-la dans **Paramètres → Signatures**.
3. SPIRUS télécharge alors deux fois par jour les empreintes des nouveaux logiciels malveillants repérés par MalwareBazaar.

Vous pouvez aussi importer n'importe quelle liste d'empreintes SHA-256 (fichier texte ou CSV).

### Règles personnalisées

Créez `%LocalAppData%\SPIRUS\Signatures\custom-rules.json` sur ce modèle, puis cliquez sur **Recharger** :

```json
{
  "rules": [
    {
      "id": "PERSO-001", "name": "Perso.MonaRegle", "category": "Script malveillant",
      "score": 80, "targets": ["script"], "desc": "Ce que la règle détecte.",
      "groups": [ { "of": ["motif un", "motif deux"] }, { "min": 2, "of": ["a", "b", "c"] } ],
      "exclude": ["motif qui annule la détection"]
    }
  ]
}
```

- Un fichier est détecté si **chaque groupe** a au moins `min` motifs présents (1 par défaut).
- Les motifs ne tiennent pas compte de la casse ; préfixez par `hex:` pour un motif binaire.
- Cibles possibles : `pe`, `script`, `lnk`, `office`, `pdf`, `archive`, `other`, `any`.
- Un score de 80 ou plus donne « Menace », de 50 à 79 « Suspect » (sensibilité normale).

## Ligne de commande

```
spirus-cli scan <fichier|dossier> [...]   analyse (code de sortie 1 si menace)
spirus-cli quick                          analyse rapide
spirus-cli watch [secondes]               protection temps réel dans la console
spirus-cli test <dossier>                 crée le fichier de test
spirus-cli info                           état du moteur
spirus-cli mem                            diagnostic mémoire du moteur
```

## Légèreté

SPIRUS est conçu pour tourner en permanence sans se faire remarquer :

- **Au démarrage de Windows**, aucune fenêtre n'est créée : environ 50 Mo de mémoire.
- **Une fois la fenêtre fermée**, elle est détruite et la mémoire de travail redescend autour de 50 Mo.
- **Pendant les analyses**, les tampons de lecture sont réutilisés d'un fichier à l'autre, et la mémoire est rendue au système dès que SPIRUS retourne au repos.

`SPIRUS.exe` accepte aussi `--background` (démarre dans la zone de notification) et `--scan "chemin"`.

## Limites à connaître

- SPIRUS fonctionne en mode utilisateur, sans pilote noyau. Il détecte un fichier **juste après** son écriture (environ 1 seconde) et un programme **juste après** son lancement, mais ne peut pas bloquer l'ouverture d'un fichier à l'avance comme le fait Microsoft Defender.
- Sans clé abuse.ch, la base d'empreintes est presque vide. La détection repose alors sur les règles, les heuristiques et AMSI.
- **SPIRUS complète Microsoft Defender, il ne le remplace pas** : gardez Defender activé.
- Pour neutraliser des menaces dans les dossiers système, relancez SPIRUS en administrateur (bouton sur le tableau de bord).

## Code source

```
SPIRUS/
  Core/   moteur : Engine/ (Aho-Corasick, PE, AMSI, Authenticode, analyses), Monitors.cs (temps réel,
          processus, USB, rançongiciels), Quarantine.cs, Guardian.cs (orchestration), Signatures/rules.json
  App/    interface WPF : MainWindow, Pages/ (tableau de bord, analyse, protection, quarantaine,
          journal, paramètres), notifications, icône de la zone de notification
  Cli/    outil en ligne de commande
  build.ps1  recompile tout dans ../dist
```

Les règles sont compressées et brouillées à la compilation : leurs motifs ne figurent pas en clair dans le programme, ce qui évite que les autres antivirus ne prennent SPIRUS pour une menace.
