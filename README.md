# SPIRUS Antivirus

Antivirus gratuit pour Windows 10 et 11 : protection en temps réel, surveillance des programmes, bouclier anti-rançongiciel, contrôle des clés USB, analyses à la demande et quarantaine, dans une interface noire et sobre.

## Télécharger

👉 **[Dernière version : SPIRUS-Setup.exe](https://github.com/plumeofficialent-lang/SPIRUS/releases/latest)**

1. Téléchargez `SPIRUS-Setup.exe` depuis la page ci-dessus.
2. Lancez-le et cliquez sur **Installer** (aucun droit administrateur nécessaire).
3. Si Windows affiche « Windows a protégé votre ordinateur », cliquez sur **Informations complémentaires**, puis **Exécuter quand même** (l'installeur n'est pas signé numériquement).

SPIRUS se met ensuite à jour tout seul : il vérifie les nouvelles versions toutes les 6 heures.

Il nécessite le runtime gratuit **.NET 10 Desktop** de Microsoft. Windows propose de le télécharger s'il manque.

SPIRUS complète Microsoft Defender, il ne le remplace pas : gardez Defender activé.

## Documentation

Le fonctionnement détaillé (moteur de détection, règles personnalisées, ligne de commande, limites) est décrit dans [SPIRUS/README.md](SPIRUS/README.md).

## Développement

| Action | Commande |
|---|---|
| Compiler l'installeur dans `dist/` | `powershell -ExecutionPolicy Bypass -File SPIRUS\build.ps1` |
| Publier une nouvelle version | `powershell -ExecutionPolicy Bypass -File SPIRUS\release.ps1 1.2.0` |

Publier une version envoie l'étiquette `v1.2.0` sur GitHub. GitHub Actions compile alors l'installeur et crée la release, que les SPIRUS installés téléchargent automatiquement. L'empreinte SHA-256 de l'installeur est vérifiée avant toute installation.
