# Publie une nouvelle version de SPIRUS pour tous les utilisateurs.
#   powershell -ExecutionPolicy Bypass -File SPIRUS\release.ps1 1.2.0
# Le script met à jour le numéro de version, enregistre les modifications et envoie
# l'étiquette v1.2.0 sur GitHub. GitHub Actions compile alors l'installeur et publie
# la release : les SPIRUS installés la téléchargent automatiquement dans les 6 heures.
param([Parameter(Mandatory = $true)][string]$Version)
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Version attendue au format 1.2.3" }
$repo = Split-Path $PSScriptRoot -Parent
Push-Location $repo
try {
    $props = Join-Path $PSScriptRoot 'Directory.Build.props'
    $text = [IO.File]::ReadAllText($props)
    $text = [regex]::Replace($text, '<Version>[^<]*</Version>', "<Version>$Version</Version>")
    [IO.File]::WriteAllText($props, $text, (New-Object System.Text.UTF8Encoding $false))

    git add -A
    git commit -m "SPIRUS $Version"
    git tag "v$Version"
    git push origin HEAD
    git push origin "v$Version"
    Write-Host "Version $Version envoyée. Suivi de la publication : gh run watch" -ForegroundColor Green
}
finally { Pop-Location }
