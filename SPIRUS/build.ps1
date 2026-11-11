# Compile SPIRUS et produit l'installeur dist\SPIRUS-Setup.exe.
#   powershell -ExecutionPolicy Bypass -File build.ps1 [-Version 1.2.0]
param([string]$Version)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$dist = Join-Path (Split-Path $root -Parent) 'dist'
$payload = Join-Path ([IO.Path]::GetTempPath()) 'spirus-payload'

foreach ($dir in $dist, $payload) {
    if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
    New-Item -ItemType Directory -Force $dir | Out-Null
}

$common = @('-c', 'Release', '-r', 'win-x64', '--self-contained', 'false', '-p:PublishSingleFile=true', '-p:DebugType=none', '-nologo', '-v', 'q')
if ($Version) { $common += "-p:Version=$Version" }

# 1. L'application et l'outil en ligne de commande
dotnet publish (Join-Path $root 'App\App.csproj') @common -o $payload
if ($LASTEXITCODE -ne 0) { throw "Échec de la compilation de l'application." }
dotnet publish (Join-Path $root 'Cli\Cli.csproj') @common -o $payload
if ($LASTEXITCODE -ne 0) { throw "Échec de la compilation de l'outil en ligne de commande." }

# 2. L'installeur, qui embarque les deux programmes
dotnet publish (Join-Path $root 'Setup\Setup.csproj') @common "-p:PayloadDir=$payload" -o $dist
if ($LASTEXITCODE -ne 0) { throw "Échec de la compilation de l'installeur." }

Copy-Item (Join-Path $root 'README.md') $dist -Force
Remove-Item $payload -Recurse -Force
Write-Host "Installeur prêt : $(Join-Path $dist 'SPIRUS-Setup.exe')" -ForegroundColor Green
