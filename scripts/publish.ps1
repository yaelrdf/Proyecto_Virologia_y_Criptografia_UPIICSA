# Publica el nodo como aplicación autocontenida.  .\scripts\publish.ps1 [-Rid win-x64|linux-x64|todos]
param([ValidateSet("win-x64", "linux-x64", "todos")][string]$Rid = "todos")
$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$rids = if ($Rid -eq "todos") { @("win-x64", "linux-x64") } else { @($Rid) }
foreach ($r in $rids) {
    Write-Host "[publicar] $r"
    $out = Join-Path $root "publish\$r"
    dotnet publish (Join-Path $root "src\CentroCiber.Web\CentroCiber.Web.csproj") -c Release -r $r --self-contained true -p:PublishSingleFile=false -o $out
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish falló para $r" }
    Compress-Archive -Path $out -DestinationPath (Join-Path $root "publish\centrociber-eq08-$r.zip") -Force
    Write-Host "[publicar] listo: $out"
}
