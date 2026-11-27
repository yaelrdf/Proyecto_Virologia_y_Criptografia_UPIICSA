# Levanta dos nodos locales para la demo en Windows: EQ08 (5008/5108) y EQ09 (5009/5109).
# Uso:  $env:CC_PFX_PASSWORD = "<contraseña>"; .\scripts\run-two-nodes.ps1 [-Data .\data\demo]
param([string]$Data = (Join-Path $PSScriptRoot "..\data\demo"))
$ErrorActionPreference = "Stop"
if (-not $env:CC_PFX_PASSWORD) { throw "Define `$env:CC_PFX_PASSWORD con la contraseña de los PFX de prueba." }

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Write-Host "[demo] Compilando..."
dotnet build (Join-Path $root "src\CentroCiber.Web") -c Release -v quiet -nologo | Out-Null
$dll = Join-Path $root "src\CentroCiber.Web\bin\Release\net10.0\CentroCiber.Web.dll"
$content = Join-Path $root "src\CentroCiber.Web"

function Start-Node([int]$team, [int]$http, [int]$https) {
    $id = "EQ{0:D2}" -f $team
    $env:CC_Node__TeamNumber = "$team"
    $env:CC_Node__HttpPort = "$http"
    $env:CC_Node__HttpsPort = "$https"
    $env:CC_Node__DataPath = (Join-Path $Data $id)
    $env:ASPNETCORE_ENVIRONMENT = "Development"
    Start-Process dotnet -ArgumentList "`"$dll`" --contentRoot `"$content`"" -PassThru -NoNewWindow
}

$a = Start-Node 8 5008 5108
$b = Start-Node 9 5009 5109
Write-Host "[demo] EQ08 -> http://localhost:5008   EQ09 -> http://localhost:5009"
Write-Host "[demo] Presiona Enter para detener ambos nodos."
[void][Console]::ReadLine()
Stop-Process -Id $a.Id, $b.Id -ErrorAction SilentlyContinue
