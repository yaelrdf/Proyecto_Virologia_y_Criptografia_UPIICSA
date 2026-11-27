# Abre en el Firewall de Windows los puertos del nodo (§5.1 del estándar v2.0):
#   HTTP 5000+n (TCP), HTTPS 5100+n (TCP) y anuncio de descubrimiento 5099 (UDP).
# Ejecutar en PowerShell como Administrador:
#   .\scripts\firewall-windows.ps1 [-Team 8] [-Perfil Private] [-Quitar]
# Alternativa con netsh (equivalente):
#   netsh advfirewall firewall add rule name="CentroCiber HTTP EQ08" dir=in action=allow protocol=TCP localport=5008 profile=private
param(
    [int]$Team = 8,
    [ValidateSet("Private", "Domain", "Public", "Any")][string]$Perfil = "Private",
    [switch]$Quitar
)
$ErrorActionPreference = "Stop"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Ejecuta PowerShell como Administrador."
}

$id = "EQ{0:D2}" -f $Team
$reglas = @(
    @{ Nombre = "CentroCiber API HTTP $id";  Protocolo = "TCP"; Puerto = 5000 + $Team },
    @{ Nombre = "CentroCiber API HTTPS $id"; Protocolo = "TCP"; Puerto = 5100 + $Team },
    @{ Nombre = "CentroCiber Descubrimiento UDP 5099"; Protocolo = "UDP"; Puerto = 5099 }
)

foreach ($r in $reglas) {
    Get-NetFirewallRule -DisplayName $r.Nombre -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    if ($Quitar) { Write-Host "Quitada: $($r.Nombre)"; continue }
    New-NetFirewallRule -DisplayName $r.Nombre -Direction Inbound -Action Allow `
        -Protocol $r.Protocolo -LocalPort $r.Puerto -Profile $Perfil | Out-Null
    Write-Host "Permitido $($r.Protocolo)/$($r.Puerto) ($($r.Nombre)) en perfil $Perfil"
}

Write-Host "Verifica que la red Wi-Fi/Ethernet esté marcada como 'Privada' (Configuración > Red e Internet)."
