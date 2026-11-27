# Launcher of the EQ08 node for Windows (portable zip).
# - Data (SQLite, identidad.pfx, paquetes) lives in .\data next to the executable unless CC_Node__DataPath is set.
# - If CC_PFX_PASSWORD is not defined, it is requested without echo.
# - Opens the web interface in the default browser once the node is listening.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here
$Host.UI.RawUI.WindowTitle = 'Atalaya EQ08'

$env:ASPNETCORE_CONTENTROOT = $here
if (-not $env:CC_Node__DataPath) { $env:CC_Node__DataPath = Join-Path $here 'data' }

if (-not $env:CC_PFX_PASSWORD) {
    Write-Host 'Contraseña del certificado del nodo (identidad.pfx).'
    Write-Host 'Si es el primer inicio, se creará un certificado nuevo protegido con ella.'
    $secure = Read-Host -AsSecureString 'Contraseña'
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    if ([string]::IsNullOrEmpty($plain)) {
        Write-Host 'La contraseña no puede estar vacía.' -ForegroundColor Red
        Read-Host 'Pulsa Enter para salir' | Out-Null
        exit 1
    }
    $env:CC_PFX_PASSWORD = $plain
    Remove-Variable plain
}

$port = if ($env:CC_Node__HttpPort -and $env:CC_Node__HttpPort -ne '0') { [int]$env:CC_Node__HttpPort } else { 5008 }
$url = "http://localhost:$port/"
Write-Host "Datos: $($env:CC_Node__DataPath)"
Write-Host "Interfaz: $url  (Ctrl+C o cerrar esta ventana para detener)"

if ($env:CC_NO_BROWSER -ne '1') {
    # Background job: wait until the port answers, then open the browser.
    Start-Job -ArgumentList $port, $url -ScriptBlock {
        param($p, $u)
        for ($i = 0; $i -lt 60; $i++) {
            try { $c = New-Object Net.Sockets.TcpClient('127.0.0.1', $p); $c.Close(); Start-Process $u; return }
            catch { Start-Sleep -Seconds 1 }
        }
    } | Out-Null
}

& (Join-Path $here 'CentroCiber.Web.exe') @args
$code = $LASTEXITCODE
if ($code -ne 0) {
    Write-Host "El nodo terminó con código $code." -ForegroundColor Red
    Read-Host 'Pulsa Enter para salir' | Out-Null
}
exit $code
