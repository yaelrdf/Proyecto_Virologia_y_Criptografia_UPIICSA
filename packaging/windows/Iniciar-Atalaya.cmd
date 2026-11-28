@echo off
rem Lanzador del nodo Atalaya EQ08 (Windows). Los datos quedan en la carpeta "data" junto al programa.
setlocal
cd /d "%~dp0"
if "%CC_PFX_PASSWORD%"=="" (
  for /f "usebackq delims=" %%p in (`powershell -NoProfile -Command "$s = Read-Host 'Contraseña del certificado (CC_PFX_PASSWORD)' -AsSecureString; [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))"`) do set "CC_PFX_PASSWORD=%%p"
)
if "%CC_PFX_PASSWORD%"=="" (
  echo No se definio la contrasena del certificado. Cierra esta ventana e intentalo de nuevo.
  pause
  exit /b 1
)
echo Iniciando Atalaya EQ08 en http://localhost:5008 ...  (Ctrl+C para detener)
start "" "http://localhost:5008"
CentroCiber.Web.exe %*
endlocal
