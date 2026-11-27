@echo off
rem Double-click launcher: runs iniciar-eq08.ps1 (asks for the certificate password and opens the browser).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0iniciar-eq08.ps1" %*
