@echo off
setlocal
title Enterprise RAG System - Stopper
cd /d "%~dp0"

set "BACKEND_PORT=8010"
set "FRONTEND_PORT=5173"

echo ============================================================================
echo   MENGHENTIKAN LAYANAN ENTERPRISE RAG (PORT %BACKEND_PORT% ^& PORT %FRONTEND_PORT%)
echo ============================================================================

:: PENGAMAN: hanya hentikan proses backend_rust.exe / python.exe / node.exe pada port milik proyek.
:: Proses sistem (mis. svchost.exe) TIDAK akan pernah dihentikan.
call :stop_port %BACKEND_PORT% backend_rust.exe "Backend Rust API"
call :stop_port %BACKEND_PORT% python.exe "Backend Python API"
call :stop_port %FRONTEND_PORT% node.exe "Frontend UI"

:: Hentikan backend_rust.exe bila masih berjalan
taskkill /IM backend_rust.exe /F >nul 2>&1

:: Tutup jendela command prompt launcher jika masih terbuka
taskkill /FI "WINDOWTITLE eq Enterprise RAG - Backend Rust*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq Enterprise RAG - Backend API*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq Enterprise RAG - Frontend UI*" /F >nul 2>&1

echo.
echo [SELESAI] Seluruh layanan Enterprise RAG telah dihentikan.
pause
exit /b 0

:stop_port
:: %1 = port, %2 = nama image yang diizinkan, %3 = label
for /f "tokens=5" %%a in ('netstat -ano ^| findstr /R /C:":%~1 .*LISTENING"') do (
    tasklist /FI "PID eq %%a" /FI "IMAGENAME eq %~2" /NH | findstr /I "%~2" >nul
    if not errorlevel 1 (
        echo Menghentikan %~3 ^(%~2^) pada PID %%a...
        taskkill /F /PID %%a >nul 2>&1
    ) else (
        echo [LEWATI] PID %%a pada port %~1 bukan %~2 - tidak dihentikan.
    )
)
exit /b 0
