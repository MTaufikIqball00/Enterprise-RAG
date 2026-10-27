@echo off
setlocal
title Enterprise RAG System - Launcher
cd /d "%~dp0"

:: Port backend. Port 8000 tidak dipakai karena pada mesin ini dipegang oleh
:: aturan Windows "netsh interface portproxy" (layanan IP Helper / iphlpsvc).
set "BACKEND_PORT=8010"
set "FRONTEND_PORT=5173"

echo ============================================================================
echo   ENTERPRISE RAG SYSTEM - ONE-CLICK LAUNCHER (WINDOWS)
echo   RBAC + Document ACL + Guardrails + Audit Logging + Evaluation
echo ============================================================================
echo.

:: 0. Pastikan port backend dan frontend belum dipakai proses lain
netstat -ano | findstr /R /C:":%BACKEND_PORT% .*LISTENING" >nul
if not errorlevel 1 (
    echo [ERROR] Port %BACKEND_PORT% sudah digunakan proses lain.
    echo         Jalankan stop_enterprise_rag.bat terlebih dahulu, atau periksa dengan:
    echo         netstat -ano ^| findstr :%BACKEND_PORT%
    pause
    exit /b 1
)
netstat -ano | findstr /R /C:":%FRONTEND_PORT% .*LISTENING" >nul
if not errorlevel 1 (
    echo [ERROR] Port %FRONTEND_PORT% sudah digunakan proses lain.
    echo         Jalankan stop_enterprise_rag.bat terlebih dahulu, atau periksa dengan:
    echo         netstat -ano ^| findstr :%FRONTEND_PORT%
    pause
    exit /b 1
)

:: 1. Pastikan file .env tersedia
if not exist ".env" (
    echo [1/4] Membuat file .env dari template .env.example...
    copy /Y ".env.example" ".env" >nul
) else (
    echo [1/4] File konfigurasi .env sudah tersedia.
)

:: 2. Pastikan binary Backend Rust sudah siap
echo [2/4] Memeriksa executable Backend Rust...
if not exist "backend_rust\target\release\backend_rust.exe" (
    if not exist "backend_rust\target\debug\backend_rust.exe" (
        echo       Binary belum ditemukan, melakukan kompilasi Rust...
        cargo build --manifest-path backend_rust\Cargo.toml
        if errorlevel 1 (
            echo [ERROR] Gagal mengompilasi backend Rust. Pastikan Rust toolchain terinstal.
            pause
            exit /b 1
        )
    )
)
echo       Binary Backend Rust siap digunakan.

:: 3. Periksa node_modules pada frontend
if not exist "frontend\node_modules" (
    echo [3/4] Menginstal dependency frontend React + Vite...
    call npm --prefix frontend install
    if errorlevel 1 (
        echo [ERROR] Gagal menginstal dependency frontend.
        pause
        exit /b 1
    )
) else (
    echo [3/4] Dependency frontend sudah terinstal.
)

:: 4. Jalankan Backend Rust dan Frontend Vite secara paralel
::    BACKEND_PORT diwariskan ke jendela frontend sehingga proxy Vite mengarah ke port yang sama.
if exist "backend_rust\target\release\backend_rust.exe" (
    echo [4/4] Menjalankan Backend Rust Release (Port %BACKEND_PORT%) dan Frontend React (Port %FRONTEND_PORT%)...
    start "Enterprise RAG - Backend Rust" cmd /k "cd /d "%~dp0" && backend_rust\target\release\backend_rust.exe"
) else (
    echo [4/4] Menjalankan Backend Rust Debug (Port %BACKEND_PORT%) dan Frontend React (Port %FRONTEND_PORT%)...
    start "Enterprise RAG - Backend Rust" cmd /k "cd /d "%~dp0" && backend_rust\target\debug\backend_rust.exe"
)
start "Enterprise RAG - Frontend UI" cmd /k "cd /d "%~dp0" && npm --prefix frontend run dev"

echo.
echo ============================================================================
echo   LAYANAN SEDANG DIJALANKAN (cek jendela Backend/Frontend bila ada error)
echo ----------------------------------------------------------------------------
echo   - Frontend Web UI  : http://localhost:%FRONTEND_PORT%
echo   - Backend REST API : http://127.0.0.1:%BACKEND_PORT%
echo   - Swagger OpenAPI  : http://127.0.0.1:%BACKEND_PORT%/docs
echo ----------------------------------------------------------------------------
echo   AKUN UJI SINTETIS (Password sesuai Role):
echo   1. Employee  : budi.employee  ^| EmpPass#2026!
echo   2. HR        : siti.hr        ^| HrPass#2026!
echo   3. Finance   : andi.finance   ^| FinPass#2026!
echo   4. Executive : dian.exec      ^| ExecPass#2026!
echo   5. Admin     : rudi.admin     ^| AdmPass#2026!
echo ============================================================================
echo.
echo Membuka browser ke http://localhost:%FRONTEND_PORT% dalam 5 detik...
timeout /t 5 /nobreak >nul
start "" "http://localhost:%FRONTEND_PORT%"

echo Untuk menghentikan seluruh layanan sekaligus, jalankan: stop_enterprise_rag.bat
pause
