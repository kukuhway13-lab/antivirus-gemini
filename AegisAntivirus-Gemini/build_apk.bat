@echo off
title Build Aegis Gemini Antivirus APK
echo =======================================================
echo   BUILDING AEGIS GEMINI ANTIVIRUS (.APK)
echo =======================================================
echo.

rem Cek apakah Java / JDK tersedia
if not defined JAVA_HOME (
    if exist "C:\Program Files\JetBrains\PyCharm 2025.1.1.1\jbr" (
        set "JAVA_HOME=C:\Program Files\JetBrains\PyCharm 2025.1.1.1\jbr"
        echo Menemukan JDK di: %JAVA_HOME%
    )
)

echo Memulai kompilasi APK dengan Gradle Wrapper...
call "%~dp0gradlew.bat" assembleDebug

if %ERRORLEVEL% equ 0 (
    echo.
    echo =======================================================
    echo [SUKSES] File APK berhasil dibuat!
    echo Lokasi: app\build\outputs\apk\debug\app-debug.apk
    echo =======================================================
    explorer "%~dp0app\build\outputs\apk\debug"
) else (
    echo.
    echo [CATATAN] Jika Anda belum menginstal Android SDK di komputer ini,
    echo silakan buka folder ini di Android Studio, atau gunakan GitHub Actions
    echo gratis untuk men-download file APK secara otomatis.
    echo Baca panduan di: PANDUAN_BUILD_APK.md
)
echo.
pause
