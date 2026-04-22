@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1
title MotunNet Pro v10.2

echo.
echo ========================================================
echo         MotunNet Pro v10.2 - Network Management
echo              Ultimate Network Management Suite
echo ========================================================
echo.

REM Python kontrolu
echo [*] Python kontrol ediliyor...
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python bulunamadi!
    echo.
    echo Python otomatik olarak kurulacak...
    echo.
    call :InstallPython
    if !errorlevel! neq 0 (
        echo [HATA] Python kurulamadi!
        echo Lutfen manuel olarak kurun: https://www.python.org/downloads/
        pause
        exit /b 1
    )
)

REM Python versiyonunu goster
echo [OK] Python bulundu:
python --version
echo.

REM Kutuphaneleri kontrol et ve kur
echo [*] Kutuphaneler kontrol ediliyor...

pip show PyQt6 >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] PyQt6 yukleniyor... (bu biraz zaman alabilir)
    pip install PyQt6 --quiet --disable-pip-version-check
)

pip show openpyxl >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] openpyxl yukleniyor...
    pip install openpyxl --quiet --disable-pip-version-check
)

pip show scapy >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] scapy yukleniyor...
    pip install scapy --quiet --disable-pip-version-check
)

echo [OK] Tum kutuphaneler hazir.
echo.
echo [*] MotunNet Pro baslatiliyor...
echo.

REM Uygulamayi baslat
python "%~dp0motunnet.py"

if %errorlevel% neq 0 (
    echo.
    echo [HATA] Uygulama hata ile sonlandi.
    pause
)
exit /b 0

REM ========== PYTHON KURULUM FONKSIYONU ==========
:InstallPython
echo.
echo ========================================================
echo            Python Otomatik Kurulum
echo ========================================================
echo.

REM Winget ile dene
echo [1/3] Winget ile kurulum deneniyor...
where winget >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Winget bulundu, Python kuruluyor...
    winget install Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
    if !errorlevel! equ 0 (
        echo [OK] Python winget ile kuruldu!
        echo [!] Bu pencereyi kapatin ve BAT dosyasini tekrar calistirin.
        pause
        exit /b 0
    )
)

REM Dogrudan indir
echo [2/3] Python indiriliyor...

set "TEMP_DIR=%TEMP%\python_install"
if not exist "%TEMP_DIR%" mkdir "%TEMP_DIR%"

set "PYTHON_URL=https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe"
set "PYTHON_INSTALLER=%TEMP_DIR%\python_installer.exe"

echo [*] Python 3.12 indiriliyor...

powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%PYTHON_URL%' -OutFile '%PYTHON_INSTALLER%' -UseBasicParsing}"

if not exist "%PYTHON_INSTALLER%" (
    echo [HATA] Python indirilemedi!
    exit /b 1
)

echo [3/3] Python kuruluyor...

"%PYTHON_INSTALLER%" /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1 Include_test=0

del "%PYTHON_INSTALLER%" >nul 2>&1

echo.
echo [OK] Python kuruldu! Bu pencereyi kapatin ve tekrar calistirin.
pause
exit /b 0
