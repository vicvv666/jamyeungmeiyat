@echo off
chcp 65001 >nul
echo.
echo ╔══════════════════════════════════╗
echo ║   今晚飲咗未 APK Builder       ║
echo ║   Jam Yeung Mei Yat v1.0        ║
echo ╚══════════════════════════════════╝
echo.

REM === Check Java ===
java -version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Java 未安裝！
    echo 請到 https://adoptium.net/ 下載安裝 Java 17+
    pause
    exit /b 1
)
echo [OK] Java found

REM === Check Node ===
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js 未安裝！
    echo 請到 https://nodejs.org/ 下載安裝 Node.js
    pause
    exit /b 1
)
echo [OK] Node.js found

REM === Install Cordova ===
where cordova >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] 安裝 Cordova...
    npm install -g cordova
    if %errorlevel% neq 0 (
        echo [ERROR] Cordova 安裝失敗
        pause
        exit /b 1
    )
)
echo [OK] Cordova ready

REM === Environment Setup ===
echo [INFO] 設定 Android SDK...
set ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk
set PATH=%ANDROID_HOME%\cmdline-tools\latest\bin;%ANDROID_HOME%\platform-tools;%PATH%

REM Check Android SDK
call sdkmanager --list >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Android SDK 未完整安裝
    echo 請安裝 Android Studio: https://developer.android.com/studio
    echo 或運行: sdkmanager "platforms;android-34" "build-tools;34.0.0"
)

REM === Build APK ===
cd /d "%~dp0cordova-project"

echo.
echo [BUILD] 開始生成 APK...
call cordova build android --release

if %errorlevel% neq 0 (
    echo [ERROR] APK 生成失敗
    echo 請確保已安裝 Android SDK 並設置 ANDROID_HOME
    pause
    exit /b 1
)

REM === Sign APK ===
echo [SIGN] 簽名 APK...
set APK_PATH=platforms\android\app\build\outputs\apk\release\app-release-unsigned.apk
set KEYSTORE=%~dp0android.keystore

if exist "%APK_PATH%" (
    echo [SUCCESS] APK 生成成功！
    echo 位置: %cd%\%APK_PATH%
    echo.
    echo 若要簽名，請運行:
    echo   apksigner sign --ks %KEYSTORE% --ks-pass pass:vv111222 %APK_PATH%
    echo.
) else (
    echo [ERROR] APK 文件未找到
)

echo.
echo ============================================
echo   APK 生成完成
echo ============================================
echo.
echo 簽名密鑰: android.keystore (密碼: vv111222)
echo.
pause