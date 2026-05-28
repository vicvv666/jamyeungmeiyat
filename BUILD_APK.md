# Android 原生 APK 構建指南

## 📱 項目位置
`E:/HermesFiles/jamyeungmeiyat-android/`

## 🏗 構建方式

### 1. debug APK（已簽名，可直接安裝）
```bash
cd /e/HermesFiles/jamyeungmeiyat-android
export JAVA_HOME="/c/Program Files/Eclipse Adoptium/jdk-21.0.11.10-hotspot"
export ANDROID_HOME="/c/Users/Administrator/AppData/Local/Android/Sdk"
export ANDROID_SDK_ROOT="/c/Users/Administrator/AppData/Local/Android/Sdk"
./gradlew assembleDebug
```
輸出：`app/build/outputs/apk/debug/app-debug.apk`

### 2. release APK（需要 Release Key）
```bash
./gradlew assembleRelease
```

## 🔧 項目結構
```
jamyeungmeiyat-android/
├── app/
│   ├── build.gradle           # Android 構建設定
│   ├── src/
│   │   └── main/
│   │       ├── AndroidManifest.xml
│   │       ├── assets/
│   │       │   └── www/       # 網頁靜態資源（index.html + CSS/JS/PNG）
│   │       ├── java/com/jamyeungmeiyat/app/
│   │       │   └── MainActivity.java
│   │       └── res/
│   │           ├── mipmap-*/  # App 圖標
│   │           ├── values/strings.xml
│   │           └── xml/network_security_config.xml
├── build.gradle
├── settings.gradle
└── gradle/wrapper/
```

## 🔗 JS Bridge API（`window.JymyNative`）
| 方法 | 說明 |
|------|------|
| `getServerUrl()` | 獲取已保存的服務器地址 |
| `setServerUrl(url)` | 保存服務器地址 |
| `showToast(msg)` | 顯示原生 Toast |
| `reload()` | 重新加載 WebView |

## ⚙ 技術細節
- 純 Android 原生 WebView（非 Cordova/Flutter）
- 所有靜態資源打包進 assets/www，啟動時從本地加載
- API 請求通過 JavaScript Bridge 配置的服務器地址
- 全屏沉浸式 + 暗黑模式自動跟隨系統
- 豎屏鎖定，適合社交打卡 App

## 🖼 App 圖標
當前使用 icon-512.png 作為圖標（所有密度共用）
如需專業圖標，請在 res/mipmap-* 目錄放置對應尺寸：
- mdpi: 48×48
- hdpi: 72×72
- xhdpi: 96×96
- xxhdpi: 144×144
- xxxhdpi: 192×192

## 📦 APK 輸出
當前 debug APK：`E:/Hermes/jamyeungmeiyat/jamyeungmeiyat.apk`（1.1MB）