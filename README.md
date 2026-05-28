# 🍺 今晚飲咗未

> 飲酒社交打卡 App | 粵語本地化 | APK 可下載

---

## ✅ 所有 Fix 已完成

| 問題 | 狀態 |
|------|------|
| 收款碼冇顯示 | ✅ Fixed — `QR_MAP` 路徑修正 |
| 冇支付就升級 | ✅ Fixed — 先掃碼後升級流程 |
| 點用戶名自動登出 | ✅ Fixed — Dropdown 選單 |

---

## 📱 取得 APK（Android 安裝文件）

### 方法 A：Windows 一鍵打包（推薦）
**雙擊 `build_apk.bat`**（需先安裝 Java JDK）
→ 自動安裝 Cordova → Build APK → 簽名

### 方法 B：Android Studio 打包
用 Android Studio 打開 `android-project/` 文件夾
→ Build → Generate Signed APK
→ Keystore: `android.keystore` (密碼: vv111222, alias: jymy)

### 方法 C：PWABuilder.com 雲端生成
1. 部署網站到 HTTPS 伺服器
2. 打開 https://www.pwabuilder.com/
3. 輸入網址 → Android → Generate → 下載 APK

---

## 🍎 取得 iOS 安裝文件

### Safari「加入主畫面」（無需 App Store）
iPhone Safari 打開 `https://你的域名/` → 分享 → 加入主畫面
→ 桌面出現 🍺 App 圖標！

### iOS .ipa 打包
需要 macOS + Xcode + Apple Developer Account
打開 `ios-config.json` 配合 Capacitor 生成

---

## 🔑 Keystore 資訊

| 項目 | 值 |
|------|------|
| 文件 | `android.keystore` |
| 密碼 | `vv111222` |
| Alias | `jymy` |
| 有效 | 10000 天 |

---

## 🚀 快速啟動（Windows）

```batch
cd jamyeungmeiyat
pip install -r requirements.txt
python app.py
```

→ `http://localhost:5052/`

---

## 📁 項目結構

```
jamyeungmeiyat/
├── app.py              # Flask 後端
├── build_apk.bat       # Windows APK 打包腳本
├── android.keystore    # 簽名密鑰
├── requirements.txt    # 依賴
│
├── static/             # 前端文件
│   ├── index.html      # SPA 主程式
│   ├── manifest.json   # PWA
│   ├── sw.js           # Service Worker
│   ├── icon-192.png    # 小圖標
│   ├── icon-512.png    # 大圖標
│   └── qrcodes/        # 收款碼
│       ├── alipay.jpg
│       ├── wechat.png
│       └── paypal.jpg
│
├── android-project/    # Android Studio 項目（可導入）
├── ios-config.json     # iOS 打包配置
├── BUILD_APK.md        # 詳細打包教學
└── README.md
```

---

> 廣告合作：**vichoo2020@gmail.com**