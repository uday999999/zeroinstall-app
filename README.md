# APK Shield & Anti-Stealth Guard (Android)

A multi-layered Android security application designed to **stop unauthorized APK installations**, **intercept malicious links that drop hidden/background APKs or trackers**, **quarantine disguised `.apk` files**, and **detect invisible ("ghost") background spyware apps**.

---

## 6 Active Security Layers

1. **Real-Time APK Installer & "Unknown Sources" UI Interceptor (`ApkInstallBlockerAccessibilityService`)**
   - Monitors active windows across standard Android, Samsung OneUI, Xiaomi MIUI/HyperOS, Oppo/Realme ColorOS, and Vivo package installers.
   - Automatically clicks **"Cancel" / "Deny"** and navigates back within milliseconds if any app or link triggers an APK installation dialog or tries to open the **"Install Unknown Apps"** setting screen.
   - Inspects browser URL bars in real time to abort drive-by `.apk` downloads before they complete.

2. **Background Installation Session Interceptor (`ContinuousShieldMonitorService`)**
   - Hooks directly into Android's `PackageInstaller.SessionCallback` (`onCreated`, `onBadgingChanged`, `onActiveChanged`, `onProgressChanged`).
   - Detects **silent or background APK installation sessions** the instant a session is created—even before any UI appears—attempts to abandon the session, and triggers a full-screen Red Alert (`ThreatAlertActivity`).

3. **Magic-Byte Disguised APK Quarantine (`ContinuousShieldMonitorService`)**
   - Uses a real-time `FileObserver` on the device's `Download` folder.
   - Performs **binary magic-byte inspection (`PK\x03\x04` + `AndroidManifest.xml` / `classes.dex`)** on every newly downloaded file. Even if an attacker disguises an APK as `photo.jpg` or `invoice.pdf`, it is immediately caught, deleted/quarantined, and reported.

4. **WhatsApp / SMS / Telegram Link & APK Guard (`MessageLinkScannerNotificationService` & `LinkAndApkInterceptorActivity`)**
   - Scans incoming message notifications for `.apk` attachments, `intent://` package-installer exploits, raw IP servers, Punycode homographs, and ephemeral tunnels (`ngrok`, `trycloudflare`, `duckdns`, URL shorteners).
   - Performs **deep HTTP Header inspection** (`Content-Type: application/vnd.android.package-archive` and `Content-Disposition: attachment; filename="...apk"`) across redirect chains without executing the link in a browser.

5. **Invisible "Ghost App" & Stalkerware Scanner (`StealthAndSpywareScanner` + `PackageAndBootReceiver`)**
   - Detects stealth apps that install **with no Launcher Activity (`getLaunchIntentForPackage == null`)** or use zero-width invisible Unicode labels (`\u200B`, `\u3164`) to hide from the app drawer while running trackers in the background.
   - Flags sideloaded apps and dangerous spyware permission combinations (Accessibility + SMS/OTP reading + Microphone + Background Location).

6. **Local VPN Anti-Tracker Firewall & OS Kernel Lock (`TrackerBlockVpnService` & `ShieldDeviceAdminReceiver`)**
   - On-device loopback `VpnService` DNS sinkhole that blocks background connections to known stalkerware/spyware C2 domains (`mSpy`, `FlexiSpy`, `Hoverwatch`, `Cerberus`, etc.).
   - Supports **Device Admin** (to prevent malware from uninstalling APK Shield) and **Device Owner mode** (`UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES_GLOBALLY`) for an unbypassable OS-kernel block on all unknown APK installations.

---

## How to Build & Run

1. Open `/Users/uday/.gemini/antigravity/scratch/ApkShieldGuard` in **Android Studio**.
2. Connect your Android phone (Android 8.0 / API 26+) or start an emulator and click **Run (`app`)**.
3. In the **Shield** tab, enable the protection engines (Accessibility Blocker, Message Link Guard, VPN Tracker Firewall, and Device Admin).
4. Optional **OS-Kernel Hard Lock** via ADB (blocks even background session installs at the OS level):
   ```bash
   adb shell dpm set-device-owner com.security.apkshield/.receiver.ShieldDeviceAdminReceiver
   ```
