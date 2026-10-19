package com.security.apkshield.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.security.apkshield.model.AppSecurityAuditItem

object StealthAndSpywareScanner {

    /**
     * Trusted official app stores. Anything else (Chrome, WhatsApp, Telegram, File Manager, null/ADB)
     * is flagged as a sideloaded APK source.
     */
    val TRUSTED_INSTALLERS = setOf(
        "com.android.vending",           // Google Play Store
        "com.google.android.feedback",
        "com.sec.android.app.samsungapps", // Samsung Galaxy Store
        "com.aurora.store"
    )

    private val HIGH_RISK_PERMISSIONS = mapOf(
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to "Accessibility Control (Can read screen & auto-click)",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" to "Notification Reader (Can intercept OTPs & messages)",
        "android.permission.BIND_DEVICE_ADMIN" to "Device Admin (Prevents normal uninstallation)",
        "android.permission.READ_SMS" to "Read SMS & OTP Messages",
        "android.permission.RECEIVE_SMS" to "Intercept Incoming SMS",
        "android.permission.SEND_SMS" to "Send SMS Silently",
        "android.permission.READ_CALL_LOG" to "Read Call History",
        "android.permission.PROCESS_OUTGOING_CALLS" to "Monitor Outgoing Calls",
        "android.permission.RECORD_AUDIO" to "Microphone Recording",
        "android.permission.CAMERA" to "Camera Access",
        "android.permission.ACCESS_BACKGROUND_LOCATION" to "24/7 Background Location Tracking",
        "android.permission.SYSTEM_ALERT_WINDOW" to "Draw Over Other Apps (Screen Overlay / Phishing)",
        "android.permission.REQUEST_INSTALL_PACKAGES" to "Install Other APK Files Silently",
        "android.permission.PACKAGE_USAGE_STATS" to "Track Which Apps You Use"
    )

    private val KNOWN_STALKERWARE_AND_TRACKER_PACKAGES = listOf(
        "com.mspy", "com.flexispy", "com.hoverwatch", "com.cocospy",
        "com.spyzie", "com.cerberus", "com.XNSPY", "com.eyezy",
        "com.kidsguard", "com.spybubble", "com.thetruthspy", "com.highstermobile",
        "com.spyhuman", "com.pctattletale", "com.mobistealth", "com.copy9"
    )

    /**
     * Scans all installed applications to uncover:
     * 1. Invisible / Iconless "Ghost Apps" running in the background without a launcher icon
     * 2. Apps with blank or zero-width stealth names
     * 3. Apps sideloaded via browsers, messaging apps, or unknown APK files
     * 4. Stalkerware / Background Trackers with dangerous spyware permissions
     */
    fun scanAllInstalledApps(context: Context): List<AppSecurityAuditItem> {
        val pm = context.packageManager
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS
        val packages: List<PackageInfo> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(flags)
        }

        val results = mutableListOf<AppSecurityAuditItem>()
        val myPackage = context.packageName

        for (pkgInfo in packages) {
            val pkgName = pkgInfo.packageName
            if (pkgName == myPackage) continue

            val appInfo = pkgInfo.applicationInfo ?: continue
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                    (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

            // Skip core Android OS packages unless they match known stalkerware
            if (isSystem && !KNOWN_STALKERWARE_AND_TRACKER_PACKAGES.any { pkgName.startsWith(it, ignoreCase = true) }) {
                continue
            }

            val rawLabel = try {
                pm.getApplicationLabel(appInfo).toString()
            } catch (_: Exception) {
                ""
            }

            val installer = getInstallerPackageNameCompat(pm, pkgName)
            val hasLauncher = pm.getLaunchIntentForPackage(pkgName) != null
            val isSideloaded = installer == null || installer !in TRUSTED_INSTALLERS

            val requestedPerms = pkgInfo.requestedPermissions?.toList() ?: emptyList()
            val dangerousPerms = mutableListOf<String>()
            for (perm in requestedPerms) {
                HIGH_RISK_PERMISSIONS[perm]?.let { friendly ->
                    dangerousPerms.add(friendly)
                }
            }

            // Check services/receivers for Accessibility or DeviceAdmin or NotificationListener declarations
            pkgInfo.services?.forEach { svc ->
                when (svc.permission) {
                    "android.permission.BIND_ACCESSIBILITY_SERVICE" -> {
                        val label = HIGH_RISK_PERMISSIONS["android.permission.BIND_ACCESSIBILITY_SERVICE"]!!
                        if (label !in dangerousPerms) dangerousPerms.add(label)
                    }
                    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" -> {
                        val label = HIGH_RISK_PERMISSIONS["android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"]!!
                        if (label !in dangerousPerms) dangerousPerms.add(label)
                    }
                }
            }

            val riskReasons = mutableListOf<String>()
            var riskScore = 0

            // Check 1: Invisible / Ghost App (No Launcher Icon!)
            if (!hasLauncher) {
                riskScore += 50
                riskReasons.add("👻 INVISIBLE APP: Has no Launcher icon (hides from app drawer to run silently in background)")
            }

            // Check 2: Blank or zero-width invisible app name
            val cleanedLabel = rawLabel.replace(Regex("[\\s\\u200B\\u200C\\u200D\\uFEFF\\u3164]"), "")
            if (cleanedLabel.isEmpty() || rawLabel == pkgName) {
                riskScore += 35
                riskReasons.add("🕵️ STEALTH LABEL: Uses a blank, invisible, or obfuscated application name")
            }

            // Check 3: Sideloaded APK outside official Play Store
            if (isSideloaded) {
                riskScore += 25
                val sourceDesc = installer ?: "Direct APK Sideload / Background Session"
                riskReasons.add("⚠️ SIDELOADED APK: Installed via '$sourceDesc' instead of Google Play Store")
            }

            // Check 4: Known stalkerware signature
            val matchedTrackers = mutableListOf<String>()
            if (KNOWN_STALKERWARE_AND_TRACKER_PACKAGES.any { pkgName.contains(it, ignoreCase = true) }) {
                riskScore += 95
                matchedTrackers.add("Known Stalkerware / Spyware Signature ($pkgName)")
                riskReasons.add("🚨 KNOWN SPYWARE: Matches known commercial stalkerware/tracker package signature")
            }

            // Check 5: High-risk spyware permission combinations
            if (dangerousPerms.size >= 3) {
                riskScore += 30
                riskReasons.add("🔓 EXCESSIVE SPY PERMISSIONS: Requests ${dangerousPerms.size} sensitive monitoring capabilities")
            } else if (dangerousPerms.isNotEmpty()) {
                riskScore += dangerousPerms.size * 10
            }

            val clampedScore = riskScore.coerceAtMost(100)
            results.add(
                AppSecurityAuditItem(
                    packageName = pkgName,
                    appName = cleanedLabel.ifEmpty { "(Invisible Name) $pkgName" },
                    installerPackage = installer,
                    isSystemApp = isSystem,
                    hasLauncherIcon = hasLauncher,
                    isSideloaded = isSideloaded,
                    dangerousPermissions = dangerousPerms,
                    detectedTrackers = matchedTrackers,
                    riskScore = clampedScore,
                    riskReasons = riskReasons,
                    firstInstallTime = pkgInfo.firstInstallTime
                )
            )
        }

        return results.sortedByDescending { it.riskScore }
    }

    /**
     * Inspects a single newly installed or updated package immediately when PACKAGE_ADDED fires.
     */
    fun auditSinglePackage(context: Context, packageName: String): AppSecurityAuditItem? {
        return scanAllInstalledApps(context).find { it.packageName == packageName }
    }

    private fun getInstallerPackageNameCompat(pm: PackageManager, packageName: String): String? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val info = pm.getInstallSourceInfo(packageName)
                info.initiatingPackageName ?: info.installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
        } catch (_: Exception) {
            null
        }
    }
}
