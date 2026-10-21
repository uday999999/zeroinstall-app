package com.security.apkshield.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.security.apkshield.model.AppSecurityAuditItem

object StealthAndSpywareScanner {

    /**
     * Trusted official app stores and OEM system installers.
     */
    val TRUSTED_INSTALLERS = setOf(
        "com.android.vending",                  // Google Play Store
        "com.google.android.feedback",
        "com.sec.android.app.samsungapps",      // Samsung Galaxy Store
        "com.samsung.android.scloud",           // Samsung Cloud / Smart Switch restore
        "com.sec.android.easyMover",            // Samsung Smart Switch
        "com.sec.android.preloadinstaller",     // Samsung Official Preload Installer
        "com.aurora.store"
    )

    /**
     * Official OS, Google, and Samsung OEM modular service prefixes that legitimately run
     * without a launcher icon (e.g., Bixby Dictation, Google Verifier, Samsung TTS, Good Lock modules).
     */
    val VERIFIED_OEM_PREFIXES = listOf(
        "com.samsung.",
        "com.sec.android.",
        "com.osp.app.",
        "com.monotype.android.font.",
        "com.google.android.",
        "com.google.ar.",
        "com.android.",
        "android.",
        "androidx.",
        "com.qualcomm.",
        "com.qti."
    )

    private val HIGH_RISK_PERMISSIONS = mapOf(
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to "Accessibility Control",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" to "Notification Access",
        "android.permission.BIND_DEVICE_ADMIN" to "Device Admin Lock",
        "android.permission.READ_SMS" to "Read SMS Messages",
        "android.permission.RECEIVE_SMS" to "Receive SMS",
        "android.permission.SEND_SMS" to "Send SMS",
        "android.permission.READ_CALL_LOG" to "Read Call History",
        "android.permission.RECORD_AUDIO" to "Microphone Access",
        "android.permission.CAMERA" to "Camera Access",
        "android.permission.ACCESS_BACKGROUND_LOCATION" to "Background Location",
        "android.permission.SYSTEM_ALERT_WINDOW" to "Screen Overlay",
        "android.permission.REQUEST_INSTALL_PACKAGES" to "Install Unknown APKs"
    )

    private val KNOWN_STALKERWARE_AND_TRACKER_PACKAGES = listOf(
        "com.mspy", "com.flexispy", "com.hoverwatch", "com.cocospy",
        "com.spyzie", "com.cerberus", "com.XNSPY", "com.eyezy",
        "com.kidsguard", "com.spybubble", "com.thetruthspy", "com.highstermobile",
        "com.spyhuman", "com.pctattletale", "com.mobistealth", "com.copy9"
    )

    fun isVerifiedOemOrSystemPackage(pkgName: String, appInfo: ApplicationInfo): Boolean {
        val hasSystemFlag = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        val matchesOemPrefix = VERIFIED_OEM_PREFIXES.any { pkgName.startsWith(it, ignoreCase = true) }
        return hasSystemFlag || matchesOemPrefix
    }

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
            val isKnownSpyware = KNOWN_STALKERWARE_AND_TRACKER_PACKAGES.any {
                pkgName.contains(it, ignoreCase = true)
            }

            // Skip official Samsung, Google, and Android OS system services so legitimate modules
            // like Bixby Dictation or Google Developer Verifier are never falsely flagged.
            if (isVerifiedOemOrSystemPackage(pkgName, appInfo) && !isKnownSpyware) {
                continue
            }

            val rawLabel = try {
                pm.getApplicationLabel(appInfo).toString()
            } catch (_: Exception) {
                ""
            }

            val installer = getInstallerPackageNameCompat(pm, pkgName)
            val isFromTrustedStore = isInstalledFromTrustedStore(pm, pkgName)
            val hasLauncher = pm.getLaunchIntentForPackage(pkgName) != null
            val isSideloaded = !isFromTrustedStore

            val requestedPerms = pkgInfo.requestedPermissions?.toList() ?: emptyList()
            val reqFlags = pkgInfo.requestedPermissionsFlags
            val grantedDangerousPerms = mutableListOf<String>()

            if (reqFlags != null) {
                for (i in requestedPerms.indices) {
                    val perm = requestedPerms[i]
                    val isGranted = (reqFlags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                    if (isGranted) {
                        HIGH_RISK_PERMISSIONS[perm]?.let { friendly ->
                            if (friendly !in grantedDangerousPerms) grantedDangerousPerms.add(friendly)
                        }
                    }
                }
            }

            // Check special services (Accessibility / Notification Listener)
            var hasSpecialMonitoringService = false
            pkgInfo.services?.forEach { svc ->
                when (svc.permission) {
                    "android.permission.BIND_ACCESSIBILITY_SERVICE" -> {
                        hasSpecialMonitoringService = true
                        val label = "Accessibility Service"
                        if (label !in grantedDangerousPerms) grantedDangerousPerms.add(label)
                    }
                    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" -> {
                        hasSpecialMonitoringService = true
                        val label = "Notification Listener"
                        if (label !in grantedDangerousPerms) grantedDangerousPerms.add(label)
                    }
                }
            }

            val riskReasons = mutableListOf<String>()
            var riskScore = 0

            // 1. Known commercial spyware/stalkerware signature
            val matchedTrackers = mutableListOf<String>()
            if (isKnownSpyware) {
                riskScore += 95
                matchedTrackers.add("Known Spyware Signature ($pkgName)")
                riskReasons.add("Matches known stalkerware / monitoring package signature")
            }

            // 2. Hidden / Iconless App check:
            // Only flag an iconless app if it was sideloaded outside official stores OR has active monitoring services
            if (!hasLauncher && (isSideloaded || hasSpecialMonitoringService)) {
                riskScore += 55
                riskReasons.add("Hidden background app: Has no home screen icon")
            }

            // 3. Blank or zero-width stealth app name
            val cleanedLabel = rawLabel.replace(Regex("[\\s\\u200B\\u200C\\u200D\\uFEFF\\u3164]"), "")
            if (cleanedLabel.isEmpty() || rawLabel == pkgName) {
                riskScore += 35
                riskReasons.add("Uses a blank or hidden application name")
            }

            // 4. Sideloaded APK outside Google Play / Samsung Galaxy Store
            if (isSideloaded) {
                riskScore += 25
                riskReasons.add("Installed outside Google Play Store / Galaxy Store")
            }

            // 5. High-risk permission combination on a sideloaded or non-store app
            if (isSideloaded && grantedDangerousPerms.size >= 3) {
                riskScore += 25
                riskReasons.add("Sideloaded app with ${grantedDangerousPerms.size} sensitive permissions (${grantedDangerousPerms.take(3).joinToString(", ")})")
            } else if (hasSpecialMonitoringService && isSideloaded) {
                riskScore += 25
                riskReasons.add("Sideloaded app with background screen/notification monitoring")
            }

            val clampedScore = riskScore.coerceAtMost(100)
            results.add(
                AppSecurityAuditItem(
                    packageName = pkgName,
                    appName = cleanedLabel.ifEmpty { pkgName },
                    installerPackage = installer,
                    isSystemApp = false,
                    hasLauncherIcon = hasLauncher,
                    isSideloaded = isSideloaded,
                    dangerousPermissions = grantedDangerousPerms,
                    detectedTrackers = matchedTrackers,
                    riskScore = clampedScore,
                    riskReasons = riskReasons,
                    firstInstallTime = pkgInfo.firstInstallTime
                )
            )
        }

        return results.sortedByDescending { it.riskScore }
    }

    fun auditSinglePackage(context: Context, packageName: String): AppSecurityAuditItem? {
        return scanAllInstalledApps(context).find { it.packageName == packageName }
    }

    private fun isInstalledFromTrustedStore(pm: PackageManager, packageName: String): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val info = pm.getInstallSourceInfo(packageName)
                val sources = listOfNotNull(
                    info.installingPackageName,
                    info.initiatingPackageName,
                    info.originatingPackageName
                )
                sources.any { src ->
                    src in TRUSTED_INSTALLERS ||
                            src.startsWith("com.samsung.") ||
                            src.startsWith("com.sec.android.") ||
                            src.startsWith("com.google.android.")
                }
            } else {
                @Suppress("DEPRECATION")
                val src = pm.getInstallerPackageName(packageName)
                src != null && src in TRUSTED_INSTALLERS
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun getInstallerPackageNameCompat(pm: PackageManager, packageName: String): String? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val info = pm.getInstallSourceInfo(packageName)
                info.installingPackageName ?: info.initiatingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
        } catch (_: Exception) {
            null
        }
    }
}
