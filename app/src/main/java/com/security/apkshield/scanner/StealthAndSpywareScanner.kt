package com.security.apkshield.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.os.Build
import com.security.apkshield.model.AppSecurityAuditItem

object StealthAndSpywareScanner {

    val TRUSTED_INSTALLERS = setOf(
        "com.android.vending",                  // Google Play Store
        "com.google.android.feedback",
        "com.sec.android.app.samsungapps",      // Samsung Galaxy Store
        "com.samsung.android.scloud",           // Samsung Cloud / Smart Switch
        "com.sec.android.easyMover",            // Samsung Smart Switch
        "com.sec.android.preloadinstaller",     // Samsung Preload Installer
        "com.aurora.store"
    )

    /**
     * Official OS, Google, Samsung, and preloaded OEM service prefixes.
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
        "com.qti.",
        "com.microsoft.appmanager"
    )

    /**
     * Clear, human-readable runtime permissions that users care about reviewing
     * (e.g., ChatGPT -> Camera, Microphone, Location).
     */
    private val SENSITIVE_RUNTIME_PERMISSIONS = linkedMapOf(
        "android.permission.CAMERA" to "Camera",
        "android.permission.RECORD_AUDIO" to "Microphone",
        "android.permission.ACCESS_FINE_LOCATION" to "Location",
        "android.permission.ACCESS_COARSE_LOCATION" to "Location",
        "android.permission.ACCESS_BACKGROUND_LOCATION" to "Background Location",
        "android.permission.READ_CONTACTS" to "Contacts",
        "android.permission.READ_SMS" to "SMS",
        "android.permission.RECEIVE_SMS" to "SMS",
        "android.permission.SEND_SMS" to "Send SMS",
        "android.permission.READ_CALL_LOG" to "Call Logs",
        "android.permission.READ_MEDIA_IMAGES" to "Photos & Media",
        "android.permission.READ_MEDIA_VIDEO" to "Photos & Media",
        "android.permission.READ_EXTERNAL_STORAGE" to "Files & Media"
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

            // Collect ONLY runtime permissions that the user has ACTUALLY granted to this app
            val requestedPerms = pkgInfo.requestedPermissions?.toList() ?: emptyList()
            val reqFlags = pkgInfo.requestedPermissionsFlags
            val grantedPerms = mutableListOf<String>()

            if (reqFlags != null) {
                for (i in requestedPerms.indices) {
                    val perm = requestedPerms[i]
                    val isGranted = (reqFlags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                    if (isGranted) {
                        SENSITIVE_RUNTIME_PERMISSIONS[perm]?.let { friendly ->
                            if (friendly !in grantedPerms) grantedPerms.add(friendly)
                        }
                    }
                }
            }

            val riskReasons = mutableListOf<String>()
            var riskScore = 0

            val matchedTrackers = mutableListOf<String>()
            if (isKnownSpyware) {
                riskScore += 95
                matchedTrackers.add("Known Spyware Signature ($pkgName)")
                riskReasons.add("Matches known stalkerware package signature")
            }

            if (!hasLauncher && isSideloaded) {
                riskScore += 60
                riskReasons.add("Hidden app: Installed outside Play Store with no home screen icon")
            }

            val cleanedLabel = rawLabel.replace(Regex("[\\s\\u200B\\u200C\\u200D\\uFEFF\\u3164]"), "")
            if (cleanedLabel.isEmpty() || rawLabel == pkgName) {
                riskScore += 35
                riskReasons.add("Uses a blank or hidden application name")
            }

            if (isSideloaded) {
                riskScore += 30
                riskReasons.add("Sideloaded outside Google Play / Galaxy Store")
            }

            // Give a mild review score based on how many sensitive permissions are currently active
            if (grantedPerms.isNotEmpty()) {
                riskScore += (grantedPerms.size * 8).coerceAtMost(40)
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
                    dangerousPermissions = grantedPerms,
                    detectedTrackers = matchedTrackers,
                    riskScore = clampedScore,
                    riskReasons = riskReasons,
                    firstInstallTime = pkgInfo.firstInstallTime
                )
            )
        }

        return results.sortedWith(
            compareByDescending<AppSecurityAuditItem> { it.isSideloaded && !it.hasLauncherIcon }
                .thenByDescending { it.dangerousPermissions.size }
                .thenBy { it.appName.lowercase() }
        )
    }

    fun auditSinglePackage(context: Context, packageName: String): AppSecurityAuditItem? {
        return scanAllInstalledApps(context).find { it.packageName == packageName }
    }

    private fun isInstalledFromTrustedStore(pm: PackageManager, packageName: String): Boolean {
        // Pre-installed Microsoft apps on Samsung devices (Excel, Office, OneDrive, Outlook)
        if (packageName.startsWith("com.microsoft.")) return true
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
