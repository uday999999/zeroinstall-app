package com.security.apkshield.scanner

import android.app.AppOpsManager
import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.TrafficStats
import android.os.Build
import android.os.Process

data class AppDataUsageReport(
    val packageName: String,
    val appName: String,
    val uid: Int,
    val hasLauncherIcon: Boolean,
    val isSystemApp: Boolean,
    val downloadedBytes: Long,       // Total RX (Download)
    val uploadedBytes: Long,         // Total TX (Upload)
    val backgroundUploadedBytes: Long, // Data uploaded silently in background
    val backgroundDownloadedBytes: Long,
    val foregroundTimeMs: Long,      // How long user actually opened the app
    val sensitiveDataAccessed: List<String>, // e.g. Contacts, SMS, Photos, Location, Mic
    val isSuspiciousExfiltration: Boolean,
    val exfiltrationWarning: String?
) {
    val totalBytes: Long get() = downloadedBytes + uploadedBytes

    val uploadRatioPercent: Int
        get() = if (totalBytes > 0) ((uploadedBytes * 100L) / totalBytes).toInt() else 0
}

object NetworkAndDataExfiltrationMonitor {

    private val SENSITIVE_DATA_PERMISSIONS = mapOf(
        "android.permission.READ_CONTACTS" to "Contacts",
        "android.permission.READ_SMS" to "SMS / OTPs",
        "android.permission.RECEIVE_SMS" to "Incoming SMS",
        "android.permission.READ_CALL_LOG" to "Call Logs",
        "android.permission.RECORD_AUDIO" to "Microphone Audio",
        "android.permission.CAMERA" to "Camera",
        "android.permission.ACCESS_FINE_LOCATION" to "Precise Location",
        "android.permission.ACCESS_BACKGROUND_LOCATION" to "Background Location",
        "android.permission.READ_EXTERNAL_STORAGE" to "Files & Photos",
        "android.permission.READ_MEDIA_IMAGES" to "Photos",
        "android.permission.READ_MEDIA_VIDEO" to "Videos"
    )

    /**
     * Checks if the user has granted Usage Access (`PACKAGE_USAGE_STATS`), which allows
     * querying per-app historical & background upload/download network statistics.
     */
    fun hasUsageStatsPermission(context: Context): Boolean {
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            appOps.unsafeCheckOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(),
                context.packageName
            )
        } else {
            @Suppress("DEPRECATION")
            appOps.checkOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(),
                context.packageName
            )
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    /**
     * Scans all installed apps and computes:
     * 1. Total Downloaded bytes (RX) and Uploaded bytes (TX) over the last 30 days (or since boot).
     * 2. Background Upload vs. Foreground Usage time.
     * 3. Which sensitive personal data (SMS, Contacts, Photos, Mic, Location) the app can take.
     * 4. Flags apps that are secretly uploading your data in the background ("Data Exfiltration").
     */
    fun analyzeAppDataAndUploads(context: Context): List<AppDataUsageReport> {
        val pm = context.packageManager
        val now = System.currentTimeMillis()
        val thirtyDaysAgo = now - (30L * 24 * 60 * 60 * 1000L)

        val hasUsagePerm = hasUsageStatsPermission(context)

        // 1. Collect per-UID network stats (Wi-Fi + Cellular, Foreground vs Background)
        val uidRxMap = mutableMapOf<Int, Long>()
        val uidTxMap = mutableMapOf<Int, Long>()
        val uidBgRxMap = mutableMapOf<Int, Long>()
        val uidBgTxMap = mutableMapOf<Int, Long>()

        if (hasUsagePerm) {
            collectNetworkStatsForType(
                context,
                ConnectivityManager.TYPE_WIFI,
                thirtyDaysAgo,
                now,
                uidRxMap,
                uidTxMap,
                uidBgRxMap,
                uidBgTxMap
            )
            collectNetworkStatsForType(
                context,
                ConnectivityManager.TYPE_MOBILE,
                thirtyDaysAgo,
                now,
                uidRxMap,
                uidTxMap,
                uidBgRxMap,
                uidBgTxMap
            )
        }

        // 2. Collect Foreground Screen Time per package so we can detect apps that upload data
        //    even though the user NEVER opens them!
        val foregroundTimeMap = mutableMapOf<String, Long>()
        if (hasUsagePerm) {
            try {
                val usm = context.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
                val stats = usm.queryUsageStats(UsageStatsManager.INTERVAL_MONTHLY, thirtyDaysAgo, now)
                stats?.forEach { u ->
                    foregroundTimeMap[u.packageName] =
                        (foregroundTimeMap[u.packageName] ?: 0L) + u.totalTimeInForeground
                }
            } catch (_: Exception) {
            }
        }

        // 3. Inspect installed packages
        val flags = PackageManager.GET_PERMISSIONS
        val packages: List<PackageInfo> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(flags)
        }

        val reports = mutableListOf<AppDataUsageReport>()

        for (pkgInfo in packages) {
            val appInfo = pkgInfo.applicationInfo ?: continue
            val pkgName = pkgInfo.packageName
            if (pkgName == context.packageName) continue

            val uid = appInfo.uid
            val isSystem = StealthAndSpywareScanner.isVerifiedOemOrSystemPackage(pkgName, appInfo)

            // Combine NetworkStatsManager data with TrafficStats fallback
            val trafficRx = TrafficStats.getUidRxBytes(uid).coerceAtLeast(0L)
            val trafficTx = TrafficStats.getUidTxBytes(uid).coerceAtLeast(0L)

            val rxBytes = maxOf(uidRxMap[uid] ?: 0L, trafficRx)
            val txBytes = maxOf(uidTxMap[uid] ?: 0L, trafficTx)
            val bgRxBytes = uidBgRxMap[uid] ?: 0L
            val bgTxBytes = uidBgTxMap[uid] ?: 0L

            // Check which sensitive personal data this app has permission to access
            val grantedSensitiveData = mutableListOf<String>()
            val reqPerms = pkgInfo.requestedPermissions
            val reqFlags = pkgInfo.requestedPermissionsFlags
            if (reqPerms != null && reqFlags != null) {
                for (i in reqPerms.indices) {
                    val permName = reqPerms[i]
                    val isGranted = (reqFlags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                    if (isGranted) {
                        SENSITIVE_DATA_PERMISSIONS[permName]?.let { label ->
                            if (label !in grantedSensitiveData) grantedSensitiveData.add(label)
                        }
                    }
                }
            }

            val hasLauncher = pm.getLaunchIntentForPackage(pkgName) != null
            val fgTimeMs = foregroundTimeMap[pkgName] ?: 0L

            // Detect Suspicious Data Exfiltration (Spyware / Tracker uploading user data)
            val warnings = mutableListOf<String>()

            // Rule A: App has uploaded > 1 MB in background while user barely/never opened it (< 1 min screen time)
            if (bgTxBytes > 1024 * 1024L && fgTimeMs < 60_000L && !isSystem) {
                warnings.add(
                    "Uploaded ${formatBytes(bgTxBytes)} in the background with almost zero screen time!"
                )
            }

            // Rule B: Abnormal Upload-heavy traffic (Upload > 40% of total traffic & > 2 MB uploaded)
            val total = rxBytes + txBytes
            if (txBytes > 2 * 1024 * 1024L && total > 0 && (txBytes * 100L / total) >= 40 && !isSystem) {
                warnings.add(
                    "Unusually high Upload ratio (${(txBytes * 100L / total)}% of traffic is outgoing upload)"
                )
            }

            // Rule C: Has access to sensitive data (SMS/Contacts/Mic/Photos) AND is uploading data in background
            if (grantedSensitiveData.isNotEmpty() && (txBytes > 500 * 1024L || bgTxBytes > 200 * 1024L) && !isSystem) {
                warnings.add(
                    "Accesses [${grantedSensitiveData.joinToString(", ")}] and has uploaded ${formatBytes(txBytes)}"
                )
            }

            // Rule D: Invisible / Iconless app using network data
            if (!hasLauncher && total > 0 && !isSystem) {
                warnings.add(
                    "👻 Invisible (no-icon) app transferring data in background!"
                )
            }

            // Skip system apps with 0 bytes unless they have warnings
            if (isSystem && total == 0L && warnings.isEmpty()) continue

            val label = try {
                pm.getApplicationLabel(appInfo).toString()
            } catch (_: Exception) {
                pkgName
            }

            reports.add(
                AppDataUsageReport(
                    packageName = pkgName,
                    appName = label,
                    uid = uid,
                    hasLauncherIcon = hasLauncher,
                    isSystemApp = isSystem,
                    downloadedBytes = rxBytes,
                    uploadedBytes = txBytes,
                    backgroundUploadedBytes = bgTxBytes,
                    backgroundDownloadedBytes = bgRxBytes,
                    foregroundTimeMs = fgTimeMs,
                    sensitiveDataAccessed = grantedSensitiveData,
                    isSuspiciousExfiltration = warnings.isNotEmpty(),
                    exfiltrationWarning = warnings.joinToString("\n• ", prefix = "• ").takeIf { warnings.isNotEmpty() }
                )
            )
        }

        // Sort so suspicious data-exfiltrating apps and top uploaders appear first
        return reports.sortedWith(
            compareByDescending<AppDataUsageReport> { it.isSuspiciousExfiltration }
                .thenByDescending { it.uploadedBytes }
                .thenByDescending { it.downloadedBytes }
        )
    }

    @Suppress("DEPRECATION")
    private fun collectNetworkStatsForType(
        context: Context,
        networkType: Int,
        startTime: Long,
        endTime: Long,
        uidRxMap: MutableMap<Int, Long>,
        uidTxMap: MutableMap<Int, Long>,
        uidBgRxMap: MutableMap<Int, Long>,
        uidBgTxMap: MutableMap<Int, Long>
    ) {
        try {
            val nsm = context.getSystemService(Context.NETWORK_STATS_SERVICE) as NetworkStatsManager
            val stats = nsm.querySummary(networkType, null, startTime, endTime)
            val bucket = NetworkStats.Bucket()
            while (stats.hasNextBucket()) {
                stats.getNextBucket(bucket)
                val uid = bucket.uid
                val rx = bucket.rxBytes.coerceAtLeast(0L)
                val tx = bucket.txBytes.coerceAtLeast(0L)
                uidRxMap[uid] = (uidRxMap[uid] ?: 0L) + rx
                uidTxMap[uid] = (uidTxMap[uid] ?: 0L) + tx

                // STATE_DEFAULT represents background network usage (when app is not in foreground)
                if (bucket.state == NetworkStats.Bucket.STATE_DEFAULT) {
                    uidBgRxMap[uid] = (uidBgRxMap[uid] ?: 0L) + rx
                    uidBgTxMap[uid] = (uidBgTxMap[uid] ?: 0L) + tx
                }
            }
            stats.close()
        } catch (_: Exception) {
        }
    }

    fun formatBytes(bytes: Long): String {
        if (bytes <= 0L) return "0 B"
        val kb = 1024.0
        val mb = kb * 1024.0
        val gb = mb * 1024.0
        return when {
            bytes >= gb -> String.format("%.2f GB", bytes / gb)
            bytes >= mb -> String.format("%.2f MB", bytes / mb)
            bytes >= kb -> String.format("%.1f KB", bytes / kb)
            else -> "$bytes B"
        }
    }
}
