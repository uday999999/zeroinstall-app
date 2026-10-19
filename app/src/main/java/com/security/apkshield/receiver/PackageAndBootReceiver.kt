package com.security.apkshield.receiver

import android.app.DownloadManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.security.apkshield.data.PeopleProtectionTools
import com.security.apkshield.data.ShieldRepository
import com.security.apkshield.model.Severity
import com.security.apkshield.model.ThreatType
import com.security.apkshield.scanner.StealthAndSpywareScanner
import com.security.apkshield.service.ContinuousShieldMonitorService
import java.util.Locale

class PackageAndBootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        ShieldRepository.init(context.applicationContext)

        when (action) {
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_LOCKED_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED -> {
                ContinuousShieldMonitorService.start(context.applicationContext)
            }

            // Google Play Store-compliant Download inspection via DownloadManager
            DownloadManager.ACTION_DOWNLOAD_COMPLETE -> {
                val downloadId = intent.getLongExtra(DownloadManager.EXTRA_DOWNLOAD_ID, -1L)
                if (downloadId != -1L) {
                    inspectCompletedDownload(context, downloadId)
                }
            }

            Intent.ACTION_PACKAGE_ADDED,
            Intent.ACTION_PACKAGE_REPLACED -> {
                val pkgName = intent.data?.schemeSpecificPart ?: return
                if (pkgName == context.packageName) return

                // 0. Check if a Remote-Access / Screen-Share Scam App (AnyDesk, TeamViewer, RustDesk) was installed
                val remoteScamApps = PeopleProtectionTools.detectRemoteAccessScamApps(context)
                val matchedRemote = remoteScamApps.find { it.packageName == pkgName }
                if (matchedRemote != null) {
                    ShieldRepository.recordAndAlertThreat(
                        context = context.applicationContext,
                        type = ThreatType.APK_INSTALL_BLOCKED,
                        severity = Severity.CRITICAL,
                        sourcePackageOrUrl = "${matchedRemote.appName} ($pkgName)",
                        title = "🚨 Remote Screen-Share Scam Alert!",
                        description = "'${matchedRemote.appName}' was just installed.\n\n⚠️ ${matchedRemote.dangerExplanation}\n\nIf a caller asked you to install this app, HANG UP IMMEDIATELY and uninstall it!",
                        actionTaken = "Triggered Anti-Bank-Scam Emergency Alert",
                        canUninstallPackage = pkgName,
                        showFullScreenPopup = true
                    )
                    return
                }

                val audit = StealthAndSpywareScanner.auditSinglePackage(context, pkgName) ?: return

                // 1. Check if the newly installed app is an INVISIBLE / ICONLESS Ghost App!
                if (!audit.hasLauncherIcon && ShieldRepository.isDetectInvisibleAppsEnabled(context)) {
                    ShieldRepository.recordAndAlertThreat(
                        context = context.applicationContext,
                        type = ThreatType.STEALTH_GHOST_APP_DETECTED,
                        severity = Severity.CRITICAL,
                        sourcePackageOrUrl = "${audit.appName} ($pkgName) | Installer: ${audit.installerPackage ?: "Unknown APK"}",
                        title = "👻 Invisible Background App Installed!",
                        description = "A stealth application '${audit.appName}' ($pkgName) was just installed WITH NO APP ICON so it can hide in the background!\n\n" +
                                audit.riskReasons.joinToString("\n• ", prefix = "• "),
                        actionTaken = "Flagged for Immediate Removal",
                        canUninstallPackage = pkgName,
                        showFullScreenPopup = true
                    )
                    return
                }

                // 2. Check if it was sideloaded outside Google Play Store or has spyware permissions
                if (audit.isSideloaded || audit.riskScore >= 50) {
                    ShieldRepository.recordAndAlertThreat(
                        context = context.applicationContext,
                        type = if (audit.detectedTrackers.isNotEmpty()) {
                            ThreatType.TRACKER_SPYWARE_DETECTED
                        } else {
                            ThreatType.APK_INSTALL_BLOCKED
                        },
                        severity = Severity.CRITICAL,
                        sourcePackageOrUrl = "${audit.appName} ($pkgName)",
                        title = "⚠️ High-Risk / Sideloaded App Detected!",
                        description = "Package '${audit.appName}' ($pkgName) was installed from '${audit.installerPackage ?: "Unknown APK"}' with Risk Score ${audit.riskScore}/100:\n\n" +
                                audit.riskReasons.joinToString("\n• ", prefix = "• "),
                        actionTaken = "Prompted Immediate Uninstall",
                        canUninstallPackage = pkgName,
                        showFullScreenPopup = true
                    )
                }
            }
        }
    }

    private fun inspectCompletedDownload(context: Context, downloadId: Long) {
        try {
            val dm = context.getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager
            val query = DownloadManager.Query().setFilterById(downloadId)
            dm.query(query)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val titleIdx = cursor.getColumnIndex(DownloadManager.COLUMN_TITLE)
                    val mimeIdx = cursor.getColumnIndex(DownloadManager.COLUMN_MEDIA_TYPE)
                    val uriIdx = cursor.getColumnIndex(DownloadManager.COLUMN_URI)

                    val title = if (titleIdx >= 0) cursor.getString(titleIdx) ?: "" else ""
                    val mime = if (mimeIdx >= 0) cursor.getString(mimeIdx) ?: "" else ""
                    val sourceUrl = if (uriIdx >= 0) cursor.getString(uriIdx) ?: "" else ""

                    val lowerTitle = title.lowercase(Locale.ROOT)
                    val lowerMime = mime.lowercase(Locale.ROOT)

                    if (lowerMime.contains("application/vnd.android.package-archive") ||
                        lowerTitle.endsWith(".apk") ||
                        lowerTitle.endsWith(".xapk") ||
                        lowerTitle.endsWith(".apkm")
                    ) {
                        if (ShieldRepository.isAutoDeleteDownloadedApks(context)) {
                            dm.remove(downloadId)
                        }
                        ShieldRepository.recordAndAlertThreat(
                            context = context.applicationContext,
                            type = ThreatType.APK_FILE_QUARANTINED,
                            severity = Severity.CRITICAL,
                            sourcePackageOrUrl = "$title ($sourceUrl)",
                            title = "🛑 Downloaded APK File Intercepted!",
                            description = "A browser or app downloaded an APK installer file ('$title') from:\n$sourceUrl",
                            actionTaken = if (ShieldRepository.isAutoDeleteDownloadedApks(context)) {
                                "Automatically Removed APK via DownloadManager"
                            } else {
                                "Blocked & Warned User"
                            },
                            showFullScreenPopup = true
                        )
                    }
                }
            }
        } catch (_: Exception) {
        }
    }
}
