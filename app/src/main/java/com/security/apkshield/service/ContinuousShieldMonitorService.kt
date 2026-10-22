package com.security.apkshield.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import androidx.core.app.NotificationCompat
import com.security.apkshield.data.ShieldRepository
import com.security.apkshield.model.Severity
import com.security.apkshield.model.ThreatType
import com.security.apkshield.scanner.StealthAndSpywareScanner
import com.security.apkshield.ui.MainActivity
import java.io.File
import java.io.RandomAccessFile
import java.util.Locale
import java.util.zip.ZipFile

/**
 * Continuous foreground security monitor that:
 * 1. Hooks into Android's PackageInstaller.SessionCallback to catch silent/background APK installation
 *    sessions the exact millisecond they are created in the background.
 * 2. Watches Download directories in real-time using FileObserver and inspects magic bytes
 *    (even if an APK is disguised as a .jpg, .pdf, or .bin file!) to quarantine stealth APK files.
 */
class ContinuousShieldMonitorService : Service() {

    companion object {
        private const val FGS_CHANNEL_ID = "apk_shield_continuous_guard"
        private const val FGS_NOTIFICATION_ID = 1001

        @Volatile
        var isRunning: Boolean = false
            private set

        fun start(context: Context) {
            val intent = Intent(context, ContinuousShieldMonitorService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }

    private lateinit var packageInstaller: PackageInstaller
    private val mainHandler = Handler(Looper.getMainLooper())
    private var downloadObserver: FileObserver? = null
    private val alertedSessionIds = mutableSetOf<Int>()

    private val sessionCallback = object : PackageInstaller.SessionCallback() {
        override fun onCreated(sessionId: Int) {
            inspectInstallSession(sessionId, "Session Created")
        }

        override fun onBadgingChanged(sessionId: Int) {
            inspectInstallSession(sessionId, "Badging Changed")
        }

        override fun onActiveChanged(sessionId: Int, active: Boolean) {
            if (active) {
                inspectInstallSession(sessionId, "Session Active in Background")
            }
        }

        override fun onProgressChanged(sessionId: Int, progress: Float) {
            inspectInstallSession(sessionId, "Installing (${(progress * 100).toInt()}%)")
        }

        override fun onFinished(sessionId: Int, success: Boolean) {
            alertedSessionIds.remove(sessionId)
        }
    }

    override fun onCreate() {
        super.onCreate()
        ShieldRepository.init(applicationContext)
        isRunning = true
        startForeground(FGS_NOTIFICATION_ID, buildForegroundNotification())

        packageInstaller = applicationContext.packageManager.packageInstaller
        packageInstaller.registerSessionCallback(sessionCallback, mainHandler)

        startDownloadDirectoryWatcher()
    }

    /**
     * Inspects any active or newly created PackageInstaller session on the device.
     * Detects background / silent installs initiated by browsers, droppers, ADB, or third-party stores.
     */
    private fun inspectInstallSession(sessionId: Int, stage: String) {
        if (!ShieldRepository.isBlockAllApkEnabled(applicationContext)) return
        if (sessionId in alertedSessionIds) return

        val sessionInfo = try {
            packageInstaller.getSessionInfo(sessionId)
        } catch (_: Exception) {
            null
        } ?: return

        val installerPkg = sessionInfo.installerPackageName ?: "Unknown / Background Sideload"
        val targetPkg = sessionInfo.appPackageName ?: "Hidden Package Name"
        val targetLabel = sessionInfo.appLabel?.toString() ?: targetPkg

        // If user allows official Google Play Store updates, skip trusted Play Store sessions
        if (ShieldRepository.isAllowPlayStoreUpdates(applicationContext) &&
            installerPkg in StealthAndSpywareScanner.TRUSTED_INSTALLERS
        ) {
            return
        }

        alertedSessionIds.add(sessionId)

        // Attempt to abandon the session if owned or accessible
        var abandoned = false
        try {
            packageInstaller.abandonSession(sessionId)
            abandoned = true
        } catch (_: SecurityException) {
            // System restricts abandoning another app's session without root/device-owner,
            // so we immediately launch our blocker overlay & accessibility cancel action!
        }

        ShieldRepository.recordAndAlertThreat(
            context = applicationContext,
            type = ThreatType.BACKGROUND_SESSION_BLOCKED,
            severity = Severity.CRITICAL,
            sourcePackageOrUrl = "Installer: $installerPkg → Target: $targetLabel ($targetPkg)",
            title = "🚨 Silent / Background APK Install Detected!",
            description = "An application ('$installerPkg') initiated a background package installation session [$stage] for '$targetLabel' ($targetPkg).",
            actionTaken = if (abandoned) {
                "Session Terminated Immediately"
            } else {
                "Blocked Installer UI & Triggered Emergency Security Alert"
            },
            canUninstallPackage = installerPkg.takeIf { it != "Unknown / Background Sideload" },
            showFullScreenPopup = true
        )
    }

    /**
     * Watches the public Downloads directory for any newly created or downloaded APK files,
     * INCLUDING disguised APK files (e.g. `photo.jpg` or `invoice.pdf` that is actually an APK archive
     * containing `AndroidManifest.xml` and `classes.dex`).
     */
    private fun startDownloadDirectoryWatcher() {
        val downloadDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        if (!downloadDir.exists()) return

        @Suppress("DEPRECATION")
        downloadObserver = object : FileObserver(
            downloadDir.absolutePath,
            CLOSE_WRITE or MOVED_TO or CREATE
        ) {
            override fun onEvent(event: Int, path: String?) {
                if (path == null) return
                val file = File(downloadDir, path)
                if (!file.exists() || !file.isFile) return

                mainHandler.postDelayed({
                    inspectDownloadedFile(file)
                }, 400L)
            }
        }
        downloadObserver?.startWatching()
    }

    private fun inspectDownloadedFile(file: File) {
        if (!ShieldRepository.isBlockAllApkEnabled(applicationContext)) return
        if (!file.exists() || !file.isFile) return
        val nameLower = file.name.lowercase(Locale.ROOT)

        // Ignore temporary browser partial files until they finish renaming
        if (nameLower.endsWith(".crdownload") || nameLower.endsWith(".part") || nameLower.endsWith(".tmp")) {
            return
        }

        val hasApkExtension = nameLower.endsWith(".apk") ||
                nameLower.endsWith(".xapk") ||
                nameLower.endsWith(".apkm") ||
                nameLower.endsWith(".apks") ||
                nameLower.endsWith(".dex")

        val isDisguisedApk = !hasApkExtension && isHiddenApkArchiveByMagicBytes(file)

        if (hasApkExtension || isDisguisedApk) {
            val shouldDelete = ShieldRepository.isAutoDeleteDownloadedApks(applicationContext)
            var deleted = false
            val filePath = file.absolutePath
            val fileSizeKb = file.length() / 1024

            if (shouldDelete) {
                try {
                    deleted = file.delete()
                } catch (_: Exception) {
                }
            }

            val disguiseWarning = if (isDisguisedApk) {
                "DISGUISED STEALTH APK! The file '${file.name}' pretends to be a normal file, but binary inspection revealed AndroidManifest.xml + classes.dex inside!"
            } else {
                "An APK installer file ('${file.name}', ${fileSizeKb} KB) was downloaded to your device."
            }

            ShieldRepository.recordAndAlertThreat(
                context = applicationContext,
                type = ThreatType.APK_FILE_QUARANTINED,
                severity = Severity.CRITICAL,
                sourcePackageOrUrl = filePath,
                title = if (isDisguisedApk) "🕵️ Disguised Stealth APK File Caught!" else "⚠️ Downloaded APK File Blocked!",
                description = disguiseWarning,
                actionTaken = if (deleted) {
                    "Automatically Deleted Malicious APK File from Storage"
                } else {
                    "Flagged & Blocked from Execution (Enable Storage Permission for Auto-Delete)"
                },
                showFullScreenPopup = true
            )
        }
    }

    /**
     * Checks if any file (even named `video.mp4` or `document.pdf`) starts with PK\x03\x04 (ZIP header)
     * and contains `AndroidManifest.xml` or `classes.dex` inside.
     */
    private fun isHiddenApkArchiveByMagicBytes(file: File): Boolean {
        if (file.length() < 128 || file.length() > 300 * 1024 * 1024L) return false
        return try {
            RandomAccessFile(file, "r").use { raf ->
                val b0 = raf.read()
                val b1 = raf.read()
                val b2 = raf.read()
                val b3 = raf.read()
                // ZIP/APK magic bytes: 0x50 0x4B 0x03 0x04 ("PK\u0003\u0004")
                if (b0 != 0x50 || b1 != 0x4B || b2 != 0x03 || b3 != 0x04) {
                    return false
                }
            }
            ZipFile(file).use { zip ->
                zip.getEntry("AndroidManifest.xml") != null || zip.getEntry("classes.dex") != null
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun buildForegroundNotification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                FGS_CHANNEL_ID,
                "Active APK & Anti-Stealth Shield",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "24/7 real-time protection against silent APK installs, hidden trackers, and malicious links"
            }
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }

        val openIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, FGS_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("APK Shield Guard Active")
            .setContentText("Blocking APK installs, background sessions & stealth tracker links")
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        isRunning = false
        try {
            packageInstaller.unregisterSessionCallback(sessionCallback)
        } catch (_: Exception) {
        }
        downloadObserver?.stopWatching()
        super.onDestroy()
    }
}
