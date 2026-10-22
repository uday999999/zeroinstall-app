package com.security.apkshield.service

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import com.security.apkshield.data.ShieldRepository
import com.security.apkshield.model.Severity
import com.security.apkshield.model.ThreatType
import com.security.apkshield.scanner.MaliciousLinkAnalyzer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.util.Locale

/**
 * Monitors incoming notifications from WhatsApp, Telegram, SMS, Email, and Browsers.
 * If someone sends a link that points to an APK, a hidden redirect APK dropper, or an `.apk` attachment,
 * this service immediately warns the user and cancels the dangerous notification action!
 */
class MessageLinkScannerNotificationService : NotificationListenerService() {

    companion object {
        @Volatile
        var isNotificationGuardActive: Boolean = false
            private set
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val recentlyScannedHashes = LinkedHashSet<Int>()

    override fun onListenerConnected() {
        super.onListenerConnected()
        isNotificationGuardActive = true
        ShieldRepository.init(applicationContext)
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null) return
        val pkg = sbn.packageName ?: return
        if (pkg == applicationContext.packageName) return
        if (!ShieldRepository.isBlockMaliciousLinksEnabled(applicationContext)) return

        val extras = sbn.notification.extras ?: return
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString() ?: ""
        val combinedText = "$title $text $bigText".trim()
        if (combinedText.isEmpty()) return

        val hash = (pkg + combinedText).hashCode()
        synchronized(recentlyScannedHashes) {
            if (!recentlyScannedHashes.add(hash)) return
            if (recentlyScannedHashes.size > 200) {
                recentlyScannedHashes.remove(recentlyScannedHashes.first())
            }
        }

        // Check 1: Direct APK file attachment sent via WhatsApp / Telegram / Messenger
        val lower = combinedText.lowercase(Locale.ROOT)
        if (lower.contains(".apk") || lower.contains(".xapk") || lower.contains(".apkm")) {
            ShieldRepository.recordAndAlertThreat(
                context = applicationContext,
                type = ThreatType.MALICIOUS_LINK_BLOCKED,
                severity = Severity.CRITICAL,
                sourcePackageOrUrl = "App: $pkg | Sender: $title",
                title = "🚨 HIGH ALERT: Hidden APK Detected in Message Link!",
                description = "A message from '$title' in '$pkg' contains a hidden APK file or link:\n\"$text\"\n\nDo NOT open or install this file—it may secretly install spyware or a banking trojan.",
                actionTaken = "HIGH ALERT Warning Displayed — Link Blocked",
                showFullScreenPopup = true
            )
            return
        }

        // Check 2: Extract any URLs in the message and run both Fast + Deep Header inspection
        val urls = MaliciousLinkAnalyzer.extractUrlsFromText(combinedText)
        if (urls.isEmpty()) return

        scope.launch {
            for (url in urls) {
                val fastScan = MaliciousLinkAnalyzer.analyzeUrlFast(url)
                val finalScan = if (fastScan.isThreat) {
                    fastScan
                } else {
                    MaliciousLinkAnalyzer.inspectUrlHeadersDeep(url)
                }

                if (finalScan.isThreat) {
                    ShieldRepository.recordAndAlertThreat(
                        context = applicationContext,
                        type = ThreatType.MALICIOUS_LINK_BLOCKED,
                        severity = Severity.CRITICAL,
                        sourcePackageOrUrl = "Message in $pkg ($title) → $url",
                        title = "🚨 HIGH ALERT: Hidden APK Detected in Link!",
                        description = "Sender '$title' sent a dangerous link containing a hidden APK or phishing payload ($url).\n\nReasons:\n${finalScan.reasons.joinToString("\n• ", prefix = "• ")}",
                        actionTaken = "HIGH ALERT — Hidden APK Link Strictly Blocked",
                        showFullScreenPopup = true
                    )
                    break
                }
            }
        }
    }

    override fun onListenerDisconnected() {
        isNotificationGuardActive = false
        super.onListenerDisconnected()
    }
}
