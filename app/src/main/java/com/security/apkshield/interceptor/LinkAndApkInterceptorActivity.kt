package com.security.apkshield.interceptor

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import com.security.apkshield.data.ShieldRepository
import com.security.apkshield.model.Severity
import com.security.apkshield.model.ThreatType
import com.security.apkshield.scanner.MaliciousLinkAnalyzer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Intercepts:
 * 1. Direct clicks on `.apk` files (`application/vnd.android.package-archive`) from WhatsApp, Telegram,
 *    File Managers, or Browsers and blocks them when APK Lockdown is active.
 * 2. Shared or opened URLs (`http://`, `https://`, `text/plain`) to scan for hidden APK redirects and trackers.
 */
class LinkAndApkInterceptorActivity : ComponentActivity() {

    private val scope = CoroutineScope(Dispatchers.IO)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ShieldRepository.init(applicationContext)

        val currentIntent = intent
        val mimeType = currentIntent?.type ?: ""
        val dataUri = currentIntent?.data

        // Case 1: Someone clicked or an app tried to launch an APK file directly
        if (mimeType == "application/vnd.android.package-archive" ||
            dataUri?.toString()?.endsWith(".apk", ignoreCase = true) == true
        ) {
            val sourceUri = dataUri?.toString() ?: "Unknown APK File"
            ShieldRepository.recordAndAlertThreat(
                context = applicationContext,
                type = ThreatType.APK_INSTALL_BLOCKED,
                severity = Severity.CRITICAL,
                sourcePackageOrUrl = sourceUri,
                title = "🛑 Direct APK File Execution Blocked!",
                description = "An application or link attempted to launch an APK package installer directly:\n$sourceUri\n\nAPK Shield intercepted and terminated the installation request.",
                actionTaken = "Intercepted Intent & Blocked APK Execution",
                showFullScreenPopup = true
            )
            finish()
            return
        }

        // Case 2: Someone opened or shared a link to scan
        val sharedText = currentIntent?.getStringExtra(Intent.EXTRA_TEXT) ?: dataUri?.toString() ?: ""
        val urls = MaliciousLinkAnalyzer.extractUrlsFromText(sharedText)
        if (urls.isNotEmpty()) {
            val targetUrl = urls.first()
            scope.launch {
                val scanResult = MaliciousLinkAnalyzer.inspectUrlHeadersDeep(targetUrl)
                if (scanResult.isThreat) {
                    ShieldRepository.recordAndAlertThreat(
                        context = applicationContext,
                        type = ThreatType.MALICIOUS_LINK_BLOCKED,
                        severity = Severity.CRITICAL,
                        sourcePackageOrUrl = targetUrl,
                        title = "🛑 Dangerous APK / Tracker Link Stopped!",
                        description = "This link ($targetUrl) was blocked because deep inspection found:\n\n" +
                                scanResult.reasons.joinToString("\n• ", prefix = "• "),
                        actionTaken = "Connection Aborted Before Browser Launch",
                        showFullScreenPopup = true
                    )
                } else {
                    ShieldRepository.recordAndAlertThreat(
                        context = applicationContext,
                        type = ThreatType.MALICIOUS_LINK_BLOCKED,
                        severity = Severity.INFO,
                        sourcePackageOrUrl = targetUrl,
                        title = "✅ Link Scanned: No Hidden APK Detected",
                        description = "Deep header inspection of $targetUrl completed (Risk Score: ${scanResult.threatScore}/100). No APK payload or redirect dropper found.",
                        actionTaken = "Verified Safe",
                        showFullScreenPopup = true
                    )
                }
            }
        }
        finish()
    }
}
