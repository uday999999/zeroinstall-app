package com.security.apkshield.service

import android.accessibilityservice.AccessibilityService
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.security.apkshield.data.ShieldRepository
import com.security.apkshield.model.Severity
import com.security.apkshield.model.ThreatType
import com.security.apkshield.scanner.MaliciousLinkAnalyzer
import java.util.Locale

class ApkInstallBlockerAccessibilityService : AccessibilityService() {

    companion object {
        @Volatile
        var isServiceRunning: Boolean = false
            private set

        private val PACKAGE_INSTALLER_PACKAGES = setOf(
            "com.android.packageinstaller",
            "com.google.android.packageinstaller",
            "com.miui.packageinstaller",
            "com.samsung.android.packageinstaller",
            "com.sec.android.preloadinstaller",
            "com.coloros.phonemanager",
            "com.oplus.appdetail",
            "com.vivo.secime.service",
            "com.huawei.appmarket"
        )

        private val INSTALL_PROMPT_KEYWORDS = listOf(
            "do you want to install this app",
            "do you want to update this app",
            "install unknown apps",
            "allow from this source",
            "install anyway",
            "unsafe app blocked"
        )

        private val CANCEL_BUTTON_TEXTS = listOf(
            "cancel", "don't allow", "deny", "close", "block"
        )
    }

    private var lastAlertTimeMs = 0L

    override fun onServiceConnected() {
        super.onServiceConnected()
        isServiceRunning = true
        ShieldRepository.init(applicationContext)
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return
        val pkgName = event.packageName?.toString() ?: return
        if (pkgName == applicationContext.packageName) return

        val rootNode = rootInActiveWindow ?: return

        // 1. Intercept Android Package Installer dialogs immediately
        if (ShieldRepository.isBlockAllApkEnabled(applicationContext)) {
            if (pkgName in PACKAGE_INSTALLER_PACKAGES || isPackageInstallerScreen(rootNode)) {
                val targetAppDetails = extractTargetAppName(rootNode)
                clickCancelButtonAndAbort(rootNode)
                triggerThrottledAlert(
                    type = ThreatType.APK_INSTALL_BLOCKED,
                    source = pkgName,
                    title = "Unauthorized APK Installation Stopped!",
                    description = "APK Shield intercepted an attempt to install an APK package ($targetAppDetails) and automatically cancelled the installer.",
                    actionTaken = "Clicked Cancel & Closed Package Installer"
                )
                return
            }
        }

        // 2. Intercept attempts to turn on "Install Unknown Apps" / "Allow from this source" in Settings
        if (ShieldRepository.isBlockUnknownSourcesSettingsEnabled(applicationContext)) {
            if (pkgName.contains("settings", ignoreCase = true) && isUnknownSourcesPermissionScreen(rootNode)) {
                performGlobalAction(GLOBAL_ACTION_BACK)
                triggerThrottledAlert(
                    type = ThreatType.UNKNOWN_SOURCE_SETTING_BLOCKED,
                    source = pkgName,
                    title = "'Install Unknown Apps' Setting Locked!",
                    description = "An app or user attempted to enable 'Install Unknown Apps' permission in System Settings. Blocked by APK Shield Lockdown.",
                    actionTaken = "Navigated Back & Prevented Permission Toggle"
                )
                return
            }
        }

        // 3. Inspect browser URL bars for drive-by .apk downloads or malicious links
        if (ShieldRepository.isBlockMaliciousLinksEnabled(applicationContext)) {
            if (pkgName.contains("chrome") || pkgName.contains("browser") || pkgName.contains("firefox")) {
                inspectBrowserUrlBar(rootNode, pkgName)
            }
        }
    }

    private fun isPackageInstallerScreen(root: AccessibilityNodeInfo): Boolean {
        val texts = collectVisibleTexts(root).joinToString(" ").lowercase(Locale.ROOT)
        return INSTALL_PROMPT_KEYWORDS.any { texts.contains(it) } &&
                (texts.contains("install") && texts.contains("cancel"))
    }

    private fun isUnknownSourcesPermissionScreen(root: AccessibilityNodeInfo): Boolean {
        val texts = collectVisibleTexts(root).joinToString(" ").lowercase(Locale.ROOT)
        return texts.contains("install unknown apps") ||
                texts.contains("allow from this source") ||
                texts.contains("install unknown applications")
    }

    private fun extractTargetAppName(root: AccessibilityNodeInfo): String {
        val texts = collectVisibleTexts(root)
        return texts.firstOrNull { text ->
            text.length in 2..40 &&
                    !text.contains("install", ignoreCase = true) &&
                    !text.contains("cancel", ignoreCase = true)
        } ?: "Unknown APK File"
    }

    private fun clickCancelButtonAndAbort(root: AccessibilityNodeInfo) {
        // First try standard Android negative button IDs
        val buttonIds = listOf(
            "android:id/button2",
            "com.android.packageinstaller:id/cancel_button",
            "com.google.android.packageinstaller:id/cancel_button"
        )
        for (id in buttonIds) {
            val nodes = root.findAccessibilityNodeInfosByViewId(id)
            if (!nodes.isNullOrEmpty()) {
                for (node in nodes) {
                    if (node.isClickable) {
                        node.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                    }
                }
            }
        }

        // Also search by text ("Cancel", "Don't allow", "Deny")
        for (cancelText in CANCEL_BUTTON_TEXTS) {
            val matches = root.findAccessibilityNodeInfosByText(cancelText)
            if (!matches.isNullOrEmpty()) {
                for (node in matches) {
                    if (node.isClickable) {
                        node.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                    } else if (node.parent?.isClickable == true) {
                        node.parent.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                    }
                }
            }
        }

        // Finally enforce global BACK and HOME to dismiss any overlay installer
        performGlobalAction(GLOBAL_ACTION_BACK)
        performGlobalAction(GLOBAL_ACTION_HOME)
    }

    private fun inspectBrowserUrlBar(root: AccessibilityNodeInfo, browserPkg: String) {
        val urlBarIds = listOf(
            "$browserPkg:id/url_bar",
            "com.android.chrome:id/url_bar",
            "org.mozilla.firefox:id/mozac_browser_toolbar_url_view"
        )
        for (id in urlBarIds) {
            val nodes = root.findAccessibilityNodeInfosByViewId(id) ?: continue
            for (node in nodes) {
                val urlText = node.text?.toString()?.trim() ?: continue
                if (urlText.isNotEmpty()) {
                    val fullUrl = if (urlText.startsWith("http")) urlText else "https://$urlText"
                    val scan = MaliciousLinkAnalyzer.analyzeUrlFast(fullUrl)
                    if (scan.isThreat) {
                        performGlobalAction(GLOBAL_ACTION_BACK)
                        triggerThrottledAlert(
                            type = ThreatType.MALICIOUS_LINK_BLOCKED,
                            source = fullUrl,
                            title = "Malicious APK / Tracker Link Blocked in Browser!",
                            description = "Browser attempted to open a high-risk URL:\n${scan.reasons.joinToString("\n• ", prefix = "• ")}",
                            actionTaken = "Navigated Back & Stopped Page Load"
                        )
                        return
                    }
                }
            }
        }
    }

    private fun collectVisibleTexts(node: AccessibilityNodeInfo?, depth: Int = 0): List<String> {
        if (node == null || depth > 8) return emptyList()
        val list = mutableListOf<String>()
        node.text?.toString()?.trim()?.takeIf { it.isNotEmpty() }?.let { list.add(it) }
        node.contentDescription?.toString()?.trim()?.takeIf { it.isNotEmpty() }?.let { list.add(it) }
        for (i in 0 until node.childCount) {
            list.addAll(collectVisibleTexts(node.getChild(i), depth + 1))
        }
        return list
    }

    private fun triggerThrottledAlert(
        type: ThreatType,
        source: String,
        title: String,
        description: String,
        actionTaken: String
    ) {
        val now = System.currentTimeMillis()
        if (now - lastAlertTimeMs < 2500L) return
        lastAlertTimeMs = now

        ShieldRepository.recordAndAlertThreat(
            context = applicationContext,
            type = type,
            severity = Severity.CRITICAL,
            sourcePackageOrUrl = source,
            title = title,
            description = description,
            actionTaken = actionTaken,
            showFullScreenPopup = true
        )
    }

    override fun onInterrupt() {
        isServiceRunning = false
    }

    override fun onDestroy() {
        isServiceRunning = false
        super.onDestroy()
    }
}
