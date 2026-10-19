package com.security.apkshield.model

enum class ThreatType(val title: String, val badgeColorHex: Long) {
    APK_INSTALL_BLOCKED("APK Installation Blocked", 0xFFEF4444),
    BACKGROUND_SESSION_BLOCKED("Silent/Background Install Stopped", 0xFFDC2626),
    MALICIOUS_LINK_BLOCKED("Phishing / APK Drop Link Blocked", 0xFFF97316),
    STEALTH_GHOST_APP_DETECTED("Invisible / Iconless App Detected", 0xFFA855F7),
    TRACKER_SPYWARE_DETECTED("Spyware / Background Tracker", 0xFFEC4899),
    APK_FILE_QUARANTINED("Downloaded APK Quarantined", 0xFFEAB308),
    UNKNOWN_SOURCE_SETTING_BLOCKED("Unknown Sources Toggle Blocked", 0xFF3B82F6)
}

enum class Severity {
    CRITICAL, HIGH, MEDIUM, INFO
}

data class ThreatEvent(
    val id: String,
    val timestamp: Long,
    val type: ThreatType,
    val severity: Severity,
    val sourcePackageOrUrl: String,
    val title: String,
    val description: String,
    val actionTaken: String,
    val canUninstallPackage: String? = null
)

data class AppSecurityAuditItem(
    val packageName: String,
    val appName: String,
    val installerPackage: String?,
    val isSystemApp: Boolean,
    val hasLauncherIcon: Boolean,
    val isSideloaded: Boolean,
    val dangerousPermissions: List<String>,
    val detectedTrackers: List<String>,
    val riskScore: Int, // 0..100
    val riskReasons: List<String>,
    val firstInstallTime: Long
)
