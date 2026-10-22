package com.security.apkshield.data

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import androidx.core.app.NotificationCompat
import com.security.apkshield.model.Severity
import com.security.apkshield.model.ThreatEvent
import com.security.apkshield.model.ThreatType
import com.security.apkshield.ui.ThreatAlertActivity
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

object ShieldRepository {
    private const val PREFS_NAME = "apk_shield_prefs"
    private const val KEY_BLOCK_ALL_APK = "block_all_apk"
    private const val KEY_BLOCK_UNKNOWN_SOURCES_SETTINGS = "block_unknown_sources_settings"
    private const val KEY_AUTO_DELETE_DOWNLOADED_APKS = "auto_delete_downloaded_apks"
    private const val KEY_BLOCK_MALICIOUS_LINKS = "block_malicious_links"
    private const val KEY_DETECT_INVISIBLE_APPS = "detect_invisible_apps"
    private const val KEY_ALLOW_PLAY_STORE_UPDATES = "allow_play_store_updates"
    private const val KEY_VPN_TRACKER_FIREWALL = "vpn_tracker_firewall"
    private const val KEY_PIN_CODE = "security_pin_code"
    private const val KEY_THREAT_LOGS = "threat_logs_json"
    private const val KEY_PRO_UNLOCKED = "zeroinstall_pro_unlocked"
    private const val KEY_PRO_AD_EXPIRY_MS = "zeroinstall_pro_ad_expiry_ms"
    private const val KEY_ADS_WATCHED_COUNT = "zeroinstall_ads_watched_count"

    private const val KEY_FIRST_RUN_PRO_INITIALIZED = "zeroinstall_first_run_pro_initialized"

    private const val ALERT_CHANNEL_ID = "apk_shield_critical_alerts"

    private val _threatEvents = MutableStateFlow<List<ThreatEvent>>(emptyList())
    val threatEvents: StateFlow<List<ThreatEvent>> = _threatEvents.asStateFlow()

    private val _blockedTrackersCount = MutableStateFlow(0)
    val blockedTrackersCount: StateFlow<Int> = _blockedTrackersCount.asStateFlow()

    private val _isProUnlocked = MutableStateFlow(false)
    val isProUnlocked: StateFlow<Boolean> = _isProUnlocked.asStateFlow()

    private val _proAdExpiryMs = MutableStateFlow(0L)
    val proAdExpiryMs: StateFlow<Long> = _proAdExpiryMs.asStateFlow()

    private val _adsWatchedCount = MutableStateFlow(0)
    val adsWatchedCount: StateFlow<Int> = _adsWatchedCount.asStateFlow()

    @Volatile
    private var temporaryBypassUntilMs: Long = 0L

    fun init(context: Context) {
        createNotificationChannel(context)
        loadLogs(context)
        val p = prefs(context)

        // Automatically give 3 days of Free Pro on first app launch
        if (!p.getBoolean(KEY_FIRST_RUN_PRO_INITIALIZED, false)) {
            val threeDaysMs = System.currentTimeMillis() + (3 * 24 * 3600_000L)
            p.edit()
                .putBoolean(KEY_FIRST_RUN_PRO_INITIALIZED, true)
                .putLong(KEY_PRO_AD_EXPIRY_MS, threeDaysMs)
                .apply()
        }

        val savedExpiry = p.getLong(KEY_PRO_AD_EXPIRY_MS, 0L)
        val isPaidSub = p.getBoolean(KEY_PRO_UNLOCKED, false)
        _proAdExpiryMs.value = savedExpiry
        _adsWatchedCount.value = p.getInt(KEY_ADS_WATCHED_COUNT, 0)
        _isProUnlocked.value = isPaidSub || (System.currentTimeMillis() < savedExpiry)
    }

    fun setProUnlocked(context: Context, unlocked: Boolean) {
        val editor = prefs(context).edit().putBoolean(KEY_PRO_UNLOCKED, unlocked)
        if (!unlocked) {
            editor.putLong(KEY_PRO_AD_EXPIRY_MS, 0L)
            editor.putInt(KEY_ADS_WATCHED_COUNT, 0)
            _proAdExpiryMs.value = 0L
            _adsWatchedCount.value = 0
        }
        editor.apply()
        _isProUnlocked.value = unlocked
    }

    /**
     * Stacks +24 hours of Pro Shield every time the user watches 1 Rewarded Video Ad.
     * Watch 1 ad -> 1 day (23:59:59). Watch 5 ads -> 5 full days of Pro Shield!
     */
    fun addRewardedAdProHours(context: Context, hours: Int = 24) {
        val now = System.currentTimeMillis()
        val currentBase = maxOf(now, _proAdExpiryMs.value)
        val newExpiry = currentBase + (hours * 3600_000L)
        val newAdsCount = _adsWatchedCount.value + 1

        prefs(context).edit()
            .putLong(KEY_PRO_AD_EXPIRY_MS, newExpiry)
            .putInt(KEY_ADS_WATCHED_COUNT, newAdsCount)
            .apply()

        _proAdExpiryMs.value = newExpiry
        _adsWatchedCount.value = newAdsCount
        _isProUnlocked.value = true
    }

    fun refreshProStatus(context: Context) {
        val p = prefs(context)
        val isPaidSub = p.getBoolean(KEY_PRO_UNLOCKED, false)
        val adActive = System.currentTimeMillis() < _proAdExpiryMs.value
        _isProUnlocked.value = isPaidSub || adActive
    }

    fun formatRemainingProTime(remainingMs: Long): String {
        if (remainingMs <= 0L) return "00:00:00"
        val totalSeconds = remainingMs / 1000L
        val days = totalSeconds / 86400L
        val hours = (totalSeconds % 86400L) / 3600L
        val minutes = (totalSeconds % 3600L) / 60L
        val seconds = totalSeconds % 60L
        return if (days > 0L) {
            String.format("%dd %02dh %02dm", days, hours, minutes)
        } else {
            String.format("%02d:%02d:%02d", hours, minutes, seconds)
        }
    }

    fun formatRemainingProTimeVerbose(remainingMs: Long): String {
        if (remainingMs <= 0L) return "0 Mins"
        val totalSeconds = remainingMs / 1000L
        val days = totalSeconds / 86400L
        val hours = (totalSeconds % 86400L) / 3600L
        val minutes = (totalSeconds % 3600L) / 60L
        val seconds = totalSeconds % 60L
        return if (days > 0L) {
            val dayLabel = if (days == 1L) "1 Day" else "$days Days"
            val hourLabel = if (hours == 1L) "1 Hour" else "$hours Hours"
            val minLabel = if (minutes == 1L) "1 Min" else "$minutes Mins"
            "$dayLabel $hourLabel $minLabel"
        } else {
            val hourLabel = if (hours == 1L) "1 Hour" else "$hours Hours"
            val minLabel = if (minutes == 1L) "1 Min" else "$minutes Mins"
            val secLabel = if (seconds == 1L) "1 Sec" else "$seconds Secs"
            "$hourLabel $minLabel $secLabel"
        }
    }

    /**
     * Allows the user to intentionally install their own APK for 2 minutes when they choose
     * "Take Risk & Allow Install" on the warning screen, then automatically re-locks protection.
     */
    fun grantTemporaryInstallBypass(durationMinutes: Int = 2) {
        temporaryBypassUntilMs = System.currentTimeMillis() + (durationMinutes * 60 * 1000L)
    }

    fun isTemporaryBypassActive(): Boolean =
        System.currentTimeMillis() < temporaryBypassUntilMs

    fun isBlockAllApkEnabled(context: Context): Boolean {
        if (isTemporaryBypassActive()) return false
        return prefs(context).getBoolean(KEY_BLOCK_ALL_APK, true)
    }

    fun setBlockAllApkEnabled(context: Context, enabled: Boolean) =
        prefs(context).edit().putBoolean(KEY_BLOCK_ALL_APK, enabled).apply()

    fun isBlockUnknownSourcesSettingsEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_BLOCK_UNKNOWN_SOURCES_SETTINGS, true)

    fun setBlockUnknownSourcesSettingsEnabled(context: Context, enabled: Boolean) =
        prefs(context).edit().putBoolean(KEY_BLOCK_UNKNOWN_SOURCES_SETTINGS, enabled).apply()

    fun isAutoDeleteDownloadedApks(context: Context): Boolean {
        if (isTemporaryBypassActive()) return false
        return prefs(context).getBoolean(KEY_AUTO_DELETE_DOWNLOADED_APKS, false)
    }

    fun setAutoDeleteDownloadedApks(context: Context, enabled: Boolean) =
        prefs(context).edit().putBoolean(KEY_AUTO_DELETE_DOWNLOADED_APKS, enabled).apply()

    fun isBlockMaliciousLinksEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_BLOCK_MALICIOUS_LINKS, true)

    fun setBlockMaliciousLinksEnabled(context: Context, enabled: Boolean) =
        prefs(context).edit().putBoolean(KEY_BLOCK_MALICIOUS_LINKS, enabled).apply()

    fun isDetectInvisibleAppsEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_DETECT_INVISIBLE_APPS, true)

    fun setDetectInvisibleAppsEnabled(context: Context, enabled: Boolean) =
        prefs(context).edit().putBoolean(KEY_DETECT_INVISIBLE_APPS, enabled).apply()

    fun isAllowPlayStoreUpdates(context: Context): Boolean =
        prefs(context).getBoolean(KEY_ALLOW_PLAY_STORE_UPDATES, true)

    fun setAllowPlayStoreUpdates(context: Context, enabled: Boolean) =
        prefs(context).edit().putBoolean(KEY_ALLOW_PLAY_STORE_UPDATES, enabled).apply()

    fun isVpnTrackerFirewallEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_VPN_TRACKER_FIREWALL, false)

    fun setVpnTrackerFirewallEnabled(context: Context, enabled: Boolean) =
        prefs(context).edit().putBoolean(KEY_VPN_TRACKER_FIREWALL, enabled).apply()

    fun getPinCode(context: Context): String? =
        prefs(context).getString(KEY_PIN_CODE, null)

    fun setPinCode(context: Context, pin: String?) =
        prefs(context).edit().putString(KEY_PIN_CODE, pin).apply()

    fun incrementBlockedTracker() {
        _blockedTrackersCount.value += 1
    }

    /**
     * Records a security threat, vibrates the device, fires a high-priority heads-up notification,
     * and launches the full-screen Red Alert popup so the user immediately sees what was stopped.
     */
    fun recordAndAlertThreat(
        context: Context,
        type: ThreatType,
        severity: Severity,
        sourcePackageOrUrl: String,
        title: String,
        description: String,
        actionTaken: String,
        canUninstallPackage: String? = null,
        showFullScreenPopup: Boolean = true
    ) {
        val event = ThreatEvent(
            id = UUID.randomUUID().toString(),
            timestamp = System.currentTimeMillis(),
            type = type,
            severity = severity,
            sourcePackageOrUrl = sourcePackageOrUrl,
            title = title,
            description = description,
            actionTaken = actionTaken,
            canUninstallPackage = canUninstallPackage
        )

        val updated = listOf(event) + _threatEvents.value.take(99)
        _threatEvents.value = updated
        saveLogs(context, updated)

        vibrateAlert(context)
        sendCriticalNotification(context, event)

        if (showFullScreenPopup) {
            try {
                val popupIntent = Intent(context, ThreatAlertActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    putExtra("THREAT_TITLE", event.title)
                    putExtra("THREAT_DESC", event.description)
                    putExtra("THREAT_SOURCE", event.sourcePackageOrUrl)
                    putExtra("THREAT_ACTION", event.actionTaken)
                    putExtra("THREAT_TYPE", event.type.title)
                    putExtra("UNINSTALL_PKG", event.canUninstallPackage)
                }
                context.startActivity(popupIntent)
            } catch (_: Exception) {
                // Fallback to high-priority notification if background activity launch is restricted
            }
        }
    }

    fun clearLogs(context: Context) {
        _threatEvents.value = emptyList()
        prefs(context).edit().remove(KEY_THREAT_LOGS).apply()
    }

    private fun vibrateAlert(context: Context) {
        try {
            val vibrator = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val vm = context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as VibratorManager
                vm.defaultVibrator
            } else {
                @Suppress("DEPRECATION")
                context.getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
            }
            vibrator.vibrate(
                VibrationEffect.createWaveform(longArrayOf(0, 250, 120, 350), -1)
            )
        } catch (_: Exception) {
        }
    }

    private fun createNotificationChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                ALERT_CHANNEL_ID,
                "Critical APK & Spyware Blocks",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Immediate alerts when an unauthorized APK, stealth installer, or tracker link is blocked"
                enableVibration(true)
            }
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    private fun sendCriticalNotification(context: Context, event: ThreatEvent) {
        createNotificationChannel(context)
        val alertIntent = Intent(context, ThreatAlertActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            putExtra("THREAT_TITLE", event.title)
            putExtra("THREAT_DESC", event.description)
            putExtra("THREAT_SOURCE", event.sourcePackageOrUrl)
            putExtra("THREAT_ACTION", event.actionTaken)
            putExtra("THREAT_TYPE", event.type.title)
            putExtra("UNINSTALL_PKG", event.canUninstallPackage)
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            event.id.hashCode(),
            alertIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("🛡️ ${event.title}")
            .setContentText(event.description)
            .setStyle(
                NotificationCompat.BigTextStyle().bigText(
                    "${event.description}\n\nSource: ${event.sourcePackageOrUrl}\nAction: ${event.actionTaken}"
                )
            )
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setFullScreenIntent(pendingIntent, true)
            .setContentIntent(pendingIntent)
            .build()

        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(event.id.hashCode(), notification)
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun saveLogs(context: Context, events: List<ThreatEvent>) {
        val arr = JSONArray()
        events.forEach { ev ->
            val obj = JSONObject().apply {
                put("id", ev.id)
                put("timestamp", ev.timestamp)
                put("type", ev.type.name)
                put("severity", ev.severity.name)
                put("source", ev.sourcePackageOrUrl)
                put("title", ev.title)
                put("description", ev.description)
                put("actionTaken", ev.actionTaken)
                put("canUninstallPackage", ev.canUninstallPackage ?: "")
            }
            arr.put(obj)
        }
        prefs(context).edit().putString(KEY_THREAT_LOGS, arr.toString()).apply()
    }

    private fun loadLogs(context: Context) {
        val raw = prefs(context).getString(KEY_THREAT_LOGS, null) ?: return
        try {
            val arr = JSONArray(raw)
            val list = mutableListOf<ThreatEvent>()
            for (i in 0 until arr.length()) {
                val obj = arr.getJSONObject(i)
                val uninstallPkg = obj.optString("canUninstallPackage", "").ifBlank { null }
                list.add(
                    ThreatEvent(
                        id = obj.getString("id"),
                        timestamp = obj.getLong("timestamp"),
                        type = ThreatType.valueOf(obj.getString("type")),
                        severity = Severity.valueOf(obj.getString("severity")),
                        sourcePackageOrUrl = obj.getString("source"),
                        title = obj.getString("title"),
                        description = obj.getString("description"),
                        actionTaken = obj.getString("actionTaken"),
                        canUninstallPackage = uninstallPkg
                    )
                )
            }
            _threatEvents.value = list
        } catch (_: Exception) {
        }
    }
}
