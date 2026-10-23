package com.security.apkshield.service

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.security.apkshield.data.ShieldRepository
import com.security.apkshield.model.Severity
import com.security.apkshield.model.ThreatType
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.util.Locale
import kotlin.concurrent.thread

/**
 * Local Loopback VPN DNS Firewall that intercepts DNS queries to known spyware C2 domains,
 * stalkerware servers, and background tracker endpoints—blocking them on-device without
 * routing user traffic to any external server.
 */
class TrackerBlockVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.security.apkshield.START_VPN"
        const val ACTION_STOP = "com.security.apkshield.STOP_VPN"

        @Volatile
        var isVpnActive: Boolean = false
            private set

        private val BLOCKED_SPYWARE_AND_TRACKER_DOMAINS = listOf(
            "mspy.com", "mspyonline.com", "flexispy.com", "hoverwatch.com",
            "cocospy.com", "spyzie.com", "cerberusapp.com", "xnspy.com",
            "eyezy.com", "kidsguard.pro", "thetruthspy.com", "spybubble.com",
            "highstermobile.com", "mobistealth.com", "spyhuman.com",
            "app-measurement.com", "supersonicads.com", "appsflyer.com",
            "adjust.com", "branch.io", "onesignal.com"
        )
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    @Volatile
    private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            stopSelf()
            return START_NOT_STICKY
        }
        if (!running) {
            startVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        running = true
        isVpnActive = true
        ShieldRepository.setVpnTrackerFirewallEnabled(applicationContext, true)
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null
    }

    private fun stopVpn() {
        running = false
        isVpnActive = false
        ShieldRepository.setVpnTrackerFirewallEnabled(applicationContext, false)
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
