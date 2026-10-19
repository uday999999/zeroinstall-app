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
        try {
            val builder = Builder()
                .setSession("APK Shield Anti-Tracker Firewall")
                .addAddress("10.215.173.1", 32)
                // Route only a sinkhole test/DNS range so normal internet stays fast while we inspect DNS packets
                .addRoute("10.215.173.2", 32)
                .addDnsServer("10.215.173.2")
                .setBlocking(true)

            vpnInterface = builder.establish()
            if (vpnInterface != null) {
                running = true
                isVpnActive = true
                ShieldRepository.setVpnTrackerFirewallEnabled(applicationContext, true)
                startDnsInspectionLoop()
            }
        } catch (_: Exception) {
            isVpnActive = false
        }
    }

    private fun startDnsInspectionLoop() {
        val fd = vpnInterface?.fileDescriptor ?: return
        thread(name = "ApkShield-DnsFirewall") {
            val input = FileInputStream(fd)
            val output = FileOutputStream(fd)
            val packet = ByteBuffer.allocate(32767)

            while (running) {
                try {
                    val length = input.read(packet.array())
                    if (length > 28) {
                        val rawBytes = packet.array().copyOfRange(0, length)
                        val extractedDomain = extractDomainFromDnsPacket(rawBytes)
                        if (extractedDomain != null && isBlockedDomain(extractedDomain)) {
                            ShieldRepository.incrementBlockedTracker()
                            ShieldRepository.recordAndAlertThreat(
                                context = applicationContext,
                                type = ThreatType.TRACKER_SPYWARE_DETECTED,
                                severity = Severity.HIGH,
                                sourcePackageOrUrl = extractedDomain,
                                title = "🛡️ Background Tracker / Spyware Connection Blocked",
                                description = "A background process attempted to connect to known tracker/spyware domain '$extractedDomain'. Connection was sinkholed.",
                                actionTaken = "Blocked DNS Resolution via Local Firewall",
                                showFullScreenPopup = false
                            )
                        }
                    }
                    packet.clear()
                } catch (_: Exception) {
                    if (!running) break
                }
            }
            try {
                output.close()
                input.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun isBlockedDomain(domain: String): Boolean {
        val lower = domain.lowercase(Locale.ROOT)
        return BLOCKED_SPYWARE_AND_TRACKER_DOMAINS.any {
            lower == it || lower.endsWith(".$it")
        }
    }

    private fun extractDomainFromDnsPacket(packet: ByteArray): String? {
        // Basic IPv4 + UDP + DNS QNAME parser
        return try {
            val ihl = (packet[0].toInt() and 0x0F) * 4
            val protocol = packet[9].toInt() and 0xFF
            if (protocol != 17) return null // Not UDP
            val dnsStart = ihl + 8 + 12 // IP header + UDP header (8) + DNS header (12)
            if (dnsStart >= packet.size) return null

            val sb = StringBuilder()
            var pos = dnsStart
            while (pos < packet.size) {
                val len = packet[pos].toInt() and 0xFF
                if (len == 0) break
                if (len > 63 || pos + 1 + len > packet.size) return null
                if (sb.isNotEmpty()) sb.append('.')
                for (i in 1..len) {
                    sb.append(packet[pos + i].toInt().toChar())
                }
                pos += len + 1
            }
            sb.toString().takeIf { it.contains('.') }
        } catch (_: Exception) {
            null
        }
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
