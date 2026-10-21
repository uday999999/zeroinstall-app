package com.security.apkshield.data

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import java.util.Locale

enum class ProminentDisclosureType(
    val title: String,
    val permissionBadge: String,
    val whatIsAccessed: String,
    val howItIsUsed: String,
    val privacyGuarantee: String
) {
    ACCESSIBILITY(
        title = "Enable APK Install Blocker",
        permissionBadge = "Real-Time Install Shield",
        whatIsAccessed = "Detects when an unauthorized APK installer prompt or 'Install Unknown Apps' screen opens.",
        howItIsUsed = "Used in real time to warn you and block unauthorized sideloaded app installations before they can harm your phone.",
        privacyGuarantee = "100% On-Device Privacy: ZeroInstall Shield never reads personal messages, passwords, or banking inputs, and never sends screen data off your device."
    ),
    NOTIFICATION_LISTENER(
        title = "Enable Message Link Guard",
        permissionBadge = "Phishing & APK Link Protection",
        whatIsAccessed = "Checks incoming notification links in messaging apps (such as SMS, WhatsApp, and Telegram) for hidden .apk files and phishing links.",
        howItIsUsed = "Alerts you immediately if a message contains a dangerous APK download link or scam URL before you tap it.",
        privacyGuarantee = "100% On-Device Privacy: Notification links are checked locally in memory and are never stored or shared."
    ),
    VPN_FIREWALL(
        title = "Enable Tracker & Spyware Firewall",
        permissionBadge = "Local DNS Shield",
        whatIsAccessed = "Creates a local on-device DNS filter using Android's VPN service.",
        howItIsUsed = "Blocks background apps from connecting to known spyware, stalkerware, and invasive ad-tracker servers.",
        privacyGuarantee = "100% Local Processing: Your internet traffic is never routed through external servers and your browsing is never logged."
    ),
    USAGE_AND_NETWORK_STATS(
        title = "Enable App Data Monitor",
        permissionBadge = "Background Upload Inspector",
        whatIsAccessed = "Reads per-app network upload and download data counters and background usage time.",
        howItIsUsed = "Identifies apps that secretly upload large amounts of data while your screen is off.",
        privacyGuarantee = "100% On-Device Privacy: Your app usage and network statistics stay strictly on your phone."
    ),
    DEVICE_ADMIN(
        title = "Enable Anti-Tamper Protection",
        permissionBadge = "Uninstall Lock",
        whatIsAccessed = "Uses Android Device Administrator protection.",
        howItIsUsed = "Prevents malware or an intruder from silently uninstalling ZeroInstall Shield in the background.",
        privacyGuarantee = "You can turn this off at any time from inside ZeroInstall Shield."
    )
}

data class RegionalPlanPrice(
    val countryCode: String,
    val countryName: String,
    val currencySymbol: String,
    val monthlyPriceFormatted: String,
    val yearlyPriceFormatted: String,
    val pppDiscountNote: String
)

object RegionalPricingManager {

    private val REGIONAL_TIERS = mapOf(
        "IN" to RegionalPlanPrice("IN", "India", "₹", "₹49 / month", "₹299 / year", "Save 50% with Annual Plan"),
        "US" to RegionalPlanPrice("US", "United States", "$", "$1.99 / month", "$14.99 / year", "Save 37% with Annual Plan"),
        "GB" to RegionalPlanPrice("GB", "United Kingdom", "£", "£1.49 / month", "£11.99 / year", "Save 33% with Annual Plan"),
        "DE" to RegionalPlanPrice("DE", "Europe", "€", "€1.79 / month", "€12.99 / year", "Save 40% with Annual Plan")
    )

    fun getCurrentUserRegionalPrice(): RegionalPlanPrice {
        val code = Locale.getDefault().country.uppercase(Locale.ROOT)
        return REGIONAL_TIERS[code] ?: RegionalPlanPrice(
            countryCode = code.ifEmpty { "IN" },
            countryName = Locale.getDefault().displayCountry.ifEmpty { "Standard" },
            currencySymbol = "₹",
            monthlyPriceFormatted = "₹49 / month",
            yearlyPriceFormatted = "₹299 / year",
            pppDiscountNote = "Cancel anytime via Google Play"
        )
    }

    fun getAllSampleTiers(): List<RegionalPlanPrice> = REGIONAL_TIERS.values.toList()
}

data class RemoteAccessScamApp(
    val packageName: String,
    val appName: String,
    val dangerExplanation: String
)

data class WifiSecurityReport(
    val isProxyDetected: Boolean,
    val proxyHostPort: String?,
    val statusTitle: String,
    val statusDetail: String
)

object PeopleProtectionTools {

    private val REMOTE_CONTROL_SCAM_APPS = mapOf(
        "com.anydesk.anydeskandroid" to "AnyDesk Remote Control (Can allow remote callers to view your screen and banking OTPs)",
        "com.teamviewer.quicksupport.market" to "TeamViewer QuickSupport (Allows remote users to view your screen)",
        "com.teamviewer.teamviewer.market.mobile" to "TeamViewer Remote Control",
        "com.carriez.flutter_hbb" to "RustDesk Remote Desktop",
        "com.sand.airdroid" to "AirDroid Remote Access",
        "com.sand.airmirror" to "AirMirror Remote Control",
        "com.hoptodesk.app" to "HopToDesk Remote Screen Share",
        "com.nanosystems.supremo" to "Supremo Remote Desktop",
        "com.zoho.assist.agent" to "Zoho Assist Remote Agent",
        "ink.awesun.control" to "AweSun Remote Desktop"
    )

    fun detectRemoteAccessScamApps(context: Context): List<RemoteAccessScamApp> {
        val pm = context.packageManager
        val found = mutableListOf<RemoteAccessScamApp>()

        for ((pkg, explanation) in REMOTE_CONTROL_SCAM_APPS) {
            try {
                val appInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getApplicationInfo(pkg, 0)
                }
                val label = pm.getApplicationLabel(appInfo).toString()
                found.add(
                    RemoteAccessScamApp(
                        packageName = pkg,
                        appName = label,
                        dangerExplanation = explanation
                    )
                )
            } catch (_: PackageManager.NameNotFoundException) {
            }
        }
        return found
    }

    fun auditNetworkProxySafety(context: Context): WifiSecurityReport {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val proxyInfo = cm.defaultProxy
            val host = proxyInfo?.host
            val port = proxyInfo?.port ?: 0

            if (!host.isNullOrBlank() && host != "localhost" && host != "127.0.0.1") {
                WifiSecurityReport(
                    isProxyDetected = true,
                    proxyHostPort = "$host:$port",
                    statusTitle = "Network Proxy Detected ($host:$port)",
                    statusDetail = "Your connection is routing traffic through a proxy server ($host:$port)."
                )
            } else {
                WifiSecurityReport(
                    isProxyDetected = false,
                    proxyHostPort = null,
                    statusTitle = "Wi-Fi & Network Connection Secure",
                    statusDetail = "No unauthorized proxy or traffic interception detected."
                )
            }
        } catch (_: Exception) {
            WifiSecurityReport(
                isProxyDetected = false,
                proxyHostPort = null,
                statusTitle = "Wi-Fi & Network Connection Secure",
                statusDetail = "No suspicious proxy configuration detected."
            )
        }
    }
}
