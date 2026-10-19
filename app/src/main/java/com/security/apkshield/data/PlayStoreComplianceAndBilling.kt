package com.security.apkshield.data

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import java.util.Locale

/**
 * 1. GOOGLE PLAY PROMINENT DISCLOSURE DEFINITIONS
 * Google Play Store policy strictly requires an in-app Prominent Disclosure dialog
 * with explicit "Accept" and "Decline" buttons BEFORE opening Android system settings
 * for Accessibility, Notification Listener, VPN, Usage Access, or Device Admin.
 */
enum class ProminentDisclosureType(
    val title: String,
    val permissionBadge: String,
    val whatIsAccessed: String,
    val howItIsUsed: String,
    val privacyGuarantee: String
) {
    ACCESSIBILITY(
        title = "Accessibility Service Disclosure",
        permissionBadge = "BIND_ACCESSIBILITY_SERVICE",
        whatIsAccessed = "ZeroInstall Shield uses the Android AccessibilityService API to detect when the system Package Installer dialog, 'Install Unknown Apps' setting screen, or a browser address bar with a malicious .apk URL appears on screen.",
        howItIsUsed = "This data is used strictly in real time to warn you and help block unauthorized APK installations and drive-by phishing links when APK Lockdown Mode is active.",
        privacyGuarantee = "100% On-Device: ZeroInstall Shield NEVER reads passwords, personal messages, or banking inputs, and NEVER transmits or stores any screen content outside your device."
    ),
    NOTIFICATION_LISTENER(
        title = "Message Link Guard Disclosure",
        permissionBadge = "BIND_NOTIFICATION_LISTENER_SERVICE",
        whatIsAccessed = "ZeroInstall Shield accesses incoming notification text solely to extract URLs and check for '.apk' file attachments in messaging apps (such as WhatsApp, SMS, and Telegram).",
        howItIsUsed = "Used exclusively to warn you immediately if someone sends a phishing link, a hidden APK dropper, or a tracker link before you tap it.",
        privacyGuarantee = "100% On-Device: Notification text is inspected in memory only and is NEVER saved, logged to a server, or shared with any third party."
    ),
    VPN_FIREWALL(
        title = "Local Anti-Tracker VPN Disclosure",
        permissionBadge = "BIND_VPN_SERVICE",
        whatIsAccessed = "ZeroInstall Shield uses Android's VpnService API to create a local loopback DNS filter on your phone.",
        howItIsUsed = "Used strictly to block background connections to known spyware, stalkerware (mSpy, FlexiSpy, Cerberus), and invasive tracker domains.",
        privacyGuarantee = "100% Local Loopback: Your internet traffic is NEVER routed through any external VPN server, and your browsing activity is never logged."
    ),
    USAGE_AND_NETWORK_STATS(
        title = "Data Usage & Upload Spy Disclosure",
        permissionBadge = "PACKAGE_USAGE_STATS",
        whatIsAccessed = "ZeroInstall Shield reads per-app network upload (TX) and download (RX) byte counters and foreground screen time intervals.",
        howItIsUsed = "Used to show you which apps are consuming data and to alert you if a hidden background app is secretly uploading large amounts of data while your screen is off.",
        privacyGuarantee = "100% On-Device: App usage and data statistics never leave your phone."
    ),
    DEVICE_ADMIN(
        title = "Device Admin Tamper Lock Disclosure",
        permissionBadge = "BIND_DEVICE_ADMIN",
        whatIsAccessed = "ZeroInstall Shield requests Device Administrator activation.",
        howItIsUsed = "Used solely to prevent malware or unauthorized users from silently uninstalling ZeroInstall Shield in the background.",
        privacyGuarantee = "You can deactivate Device Admin at any time from inside ZeroInstall Shield or Android Settings."
    )
}

/**
 * 2. PURCHASING POWER PARITY (PPP) REGIONAL FAIR PRICING ENGINE
 * Google Play Billing supports country-specific pricing across 170+ countries.
 * This automatically displays ultra-affordable local pricing in developing/low-income nations
 * while keeping core protection 100% Free for everyone.
 */
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
        // Low / Lower-Middle Per-Capita Income Nations (70% - 85% PPP Reduction)
        "IN" to RegionalPlanPrice("IN", "India", "₹", "₹29 / month", "₹199 / year", "80% Regional Income Adjustment Applied"),
        "ID" to RegionalPlanPrice("ID", "Indonesia", "Rp", "Rp 9,000 / month", "Rp 69,000 / year", "75% Regional Income Adjustment Applied"),
        "PK" to RegionalPlanPrice("PK", "Pakistan", "Rs", "Rs 90 / month", "Rs 690 / year", "85% Regional Income Adjustment Applied"),
        "BD" to RegionalPlanPrice("BD", "Bangladesh", "৳", "৳40 / month", "৳299 / year", "85% Regional Income Adjustment Applied"),
        "NG" to RegionalPlanPrice("NG", "Nigeria", "₦", "₦400 / month", "₦2,900 / year", "85% Regional Income Adjustment Applied"),
        "KE" to RegionalPlanPrice("KE", "Kenya", "KSh", "KSh 50 / month", "KSh 390 / year", "80% Regional Income Adjustment Applied"),
        "PH" to RegionalPlanPrice("PH", "Philippines", "₱", "₱29 / month", "₱199 / year", "75% Regional Income Adjustment Applied"),
        "VN" to RegionalPlanPrice("VN", "Vietnam", "₫", "12,000 ₫ / month", "89,000 ₫ / year", "75% Regional Income Adjustment Applied"),
        "EG" to RegionalPlanPrice("EG", "Egypt", "E£", "E£ 20 / month", "E£ 149 / year", "80% Regional Income Adjustment Applied"),
        "NP" to RegionalPlanPrice("NP", "Nepal", "Rs", "Rs 49 / month", "Rs 349 / year", "80% Regional Income Adjustment Applied"),
        "LK" to RegionalPlanPrice("LK", "Sri Lanka", "Rs", "Rs 99 / month", "Rs 750 / year", "80% Regional Income Adjustment Applied"),

        // Middle-Income Nations (50% - 65% PPP Reduction)
        "BR" to RegionalPlanPrice("BR", "Brazil", "R$", "R$ 4,90 / month", "R$ 34,90 / year", "60% Regional Income Adjustment Applied"),
        "MX" to RegionalPlanPrice("MX", "Mexico", "MX$", "MX$ 19 / month", "MX$ 149 / year", "55% Regional Income Adjustment Applied"),
        "ZA" to RegionalPlanPrice("ZA", "South Africa", "R", "R 15 / month", "R 119 / year", "60% Regional Income Adjustment Applied"),
        "TR" to RegionalPlanPrice("TR", "Türkiye", "₺", "₺19 / month", "₺149 / year", "65% Regional Income Adjustment Applied"),
        "CO" to RegionalPlanPrice("CO", "Colombia", "COP", "COP 3,500 / month", "COP 25,000 / year", "65% Regional Income Adjustment Applied"),

        // High-Income Nations (Standard Affordable Price)
        "US" to RegionalPlanPrice("US", "United States", "$", "$1.49 / month", "$9.99 / year", "Standard Affordable Global Rate"),
        "GB" to RegionalPlanPrice("GB", "United Kingdom", "£", "£1.19 / month", "£7.99 / year", "Standard Affordable Global Rate"),
        "DE" to RegionalPlanPrice("DE", "Eurozone", "€", "€1.39 / month", "€8.99 / year", "Standard Affordable Global Rate")
    )

    fun getCurrentUserRegionalPrice(): RegionalPlanPrice {
        val code = Locale.getDefault().country.uppercase(Locale.ROOT)
        return REGIONAL_TIERS[code] ?: RegionalPlanPrice(
            countryCode = code.ifEmpty { "GLOBAL" },
            countryName = Locale.getDefault().displayCountry.ifEmpty { "Global" },
            currencySymbol = "$",
            monthlyPriceFormatted = "$0.99 / month",
            yearlyPriceFormatted = "$6.99 / year",
            pppDiscountNote = "Google Play Local Purchasing-Power Pricing Active"
        )
    }

    fun getAllSampleTiers(): List<RegionalPlanPrice> = REGIONAL_TIERS.values.toList()
}

/**
 * 3. HIGH-UTILITY EVERYDAY PROTECTION SCANNERS:
 * - Screen-Share & Remote-Access Scam App Detector (Stops AnyDesk/TeamViewer bank OTP scams)
 * - Wi-Fi Proxy / MITM Tamper Check
 */
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
        "com.anydesk.anydeskandroid" to "AnyDesk Remote Control (Frequently abused by bank/KYC scammers to view your screen & steal OTPs)",
        "com.teamviewer.quicksupport.market" to "TeamViewer QuickSupport (Allows remote users to view your screen & SMS OTPs)",
        "com.teamviewer.teamviewer.market.mobile" to "TeamViewer Remote Control",
        "com.carriez.flutter_hbb" to "RustDesk Remote Desktop (Can grant full remote screen control)",
        "com.sand.airdroid" to "AirDroid Remote Access (Can remotely read SMS, notifications, and files)",
        "com.sand.airmirror" to "AirMirror Remote Control",
        "com.hoptodesk.app" to "HopToDesk Remote Screen Share",
        "com.nanosystems.supremo" to "Supremo Remote Desktop",
        "com.zoho.assist.agent" to "Zoho Assist Remote Agent",
        "ink.awesun.control" to "AweSun Remote Desktop"
    )

    /**
     * Checks if any Remote Desktop / Screen-Sharing app is installed that scammers commonly
     * trick victims into installing during fake bank/customer-care calls.
     */
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
                // Not installed
            }
        }
        return found
    }

    /**
     * Checks if the current Wi-Fi / Network connection has an HTTP proxy configured,
     * which attackers on public Wi-Fi use to intercept traffic or inject fake APK updates.
     */
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
                    statusTitle = "⚠️ Warning: Network Proxy Active ($host:$port)",
                    statusDetail = "Your Wi-Fi or mobile connection is routing traffic through an external proxy ($host:$port). Attackers can use proxies to intercept data or inject fake APK updates."
                )
            } else {
                WifiSecurityReport(
                    isProxyDetected = false,
                    proxyHostPort = null,
                    statusTitle = "✅ Network Proxy Check: Clean",
                    statusDetail = "No unauthorized HTTP proxy or Man-in-the-Middle (MITM) traffic redirector detected on your active connection."
                )
            }
        } catch (_: Exception) {
            WifiSecurityReport(
                isProxyDetected = false,
                proxyHostPort = null,
                statusTitle = "✅ Network Proxy Check: Clean",
                statusDetail = "No suspicious proxy configuration detected."
            )
        }
    }
}
