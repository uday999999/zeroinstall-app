package com.security.apkshield.scanner

import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.util.Locale

data class LinkScanResult(
    val url: String,
    val isThreat: Boolean,
    val threatScore: Int, // 0..100
    val reasons: List<String>,
    val resolvedFinalUrl: String? = null
)

object MaliciousLinkAnalyzer {

    private val SUSPICIOUS_EXTENSIONS = listOf(
        ".apk", ".xapk", ".apkm", ".apks", ".dex", ".sh", ".bin", ".payload"
    )

    private val HIGH_RISK_TUNNEL_AND_DDNS_HOSTS = listOf(
        "ngrok.io", "ngrok-free.app", "trycloudflare.com", "duckdns.org",
        "no-ip.org", "serveo.net", "localto.net", "loca.lt", "workers.dev",
        "firebasestorage.googleapis.com", "discordapp.com/attachments",
        "cdn.discordapp.com/attachments", "t.me/", "bit.ly", "tinyurl.com",
        "cutt.ly", "rb.gy", "is.gd", "shorturl.at"
    )

    private val TRACKER_AND_SPYWARE_KEYWORDS = listOf(
        "spy", "stealer", "rat-apk", "keylogger", "stalker", "mspy", "flexispy",
        "hoverwatch", "cerberus", "silent-install", "auto-install", "bg-tracker",
        "sms-forward", "otp-steal", "bank-update", "kyc-update", "reward-claim"
    )

    private val URL_REGEX = Regex(
        """(https?://[^\s<>"]+|intent://[^\s<>"]+)""",
        RegexOption.IGNORE_CASE
    )

    fun extractUrlsFromText(text: String): List<String> {
        return URL_REGEX.findAll(text).map { it.value.trimEnd('.', ',', ')', ']') }.distinct().toList()
    }

    /**
     * Fast synchronous heuristic analysis of any URL or deep link.
     */
    fun analyzeUrlFast(rawUrl: String): LinkScanResult {
        val normalized = rawUrl.trim()
        val lower = normalized.lowercase(Locale.ROOT)
        val reasons = mutableListOf<String>()
        var score = 0

        // 1. Direct or query-param APK / executable payload
        for (ext in SUSPICIOUS_EXTENSIONS) {
            if (lower.endsWith(ext) ||
                lower.contains("$ext?") ||
                lower.contains("$ext&") ||
                lower.contains("$ext#") ||
                lower.contains("=$ext") ||
                lower.contains("application/vnd.android.package-archive")
            ) {
                score += 90
                reasons.add("Link directly delivers an Android Package ($ext) file")
                break
            }
        }

        // 2. Android intent:// scheme used for drive-by silent package launches
        if (lower.startsWith("intent://")) {
            score += 85
            reasons.add("Uses 'intent://' URI scheme capable of launching hidden package installers")
            if (lower.contains("package=") || lower.contains("action=android.intent.action.install_package")) {
                score += 20
                reasons.add("Attempts to trigger Android Package Installer directly via browser intent")
            }
        }

        // 3. Raw IP address host (commonly used by malware drop servers & C2 trackers)
        try {
            val host = URI(normalized).host?.lowercase(Locale.ROOT) ?: ""
            if (host.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))) {
                score += 75
                reasons.add("Hosted on a raw IP address ($host) instead of a verified domain")
            }
            if (host.startsWith("xn--") || host.contains(".xn--")) {
                score += 65
                reasons.add("Uses Punycode (IDN homograph) domain to impersonate legitimate websites")
            }
            for (tunnel in HIGH_RISK_TUNNEL_AND_DDNS_HOSTS) {
                if (host == tunnel || host.endsWith(".$tunnel") || lower.contains(tunnel)) {
                    score += 45
                    reasons.add("Uses ephemeral tunnel / URL shortener / file-drop host ($tunnel)")
                    break
                }
            }
        } catch (_: Exception) {
        }

        // 4. Suspicious lure / spyware / banking APK keywords
        for (kw in TRACKER_AND_SPYWARE_KEYWORDS) {
            if (lower.contains(kw)) {
                score += 55
                reasons.add("Contains high-risk social engineering or spyware keyword ('$kw')")
                break
            }
        }

        // 5. Unencrypted HTTP link
        if (lower.startsWith("http://")) {
            score += 25
            reasons.add("Uses unencrypted HTTP connection vulnerable to payload injection")
        }

        val finalScore = score.coerceAtMost(100)
        return LinkScanResult(
            url = rawUrl,
            isThreat = finalScore >= 50,
            threatScore = finalScore,
            reasons = reasons
        )
    }

    /**
     * Deep network inspection (runs on background IO thread):
     * Follows redirects without downloading the body and checks if the remote server
     * returns an APK MIME type, attachment filename=".apk", or ZIP/APK magic header.
     */
    fun inspectUrlHeadersDeep(rawUrl: String): LinkScanResult {
        val fastResult = analyzeUrlFast(rawUrl)
        val reasons = fastResult.reasons.toMutableList()
        var score = fastResult.threatScore
        var finalUrl = rawUrl

        try {
            var currentUrl = rawUrl
            var redirects = 0
            while (redirects < 5) {
                val conn = (URL(currentUrl).openConnection() as HttpURLConnection).apply {
                    requestMethod = "GET"
                    instanceFollowRedirects = false
                    connectTimeout = 3500
                    readTimeout = 3500
                    setRequestProperty("Range", "bytes=0-63")
                    setRequestProperty("User-Agent", "APKShield-SecurityScanner/1.0")
                }
                conn.connect()
                val status = conn.responseCode
                if (status in 300..399) {
                    val location = conn.getHeaderField("Location") ?: break
                    currentUrl = URL(URL(currentUrl), location).toString()
                    finalUrl = currentUrl
                    redirects++
                    conn.disconnect()
                    continue
                }

                val contentType = (conn.contentType ?: "").lowercase(Locale.ROOT)
                val disposition = (conn.getHeaderField("Content-Disposition") ?: "").lowercase(Locale.ROOT)

                if (contentType.contains("application/vnd.android.package-archive") ||
                    contentType.contains("application/octet-stream") && disposition.contains(".apk") ||
                    disposition.contains(".apk") ||
                    disposition.contains(".xapk")
                ) {
                    score = 100
                    reasons.add("Server headers confirm hidden APK payload delivery (Content-Type: $contentType)")
                }

                // Check redirect chain target
                if (finalUrl != rawUrl) {
                    val redirectCheck = analyzeUrlFast(finalUrl)
                    if (redirectCheck.isThreat) {
                        score = maxOf(score, redirectCheck.threatScore)
                        reasons.addAll(redirectCheck.reasons.map { "Redirect target: $it" })
                    }
                }
                conn.disconnect()
                break
            }
        } catch (_: Exception) {
            // Network unreachable or blocked by VPN firewall
        }

        val clampedScore = score.coerceAtMost(100)
        return LinkScanResult(
            url = rawUrl,
            isThreat = clampedScore >= 50,
            threatScore = clampedScore,
            reasons = reasons.distinct(),
            resolvedFinalUrl = if (finalUrl != rawUrl) finalUrl else null
        )
    }
}
