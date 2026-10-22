package com.security.apkshield.ui

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.security.apkshield.data.ShieldRepository
import com.security.apkshield.model.ThreatType
import com.security.apkshield.scanner.StealthAndSpywareScanner

class ThreatAlertActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val title = intent.getStringExtra("THREAT_TITLE") ?: "APK Installation Intercepted"
        val desc = intent.getStringExtra("THREAT_DESC")
            ?: "ZeroPro paused an APK installation outside the official Google Play Store to protect your phone."
        val source = intent.getStringExtra("THREAT_SOURCE") ?: "External APK File"
        val actionTaken = intent.getStringExtra("THREAT_ACTION") ?: "Installation Paused for Your Safety"
        val threatType = intent.getStringExtra("THREAT_TYPE") ?: "APK Security Shield"
        val uninstallPkg = intent.getStringExtra("UNINSTALL_PKG")

        // Detect if this alert is from a HIDDEN APK IN A LINK or a DISGUISED STEALTH APK
        val isHiddenApkInLink = threatType.equals(ThreatType.MALICIOUS_LINK_BLOCKED.title, ignoreCase = true) ||
                source.startsWith("http://", ignoreCase = true) ||
                source.startsWith("https://", ignoreCase = true) ||
                source.startsWith("intent://", ignoreCase = true) ||
                title.contains("Hidden APK", ignoreCase = true) ||
                title.contains("Disguised", ignoreCase = true) ||
                title.contains("Link", ignoreCase = true)

        val apkArchiveInfo = StealthAndSpywareScanner.inspectApkArchiveAbilities(
            applicationContext,
            explicitPath = source.takeIf { it.endsWith(".apk", ignoreCase = true) && !it.startsWith("http") }
        )

        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                ThreatAlertScreen(
                    threatType = threatType,
                    title = if (isHiddenApkInLink) "🚨 HIGH ALERT: Hidden APK Detected in Link!" else title,
                    description = desc,
                    source = source,
                    actionTaken = actionTaken,
                    isStrictHiddenLinkAlert = isHiddenApkInLink,
                    apkAnalysis = apkArchiveInfo,
                    uninstallPackage = uninstallPkg,
                    onUninstallClick = { pkg ->
                        val uninstallIntent = Intent(Intent.ACTION_DELETE).apply {
                            data = Uri.parse("package:$pkg")
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                        startActivity(uninstallIntent)
                        finish()
                    },
                    onGoBackSafe = {
                        finish()
                    },
                    onTakeRiskAndAllow = {
                        ShieldRepository.grantTemporaryInstallBypass(durationMinutes = 2)
                        Toast.makeText(
                            applicationContext,
                            "APK Install allowed for 2 minutes. Protection will automatically turn back on.",
                            Toast.LENGTH_LONG
                        ).show()
                        finish()
                    }
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ThreatAlertScreen(
    threatType: String,
    title: String,
    description: String,
    source: String,
    actionTaken: String,
    isStrictHiddenLinkAlert: Boolean,
    apkAnalysis: StealthAndSpywareScanner.ApkArchiveAnalysis?,
    uninstallPackage: String?,
    onUninstallClick: (String) -> Unit,
    onGoBackSafe: () -> Unit,
    onTakeRiskAndAllow: () -> Unit
) {
    var showConfirmRiskDialog by remember { mutableStateOf(false) }

    if (showConfirmRiskDialog) {
        AlertDialog(
            onDismissRequest = { showConfirmRiskDialog = false },
            containerColor = Color(0xFF101F36),
            shape = RoundedCornerShape(20.dp),
            title = {
                Text(
                    text = "Allow APK Install for 2 Minutes?",
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "Only proceed if you personally downloaded this APK from a source you trust.",
                        color = Color(0xFFCBD5E1),
                        fontSize = 13.sp,
                        lineHeight = 19.sp
                    )
                    if (apkAnalysis != null && apkAnalysis.abilities.isNotEmpty()) {
                        Text(
                            text = "This APK requests ${apkAnalysis.abilities.size} sensitive abilities:\n• ${apkAnalysis.abilities.joinToString("\n• ")}",
                            color = Color(0xFF7DD3FC),
                            fontSize = 12.sp,
                            lineHeight = 17.sp
                        )
                    }
                    Text(
                        text = "ZeroPro will allow installation for 2 minutes and then automatically re-enable protection.",
                        color = Color(0xFF94A3B8),
                        fontSize = 12.sp
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        showConfirmRiskDialog = false
                        onTakeRiskAndAllow()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF0EA5E9)),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Text("I Understand — Allow (2 Min)", color = Color.White, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showConfirmRiskDialog = false }) {
                    Text("Go Back to Safety", color = Color(0xFF6EE7B7), fontWeight = FontWeight.Bold)
                }
            }
        )
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = if (isStrictHiddenLinkAlert) {
                        // Strict Crimson Red High-Alert Gradient for Hidden APK Links
                        listOf(
                            Color(0xFF5C0A16),
                            Color(0xFF28060C),
                            Color(0xFF081221)
                        )
                    } else {
                        listOf(
                            Color(0xFF0C2D48),
                            Color(0xFF081221)
                        )
                    }
                )
            )
            .statusBarsPadding()
            .padding(22.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Box(
                modifier = Modifier
                    .size(84.dp)
                    .background(
                        if (isStrictHiddenLinkAlert) Color(0xFFEF4444).copy(alpha = 0.22f) else Color(0xFF10B981).copy(alpha = 0.18f),
                        CircleShape
                    )
                    .border(
                        2.dp,
                        if (isStrictHiddenLinkAlert) Color(0xFFEF4444) else Color(0xFF6EE7B7),
                        CircleShape
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = if (isStrictHiddenLinkAlert) Icons.Default.GppBad else Icons.Default.GppMaybe,
                    contentDescription = "APK Shield Warning",
                    tint = if (isStrictHiddenLinkAlert) Color(0xFFF87171) else Color(0xFF6EE7B7),
                    modifier = Modifier.size(46.dp)
                )
            }

            Spacer(modifier = Modifier.height(14.dp))

            Surface(
                color = if (isStrictHiddenLinkAlert) Color(0xFFDC2626) else Color(0xFF064E3B),
                shape = RoundedCornerShape(50),
                modifier = Modifier.border(
                    1.dp,
                    if (isStrictHiddenLinkAlert) Color(0xFFFCA5A5) else Color(0xFF10B981).copy(alpha = 0.5f),
                    RoundedCornerShape(50)
                )
            ) {
                Text(
                    text = if (isStrictHiddenLinkAlert) "HIGH ALERT • HIDDEN APK TRAP BLOCKED" else threatType.uppercase(),
                    color = if (isStrictHiddenLinkAlert) Color.White else Color(0xFF6EE7B7),
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 11.sp,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 5.dp)
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = title,
                color = Color.White,
                fontSize = 21.sp,
                fontWeight = FontWeight.ExtraBold,
                textAlign = TextAlign.Center
            )

            if (isStrictHiddenLinkAlert) {
                Spacer(modifier = Modifier.height(10.dp))
                Surface(
                    color = Color(0xFF450A0A),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, Color(0xFFEF4444), RoundedCornerShape(12.dp))
                ) {
                    Text(
                        text = "⚠️ CRITICAL WARNING: This link secretly hides an Android APK installer file designed to install malware or spyware on your phone without your permission. Do NOT open or install from this link!",
                        color = Color(0xFFFECACA),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                        lineHeight = 18.sp,
                        modifier = Modifier.padding(14.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Details & Abilities Inside This APK
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF101F36)),
                shape = RoundedCornerShape(18.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(
                        1.dp,
                        if (isStrictHiddenLinkAlert) Color(0xFFEF4444).copy(alpha = 0.5f) else Color(0xFF0EA5E9).copy(alpha = 0.45f),
                        RoundedCornerShape(18.dp)
                    )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = if (apkAnalysis != null) "ABILITIES & PERMISSIONS INSIDE THIS APK" else "THREAT DETAILS",
                        color = if (isStrictHiddenLinkAlert) Color(0xFFF87171) else Color(0xFF7DD3FC),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    if (apkAnalysis != null) {
                        Text(
                            text = "${apkAnalysis.fileName} (${apkAnalysis.packageName})",
                            color = Color.White,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 13.sp
                        )
                        Spacer(modifier = Modifier.height(8.dp))

                        if (apkAnalysis.abilities.isEmpty()) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    Icons.Default.CheckCircle,
                                    contentDescription = null,
                                    tint = Color(0xFF6EE7B7),
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    text = "No sensitive permissions (SMS, Camera, Mic, Contacts) found inside this APK.",
                                    color = Color(0xFF6EE7B7),
                                    fontSize = 12.sp
                                )
                            }
                        } else {
                            Text(
                                text = "If installed, this APK has the ability to:",
                                color = Color(0xFF94A3B8),
                                fontSize = 12.sp
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            FlowRow(
                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                apkAnalysis.abilities.forEach { ability ->
                                    val isCritical = ability.contains("SMS") ||
                                            ability.contains("Screen Control") ||
                                            ability.contains("Notifications") ||
                                            ability.contains("Device Admin")
                                    Surface(
                                        color = if (isCritical) Color(0xFF3B1A22) else Color(0xFF172B49),
                                        shape = RoundedCornerShape(8.dp),
                                        modifier = Modifier.border(
                                            1.dp,
                                            if (isCritical) Color(0xFFFCA5A5).copy(alpha = 0.5f) else Color(0xFF0EA5E9).copy(alpha = 0.4f),
                                            RoundedCornerShape(8.dp)
                                        )
                                    ) {
                                        Text(
                                            text = ability,
                                            color = if (isCritical) Color(0xFFFCA5A5) else Color(0xFF7DD3FC),
                                            fontSize = 11.sp,
                                            fontWeight = FontWeight.SemiBold,
                                            modifier = Modifier.padding(horizontal = 9.dp, vertical = 4.dp)
                                        )
                                    }
                                }
                            }
                        }
                    } else {
                        Text(
                            text = description,
                            color = Color(0xFFF8FAFC),
                            fontSize = 13.sp,
                            lineHeight = 19.sp
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))
                    HorizontalDivider(color = Color(0xFF1E385B))
                    Spacer(modifier = Modifier.height(10.dp))

                    Text(
                        text = "SOURCE: $source",
                        color = Color(0xFF94A3B8),
                        fontSize = 11.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "✓ $actionTaken",
                        color = Color(0xFF6EE7B7),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Primary Recommended Button: Block & Go Back to Safety
            Button(
                onClick = onGoBackSafe,
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (isStrictHiddenLinkAlert) Color(0xFFDC2626) else Color(0xFF10B981)
                ),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp)
            ) {
                Icon(Icons.Default.Shield, contentDescription = null, tint = Color.White)
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = if (isStrictHiddenLinkAlert) "Block Dangerous Link & Exit to Safety" else "Go Back to Safety (Keep Blocked)",
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 15.sp
                )
            }

            // Only show "Take Risk & Allow My APK" when the user tapped a local APK file (NEVER on a malicious hidden APK link!)
            if (!isStrictHiddenLinkAlert) {
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedButton(
                    onClick = { showConfirmRiskDialog = true },
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(50.dp)
                ) {
                    Icon(
                        Icons.Default.WarningAmber,
                        contentDescription = null,
                        tint = Color(0xFF7DD3FC),
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Take Risk & Allow My APK (2 Min)",
                        color = Color(0xFF7DD3FC),
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 13.sp
                    )
                }
            }

            if (!uninstallPackage.isNullOrBlank()) {
                Spacer(modifier = Modifier.height(10.dp))
                TextButton(onClick = { onUninstallClick(uninstallPackage) }) {
                    Icon(
                        Icons.Default.DeleteForever,
                        contentDescription = null,
                        tint = Color(0xFFFCA5A5),
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "Uninstall Source App",
                        color = Color(0xFFFCA5A5),
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 13.sp
                    )
                }
            }
        }
    }
}
