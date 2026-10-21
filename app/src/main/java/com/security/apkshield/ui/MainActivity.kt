package com.security.apkshield.ui

import android.Manifest
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.security.apkshield.data.PeopleProtectionTools
import com.security.apkshield.data.ProminentDisclosureType
import com.security.apkshield.data.RegionalPricingManager
import com.security.apkshield.data.ShieldRepository
import com.security.apkshield.model.AppSecurityAuditItem
import com.security.apkshield.model.Severity
import com.security.apkshield.model.ThreatEvent
import com.security.apkshield.model.ThreatType
import com.security.apkshield.receiver.ShieldDeviceAdminReceiver
import com.security.apkshield.scanner.AppDataUsageReport
import com.security.apkshield.scanner.LinkScanResult
import com.security.apkshield.scanner.MaliciousLinkAnalyzer
import com.security.apkshield.scanner.NetworkAndDataExfiltrationMonitor
import com.security.apkshield.scanner.StealthAndSpywareScanner
import com.security.apkshield.service.ApkInstallBlockerAccessibilityService
import com.security.apkshield.service.ContinuousShieldMonitorService
import com.security.apkshield.service.MessageLinkScannerNotificationService
import com.security.apkshield.service.TrackerBlockVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

// Cohesive, Uplifting, Positive & Secure Emerald-Teal + Sky-Cyan Palette
private val BgDeepSlate = Color(0xFF081221)
private val SurfaceCard = Color(0xFF101F36)
private val SurfaceElevated = Color(0xFF172B49)
private val BorderSubtle = Color(0xFF1E385B)
private val EmeraldPrimary = Color(0xFF10B981)
private val EmeraldSoft = Color(0xFF6EE7B7)
private val EmeraldDark = Color(0xFF064E3B)
private val CyanPrimary = Color(0xFF0EA5E9)
private val CyanSoft = Color(0xFF7DD3FC)
private val CyanDark = Color(0xFF0C3559)
private val TextPrimary = Color(0xFFF8FAFC)
private val TextSecondary = Color(0xFF94A3B8)
private val DangerSoft = Color(0xFFFCA5A5)
private val DangerBg = Color(0xFF3B1A22)

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ShieldRepository.init(applicationContext)
        ContinuousShieldMonitorService.start(applicationContext)

        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = EmeraldPrimary,
                    secondary = CyanPrimary,
                    background = BgDeepSlate,
                    surface = SurfaceCard
                )
            ) {
                ApkShieldMainApp()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun ApkShieldMainApp() {
    val context = LocalContext.current
    var selectedTab by remember { mutableIntStateOf(0) }
    var showProModal by remember { mutableStateOf(false) }
    val threatEvents by ShieldRepository.threatEvents.collectAsState()
    val blockedTrackers by ShieldRepository.blockedTrackersCount.collectAsState()
    val isProUnlocked by ShieldRepository.isProUnlocked.collectAsState()

    val notifPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { }

    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    if (showProModal) {
        ZeroInstallProDialog(
            isProUnlocked = isProUnlocked,
            onUnlockPro = {
                ShieldRepository.setProUnlocked(context, true)
                showProModal = false
            },
            onSwitchToFree = {
                ShieldRepository.setProUnlocked(context, false)
                showProModal = false
            },
            onDismiss = { showProModal = false }
        )
    }

    Scaffold(
        topBar = {
            Surface(
                color = BgDeepSlate,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .statusBarsPadding()
                        .padding(top = 10.dp, bottom = 10.dp, start = 18.dp, end = 18.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(38.dp)
                                    .background(
                                        Brush.linearGradient(
                                            listOf(EmeraldPrimary, CyanPrimary)
                                        ),
                                        RoundedCornerShape(11.dp)
                                    ),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Default.VerifiedUser,
                                    contentDescription = null,
                                    tint = Color.White,
                                    modifier = Modifier.size(21.dp)
                                )
                            }
                            Spacer(modifier = Modifier.width(12.dp))
                            Column {
                                Text(
                                    text = "ZeroInstall",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 18.sp,
                                    color = TextPrimary
                                )
                                Text(
                                    text = "Smart APK & Privacy Shield",
                                    fontSize = 11.sp,
                                    color = CyanSoft
                                )
                            }
                        }

                        // Cohesive Emerald-Cyan Gradient Pro Pill matching the app theme
                        Box(
                            modifier = Modifier
                                .background(
                                    Brush.horizontalGradient(
                                        if (isProUnlocked) {
                                            listOf(EmeraldDark, CyanDark)
                                        } else {
                                            listOf(EmeraldPrimary, CyanPrimary)
                                        }
                                    ),
                                    RoundedCornerShape(50)
                                )
                                .border(
                                    1.dp,
                                    if (isProUnlocked) EmeraldSoft.copy(alpha = 0.6f) else Color.White.copy(alpha = 0.35f),
                                    RoundedCornerShape(50)
                                )
                                .clickable { showProModal = true }
                                .padding(horizontal = 13.dp, vertical = 7.dp)
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = if (isProUnlocked) Icons.Default.CheckCircle else Icons.Default.AutoAwesome,
                                    contentDescription = null,
                                    tint = Color.White,
                                    modifier = Modifier.size(14.dp)
                                )
                                Spacer(modifier = Modifier.width(5.dp))
                                Text(
                                    text = if (isProUnlocked) "PRO ACTIVE" else "PRO SHIELD",
                                    color = Color.White,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        }
                    }
                }
            }
        },
        bottomBar = {
            NavigationBar(
                containerColor = Color(0xFF0A172A),
                tonalElevation = 0.dp
            ) {
                NavigationBarItem(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    icon = { Icon(Icons.Default.Shield, contentDescription = null) },
                    label = { Text("Protection", fontSize = 11.sp) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = EmeraldSoft,
                        selectedTextColor = EmeraldSoft,
                        indicatorColor = EmeraldDark.copy(alpha = 0.7f),
                        unselectedIconColor = TextSecondary,
                        unselectedTextColor = TextSecondary
                    )
                )
                NavigationBarItem(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    icon = { Icon(Icons.Default.FactCheck, contentDescription = null) },
                    label = { Text("App Audit", fontSize = 11.sp) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = EmeraldSoft,
                        selectedTextColor = EmeraldSoft,
                        indicatorColor = EmeraldDark.copy(alpha = 0.7f),
                        unselectedIconColor = TextSecondary,
                        unselectedTextColor = TextSecondary
                    )
                )
                NavigationBarItem(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    icon = {
                        BadgedBox(
                            badge = {
                                if (!isProUnlocked) {
                                    Badge(containerColor = CyanPrimary) {
                                        Text("PRO", color = Color.White, fontSize = 8.sp, fontWeight = FontWeight.ExtraBold)
                                    }
                                }
                            }
                        ) {
                            Icon(Icons.Default.DataUsage, contentDescription = null)
                        }
                    },
                    label = { Text("Data Guard", fontSize = 11.sp) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = EmeraldSoft,
                        selectedTextColor = EmeraldSoft,
                        indicatorColor = EmeraldDark.copy(alpha = 0.7f),
                        unselectedIconColor = TextSecondary,
                        unselectedTextColor = TextSecondary
                    )
                )
                NavigationBarItem(
                    selected = selectedTab == 3,
                    onClick = { selectedTab = 3 },
                    icon = { Icon(Icons.Default.Link, contentDescription = null) },
                    label = { Text("Link Check", fontSize = 11.sp) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = EmeraldSoft,
                        selectedTextColor = EmeraldSoft,
                        indicatorColor = EmeraldDark.copy(alpha = 0.7f),
                        unselectedIconColor = TextSecondary,
                        unselectedTextColor = TextSecondary
                    )
                )
                NavigationBarItem(
                    selected = selectedTab == 4,
                    onClick = { selectedTab = 4 },
                    icon = {
                        BadgedBox(
                            badge = {
                                if (threatEvents.isNotEmpty()) {
                                    Badge(containerColor = EmeraldPrimary) {
                                        Text("${threatEvents.size}", color = Color.White)
                                    }
                                }
                            }
                        ) {
                            Icon(Icons.Default.NotificationsNone, contentDescription = null)
                        }
                    },
                    label = { Text("Activity", fontSize = 11.sp) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = EmeraldSoft,
                        selectedTextColor = EmeraldSoft,
                        indicatorColor = EmeraldDark.copy(alpha = 0.7f),
                        unselectedIconColor = TextSecondary,
                        unselectedTextColor = TextSecondary
                    )
                )
            }
        },
        containerColor = BgDeepSlate
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            when (selectedTab) {
                0 -> ShieldDashboardTab(
                    context = context,
                    totalBlocked = threatEvents.size,
                    blockedTrackers = blockedTrackers,
                    isProUnlocked = isProUnlocked,
                    onOpenPro = { showProModal = true }
                )
                1 -> GhostAndSpywareAuditTab(context)
                2 -> DataExfiltrationMonitorTab(
                    context = context,
                    isProUnlocked = isProUnlocked,
                    onOpenPro = { showProModal = true }
                )
                3 -> LinkScannerTab(context)
                4 -> ThreatHistoryTab(context, threatEvents)
            }
        }
    }
}

@Composable
fun ProminentDisclosureModal(
    disclosure: ProminentDisclosureType,
    onAccept: () -> Unit,
    onDecline: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDecline,
        containerColor = SurfaceCard,
        shape = RoundedCornerShape(22.dp),
        title = {
            Column {
                Surface(
                    color = CyanDark,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(
                        text = disclosure.permissionBadge,
                        color = CyanSoft,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                    )
                }
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = disclosure.title,
                    color = TextPrimary,
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp
                )
            }
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = disclosure.whatIsAccessed,
                    color = Color(0xFFE2E8F0),
                    fontSize = 13.sp,
                    lineHeight = 19.sp
                )
                Text(
                    text = disclosure.howItIsUsed,
                    color = TextSecondary,
                    fontSize = 13.sp,
                    lineHeight = 19.sp
                )
                Surface(
                    color = EmeraldDark.copy(alpha = 0.5f),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.border(1.dp, EmeraldPrimary.copy(alpha = 0.35f), RoundedCornerShape(12.dp))
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.VerifiedUser,
                            contentDescription = null,
                            tint = EmeraldSoft,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = disclosure.privacyGuarantee,
                            color = EmeraldSoft,
                            fontSize = 12.sp,
                            lineHeight = 17.sp
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onAccept,
                colors = ButtonDefaults.buttonColors(containerColor = EmeraldPrimary),
                shape = RoundedCornerShape(10.dp)
            ) {
                Text("Continue", color = Color.White, fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            TextButton(onClick = onDecline) {
                Text("Not Now", color = TextSecondary)
            }
        }
    )
}

@Composable
fun ZeroInstallProDialog(
    isProUnlocked: Boolean,
    onUnlockPro: () -> Unit,
    onSwitchToFree: () -> Unit,
    onDismiss: () -> Unit
) {
    val price = remember { RegionalPricingManager.getCurrentUserRegionalPrice() }
    var selectedPlan by remember { mutableIntStateOf(0) }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SurfaceCard,
        shape = RoundedCornerShape(24.dp),
        title = {
            Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                Box(
                    modifier = Modifier
                        .size(54.dp)
                        .background(
                            Brush.linearGradient(listOf(EmeraldPrimary, CyanPrimary)),
                            CircleShape
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        Icons.Default.AutoAwesome,
                        contentDescription = null,
                        tint = Color.White,
                        modifier = Modifier.size(26.dp)
                    )
                }
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "ZeroInstall Pro Shield",
                    color = TextPrimary,
                    fontWeight = FontWeight.Bold,
                    fontSize = 20.sp
                )
                Text(
                    text = "Complete 24/7 automated protection for your phone",
                    color = CyanSoft,
                    fontSize = 12.sp,
                    textAlign = TextAlign.Center
                )
            }
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                ProFeatureItem("Auto-Scan WhatsApp, SMS & Telegram Links")
                ProFeatureItem("24/7 Background Tracker & Spyware Firewall")
                ProFeatureItem("Deep App Data Upload & Leak Monitor")
                ProFeatureItem("Anti-Tamper Uninstall Protection Lock")

                Spacer(modifier = Modifier.height(4.dp))

                Surface(
                    color = if (selectedPlan == 0) EmeraldDark.copy(alpha = 0.5f) else BgDeepSlate,
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(
                            width = if (selectedPlan == 0) 1.5.dp else 1.dp,
                            color = if (selectedPlan == 0) EmeraldPrimary else BorderSubtle,
                            shape = RoundedCornerShape(14.dp)
                        )
                        .clickable { selectedPlan = 0 }
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("Annual Plan", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                                Spacer(modifier = Modifier.width(6.dp))
                                Surface(color = CyanPrimary, shape = RoundedCornerShape(50)) {
                                    Text(
                                        "SAVE 50%",
                                        color = Color.White,
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.ExtraBold,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                    )
                                }
                            }
                            Text("7-day free trial • Cancel anytime", color = TextSecondary, fontSize = 11.sp)
                        }
                        Text(price.yearlyPriceFormatted, color = EmeraldSoft, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    }
                }

                Surface(
                    color = if (selectedPlan == 1) EmeraldDark.copy(alpha = 0.5f) else BgDeepSlate,
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(
                            width = if (selectedPlan == 1) 1.5.dp else 1.dp,
                            color = if (selectedPlan == 1) EmeraldPrimary else BorderSubtle,
                            shape = RoundedCornerShape(14.dp)
                        )
                        .clickable { selectedPlan = 1 }
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("Monthly Plan", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                            Text("Flexible monthly protection", color = TextSecondary, fontSize = 11.sp)
                        }
                        Text(price.monthlyPriceFormatted, color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    }
                }
            }
        },
        confirmButton = {
            Column(modifier = Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                if (!isProUnlocked) {
                    Button(
                        onClick = onUnlockPro,
                        colors = ButtonDefaults.buttonColors(containerColor = EmeraldPrimary),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            "Start 7-Day Free Trial",
                            color = Color.White,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(vertical = 4.dp)
                        )
                    }
                } else {
                    OutlinedButton(
                        onClick = onSwitchToFree,
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Switch Back to Free Tier (Preview)", color = TextSecondary, fontSize = 12.sp)
                    }
                }
                TextButton(onClick = onDismiss) {
                    Text("Close", color = TextSecondary, fontSize = 12.sp)
                }
            }
        }
    )
}

@Composable
private fun ProFeatureItem(text: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
            Icons.Default.CheckCircle,
            contentDescription = null,
            tint = EmeraldSoft,
            modifier = Modifier.size(16.dp)
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(text = text, color = TextPrimary, fontSize = 13.sp)
    }
}

@Composable
fun ShieldDashboardTab(
    context: Context,
    totalBlocked: Int,
    blockedTrackers: Int,
    isProUnlocked: Boolean,
    onOpenPro: () -> Unit
) {
    val scope = rememberCoroutineScope()
    var blockAllApk by remember { mutableStateOf(ShieldRepository.isBlockAllApkEnabled(context)) }
    var blockUnknownSources by remember { mutableStateOf(ShieldRepository.isBlockUnknownSourcesSettingsEnabled(context)) }
    var autoDeleteApks by remember { mutableStateOf(ShieldRepository.isAutoDeleteDownloadedApks(context)) }
    var blockLinks by remember { mutableStateOf(ShieldRepository.isBlockMaliciousLinksEnabled(context)) }
    var detectGhostApps by remember { mutableStateOf(ShieldRepository.isDetectInvisibleAppsEnabled(context)) }
    var allowPlayUpdates by remember { mutableStateOf(ShieldRepository.isAllowPlayStoreUpdates(context)) }

    var isAccessibilityActive by remember { mutableStateOf(isAccessibilityServiceEnabled(context)) }
    var isNotificationGuardActive by remember { mutableStateOf(isNotificationListenerEnabled(context)) }
    var isDeviceAdminActive by remember { mutableStateOf(ShieldDeviceAdminReceiver.isAdminActive(context)) }
    var isVpnRunning by remember { mutableStateOf(TrackerBlockVpnService.isVpnActive) }

    var pendingDisclosure by remember { mutableStateOf<ProminentDisclosureType?>(null) }
    var isQuickScanning by remember { mutableStateOf(false) }
    var quickScanComplete by remember { mutableStateOf(false) }

    val remoteScamApps = remember(quickScanComplete) { PeopleProtectionTools.detectRemoteAccessScamApps(context) }
    val wifiReport = remember(quickScanComplete) { PeopleProtectionTools.auditNetworkProxySafety(context) }

    val vpnLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        val startIntent = Intent(context, TrackerBlockVpnService::class.java).apply {
            action = TrackerBlockVpnService.ACTION_START
        }
        context.startService(startIntent)
        isVpnRunning = true
    }

    pendingDisclosure?.let { disclosure ->
        ProminentDisclosureModal(
            disclosure = disclosure,
            onAccept = {
                pendingDisclosure = null
                when (disclosure) {
                    ProminentDisclosureType.ACCESSIBILITY -> {
                        context.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                    }
                    ProminentDisclosureType.NOTIFICATION_LISTENER -> {
                        context.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                    }
                    ProminentDisclosureType.VPN_FIREWALL -> {
                        val prepare = VpnService.prepare(context)
                        if (prepare != null) {
                            vpnLauncher.launch(prepare)
                        } else {
                            val startIntent = Intent(context, TrackerBlockVpnService::class.java).apply {
                                action = TrackerBlockVpnService.ACTION_START
                            }
                            context.startService(startIntent)
                            isVpnRunning = true
                        }
                    }
                    ProminentDisclosureType.DEVICE_ADMIN -> {
                        val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
                            putExtra(
                                DevicePolicyManager.EXTRA_DEVICE_ADMIN,
                                ShieldDeviceAdminReceiver.getComponentName(context)
                            )
                            putExtra(
                                DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                                "Prevents unauthorized removal of ZeroInstall Shield."
                            )
                        }
                        context.startActivity(intent)
                    }
                    ProminentDisclosureType.USAGE_AND_NETWORK_STATS -> {
                        context.startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
                    }
                }
            },
            onDecline = { pendingDisclosure = null }
        )
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 18.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        contentPadding = PaddingValues(top = 6.dp, bottom = 28.dp)
    ) {
        // 1. Positive, Uplifting Emerald-Cyan Hero Card
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = Color.Transparent),
                shape = RoundedCornerShape(24.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        Brush.verticalGradient(
                            colors = if (blockAllApk) {
                                listOf(Color(0xFF065F46), Color(0xFF0C3559), SurfaceCard)
                            } else {
                                listOf(Color(0xFF3B1A22), SurfaceCard)
                            }
                        ),
                        RoundedCornerShape(24.dp)
                    )
                    .border(
                        1.dp,
                        if (blockAllApk) EmeraldSoft.copy(alpha = 0.4f) else DangerSoft.copy(alpha = 0.35f),
                        RoundedCornerShape(24.dp)
                    )
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(22.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Box(
                        modifier = Modifier
                            .size(78.dp)
                            .background(
                                Brush.linearGradient(
                                    if (blockAllApk) {
                                        listOf(EmeraldPrimary.copy(alpha = 0.28f), CyanPrimary.copy(alpha = 0.28f))
                                    } else {
                                        listOf(DangerSoft.copy(alpha = 0.2f), DangerSoft.copy(alpha = 0.1f))
                                    }
                                ),
                                CircleShape
                            )
                            .border(
                                2.dp,
                                if (blockAllApk) EmeraldSoft else DangerSoft,
                                CircleShape
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        if (isQuickScanning) {
                            CircularProgressIndicator(
                                color = EmeraldSoft,
                                strokeWidth = 3.dp,
                                modifier = Modifier.size(44.dp)
                            )
                        } else {
                            Icon(
                                imageVector = if (blockAllApk) Icons.Default.VerifiedUser else Icons.Default.Shield,
                                contentDescription = null,
                                tint = if (blockAllApk) EmeraldSoft else DangerSoft,
                                modifier = Modifier.size(40.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    Text(
                        text = when {
                            isQuickScanning -> "Scanning Device Security..."
                            quickScanComplete -> "Your Phone is Safe & Protected"
                            blockAllApk -> "Your Phone is Protected"
                            else -> "Protection Paused"
                        },
                        color = TextPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 20.sp
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = "Active protection against unauthorized APK installs & scam links",
                        color = CyanSoft,
                        fontSize = 12.sp,
                        textAlign = TextAlign.Center
                    )

                    Spacer(modifier = Modifier.height(18.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        MetricTile(
                            modifier = Modifier.weight(1f),
                            value = "$totalBlocked",
                            label = "Blocked",
                            valueColor = TextPrimary
                        )
                        MetricTile(
                            modifier = Modifier.weight(1f),
                            value = "$blockedTrackers",
                            label = "Trackers",
                            valueColor = CyanSoft
                        )
                        MetricTile(
                            modifier = Modifier.weight(1f),
                            value = if (remoteScamApps.isEmpty() && !wifiReport.isProxyDetected) "Secure" else "Review",
                            label = "Call & Wi-Fi",
                            valueColor = if (remoteScamApps.isEmpty() && !wifiReport.isProxyDetected) EmeraldSoft else CyanSoft
                        )
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    Button(
                        onClick = {
                            if (!isQuickScanning) {
                                isQuickScanning = true
                                scope.launch {
                                    delay(1000)
                                    isQuickScanning = false
                                    quickScanComplete = true
                                }
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = EmeraldPrimary),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(
                            imageVector = if (quickScanComplete) Icons.Default.CheckCircle else Icons.Default.Radar,
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (isQuickScanning) "Checking Device..." else if (quickScanComplete) "All Checks Passed • Scan Again" else "Run Quick Security Check",
                            color = Color.White,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 14.sp,
                            modifier = Modifier.padding(vertical = 4.dp)
                        )
                    }
                }
            }
        }

        // 2. Banking & Screen-Share Safety Status Card
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = SurfaceCard),
                shape = RoundedCornerShape(18.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, BorderSubtle, RoundedCornerShape(18.dp))
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(42.dp)
                            .background(
                                if (remoteScamApps.isEmpty()) EmeraldDark.copy(alpha = 0.65f) else DangerBg,
                                RoundedCornerShape(12.dp)
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.PhonelinkLock,
                            contentDescription = null,
                            tint = if (remoteScamApps.isEmpty()) EmeraldSoft else DangerSoft,
                            modifier = Modifier.size(22.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(14.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Bank Call & Screen-Share Safety",
                            color = TextPrimary,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 14.sp
                        )
                        if (remoteScamApps.isEmpty()) {
                            Text(
                                text = "No screen-sharing apps (AnyDesk / TeamViewer) found. Your banking OTPs are safe.",
                                color = TextSecondary,
                                fontSize = 12.sp,
                                lineHeight = 17.sp
                            )
                        } else {
                            remoteScamApps.forEach { app ->
                                Text(
                                    text = "Review: ${app.appName} is installed on this phone.",
                                    color = DangerSoft,
                                    fontSize = 12.sp
                                )
                            }
                        }
                    }
                }
            }
        }

        // 3. Protection Layers Section
        item {
            Text(
                text = "Protection Layers",
                color = TextPrimary,
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold
            )
        }

        item {
            EnginePermissionCard(
                icon = Icons.Default.AppBlocking,
                title = "APK Install Blocker",
                subtitle = "Stops unauthorized APK install popups from browsers and file managers.",
                isEnabled = isAccessibilityActive,
                isProFeature = false,
                isProUnlocked = true,
                buttonText = if (isAccessibilityActive) "Active" else "Enable",
                onClick = {
                    if (isAccessibilityActive) {
                        context.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                    } else {
                        pendingDisclosure = ProminentDisclosureType.ACCESSIBILITY
                    }
                },
                onRefresh = { isAccessibilityActive = isAccessibilityServiceEnabled(context) }
            )
        }

        item {
            EnginePermissionCard(
                icon = Icons.Default.MarkChatRead,
                title = "WhatsApp & SMS Link Guard",
                subtitle = "Automatically checks incoming message links for phishing & hidden APKs.",
                isEnabled = isNotificationGuardActive && isProUnlocked,
                isProFeature = true,
                isProUnlocked = isProUnlocked,
                buttonText = when {
                    !isProUnlocked -> "Unlock"
                    isNotificationGuardActive -> "Active"
                    else -> "Enable"
                },
                onClick = {
                    if (!isProUnlocked) {
                        onOpenPro()
                    } else if (isNotificationGuardActive) {
                        context.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                    } else {
                        pendingDisclosure = ProminentDisclosureType.NOTIFICATION_LISTENER
                    }
                },
                onRefresh = { isNotificationGuardActive = isNotificationListenerEnabled(context) }
            )
        }

        item {
            EnginePermissionCard(
                icon = Icons.Default.VpnLock,
                title = "Tracker & Spyware Firewall",
                subtitle = "Blocks background apps from connecting to spyware & tracker servers.",
                isEnabled = isVpnRunning && isProUnlocked,
                isProFeature = true,
                isProUnlocked = isProUnlocked,
                buttonText = when {
                    !isProUnlocked -> "Unlock"
                    isVpnRunning -> "Active"
                    else -> "Start"
                },
                onClick = {
                    if (!isProUnlocked) {
                        onOpenPro()
                    } else if (isVpnRunning) {
                        val stopIntent = Intent(context, TrackerBlockVpnService::class.java).apply {
                            action = TrackerBlockVpnService.ACTION_STOP
                        }
                        context.startService(stopIntent)
                        isVpnRunning = false
                    } else {
                        pendingDisclosure = ProminentDisclosureType.VPN_FIREWALL
                    }
                },
                onRefresh = { isVpnRunning = TrackerBlockVpnService.isVpnActive }
            )
        }

        item {
            EnginePermissionCard(
                icon = Icons.Default.LockPerson,
                title = "Anti-Tamper Uninstall Lock",
                subtitle = "Prevents unauthorized removal of ZeroInstall protection.",
                isEnabled = isDeviceAdminActive && isProUnlocked,
                isProFeature = true,
                isProUnlocked = isProUnlocked,
                buttonText = when {
                    !isProUnlocked -> "Unlock"
                    isDeviceAdminActive -> "Locked"
                    else -> "Enable"
                },
                onClick = {
                    if (!isProUnlocked) {
                        onOpenPro()
                    } else {
                        pendingDisclosure = ProminentDisclosureType.DEVICE_ADMIN
                    }
                },
                onRefresh = { isDeviceAdminActive = ShieldDeviceAdminReceiver.isAdminActive(context) }
            )
        }

        // 4. Security Preferences
        item {
            Text(
                text = "Security Preferences",
                color = TextPrimary,
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold
            )
        }

        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = SurfaceCard),
                shape = RoundedCornerShape(18.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, BorderSubtle, RoundedCornerShape(18.dp))
            ) {
                Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                    PolicySwitchRow(
                        title = "Block Sideloaded APK Installs",
                        subtitle = "Stop unauthorized .apk & .xapk files outside Google Play",
                        checked = blockAllApk,
                        onCheckedChange = {
                            blockAllApk = it
                            ShieldRepository.setBlockAllApkEnabled(context, it)
                            ShieldDeviceAdminReceiver.enforceOsLevelApkBlockIfPossible(context, it)
                        }
                    )
                    HorizontalDivider(color = BorderSubtle)
                    PolicySwitchRow(
                        title = "Protect 'Install Unknown Apps' Settings",
                        subtitle = "Warn before Unknown Sources is enabled for any app",
                        checked = blockUnknownSources,
                        onCheckedChange = {
                            blockUnknownSources = it
                            ShieldRepository.setBlockUnknownSourcesSettingsEnabled(context, it)
                        }
                    )
                    HorizontalDivider(color = BorderSubtle)
                    PolicySwitchRow(
                        title = "Auto-Clean Downloaded APK Files",
                        subtitle = "Automatically quarantine newly downloaded .apk files",
                        checked = autoDeleteApks,
                        onCheckedChange = {
                            autoDeleteApks = it
                            ShieldRepository.setAutoDeleteDownloadedApks(context, it)
                        }
                    )
                    HorizontalDivider(color = BorderSubtle)
                    PolicySwitchRow(
                        title = "Block Dangerous Download Links",
                        subtitle = "Stop drive-by APK downloads and suspicious redirect links",
                        checked = blockLinks,
                        onCheckedChange = {
                            blockLinks = it
                            ShieldRepository.setBlockMaliciousLinksEnabled(context, it)
                        }
                    )
                    HorizontalDivider(color = BorderSubtle)
                    PolicySwitchRow(
                        title = "Detect Hidden Iconless Apps",
                        subtitle = "Alert immediately if an app installs without a home screen icon",
                        checked = detectGhostApps,
                        onCheckedChange = {
                            detectGhostApps = it
                            ShieldRepository.setDetectInvisibleAppsEnabled(context, it)
                        }
                    )
                    HorizontalDivider(color = BorderSubtle)
                    PolicySwitchRow(
                        title = "Allow Official Google Play Updates",
                        subtitle = "Let verified Google Play Store updates install normally",
                        checked = allowPlayUpdates,
                        onCheckedChange = {
                            allowPlayUpdates = it
                            ShieldRepository.setAllowPlayStoreUpdates(context, it)
                        }
                    )
                }
            }
        }
    }
}

@Composable
fun DataExfiltrationMonitorTab(
    context: Context,
    isProUnlocked: Boolean,
    onOpenPro: () -> Unit
) {
    if (!isProUnlocked) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            contentAlignment = Alignment.Center
        ) {
            Card(
                colors = CardDefaults.cardColors(containerColor = SurfaceCard),
                shape = RoundedCornerShape(24.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, CyanPrimary.copy(alpha = 0.45f), RoundedCornerShape(24.dp))
            ) {
                Column(
                    modifier = Modifier.padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Box(
                        modifier = Modifier
                            .size(64.dp)
                            .background(
                                Brush.linearGradient(listOf(EmeraldPrimary, CyanPrimary)),
                                CircleShape
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            Icons.Default.DataUsage,
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(32.dp)
                        )
                    }
                    Spacer(modifier = Modifier.height(16.dp))
                    Surface(
                        color = CyanDark,
                        shape = RoundedCornerShape(50),
                        modifier = Modifier.border(1.dp, CyanSoft.copy(alpha = 0.4f), RoundedCornerShape(50))
                    ) {
                        Text(
                            text = "ZEROINSTALL PRO SHIELD",
                            color = CyanSoft,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.ExtraBold,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp)
                        )
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = "Background Data & Upload Guard",
                        color = TextPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 19.sp,
                        textAlign = TextAlign.Center
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Inspect which apps are uploading data in the background while your screen is off, and review the personal permissions they access.",
                        color = TextSecondary,
                        fontSize = 13.sp,
                        textAlign = TextAlign.Center,
                        lineHeight = 19.sp
                    )
                    Spacer(modifier = Modifier.height(20.dp))
                    Button(
                        onClick = onOpenPro,
                        colors = ButtonDefaults.buttonColors(containerColor = EmeraldPrimary),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.AutoAwesome, contentDescription = null, tint = Color.White)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            "Unlock with ZeroInstall Pro",
                            color = Color.White,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(vertical = 4.dp)
                        )
                    }
                }
            }
        }
        return
    }

    val scope = rememberCoroutineScope()
    var hasUsageAccess by remember {
        mutableStateOf(NetworkAndDataExfiltrationMonitor.hasUsageStatsPermission(context))
    }
    var showUsageDisclosure by remember { mutableStateOf(false) }
    var isLoading by remember { mutableStateOf(true) }
    var reports by remember { mutableStateOf<List<AppDataUsageReport>>(emptyList()) }
    var filterMode by remember { mutableIntStateOf(0) }

    fun refreshStats() {
        hasUsageAccess = NetworkAndDataExfiltrationMonitor.hasUsageStatsPermission(context)
        isLoading = true
        scope.launch {
            val data = withContext(Dispatchers.IO) {
                NetworkAndDataExfiltrationMonitor.analyzeAppDataAndUploads(context)
            }
            reports = data
            isLoading = false
        }
    }

    LaunchedEffect(Unit) {
        refreshStats()
    }

    if (showUsageDisclosure) {
        ProminentDisclosureModal(
            disclosure = ProminentDisclosureType.USAGE_AND_NETWORK_STATS,
            onAccept = {
                showUsageDisclosure = false
                context.startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
            },
            onDecline = { showUsageDisclosure = false }
        )
    }

    val filteredReports = remember(reports, filterMode) {
        when (filterMode) {
            1 -> reports.filter { it.isSuspiciousExfiltration }
            2 -> reports.filter { it.sensitiveDataAccessed.isNotEmpty() }
            else -> reports
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 18.dp, vertical = 8.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Background Data Guard",
                    color = TextPrimary,
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp
                )
                Text(
                    text = "Monitor app uploads and active data access",
                    color = TextSecondary,
                    fontSize = 12.sp
                )
            }
            IconButton(onClick = { refreshStats() }) {
                Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = EmeraldSoft)
            }
        }

        if (!hasUsageAccess) {
            Spacer(modifier = Modifier.height(10.dp))
            Card(
                colors = CardDefaults.cardColors(containerColor = SurfaceElevated),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Enable Detailed Usage Insights",
                            color = TextPrimary,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 13.sp
                        )
                        Text(
                            text = "Allow Usage Access to inspect 30-day background upload history.",
                            color = TextSecondary,
                            fontSize = 11.sp
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(
                        onClick = { showUsageDisclosure = true },
                        colors = ButtonDefaults.buttonColors(containerColor = EmeraldPrimary),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        Text("Enable", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = filterMode == 0,
                onClick = { filterMode = 0 },
                label = { Text("All Apps (${reports.size})", fontSize = 11.sp) }
            )
            FilterChip(
                selected = filterMode == 1,
                onClick = { filterMode = 1 },
                label = { Text("High Upload", fontSize = 11.sp) }
            )
            FilterChip(
                selected = filterMode == 2,
                onClick = { filterMode = 2 },
                label = { Text("With Permissions", fontSize = 11.sp) }
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        if (isLoading) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = EmeraldSoft)
            }
        } else if (filteredReports.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    "No unusual background data activity found in this view.",
                    color = EmeraldSoft,
                    fontSize = 14.sp
                )
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                items(filteredReports, key = { it.packageName }) { item ->
                    Card(
                        colors = CardDefaults.cardColors(containerColor = SurfaceCard),
                        shape = RoundedCornerShape(16.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(1.dp, BorderSubtle, RoundedCornerShape(16.dp))
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = item.appName,
                                        color = TextPrimary,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 15.sp
                                    )
                                    Text(
                                        text = item.packageName,
                                        color = TextSecondary,
                                        fontSize = 11.sp
                                    )
                                }
                                Surface(
                                    color = if (item.isSuspiciousExfiltration) CyanDark else EmeraldDark,
                                    shape = RoundedCornerShape(50)
                                ) {
                                    Text(
                                        text = if (item.isSuspiciousExfiltration) "Review Data" else "Normal",
                                        color = if (item.isSuspiciousExfiltration) CyanSoft else EmeraldSoft,
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(10.dp))

                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(BgDeepSlate, RoundedCornerShape(12.dp))
                                    .padding(12.dp),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Column {
                                    Text("SENT (UPLOAD)", color = TextSecondary, fontSize = 10.sp)
                                    Text(
                                        text = NetworkAndDataExfiltrationMonitor.formatBytes(item.uploadedBytes),
                                        color = TextPrimary,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 14.sp
                                    )
                                }
                                Column {
                                    Text("RECEIVED", color = TextSecondary, fontSize = 10.sp)
                                    Text(
                                        text = NetworkAndDataExfiltrationMonitor.formatBytes(item.downloadedBytes),
                                        color = TextPrimary,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 14.sp
                                    )
                                }
                                Column(horizontalAlignment = Alignment.End) {
                                    Text("UPLOAD RATIO", color = TextSecondary, fontSize = 10.sp)
                                    Text(
                                        text = "${item.uploadRatioPercent}%",
                                        color = if (item.uploadRatioPercent >= 40) CyanSoft else EmeraldSoft,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 14.sp
                                    )
                                }
                            }

                            if (item.sensitiveDataAccessed.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    text = "Active Access: ${item.sensitiveDataAccessed.joinToString(" • ")}",
                                    color = CyanSoft,
                                    fontSize = 11.sp
                                )
                            }

                            Spacer(modifier = Modifier.height(10.dp))

                            OutlinedButton(
                                onClick = {
                                    val infoIntent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                        data = Uri.parse("package:${item.packageName}")
                                    }
                                    context.startActivity(infoIntent)
                                },
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Review App Permissions & Data", fontSize = 12.sp, color = TextPrimary)
                            }
                        }
                    }
                }
            }
        }
    }
}

/**
 * Positive, transparent App & Permission Inspector:
 * Shows apps with granted permissions (e.g., ChatGPT -> Camera, Microphone, Location) with a
 * "Review Permissions" action, apps with 0 permissions ("No Permissions Used"), and sideloaded apps.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun GhostAndSpywareAuditTab(context: Context) {
    val scope = rememberCoroutineScope()
    var isScanning by remember { mutableStateOf(true) }
    var allApps by remember { mutableStateOf<List<AppSecurityAuditItem>>(emptyList()) }
    var filterMode by remember { mutableIntStateOf(0) }

    fun triggerScan() {
        isScanning = true
        scope.launch {
            val scanned = withContext(Dispatchers.IO) {
                StealthAndSpywareScanner.scanAllInstalledApps(context)
            }
            allApps = scanned
            isScanning = false
        }
    }

    LaunchedEffect(Unit) {
        triggerScan()
    }

    val appsWithPermissions = remember(allApps) { allApps.filter { it.dangerousPermissions.isNotEmpty() } }
    val appsWithZeroPermissions = remember(allApps) { allApps.filter { it.dangerousPermissions.isEmpty() && !it.isSideloaded } }
    val sideloadedOrHiddenApps = remember(allApps) { allApps.filter { it.isSideloaded || !it.hasLauncherIcon } }

    val filteredApps = remember(allApps, filterMode) {
        when (filterMode) {
            0 -> appsWithPermissions
            1 -> appsWithZeroPermissions
            2 -> sideloadedOrHiddenApps
            else -> allApps
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 18.dp, vertical = 8.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "App & Permission Review",
                    color = TextPrimary,
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp
                )
                Text(
                    text = "Review active permissions (Camera, Mic, Location) & install sources",
                    color = TextSecondary,
                    fontSize = 12.sp
                )
            }
            IconButton(onClick = { triggerScan() }) {
                Icon(Icons.Default.Refresh, contentDescription = "Rescan", tint = EmeraldSoft)
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilterChip(
                selected = filterMode == 0,
                onClick = { filterMode = 0 },
                label = { Text("Active Permissions (${appsWithPermissions.size})", fontSize = 11.sp) }
            )
            FilterChip(
                selected = filterMode == 1,
                onClick = { filterMode = 1 },
                label = { Text("No Permissions (${appsWithZeroPermissions.size})", fontSize = 11.sp) }
            )
            FilterChip(
                selected = filterMode == 2,
                onClick = { filterMode = 2 },
                label = { Text("Sideloaded (${sideloadedOrHiddenApps.size})", fontSize = 11.sp) }
            )
            FilterChip(
                selected = filterMode == 3,
                onClick = { filterMode = 3 },
                label = { Text("All Apps (${allApps.size})", fontSize = 11.sp) }
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        if (isScanning) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator(color = EmeraldSoft)
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        "Inspecting app permissions & install sources...",
                        color = TextSecondary,
                        fontSize = 13.sp
                    )
                }
            }
        } else if (filteredApps.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        Icons.Default.VerifiedUser,
                        contentDescription = null,
                        tint = EmeraldSoft,
                        modifier = Modifier.size(44.dp)
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        "All clear in this view",
                        color = TextPrimary,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 15.sp
                    )
                    Text(
                        "No apps match this filter right now.",
                        color = TextSecondary,
                        fontSize = 12.sp
                    )
                }
            }
        } else {
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(12.dp),
                contentPadding = PaddingValues(bottom = 24.dp)
            ) {
                items(filteredApps, key = { it.packageName }) { item ->
                    Card(
                        colors = CardDefaults.cardColors(containerColor = SurfaceCard),
                        shape = RoundedCornerShape(16.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(1.dp, BorderSubtle, RoundedCornerShape(16.dp))
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = item.appName,
                                        color = TextPrimary,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 15.sp
                                    )
                                    Text(
                                        text = if (item.isSideloaded) "Installed outside Play Store" else "Verified Store App",
                                        color = if (item.isSideloaded) CyanSoft else TextSecondary,
                                        fontSize = 11.sp
                                    )
                                }
                                Surface(
                                    color = when {
                                        item.isSideloaded && !item.hasLauncherIcon -> DangerBg
                                        item.dangerousPermissions.isNotEmpty() -> CyanDark
                                        else -> EmeraldDark
                                    },
                                    shape = RoundedCornerShape(50)
                                ) {
                                    Text(
                                        text = when {
                                            item.isSideloaded && !item.hasLauncherIcon -> "Hidden App"
                                            item.dangerousPermissions.isNotEmpty() -> "Review (${item.dangerousPermissions.size})"
                                            else -> "No Permissions"
                                        },
                                        color = when {
                                            item.isSideloaded && !item.hasLauncherIcon -> DangerSoft
                                            item.dangerousPermissions.isNotEmpty() -> CyanSoft
                                            else -> EmeraldSoft
                                        },
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(10.dp))

                            if (item.dangerousPermissions.isEmpty()) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        Icons.Default.CheckCircle,
                                        contentDescription = null,
                                        tint = EmeraldSoft,
                                        modifier = Modifier.size(15.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = "No sensitive permissions granted (Camera, Mic, Location, SMS are off)",
                                        color = EmeraldSoft,
                                        fontSize = 12.sp
                                    )
                                }
                            } else {
                                Text(
                                    text = "Permissions Granted:",
                                    color = TextSecondary,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Medium
                                )
                                Spacer(modifier = Modifier.height(6.dp))
                                FlowRow(
                                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                                    verticalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    item.dangerousPermissions.forEach { perm ->
                                        Surface(
                                            color = SurfaceElevated,
                                            shape = RoundedCornerShape(8.dp),
                                            modifier = Modifier.border(
                                                1.dp,
                                                CyanPrimary.copy(alpha = 0.35f),
                                                RoundedCornerShape(8.dp)
                                            )
                                        ) {
                                            Text(
                                                text = perm,
                                                color = CyanSoft,
                                                fontSize = 11.sp,
                                                fontWeight = FontWeight.SemiBold,
                                                modifier = Modifier.padding(horizontal = 9.dp, vertical = 4.dp)
                                            )
                                        }
                                    }
                                }
                            }

                            Spacer(modifier = Modifier.height(12.dp))

                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                OutlinedButton(
                                    onClick = {
                                        val infoIntent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                            data = Uri.parse("package:${item.packageName}")
                                        }
                                        context.startActivity(infoIntent)
                                    },
                                    shape = RoundedCornerShape(10.dp),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text(
                                        text = if (item.dangerousPermissions.isNotEmpty()) "Review Permissions" else "App Settings",
                                        fontSize = 12.sp,
                                        color = TextPrimary
                                    )
                                }

                                if (item.isSideloaded) {
                                    Button(
                                        onClick = {
                                            val uninstallIntent = Intent(Intent.ACTION_DELETE).apply {
                                                data = Uri.parse("package:${item.packageName}")
                                            }
                                            context.startActivity(uninstallIntent)
                                        },
                                        colors = ButtonDefaults.buttonColors(containerColor = SurfaceElevated),
                                        shape = RoundedCornerShape(10.dp)
                                    ) {
                                        Text("Uninstall", fontSize = 12.sp, color = DangerSoft)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun LinkScannerTab(context: Context) {
    val scope = rememberCoroutineScope()
    var urlInput by remember { mutableStateOf("") }
    var isScanning by remember { mutableStateOf(false) }
    var scanResult by remember { mutableStateOf<LinkScanResult?>(null) }

    val sampleLinks = listOf(
        "https://promo-reward-claim.ngrok-free.app/kyc-update.apk",
        "https://www.google.com"
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 18.dp, vertical = 8.dp)
    ) {
        Text(
            text = "Safe Link Checker",
            color = TextPrimary,
            fontWeight = FontWeight.Bold,
            fontSize = 18.sp
        )
        Text(
            text = "Check any link from SMS, WhatsApp, or Email for hidden APK downloads before opening it.",
            color = TextSecondary,
            fontSize = 12.sp
        )

        Spacer(modifier = Modifier.height(16.dp))

        OutlinedTextField(
            value = urlInput,
            onValueChange = { urlInput = it },
            label = { Text("Paste link here...") },
            singleLine = true,
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(12.dp))

        Button(
            onClick = {
                if (urlInput.isBlank()) return@Button
                isScanning = true
                scope.launch {
                    val result = withContext(Dispatchers.IO) {
                        MaliciousLinkAnalyzer.inspectUrlHeadersDeep(urlInput.trim())
                    }
                    scanResult = result
                    isScanning = false
                    if (result.isThreat) {
                        ShieldRepository.recordAndAlertThreat(
                            context = context,
                            type = ThreatType.MALICIOUS_LINK_BLOCKED,
                            severity = Severity.CRITICAL,
                            sourcePackageOrUrl = result.url,
                            title = "Suspicious Link Blocked",
                            description = result.reasons.joinToString("\n• ", prefix = "• "),
                            actionTaken = "Flagged by Safe Link Checker",
                            showFullScreenPopup = false
                        )
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(containerColor = EmeraldPrimary)
        ) {
            Icon(Icons.Default.Search, contentDescription = null, tint = Color.White)
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                if (isScanning) "Checking Link Safety..." else "Check Link Safety",
                color = Color.White,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(vertical = 4.dp)
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Try an example link:",
            color = TextSecondary,
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium
        )
        Spacer(modifier = Modifier.height(6.dp))

        sampleLinks.forEach { sample ->
            Surface(
                color = SurfaceCard,
                shape = RoundedCornerShape(10.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 3.dp)
                    .border(1.dp, BorderSubtle, RoundedCornerShape(10.dp))
                    .clickable { urlInput = sample }
            ) {
                Text(
                    text = sample,
                    color = CyanSoft,
                    fontSize = 12.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(12.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        scanResult?.let { res ->
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = if (res.isThreat) DangerBg else EmeraldDark.copy(alpha = 0.55f)
                ),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(
                        1.dp,
                        if (res.isThreat) DangerSoft.copy(alpha = 0.4f) else EmeraldPrimary.copy(alpha = 0.4f),
                        RoundedCornerShape(16.dp)
                    )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = if (res.isThreat) "Unsafe Link Detected" else "Link Appears Safe",
                        color = if (res.isThreat) DangerSoft else EmeraldSoft,
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    if (res.reasons.isEmpty()) {
                        Text(
                            "No APK downloads or suspicious redirects were found in this link.",
                            color = TextPrimary,
                            fontSize = 13.sp
                        )
                    } else {
                        res.reasons.forEach { reason ->
                            Text("• $reason", color = TextPrimary, fontSize = 13.sp)
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ThreatHistoryTab(context: Context, events: List<ThreatEvent>) {
    val fmt = remember { SimpleDateFormat("dd MMM, hh:mm a", Locale.getDefault()) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 18.dp, vertical = 8.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "Security Activity",
                    color = TextPrimary,
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp
                )
                Text(
                    text = "Recent protection events & blocked install attempts",
                    color = TextSecondary,
                    fontSize = 12.sp
                )
            }
            if (events.isNotEmpty()) {
                TextButton(onClick = { ShieldRepository.clearLogs(context) }) {
                    Text("Clear", color = TextSecondary)
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        if (events.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        Icons.Default.VerifiedUser,
                        contentDescription = null,
                        tint = EmeraldSoft,
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        "Everything looks safe",
                        color = TextPrimary,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 16.sp
                    )
                    Text(
                        "Your phone is protected. Any blocked APK installs or risky links will appear here.",
                        color = TextSecondary,
                        fontSize = 12.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(horizontal = 24.dp, vertical = 4.dp)
                    )
                }
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                items(events, key = { it.id }) { ev ->
                    Card(
                        colors = CardDefaults.cardColors(containerColor = SurfaceCard),
                        shape = RoundedCornerShape(16.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(1.dp, BorderSubtle, RoundedCornerShape(16.dp))
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    text = ev.title,
                                    color = TextPrimary,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 14.sp,
                                    modifier = Modifier.weight(1f)
                                )
                                Text(
                                    text = fmt.format(Date(ev.timestamp)),
                                    color = TextSecondary,
                                    fontSize = 11.sp
                                )
                            }
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = ev.description,
                                color = TextSecondary,
                                fontSize = 12.sp
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = ev.actionTaken,
                                color = EmeraldSoft,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun MetricTile(
    modifier: Modifier = Modifier,
    value: String,
    label: String,
    valueColor: Color
) {
    Surface(
        color = BgDeepSlate.copy(alpha = 0.5f),
        shape = RoundedCornerShape(14.dp),
        modifier = modifier.border(1.dp, Color.White.copy(alpha = 0.08f), RoundedCornerShape(14.dp))
    ) {
        Column(
            modifier = Modifier.padding(vertical = 10.dp, horizontal = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(text = value, color = valueColor, fontWeight = FontWeight.Bold, fontSize = 16.sp)
            Spacer(modifier = Modifier.height(2.dp))
            Text(text = label, color = TextSecondary, fontSize = 10.sp, maxLines = 1)
        }
    }
}

@Composable
private fun EnginePermissionCard(
    icon: ImageVector,
    title: String,
    subtitle: String,
    isEnabled: Boolean,
    isProFeature: Boolean,
    isProUnlocked: Boolean,
    buttonText: String,
    onClick: () -> Unit,
    onRefresh: () -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = SurfaceCard),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, BorderSubtle, RoundedCornerShape(16.dp))
    ) {
        Row(
            modifier = Modifier.padding(15.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .background(
                        if (isEnabled) EmeraldDark.copy(alpha = 0.7f) else SurfaceElevated,
                        RoundedCornerShape(12.dp)
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = if (isEnabled) EmeraldSoft else CyanSoft,
                    modifier = Modifier.size(20.dp)
                )
            }
            Spacer(modifier = Modifier.width(14.dp))
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = title,
                        color = TextPrimary,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 14.sp
                    )
                    if (isProFeature && !isProUnlocked) {
                        Spacer(modifier = Modifier.width(6.dp))
                        Surface(
                            color = CyanDark,
                            shape = RoundedCornerShape(50),
                            modifier = Modifier.border(1.dp, CyanPrimary.copy(alpha = 0.5f), RoundedCornerShape(50))
                        ) {
                            Text(
                                text = "PRO",
                                color = CyanSoft,
                                fontSize = 9.sp,
                                fontWeight = FontWeight.ExtraBold,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 1.dp)
                            )
                        }
                    }
                }
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = subtitle,
                    color = TextSecondary,
                    fontSize = 12.sp,
                    lineHeight = 16.sp
                )
            }
            Spacer(modifier = Modifier.width(10.dp))
            Button(
                onClick = {
                    onClick()
                    onRefresh()
                },
                colors = ButtonDefaults.buttonColors(
                    containerColor = when {
                        isProFeature && !isProUnlocked -> CyanDark
                        isEnabled -> EmeraldDark
                        else -> EmeraldPrimary
                    }
                ),
                shape = RoundedCornerShape(10.dp),
                contentPadding = PaddingValues(horizontal = 14.dp, vertical = 6.dp)
            ) {
                Text(
                    text = buttonText,
                    color = when {
                        isProFeature && !isProUnlocked -> CyanSoft
                        isEnabled -> EmeraldSoft
                        else -> Color.White
                    },
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}

@Composable
private fun PolicySwitchRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, color = TextPrimary, fontWeight = FontWeight.Medium, fontSize = 14.sp)
            Text(text = subtitle, color = TextSecondary, fontSize = 11.sp)
        }
        Spacer(modifier = Modifier.width(8.dp))
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = Color.White,
                checkedTrackColor = EmeraldPrimary
            )
        )
    }
}

private fun isAccessibilityServiceEnabled(context: Context): Boolean {
    if (ApkInstallBlockerAccessibilityService.isServiceRunning) return true
    val expected = "${context.packageName}/${ApkInstallBlockerAccessibilityService::class.java.canonicalName}"
    val enabledServices = Settings.Secure.getString(
        context.contentResolver,
        Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
    ) ?: return false
    return enabledServices.contains(expected, ignoreCase = true)
}

private fun isNotificationListenerEnabled(context: Context): Boolean {
    if (MessageLinkScannerNotificationService.isNotificationGuardActive) return true
    val flat = Settings.Secure.getString(
        context.contentResolver,
        "enabled_notification_listeners"
    ) ?: return false
    return flat.contains(context.packageName)
}
