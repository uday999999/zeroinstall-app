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
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
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
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ShieldRepository.init(applicationContext)
        ContinuousShieldMonitorService.start(applicationContext)

        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = Color(0xFF3B82F6),
                    secondary = Color(0xFF10B981),
                    background = Color(0xFF0B0F19),
                    surface = Color(0xFF151C2C)
                )
            ) {
                ApkShieldMainApp()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ApkShieldMainApp() {
    val context = LocalContext.current
    var selectedTab by remember { mutableIntStateOf(0) }
    var showPricingDialog by remember { mutableStateOf(false) }
    val threatEvents by ShieldRepository.threatEvents.collectAsState()
    val blockedTrackers by ShieldRepository.blockedTrackersCount.collectAsState()

    val notifPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { }

    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    if (showPricingDialog) {
        RegionalFairPricingDialog(onDismiss = { showPricingDialog = false })
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            tint = Color(0xFF38BDF8),
                            modifier = Modifier.size(26.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "ZeroInstall Shield",
                                fontWeight = FontWeight.ExtraBold,
                                fontSize = 18.sp,
                                color = Color.White
                            )
                            Text(
                                text = "zeroinstall.app • APK Blocker • Ghost & Data Spy",
                                fontSize = 11.sp,
                                color = Color(0xFF94A3B8)
                            )
                        }
                        Surface(
                            color = Color(0xFF065F46),
                            shape = RoundedCornerShape(50),
                            modifier = Modifier.clickable { showPricingDialog = true }
                        ) {
                            Row(
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    Icons.Default.Public,
                                    contentDescription = null,
                                    tint = Color(0xFF34D399),
                                    modifier = Modifier.size(14.dp)
                                )
                                Spacer(modifier = Modifier.width(4.dp))
                                Text(
                                    text = "Fair Price",
                                    color = Color.White,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color(0xFF0F172A)
                )
            )
        },
        bottomBar = {
            NavigationBar(containerColor = Color(0xFF0F172A)) {
                NavigationBarItem(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    icon = { Icon(Icons.Default.Security, contentDescription = null) },
                    label = { Text("Shield", fontSize = 10.sp) }
                )
                NavigationBarItem(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    icon = { Icon(Icons.Default.VisibilityOff, contentDescription = null) },
                    label = { Text("Ghost Scan", fontSize = 10.sp) }
                )
                NavigationBarItem(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    icon = { Icon(Icons.Default.SwapVert, contentDescription = null) },
                    label = { Text("Data Spy", fontSize = 10.sp) }
                )
                NavigationBarItem(
                    selected = selectedTab == 3,
                    onClick = { selectedTab = 3 },
                    icon = { Icon(Icons.Default.LinkOff, contentDescription = null) },
                    label = { Text("Link Guard", fontSize = 10.sp) }
                )
                NavigationBarItem(
                    selected = selectedTab == 4,
                    onClick = { selectedTab = 4 },
                    icon = {
                        BadgedBox(
                            badge = {
                                if (threatEvents.isNotEmpty()) {
                                    Badge { Text("${threatEvents.size}") }
                                }
                            }
                        ) {
                            Icon(Icons.Default.History, contentDescription = null)
                        }
                    },
                    label = { Text("Alerts", fontSize = 10.sp) }
                )
            }
        },
        containerColor = Color(0xFF0B0F19)
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
                    onOpenPricing = { showPricingDialog = true }
                )
                1 -> GhostAndSpywareAuditTab(context)
                2 -> DataExfiltrationMonitorTab(context)
                3 -> LinkScannerTab(context)
                4 -> ThreatHistoryTab(context, threatEvents)
            }
        }
    }
}

/**
 * GOOGLE PLAY MANDATORY PROMINENT DISCLOSURE DIALOG
 * Ensures 100% Google Play review compliance before requesting Accessibility,
 * Notification Listener, VPN, Usage Access, or Device Admin permissions.
 */
@Composable
fun ProminentDisclosureModal(
    disclosure: ProminentDisclosureType,
    onAccept: () -> Unit,
    onDecline: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDecline,
        containerColor = Color(0xFF151C2C),
        title = {
            Column {
                Surface(
                    color = Color(0xFF1D4ED8),
                    shape = RoundedCornerShape(6.dp)
                ) {
                    Text(
                        text = "GOOGLE PLAY PRIVACY DISCLOSURE",
                        color = Color.White,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = disclosure.title,
                    color = Color.White,
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 18.sp
                )
            }
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "What is accessed:",
                    color = Color(0xFF38BDF8),
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.sp
                )
                Text(
                    text = disclosure.whatIsAccessed,
                    color = Color(0xFFE2E8F0),
                    fontSize = 13.sp
                )
                Text(
                    text = "Why it is needed:",
                    color = Color(0xFF38BDF8),
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.sp
                )
                Text(
                    text = disclosure.howItIsUsed,
                    color = Color(0xFFE2E8F0),
                    fontSize = 13.sp
                )
                Surface(
                    color = Color(0xFF064E3B),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Text(
                        text = "🔒 ${disclosure.privacyGuarantee}",
                        color = Color(0xFFA7F3D0),
                        fontSize = 12.sp,
                        modifier = Modifier.padding(10.dp)
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onAccept,
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981))
            ) {
                Text("Accept & Enable", fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            TextButton(onClick = onDecline) {
                Text("No Thanks", color = Color(0xFF94A3B8))
            }
        }
    )
}

/**
 * PURCHASING POWER PARITY (PPP) FAIR REGIONAL PRICING DIALOG
 * Automatically lowers subscription cost in lower per-capita income nations via Google Play Billing.
 */
@Composable
fun RegionalFairPricingDialog(onDismiss: () -> Unit) {
    val userTier = remember { RegionalPricingManager.getCurrentUserRegionalPrice() }
    val allTiers = remember { RegionalPricingManager.getAllSampleTiers() }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Color(0xFF151C2C),
        title = {
            Column {
                Text(
                    text = "🌍 People-First Regional Fair Pricing",
                    color = Color.White,
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 18.sp
                )
                Text(
                    text = "Automatically adjusted for local per-capita income via Google Play",
                    color = Color(0xFF94A3B8),
                    fontSize = 12.sp
                )
            }
        },
        text = {
            LazyColumn(
                modifier = Modifier.heightIn(max = 420.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                item {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color(0xFF064E3B)),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(
                                text = "YOUR REGION (${userTier.countryName})",
                                color = Color(0xFF6EE7B7),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = "${userTier.monthlyPriceFormatted}  •  ${userTier.yearlyPriceFormatted}",
                                color = Color.White,
                                fontWeight = FontWeight.ExtraBold,
                                fontSize = 17.sp
                            )
                            Text(
                                text = "✓ ${userTier.pppDiscountNote}",
                                color = Color(0xFFA7F3D0),
                                fontSize = 11.sp
                            )
                        }
                    }
                }

                item {
                    Text(
                        text = "• Core APK Blocker, Ghost App Scanner & Bank Screen-Share Scam Protection are 100% FREE forever.\n• Pro unlocks 24/7 Automatic VPN Tracker Firewall, Deep Background Upload Alerts & Family Protection (up to 5 phones).",
                        color = Color(0xFFCBD5E1),
                        fontSize = 12.sp
                    )
                }

                item {
                    Text(
                        text = "GLOBAL PURCHASING-POWER PRICING EXAMPLES:",
                        color = Color(0xFF38BDF8),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                }

                items(allTiers) { tier ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color(0xFF0F172A), RoundedCornerShape(8.dp))
                            .padding(horizontal = 10.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(
                                text = "${tier.countryName} (${tier.countryCode})",
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 12.sp
                            )
                            Text(
                                text = tier.pppDiscountNote,
                                color = Color(0xFF64748B),
                                fontSize = 10.sp
                            )
                        }
                        Text(
                            text = tier.monthlyPriceFormatted,
                            color = Color(0xFF34D399),
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onDismiss,
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB))
            ) {
                Text("Got It")
            }
        }
    )
}

@Composable
fun DataExfiltrationMonitorTab(context: Context) {
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
            .padding(16.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "App Upload, Download & Data Theft Monitor",
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 17.sp
                )
                Text(
                    text = "See which apps upload data in the background & what personal data they take",
                    color = Color(0xFF94A3B8),
                    fontSize = 11.sp
                )
            }
            IconButton(onClick = { refreshStats() }) {
                Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = Color(0xFF38BDF8))
            }
        }

        if (!hasUsageAccess) {
            Spacer(modifier = Modifier.height(10.dp))
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF422006)),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Grant Usage Access for Deep Background Upload Stats",
                            color = Color(0xFFFDE68A),
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp
                        )
                        Text(
                            text = "Allows inspecting 30-day Background vs. Foreground upload/download history per app.",
                            color = Color(0xFFFEF3C7),
                            fontSize = 11.sp
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(
                        onClick = { showUsageDisclosure = true },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFD97706))
                    ) {
                        Text("Grant", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = filterMode == 0,
                onClick = { filterMode = 0 },
                label = { Text("Top Uploaders (${reports.size})", fontSize = 11.sp) }
            )
            FilterChip(
                selected = filterMode == 1,
                onClick = { filterMode = 1 },
                label = { Text("🚨 Data Leak Risk", fontSize = 11.sp) }
            )
            FilterChip(
                selected = filterMode == 2,
                onClick = { filterMode = 2 },
                label = { Text("🔍 Taking Private Data", fontSize = 11.sp) }
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        if (isLoading) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = Color(0xFF38BDF8))
            }
        } else if (filteredReports.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    "✅ No suspicious background data uploaders detected in this filter!",
                    color = Color(0xFF34D399),
                    fontSize = 14.sp
                )
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                items(filteredReports, key = { it.packageName }) { item ->
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = if (item.isSuspiciousExfiltration) Color(0xFF2A1215) else Color(0xFF151C2C)
                        ),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(
                                width = 1.dp,
                                color = if (item.isSuspiciousExfiltration) Color(0xFFEF4444).copy(alpha = 0.5f) else Color.Transparent,
                                shape = RoundedCornerShape(14.dp)
                            )
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = item.appName,
                                        color = Color.White,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 15.sp
                                    )
                                    Text(
                                        text = item.packageName,
                                        color = Color(0xFF64748B),
                                        fontSize = 11.sp
                                    )
                                }
                                if (item.isSuspiciousExfiltration) {
                                    Surface(
                                        color = Color(0xFFDC2626),
                                        shape = RoundedCornerShape(50)
                                    ) {
                                        Text(
                                            text = "DATA EXFILTRATION RISK",
                                            color = Color.White,
                                            fontSize = 10.sp,
                                            fontWeight = FontWeight.Bold,
                                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                                        )
                                    }
                                }
                            }

                            Spacer(modifier = Modifier.height(10.dp))

                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(Color(0xFF0F172A), RoundedCornerShape(10.dp))
                                    .padding(10.dp),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Column {
                                    Text("⬆ UPLOADED (SENT)", color = Color(0xFFF87171), fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                    Text(
                                        text = NetworkAndDataExfiltrationMonitor.formatBytes(item.uploadedBytes),
                                        color = Color.White,
                                        fontWeight = FontWeight.ExtraBold,
                                        fontSize = 14.sp
                                    )
                                    Text(
                                        text = "Bg: ${NetworkAndDataExfiltrationMonitor.formatBytes(item.backgroundUploadedBytes)}",
                                        color = Color(0xFFFCA5A5),
                                        fontSize = 10.sp
                                    )
                                }

                                Column {
                                    Text("⬇ DOWNLOADED", color = Color(0xFF38BDF8), fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                    Text(
                                        text = NetworkAndDataExfiltrationMonitor.formatBytes(item.downloadedBytes),
                                        color = Color.White,
                                        fontWeight = FontWeight.ExtraBold,
                                        fontSize = 14.sp
                                    )
                                    Text(
                                        text = "Bg: ${NetworkAndDataExfiltrationMonitor.formatBytes(item.backgroundDownloadedBytes)}",
                                        color = Color(0xFF93C5FD),
                                        fontSize = 10.sp
                                    )
                                }

                                Column(horizontalAlignment = Alignment.End) {
                                    Text("UPLOAD RATIO", color = Color(0xFFFBBF24), fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                    Text(
                                        text = "${item.uploadRatioPercent}%",
                                        color = if (item.uploadRatioPercent >= 40) Color(0xFFEF4444) else Color(0xFF34D399),
                                        fontWeight = FontWeight.ExtraBold,
                                        fontSize = 14.sp
                                    )
                                    Text(
                                        text = "Screen: ${item.foregroundTimeMs / 60000}m",
                                        color = Color(0xFF94A3B8),
                                        fontSize = 10.sp
                                    )
                                }
                            }

                            if (item.sensitiveDataAccessed.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    text = "📂 Personal Data This App Takes: ${item.sensitiveDataAccessed.joinToString(" • ")}",
                                    color = Color(0xFFFBBF24),
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }

                            item.exfiltrationWarning?.let { warning ->
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = warning,
                                    color = Color(0xFFFCA5A5),
                                    fontSize = 12.sp
                                )
                            }

                            Spacer(modifier = Modifier.height(10.dp))

                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                OutlinedButton(
                                    onClick = {
                                        val infoIntent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                            data = Uri.parse("package:${item.packageName}")
                                        }
                                        context.startActivity(infoIntent)
                                    },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text("Block Data / Permissions", fontSize = 11.sp)
                                }

                                if (!item.isSystemApp) {
                                    Button(
                                        onClick = {
                                            val uninstallIntent = Intent(Intent.ACTION_DELETE).apply {
                                                data = Uri.parse("package:${item.packageName}")
                                            }
                                            context.startActivity(uninstallIntent)
                                        },
                                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                                        modifier = Modifier.weight(1f)
                                    ) {
                                        Text("Uninstall App", fontSize = 11.sp)
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
fun ShieldDashboardTab(
    context: Context,
    totalBlocked: Int,
    blockedTrackers: Int,
    onOpenPricing: () -> Unit
) {
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

    // Google Play Mandatory Prominent Disclosure state
    var pendingDisclosure by remember { mutableStateOf<ProminentDisclosureType?>(null) }

    // Everyday helpful people-protection checks
    val remoteScamApps = remember { PeopleProtectionTools.detectRemoteAccessScamApps(context) }
    val wifiReport = remember { PeopleProtectionTools.auditNetworkProxySafety(context) }
    val regionalPrice = remember { RegionalPricingManager.getCurrentUserRegionalPrice() }

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
                                "Prevents unauthorized uninstallation of ZeroInstall Shield and enforces OS-level restrictions against unknown APK sources."
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
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF172554)),
                shape = RoundedCornerShape(18.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, Color(0xFF3B82F6), RoundedCornerShape(18.dp))
            ) {
                Column(modifier = Modifier.padding(18.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(48.dp)
                                .background(Color(0xFF1D4ED8), CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                Icons.Default.VerifiedUser,
                                contentDescription = null,
                                tint = Color.White,
                                modifier = Modifier.size(28.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(14.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = if (blockAllApk) "ZEROINSTALL LOCKDOWN ACTIVE" else "PROTECTION PAUSED",
                                color = if (blockAllApk) Color(0xFF34D399) else Color(0xFFF87171),
                                fontWeight = FontWeight.ExtraBold,
                                fontSize = 15.sp
                            )
                            Text(
                                text = "Google Play Compliant • 100% On-Device APK, Link & Data Guard",
                                color = Color(0xFFBFDBFE),
                                fontSize = 12.sp
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        StatPill("Threats Stopped", "$totalBlocked", Color(0xFFEF4444))
                        StatPill("Trackers Blocked", "$blockedTrackers", Color(0xFFA855F7))
                        StatPill("Session Monitor", "ONLINE", Color(0xFF10B981))
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    Button(
                        onClick = {
                            ShieldRepository.recordAndAlertThreat(
                                context = context,
                                type = ThreatType.BACKGROUND_SESSION_BLOCKED,
                                severity = Severity.CRITICAL,
                                sourcePackageOrUrl = "https://stealth-drop-cdn.ngrok-free.app/silent_tracker_v4.apk",
                                title = "🛑 [SIMULATION] Stealth Background APK Blocked!",
                                description = "Simulated Attack: A hidden link attempted to drop and silently install 'SystemUpdateService.apk' (Invisible Background Tracker) without a launcher icon.",
                                actionTaken = "Terminated PackageInstaller Session & Quarantined Payload",
                                showFullScreenPopup = true
                            )
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.BugReport, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Simulate Stealth APK & Tracker Link Attack", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        // People-First Feature: Bank Call & Screen-Share Scam Check + Wi-Fi Proxy Check
        item {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = if (remoteScamApps.isNotEmpty() || wifiReport.isProxyDetected) {
                        Color(0xFF3B0D0D)
                    } else {
                        Color(0xFF062E22)
                    }
                ),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "🛡️ BANK CALL & SCREEN-SHARE SCAM CHECK",
                        color = Color(0xFF34D399),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    if (remoteScamApps.isEmpty()) {
                        Text(
                            text = "✅ No Remote Screen-Sharing Apps Found (Safe from AnyDesk/TeamViewer OTP Theft)",
                            color = Color.White,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 13.sp
                        )
                    } else {
                        remoteScamApps.forEach { app ->
                            Text(
                                text = "🚨 WARNING: ${app.appName} is installed! ${app.dangerExplanation}",
                                color = Color(0xFFFCA5A5),
                                fontSize = 12.sp
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = wifiReport.statusTitle,
                        color = if (wifiReport.isProxyDetected) Color(0xFFFBBF24) else Color(0xFFA7F3D0),
                        fontSize = 12.sp
                    )
                }
            }
        }

        item {
            Text(
                text = "ACTIVE ENFORCEMENT ENGINES (WITH PLAY STORE DISCLOSURE)",
                color = Color(0xFF94A3B8),
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold
            )
        }

        item {
            EnginePermissionCard(
                title = "1. Real-Time APK Installer Interceptor",
                subtitle = "Warns & stops unauthorized APK install dialogs and 'Install Unknown Apps' settings.",
                isEnabled = isAccessibilityActive,
                buttonText = if (isAccessibilityActive) "Configured" else "Enable Blocker",
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
                title = "2. WhatsApp / SMS / Telegram Link Guard",
                subtitle = "Scans incoming message notifications for hidden .apk files, redirect droppers & spyware links.",
                isEnabled = isNotificationGuardActive,
                buttonText = if (isNotificationGuardActive) "Active" else "Enable Guard",
                onClick = {
                    if (isNotificationGuardActive) {
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
                title = "3. Background Tracker & Spyware VPN Firewall",
                subtitle = "Blocks background apps from communicating with stalkerware servers (mSpy, FlexiSpy, Cerberus, etc.).",
                isEnabled = isVpnRunning,
                buttonText = if (isVpnRunning) "Stop VPN" else "Start Firewall",
                onClick = {
                    if (isVpnRunning) {
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
                title = "4. Device Admin Anti-Uninstall & OS Policy Lock",
                subtitle = "Prevents attackers or malware from uninstalling ZeroInstall Shield in the background.",
                isEnabled = isDeviceAdminActive,
                buttonText = if (isDeviceAdminActive) "Protected" else "Activate Admin",
                onClick = {
                    pendingDisclosure = ProminentDisclosureType.DEVICE_ADMIN
                },
                onRefresh = { isDeviceAdminActive = ShieldDeviceAdminReceiver.isAdminActive(context) }
            )
        }

        // Regional Fair Pricing Card
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1B4B)),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onOpenPricing() }
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "🌍 FAIR REGIONAL PRICING (${regionalPrice.countryName})",
                            color = Color(0xFFA5B4FC),
                            fontWeight = FontWeight.Bold,
                            fontSize = 11.sp
                        )
                        Text(
                            text = "Core Protection is 100% Free • Pro is ${regionalPrice.monthlyPriceFormatted}",
                            color = Color.White,
                            fontWeight = FontWeight.ExtraBold,
                            fontSize = 14.sp
                        )
                        Text(
                            text = "${regionalPrice.pppDiscountNote} — Tap to view global income-adjusted pricing",
                            color = Color(0xFFC7D2FE),
                            fontSize = 11.sp
                        )
                    }
                    Icon(
                        Icons.Default.ChevronRight,
                        contentDescription = null,
                        tint = Color.White
                    )
                }
            }
        }

        item {
            Text(
                text = "LOCKDOWN SECURITY POLICIES",
                color = Color(0xFF94A3B8),
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold
            )
        }

        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF151C2C)),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    PolicySwitchRow(
                        title = "Block All APK Installations",
                        subtitle = "Stop all .apk, .xapk, .apkm & background PackageInstaller sessions",
                        checked = blockAllApk,
                        onCheckedChange = {
                            blockAllApk = it
                            ShieldRepository.setBlockAllApkEnabled(context, it)
                            ShieldDeviceAdminReceiver.enforceOsLevelApkBlockIfPossible(context, it)
                        }
                    )
                    HorizontalDivider(color = Color(0xFF1E293B))
                    PolicySwitchRow(
                        title = "Lock 'Install Unknown Apps' Settings",
                        subtitle = "Prevent enabling Unknown Sources permission in Android Settings",
                        checked = blockUnknownSources,
                        onCheckedChange = {
                            blockUnknownSources = it
                            ShieldRepository.setBlockUnknownSourcesSettingsEnabled(context, it)
                        }
                    )
                    HorizontalDivider(color = Color(0xFF1E293B))
                    PolicySwitchRow(
                        title = "Auto-Quarantine Downloaded APKs",
                        subtitle = "Automatically remove newly downloaded .apk payloads via DownloadManager",
                        checked = autoDeleteApks,
                        onCheckedChange = {
                            autoDeleteApks = it
                            ShieldRepository.setAutoDeleteDownloadedApks(context, it)
                        }
                    )
                    HorizontalDivider(color = Color(0xFF1E293B))
                    PolicySwitchRow(
                        title = "Block Malicious & Redirect APK Links",
                        subtitle = "Stop drive-by download links, raw IP droppers, and intent:// exploits",
                        checked = blockLinks,
                        onCheckedChange = {
                            blockLinks = it
                            ShieldRepository.setBlockMaliciousLinksEnabled(context, it)
                        }
                    )
                    HorizontalDivider(color = Color(0xFF1E293B))
                    PolicySwitchRow(
                        title = "Detect Invisible / Iconless Ghost Apps",
                        subtitle = "Alert immediately if an app installs without a launcher icon",
                        checked = detectGhostApps,
                        onCheckedChange = {
                            detectGhostApps = it
                            ShieldRepository.setDetectInvisibleAppsEnabled(context, it)
                        }
                    )
                    HorizontalDivider(color = Color(0xFF1E293B))
                    PolicySwitchRow(
                        title = "Allow Official Google Play Store Updates",
                        subtitle = "Permit verified Play Store updates while blocking all sideloaded APKs",
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

    val filteredApps = remember(allApps, filterMode) {
        when (filterMode) {
            0 -> allApps.filter { it.riskScore >= 25 || !it.hasLauncherIcon || it.isSideloaded }
            1 -> allApps.filter { !it.hasLauncherIcon }
            else -> allApps
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "Invisible Apps & Tracker Auditor",
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp
                )
                Text(
                    text = "Detects iconless background apps, sideloaded APKs & stalkerware",
                    color = Color(0xFF94A3B8),
                    fontSize = 12.sp
                )
            }
            IconButton(onClick = { triggerScan() }) {
                Icon(Icons.Default.Refresh, contentDescription = "Rescan", tint = Color(0xFF38BDF8))
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = filterMode == 0,
                onClick = { filterMode = 0 },
                label = { Text("Risky / Sideloaded") }
            )
            FilterChip(
                selected = filterMode == 1,
                onClick = { filterMode = 1 },
                label = { Text("👻 Invisible (No Icon)") }
            )
            FilterChip(
                selected = filterMode == 2,
                onClick = { filterMode = 2 },
                label = { Text("All User Apps (${allApps.size})") }
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        if (isScanning) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator(color = Color(0xFF38BDF8))
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        "Scanning installed packages for hidden apps & spyware permissions...",
                        color = Color(0xFF94A3B8),
                        fontSize = 13.sp
                    )
                }
            }
        } else if (filteredApps.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    "✅ No invisible ghost apps or high-risk sideloaded packages found in this view!",
                    color = Color(0xFF34D399),
                    fontSize = 14.sp
                )
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                items(filteredApps, key = { it.packageName }) { item ->
                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color(0xFF151C2C)),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = item.appName,
                                        color = Color.White,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 15.sp
                                    )
                                    Text(
                                        text = item.packageName,
                                        color = Color(0xFF64748B),
                                        fontSize = 11.sp
                                    )
                                }
                                Surface(
                                    color = when {
                                        item.riskScore >= 60 -> Color(0xFFDC2626)
                                        item.riskScore >= 30 -> Color(0xFFD97706)
                                        else -> Color(0xFF059669)
                                    },
                                    shape = RoundedCornerShape(50)
                                ) {
                                    Text(
                                        text = "Risk ${item.riskScore}/100",
                                        color = Color.White,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                                    )
                                }
                            }

                            if (item.riskReasons.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(8.dp))
                                item.riskReasons.forEach { reason ->
                                    Text(
                                        text = reason,
                                        color = Color(0xFFFCA5A5),
                                        fontSize = 12.sp
                                    )
                                }
                            }

                            if (item.dangerousPermissions.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = "Capabilities: ${item.dangerousPermissions.joinToString(", ")}",
                                    color = Color(0xFFFBBF24),
                                    fontSize = 11.sp
                                )
                            }

                            Spacer(modifier = Modifier.height(10.dp))

                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(
                                    onClick = {
                                        val uninstallIntent = Intent(Intent.ACTION_DELETE).apply {
                                            data = Uri.parse("package:${item.packageName}")
                                        }
                                        context.startActivity(uninstallIntent)
                                    },
                                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(Icons.Default.Delete, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Uninstall", fontSize = 12.sp)
                                }

                                OutlinedButton(
                                    onClick = {
                                        val infoIntent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                            data = Uri.parse("package:${item.packageName}")
                                        }
                                        context.startActivity(infoIntent)
                                    },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text("Force Stop / Info", fontSize = 12.sp)
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

    val sampleAttackLinks = listOf(
        "https://promo-reward-claim.ngrok-free.app/kyc-update.apk",
        "intent://scan/#Intent;scheme=package;action=android.intent.action.INSTALL_PACKAGE;end",
        "http://185.199.108.153/silent-install/bg-tracker.dex",
        "https://www.google.com"
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text(
            text = "Deep Link & Invisible Dropper Scanner",
            color = Color.White,
            fontWeight = FontWeight.Bold,
            fontSize = 18.sp
        )
        Text(
            text = "Inspects URLs, redirect chains & HTTP headers for hidden APK payloads without opening them in your browser.",
            color = Color(0xFF94A3B8),
            fontSize = 12.sp
        )

        Spacer(modifier = Modifier.height(14.dp))

        OutlinedTextField(
            value = urlInput,
            onValueChange = { urlInput = it },
            label = { Text("Paste suspicious link from SMS / WhatsApp / Email") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(10.dp))

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
                            title = "🛑 Malicious APK / Tracker Link Detected!",
                            description = result.reasons.joinToString("\n• ", prefix = "• "),
                            actionTaken = "Blocked by Link Guard",
                            showFullScreenPopup = false
                        )
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB))
        ) {
            Icon(Icons.Default.Radar, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text(if (isScanning) "Inspecting Headers & Redirects..." else "Scan Link Safely")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "TAP A SAMPLE LINK TO TEST DETECTION:",
            color = Color(0xFF94A3B8),
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold
        )
        Spacer(modifier = Modifier.height(6.dp))

        sampleAttackLinks.forEach { sample ->
            Surface(
                color = Color(0xFF151C2C),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 3.dp)
                    .clickable { urlInput = sample }
            ) {
                Text(
                    text = sample,
                    color = Color(0xFF38BDF8),
                    fontSize = 11.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(10.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        scanResult?.let { res ->
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = if (res.isThreat) Color(0xFF3B0D0D) else Color(0xFF062E22)
                ),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = if (res.isThreat) {
                            "🚨 DANGER: BLOCKED APK / SPYWARE LINK (Score: ${res.threatScore}/100)"
                        } else {
                            "✅ SAFE: No APK Payload or Tracker Found (Score: ${res.threatScore}/100)"
                        },
                        color = if (res.isThreat) Color(0xFFF87171) else Color(0xFF34D399),
                        fontWeight = FontWeight.ExtraBold,
                        fontSize = 15.sp
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    if (res.reasons.isEmpty()) {
                        Text(
                            "No suspicious APK extensions, intent:// schemes, or malware headers detected.",
                            color = Color.White,
                            fontSize = 13.sp
                        )
                    } else {
                        res.reasons.forEach { reason ->
                            Text("• $reason", color = Color(0xFFFECACA), fontSize = 13.sp)
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ThreatHistoryTab(context: Context, events: List<ThreatEvent>) {
    val fmt = remember { SimpleDateFormat("dd MMM HH:mm:ss", Locale.getDefault()) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Blocked Attempts & Security Log",
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 18.sp
            )
            if (events.isNotEmpty()) {
                TextButton(onClick = { ShieldRepository.clearLogs(context) }) {
                    Text("Clear Log", color = Color(0xFFF87171))
                }
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        if (events.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    "No blocked threats recorded yet. Tap 'Simulate Stealth APK Attack' on the Shield tab to test!",
                    color = Color(0xFF64748B),
                    fontSize = 13.sp
                )
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                items(events, key = { it.id }) { ev ->
                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color(0xFF151C2C)),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    text = ev.type.title,
                                    color = Color(ev.type.badgeColorHex),
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 11.sp
                                )
                                Text(
                                    text = fmt.format(Date(ev.timestamp)),
                                    color = Color(0xFF64748B),
                                    fontSize = 11.sp
                                )
                            }
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = ev.title,
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 14.sp
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = ev.description,
                                color = Color(0xFFCBD5E1),
                                fontSize = 12.sp
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = "Source: ${ev.sourcePackageOrUrl}",
                                color = Color(0xFFFBBF24),
                                fontSize = 11.sp
                            )
                            Text(
                                text = "Action: ${ev.actionTaken}",
                                color = Color(0xFF34D399),
                                fontSize = 11.sp,
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
private fun StatPill(label: String, value: String, color: Color) {
    Surface(
        color = Color(0xFF0F172A),
        shape = RoundedCornerShape(10.dp)
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(text = value, color = color, fontWeight = FontWeight.ExtraBold, fontSize = 15.sp)
            Text(text = label, color = Color(0xFF94A3B8), fontSize = 10.sp)
        }
    }
}

@Composable
private fun EnginePermissionCard(
    title: String,
    subtitle: String,
    isEnabled: Boolean,
    buttonText: String,
    onClick: () -> Unit,
    onRefresh: () -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Color(0xFF151C2C)),
        shape = RoundedCornerShape(14.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(12.dp)
                    .background(
                        if (isEnabled) Color(0xFF10B981) else Color(0xFFF59E0B),
                        CircleShape
                    )
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(text = title, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                Text(text = subtitle, color = Color(0xFF94A3B8), fontSize = 11.sp)
            }
            Spacer(modifier = Modifier.width(8.dp))
            Button(
                onClick = {
                    onClick()
                    onRefresh()
                },
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (isEnabled) Color(0xFF065F46) else Color(0xFF2563EB)
                ),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
            ) {
                Text(text = buttonText, fontSize = 11.sp, fontWeight = FontWeight.Bold)
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
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
            Text(text = subtitle, color = Color(0xFF94A3B8), fontSize = 11.sp)
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
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
