package com.security.apkshield.ui

import android.Manifest
import android.app.Activity
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
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat
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

data class ShieldPalette(
    val bgDeepSlate: Color,
    val surfaceCard: Color,
    val surfaceElevated: Color,
    val borderSubtle: Color,
    val emeraldPrimary: Color,
    val emeraldSoft: Color,
    val emeraldDark: Color,
    val cyanPrimary: Color,
    val cyanSoft: Color,
    val cyanDark: Color,
    val textPrimary: Color,
    val textSecondary: Color,
    val dangerSoft: Color,
    val dangerBg: Color,
    val proGold: Color,
    val proGoldSoft: Color,
    val proGoldDark: Color,
    val proCardBg: Color,
    val proBorder: Color,
    val isLight: Boolean
)

// Green Black Grey Executive Security Palette
private val GreenBlackGreyYellowPalette = ShieldPalette(
    bgDeepSlate = Color(0xFF0B0F19),      // Midnight Onyx Canvas
    surfaceCard = Color(0xFF111827),      // Deep Charcoal Slate Cards
    surfaceElevated = Color(0xFF161F30),  // Dark Slate Elevated Container
    borderSubtle = Color(0xFF263246),     // Subtle Sleek Border
    emeraldPrimary = Color(0xFF10B981),   // Bright Security Green (Active / Safe / Protected)
    emeraldSoft = Color(0xFF10B981),      // Bright Security Green
    emeraldDark = Color(0xFF162820),      // Dark Green Pill Container
    cyanPrimary = Color(0xFF10B981),      // Security Green Accent
    cyanSoft = Color(0xFF34D399),         // Mint Green Accent
    cyanDark = Color(0xFF162820),         // Dark Green Container
    textPrimary = Color(0xFFFFFFFF),      // Pure White High-Contrast Typography
    textSecondary = Color(0xFF9CA3AF),    // Cool Silver-Grey Description Text
    dangerSoft = Color(0xFFEF4444),       // Vivid Alert Red
    dangerBg = Color(0xFF2D1217),         // Dark Alert Container
    proGold = Color(0xFF10B981),          // Security Green Accent (Buttons, PRO badge)
    proGoldSoft = Color(0xFF34D399),      // Bright Green Accent
    proGoldDark = Color(0xFF162820),      // Dark Green Pill Background
    proCardBg = Color(0xFF111827),        // Deep Slate Card
    proBorder = Color(0xFF263246),        // Sleek Border
    isLight = false
)

private val FreeDarkPalette = GreenBlackGreyYellowPalette
private val ProLightPalette = GreenBlackGreyYellowPalette

private val LocalShieldPalette = staticCompositionLocalOf { GreenBlackGreyYellowPalette }

private val BgDeepSlate: Color @Composable get() = LocalShieldPalette.current.bgDeepSlate
private val SurfaceCard: Color @Composable get() = LocalShieldPalette.current.surfaceCard
private val SurfaceElevated: Color @Composable get() = LocalShieldPalette.current.surfaceElevated
private val BorderSubtle: Color @Composable get() = LocalShieldPalette.current.borderSubtle
private val EmeraldPrimary: Color @Composable get() = LocalShieldPalette.current.emeraldPrimary
private val EmeraldSoft: Color @Composable get() = LocalShieldPalette.current.emeraldSoft
private val EmeraldDark: Color @Composable get() = LocalShieldPalette.current.emeraldDark
private val CyanPrimary: Color @Composable get() = LocalShieldPalette.current.cyanPrimary
private val CyanSoft: Color @Composable get() = LocalShieldPalette.current.cyanSoft
private val CyanDark: Color @Composable get() = LocalShieldPalette.current.cyanDark
private val TextPrimary: Color @Composable get() = LocalShieldPalette.current.textPrimary
private val TextSecondary: Color @Composable get() = LocalShieldPalette.current.textSecondary
private val DangerSoft: Color @Composable get() = LocalShieldPalette.current.dangerSoft
private val DangerBg: Color @Composable get() = LocalShieldPalette.current.dangerBg
private val ProGold: Color @Composable get() = LocalShieldPalette.current.proGold
private val ProGoldSoft: Color @Composable get() = LocalShieldPalette.current.proGoldSoft
private val ProGoldDark: Color @Composable get() = LocalShieldPalette.current.proGoldDark
private val ProCardBg: Color @Composable get() = LocalShieldPalette.current.proCardBg
private val ProBorder: Color @Composable get() = LocalShieldPalette.current.proBorder

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ShieldRepository.init(applicationContext)
        ContinuousShieldMonitorService.start(applicationContext)

        setContent {
            val isProUnlocked by ShieldRepository.isProUnlocked.collectAsState()
            val palette = GreenBlackGreyYellowPalette

            val view = LocalView.current
            if (!view.isInEditMode) {
                SideEffect {
                    val window = (view.context as? Activity)?.window ?: return@SideEffect
                    val insetsController = WindowCompat.getInsetsController(window, view)
                    insetsController.isAppearanceLightStatusBars = false
                }
            }

            CompositionLocalProvider(LocalShieldPalette provides palette) {
                MaterialTheme(
                    colorScheme = if (isProUnlocked) {
                        lightColorScheme(
                            primary = palette.emeraldPrimary,
                            secondary = palette.cyanPrimary,
                            background = palette.bgDeepSlate,
                            surface = palette.surfaceCard,
                            onPrimary = Color.White,
                            onSecondary = Color.White,
                            onBackground = palette.textPrimary,
                            onSurface = palette.textPrimary
                        )
                    } else {
                        darkColorScheme(
                            primary = palette.emeraldPrimary,
                            secondary = palette.cyanPrimary,
                            background = palette.bgDeepSlate,
                            surface = palette.surfaceCard,
                            onPrimary = Color.White,
                            onSecondary = Color.White,
                            onBackground = palette.textPrimary,
                            onSurface = palette.textPrimary
                        )
                    }
                ) {
                    ApkShieldMainApp()
                }
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
    val proAdExpiryMs by ShieldRepository.proAdExpiryMs.collectAsState()
    val adsWatchedCount by ShieldRepository.adsWatchedCount.collectAsState()

    var currentTimeMs by remember { mutableLongStateOf(System.currentTimeMillis()) }

    LaunchedEffect(proAdExpiryMs, isProUnlocked) {
        while (isProUnlocked || proAdExpiryMs > System.currentTimeMillis()) {
            currentTimeMs = System.currentTimeMillis()
            ShieldRepository.refreshProStatus(context)
            delay(1000L)
        }
    }

    val remainingProMs = (proAdExpiryMs - currentTimeMs).coerceAtLeast(0L)
    val remainingFormatted = ShieldRepository.formatRemainingProTime(remainingProMs)
    val remainingVerboseFormatted = ShieldRepository.formatRemainingProTimeVerbose(remainingProMs)

    val notifPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            ContinuousShieldMonitorService.start(context.applicationContext)
        }
    }

    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    if (showProModal) {
        ZeroInstallProDialog(
            isProUnlocked = isProUnlocked,
            remainingProMs = remainingProMs,
            remainingVerboseFormatted = remainingVerboseFormatted,
            onWatchAdRewardDay = {
                ShieldRepository.addRewardedAdProHours(context, 24)
                currentTimeMs = System.currentTimeMillis()
            },
            onUnlockPro = {
                ShieldRepository.setProUnlocked(context, true)
                currentTimeMs = System.currentTimeMillis()
            },
            onSwitchToFree = {
                ShieldRepository.setProUnlocked(context, false)
                currentTimeMs = System.currentTimeMillis()
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
                        .padding(top = 14.dp, bottom = 10.dp, start = 18.dp, end = 18.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(36.dp)
                                    .background(Color(0xFFFACC15), RoundedCornerShape(10.dp)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Shield,
                                    contentDescription = null,
                                    tint = Color(0xFF0B0F19),
                                    modifier = Modifier.size(19.dp)
                                )
                            }
                            Spacer(modifier = Modifier.width(10.dp))
                            Column {
                                Text(
                                    text = "ZeroPro",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 17.sp,
                                    color = TextPrimary
                                )
                                Text(
                                    text = "by ZeroInstall",
                                    fontSize = 11.sp,
                                    color = Color(0xFF10B981),
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                        }

                        // Pro Badge: Shield Logo + PRO in bold letters (Yellow Background)
                        Surface(
                            color = Color(0xFFFACC15),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier
                                .clickable { showProModal = true }
                        ) {
                            Row(
                                modifier = Modifier.padding(horizontal = 11.dp, vertical = 6.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Shield,
                                    contentDescription = null,
                                    tint = Color(0xFF0B0F19),
                                    modifier = Modifier.size(15.dp)
                                )
                                Spacer(modifier = Modifier.width(5.dp))
                                Text(
                                    text = "PRO",
                                    color = Color(0xFF0B0F19),
                                    fontSize = 12.5.sp,
                                    fontWeight = FontWeight.Black
                                )
                            }
                        }
                    }
                }
            }
        },
        bottomBar = {
            val activeNavTint = Color(0xFF10B981)
            val activeNavIndicator = Color(0xFF162820)
            NavigationBar(
                containerColor = SurfaceCard,
                tonalElevation = 0.dp
            ) {
                NavigationBarItem(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    icon = { Icon(Icons.Default.Shield, contentDescription = null) },
                    label = { Text("Protection", fontSize = 11.sp) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = activeNavTint,
                        selectedTextColor = activeNavTint,
                        indicatorColor = activeNavIndicator,
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
                        selectedIconColor = activeNavTint,
                        selectedTextColor = activeNavTint,
                        indicatorColor = activeNavIndicator,
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
                                    Badge(containerColor = Color(0xFFFACC15)) {
                                        Text("PRO", color = Color(0xFF0B0F19), fontSize = 8.sp, fontWeight = FontWeight.ExtraBold)
                                    }
                                }
                            }
                        ) {
                            Icon(Icons.Default.DataUsage, contentDescription = null)
                        }
                    },
                    label = { Text("Data Guard", fontSize = 11.sp) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = activeNavTint,
                        selectedTextColor = activeNavTint,
                        indicatorColor = activeNavIndicator,
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
                        selectedIconColor = activeNavTint,
                        selectedTextColor = activeNavTint,
                        indicatorColor = activeNavIndicator,
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
                                    Badge(containerColor = Color(0xFF10B981)) {
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
                        selectedIconColor = activeNavTint,
                        selectedTextColor = activeNavTint,
                        indicatorColor = activeNavIndicator,
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
                    color = TextPrimary,
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
    remainingProMs: Long,
    remainingVerboseFormatted: String,
    onWatchAdRewardDay: () -> Unit,
    onUnlockPro: () -> Unit,
    onSwitchToFree: () -> Unit,
    onDismiss: () -> Unit
) {
    val scope = rememberCoroutineScope()
    val price = remember { RegionalPricingManager.getCurrentUserRegionalPrice() }
    var isPlayingRewardedAd by remember { mutableStateOf(false) }
    var adSecondsLeft by remember { mutableIntStateOf(5) }
    var showAdConfirmationDialog by remember { mutableStateOf(false) }

    if (showAdConfirmationDialog) {
        AlertDialog(
            onDismissRequest = { showAdConfirmationDialog = false },
            containerColor = SurfaceCard,
            shape = RoundedCornerShape(20.dp),
            modifier = Modifier.border(1.dp, BorderSubtle, RoundedCornerShape(20.dp)),
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.PlayCircleFilled,
                        contentDescription = null,
                        tint = EmeraldSoft,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Extend Pro for Free",
                        color = TextPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 17.sp
                    )
                }
            },
            text = {
                Text(
                    text = "Once you complete watching this short ad, your Pro protection will extend by 1 more day (+24 hours).\n\nYou can watch and extend unlimited times to keep Pro free forever!",
                    color = TextSecondary,
                    fontSize = 13.5.sp,
                    lineHeight = 20.sp
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showAdConfirmationDialog = false
                        isPlayingRewardedAd = true
                        adSecondsLeft = 5
                        scope.launch {
                            while (adSecondsLeft > 0) {
                                delay(1000L)
                                adSecondsLeft--
                            }
                            isPlayingRewardedAd = false
                            onWatchAdRewardDay()
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981)),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Text("Watch Ad & Extend +1 Day", color = Color.White, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showAdConfirmationDialog = false }) {
                    Text("Cancel", color = TextSecondary)
                }
            }
        )
    }

    AlertDialog(
        onDismissRequest = { if (!isPlayingRewardedAd) onDismiss() },
        containerColor = SurfaceCard,
        shape = RoundedCornerShape(24.dp),
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 16.dp)
            .border(
                width = 1.dp,
                color = BorderSubtle,
                shape = RoundedCornerShape(24.dp)
            ),
        title = null,
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Spacer(modifier = Modifier.height(6.dp))

                // Emblem (Yellow Circle with Black Shield)
                Box(
                    modifier = Modifier
                        .size(46.dp)
                        .background(
                            Color(0xFFFACC15),
                            CircleShape
                        )
                        .border(1.5.dp, Color(0xFFFACC15), CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = null,
                        tint = Color(0xFF0B0F19),
                        modifier = Modifier.size(24.dp)
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))

                Text(
                    text = if (isProUnlocked) "ZeroPro Enterprise Edition" else "ZeroPro Defense",
                    color = TextPrimary,
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp,
                    textAlign = TextAlign.Center
                )
                Text(
                    text = "24/7 Automated Device & Link Defense",
                    color = Color(0xFF10B981),
                    fontSize = 11.5.sp,
                    fontWeight = FontWeight.Medium,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(14.dp))

                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    ProFeatureItem("Auto-Scan WhatsApp, SMS & Telegram Links")
                    ProFeatureItem("24/7 Background Tracker & Spyware Firewall")
                    ProFeatureItem("Deep App Data Upload & Leak Monitor")
                }

                Spacer(modifier = Modifier.height(16.dp))

                // 1. Monthly Plan (₹99 / month)
                Surface(
                    color = SurfaceElevated,
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, BorderSubtle, RoundedCornerShape(14.dp))
                        .clickable { onUnlockPro() }
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Monthly Plan",
                                color = TextPrimary,
                                fontWeight = FontWeight.Bold,
                                fontSize = 14.sp
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = "Full monthly protection • Cancel anytime",
                                color = TextSecondary,
                                fontSize = 11.sp
                            )
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = price.monthlyPriceFormatted,
                            color = TextPrimary,
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.5.sp,
                            maxLines = 1,
                            softWrap = false
                        )
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))

                // 2. Annual Plan (₹999 / year)
                Surface(
                    color = SurfaceElevated,
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, BorderSubtle, RoundedCornerShape(14.dp))
                        .clickable { onUnlockPro() }
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = "Annual Plan",
                                    color = TextPrimary,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 14.sp
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Surface(
                                    color = Color(0xFF10B981),
                                    shape = RoundedCornerShape(50)
                                ) {
                                    Text(
                                        "BEST VALUE",
                                        color = Color.White,
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.ExtraBold,
                                        modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp)
                                    )
                                }
                            }
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = "Full year protection • Cancel anytime",
                                color = TextSecondary,
                                fontSize = 11.sp
                            )
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = price.yearlyPriceFormatted,
                            color = Color(0xFF10B981),
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.5.sp,
                            maxLines = 1,
                            softWrap = false
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                // 3. Free Option ("Free Forever" / "Watch 1 Ad Extend 1 Day" / "Active: 2 Days 23 Hours 58 Mins")
                Surface(
                    color = Color(0xFF10B981),
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            if (!isPlayingRewardedAd) {
                                showAdConfirmationDialog = true
                            }
                        }
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 14.dp, vertical = 12.dp)
                    ) {
                        if (isPlayingRewardedAd) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.Center
                            ) {
                                CircularProgressIndicator(
                                    color = Color.White,
                                    strokeWidth = 2.dp,
                                    modifier = Modifier.size(18.dp)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "Playing Video Ad... ${adSecondsLeft}s (+1 Day)",
                                    color = Color.White,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 13.sp
                                )
                            }
                        } else {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    imageVector = Icons.Default.PlayCircleFilled,
                                    contentDescription = null,
                                    tint = Color.White,
                                    modifier = Modifier.size(24.dp)
                                )
                                Spacer(modifier = Modifier.width(10.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = "Free Forever",
                                        color = Color.White,
                                        fontWeight = FontWeight.Black,
                                        fontSize = 15.sp
                                    )
                                    Spacer(modifier = Modifier.height(2.dp))
                                    Text(
                                        text = "Watch 1 Ad Extend 1 Day",
                                        color = Color.White.copy(alpha = 0.95f),
                                        fontSize = 11.5.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                    if (remainingProMs > 0L) {
                                        Spacer(modifier = Modifier.height(2.dp))
                                        Text(
                                            text = "Active: $remainingVerboseFormatted",
                                            color = Color.White.copy(alpha = 0.90f),
                                            fontSize = 11.sp,
                                            fontWeight = FontWeight.SemiBold
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))

                TextButton(onClick = onDismiss) {
                    Text("Close", color = TextSecondary, fontSize = 12.sp)
                }
            }
        },
        confirmButton = {}
    )
}

@Composable
private fun ProFeatureItem(text: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top
    ) {
        Icon(
            imageVector = Icons.Default.CheckCircle,
            contentDescription = null,
            tint = Color(0xFF10B981),
            modifier = Modifier
                .padding(top = 2.dp)
                .size(16.dp)
        )
        Spacer(modifier = Modifier.width(10.dp))
        Text(
            text = text,
            color = TextPrimary,
            fontSize = 12.5.sp,
            lineHeight = 18.sp
        )
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
                                "Prevents unauthorized removal of ZeroPro."
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
        // 1. Staggering Pro Edition / Emerald-Cyan Hero Card (No extra ad banner panel on main dashboard)
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = Color.Transparent),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        Brush.verticalGradient(
                            colors = when {
                                !blockAllApk -> listOf(DangerBg, SurfaceCard)
                                else -> listOf(Color(0xFF161F30), SurfaceCard)
                            }
                        ),
                        RoundedCornerShape(16.dp)
                    )
                    .border(
                        width = 1.dp,
                        color = when {
                            !blockAllApk -> DangerSoft.copy(alpha = 0.5f)
                            else -> Color(0xFF10B981).copy(alpha = 0.45f)
                        },
                        shape = RoundedCornerShape(16.dp)
                    )
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    // Status Pill with Live Pulse Dot
                    Surface(
                        color = Color(0xFF162820),
                        shape = RoundedCornerShape(20.dp),
                        modifier = Modifier
                            .padding(bottom = 16.dp)
                            .border(1.dp, Color(0xFF10B981).copy(alpha = 0.35f), RoundedCornerShape(20.dp))
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 5.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(7.dp)
                                    .background(if (blockAllApk) Color(0xFF10B981) else DangerSoft, CircleShape)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = if (isProUnlocked) "24/7 PRO ENDPOINT PROTECTION" else "STANDARD PROTECTION ACTIVE",
                                color = if (blockAllApk) Color(0xFF10B981) else DangerSoft,
                                fontSize = 10.5.sp,
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 0.5.sp
                            )
                        }
                    }

                    // Defender Shield Emblem
                    Box(
                        modifier = Modifier
                            .size(if (isProUnlocked) 72.dp else 68.dp)
                            .background(
                                when {
                                    !blockAllApk -> DangerBg
                                    else -> Color(0xFFFACC15)
                                },
                                CircleShape
                            )
                            .border(
                                width = 2.dp,
                                color = when {
                                    !blockAllApk -> DangerSoft
                                    else -> Color(0xFFFACC15)
                                },
                                shape = CircleShape
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        if (isQuickScanning) {
                            CircularProgressIndicator(
                                color = Color(0xFF0B0F19),
                                strokeWidth = 3.dp,
                                modifier = Modifier.size(40.dp)
                            )
                        } else {
                            Icon(
                                imageVector = when {
                                    !blockAllApk -> Icons.Default.Shield
                                    else -> Icons.Default.VerifiedUser
                                },
                                contentDescription = null,
                                tint = when {
                                    !blockAllApk -> DangerSoft
                                    else -> Color(0xFF0B0F19)
                                },
                                modifier = Modifier.size(36.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    Text(
                        text = when {
                            isQuickScanning -> "Scanning Device Security..."
                            isProUnlocked -> "Your Device is Protected"
                            quickScanComplete -> "Your Phone is Safe & Protected"
                            blockAllApk -> "Your Phone is Protected"
                            else -> "Protection Paused"
                        },
                        color = if (blockAllApk) Color(0xFF10B981) else DangerSoft,
                        fontWeight = FontWeight.Bold,
                        fontSize = 19.sp,
                        textAlign = TextAlign.Center
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = if (isProUnlocked) {
                            "All real-time defenses, links & app monitors running 24/7"
                        } else {
                            "Active protection against unauthorized APK installs & scam links"
                        },
                        color = TextSecondary,
                        fontSize = 12.sp,
                        textAlign = TextAlign.Center
                    )

                    Spacer(modifier = Modifier.height(18.dp))

                    // Unified Corporate Metrics Strip
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(SurfaceElevated, RoundedCornerShape(10.dp))
                            .border(1.dp, BorderSubtle, RoundedCornerShape(10.dp))
                            .padding(vertical = 12.dp),
                        horizontalArrangement = Arrangement.SpaceEvenly,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(
                                text = "$totalBlocked",
                                color = TextPrimary,
                                fontWeight = FontWeight.Bold,
                                fontSize = 17.sp
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = "Blocked",
                                color = TextSecondary,
                                fontSize = 10.5.sp,
                                maxLines = 1
                            )
                        }

                        Box(
                            modifier = Modifier
                                .width(1.dp)
                                .height(26.dp)
                                .background(BorderSubtle)
                        )

                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(
                                text = "$blockedTrackers",
                                color = EmeraldPrimary,
                                fontWeight = FontWeight.Bold,
                                fontSize = 17.sp
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = "Trackers",
                                color = TextSecondary,
                                fontSize = 10.5.sp,
                                maxLines = 1
                            )
                        }

                        Box(
                            modifier = Modifier
                                .width(1.dp)
                                .height(26.dp)
                                .background(BorderSubtle)
                        )

                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(
                                text = if (remoteScamApps.isEmpty() && !wifiReport.isProxyDetected) "Safe" else "Review",
                                color = if (remoteScamApps.isEmpty() && !wifiReport.isProxyDetected) EmeraldSoft else DangerSoft,
                                fontWeight = FontWeight.Bold,
                                fontSize = 17.sp
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = "Network",
                                color = TextSecondary,
                                fontSize = 10.5.sp,
                                maxLines = 1
                            )
                        }
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
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981)),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(44.dp)
                    ) {
                        Icon(
                            imageVector = if (quickScanComplete) Icons.Default.CheckCircle else Icons.Default.Radar,
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(17.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (isQuickScanning) "Checking Device Security..." else if (quickScanComplete) "All Checks Passed • Scan Again" else "Run Security Check",
                            color = Color.White,
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.5.sp
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        text = if (quickScanComplete) "Last scanned: Just now • Definitions up to date" else "Continuous background protection active",
                        color = TextSecondary,
                        fontSize = 11.sp,
                        textAlign = TextAlign.Center
                    )
                }
            }
        }

        // 2. Daily Feature: "Safe for Banking & UPI" Live Readiness Check + OTP Clipboard Scrubber
        item {
            var bankingScanTrigger by remember { mutableIntStateOf(0) }
            var isCheckingBanking by remember { mutableStateOf(false) }
            var bankingVerifiedJustNow by remember { mutableStateOf(false) }
            var clipboardClearedJustNow by remember { mutableStateOf(false) }
            val bankingReport = remember(bankingScanTrigger, quickScanComplete) {
                PeopleProtectionTools.runBankingUpiSafetyCheck(context)
            }

            Card(
                colors = CardDefaults.cardColors(containerColor = SurfaceCard),
                shape = RoundedCornerShape(20.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(
                        1.dp,
                        if (bankingReport.isAllSafe) EmeraldPrimary.copy(alpha = 0.45f) else DangerSoft.copy(alpha = 0.45f),
                        RoundedCornerShape(20.dp)
                    )
            ) {
                Column(modifier = Modifier.padding(18.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(44.dp)
                                .background(
                                    if (bankingReport.isAllSafe) EmeraldDark.copy(alpha = 0.7f) else DangerBg,
                                    RoundedCornerShape(12.dp)
                                ),
                            contentAlignment = Alignment.Center
                        ) {
                            if (isCheckingBanking) {
                                CircularProgressIndicator(
                                    color = EmeraldSoft,
                                    strokeWidth = 2.5.dp,
                                    modifier = Modifier.size(22.dp)
                                )
                            } else {
                                Icon(
                                    imageVector = Icons.Default.AccountBalance,
                                    contentDescription = null,
                                    tint = if (bankingReport.isAllSafe) EmeraldSoft else DangerSoft,
                                    modifier = Modifier.size(22.dp)
                                )
                            }
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = "Safe for Banking & UPI",
                                    color = TextPrimary,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 15.sp
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Surface(
                                    color = if (bankingReport.isAllSafe) EmeraldDark else DangerBg,
                                    shape = RoundedCornerShape(50)
                                ) {
                                    Text(
                                        text = if (bankingReport.isAllSafe) "SAFE TO PAY" else "REVIEW",
                                        color = if (bankingReport.isAllSafe) EmeraldSoft else DangerSoft,
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.ExtraBold,
                                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                                    )
                                }
                            }
                            Text(
                                text = "Run before opening banking or UPI payment apps",
                                color = TextSecondary,
                                fontSize = 11.sp
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(SurfaceElevated, RoundedCornerShape(10.dp))
                            .border(1.dp, BorderSubtle, RoundedCornerShape(10.dp))
                            .padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        BankingCheckRow(
                            isSafe = bankingReport.screenShareSafe,
                            label = bankingReport.screenShareDetail
                        )
                        BankingCheckRow(
                            isSafe = bankingReport.networkSafe,
                            label = bankingReport.networkDetail
                        )
                        BankingCheckRow(
                            isSafe = bankingReport.usbDebuggingSafe,
                            label = bankingReport.usbDebuggingDetail
                        )
                        BankingCheckRow(
                            isSafe = bankingReport.screenOverlaySafe,
                            label = bankingReport.screenOverlayDetail
                        )
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Button(
                            onClick = {
                                if (!isCheckingBanking) {
                                    isCheckingBanking = true
                                    scope.launch {
                                        delay(700)
                                        bankingScanTrigger++
                                        isCheckingBanking = false
                                        bankingVerifiedJustNow = true
                                    }
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = EmeraldPrimary),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.weight(1.3f),
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 10.dp)
                        ) {
                            Icon(
                                imageVector = if (bankingVerifiedJustNow) Icons.Default.Verified else Icons.Default.Shield,
                                contentDescription = null,
                                tint = Color.White,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = when {
                                    isCheckingBanking -> "Verifying..."
                                    bankingVerifiedJustNow -> "Verified Safe"
                                    else -> "Verify Now"
                                },
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 12.sp
                            )
                        }

                        OutlinedButton(
                            onClick = {
                                PeopleProtectionTools.scrubClipboard(context)
                                clipboardClearedJustNow = true
                            },
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.weight(1f),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp)
                        ) {
                            Text(
                                text = if (clipboardClearedJustNow) "Clipboard Cleared ✓" else "Clear Copied OTPs",
                                color = if (clipboardClearedJustNow) EmeraldSoft else CyanSoft,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 11.sp,
                                maxLines = 1
                            )
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
                title = "Scam & Malware Uninstall Lock",
                subtitle = "Stops scammers or malware popups from tricking you into deleting ZeroPro.",
                isEnabled = isDeviceAdminActive,
                isProFeature = false,
                isProUnlocked = true,
                buttonText = if (isDeviceAdminActive) "Locked" else "Enable",
                onClick = {
                    pendingDisclosure = ProminentDisclosureType.DEVICE_ADMIN
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
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, BorderSubtle, RoundedCornerShape(16.dp))
            ) {
                Column(
                    modifier = Modifier.padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Box(
                        modifier = Modifier
                            .size(60.dp)
                            .background(
                                Color(0xFF161F30),
                                CircleShape
                            )
                            .border(1.5.dp, Color(0xFF10B981), CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            Icons.Default.DataUsage,
                            contentDescription = null,
                            tint = Color(0xFF10B981),
                            modifier = Modifier.size(30.dp)
                        )
                    }
                    Spacer(modifier = Modifier.height(16.dp))
                    Surface(
                        color = Color(0xFF162820),
                        shape = RoundedCornerShape(4.dp),
                        modifier = Modifier.border(1.dp, Color(0xFF10B981).copy(alpha = 0.4f), RoundedCornerShape(4.dp))
                    ) {
                        Text(
                            text = "24/7 ACTIVE DATA GUARD",
                            color = Color(0xFF10B981),
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 3.dp)
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
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFFACC15)),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.AutoAwesome, contentDescription = null, tint = Color(0xFF0B0F19))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Unlock 24/7 Data Guard",
                            color = Color(0xFF0B0F19),
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp
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
            ShieldFilterPill(
                selected = filterMode == 0,
                onClick = { filterMode = 0 },
                label = "All Apps (${reports.size})"
            )
            ShieldFilterPill(
                selected = filterMode == 1,
                onClick = { filterMode = 1 },
                label = "High Upload"
            )
            ShieldFilterPill(
                selected = filterMode == 2,
                onClick = { filterMode = 2 },
                label = "With Permissions"
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
            ShieldFilterPill(
                selected = filterMode == 0,
                onClick = { filterMode = 0 },
                label = "Active Permissions (${appsWithPermissions.size})"
            )
            ShieldFilterPill(
                selected = filterMode == 1,
                onClick = { filterMode = 1 },
                label = "No Permissions (${appsWithZeroPermissions.size})"
            )
            ShieldFilterPill(
                selected = filterMode == 2,
                onClick = { filterMode = 2 },
                label = "Sideloaded (${sideloadedOrHiddenApps.size})"
            )
            ShieldFilterPill(
                selected = filterMode == 3,
                onClick = { filterMode = 3 },
                label = "All Apps (${allApps.size})"
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
                                        item.dangerousPermissions.isNotEmpty() -> EmeraldDark
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
                                            item.dangerousPermissions.isNotEmpty() -> EmeraldSoft
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
                                                Color(0xFF10B981).copy(alpha = 0.4f),
                                                RoundedCornerShape(8.dp)
                                            )
                                        ) {
                                            Text(
                                                text = perm,
                                                color = Color(0xFF10B981),
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
                                    border = BorderStroke(1.dp, Color(0xFF10B981).copy(alpha = 0.45f)),
                                    shape = RoundedCornerShape(10.dp),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text(
                                        text = if (item.dangerousPermissions.isNotEmpty()) "Review Permissions" else "App Settings",
                                        fontSize = 12.sp,
                                        color = Color(0xFF10B981),
                                        fontWeight = FontWeight.SemiBold
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
                        val hasHiddenApk = result.url.contains(".apk", ignoreCase = true) ||
                            result.reasons.any { it.contains("APK", ignoreCase = true) }
                        ShieldRepository.recordAndAlertThreat(
                            context = context,
                            type = ThreatType.MALICIOUS_LINK_BLOCKED,
                            severity = Severity.CRITICAL,
                            sourcePackageOrUrl = result.url,
                            title = if (hasHiddenApk) "HIGH ALERT: Hidden APK Detected in Link!" else "Suspicious Link Blocked",
                            description = result.reasons.joinToString("\n• ", prefix = "• "),
                            actionTaken = if (hasHiddenApk) "HIDDEN APK LINK STRICTLY BLOCKED — Do Not Open" else "Flagged by Safe Link Checker",
                            showFullScreenPopup = hasHiddenApk
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
            val hasHiddenApk = res.url.contains(".apk", ignoreCase = true) ||
                res.reasons.any { it.contains("APK", ignoreCase = true) }
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = if (res.isThreat) DangerBg else EmeraldDark.copy(alpha = 0.55f)
                ),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(
                        if (hasHiddenApk) 2.dp else 1.dp,
                        if (res.isThreat) DangerSoft.copy(alpha = if (hasHiddenApk) 0.85f else 0.4f) else EmeraldPrimary.copy(alpha = 0.4f),
                        RoundedCornerShape(16.dp)
                    )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    if (hasHiddenApk) {
                        Surface(
                            color = Color(0xFFDC2626),
                            shape = RoundedCornerShape(50),
                            modifier = Modifier.padding(bottom = 8.dp)
                        ) {
                            Text(
                                text = "🚨 HIGH ALERT • HIDDEN APK IN LINK",
                                color = Color.White,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.ExtraBold,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                            )
                        }
                    }
                    Text(
                        text = when {
                            hasHiddenApk -> "HIGH ALERT: Hidden APK Detected in Link!"
                            res.isThreat -> "Unsafe Link Detected"
                            else -> "Link Appears Safe"
                        },
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
                        if (hasHiddenApk) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                "⚠️ STRICT SECURITY WARNING: This link secretly delivers an Android installer (.apk) file. Opening it can allow attackers to steal OTPs, banking messages, or control your screen. Do NOT open this link.",
                                color = DangerSoft,
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
private fun ShieldFilterPill(
    selected: Boolean,
    label: String,
    onClick: () -> Unit
) {
    Surface(
        color = if (selected) Color(0xFF162820) else SurfaceElevated,
        shape = RoundedCornerShape(20.dp),
        modifier = Modifier
            .border(
                width = 1.dp,
                color = if (selected) Color(0xFF10B981) else BorderSubtle,
                shape = RoundedCornerShape(20.dp)
            )
            .clickable { onClick() }
    ) {
        Text(
            text = label,
            color = if (selected) Color(0xFF10B981) else TextSecondary,
            fontSize = 11.5.sp,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
        )
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
        color = SurfaceElevated,
        shape = RoundedCornerShape(10.dp),
        modifier = modifier.border(1.dp, BorderSubtle, RoundedCornerShape(10.dp))
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
                            color = Color(0xFFFACC15),
                            shape = RoundedCornerShape(50),
                            modifier = Modifier.border(1.dp, Color(0xFFFACC15), RoundedCornerShape(50))
                        ) {
                            Text(
                                text = "PRO",
                                color = Color(0xFF0B0F19),
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

@Composable
private fun BankingCheckRow(
    isSafe: Boolean,
    label: String
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
            imageVector = if (isSafe) Icons.Default.CheckCircle else Icons.Default.Warning,
            contentDescription = null,
            tint = if (isSafe) EmeraldSoft else DangerSoft,
            modifier = Modifier.size(15.dp)
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = label,
            color = if (isSafe) TextPrimary else DangerSoft,
            fontSize = 12.sp
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
