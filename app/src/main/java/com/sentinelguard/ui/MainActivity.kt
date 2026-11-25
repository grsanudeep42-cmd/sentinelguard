package com.sentinelguard.ui

import android.app.Activity
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.sentinelguard.keystore.SentinelKeyManagerHolder
import com.sentinelguard.ui.screens.DashboardScreen
import com.sentinelguard.ui.screens.SystemStatusScreen
import com.sentinelguard.ui.screens.ThreatLogScreen
import com.sentinelguard.ui.theme.ColorAccent
import com.sentinelguard.ui.theme.ColorBackground
import com.sentinelguard.ui.theme.ColorSurface
import com.sentinelguard.ui.theme.ColorTextSecondary
import com.sentinelguard.ui.theme.SentinelGuardTheme
import com.sentinelguard.vpn.SentinelVpnService
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController

// ─────────────────────────────────────────────────────────────────────────────
// Navigation destinations
// ─────────────────────────────────────────────────────────────────────────────

private object Route {
    const val DASHBOARD     = "dashboard"
    const val THREAT_LOG    = "threat_log"
    const val SYSTEM_STATUS = "system_status"
}

/** Describes a single bottom-nav item. */
private data class NavItem(
    val route:       String,
    val icon:        ImageVector,
    val label:       String,
    val contentDesc: String
)

private val NAV_ITEMS = listOf(
    NavItem(Route.DASHBOARD,     Icons.Filled.Shield,           "Shield",   "Dashboard"),
    NavItem(Route.THREAT_LOG,    Icons.AutoMirrored.Filled.List, "Log",      "Threat Log"),
    NavItem(Route.SYSTEM_STATUS, Icons.Filled.Info,             "Status",   "System Status")
)

// ─────────────────────────────────────────────────────────────────────────────
// Activity
// ─────────────────────────────────────────────────────────────────────────────

class MainActivity : ComponentActivity() {

    private val mainViewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            SentinelGuardTheme {

                // ── Collect state from MainViewModel ──────────────────────────
                val vpnActive     by mainViewModel.vpnActive.collectAsStateWithLifecycle()
                val recentThreats by mainViewModel.recentThreats.collectAsStateWithLifecycle()
                val threatCounts  by mainViewModel.threatCounts.collectAsStateWithLifecycle()
                val keystoreInfo  by mainViewModel.keystoreInfo.collectAsStateWithLifecycle()
                val systemStatus  by mainViewModel.systemStatus.collectAsStateWithLifecycle()
                val allVerdicts   by mainViewModel.allVerdicts.collectAsStateWithLifecycle()
                val blocklistStats by mainViewModel.blocklistStats.collectAsStateWithLifecycle()
                val exportMessage by mainViewModel.exportMessage.collectAsStateWithLifecycle()

                // ── VPN permission launcher ───────────────────────────────────
                val vpnPermissionLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.StartActivityForResult()
                ) { result ->
                    if (result.resultCode == Activity.RESULT_OK) {
                        SentinelVpnService.start(this)
                        mainViewModel.setVpnActive(true)
                    } else {
                        // User denied — revert toggle state
                        mainViewModel.setVpnActive(false)
                    }
                }

                // ── VPN toggle handler ────────────────────────────────────────
                val onVpnToggle: (Boolean) -> Unit = { requestedEnabled ->
                    if (requestedEnabled) {
                        val prepareIntent = VpnService.prepare(this)
                        if (prepareIntent != null) {
                            // System needs explicit user consent via dialog
                            vpnPermissionLauncher.launch(prepareIntent)
                        } else {
                            // Permission already granted — start immediately
                            SentinelVpnService.start(this)
                            mainViewModel.setVpnActive(true)
                        }
                    } else {
                        SentinelVpnService.stop(this)
                        mainViewModel.setVpnActive(false)
                    }
                }

                // ── Root navigation host ──────────────────────────────────────
                val navController = rememberNavController()

                SentinelNavHost(
                    navController  = navController,
                    vpnActive      = vpnActive,
                    onVpnToggle    = onVpnToggle,
                    threatCounts   = threatCounts,
                    recentThreats  = recentThreats,
                    keystoreInfo   = keystoreInfo,
                    systemStatus   = systemStatus,
                    allVerdicts    = allVerdicts,
                    blocklistStats = blocklistStats,
                    onRefresh         = { mainViewModel.refreshVerdicts() },
                    onSaveExplanation = { id, text -> mainViewModel.saveExplanation(id, text) },
                    onExport          = { mainViewModel.exportVerdicts(this@MainActivity) },
                    exportMessage     = exportMessage,
                    onClearExportMsg  = { mainViewModel.clearExportMessage() }
                )
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NavHost + Scaffold
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun SentinelNavHost(
    navController:  NavHostController,
    vpnActive:      Boolean,
    onVpnToggle:    (Boolean) -> Unit,
    threatCounts:   ThreatCounts,
    recentThreats:  List<com.sentinelguard.vpn.ThreatEvent>,
    keystoreInfo:   com.sentinelguard.keystore.KeystoreAttestationInfo,
    systemStatus:   SystemStatus,
    allVerdicts:    List<com.sentinelguard.keystore.SignedVerdictEntity>,
    blocklistStats: BlocklistStats,
    onRefresh:         () -> Unit,
    onSaveExplanation: (Long, String) -> Unit,
    onExport:          () -> Unit,
    exportMessage:     String?,
    onClearExportMsg:  () -> Unit
) {
    Scaffold(
        containerColor = ColorBackground,
        bottomBar = {
            SentinelBottomBar(navController = navController)
        }
    ) { innerPadding ->

        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(ColorBackground)
                .padding(bottom = innerPadding.calculateBottomPadding())
        ) {
            NavHost(
                navController    = navController,
                startDestination = Route.DASHBOARD
            ) {

                // ── Dashboard ─────────────────────────────────────────────────
                composable(Route.DASHBOARD) {
                    DashboardScreen(
                        vpnActive     = vpnActive,
                        onToggle      = onVpnToggle,
                        threatCounts  = threatCounts,
                        recentThreats = recentThreats,
                        keystoreInfo  = keystoreInfo,
                        keystoreReady = SentinelKeyManagerHolder.isReady
                    )
                }

                // ── Threat Log ────────────────────────────────────────────────
                composable(Route.THREAT_LOG) {
                    ThreatLogScreen(
                        verdicts           = allVerdicts,
                        onRefresh          = onRefresh,
                        onSaveExplanation  = onSaveExplanation,
                        onExport           = onExport,
                        exportMessage      = exportMessage,
                        onExportMsgShown   = onClearExportMsg
                    )
                }

                // ── System Status ─────────────────────────────────────────────
                composable(Route.SYSTEM_STATUS) {
                    SystemStatusScreen(
                        systemStatus   = systemStatus,
                        keystoreInfo   = keystoreInfo,
                        keystoreReady  = SentinelKeyManagerHolder.isReady,
                        blocklistStats = blocklistStats
                    )
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bottom navigation bar
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun SentinelBottomBar(navController: NavHostController) {
    val backStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute   = backStackEntry?.destination?.route

    NavigationBar(
        containerColor = ColorSurface,
        tonalElevation = 0.dp,
        modifier       = Modifier.height(64.dp)
    ) {
        NAV_ITEMS.forEach { item ->
            val selected = currentRoute == item.route

            NavigationBarItem(
                selected = selected,
                onClick  = {
                    if (currentRoute != item.route) {
                        navController.navigate(item.route) {
                            // Pop up to the start destination to avoid back-stack accumulation
                            popUpTo(Route.DASHBOARD) { saveState = true }
                            launchSingleTop = true
                            restoreState    = true
                        }
                    }
                },
                icon = {
                    Icon(
                        imageVector        = item.icon,
                        contentDescription = item.contentDesc,
                        modifier           = Modifier.size(22.dp)
                    )
                },
                label = {
                    AnimatedVisibility(
                        visible = selected,
                        enter   = fadeIn(),
                        exit    = fadeOut()
                    ) {
                        Text(
                            text       = item.label,
                            fontSize   = 10.sp,
                            fontWeight = FontWeight.Medium,
                            letterSpacing = 0.4.sp
                        )
                    }
                },
                alwaysShowLabel = false,
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor   = ColorAccent,
                    selectedTextColor   = ColorAccent,
                    indicatorColor      = ColorAccent.copy(alpha = 0.15f),
                    unselectedIconColor = ColorTextSecondary,
                    unselectedTextColor = ColorTextSecondary
                )
            )
        }
    }
}
