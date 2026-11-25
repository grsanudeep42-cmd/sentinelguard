package com.sentinelguard.ui

import android.app.Application
import android.content.Context
import android.content.ContentValues
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.sentinelguard.dns.SentinelDatabase
import com.sentinelguard.keystore.KeystoreAttestationInfo
import com.sentinelguard.keystore.SentinelKeyManager
import com.sentinelguard.keystore.SentinelKeyManagerHolder
import com.sentinelguard.keystore.SignedVerdictEntity
import com.sentinelguard.keystore.VerdictExporter
import com.sentinelguard.SentinelApplication
import com.sentinelguard.sms.ConnectionAnalyserHolder
import com.sentinelguard.vpn.BootReceiver
import com.sentinelguard.vpn.ConnectionAnalyser
import com.sentinelguard.vpn.SentinelVpnService
import com.sentinelguard.vpn.ThreatEvent
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import java.text.SimpleDateFormat
import java.util.*

// ─────────────────────────────────────────────────────────────────────────────
// Supporting data classes
// ─────────────────────────────────────────────────────────────────────────────

data class ThreatCounts(
    val dns:         Int = 0,
    val sms:         Int = 0,
    val connections: Int = 0
)

data class SystemStatus(
    val dnsInspectorActive:         Boolean = false,
    val smsMonitorActive:           Boolean = false,
    val notificationListenerActive: Boolean = false,
    val vpnTunnelActive:            Boolean = false
)

data class BlocklistStats(
    val totalDomains: Int  = 0,
    val lastUpdated:  Long = 0L
)

// ─────────────────────────────────────────────────────────────────────────────
// MainViewModel
// ─────────────────────────────────────────────────────────────────────────────

/**
 * [MainViewModel] — single ViewModel that backs all three nav screens.
 *
 * Exposes:
 *   - [vpnActive]       SharedPreference-persisted VPN toggle state.
 *   - [recentThreats]   Live-updated list of the last 5 [ThreatEvent]s.
 *   - [threatCounts]    Running counters broken down by threat category.
 *   - [keystoreInfo]    Hardware attestation snapshot.
 *   - [systemStatus]    Per-module active/inactive flags.
 *   - [allVerdicts]     Room-backed flow of all [SignedVerdictEntity] rows.
 *   - [blocklistStats]  Count of blocked domains + last-fetch timestamp.
 */
class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val prefs = application.getSharedPreferences(
        BootReceiver.PREFS_NAME,
        Context.MODE_PRIVATE
    )

    private val db = SentinelDatabase.getInstance(application)

    // ── VPN toggle ───────────────────────────────────────────────────────────

    private val _vpnActive = MutableStateFlow(SentinelVpnService.isRunning.value)
    val vpnActive: StateFlow<Boolean> = _vpnActive.asStateFlow()

    fun setVpnActive(enabled: Boolean) {
        _vpnActive.value = enabled
        prefs.edit().putBoolean(BootReceiver.PREF_VPN_ENABLED, enabled).apply()
    }

    // ── Recent threats (last 5) ──────────────────────────────────────────────

    private val _recentThreats = MutableStateFlow<List<ThreatEvent>>(emptyList())
    val recentThreats: StateFlow<List<ThreatEvent>> = _recentThreats.asStateFlow()

    // ── Threat counters ──────────────────────────────────────────────────────

    private val _threatCounts = MutableStateFlow(ThreatCounts())
    val threatCounts: StateFlow<ThreatCounts> = _threatCounts.asStateFlow()

    // ── Keystore attestation ─────────────────────────────────────────────────

    private val _keystoreInfo = MutableStateFlow(
        KeystoreAttestationInfo(false, false, "UNKNOWN", 0L)
    )
    val keystoreInfo: StateFlow<KeystoreAttestationInfo> = _keystoreInfo.asStateFlow()

    // ── System status (module active flags) ──────────────────────────────────

    private val _systemStatus = MutableStateFlow(SystemStatus())
    val systemStatus: StateFlow<SystemStatus> = _systemStatus.asStateFlow()

    // ── All signed verdicts from Room ────────────────────────────────────────

    /**
     * Hot flow of all [SignedVerdictEntity] rows, newest first.
     * Polled once on init and refreshed whenever [refreshVerdicts] is called.
     */
    private val _allVerdicts = MutableStateFlow<List<SignedVerdictEntity>>(emptyList())
    val allVerdicts: StateFlow<List<SignedVerdictEntity>> = _allVerdicts.asStateFlow()

    // ── Blocklist stats ──────────────────────────────────────────────────────

    private val _blocklistStats = MutableStateFlow(BlocklistStats())
    val blocklistStats: StateFlow<BlocklistStats> = _blocklistStats.asStateFlow()

    // ─────────────────────────────────────────────────────────────────────────
    // Init
    // ─────────────────────────────────────────────────────────────────────────

    init {
        viewModelScope.launch {
            SentinelVpnService.isRunning.collect { running ->
                _vpnActive.value = running
                _systemStatus.update { it.copy(vpnTunnelActive = running) }
            }
        }
        collectThreatEvents()
        loadKeystoreInfo()
        loadBlocklistStats()
        refreshVerdicts()
        refreshSystemStatus()

        // On first launch the asset-seed coroutine in SentinelApplication runs
        // concurrently with this ViewModel init. Poll again after a short delay so
        // the UI reflects the domain count once seeding completes (~2–8 s on first run).
        viewModelScope.launch {
            delay(BLOCKLIST_RECHECK_DELAY_MS)
            loadBlocklistStats()
            refreshSystemStatus()
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Threat event collection
    // ─────────────────────────────────────────────────────────────────────────

    private fun collectThreatEvents() {
        val analyser = ConnectionAnalyserHolder.analyser ?: return

        viewModelScope.launch {
            analyser.threatEvents.collect { event ->
                // Update recent list (cap at 5, newest first)
                _recentThreats.update { prev ->
                    (listOf(event) + prev).take(5)
                }

                // Update counters
                _threatCounts.update { prev ->
                    when {
                        event.type == "DNS_THREAT"  -> prev.copy(dns = prev.dns + 1)
                        event.type == "SMS_SCAM"    -> prev.copy(sms = prev.sms + 1)
                        else                        -> prev.copy(connections = prev.connections + 1)
                    }
                }

                // Refresh Room list when new threat comes in
                refreshVerdicts()

                // Update VPN tunnel active state based on live events
                _systemStatus.update { it.copy(vpnTunnelActive = true) }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Data loaders
    // ─────────────────────────────────────────────────────────────────────────

    private fun loadKeystoreInfo() {
        viewModelScope.launch {
            if (SentinelKeyManagerHolder.isReady) {
                _keystoreInfo.value = SentinelKeyManager.getAttestationInfo()
            }
        }
    }

    private fun loadBlocklistStats() {
        viewModelScope.launch {
            runCatching {
                val count = db.blockedDomainDao().count().toInt()
                _blocklistStats.value = BlocklistStats(
                    totalDomains = count,
                    lastUpdated  = prefs.getLong(PREF_BLOCKLIST_UPDATED, 0L)
                )
            }
        }
    }

    fun refreshVerdicts() {
        viewModelScope.launch {
            runCatching {
                _allVerdicts.value = db.signedVerdictDao().getAll()
            }
        }
    }

    /**
     * Persists a Llama-generated explanation for a [SignedVerdictEntity] row.
     * Called from the UI after [ExplanationBottomSheet] finishes streaming tokens.
     * Triggers a verdicts refresh so the expanded row immediately shows the saved text.
     */
    fun saveExplanation(verdictId: Long, explanation: String) {
        viewModelScope.launch {
            runCatching {
                db.signedVerdictDao().updateExplanation(verdictId, explanation)
            }
            refreshVerdicts()
        }
    }

    /**
     * Export all signed verdicts as a JSON file to Downloads/SentinelGuard_audit_<timestamp>.json.
     * Uses MediaStore on API 29+ (scoped storage) so no extra permissions are needed.
     * Returns the display name of the saved file, or null on failure.
     */
    fun exportVerdicts(context: Context) {
        viewModelScope.launch {
            runCatching {
                val json      = VerdictExporter.exportAsJson(context)
                val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
                val fileName  = "SentinelGuard_audit_$timestamp.json"

                val resolver = context.contentResolver
                val values   = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, fileName)
                    put(MediaStore.Downloads.MIME_TYPE, "application/json")
                    put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                }
                val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                uri?.let {
                    resolver.openOutputStream(it)?.use { out ->
                        out.write(json.toByteArray(Charsets.UTF_8))
                    }
                }
                fileName
            }.onSuccess { fileName ->
                _exportMessage.value = "Audit log exported to Downloads/$fileName"
            }.onFailure {
                _exportMessage.value = "Export failed: ${it.message}"
            }
        }
    }

    private val _exportMessage = MutableStateFlow<String?>(null)
    val exportMessage: StateFlow<String?> = _exportMessage.asStateFlow()

    fun clearExportMessage() { _exportMessage.value = null }

    fun refreshSystemStatus() {
        _systemStatus.update {
            it.copy(
                vpnTunnelActive            = SentinelVpnService.isRunning.value,
                // DNS Inspector is active once its in-memory blocklist has been populated
                dnsInspectorActive         = _blocklistStats.value.totalDomains > 0,
                smsMonitorActive           = true,  // always registered as BroadcastReceiver
                notificationListenerActive = true   // system manages binding
            )
        }
        // Also refresh keystore now that it may have finished initialising
        loadKeystoreInfo()
    }

    companion object {
        // Key defined in SentinelApplication — used by both asset seeder and BlocklistUpdater
        private const val PREF_BLOCKLIST_UPDATED = SentinelApplication.PREF_BLOCKLIST_UPDATED

        /** How long to wait before re-checking blocklist stats after first-launch seed. */
        private const val BLOCKLIST_RECHECK_DELAY_MS = 8_000L
    }
}
