package com.sentinelguard.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * BootReceiver — restores the VPN tunnel after a device reboot.
 *
 * Listens for [Intent.ACTION_BOOT_COMPLETED] and the HTC/ASUS quick-boot
 * variant [QUICKBOOT_POWERON]. If the user had previously enabled protection
 * (persisted as [PREF_VPN_ENABLED] in [PREFS_NAME]), the VPN service is
 * started automatically without requiring user interaction.
 *
 * Registration in AndroidManifest.xml requires:
 *   android:permission="android.permission.RECEIVE_BOOT_COMPLETED"
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED && action != QUICKBOOT_POWERON) return

        Log.i(TAG, "Boot completed — checking VPN auto-start preference")

        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val vpnEnabled = prefs.getBoolean(PREF_VPN_ENABLED, false)

        if (vpnEnabled) {
            Log.i(TAG, "vpn_enabled=true — starting SentinelVpnService")
            SentinelVpnService.start(context)
        } else {
            Log.d(TAG, "vpn_enabled=false — skipping auto-start")
        }
    }

    companion object {
        private const val TAG = "BootReceiver"

        /** Action broadcast by HTC / ASUS devices instead of BOOT_COMPLETED. */
        const val QUICKBOOT_POWERON = "android.intent.action.QUICKBOOT_POWERON"

        /** SharedPreferences file name — must match the value used in MainActivity. */
        const val PREFS_NAME = "sentinel_prefs"

        /** Key that records whether the user has enabled VPN protection. */
        const val PREF_VPN_ENABLED = "vpn_enabled"
    }
}
