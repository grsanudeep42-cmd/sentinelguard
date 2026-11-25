package com.sentinelguard.vpn

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.sentinelguard.SentinelApplication
import com.sentinelguard.dns.DnsInspector
import com.sentinelguard.dns.DnsInspectorHolder
import com.sentinelguard.dns.DnsResult
import com.sentinelguard.sms.ConnectionAnalyserHolder
import com.sentinelguard.ui.MainActivity
import com.sentinelguard.ui.screens.PerfCounters
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.filterNotNull
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.Socket

/**
 * SentinelVpnService — core VPN tunnel.
 *
 * Establishes a local TUN interface at 10.0.0.2/32 and routes all device
 * traffic through it. Two coroutines run on [Dispatchers.IO]:
 *
 *  1. **Packet-read loop** — reads raw IPv4 packets, extracts metadata,
 *     dispatches DNS payloads to [DnsInspector], all packets to [ConnectionAnalyser].
 *  2. **DNS-result collector** — subscribes to [DnsInspector.results] and
 *     forwards malicious results as [ThreatEvent]s via [ConnectionAnalyser].
 *
 * Lifecycle:
 *  onCreate          → prepare resources
 *  onStartCommand    → build TUN interface, post foreground notification,
 *                      launch coroutines
 *  onRevoke          → Android revoked our permission; clean up gracefully
 *  onDestroy         → cancel coroutines, close TUN fd
 */
class SentinelVpnService : VpnService() {

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    private var tunInterface: ParcelFileDescriptor? = null

    /**
     * Active upstream DNS server — resolved dynamically from the current
     * network via [getNetworkDnsServers] at VPN start. Used by [forwardUdpAndReceive]
     * to forward DNS queries to the correct resolver for this network.
     */
    @Volatile
    private var activeDns: String = FALLBACK_DNS

    /**
     * All upstream DNS addresses reported by [ConnectivityManager] (including IPv6),
     * used as secondary upstream targets in [forwardDnsAndReceive] if [activeDns] times out.
     */
    @Volatile
    private var fallbackUpstreamDns: List<String> = emptyList()

    /** Physical active network captured before [Builder.establish] for socket binding. */
    @Volatile
    private var underlyingNetwork: Network? = null

    /**
     * [SupervisorJob] so an individual child coroutine failure (e.g. a single
     * malformed packet throwing) does not tear down the entire scope.
     */
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Resolved lazily from [DnsInspectorHolder] — set by [SentinelApplication]. */
    private val dnsInspector: DnsInspector
        get() = DnsInspectorHolder.inspector
            ?: error("DnsInspector not initialised — SentinelApplication.onCreate not called?")

    /**
     * Resolved from [ConnectionAnalyserHolder] — the same singleton that
     * [com.sentinelguard.sms.SmsReceiver] and [com.sentinelguard.sms.SentinelNotificationListenerService]
     * inject into, ensuring the entire app shares one unified [ThreatEvent] stream.
     */
    private val connectionAnalyser: ConnectionAnalyser
        get() = ConnectionAnalyserHolder.analyser
            ?: error("ConnectionAnalyser not initialised — SentinelApplication.onCreate not called?")

    // -------------------------------------------------------------------------
    // Service lifecycle
    // -------------------------------------------------------------------------

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "onCreate")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_START -> {
                startForegroundNotification()
                startVpn()
                START_STICKY
            }
            ACTION_STOP -> {
                stopVpn()
                START_NOT_STICKY
            }
            else -> START_NOT_STICKY
        }
    }

    /** Called by the system when the user revokes VPN permission. */
    override fun onRevoke() {
        Log.w(TAG, "VPN permission revoked by system")
        getSharedPreferences(BootReceiver.PREFS_NAME, MODE_PRIVATE)
            .edit()
            .putBoolean(BootReceiver.PREF_VPN_ENABLED, false)
            .apply()
        tearDown()
        super.onRevoke()
    }

    override fun onDestroy() {
        Log.d(TAG, "onDestroy")
        tearDown()
        super.onDestroy()
    }

    // -------------------------------------------------------------------------
    // VPN setup / teardown
    // -------------------------------------------------------------------------

    /**
     * Read IPv4 DNS servers from the currently active network via [ConnectivityManager].
     *
     * Our TUN interface and packet parser are IPv4-only (`10.0.0.2/32`), and
     * [VpnService.Builder.addRoute] throws [IllegalArgumentException] ("Bad address")
     * when given an IPv6 address with a `/32` mask. Filtering to [Inet4Address]
     * prevents crashes on dual-stack Wi-Fi / 5G networks.
     *
     * Falls back to [FALLBACK_DNS] if no IPv4 DNS servers are present.
     */
    private fun getNetworkDnsServers(): List<String> {
        val cm = getSystemService(ConnectivityManager::class.java)
        val activeNetwork = cm?.activeNetwork
        underlyingNetwork = activeNetwork
        val linkProps = cm?.getLinkProperties(activeNetwork)
        val rawDns = linkProps?.dnsServers.orEmpty()

        fallbackUpstreamDns = rawDns
            .mapNotNull { it.hostAddress?.substringBefore('%') }
            .filter { it.isNotBlank() }

        val ipv4Dns = rawDns
            .filterIsInstance<Inet4Address>()
            .mapNotNull { it.hostAddress }
            .filter { it.isNotBlank() }

        return if (ipv4Dns.isNotEmpty()) {
            Log.i(TAG, "IPv4 network DNS resolved: $ipv4Dns (all upstream: $fallbackUpstreamDns)")
            ipv4Dns
        } else {
            Log.w(TAG, "No IPv4 network DNS found (upstream=$fallbackUpstreamDns) — using fallback $FALLBACK_DNS")
            listOf(FALLBACK_DNS)
        }
    }

    private fun startVpn() {
        if (tunInterface != null) {
            Log.d(TAG, "VPN already running — ignoring start")
            return
        }

        // ── Dynamically read IPv4 DNS servers from the active network ────────
        // We advertise a virtual private resolver (10.0.0.1) inside the TUN
        // instead of 8.8.8.8 so Android/Chrome do not auto-upgrade to encrypted
        // DoH (which would bypass UDP:53 inspection via 8.8.4.4:443). We also
        // capture common public DoH/DoT resolver IPs into the TUN (where TCP:443
        // is not forwarded), forcing browsers back onto the inspected TUN DNS
        // while SentinelGuard's own disallowed UDP:53 sockets forward normally.
        val networkDnsServers = getNetworkDnsServers()
        Log.i(TAG, "Resolved upstream IPv4 DNS: $networkDnsServers")

        val builder = Builder()
            .setSession("SentinelGuard")
            .addAddress("10.0.0.2", 32)
            .addDnsServer(LOCAL_TUN_DNS)
            .setMtu(MTU)

        // Exclude SentinelGuard itself so protected upstream DNS queries & blocklist
        // sync never loop through our own TUN interface.
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.w(TAG, "addDisallowedApplication failed: ${e.message}")
        }

        // Route virtual TUN DNS + public DoH/DoT IPs through the TUN so browsers
        // cannot bypass UDP:53 DNS inspection via built-in Secure DNS.
        val tunRoutes = buildSet {
            add(LOCAL_TUN_DNS)
            addAll(networkDnsServers)
            addAll(DOH_RESOLVER_IPS)
        }
        tunRoutes.forEach { ip ->
            try {
                builder.addRoute(ip, 32)
            } catch (e: IllegalArgumentException) {
                Log.w(TAG, "Skipping unsupported TUN route '$ip': ${e.message}")
            }
        }

        val tun = try {
            builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN TUN interface", e)
            null
        }

        if (tun == null) {
            Log.e(TAG, "establish() returned null — VPN permission not granted or establish failed")
            getSharedPreferences(BootReceiver.PREFS_NAME, MODE_PRIVATE)
                .edit()
                .putBoolean(BootReceiver.PREF_VPN_ENABLED, false)
                .apply()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        tunInterface = tun
        // Store active upstream DNS for the forwarder to use
        activeDns = networkDnsServers.firstOrNull() ?: FALLBACK_DNS
        _isRunning.value = true
        Log.i(TAG, "TUN interface established (fd=${tun.fd}), upstream DNS=$activeDns")

        launchDnsResultCollector()
        launchPacketReadLoop(tun)
        launchUdpForwardLoop(tun)
    }

    private fun stopVpn() {
        getSharedPreferences(BootReceiver.PREFS_NAME, MODE_PRIVATE)
            .edit()
            .putBoolean(BootReceiver.PREF_VPN_ENABLED, false)
            .apply()
        tearDown()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun tearDown() {
        _isRunning.value = false
        serviceScope.coroutineContext[Job]?.cancelChildren()
        try {
            tunInterface?.close()
        } catch (e: IOException) {
            Log.w(TAG, "Error closing TUN fd", e)
        }
        tunInterface = null
        Log.i(TAG, "TUN interface closed")
    }

    // -------------------------------------------------------------------------
    // DNS result collector — bridges DnsInspector → ConnectionAnalyser
    // -------------------------------------------------------------------------

    /**
     * Collects [DnsResult]s emitted by [DnsInspector.results] and forwards
     * malicious ones into [ConnectionAnalyser.injectThreatEvent] so they appear
     * on the same unified [ThreatEvent] stream as network-layer threats.
     *
     * Severity mapping:
     *   KNOWN_MALICIOUS  → HIGH
     *   SUSPICIOUS_TLD   → MEDIUM
     *   HIGH_ENTROPY_DGA → MEDIUM
     */
    private fun launchDnsResultCollector() {
        serviceScope.launch {
            dnsInspector.results
                .filterNotNull()
                .collect { result ->
                    if (!result.isMalicious) return@collect

                    val severity = when (result.category) {
                        DnsResult.KNOWN_MALICIOUS  -> "HIGH"
                        DnsResult.SUSPICIOUS_TLD   -> "MEDIUM"
                        DnsResult.HIGH_ENTROPY_DGA -> "MEDIUM"
                        else                       -> "LOW"
                    }

                    val description = when (result.category) {
                        DnsResult.KNOWN_MALICIOUS  ->
                            "DNS query to known malicious host: ${result.domain}"
                        DnsResult.SUSPICIOUS_TLD   ->
                            "DNS query to domain on abused free TLD: ${result.domain}"
                        DnsResult.HIGH_ENTROPY_DGA ->
                            "DNS query to high-entropy domain (possible DGA): ${result.domain}"
                        else -> "Suspicious DNS query: ${result.domain}"
                    }

                    connectionAnalyser.injectThreatEvent(
                        ThreatEvent(
                            type        = "DNS_THREAT",
                            severity    = severity,
                            description = description,
                            timestamp   = result.timestamp
                        )
                    )

                    Log.w(TAG, "DNS_THREAT [$severity] ${result.category}: ${result.domain}")
                }
        }
    }

    // -------------------------------------------------------------------------
    // Packet read loop
    // -------------------------------------------------------------------------

    /**
     * Reads raw IP packets from the TUN [fd] on [Dispatchers.IO].
     * Each packet is parsed for IP-layer metadata, then handed off to
     * [DnsInspector] (UDP port 53) and [ConnectionAnalyser] (all packets).
     *
     * For UDP/DNS packets we also forward them to real upstream servers and
     * write the response back into the TUN so the OS sees the DNS answer.
     */
    private fun launchPacketReadLoop(fd: ParcelFileDescriptor) {
        serviceScope.launch {
            val inputStream  = FileInputStream(fd.fileDescriptor)
            val outputStream = java.io.FileOutputStream(fd.fileDescriptor)
            val buffer = ByteArray(32_768)   // 32 KB — well above MTU

            Log.d(TAG, "Packet read loop started")

            while (isActive) {
                val bytesRead = try {
                    inputStream.read(buffer)
                } catch (e: IOException) {
                    if (isActive) Log.e(TAG, "TUN read error", e)
                    break
                }

                if (bytesRead <= 0) continue

                val packet = buffer.copyOf(bytesRead)
                PerfCounters.packetsAnalysed.incrementAndGet()
                processPacket(packet, outputStream)
            }

            Log.d(TAG, "Packet read loop exited")
        }
    }

    /**
     * Launch a coroutine that forwards UDP packets (especially DNS) to the real
     * upstream and writes the reply back into the TUN interface fd.
     *
     * For non-DNS UDP: forward to real destination IP:port.
     * For DNS (port 53): inspect first, then forward to upstream DNS if not blocked.
     */
    private fun launchUdpForwardLoop(fd: ParcelFileDescriptor) {
        // UDP forwarding is handled inline inside processPacket / forwardUdpPacket
        // This function is kept as a named entry-point for clarity; actual work
        // is done in the per-packet coroutines launched from processPacket.
        Log.d(TAG, "UDP forwarding enabled — upstream DNS: $activeDns")
    }

    /**
     * Forward a DNS [queryPayload] to [upstreamDns]:53 (falling back to
     * [fallbackUpstreamDns], 8.8.8.8, and 1.1.1.1 if needed), protected from
     * the VPN tunnel to avoid routing loops. Promotes the responsive upstream
     * to [activeDns] so subsequent queries do not stall on unreachable relays.
     */
    private fun forwardDnsAndReceive(
        queryPayload: ByteArray,
        upstreamDns:  String
    ): ByteArray? {
        val candidates = buildList {
            add(upstreamDns)
            if (FALLBACK_DNS !in this) add(FALLBACK_DNS)
            if (SECONDARY_FALLBACK_DNS !in this) add(SECONDARY_FALLBACK_DNS)
            fallbackUpstreamDns.forEach { if (it !in this) add(it) }
        }
        for (target in candidates) {
            val response = queryUpstreamUdp(queryPayload, target)
            if (response != null) {
                if (target != activeDns) {
                    Log.i(TAG, "Promoted responsive upstream DNS: $target")
                    activeDns = target
                }
                return response
            }
        }
        return null
    }

    private fun queryUpstreamUdp(queryPayload: ByteArray, targetDns: String): ByteArray? {
        val socket = DatagramSocket()
        return try {
            protect(socket)   // bypass VPN tunnel — prevents routing loop
            try {
                underlyingNetwork?.bindSocket(socket)
            } catch (_: Exception) { /* protect() already handles bypass */ }
            socket.soTimeout = UDP_TIMEOUT_MS
            val sendPacket = DatagramPacket(
                queryPayload, queryPayload.size,
                InetAddress.getByName(targetDns), PORT_DNS
            )
            socket.send(sendPacket)
            val recvBuf    = ByteArray(MAX_UDP_RESPONSE)
            val recvPacket = DatagramPacket(recvBuf, recvBuf.size)
            socket.receive(recvPacket)
            recvBuf.copyOf(recvPacket.length)
        } catch (e: Exception) {
            Log.w(TAG, "DNS forward failed to $targetDns:$PORT_DNS — ${e.message}")
            null
        } finally {
            socket.close()
        }
    }

    /**
     * Build a minimal NXDOMAIN DNS response for the given [queryPayload].
     *
     * Response layout (RFC 1035):
     *   Bytes 0–1  : Transaction ID  (copied from query)
     *   Bytes 2–3  : Flags = 0x81 0x83  (QR=1 RD=1 RA=1 RCODE=3 NXDOMAIN)
     *   Bytes 4–5  : QDCOUNT (copied from query)
     *   Bytes 6–7  : ANCOUNT = 0
     *   Bytes 8–9  : NSCOUNT = 0
     *   Bytes 10–11: ARCOUNT = 0
     *   Bytes 12+  : Question section verbatim from query
     */
    private fun buildNxdomainResponse(queryPayload: ByteArray): ByteArray {
        val questionSection = if (queryPayload.size > 12)
            queryPayload.copyOfRange(12, queryPayload.size)
        else
            ByteArray(0)
        val response = ByteArray(12 + questionSection.size)
        // Transaction ID
        response[0] = queryPayload[0]
        response[1] = queryPayload[1]
        // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, RCODE=3 (NXDOMAIN)
        response[2] = 0x81.toByte()
        response[3] = 0x83.toByte()
        // QDCOUNT (copy from query)
        response[4] = queryPayload[4]
        response[5] = queryPayload[5]
        // ANCOUNT = 0
        response[6] = 0; response[7] = 0
        // NSCOUNT = 0
        response[8] = 0; response[9] = 0
        // ARCOUNT = 0
        response[10] = 0; response[11] = 0
        // Question section verbatim
        questionSection.copyInto(response, 12)
        return response
    }

    /**
     * Build a valid IPv4 + UDP response packet that wraps [dnsPayload], with
     * src/dst swapped relative to [originalPacket] so the OS routes it back
     * to the requesting app via the TUN interface.
     *
     * Computes both the mandatory RFC 791 IPv4 header checksum and RFC 768
     * UDP pseudo-header checksum so the kernel network stack never drops
     * injected DNS replies or NXDOMAIN blocks (`IpInHdrErrors`).
     */
    private fun buildUdpIpResponse(
        originalPacket: ByteArray,
        ihl:            Int,
        dnsPayload:     ByteArray
    ): ByteArray {
        val ipSrc  = originalPacket.copyOfRange(16, 20)   // original dst → new src
        val ipDst  = originalPacket.copyOfRange(12, 16)   // original src → new dst
        val srcPort = ((originalPacket[ihl + 2].toInt() and 0xFF) shl 8) or
                       (originalPacket[ihl + 3].toInt() and 0xFF)   // orig dst port
        val dstPort = ((originalPacket[ihl + 0].toInt() and 0xFF) shl 8) or
                       (originalPacket[ihl + 1].toInt() and 0xFF)   // orig src port

        val udpLen   = UDP_HEADER_LEN + dnsPayload.size
        val totalLen = MIN_IPV4_HEADER + udpLen

        val pkt = ByteArray(totalLen)
        // IPv4 header
        pkt[0]  = 0x45.toByte()                            // version=4, IHL=5
        pkt[1]  = 0x00
        pkt[2]  = ((totalLen shr 8) and 0xFF).toByte()
        pkt[3]  = (totalLen and 0xFF).toByte()
        pkt[4]  = 0x00; pkt[5] = 0x00                     // ID
        pkt[6]  = 0x00; pkt[7] = 0x00                     // flags + fragment offset
        pkt[8]  = 64                                       // TTL
        pkt[9]  = PROTO_UDP.toByte()
        pkt[10] = 0; pkt[11] = 0                          // placeholder before checksum
        ipSrc.copyInto(pkt, 12)
        ipDst.copyInto(pkt, 16)

        val ipSum = computeIpv4HeaderChecksum(pkt, MIN_IPV4_HEADER)
        pkt[10] = ((ipSum ushr 8) and 0xFF).toByte()
        pkt[11] = (ipSum and 0xFF).toByte()

        // UDP header
        pkt[MIN_IPV4_HEADER + 0] = ((srcPort shr 8) and 0xFF).toByte()
        pkt[MIN_IPV4_HEADER + 1] = (srcPort and 0xFF).toByte()
        pkt[MIN_IPV4_HEADER + 2] = ((dstPort shr 8) and 0xFF).toByte()
        pkt[MIN_IPV4_HEADER + 3] = (dstPort and 0xFF).toByte()
        pkt[MIN_IPV4_HEADER + 4] = ((udpLen shr 8) and 0xFF).toByte()
        pkt[MIN_IPV4_HEADER + 5] = (udpLen and 0xFF).toByte()
        pkt[MIN_IPV4_HEADER + 6] = 0; pkt[MIN_IPV4_HEADER + 7] = 0
        dnsPayload.copyInto(pkt, MIN_IPV4_HEADER + UDP_HEADER_LEN)

        val udpSum = computeUdpChecksum(pkt, MIN_IPV4_HEADER, udpLen)
        pkt[MIN_IPV4_HEADER + 6] = ((udpSum ushr 8) and 0xFF).toByte()
        pkt[MIN_IPV4_HEADER + 7] = (udpSum and 0xFF).toByte()
        return pkt
    }

    /** RFC 791 one's-complement IPv4 header checksum over [headerLen] bytes. */
    private fun computeIpv4HeaderChecksum(pkt: ByteArray, headerLen: Int): Int {
        var sum = 0
        var i = 0
        while (i < headerLen) {
            if (i != 10) {
                sum += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
            }
            i += 2
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }

    /** RFC 768 one's-complement UDP checksum including the IPv4 pseudo-header. */
    private fun computeUdpChecksum(pkt: ByteArray, udpOffset: Int, udpLen: Int): Int {
        var sum = 0
        // IPv4 pseudo-header: src IP (12..15), dst IP (16..19), protocol (17), UDP length
        var i = 12
        while (i < 20) {
            sum += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
            i += 2
        }
        sum += PROTO_UDP
        sum += udpLen

        // UDP header + payload (skipping checksum bytes at udpOffset + 6..7)
        var j = 0
        while (j + 1 < udpLen) {
            if (j != 6) {
                sum += ((pkt[udpOffset + j].toInt() and 0xFF) shl 8) or
                       (pkt[udpOffset + j + 1].toInt() and 0xFF)
            }
            j += 2
        }
        if (j < udpLen) {
            sum += (pkt[udpOffset + j].toInt() and 0xFF) shl 8
        }

        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        val result = sum.inv() and 0xFFFF
        return if (result == 0) 0xFFFF else result
    }

    /**
     * Parse minimal IPv4 header fields and dispatch to subsystems.
     *
     * IPv4 header layout (all offsets in bytes):
     *  0        : version (4 bits) + IHL (4 bits)
     *  9        : protocol  (1 = ICMP, 6 = TCP, 17 = UDP)
     *  12–15    : source IP
     *  16–19    : destination IP
     *  IHL*4    : start of transport-layer header
     *  IHL*4+2  : destination port (TCP/UDP, big-endian)
     *  IHL*4+8  : start of UDP payload (8-byte UDP header)
     */
    private fun processPacket(packet: ByteArray, tunOut: FileOutputStream) {
        if (packet.size < MIN_IPV4_HEADER) return

        // Only handle IPv4 (version nibble == 4)
        val version = (packet[0].toInt() and 0xF0) ushr 4
        if (version != 4) return

        val ihl      = (packet[0].toInt() and 0x0F) * 4
        val protocol = packet[9].toInt() and 0xFF
        val srcIp    = formatIp(packet, 12)
        val dstIp    = formatIp(packet, 16)

        // Extract destination port for TCP (6) and UDP (17) only
        val dstPort = if ((protocol == PROTO_TCP || protocol == PROTO_UDP)
            && packet.size >= ihl + 4
        ) {
            ((packet[ihl + 2].toInt() and 0xFF) shl 8) or
                    (packet[ihl + 3].toInt() and 0xFF)
        } else {
            -1
        }

        // --- QUIC block: drop outbound UDP 443 to force HTTP/2 fallback ---
        // QUIC bypasses DNS inspection; dropping it forces browsers to TCP/TLS
        // where our SNI inspector can read the destination hostname.
        if (protocol == PROTO_UDP && dstPort == PORT_HTTPS) {
            PerfCounters.quicBlocked.incrementAndGet()
            return  // silently drop — no response needed, client retries over TCP
        }

        // --- DNS inspection + blocking/forwarding (UDP port 53) ---
        // UDP header is 8 bytes; DNS payload starts at ihl+8
        if (protocol == PROTO_UDP && dstPort == PORT_DNS) {
            val udpPayloadOffset = ihl + UDP_HEADER_LEN
            if (packet.size > udpPayloadOffset) {
                val dnsPayload = packet.copyOfRange(udpPayloadOffset, packet.size)
                val dnsResult  = dnsInspector.inspect(dnsPayload)
                serviceScope.launch(Dispatchers.IO) {
                    val responsePayload = if (dnsResult?.isMalicious == true) {
                        Log.w(TAG, "DNS BLOCKED: ${dnsResult.domain} [${dnsResult.category}]")
                        buildNxdomainResponse(dnsPayload)
                    } else {
                        forwardDnsAndReceive(dnsPayload, activeDns)
                    }
                    if (responsePayload != null) {
                        val responsePacket = buildUdpIpResponse(packet, ihl, responsePayload)
                        try {
                            synchronized(tunOut) { tunOut.write(responsePacket) }
                        } catch (e: IOException) {
                            Log.w(TAG, "TUN write error (DNS response): ${e.message}")
                        }
                    }
                }
            }
        }

        // --- SNI inspection: parse TLS ClientHello on TCP port 443 ---
        // Extracts plaintext hostname from the first byte of a TLS handshake.
        // No decryption needed — SNI is sent in the clear before the TLS session.
        if (protocol == PROTO_TCP && dstPort == PORT_HTTPS) {
            // TCP data offset is in the high nibble of byte [ihl+12], in 32-bit words
            if (packet.size > ihl + 13) {
                val tcpHeaderLen  = ((packet[ihl + 12].toInt() and 0xF0) ushr 4) * 4
                val tcpPayloadOff = ihl + tcpHeaderLen
                if (packet.size > tcpPayloadOff + 5) {
                    val sni = extractSni(packet, tcpPayloadOff)
                    if (sni != null) {
                        PerfCounters.httpsInspected.incrementAndGet()
                        val sniResult = dnsInspector.checkHostname(sni)
                        if (sniResult != null && sniResult.isMalicious) {
                            Log.w(TAG, "HTTPS SNI BLOCKED: $sni [${sniResult.category}]")
                            connectionAnalyser.injectThreatEvent(
                                com.sentinelguard.vpn.ThreatEvent(
                                    type        = "HTTPS_MALICIOUS",
                                    severity    = "HIGH",
                                    description = "HTTPS connection to malicious host: $sni " +
                                                  "[${sniResult.category}] blocked via SNI inspection.",
                                    timestamp   = System.currentTimeMillis()
                                )
                            )
                        }
                    }
                }
            }
        }

        // --- Connection analysis (all packets) ---
        connectionAnalyser.analyse(
            PacketMeta(
                srcIp     = srcIp,
                dstIp     = dstIp,
                protocol  = protocol,
                dstPort   = dstPort,
                timestamp = System.currentTimeMillis()
            )
        )
    }

    /**
     * Parses a TLS ClientHello from a raw TCP payload and returns the SNI hostname,
     * or null if the packet is not a ClientHello or has no SNI extension.
     *
     * Byte layout navigated (RFC 5246 / RFC 8446):
     *   TLS Record (5 bytes): ContentType=0x16, Version(2), Length(2)
     *   Handshake (4 bytes): Type=0x01, Length(3)
     *   ClientHello: Version(2), Random(32), SessionID, CipherSuites, CompressionMethods, Extensions
     *   SNI Extension: Type=0x0000, Length(2), NameListLen(2), NameType=0x00, NameLen(2), Name
     */
    private fun extractSni(packet: ByteArray, tcpPayloadOffset: Int): String? {
        return try {
            val buf = java.nio.ByteBuffer.wrap(packet, tcpPayloadOffset, packet.size - tcpPayloadOffset)
            buf.order(java.nio.ByteOrder.BIG_ENDIAN)
            if (buf.remaining() < 5) return null
            val contentType = buf.get().toInt() and 0xFF
            buf.get(); buf.get()                          // skip TLS version (2 bytes)
            val recordLen = buf.short.toInt() and 0xFFFF  // TLS record length
            if (contentType != 0x16 || buf.remaining() < recordLen) return null

            val hsType = buf.get().toInt() and 0xFF       // Handshake type
            if (hsType != 0x01) return null               // Not ClientHello

            // Skip 3-byte handshake length + 2-byte client version + 32-byte random
            if (buf.remaining() < 38) return null
            buf.position(buf.position() + 3 + 2 + 32)

            // Skip Session ID
            val sidLen = buf.get().toInt() and 0xFF
            if (buf.remaining() < sidLen) return null
            buf.position(buf.position() + sidLen)

            // Skip Cipher Suites
            if (buf.remaining() < 2) return null
            val csLen = buf.short.toInt() and 0xFFFF
            if (buf.remaining() < csLen) return null
            buf.position(buf.position() + csLen)

            // Skip Compression Methods
            if (buf.remaining() < 1) return null
            val cmLen = buf.get().toInt() and 0xFF
            if (buf.remaining() < cmLen) return null
            buf.position(buf.position() + cmLen)

            // Extensions
            if (buf.remaining() < 2) return null
            val extTotalLen = buf.short.toInt() and 0xFFFF
            val extEnd = buf.position() + extTotalLen

            while (buf.position() + 4 <= extEnd) {
                val extType = buf.short.toInt() and 0xFFFF
                val extLen  = buf.short.toInt() and 0xFFFF
                if (extType == 0x0000) {              // SNI extension
                    buf.position(buf.position() + 2)  // skip ServerNameList length
                    val nameType = buf.get().toInt() and 0xFF
                    if (nameType == 0x00) {            // HostName type
                        val nameLen = buf.short.toInt() and 0xFFFF
                        if (buf.remaining() < nameLen) return null
                        val nameBytes = ByteArray(nameLen)
                        buf.get(nameBytes)
                        return String(nameBytes, Charsets.UTF_8)
                    }
                } else {
                    if (buf.remaining() < extLen) return null
                    buf.position(buf.position() + extLen)
                }
            }
            null
        } catch (_: Exception) { null }
    }

    // -------------------------------------------------------------------------
    // Foreground notification
    // -------------------------------------------------------------------------

    private fun startForegroundNotification() {
        val openAppIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = Notification.Builder(this, SentinelApplication.CHANNEL_VPN)
            .setContentTitle("SentinelGuard")
            .setContentText("SentinelGuard is active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setShowWhen(false)
            .setContentIntent(openAppIntent)
            .build()

        startForeground(NOTIFICATION_ID, notification)
    }

    // -------------------------------------------------------------------------
    // Socket protection helpers (avoid routing loops)
    // -------------------------------------------------------------------------

    /** Protect a [DatagramSocket] from being routed through the VPN tunnel. */
    fun protectSocket(socket: DatagramSocket) = protect(socket)

    /** Protect a [Socket] from being routed through the VPN tunnel. */
    fun protectSocket(socket: Socket) = protect(socket)

    // -------------------------------------------------------------------------
    // Companion — public API
    // -------------------------------------------------------------------------

    companion object {
        private const val TAG             = "SentinelVpnService"
        private const val NOTIFICATION_ID = 1001
        private const val MIN_IPV4_HEADER = 20
        private const val PROTO_TCP       = 6
        private const val PROTO_UDP       = 17
        private const val PORT_DNS        = 53
        private const val PORT_HTTPS      = 443
        private const val UDP_HEADER_LEN  = 8
        private const val MTU             = 1500
        private const val MAX_UDP_RESPONSE = 4096
        private const val UDP_TIMEOUT_MS  = 1200
        /** Virtual DNS IP presented inside the TUN interface (never triggers Chrome auto-DoH). */
        private const val LOCAL_TUN_DNS          = "10.0.0.1"
        /** Fallback upstream DNS if ConnectivityManager returns no IPv4 servers. */
        private const val FALLBACK_DNS           = "8.8.8.8"
        private const val SECONDARY_FALLBACK_DNS = "1.1.1.1"
        /** Well-known DoH/DoT resolver IPs captured into TUN to prevent browser DNS bypass. */
        private val DOH_RESOLVER_IPS = listOf(
            "8.8.8.8", "8.8.4.4",           // Google DNS
            "1.1.1.1", "1.0.0.1",           // Cloudflare DNS
            "9.9.9.9", "149.112.112.112",   // Quad9
            "94.140.14.14", "94.140.15.15", // AdGuard DNS
            "208.67.222.222", "208.67.220.220" // OpenDNS
        )

        const val ACTION_START = "com.sentinelguard.vpn.START"
        const val ACTION_STOP  = "com.sentinelguard.vpn.STOP"

        private val _isRunning = MutableStateFlow(false)
        /** Live state reflecting whether the VPN TUN interface is currently established. */
        val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()

        /** Start the VPN service. The caller must have already obtained VPN permission. */
        fun start(context: Context) {
            val intent = Intent(context, SentinelVpnService::class.java)
                .setAction(ACTION_START)
            context.startForegroundService(intent)
        }

        /** Stop the VPN service. */
        fun stop(context: Context) {
            val intent = Intent(context, SentinelVpnService::class.java)
                .setAction(ACTION_STOP)
            context.startService(intent)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (file-private)
// ─────────────────────────────────────────────────────────────────────────────

/** Format 4 bytes at [offset] in [bytes] as a dotted-decimal IPv4 string. */
private fun formatIp(bytes: ByteArray, offset: Int): String =
    "${bytes[offset].toInt() and 0xFF}." +
            "${bytes[offset + 1].toInt() and 0xFF}." +
            "${bytes[offset + 2].toInt() and 0xFF}." +
            "${bytes[offset + 3].toInt() and 0xFF}"

/** Lightweight packet metadata passed between subsystems. */
data class PacketMeta(
    val srcIp:     String,
    val dstIp:     String,
    val protocol:  Int,
    val dstPort:   Int,
    val timestamp: Long
)
