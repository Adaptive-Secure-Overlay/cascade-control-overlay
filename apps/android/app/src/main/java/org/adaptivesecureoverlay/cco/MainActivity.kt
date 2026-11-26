package org.adaptivesecureoverlay.cco

import android.app.Activity
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.json.JSONArray
import java.util.Locale

private val CcoColors = darkColorScheme(
    primary = Color(0xFF2DD4BF),
    onPrimary = Color(0xFF06201E),
    secondary = Color(0xFF38BDF8),
    background = Color(0xFF0B1120),
    surface = Color(0xFF111827),
    surfaceVariant = Color(0xFF1E293B),
    error = Color(0xFFF87171),
)

class MainActivity : ComponentActivity() {
    private lateinit var profileStore: ProfileStore
    private var pendingStartConfig: String? = null

    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                pendingStartConfig?.let { launchVpnService(it) }
            } else {
                TunnelRepository.setError("vpn_permission_denied")
            }
            pendingStartConfig = null
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        profileStore = ProfileStore(this)

        setContent {
            MaterialTheme(colorScheme = CcoColors) {
                CcoAppRoot(
                    profileStore = profileStore,
                    onRequestStartVpn = { configJson -> requestAndStartVpn(configJson) },
                    onStopVpn = { stopVpnService() },
                    onTriggerHandshake = { sendInitiateHandshake() },
                    onReadClipboard = { readClipboardText() },
                )
            }
        }
    }

    private fun requestAndStartVpn(configJson: String) {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            pendingStartConfig = configJson
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            launchVpnService(configJson)
        }
    }

    private fun launchVpnService(configJson: String) {
        val intent = Intent(this, CcoVpnService::class.java).apply {
            action = CcoVpnService.ACTION_START
            putExtra(CcoVpnService.EXTRA_CONFIG_JSON, configJson)
        }
        startForegroundService(intent)
    }

    private fun stopVpnService() {
        val intent = Intent(this, CcoVpnService::class.java).apply {
            action = CcoVpnService.ACTION_STOP
        }
        startService(intent)
    }

    private fun sendInitiateHandshake() {
        val intent = Intent(this, CcoVpnService::class.java).apply {
            action = CcoVpnService.ACTION_INITIATE
        }
        startService(intent)
    }

    private fun readClipboardText(): String? {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return null
        val clip = cm.primaryClip ?: return null
        if (clip.itemCount == 0) return null
        return clip.getItemAt(0).coerceToText(this)?.toString()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun CcoAppRoot(
    profileStore: ProfileStore,
    onRequestStartVpn: (String) -> Unit,
    onStopVpn: () -> Unit,
    onTriggerHandshake: () -> Unit,
    onReadClipboard: () -> String?,
) {
    var selectedTab by remember { mutableIntStateOf(0) }
    var profile by remember { mutableStateOf<ProfileSummary?>(null) }
    var trustStatus by remember { mutableStateOf<TrustStatus?>(null) }
    var trustError by remember { mutableStateOf<String?>(null) }
    var selectedMccMode by remember { mutableStateOf("adaptive") }
    var x1Fanout by remember { mutableIntStateOf(2) }
    var x2Fanout by remember { mutableIntStateOf(2) }
    var selectedPeer by remember { mutableStateOf("B") }
    var coreVersion by remember { mutableStateOf("unavailable") }

    val isRunning by TunnelRepository.isRunning.collectAsState()
    val stats by TunnelRepository.stats.collectAsState()
    val events by TunnelRepository.events.collectAsState()
    val lastError by TunnelRepository.lastError.collectAsState()

    fun applyProfile(parsed: ProfileSummary) {
        profile = parsed
        selectedMccMode = parsed.mccMode
        x1Fanout = parsed.x1Fanout
        x2Fanout = parsed.x2Fanout
        selectedPeer = parsed.peerName
        if (NativeBridge.isLoaded) {
            val reqJson = JSONArray(parsed.peerNames).toString()
            when (val verified = CcoJsonParser.parseTrustStatus(
                NativeBridge.verifyTrustBundle(parsed.trustRegistryJson, parsed.trustRootJson, reqJson)
            )) {
                is FfiResult.Ok -> {
                    trustStatus = verified.data
                    trustError = null
                }
                is FfiResult.Err -> {
                    trustStatus = null
                    trustError = verified.code
                }
            }
        }
    }

    LaunchedEffect(Unit) {
        if (NativeBridge.isLoaded) {
            coreVersion = NativeBridge.version()
        }
        profileStore.loadProfileRaw()?.let { raw ->
            if (CcoJsonParser.parseProfileJson(raw) is FfiResult.Ok) {
                val ok = CcoJsonParser.parseProfileJson(raw) as FfiResult.Ok
                applyProfile(ok.data)
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("Cascade Control Overlay", fontWeight = FontWeight.Bold)
                        Text(
                            text = "Rust core $coreVersion · Split WG / MCC",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
            )
        },
        bottomBar = {
            NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                NavigationBarItem(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    icon = { Icon(Icons.Default.Shield, contentDescription = "Tunnel") },
                    label = { Text("Tunnel") },
                )
                NavigationBarItem(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    icon = { Icon(Icons.Default.VerifiedUser, contentDescription = "Proof") },
                    label = { Text("Telemetry") },
                )
                NavigationBarItem(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    icon = { Icon(Icons.Default.Analytics, contentDescription = "Analytics") },
                    label = { Text("Analytics") },
                )
            }
        },
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.background)
                .padding(padding)
                .padding(14.dp),
        ) {
            when (selectedTab) {
                0 -> TunnelTab(
                    isRunning = isRunning,
                    stats = stats,
                    lastError = lastError,
                    profile = profile,
                    trustStatus = trustStatus,
                    trustError = trustError,
                    selectedMccMode = selectedMccMode,
                    x1Fanout = x1Fanout,
                    x2Fanout = x2Fanout,
                    selectedPeer = selectedPeer,
                    onModeChange = { selectedMccMode = it },
                    onX1Change = { x1Fanout = it },
                    onX2Change = { x2Fanout = it },
                    onGenerateDemo = {
                        if (!NativeBridge.isLoaded) {
                            trustError = "native_lib_not_loaded"
                            return@TunnelTab
                        }
                        val raw = NativeBridge.generateDemoBundle("A", "B")
                        when (val res = CcoJsonParser.parseDemoEnvelopeToProfile(raw)) {
                            is FfiResult.Ok -> {
                                profileStore.saveProfileRaw(res.data.rawJson)
                                applyProfile(res.data)
                            }
                            is FfiResult.Err -> trustError = res.code
                        }
                    },
                    onImportClipboard = {
                        val txt = onReadClipboard()
                        if (txt.isNullOrBlank()) {
                            trustError = "clipboard_empty"
                            return@TunnelTab
                        }
                        when (val res = CcoJsonParser.parseProfileJson(txt)) {
                            is FfiResult.Ok -> {
                                profileStore.saveProfileRaw(res.data.rawJson)
                                applyProfile(res.data)
                            }
                            is FfiResult.Err -> trustError = res.code
                        }
                    },
                    onToggleVpn = {
                        if (isRunning) {
                            onStopVpn()
                        } else {
                            val current = profile ?: run {
                                TunnelRepository.setError("no_profile_loaded")
                                return@TunnelTab
                            }
                            val built = CcoJsonParser.buildTunnelStartJson(
                                profile = current,
                                replayDbPath = profileStore.replayDbFile.absolutePath,
                                selectedPeer = selectedPeer,
                                mccMode = selectedMccMode,
                                x1Fanout = x1Fanout,
                                x2Fanout = x2Fanout,
                            )
                            when (built) {
                                is FfiResult.Ok -> onRequestStartVpn(built.data)
                                is FfiResult.Err -> TunnelRepository.setError(built.code)
                            }
                        }
                    },
                    onTriggerHandshake = onTriggerHandshake,
                )

                1 -> TelemetryProofTab(
                    stats = stats,
                    trustStatus = trustStatus,
                    events = events,
                )

                2 -> ResearchAnalyticsTab()
            }
        }
    }
}

@Composable
private fun TunnelTab(
    isRunning: Boolean,
    stats: TunnelStats,
    lastError: String?,
    profile: ProfileSummary?,
    trustStatus: TrustStatus?,
    trustError: String?,
    selectedMccMode: String,
    x1Fanout: Int,
    x2Fanout: Int,
    selectedPeer: String,
    onModeChange: (String) -> Unit,
    onX1Change: (Int) -> Unit,
    onX2Change: (Int) -> Unit,
    onGenerateDemo: () -> Unit,
    onImportClipboard: () -> Unit,
    onToggleVpn: () -> Unit,
    onTriggerHandshake: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Tunnel Status", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                val statusLabel = when (stats.state) {
                    "connected_direct_data" -> "CONNECTED — DIRECT WG DATA (TYPE 4)"
                    "handshaking_via_mcc" -> "HANDSHAKING VIA MCC OVERLAY (A -> X1 -> X2 -> B)"
                    "starting" -> "STARTING ENGINE..."
                    else -> if (isRunning) "RUNNING (${stats.state.uppercase(Locale.US)})" else "DISCONNECTED"
                }
                val statusColor = when (stats.state) {
                    "connected_direct_data" -> Color(0xFF34D399)
                    "handshaking_via_mcc", "starting" -> Color(0xFFFBBF24)
                    else -> Color(0xFF94A3B8)
                }
                Text(statusLabel, color = statusColor, fontWeight = FontWeight.Bold)
                if (!NativeBridge.isLoaded) {
                    Text(
                        text = "Native library error: ${NativeBridge.loadError}",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (lastError != null) {
                    Text(
                        text = "Last error: $lastError",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
                    Button(
                        onClick = onToggleVpn,
                        enabled = profile != null && trustStatus?.authenticated == true,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (isRunning) Color(0xFFEF4444) else MaterialTheme.colorScheme.primary,
                        ),
                        modifier = Modifier.weight(1f),
                    ) {
                        Text(if (isRunning) "Disconnect" else "Connect Split VPN")
                    }
                    if (isRunning) {
                        OutlinedButton(onClick = onTriggerHandshake) {
                            Text("Rekey MCC")
                        }
                    }
                }
            }
        }

        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Ed25519 Trust Registry v2 Profile", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                if (profile != null) {
                    Text("Local node: ${profile.nodeName} -> Peer: $selectedPeer", style = MaterialTheme.typography.bodyMedium)
                    Text("Direct peer UDP: ${profile.peerDirectAddr}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                } else {
                    Text("No profile loaded yet. Generate an RFC 5737 demo profile or paste a signed JSON profile.", style = MaterialTheme.typography.bodySmall)
                }
                if (trustStatus != null) {
                    Text(
                        text = "VERIFIED v${trustStatus.version} · signer=${trustStatus.signerKeyId} · sha256=${trustStatus.sha256.take(16)}...",
                        color = Color(0xFF34D399),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                }
                if (trustError != null) {
                    Text(
                        text = "Fail-closed rejection: $trustError",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = onGenerateDemo, modifier = Modifier.weight(1f)) {
                        Text("Demo RFC 5737")
                    }
                    OutlinedButton(onClick = onImportClipboard, modifier = Modifier.weight(1f)) {
                        Text("Import JSON")
                    }
                }
            }
        }

        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("MCC Control-Plane Parameters", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.fillMaxWidth()) {
                    CcoJsonParser.allowedMccModes.forEach { mode ->
                        FilterChip(
                            selected = selectedMccMode == mode,
                            onClick = { onModeChange(mode) },
                            label = { Text(mode) },
                        )
                    }
                }
                Text("X1 Fanout: $x1Fanout", style = MaterialTheme.typography.bodySmall)
                Slider(
                    value = x1Fanout.toFloat(),
                    onValueChange = { onX1Change(it.toInt()) },
                    valueRange = 1f..4f,
                    steps = 2,
                )
                Text("X2 Fanout: $x2Fanout", style = MaterialTheme.typography.bodySmall)
                Slider(
                    value = x2Fanout.toFloat(),
                    onValueChange = { onX2Change(it.toInt()) },
                    valueRange = 1f..4f,
                    steps = 2,
                )
            }
        }
    }
}

@Composable
private fun TelemetryProofTab(
    stats: TunnelStats,
    trustStatus: TrustStatus?,
    events: List<SanitizedEvent>,
) {
    Column(modifier = Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Split-Plane Proof Counters", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(
                    text = if (stats.controlPlaneInvariantHolds) {
                        "DIRECT WG HANDSHAKE TX = 0 (INVARIANT VERIFIED)"
                    } else {
                        "VIOLATION: DIRECT HANDSHAKE TX = ${stats.directHandshakeTx}"
                    },
                    color = if (stats.controlPlaneInvariantHolds) Color(0xFF34D399) else MaterialTheme.colorScheme.error,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                )
                MetricLine("Overlay Handshake TX / RX (MCC)", "${stats.overlayHandshakeTx} / ${stats.overlayHandshakeRx}")
                MetricLine("Direct Handshake RX Dropped", "${stats.directHandshakeRxDropped}")
                MetricLine("Direct Data TX / RX (WG Type 4)", "${stats.directDataTx} / ${stats.directDataRx}")
                MetricLine("Direct Data Bytes TX / RX", "${stats.directBytesTx} B / ${stats.directBytesRx} B")
                MetricLine("Initial Handshake Latency", stats.handshakeMs?.let { "$it ms" } ?: "—")
                MetricLine("Selected X1 Relay (X2 hidden)", stats.selectedX1 ?: "—")
                MetricLine("MCC Mode / Hops", "${stats.mccMode} / ${stats.selectedRouteHops} hops")
                MetricLine(
                    "Trust Registry v2",
                    if (stats.trustRegistryVersion > 0) {
                        "v${stats.trustRegistryVersion} (${stats.trustRegistrySha256.take(12)}...)"
                    } else if (trustStatus != null) {
                        "v${trustStatus.version} (${trustStatus.sha256.take(12)}...)"
                    } else {
                        "unverified"
                    },
                )
            }
        }

        Text("Sanitized Security Events", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
        LazyColumn(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            items(events.asReversed()) { ev ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.padding(10.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(
                            text = "[${ev.level.uppercase(Locale.US)}] ${ev.code}",
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall,
                        )
                        if (ev.peer != null) {
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "peer=${ev.peer}",
                                color = MaterialTheme.colorScheme.primary,
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ResearchAnalyticsTab() {
    var n by remember { mutableIntStateOf(10) }
    var m by remember { mutableIntStateOf(2) }
    var j by remember { mutableIntStateOf(3) }
    var summary by remember { mutableStateOf<AnalyticsSummary?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(n, m, j) {
        if (!NativeBridge.isLoaded) {
            error = "native_lib_not_loaded"
            return@LaunchedEffect
        }
        val clampedM = m.coerceAtMost((n - 2).coerceAtLeast(1))
        if (clampedM != m) m = clampedM
        when (val res = CcoJsonParser.parseAnalyticsSummary(NativeBridge.analyticsSummary(n, clampedM, j))) {
            is FfiResult.Ok -> {
                summary = res.data
                error = null
            }
            is FfiResult.Err -> {
                summary = null
                error = res.code
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Chapter 3 Combinatorics & Monte Carlo", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text("Nodes n = $n", style = MaterialTheme.typography.bodySmall)
                Slider(value = n.toFloat(), onValueChange = { n = it.toInt() }, valueRange = 4f..30f)
                Text("Compromised relays m = $m", style = MaterialTheme.typography.bodySmall)
                Slider(
                    value = m.toFloat(),
                    onValueChange = { m = it.toInt() },
                    valueRange = 1f..(n - 2).coerceAtLeast(1).toFloat(),
                )
                Text("Cascade hops j = $j", style = MaterialTheme.typography.bodySmall)
                Slider(value = j.toFloat(), onValueChange = { j = it.toInt() }, valueRange = 1f..6f, steps = 4)
            }
        }

        if (error != null) {
            Text("Analytics error: $error", color = MaterialTheme.colorScheme.error)
        }

        summary?.let { s ->
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Exact Analytical Comparison (n=${s.n}, m=${s.m}, j=${s.j})", fontWeight = FontWeight.SemiBold)
                    MetricLine("I2P routes", s.i2pRoutes)
                    MetricLine("F1 (Tor)", "${s.f1Routes} routes | H=${fmt2(s.f1EntropyBits)} b | P=${fmt2(s.f1CompromisePct)}% | n50=${s.f1N50 ?: "—"}")
                    MetricLine("F3 (No-Rep)", "${s.f3Routes} routes | H=${fmt2(s.f3EntropyBits)} b | P=${fmt2(s.f3CompromisePct)}% | n50=${s.f3N50 ?: "—"}")
                    MetricLine("F4 (With-Rep)", "${s.f4Routes} routes | H=${fmt2(s.f4EntropyBits)} b | P=${fmt2(s.f4CompromisePct)}% | n50=${s.f4N50 ?: "—"}")
                    Spacer(modifier = Modifier.height(4.dp))
                    s.f4MonteCarloPct?.let { mcPct ->
                        MetricLine(
                            "Rayon Monte Carlo (100k)",
                            "${fmt2(mcPct)}% (err=${String.format(Locale.US, "%.4f", s.f4MonteCarloAbsError ?: 0.0)}, ${fmt2(s.f4MonteCarloMs ?: 0.0)} ms)",
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun MetricLine(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = Color(0xFF94A3B8))
        Text(value, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
    }
}

private fun fmt2(v: Double): String = String.format(Locale.US, "%.2f", v)
