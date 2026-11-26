package org.adaptivesecureoverlay.cco

import org.json.JSONArray
import org.json.JSONObject

sealed class FfiResult<out T> {
    data class Ok<T>(val data: T) : FfiResult<T>()
    data class Err(val code: String) : FfiResult<Nothing>()
}

data class TrustStatus(
    val authenticated: Boolean,
    val schema: String,
    val version: Long,
    val signerKeyId: String,
    val nodes: List<String>,
    val sha256: String,
    val recovered: Boolean,
)

data class TunnelStats(
    val state: String = "disconnected",
    val overlayHandshakeTx: Long = 0,
    val overlayHandshakeRx: Long = 0,
    val directHandshakeTx: Long = 0,
    val directHandshakeRxDropped: Long = 0,
    val directDataTx: Long = 0,
    val directDataRx: Long = 0,
    val directBytesTx: Long = 0,
    val directBytesRx: Long = 0,
    val handshakeMs: Long? = null,
    val selectedRouteHops: Int = 4,
    val selectedX1: String? = null,
    val mccMode: String = "adaptive",
    val trustRegistryVersion: Long = 0,
    val trustRegistrySha256: String = "",
    val lastErrorCode: String? = null,
) {
    /** Core dissertation invariant: zero WG Type 1/2/3 packets ever touch the direct link. */
    val controlPlaneInvariantHolds: Boolean
        get() = directHandshakeTx == 0L
}

data class SanitizedEvent(
    val timestampMs: Long,
    val level: String,
    val code: String,
    val peer: String?,
)

data class AnalyticsSummary(
    val n: Int,
    val m: Int,
    val j: Int,
    val i2pRoutes: String,
    val f1Routes: String,
    val f3Routes: String,
    val f4Routes: String,
    val f1EntropyBits: Double,
    val f3EntropyBits: Double,
    val f4EntropyBits: Double,
    val f1CompromisePct: Double,
    val f3CompromisePct: Double,
    val f4CompromisePct: Double,
    val f1N50: Int?,
    val f3N50: Int?,
    val f4N50: Int?,
    val f4MonteCarloPct: Double?,
    val f4MonteCarloAbsError: Double?,
    val f4MonteCarloMs: Double?,
)

data class ProfileSummary(
    val rawJson: String,
    val nodeName: String,
    val peerName: String,
    val peerNames: List<String>,
    val mccMode: String,
    val x1Fanout: Int,
    val x2Fanout: Int,
    val directBindAddr: String,
    val peerDirectAddr: String,
    val trustRootJson: String,
    val trustRegistryJson: String,
)

object CcoJsonParser {
    val allowedMccModes: List<String> = listOf("first", "window", "adaptive", "wait-all")

    fun parseTrustStatus(raw: String): FfiResult<TrustStatus> = parseEnvelope(raw) { d ->
        val nodesArr = d.optJSONArray("nodes") ?: JSONArray()
        val nodes = List(nodesArr.length()) { idx -> nodesArr.optString(idx, "") }
            .filter { it.isNotEmpty() }
        TrustStatus(
            authenticated = d.optBoolean("authenticated", false),
            schema = d.optString("schema", ""),
            version = d.optLong("version", 0L),
            signerKeyId = d.optString("signer_key_id", ""),
            nodes = nodes,
            sha256 = d.optString("sha256", ""),
            recovered = d.optBoolean("recovered", false),
        )
    }

    fun parseTunnelStats(raw: String): FfiResult<TunnelStats> = parseEnvelope(raw) { d ->
        TunnelStats(
            state = d.optString("state", "disconnected"),
            overlayHandshakeTx = d.optLong("overlay_handshake_tx", 0L),
            overlayHandshakeRx = d.optLong("overlay_handshake_rx", 0L),
            directHandshakeTx = d.optLong("direct_handshake_tx", 0L),
            directHandshakeRxDropped = d.optLong("direct_handshake_rx_dropped", 0L),
            directDataTx = d.optLong("direct_data_tx", 0L),
            directDataRx = d.optLong("direct_data_rx", 0L),
            directBytesTx = d.optLong("direct_bytes_tx", 0L),
            directBytesRx = d.optLong("direct_bytes_rx", 0L),
            handshakeMs = if (d.isNull("handshake_ms")) null else d.optLong("handshake_ms"),
            selectedRouteHops = d.optInt("selected_route_hops", 4),
            selectedX1 = if (d.isNull("selected_x1")) null else d.optString("selected_x1"),
            mccMode = d.optString("mcc_mode", "adaptive"),
            trustRegistryVersion = d.optLong("trust_registry_version", 0L),
            trustRegistrySha256 = d.optString("trust_registry_sha256", ""),
            lastErrorCode = if (d.isNull("last_error_code")) null else d.optString("last_error_code"),
        )
    }

    fun parseEvents(raw: String): FfiResult<List<SanitizedEvent>> {
        return try {
            val root = JSONObject(raw)
            if (!root.optBoolean("ok", false)) {
                return FfiResult.Err(root.optString("error", "unknown_ffi_error"))
            }
            val arr = root.optJSONArray("data") ?: JSONArray()
            val out = ArrayList<SanitizedEvent>(arr.length())
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i) ?: continue
                out.add(
                    SanitizedEvent(
                        timestampMs = obj.optLong("timestamp_ms", 0L),
                        level = obj.optString("level", "info"),
                        code = obj.optString("code", ""),
                        peer = if (obj.isNull("peer")) null else obj.optString("peer"),
                    )
                )
            }
            FfiResult.Ok(out)
        } catch (_: Throwable) {
            FfiResult.Err("json_parse_error")
        }
    }

    fun parseAnalyticsSummary(raw: String): FfiResult<AnalyticsSummary> = parseEnvelope(raw) { d ->
        AnalyticsSummary(
            n = d.getInt("n"),
            m = d.getInt("m"),
            j = d.getInt("j"),
            i2pRoutes = d.getString("i2p_routes"),
            f1Routes = d.getString("f1_routes"),
            f3Routes = d.getString("f3_routes"),
            f4Routes = d.getString("f4_routes"),
            f1EntropyBits = d.getDouble("f1_entropy_bits"),
            f3EntropyBits = d.getDouble("f3_entropy_bits"),
            f4EntropyBits = d.getDouble("f4_entropy_bits"),
            f1CompromisePct = d.getDouble("f1_compromise_pct"),
            f3CompromisePct = d.getDouble("f3_compromise_pct"),
            f4CompromisePct = d.getDouble("f4_compromise_pct"),
            f1N50 = if (d.isNull("f1_n50")) null else d.optInt("f1_n50"),
            f3N50 = if (d.isNull("f3_n50")) null else d.optInt("f3_n50"),
            f4N50 = if (d.isNull("f4_n50")) null else d.optInt("f4_n50"),
            f4MonteCarloPct = if (d.isNull("f4_monte_carlo_pct")) null else d.optDouble("f4_monte_carlo_pct"),
            f4MonteCarloAbsError = if (d.isNull("f4_monte_carlo_abs_error")) null else d.optDouble("f4_monte_carlo_abs_error"),
            f4MonteCarloMs = if (d.isNull("f4_monte_carlo_ms")) null else d.optDouble("f4_monte_carlo_ms"),
        )
    }

    fun parseStartHandle(raw: String): FfiResult<Long> = parseEnvelope(raw) { d ->
        val handle = d.optLong("handle", 0L)
        if (handle == 0L) throw IllegalStateException("zero_handle")
        handle
    }

    fun parseDemoEnvelopeToProfile(rawEnvelope: String): FfiResult<ProfileSummary> {
        return try {
            val root = JSONObject(rawEnvelope)
            if (!root.optBoolean("ok", false)) {
                return FfiResult.Err(root.optString("error", "demo_generation_failed"))
            }
            val dataObj = root.getJSONObject("data")
            parseProfileJson(dataObj.toString(2))
        } catch (_: Throwable) {
            FfiResult.Err("invalid_demo_envelope")
        }
    }

    fun parseProfileJson(rawJson: String): FfiResult<ProfileSummary> {
        return try {
            val obj = JSONObject(rawJson)
            val nodeName = obj.optString("node_name", "").trim()
            val peerName = obj.optString("peer_name", "").trim()
            val rootJson = obj.optString("trust_root_json", "")
            val regJson = obj.optString("trust_registry_json", "")
            val signingKey = obj.optString("signing_key_hex", "")
            val encryptionKey = obj.optString("encryption_key_hex", "")
            val wgPrivate = obj.optString("wg_private_key_hex", "")
            val peerWgPub = obj.optString("peer_wg_public_key_hex", "")
            val peersArr = obj.optJSONArray("peers")

            if (nodeName.isEmpty() || peerName.isEmpty() || nodeName == peerName) {
                return FfiResult.Err("invalid_endpoint_names")
            }
            if (rootJson.isEmpty() || regJson.isEmpty()) {
                return FfiResult.Err("missing_trust_bundle")
            }
            if (signingKey.length != 64 || encryptionKey.length != 64 ||
                wgPrivate.length != 64 || peerWgPub.length != 64
            ) {
                return FfiResult.Err("invalid_key_material_length")
            }
            if (peersArr == null || peersArr.length() < 4) {
                return FfiResult.Err("insufficient_overlay_peers")
            }

            val peerNames = ArrayList<String>(peersArr.length())
            for (i in 0 until peersArr.length()) {
                val p = peersArr.optJSONObject(i) ?: continue
                val name = p.optString("name", "").trim()
                if (name.isNotEmpty()) peerNames.add(name)
            }
            if (!peerNames.contains(nodeName) || !peerNames.contains(peerName)) {
                return FfiResult.Err("endpoint_missing_from_peers")
            }

            val mode = obj.optString("mcc_mode", "adaptive")
            val validMode = if (mode in allowedMccModes) mode else "adaptive"

            FfiResult.Ok(
                ProfileSummary(
                    rawJson = rawJson,
                    nodeName = nodeName,
                    peerName = peerName,
                    peerNames = peerNames,
                    mccMode = validMode,
                    x1Fanout = obj.optInt("x1_fanout", 2).coerceIn(1, 8),
                    x2Fanout = obj.optInt("x2_fanout", 2).coerceIn(1, 8),
                    directBindAddr = obj.optString("direct_bind_addr", "0.0.0.0:51820"),
                    peerDirectAddr = obj.optString("peer_direct_addr", ""),
                    trustRootJson = rootJson,
                    trustRegistryJson = regJson,
                )
            )
        } catch (_: Throwable) {
            FfiResult.Err("invalid_profile_json")
        }
    }

    /**
     * Merges user-selected MCC runtime options and the app-private SQLite anti-replay path
     * into the validated profile JSON before passing it across JNI to `cco-ffi`.
     */
    fun buildTunnelStartJson(
        profile: ProfileSummary,
        replayDbPath: String,
        selectedPeer: String,
        mccMode: String,
        x1Fanout: Int,
        x2Fanout: Int,
        initiateHandshake: Boolean = true,
    ): FfiResult<String> {
        if (mccMode !in allowedMccModes) {
            return FfiResult.Err("invalid_mcc_mode")
        }
        if (selectedPeer.isBlank() || selectedPeer == profile.nodeName) {
            return FfiResult.Err("invalid_peer_selection")
        }
        if (replayDbPath.isBlank()) {
            return FfiResult.Err("missing_replay_db_path")
        }
        return try {
            val obj = JSONObject(profile.rawJson)
            obj.put("peer_name", selectedPeer)
            obj.put("replay_db_path", replayDbPath)
            obj.put("mcc_mode", mccMode)
            obj.put("x1_fanout", x1Fanout.coerceIn(1, 8))
            obj.put("x2_fanout", x2Fanout.coerceIn(1, 8))
            obj.put("ike_fanout", 1)
            obj.put("has_pi_header", false)
            obj.put("initiate_handshake", initiateHandshake)
            FfiResult.Ok(obj.toString())
        } catch (_: Throwable) {
            FfiResult.Err("config_serialization_error")
        }
    }

    private inline fun <T> parseEnvelope(raw: String, mapper: (JSONObject) -> T): FfiResult<T> {
        return try {
            val root = JSONObject(raw)
            if (!root.optBoolean("ok", false)) {
                FfiResult.Err(root.optString("error", "unknown_ffi_error"))
            } else {
                FfiResult.Ok(mapper(root.getJSONObject("data")))
            }
        } catch (_: Throwable) {
            FfiResult.Err("json_parse_error")
        }
    }
}
