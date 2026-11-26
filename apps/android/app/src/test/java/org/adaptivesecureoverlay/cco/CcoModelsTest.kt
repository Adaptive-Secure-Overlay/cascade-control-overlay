package org.adaptivesecureoverlay.cco

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CcoModelsTest {

    @Test
    fun parseTunnelStatsVerifiesZeroDirectHandshakeInvariant() {
        val json = """
            {
              "ok": true,
              "data": {
                "state": "connected_direct_data",
                "overlay_handshake_tx": 2,
                "overlay_handshake_rx": 1,
                "direct_handshake_tx": 0,
                "direct_handshake_rx_dropped": 1,
                "direct_data_tx": 14,
                "direct_data_rx": 14,
                "direct_bytes_tx": 1384,
                "direct_bytes_rx": 1384,
                "handshake_ms": 105,
                "selected_route_hops": 4,
                "selected_x1": "X1",
                "mcc_mode": "adaptive",
                "trust_registry_version": 1,
                "trust_registry_sha256": "abcdef0123456789"
              }
            }
        """.trimIndent()

        val result = CcoJsonParser.parseTunnelStats(json)
        assertTrue(result is FfiResult.Ok)
        val stats = (result as FfiResult.Ok).data
        assertEquals("connected_direct_data", stats.state)
        assertEquals(0L, stats.directHandshakeTx)
        assertTrue(stats.controlPlaneInvariantHolds)
        assertEquals(105L, stats.handshakeMs)
        assertEquals("X1", stats.selectedX1)
    }

    @Test
    fun parseTunnelStatsDetectsDirectHandshakeViolation() {
        val json = """{"ok":true,"data":{"state":"error","direct_handshake_tx":1}}"""
        val stats = (CcoJsonParser.parseTunnelStats(json) as FfiResult.Ok).data
        assertFalse(stats.controlPlaneInvariantHolds)
    }

    @Test
    fun parseAnalyticsSummaryMatchesDissertationControlValues() {
        val json = """
            {
              "ok": true,
              "data": {
                "n": 10,
                "m": 2,
                "j": 3,
                "i2p_routes": "336",
                "f1_routes": "336",
                "f3_routes": "40320",
                "f4_routes": "40320",
                "f1_entropy_bits": 8.3923,
                "f3_entropy_bits": 15.2992,
                "f4_entropy_bits": 15.2992,
                "f1_compromise_pct": 64.2857,
                "f3_compromise_pct": 46.4286,
                "f4_compromise_pct": 46.4286,
                "f1_n50": 15,
                "f3_n50": 10,
                "f4_n50": 10,
                "f4_monte_carlo_pct": 46.41,
                "f4_monte_carlo_abs_error": 0.0002,
                "f4_monte_carlo_ms": 12.5
              }
            }
        """.trimIndent()

        val result = CcoJsonParser.parseAnalyticsSummary(json)
        assertTrue(result is FfiResult.Ok)
        val summary = (result as FfiResult.Ok).data
        assertEquals("336", summary.f1Routes)
        assertEquals("40320", summary.f4Routes)
        assertEquals(15, summary.f1N50)
        assertEquals(10, summary.f4N50)
    }

    @Test
    fun parseProfileRejectsMissingTrustBundleFailClosed() {
        val badProfile = """{"node_name":"A","peer_name":"B","peers":[]}"""
        val result = CcoJsonParser.parseProfileJson(badProfile)
        assertTrue(result is FfiResult.Err)
        assertEquals("missing_trust_bundle", (result as FfiResult.Err).code)
    }

    @Test
    fun buildTunnelStartJsonInjectsAndroidDefaults() {
        val hex64 = "0".repeat(64)
        val raw = """
            {
              "node_name": "A",
              "peer_name": "B",
              "peers": [
                {"name":"A","overlay_addr":"192.0.2.10:9000","underlay_ip":"192.0.2.10"},
                {"name":"X1","overlay_addr":"192.0.2.11:9000","underlay_ip":"192.0.2.11"},
                {"name":"X2","overlay_addr":"192.0.2.12:9000","underlay_ip":"192.0.2.12"},
                {"name":"B","overlay_addr":"192.0.2.13:9000","underlay_ip":"192.0.2.13"}
              ],
              "trust_root_json": "{}",
              "trust_registry_json": "{}",
              "signing_key_hex": "$hex64",
              "encryption_key_hex": "$hex64",
              "wg_private_key_hex": "$hex64",
              "peer_wg_public_key_hex": "$hex64",
              "direct_bind_addr": "192.0.2.10:51820",
              "peer_direct_addr": "192.0.2.13:51820"
            }
        """.trimIndent()

        val profile = (CcoJsonParser.parseProfileJson(raw) as FfiResult.Ok).data
        val built = CcoJsonParser.buildTunnelStartJson(
            profile = profile,
            replayDbPath = "/data/user/0/org.adaptivesecureoverlay.cco/files/cco_replay.sqlite",
            selectedPeer = "B",
            mccMode = "window",
            x1Fanout = 3,
            x2Fanout = 2,
        )
        assertTrue(built is FfiResult.Ok)
        val out = (built as FfiResult.Ok).data
        assertTrue(out.contains("\"has_pi_header\":false"))
        assertTrue(out.contains("\"mcc_mode\":\"window\""))
        assertTrue(out.contains("\"x1_fanout\":3"))
    }
}
