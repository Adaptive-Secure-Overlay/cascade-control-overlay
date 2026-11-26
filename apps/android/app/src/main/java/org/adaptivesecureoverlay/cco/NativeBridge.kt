package org.adaptivesecureoverlay.cco

import android.net.VpnService

/**
 * Direct JNI bridge to `crates/cco-ffi/src/android_jni.rs` (`libcco_ffi.so`).
 *
 * All cryptographic verification, Ed25519 Trust Registry v2 anti-rollback,
 * MCC split-plane WireGuard (boringtun), and Chapter 3 Rayon analytics execute
 * inside the single Rust core library without Go or root privileges.
 */
object NativeBridge {
    @Volatile
    var isLoaded: Boolean = false
        private set

    @Volatile
    var loadError: String? = null
        private set

    init {
        try {
            System.loadLibrary("cco_ffi")
            isLoaded = true
        } catch (t: Throwable) {
            isLoaded = false
            loadError = t.message ?: t.javaClass.simpleName
        }
    }

    @JvmStatic
    external fun version(): String

    @JvmStatic
    external fun verifyTrustBundle(
        registryJson: String,
        rootJson: String,
        requiredNodesJson: String,
    ): String

    @JvmStatic
    external fun analyticsSummary(n: Int, m: Int, j: Int): String

    @JvmStatic
    external fun generateDemoBundle(localNode: String, peerNode: String): String

    @JvmStatic
    external fun startTunnelWithFd(
        configJson: String,
        tunFd: Int,
        vpnService: VpnService?,
    ): Long

    @JvmStatic
    external fun startTunnelWithFdJson(
        configJson: String,
        tunFd: Int,
        vpnService: VpnService?,
    ): String

    @JvmStatic
    external fun initiateHandshake(handle: Long): Boolean

    @JvmStatic
    external fun tunnelStats(handle: Long): String

    @JvmStatic
    external fun tunnelDrainEvents(handle: Long): String

    @JvmStatic
    external fun stopTunnel(handle: Long)
}
