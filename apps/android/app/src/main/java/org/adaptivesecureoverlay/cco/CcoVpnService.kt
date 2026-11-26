package org.adaptivesecureoverlay.cco

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * Rootless Android [VpnService] hosting the single Rust split-plane WireGuard engine.
 *
 * Control plane (WG Type 1/2/3) flows strictly through the MCC overlay (`A -> X1 -> X2 -> B`).
 * Data plane (WG Type 4) flows directly between endpoints (`A <-> B`).
 * Every underlay UDP socket is excluded from the TUN via `VpnService.protect(fd)` called
 * directly from Rust JNI.
 */
class CcoVpnService : VpnService() {

    companion object {
        const val ACTION_START = "org.adaptivesecureoverlay.cco.ACTION_START"
        const val ACTION_STOP = "org.adaptivesecureoverlay.cco.ACTION_STOP"
        const val ACTION_INITIATE = "org.adaptivesecureoverlay.cco.ACTION_INITIATE"
        const val EXTRA_CONFIG_JSON = "config_json"
        const val EXTRA_TUN_ADDRESS = "tun_address"
        const val EXTRA_TUN_PREFIX = "tun_prefix"
        const val EXTRA_TUN_ROUTE = "tun_route"
        const val EXTRA_TUN_ROUTE_PREFIX = "tun_route_prefix"

        private const val CHANNEL_ID = "cco_vpn_channel"
        private const val NOTIFICATION_ID = 2306
    }

    private val lock = Any()
    private var nativeHandle: Long = 0L
    private var fallbackPfd: ParcelFileDescriptor? = null
    private var poller: ScheduledExecutorService? = null
    private var pollTask: ScheduledFuture<*>? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopActiveTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_INITIATE -> {
                synchronized(lock) {
                    if (nativeHandle != 0L && NativeBridge.isLoaded) {
                        NativeBridge.initiateHandshake(nativeHandle)
                    }
                }
                return START_STICKY
            }
            ACTION_START -> {
                val cfg = intent.getStringExtra(EXTRA_CONFIG_JSON)
                val tunAddr = intent.getStringExtra(EXTRA_TUN_ADDRESS) ?: "198.51.100.10"
                val tunPrefix = intent.getIntExtra(EXTRA_TUN_PREFIX, 24)
                val routeNet = intent.getStringExtra(EXTRA_TUN_ROUTE) ?: "198.51.100.0"
                val routePrefix = intent.getIntExtra(EXTRA_TUN_ROUTE_PREFIX, 24)

                if (cfg.isNullOrBlank()) {
                    TunnelRepository.setError("missing_config_json")
                    stopSelf()
                    return START_NOT_STICKY
                }
                startTunnel(cfg, tunAddr, tunPrefix, routeNet, routePrefix)
                return START_STICKY
            }
        }
        return START_NOT_STICKY
    }

    private fun startTunnel(
        configJson: String,
        tunAddr: String,
        tunPrefix: Int,
        routeNet: String,
        routePrefix: Int,
    ) {
        stopActiveTunnel()

        if (!NativeBridge.isLoaded) {
            TunnelRepository.setError("native_lib_not_loaded")
            stopSelf()
            return
        }

        ensureNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
        TunnelRepository.setError(null)
        TunnelRepository.clearEvents()

        val pfd = try {
            Builder()
                .setSession("Cascade Control Overlay")
                .setMtu(1420)
                .addAddress(tunAddr, tunPrefix)
                .addRoute(routeNet, routePrefix)
                .establish()
        } catch (_: Throwable) {
            null
        }

        if (pfd == null) {
            TunnelRepository.setError("vpn_establish_failed")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Transfer ownership of the TUN file descriptor to Rust (`OwnedFd`).
        val detachedFd = pfd.detachFd()
        val startJson = NativeBridge.startTunnelWithFdJson(configJson, detachedFd, this)
        when (val parsed = CcoJsonParser.parseStartHandle(startJson)) {
            is FfiResult.Err -> {
                TunnelRepository.setError(parsed.code)
                TunnelRepository.setRunning(false)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            is FfiResult.Ok -> {
                synchronized(lock) {
                    nativeHandle = parsed.data
                }
                TunnelRepository.setRunning(true)
                startTelemetryPoller()
            }
        }
    }

    private fun startTelemetryPoller() {
        val exec = Executors.newSingleThreadScheduledExecutor()
        poller = exec
        pollTask = exec.scheduleWithFixedDelay(
            {
                val h = synchronized(lock) { nativeHandle }
                if (h == 0L) return@scheduleWithFixedDelay
                when (val s = CcoJsonParser.parseTunnelStats(NativeBridge.tunnelStats(h))) {
                    is FfiResult.Ok -> TunnelRepository.updateStats(s.data)
                    is FfiResult.Err -> TunnelRepository.setError(s.code)
                }
                when (val ev = CcoJsonParser.parseEvents(NativeBridge.tunnelDrainEvents(h))) {
                    is FfiResult.Ok -> TunnelRepository.appendEvents(ev.data)
                    is FfiResult.Err -> Unit
                }
            },
            0L,
            500L,
            TimeUnit.MILLISECONDS,
        )
    }

    private fun stopActiveTunnel() {
        pollTask?.cancel(true)
        pollTask = null
        poller?.shutdownNow()
        poller = null

        val handleToStop = synchronized(lock) {
            val h = nativeHandle
            nativeHandle = 0L
            h
        }
        if (handleToStop != 0L && NativeBridge.isLoaded) {
            NativeBridge.stopTunnel(handleToStop)
        }
        runCatching { fallbackPfd?.close() }
        fallbackPfd = null
        TunnelRepository.setRunning(false)
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    override fun onRevoke() {
        stopActiveTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopActiveTunnel()
        super.onDestroy()
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = getSystemService(NotificationManager::class.java)
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.vpn_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            )
            mgr?.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val openIntent = Intent(this, MainActivity::class.java)
        val pending = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(getString(R.string.vpn_notification_text))
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pending)
            .setOngoing(true)
            .build()
    }
}
