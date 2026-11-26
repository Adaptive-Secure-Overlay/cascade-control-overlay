package org.adaptivesecureoverlay.cco

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File

/**
 * App-private profile and anti-replay SQLite storage.
 * Enforces owner-only (0600) permissions and never writes private keys to logs.
 */
class ProfileStore(context: Context) {
    private val appFilesDir: File = context.applicationContext.filesDir
    private val profileFile: File = File(appFilesDir, "cco_profile.json")
    val replayDbFile: File = File(appFilesDir, "cco_replay.sqlite")

    fun saveProfileRaw(json: String) {
        val tmp = File(appFilesDir, "cco_profile.json.tmp")
        tmp.writeText(json, Charsets.UTF_8)
        tmp.setReadable(false, false)
        tmp.setReadable(true, true)
        tmp.setWritable(false, false)
        tmp.setWritable(true, true)
        if (!tmp.renameTo(profileFile)) {
            profileFile.writeText(json, Charsets.UTF_8)
            tmp.delete()
        }
        profileFile.setReadable(false, false)
        profileFile.setReadable(true, true)
        profileFile.setWritable(false, false)
        profileFile.setWritable(true, true)
    }

    fun loadProfileRaw(): String? {
        if (!profileFile.exists()) return null
        return runCatching { profileFile.readText(Charsets.UTF_8) }.getOrNull()
    }
}

/**
 * Process-local reactive telemetry bridge between [CcoVpnService] and [MainActivity].
 */
object TunnelRepository {
    private const val MAX_UI_EVENTS = 120

    private val _isRunning = MutableStateFlow(false)
    val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()

    private val _stats = MutableStateFlow(TunnelStats())
    val stats: StateFlow<TunnelStats> = _stats.asStateFlow()

    private val _events = MutableStateFlow<List<SanitizedEvent>>(emptyList())
    val events: StateFlow<List<SanitizedEvent>> = _events.asStateFlow()

    private val _lastError = MutableStateFlow<String?>(null)
    val lastError: StateFlow<String?> = _lastError.asStateFlow()

    fun setRunning(running: Boolean) {
        _isRunning.value = running
        if (!running) {
            _stats.value = _stats.value.copy(state = "disconnected")
        }
    }

    fun updateStats(newStats: TunnelStats) {
        _stats.value = newStats
        if (newStats.lastErrorCode != null) {
            _lastError.value = newStats.lastErrorCode
        }
    }

    fun appendEvents(incoming: List<SanitizedEvent>) {
        if (incoming.isEmpty()) return
        val merged = (_events.value + incoming).takeLast(MAX_UI_EVENTS)
        _events.value = merged
    }

    fun setError(code: String?) {
        _lastError.value = code
    }

    fun clearEvents() {
        _events.value = emptyList()
    }
}
