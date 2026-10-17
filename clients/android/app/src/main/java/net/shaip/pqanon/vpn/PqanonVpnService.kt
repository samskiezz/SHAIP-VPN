package net.shaip.pqanon.vpn

import android.content.Intent
import android.net.VpnService
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * Availability gate for the unfinished Android packet path. Loading the native
 * library and generating keys do not establish a VPN. Never create an empty
 * TUN or claim CONNECTED until a packet pump, authenticated session, routes and
 * DNS protection are actually implemented and verified.
 */
class PqanonVpnService : VpnService() {
    companion object {
        const val ACTION_CONNECT = "net.shaip.pqanon.CONNECT"
        const val ACTION_DISCONNECT = "net.shaip.pqanon.DISCONNECT"
        const val UNAVAILABLE_REASON = "Android packet forwarding is not implemented. Your traffic is not protected by SHAIP."
        enum class State { DISCONNECTED, CONNECTING, CONNECTED, UNAVAILABLE }
        val state = MutableStateFlow(State.UNAVAILABLE)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Includes direct service starts and system restarts: the UI cannot be
        // bypassed to manufacture a connected indicator from an empty TUN.
        state.value = State.UNAVAILABLE
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        state.value = State.UNAVAILABLE
        super.onDestroy()
    }
}
