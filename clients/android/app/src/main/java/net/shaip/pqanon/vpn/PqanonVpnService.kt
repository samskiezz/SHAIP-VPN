package net.shaip.pqanon.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.flow.MutableStateFlow
import net.shaip.pqanon.MainActivity

/**
 * The Android side of the SHAIP VPN tunnel. This service owns the TUN interface
 * and the connection lifecycle. The data plane — the SHAIP VPN post-quantum
 * handshake (ML-KEM-768 + ML-DSA-65) and the encrypted tunnel — lives in the
 * shared Rust core (crate `pqanon`, already proven by the CLI and the netns
 * lab) and is bridged into this service over JNI in the next step.
 *
 * Until that bridge lands, Connect establishes the interface and reports state,
 * but it does NOT install a default route, so the phone's real traffic is never
 * silently captured or black-holed. See STATUS.md.
 */
class PqanonVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "net.shaip.pqanon.CONNECT"
        const val ACTION_DISCONNECT = "net.shaip.pqanon.DISCONNECT"
        private const val CHANNEL = "pqanon_tunnel"
        private const val NOTIF_ID = 1

        enum class State { DISCONNECTED, CONNECTING, CONNECTED }
        /** Observed by the UI so the dashboard reflects the real service state. */
        val state = MutableStateFlow(State.DISCONNECTED)
    }

    private var tun: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> { disconnect(); return START_NOT_STICKY }
            else -> connect()
        }
        return START_STICKY
    }

    private fun connect() {
        if (tun != null) return
        state.value = State.CONNECTING
        startForeground(NOTIF_ID, notification("Establishing the post-quantum tunnel…"))

        // Build the interface. No addRoute("0.0.0.0", 0) yet: without the JNI
        // data plane a full-tunnel route would black-hole traffic, so we claim
        // only the client's own tunnel address until the Rust core is wired.
        val builder = Builder()
            .setSession("SHAIP VPN")
            .addAddress("10.111.0.2", 32)
            .addDnsServer("10.111.0.1")
            .setMtu(1280)

        tun = runCatching { builder.establish() }.getOrNull()
        state.value = if (tun != null) State.CONNECTED else State.DISCONNECTED
        if (tun == null) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun disconnect() {
        runCatching { tun?.close() }
        tun = null
        state.value = State.DISCONNECTED
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        disconnect()
        super.onDestroy()
    }

    private fun notification(text: String): Notification {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, "Tunnel", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL)
            .setContentTitle("SHAIP VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }
}
