package net.shaip.net

import android.content.Context
import net.shaip.BuildConfig

/**
 * Per-device session state in app-private storage (sandboxed, and excluded from
 * cloud backup / device transfer in data_extraction_rules.xml). Holds only the
 * bearer token and the chosen control-plane base URL — no account number is
 * persisted, matching the privacy posture of the iOS and web clients.
 */
class Session(context: Context) {
    private val sp = context.applicationContext.getSharedPreferences("shaip", Context.MODE_PRIVATE)

    var token: String?
        get() = sp.getString("token", null)
        set(v) = sp.edit().apply { if (v == null) remove("token") else putString("token", v) }.apply()

    var apiBase: String
        get() = sp.getString("api_base", null) ?: BuildConfig.DEFAULT_API_BASE
        set(v) = sp.edit().putString("api_base", v.trimEnd('/')).apply()

    val isSignedIn: Boolean get() = token != null

    fun signOut() { token = null }
}
