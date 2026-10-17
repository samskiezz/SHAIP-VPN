package net.shaip.pqanon.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

/** Raised when the control plane answers non-2xx; [message] is server-supplied. */
class ApiException(message: String, val status: Int) : Exception(message)

/**
 * Thin client for the SHAIP-CP/1 control plane — the same API the web UI and
 * CLI use. All calls are suspend functions that run on the IO dispatcher.
 */
class Api(private val session: Session) {
    private val http = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .build()

    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    private val json = Json { ignoreUnknownKeys = true; explicitNulls = false }
    private val jsonType = "application/json; charset=utf-8".toMediaType()

    private inline fun <reified T> decode(body: String): T = json.decodeFromString(body)

    private suspend fun request(
        method: String,
        path: String,
        body: Any? = null,
        auth: Boolean = true,
    ): String = withContext(Dispatchers.IO) {
        val url = session.apiBase.trimEnd('/') + path
        val rb = body?.let { encodeBody(it).toRequestBody(jsonType) }
        val b = Request.Builder().url(url).method(method, rb)
        if (body != null) b.header("Content-Type", "application/json")
        if (auth) session.token?.let { b.header("Authorization", "Bearer $it") }
        http.newCall(b.build()).execute().use { resp ->
            val text = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) {
                val msg = runCatching { decode<ApiError>(text).error }.getOrNull()
                    ?.takeIf { it.isNotBlank() } ?: "request failed (${resp.code})"
                throw ApiException(msg, resp.code)
            }
            text
        }
    }

    // Bodies are small and fixed-shape; build them without reflection so no
    // @Serializable request type is needed per call.
    private fun encodeBody(body: Any): String = when (body) {
        is Map<*, *> -> buildString {
            append('{')
            body.entries.filter { it.value != null }.joinTo(this, ",") { (k, v) ->
                "\"$k\":\"${(v as String).replace("\\", "\\\\").replace("\"", "\\\"")}\""
            }
            append('}')
        }
        else -> error("unsupported body")
    }

    // --- Auth ---
    suspend fun register(password: String): RegisterResp =
        decode(request("POST", "/api/auth/register", mapOf("password" to password), auth = false))

    suspend fun login(accountNumber: String, password: String): LoginResp =
        decode(request("POST", "/api/auth/login",
            mapOf("account_number" to accountNumber, "password" to password), auth = false))

    suspend fun me(): Me = decode(request("GET", "/api/me"))

    suspend fun deleteAccount(password: String) {
        request("DELETE", "/api/me", mapOf("password" to password))
    }

    // --- Network ---
    suspend fun dashboard(): DashboardResp = decode(request("GET", "/api/dashboard"))

    suspend fun nodes(): List<Node> = decode(request("GET", "/api/nodes"))

    suspend fun deleteNode(id: String) { request("DELETE", "/api/nodes/$id") }

    // --- Devices ---
    suspend fun enroll(): EnrollResp = decode(request("POST", "/api/enroll/issue", emptyMap<String, String>()))

    // --- Pay (public, identity-free) ---
    suspend fun denominations(): DenomResp = decode(request("GET", "/api/pay/denominations", auth = false))

    suspend fun claimCode(code: String): Grant =
        decode(request("POST", "/api/pay/claim-code", mapOf("code" to code), auth = false))
}
