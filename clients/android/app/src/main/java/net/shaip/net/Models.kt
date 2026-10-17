package net.shaip.net

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

// Wire models for the SHAIP-CP/1 control plane. Field names match the Go
// handlers' JSON tags exactly.

@Serializable
data class RegisterResp(@SerialName("account_number") val accountNumber: String)

@Serializable
data class LoginResp(val token: String)

@Serializable
data class Me(
    @SerialName("account_number") val accountNumber: String,
    @SerialName("created_at") val createdAt: String? = null,
)

@Serializable
data class DashboardResp(
    @SerialName("nodes_online") val nodesOnline: Int,
    @SerialName("nodes_total") val nodesTotal: Int,
)

@Serializable
data class Node(
    val id: String,
    val name: String = "",
    val address: String = "",
    val role: String = "",
    val region: String = "",
    @SerialName("capacity_mbps") val capacityMbps: Int = 0,
    val status: String = "",
    @SerialName("stake_sats") val stakeSats: Long = 0,
    @SerialName("created_at") val createdAt: String = "",
) {
    val online: Boolean get() = status == "active" || status == "listed" || status == "online"
}

@Serializable
data class EnrollResp(val url: String, val token: String)

@Serializable
data class Denom(
    val id: String,
    val label: String,
    @SerialName("duration_days") val durationDays: Int,
    @SerialName("price_xmr") val priceXmr: String = "",
    @SerialName("price_btc") val priceBtc: String = "",
)

@Serializable
data class DenomResp(
    val rails: List<String> = emptyList(),
    @SerialName("default_rail") val defaultRail: String = "",
    val denominations: List<Denom> = emptyList(),
)

@Serializable
data class Grant(
    @SerialName("session_id") val sessionId: String = "",
    val grant: String,
    val plan: String,
    @SerialName("expires_at") val expiresAt: String,
)

@Serializable
data class ApiError(val error: String = "")
