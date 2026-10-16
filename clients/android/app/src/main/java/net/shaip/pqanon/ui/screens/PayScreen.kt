package net.shaip.pqanon.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import net.shaip.pqanon.net.Api
import net.shaip.pqanon.net.Denom
import net.shaip.pqanon.net.Grant
import net.shaip.pqanon.ui.*
import net.shaip.pqanon.ui.theme.Tokens

@Composable
fun PayScreen(api: Api) {
    val scope = rememberCoroutineScope()
    var denoms by remember { mutableStateOf<List<Denom>>(emptyList()) }
    var rails by remember { mutableStateOf<List<String>>(emptyList()) }
    var code by remember { mutableStateOf("") }
    var grant by remember { mutableStateOf<Grant?>(null) }
    var codeErr by remember { mutableStateOf<String?>(null) }
    var claiming by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        runCatching { api.denominations() }.onSuccess { denoms = it.denominations; rails = it.rails }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("PQ·ANON — Private access", color = Tokens.Signal,
            fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, fontSize = 22.sp)
        Text(
            "Pay with Monero or Bitcoin. Get blind-signed access tokens: the token you redeem " +
                "carries nothing that links it to your payment (RFC 9474 blind signatures).",
            color = Tokens.Ink2, fontSize = 14.sp,
        )

        // Plans
        Text(buildString {
            append("Plans")
            if (rails.isNotEmpty()) append("  · paid in ${rails.joinToString(" / ")}")
        }, color = Tokens.Signal, fontWeight = FontWeight.SemiBold, fontSize = 18.sp)
        Column(Modifier.fillMaxWidth().glassTile()) {
            Row(Modifier.fillMaxWidth().padding(14.dp)) {
                PCell("Plan", 1.4f, header = true); PCell("Duration", 1f, header = true)
                PCell("Monero", 1.2f, header = true); PCell("Bitcoin", 1.4f, header = true)
            }
            if (denoms.isEmpty()) Text("Loading…", color = Tokens.Ink3, modifier = Modifier.padding(14.dp))
            denoms.forEach { d ->
                Row(Modifier.fillMaxWidth().padding(14.dp)) {
                    PCell(d.label, 1.4f, bold = true)
                    PCell("${d.durationDays} ${if (d.durationDays == 1) "day" else "days"}", 1f)
                    PCell("${d.priceXmr} XMR", 1.2f, mono = true)
                    PCell("${d.priceBtc} BTC", 1.4f, mono = true)
                }
            }
        }

        // Have a code?
        Text("Have a code?", color = Tokens.Signal, fontWeight = FontWeight.SemiBold, fontSize = 18.sp)
        Text(
            "A discount, promo, or test code grants access without a payment. Like a redeemed " +
                "token, claiming a code is identity-free: no account, no card, and it records only " +
                "that one use was spent.",
            color = Tokens.Ink2, fontSize = 13.sp,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Field(code, { code = it }, "SHAIP-XXXX-XXXX-XXXX", mono = true, modifier = Modifier.weight(1f))
            GlassButton(if (claiming) "…" else "Redeem", enabled = code.isNotBlank() && !claiming) {
                scope.launch {
                    claiming = true; codeErr = null; grant = null
                    try { grant = api.claimCode(code.trim()) }
                    catch (e: Exception) { codeErr = e.message } finally { claiming = false }
                }
            }
        }
        codeErr?.let { Text(it, color = Tokens.Threat, fontSize = 13.sp) }
        grant?.let { g ->
            Column(
                Modifier.fillMaxWidth().glass().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Access granted — plan: ${g.plan}", color = Tokens.Ok, fontWeight = FontWeight.SemiBold)
                Text("Valid until ${g.expiresAt.take(10)}.", color = Tokens.Ok, fontSize = 13.sp)
                Text("Your access grant (paste into Setup → Paste config):", color = Tokens.Ink2, fontSize = 13.sp)
                Text(g.grant, color = Tokens.Ink3, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
            }
        }

        Text(
            "Limits. No account or email is needed to pay. The token is unlinkable, but timing " +
                "and IP addresses are not. The VPN server can see where your traffic goes, as any " +
                "VPN operator can.",
            color = Tokens.Ink2, fontSize = 12.sp,
        )
    }
}

@Composable
private fun RowScope.PCell(text: String, weight: Float, header: Boolean = false, bold: Boolean = false, mono: Boolean = false) {
    Text(
        if (header) text.uppercase() else text,
        color = if (header) Tokens.Ink3 else Tokens.Ink2,
        fontFamily = if (mono || header) FontFamily.Monospace else FontFamily.SansSerif,
        fontWeight = if (bold) FontWeight.Medium else FontWeight.Normal,
        fontSize = if (header) 11.sp else 13.sp,
        letterSpacing = if (header) 1.1.sp else 0.sp,
        modifier = Modifier.weight(weight),
    )
}
