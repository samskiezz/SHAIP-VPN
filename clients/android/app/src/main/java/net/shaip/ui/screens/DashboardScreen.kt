package net.shaip.ui.screens

import android.content.Intent
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.shaip.net.Api
import net.shaip.net.DashboardResp
import net.shaip.ui.*
import net.shaip.ui.theme.Tokens
import net.shaip.vpn.PqNative
import net.shaip.vpn.ShaipVpnService

@Composable
fun DashboardScreen(api: Api, onDeleted: () -> Unit) {
    val ctx = LocalContext.current
    var dash by remember { mutableStateOf<DashboardResp?>(null) }
    var account by remember { mutableStateOf<String?>(null) }
    var err by remember { mutableStateOf<String?>(null) }
    var coreStatus by remember { mutableStateOf<String?>(null) }
    val vpnState by ShaipVpnService.state.collectAsState()

    // Load the native PQ core and run a real on-device self-test (ML-DSA-65
    // keygen) off the UI thread, proving the Rust core runs on the phone.
    LaunchedEffect(Unit) {
        coreStatus = withContext(Dispatchers.Default) {
            PqNative.selfTestOrNull() ?: "PQ core library not loaded on this ABI"
        }
    }

    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == android.app.Activity.RESULT_OK) {
            ctx.startService(Intent(ctx, ShaipVpnService::class.java).setAction(ShaipVpnService.ACTION_CONNECT))
        }
    }

    LaunchedEffect(Unit) {
        runCatching { api.me() }.onSuccess { account = it.accountNumber }
        runCatching { api.dashboard() }.onSuccess { dash = it }.onFailure { err = it.message }
    }

    ScreenColumn {
        Text("Dashboard", color = Tokens.Ink, fontWeight = FontWeight.Bold, fontSize = 28.sp)
        err?.let { Text("Error: $it", color = Tokens.Threat) }

        FlowRowCards {
            account?.let { StatCard("Your account number", groupAccount(it), accent = true, mono = true) }
            dash?.let { StatCard("Servers online", "${it.nodesOnline} of ${it.nodesTotal}") }
        }

        // Connect control, wired to the real VpnService. Flipping it on runs the
        // system VPN-consent dialog, then starts the service.
        Column(Modifier.fillMaxWidth().glass().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Eyebrow("Tunnel")
            // Honest: this build does NOT carry or protect traffic. The packet
            // data path (forwarding through the PQ core over JNI) isn't wired yet,
            // so the app must never show "Connected/Protected" — that would be
            // false confidence while real traffic flows outside any tunnel.
            StatusPill("Not protected", Tokens.Warn)
            coreStatus?.let {
                Text(it, color = Tokens.Ok, fontSize = 12.sp)
            }
            Text(
                "This build does not route or protect your traffic yet. The post-quantum core " +
                    "runs on-device (the self-test above is a live ML-DSA-65 keygen), but the " +
                    "tunnel data path — forwarding packets through it over JNI — isn't wired, and " +
                    "no server is deployed to carry traffic. Connect stays off until the data path " +
                    "is real, so the app never claims protection it can't provide.",
                color = Tokens.Ink3, fontSize = 12.sp,
            )
        }

        Text(
            "This page shows the network, never your activity: the control plane keeps no record " +
                "of your connections, traffic or the sites you visit, and doesn't log the address " +
                "you sign in from.",
            color = Tokens.Ink2, fontSize = 13.sp,
        )

        DeleteAccount(api, onDeleted)
    }
}

@Composable
private fun DeleteAccount(api: Api, onDeleted: () -> Unit) {
    val scope = rememberCoroutineScope()
    var open by remember { mutableStateOf(false) }
    var password by remember { mutableStateOf("") }
    var err by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    if (!open) {
        TextButton({ open = true }) { Text("Delete account…", color = Tokens.Threat) }
        return
    }
    Column(
        Modifier.widthIn(max = 420.dp).fillMaxWidth().glass().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Delete this account", color = Tokens.Threat, fontWeight = FontWeight.SemiBold)
        Text(
            "Everything stored about it is erased: its devices, API keys and security log. Its " +
                "devices are refused by every server from now on. This can't be undone.",
            color = Tokens.Ink2, fontSize = 13.sp,
        )
        Field(password, { password = it }, "your password", password = true)
        err?.let { Text(it, color = Tokens.Threat, fontSize = 13.sp) }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            PrimaryButton(if (busy) "…" else "Delete forever", enabled = !busy) {
                scope.launch {
                    busy = true; err = null
                    try { api.deleteAccount(password); onDeleted() }
                    catch (e: Exception) { err = e.message } finally { busy = false }
                }
            }
            TextButton({ open = false }) { Text("Cancel", color = Tokens.Ink2) }
        }
    }
}
