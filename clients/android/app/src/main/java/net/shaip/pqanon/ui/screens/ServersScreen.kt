package net.shaip.pqanon.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import net.shaip.pqanon.net.Api
import net.shaip.pqanon.net.Node
import net.shaip.pqanon.ui.*
import net.shaip.pqanon.ui.theme.Tokens

private val ROLE = mapOf("entry" to "Entry", "exit" to "Exit", "gateway" to "Gateway", "mix" to "Mix")

@Composable
fun ServersScreen(api: Api) {
    var nodes by remember { mutableStateOf<List<Node>?>(null) }
    var err by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        runCatching { api.nodes() }.onSuccess { nodes = it }.onFailure { err = it.message }
    }

    ScreenColumn {
        val list = nodes
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.Bottom) {
            Text("Servers", color = Tokens.Ink, fontWeight = FontWeight.Bold, fontSize = 28.sp)
            if (list != null) {
                val online = list.count { it.online }
                val regions = list.map { it.region }.filter { it.isNotBlank() }.distinct().size
                Eyebrow("${list.size} nodes · $online online · $regions region")
            }
        }
        err?.let { Text("Could not load the directory: $it", color = Tokens.Threat) }

        when {
            list == null && err == null -> Text("Loading…", color = Tokens.Ink3)
            list != null && list.isEmpty() ->
                Column(Modifier.fillMaxWidth().glassTile().padding(20.dp)) {
                    Text("No servers are listed yet.", color = Tokens.Ink2)
                    Text(
                        "A server must bond stake to appear here. The directory is signed by the " +
                            "control plane and verified by the client before it trusts a server.",
                        color = Tokens.Ink3, fontSize = 13.sp,
                    )
                }
            list != null -> Column(Modifier.fillMaxWidth().glassTile(), verticalArrangement = Arrangement.spacedBy(0.dp)) {
                HeaderRow()
                list.forEach { NodeRow(it) }
            }
        }

        Text(
            "The directory is signed by the control plane and verified by the client before it " +
                "trusts a server. The tunnel connects to one server at a time — there is no mix " +
                "routing yet, so traffic does not hop between these nodes.",
            color = Tokens.Ink2, fontSize = 13.sp,
        )
    }
}

@Composable
private fun HeaderRow() {
    Row(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 10.dp)) {
        Cell("Server", 2.0f, header = true)
        Cell("Role", 0.9f, header = true)
        Cell("Capacity", 1.2f, header = true)
        Cell("Status", 1.5f, header = true)
    }
}

@Composable
private fun NodeRow(n: Node) {
    Row(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(2.0f).padding(end = 8.dp)) {
            Text(n.name.ifBlank { n.id }, color = Tokens.Ink, fontWeight = FontWeight.Medium,
                maxLines = 1, overflow = TextOverflow.Ellipsis)
            if (n.address.isNotBlank())
                Text(n.address, color = Tokens.Ink3, fontFamily = FontFamily.Monospace, fontSize = 11.sp,
                    maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        Cell(ROLE[n.role] ?: n.role.ifBlank { "—" }, 0.9f)
        Cell(if (n.capacityMbps > 0) "${n.capacityMbps} Mbps" else "—", 1.2f, mono = true)
        Box(Modifier.weight(1.5f)) {
            StatusPill(if (n.online) "online" else "offline", if (n.online) Tokens.Ok else Tokens.Steel)
        }
    }
}

@Composable
private fun RowScope.Cell(text: String, weight: Float, header: Boolean = false, mono: Boolean = false) {
    Text(
        if (header) text.uppercase() else text,
        color = if (header) Tokens.Ink3 else Tokens.Ink2,
        fontFamily = if (mono || header) FontFamily.Monospace else FontFamily.SansSerif,
        fontSize = if (header) 11.sp else 14.sp,
        letterSpacing = if (header) 1.2.sp else 0.sp,
        modifier = Modifier.weight(weight),
    )
}
