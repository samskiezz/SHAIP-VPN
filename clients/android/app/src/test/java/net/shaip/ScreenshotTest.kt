package net.shaip

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.cash.paparazzi.DeviceConfig
import app.cash.paparazzi.Paparazzi
import net.shaip.net.Node
import net.shaip.ui.*
import net.shaip.ui.theme.ShaipTheme
import net.shaip.ui.theme.Tokens
import org.junit.Rule
import org.junit.Test

/**
 * Headless render of the Android UI with layoutlib — no emulator, no device.
 * These previews use the real glass component kit and obviously-sample
 * infrastructure data (demo node names, a placeholder account number); no
 * customer data is involved.
 */
class ScreenshotTest {
    @get:Rule
    val paparazzi = Paparazzi(deviceConfig = DeviceConfig.PIXEL_6, showSystemUi = false)

    @Test fun login() = paparazzi.snapshot { ShaipTheme { LoginPreview() } }
    @Test fun dashboard() = paparazzi.snapshot { ShaipTheme { DashboardPreview() } }
    @Test fun servers() = paparazzi.snapshot { ShaipTheme { ServersPreview() } }
    @Test fun buyAccess() = paparazzi.snapshot { ShaipTheme { PayPreview() } }
}

@Composable
private fun LoginPreview() = ScreenBackground {
    Box(Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
        Column(Modifier.widthIn(max = 380.dp).fillMaxWidth().glass().padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                GlowDot(Tokens.Signal); Eyebrow("SHAIP VPN · Post-quantum VPN")
            }
            Text("SHAIP VPN", color = Tokens.Signal, fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold, fontSize = 26.sp)
            Text("Sign in with your account number", color = Tokens.Ink2)
            Field("1234 5678 9012 3456", {}, "1234 5678 9012 3456", mono = true)
            Field("", {}, "password (min 8 chars)", password = true)
            PrimaryButton("Sign in", modifier = Modifier.fillMaxWidth()) {}
            Text("Need an account? Create one", color = Tokens.Ink2, modifier = Modifier.fillMaxWidth())
        }
    }
}

@Composable
private fun DashboardPreview() = ScreenBackground {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())
        .padding(horizontal = 16.dp, vertical = 20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text("Dashboard", color = Tokens.Ink, fontWeight = FontWeight.Bold, fontSize = 28.sp)
        FlowRowCards {
            StatCard("Your account number", groupAccount("1234567890123456"), accent = true, mono = true)
            StatCard("Servers online", "2 of 3")
        }
        Column(Modifier.fillMaxWidth().glass().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Eyebrow("Tunnel")
            StatusPill("Not protected", Tokens.Warn)
            // The on-device PQ self-test output (the real output format, proven by
            // the JVM round-trip test over the same libshaip_jni).
            Text("PQ core OK — ML-DSA-65 verifying key 1952 bytes, identity ebe93d0a…",
                color = Tokens.Ok, fontSize = 12.sp)
            Text("This build does not route or protect traffic yet: the data path (forwarding " +
                "packets through the PQ core over JNI) isn't wired, and no server is deployed. " +
                "The core runs on-device — the line above is a live keygen.", color = Tokens.Ink3, fontSize = 12.sp)
        }
        Text("This page shows the network, never your activity: the control plane keeps no record " +
            "of your connections, traffic or the sites you visit.", color = Tokens.Ink2, fontSize = 13.sp)
    }
}

private val sampleNodes = listOf(
    Node(id = "tokyo-01", name = "tokyo-01", address = "203.0.113.10:443", role = "mix", region = "", capacityMbps = 100, status = "active"),
    Node(id = "frankfurt-01", name = "frankfurt-01", address = "198.51.100.20:443", role = "mix", region = "", capacityMbps = 100, status = "listed"),
    Node(id = "syd-edge-01", name = "syd-edge-01", address = "vpn-syd.example.net:443", role = "entry", region = "AU", capacityMbps = 1000, status = "offline"),
)

@Composable
private fun ServersPreview() = ScreenBackground {
    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp, vertical = 20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.Bottom) {
            Text("Servers", color = Tokens.Ink, fontWeight = FontWeight.Bold, fontSize = 28.sp)
            Eyebrow("3 nodes · 2 online · 1 region")
        }
        Column(Modifier.fillMaxWidth().glassTile()) {
            Row(Modifier.fillMaxWidth().padding(14.dp)) {
                PreviewCell("SERVER", 2.0f); PreviewCell("ROLE", 0.9f)
                PreviewCell("CAPACITY", 1.2f); PreviewCell("STATUS", 1.5f)
            }
            sampleNodes.forEach { n ->
                Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(2.0f).padding(end = 8.dp)) {
                        Text(n.name, color = Tokens.Ink, fontWeight = FontWeight.Medium,
                            maxLines = 1, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis)
                        Text(n.address, color = Tokens.Ink3, fontFamily = FontFamily.Monospace, fontSize = 11.sp,
                            maxLines = 1, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis)
                    }
                    PreviewCell(if (n.role == "mix") "Mix" else "Entry", 0.9f)
                    PreviewCell("${n.capacityMbps} Mbps", 1.2f)
                    Box(Modifier.weight(1.5f)) {
                        StatusPill(if (n.online) "online" else "offline", if (n.online) Tokens.Ok else Tokens.Steel)
                    }
                }
            }
        }
    }
}

@Composable
private fun PayPreview() = ScreenBackground {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())
        .padding(horizontal = 16.dp, vertical = 20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text("SHAIP VPN — Private access", color = Tokens.Signal, fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold, fontSize = 22.sp)
        Text("Pay with Monero or Bitcoin. Get blind-signed access tokens (RFC 9474).",
            color = Tokens.Ink2, fontSize = 14.sp)
        Text("Have a code?", color = Tokens.Signal, fontWeight = FontWeight.SemiBold, fontSize = 18.sp)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Field("SHAIP-FREE-YEAR", {}, "SHAIP-XXXX-XXXX-XXXX", mono = true, modifier = Modifier.weight(1f))
            GlassButton("Redeem") {}
        }
        Column(Modifier.fillMaxWidth().glass().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Access granted — plan: pro", color = Tokens.Ok, fontWeight = FontWeight.SemiBold)
            Text("Valid until 2027-10-17.", color = Tokens.Ok, fontSize = 13.sp)
        }
    }
}

@Composable
private fun RowScope.PreviewCell(text: String, weight: Float) {
    val header = text == text.uppercase() && text.length > 2
    Text(text, color = if (header) Tokens.Ink3 else Tokens.Ink2,
        fontFamily = FontFamily.Monospace, fontSize = if (header) 11.sp else 14.sp,
        modifier = Modifier.weight(weight))
}
