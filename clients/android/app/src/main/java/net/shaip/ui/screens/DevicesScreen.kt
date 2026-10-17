package net.shaip.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import net.shaip.net.Api
import net.shaip.ui.*
import net.shaip.ui.theme.Tokens

@Composable
fun DevicesScreen(api: Api) {
    val scope = rememberCoroutineScope()
    var link by remember { mutableStateOf<String?>(null) }
    var err by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    ScreenColumn {
        Text("Devices", color = Tokens.Ink, fontWeight = FontWeight.Bold, fontSize = 28.sp)
        Text(
            "Enroll a device with a one-time link. Each link issues a single device certificate " +
                "and then cannot be used again. No device name or identifier is stored.",
            color = Tokens.Ink2, fontSize = 13.sp,
        )
        PrimaryButton(if (busy) "…" else "Issue enrollment link", enabled = !busy) {
            scope.launch {
                busy = true; err = null
                try { link = api.enroll().url } catch (e: Exception) { err = e.message } finally { busy = false }
            }
        }
        err?.let { Text(it, color = Tokens.Threat, fontSize = 13.sp) }
        link?.let {
            Column(Modifier.fillMaxWidth().glassTile().padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Eyebrow("One-time enrollment link")
                Text(it, color = Tokens.Ink, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
            }
        }
    }
}
