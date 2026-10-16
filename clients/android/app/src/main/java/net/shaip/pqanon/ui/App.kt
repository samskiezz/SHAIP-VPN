package net.shaip.pqanon.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import net.shaip.pqanon.net.Api
import net.shaip.pqanon.net.Session
import net.shaip.pqanon.ui.screens.*
import net.shaip.pqanon.ui.theme.Tokens

private enum class Tab(val label: String) {
    Dashboard("Dashboard"), Servers("Servers"), Devices("Devices"), Pay("Buy access")
}

@Composable
fun PqAnonApp(api: Api, session: Session) {
    var signedIn by remember { mutableStateOf(session.isSignedIn) }

    if (!signedIn) {
        LoginScreen(api, session, onSignedIn = { signedIn = true })
        return
    }

    var tab by remember { mutableStateOf(Tab.Dashboard) }
    ScreenBackground {
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            TopBar(current = tab, onSelect = { tab = it }, onSignOut = { session.signOut(); signedIn = false })
            Box(Modifier.weight(1f)) {
                when (tab) {
                    Tab.Dashboard -> DashboardScreen(api, onDeleted = { session.signOut(); signedIn = false })
                    Tab.Servers -> ServersScreen(api)
                    Tab.Devices -> DevicesScreen(api)
                    Tab.Pay -> PayScreen(api)
                }
            }
        }
    }
}

@Composable
private fun TopBar(current: Tab, onSelect: (Tab) -> Unit, onSignOut: () -> Unit) {
    Column(Modifier.fillMaxWidth().background(Color(0x14FFFFFF))) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text("PQ·ANON", color = Tokens.Signal, fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold, fontSize = 18.sp)
            TextButton(onSignOut) { Text("Sign out", color = Tokens.Ink2) }
        }
        Row(
            Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Tab.values().forEach { t ->
                val active = t == current
                TextButton(onClick = { onSelect(t) }) {
                    Text(
                        t.label,
                        color = if (active) Tokens.Ink else Tokens.Ink3,
                        fontWeight = if (active) FontWeight.SemiBold else FontWeight.Normal,
                    )
                }
            }
        }
    }
}
