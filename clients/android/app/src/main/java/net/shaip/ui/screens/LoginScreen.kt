package net.shaip.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import net.shaip.net.Api
import net.shaip.net.Session
import net.shaip.ui.*
import net.shaip.ui.theme.Tokens

@androidx.compose.runtime.Composable
fun LoginScreen(api: Api, session: Session, onSignedIn: () -> Unit) {
    val scope = rememberCoroutineScope()
    var register by remember { mutableStateOf(false) }
    var account by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var created by remember { mutableStateOf<String?>(null) }
    var noted by remember { mutableStateOf(false) }
    var err by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    fun signIn(number: String) = scope.launch {
        busy = true; err = null
        try {
            session.token = api.login(number.filter { it.isDigit() }, password).token
            onSignedIn()
        } catch (e: Exception) { err = e.message } finally { busy = false }
    }

    ScreenBackground {
        Box(Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
            Column(
                Modifier.widthIn(max = 380.dp).fillMaxWidth().glass().padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    GlowDot(Tokens.Signal)
                    Eyebrow("SHAIP VPN · Post-quantum VPN")
                }
                Text("SHAIP VPN", color = Tokens.Signal, fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold, fontSize = 26.sp)

                val shown = created
                if (shown != null) {
                    Text("Your account number is your login:", color = Tokens.Ink2)
                    Text(
                        groupAccount(shown),
                        color = Tokens.Ink,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 20.sp,
                        letterSpacing = 3.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(Tokens.FieldFill)
                            .padding(vertical = 12.dp),
                    )
                    Text(
                        "Write it down and keep it with your password. We don't know who you " +
                            "are, so we can't recover it. It is shown only now.",
                        color = Tokens.Ink2, fontSize = 13.sp,
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(noted, { noted = it },
                            colors = CheckboxDefaults.colors(checkedColor = Tokens.Signal))
                        Text("I've written it down", color = Tokens.Ink2)
                    }
                    err?.let { Text(it, color = Tokens.Threat, fontSize = 13.sp) }
                    PrimaryButton("Continue", enabled = noted && !busy, modifier = Modifier.fillMaxWidth()) {
                        signIn(shown)
                    }
                } else {
                    Text(
                        if (register) "Create an account. No email or name: you get a random account number."
                        else "Sign in with your account number",
                        color = Tokens.Ink2,
                    )
                    if (!register) {
                        Field(account, { account = groupAccount(it).take(19) },
                            "1234 5678 9012 3456", mono = true, numeric = true)
                    }
                    Field(password, { password = it }, "password (min 8 chars)", password = true)
                    err?.let { Text(it, color = Tokens.Threat, fontSize = 13.sp) }
                    PrimaryButton(
                        if (register) "Create account" else "Sign in",
                        enabled = !busy, modifier = Modifier.fillMaxWidth(),
                    ) {
                        scope.launch {
                            busy = true; err = null
                            try {
                                if (register) created = api.register(password).accountNumber
                                else signIn(account)
                            } catch (e: Exception) { err = e.message } finally { busy = false }
                        }
                    }
                    TextButton({ err = null; register = !register }, Modifier.fillMaxWidth()) {
                        Text(
                            if (register) "Have an account number? Sign in" else "Need an account? Create one",
                            color = Tokens.Ink2,
                        )
                    }
                }
            }
        }
    }
}
