package net.shaip.pqanon.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import net.shaip.pqanon.ui.theme.Tokens

/** Group a 16-digit account number in fours, as it is shown everywhere. */
fun groupAccount(n: String): String = n.filter { it.isDigit() }.chunked(4).joinToString(" ")

/** Standard signed-in content column: padded, scrollable, spaced. */
@Composable
fun ScreenColumn(content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        content = content,
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun FlowRowCards(content: @Composable () -> Unit) {
    // The experimental FlowRow opt-in stays contained here so callers don't
    // need it; content is a plain composable lambda.
    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) { content() }
}

/** Glass stat tile: mono eyebrow label over a large value. */
@Composable
fun StatCard(label: String, value: String, accent: Boolean = false, mono: Boolean = false) {
    Column(
        Modifier.widthIn(min = 160.dp).glass().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Eyebrow(label)
        Text(
            value,
            color = if (accent) Tokens.Signal else Tokens.Ink,
            fontWeight = FontWeight.SemiBold,
            fontSize = 22.sp,
            fontFamily = if (mono) FontFamily.Monospace else FontFamily.SansSerif,
        )
    }
}
