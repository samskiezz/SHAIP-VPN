package net.shaip.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import net.shaip.ui.theme.Mono
import net.shaip.ui.theme.Tokens

/** The deep-graphite radial background shared with web and iOS. */
@Composable
fun ScreenBackground(content: @Composable () -> Unit) {
    Box(
        Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    0f to Tokens.Bg0,
                    0.55f to Tokens.Bg1,
                    1f to Tokens.Bg2,
                )
            )
    ) { content() }
}

/** Liquid-Glass card surface. */
fun Modifier.glass(radius: Int = 20): Modifier = this
    .clip(RoundedCornerShape(radius.dp))
    .background(Brush.verticalGradient(listOf(Tokens.GlassTop, Tokens.GlassBottom)))
    .border(BorderStroke(1.dp, Tokens.Hairline), RoundedCornerShape(radius.dp))

/** Secondary glass tile (lists, tables). */
fun Modifier.glassTile(radius: Int = 20): Modifier = this
    .clip(RoundedCornerShape(radius.dp))
    .background(Brush.verticalGradient(listOf(Color(0x12FFFFFF), Color(0x05FFFFFF))))
    .border(BorderStroke(1.dp, Tokens.HairlineSoft), RoundedCornerShape(radius.dp))

/** Mono uppercase eyebrow label. */
@Composable
fun Eyebrow(text: String, color: Color = Tokens.Ink3) {
    Text(
        text.uppercase(),
        color = color,
        fontFamily = Mono,
        fontSize = 11.sp,
        letterSpacing = 1.6.sp,
        fontWeight = FontWeight.Medium,
    )
}

/** A glowing status dot; tint sets the colour. */
@Composable
fun GlowDot(tint: Color, modifier: Modifier = Modifier) {
    Box(modifier.size(7.dp).clip(CircleShape).background(tint))
}

/** A small status pill with a leading glow dot. */
@Composable
fun StatusPill(label: String, tint: Color) {
    Row(
        Modifier
            .clip(RoundedCornerShape(12.dp))
            .background(tint.copy(alpha = 0.12f))
            .border(BorderStroke(1.dp, tint.copy(alpha = 0.35f)), RoundedCornerShape(12.dp))
            .height(24.dp)
            .padding(horizontal = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(5.dp),
    ) {
        GlowDot(tint)
        Text(label.uppercase(), color = tint, fontFamily = Mono, fontSize = 10.sp,
            letterSpacing = 0.8.sp, maxLines = 1, softWrap = false)
    }
}
