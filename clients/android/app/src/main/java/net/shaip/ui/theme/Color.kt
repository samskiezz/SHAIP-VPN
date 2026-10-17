package net.shaip.ui.theme

import androidx.compose.ui.graphics.Color

// The single palette shared across SHAIP: the iOS app (clients/ios/design/
// HANDOFF.md), the web UI (web-ui/tailwind.config.js) and this Android client.
object Tokens {
    val Bg0 = Color(0xFF0B1020)   // top of the background gradient
    val Bg1 = Color(0xFF04050A)   // mid
    val Bg2 = Color(0xFF020306)   // bottom / base

    val Ink = Color(0xFFF5F7FC)   // primary text
    val Ink2 = Color(0xFFB6C0D4)  // secondary text
    val Ink3 = Color(0xFF8A9BB8)  // muted / eyebrow

    val Signal = Color(0xFF5CF2FF) // cyan accent
    val Steel = Color(0xFF8A9BB8)
    val Ok = Color(0xFF62F5A8)
    val Warn = Color(0xFFFFB547)
    val Threat = Color(0xFFFF5C7A)

    // Glass surfaces are translucent whites over the gradient.
    val GlassTop = Color(0x16FFFFFF)
    val GlassBottom = Color(0x06FFFFFF)
    val Hairline = Color(0x26FFFFFF)   // ~0.15 white
    val HairlineSoft = Color(0x1AFFFFFF)
    val FieldFill = Color(0x0DFFFFFF)
}
