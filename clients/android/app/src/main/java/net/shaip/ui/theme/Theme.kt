package net.shaip.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val PqColors = darkColorScheme(
    primary = Tokens.Signal,
    onPrimary = Tokens.Bg2,
    background = Tokens.Bg2,
    onBackground = Tokens.Ink,
    surface = Tokens.Bg1,
    onSurface = Tokens.Ink,
    error = Tokens.Threat,
)

// The app is dark-only by design, like the iOS and web products.
@Composable
fun ShaipTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = PqColors, typography = PqTypography, content = content)
}
