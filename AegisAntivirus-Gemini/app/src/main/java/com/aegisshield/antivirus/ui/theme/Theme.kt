package com.aegisshield.antivirus.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val DarkColorScheme = darkColorScheme(
    primary = NeonCyan,
    secondary = NeonGreen,
    tertiary = NeonPurple,
    background = CyberBgDark,
    surface = CyberSurfaceDark,
    onPrimary = CyberBgDark,
    onSecondary = CyberBgDark,
    onTertiary = CyberBgDark,
    onBackground = TextPrimary,
    onSurface = TextPrimary
)

@Composable
fun AegisAntivirusTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        content = content
    )
}
