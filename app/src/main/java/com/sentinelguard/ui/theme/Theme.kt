package com.sentinelguard.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// ─────────────────────────────────────────────────────────────────────────────
// Brand colour palette — canonical definitions, consumed by both MaterialTheme
// and the custom SentinelColors object in screen composables.
// ─────────────────────────────────────────────────────────────────────────────

/** Deep space background — primary app canvas. */
val ColorBackground      = Color(0xFF0A0A0F)

/** Elevated card surface — sits one level above background. */
val ColorSurface         = Color(0xFF12121A)

/** Pressed / highlighted surface — inputs, chips, secondary cards. */
val ColorSurfaceVariant  = Color(0xFF1E1E2E)

/** Subtle separator lines between content regions. */
val ColorDivider         = Color(0xFF1E1E2E)

/** Deep electric blue — primary actions, icons, switch tracks. */
val ColorAccent          = Color(0xFF2D6AFF)

/** Soft blue container for accent elements. */
val ColorAccentContainer = Color(0xFF1A3D99)

/** Pure white — primary text, icon foreground on dark. */
val ColorTextPrimary     = Color(0xFFFFFFFF)

/** Mid-grey — secondary labels, descriptions, timestamps. */
val ColorTextSecondary   = Color(0xFF8A8A9A)

/** Vibrant green — "active", "clean", "LOW" severity badge. */
val ColorStatusActive    = Color(0xFF00E676)

/** Signal red — "HIGH" severity badge, error state. */
val ColorSeverityHigh    = Color(0xFFFF3D3D)

/** Amber — "MEDIUM" severity badge, warning state. */
val ColorSeverityMedium  = Color(0xFFFFB020)

/** Same as ColorStatusActive — LOW severity badge. */
val ColorSeverityLow     = Color(0xFF00E676)

/** Muted red — inactive indicators. */
val ColorStatusInactive  = Color(0xFFFF3D3D)

/** Outline / border colour. */
val ColorOutline         = Color(0xFF2A2A3A)

// ─────────────────────────────────────────────────────────────────────────────
// Material3 dark colour scheme
// ─────────────────────────────────────────────────────────────────────────────

private val SentinelDarkColorScheme = darkColorScheme(
    primary            = ColorAccent,
    onPrimary          = ColorTextPrimary,
    primaryContainer   = ColorAccentContainer,
    onPrimaryContainer = Color(0xFFCCDDFF),

    secondary          = ColorTextSecondary,
    onSecondary        = ColorTextPrimary,

    background         = ColorBackground,
    onBackground       = ColorTextPrimary,

    surface            = ColorSurface,
    onSurface          = ColorTextPrimary,
    surfaceVariant     = ColorSurfaceVariant,
    onSurfaceVariant   = ColorTextSecondary,

    outline            = ColorOutline,
    error              = ColorSeverityHigh,
    onError            = ColorTextPrimary,
)

// ─────────────────────────────────────────────────────────────────────────────
// Theme entry point — dark only
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun SentinelGuardTheme(content: @Composable () -> Unit) {
    // Dark theme only — SentinelGuard has no light mode
    MaterialTheme(
        colorScheme = SentinelDarkColorScheme,
        typography  = SentinelTypography,
        content     = content
    )
}
