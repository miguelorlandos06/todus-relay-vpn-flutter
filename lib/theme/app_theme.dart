import 'package:flutter/material.dart';

/// Paleta de la app: “dark premium” con acento verde-azulado (teal).
///
/// El teal viene de la marca original de ToDus VPN (#00897B); aquí se usa una
/// variante más luminosa (#2DD4BF) para garantizar contraste sobre fondos
/// casi negros con matiz verdoso. Un solo acento: el color comunica estado,
/// no decora.
abstract final class AppColors {
  /// Fondo base (negro con matiz verdoso, no #000 puro: evita el “smearing” OLED).
  static const Color background = Color(0xFF0A0F0D);

  /// Superficie de tarjetas y barras.
  static const Color surface = Color(0xFF121917);

  /// Superficie elevada (botón principal, tooltips).
  static const Color surfaceRaised = Color(0xFF17211E);

  /// Bordes finos (“hairlines”).
  static const Color outline = Color(0xFF223029);

  /// Acento: teal luminoso (conectado / acciones primarias).
  static const Color accent = Color(0xFF2DD4BF);

  /// Acento apagado (fondos tenues del acento).
  static const Color accentDeep = Color(0xFF0F766E);

  /// Conectando.
  static const Color warning = Color(0xFFFBBF24);

  /// Error / desconexión forzada.
  static const Color danger = Color(0xFFF87171);

  /// Texto principal.
  static const Color textPrimary = Color(0xFFEDF4F0);

  /// Texto secundario / etiquetas.
  static const Color textMuted = Color(0xFF8CA39B);
}

/// Familia tipográfica de display (títulos, cifras y estados).
const String kDisplayFont = 'SpaceGrotesk';

/// Familia monoespaciada (registro y valores técnicos).
const String kMonoFont = 'JetBrainsMono';

/// Cifras tabulares: columnas de números alineadas dígito a dígito.
TextStyle tabular(TextStyle style) =>
    style.copyWith(fontFeatures: const <FontFeature>[FontFeature.tabularFigures()]);

/// Tema oscuro de la app (Material 3).
abstract final class AppTheme {
  static const ColorScheme _scheme = ColorScheme.dark(
    primary: AppColors.accent,
    onPrimary: Color(0xFF04211C),
    secondary: AppColors.accent,
    onSecondary: Color(0xFF04211C),
    error: AppColors.danger,
    onError: Color(0xFF330B0B),
    surface: AppColors.surface,
    onSurface: AppColors.textPrimary,
    onSurfaceVariant: AppColors.textMuted,
    outline: AppColors.outline,
    outlineVariant: AppColors.outline,
  );

  static ThemeData dark() {
    final base = ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      colorScheme: _scheme,
      scaffoldBackgroundColor: AppColors.background,
    );

    final t = base.textTheme;

    return base.copyWith(
      textTheme: t.copyWith(
        // Display/Headline: Space Grotesk (estados, cifras grandes).
        displaySmall: t.displaySmall?.copyWith(fontFamily: kDisplayFont, fontWeight: FontWeight.w700),
        headlineLarge: t.headlineLarge?.copyWith(fontFamily: kDisplayFont, fontWeight: FontWeight.w700),
        headlineMedium: t.headlineMedium?.copyWith(fontFamily: kDisplayFont, fontWeight: FontWeight.w600),
        headlineSmall: t.headlineSmall?.copyWith(fontFamily: kDisplayFont, fontWeight: FontWeight.w600),
        titleLarge: t.titleLarge?.copyWith(fontFamily: kDisplayFont, fontWeight: FontWeight.w600),
        // Cuerpo y etiquetas: Roboto del sistema.
        bodyLarge: t.bodyLarge?.copyWith(color: AppColors.textPrimary),
        bodyMedium: t.bodyMedium?.copyWith(color: AppColors.textPrimary),
        bodySmall: t.bodySmall?.copyWith(color: AppColors.textMuted),
        labelLarge: t.labelLarge?.copyWith(fontWeight: FontWeight.w600),
        labelMedium: t.labelMedium?.copyWith(
          color: AppColors.textMuted,
          fontWeight: FontWeight.w600,
          letterSpacing: 0.9,
        ),
        labelSmall: t.labelSmall?.copyWith(
          color: AppColors.textMuted,
          fontWeight: FontWeight.w500,
          letterSpacing: 0.6,
        ),
      ),
      splashFactory: InkSparkle.splashFactory,
      dividerTheme: const DividerThemeData(
        color: AppColors.outline,
        thickness: 1,
        space: 1,
      ),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: AppColors.surface,
        surfaceTintColor: Colors.transparent,
        indicatorColor: AppColors.accent.withValues(alpha: 0.16),
        elevation: 0,
        height: 68,
        labelBehavior: NavigationDestinationLabelBehavior.alwaysShow,
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          minimumSize: const Size(48, 48),
          backgroundColor: AppColors.accent,
          foregroundColor: const Color(0xFF04211C),
          textStyle: t.labelLarge?.copyWith(fontFamily: kDisplayFont, fontWeight: FontWeight.w600),
        ),
      ),
      snackBarTheme: SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        backgroundColor: AppColors.surfaceRaised,
        contentTextStyle: t.bodyMedium?.copyWith(color: AppColors.textPrimary),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: const BorderSide(color: AppColors.outline),
        ),
      ),
    );
  }
}
