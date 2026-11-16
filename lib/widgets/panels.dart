import 'package:flutter/material.dart';

import '../theme/app_theme.dart';

/// Cabecera de sección: etiqueta mayúscula, discreta y constante.
class SectionHeader extends StatelessWidget {
  const SectionHeader({super.key, required this.label, this.trailing});

  final String label;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(left: 4, bottom: 10),
      child: Row(
        children: [
          Expanded(
            child: Text(label.toUpperCase(), style: Theme.of(context).textTheme.labelMedium),
          ),
          if (trailing != null) trailing!,
        ],
      ),
    );
  }
}

/// Fila “etiqueta …… valor” con cifras tabulares y divisor fino.
class StatRow extends StatelessWidget {
  const StatRow({
    super.key,
    required this.label,
    required this.value,
    this.emphasis = false,
    this.valueColor,
  });

  final String label;
  final String value;

  /// Fila destacada: valor en tamaño mayor.
  final bool emphasis;

  /// Color opcional del valor (p. ej. fallos en rojo).
  final Color? valueColor;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final valueStyle = emphasis
        ? tabular(theme.textTheme.headlineSmall!.copyWith(fontWeight: FontWeight.w600))
        : tabular(theme.textTheme.titleMedium!.copyWith(fontFamily: kDisplayFont));
    final style = valueColor != null ? valueStyle.copyWith(color: valueColor) : valueStyle;

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 13),
      child: Row(
        children: [
          Expanded(child: Text(label, style: theme.textTheme.bodyMedium)),
          const SizedBox(width: 12),
          Text(value, style: style),
        ],
      ),
    );
  }
}

/// Tarjeta contenedora con borde fino (hairline) y esquinas suaves.
class HairlineCard extends StatelessWidget {
  const HairlineCard({super.key, required this.child, this.padding = EdgeInsets.zero});

  final Widget child;
  final EdgeInsetsGeometry padding;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: padding,
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: Theme.of(context).colorScheme.outline),
      ),
      child: child,
    );
  }
}

/// Divisor fino a ancho completo (dentro de tarjetas).
class HairlineDivider extends StatelessWidget {
  const HairlineDivider({super.key});

  @override
  Widget build(BuildContext context) {
    return const Divider(height: 1, thickness: 1, indent: 16, endIndent: 16);
  }
}
