import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../core/vpn_bridge.dart';
import '../theme/app_theme.dart';

/// Consola de diagnóstico: el mismo registro “tipo Termux” de la APK original
/// ([+] CONNECT…, [ToDus PUT]…), en tipografía mono y con niveles coloreados.
///
/// La lista es inversa (la línea más reciente queda anclada abajo, como una
/// terminal) y el usuario puede desplazarse hacia arriba sin perder la posición.
class LogScreen extends StatelessWidget {
  const LogScreen({super.key, required this.bridge});

  final VpnBridge bridge;

  static final RegExp _linePattern =
      RegExp(r'^\[(\d{2}:\d{2}:\d{2}) (INFO|WARN|ERROR)\] (.*)$', dotAll: true);

  Future<void> _copyAll(BuildContext context, List<String> lines) async {
    await Clipboard.setData(ClipboardData(text: lines.join('\n')));
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('${lines.length} líneas copiadas')),
      );
    }
  }

  Future<void> _confirmClear(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('¿Borrar el registro?'),
        content: const Text(
          'Se elimina el registro en memoria de esta sesión. '
          'Esta acción no se puede deshacer.',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(context).pop(false), child: const Text('Cancelar')),
          FilledButton(onPressed: () => Navigator.of(context).pop(true), child: const Text('Borrar')),
        ],
      ),
    );
    if (confirmed == true) {
      await bridge.clearLog();
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return SafeArea(
      bottom: false,
      child: AnimatedBuilder(
        animation: bridge,
        builder: (context, _) {
          final lines = bridge.snapshot.logLines;
          final hasLines = lines.isNotEmpty;

          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Padding(
                padding: const EdgeInsets.fromLTRB(24, 16, 12, 8),
                child: Row(
                  children: [
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text('Registro', style: theme.textTheme.headlineSmall),
                          const SizedBox(height: 4),
                          Text(
                            hasLines ? '${lines.length} líneas · en vivo' : 'Sin actividad',
                            style: theme.textTheme.bodySmall,
                          ),
                        ],
                      ),
                    ),
                    IconButton(
                      tooltip: 'Copiar registro',
                      onPressed: hasLines ? () => _copyAll(context, lines) : null,
                      icon: const Icon(Icons.content_copy),
                      color: AppColors.textMuted,
                    ),
                    IconButton(
                      tooltip: 'Borrar registro',
                      onPressed: hasLines ? () => _confirmClear(context) : null,
                      icon: const Icon(Icons.delete_sweep_outlined),
                      color: AppColors.textMuted,
                    ),
                  ],
                ),
              ),
              Expanded(
                child: hasLines
                    ? Container(
                        margin: const EdgeInsets.fromLTRB(16, 8, 16, 16),
                        decoration: BoxDecoration(
                          color: theme.colorScheme.surface,
                          borderRadius: BorderRadius.circular(18),
                          border: Border.all(color: theme.colorScheme.outline),
                        ),
                        child: ClipRRect(
                          borderRadius: BorderRadius.circular(18),
                          child: ListView.builder(
                            reverse: true,
                            padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 14),
                            itemCount: lines.length,
                            itemBuilder: (context, index) {
                              final line = lines[lines.length - 1 - index];
                              return _LogLine(line: line, pattern: _linePattern);
                            },
                          ),
                        ),
                      )
                    : const _EmptyLog(),
              ),
            ],
          );
        },
      ),
    );
  }
}

/// Una línea del registro con marca de tiempo y nivel coloreados.
class _LogLine extends StatelessWidget {
  const _LogLine({required this.line, required this.pattern});

  final String line;
  final RegExp pattern;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final match = pattern.firstMatch(line);

    if (match == null) {
      return Padding(
        padding: const EdgeInsets.symmetric(vertical: 1.5),
        child: Text(
          line,
          style: theme.textTheme.bodySmall!.copyWith(fontFamily: kMonoFont, height: 1.5),
        ),
      );
    }

    final time = match.group(1)!;
    final level = match.group(2)!;
    final message = match.group(3)!;
    final Color levelColor;
    switch (level) {
      case 'ERROR':
        levelColor = theme.colorScheme.error;
      case 'WARN':
        levelColor = AppColors.warning;
      default:
        levelColor = theme.colorScheme.primary;
    }

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 1.5),
      child: Text.rich(
        TextSpan(
          children: [
            TextSpan(
              text: '$time ',
              style: const TextStyle(color: AppColors.textMuted),
            ),
            TextSpan(text: level.padRight(5), style: TextStyle(color: levelColor)),
            TextSpan(text: ' $message'),
          ],
        ),
        style: theme.textTheme.bodySmall!.copyWith(fontFamily: kMonoFont, height: 1.5),
      ),
    );
  }
}

/// Estado vacío: explica qué aparecerá aquí y cuándo.
class _EmptyLog extends StatelessWidget {
  const _EmptyLog();

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.receipt_long_outlined, size: 42, color: AppColors.textMuted),
            const SizedBox(height: 14),
            Text('Sin actividad todavía', style: theme.textTheme.titleMedium),
            const SizedBox(height: 6),
            Text(
              'Cuando conectes la VPN, aquí verás el registro técnico '
              '(conexiones SOCKS5, operaciones ToDus PUT/GET y avisos).',
              style: theme.textTheme.bodySmall,
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}
