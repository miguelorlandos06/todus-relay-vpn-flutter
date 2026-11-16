import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../core/vpn_bridge.dart';
import '../core/vpn_ui.dart';
import '../theme/app_theme.dart';

/// Botón principal de conexión.
///
/// Un solo control grande (Operate) que concentra el estado de la VPN:
/// - Parado: aro apagado, sin brillo.
/// - Conectando: arco giratorio ámbar sobre el aro exterior.
/// - Conectado: respiración lenta del halo teal (señal de vida, no teatro).
/// - Error: halo rojo tenue y constante.
///
/// Respeta “quitar animaciones” del sistema: sin bucles, colores planos.
class ConnectOrb extends StatefulWidget {
  const ConnectOrb({
    super.key,
    required this.state,
    required this.onPressed,
    required this.size,
  });

  final VpnState state;
  final VoidCallback onPressed;
  final double size;

  @override
  State<ConnectOrb> createState() => _ConnectOrbState();
}

class _ConnectOrbState extends State<ConnectOrb>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;
  bool _pressed = false;
  bool _reduceMotion = false;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 2600),
    );
    _configureAnimation();
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final reduceMotion = MediaQuery.of(context).disableAnimations;
    if (reduceMotion != _reduceMotion) {
      _reduceMotion = reduceMotion;
      _configureAnimation();
    }
  }

  @override
  void didUpdateWidget(ConnectOrb oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.state != widget.state) {
      _configureAnimation();
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _configureAnimation() {
    switch (widget.state) {
      case VpnState.active:
        _controller.duration = const Duration(milliseconds: 2600);
        _reduceMotion ? _controller.stop() : _controller.repeat(reverse: true);
      case VpnState.connecting:
        _controller.duration = const Duration(milliseconds: 1300);
        _reduceMotion ? _controller.stop() : _controller.repeat();
      case VpnState.error:
      case VpnState.stopped:
        _controller
          ..stop()
          ..value = 0;
    }
  }

  void _handleTap() {
    HapticFeedback.mediumImpact();
    widget.onPressed();
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final stateColor = vpnStateColor(widget.state, scheme);
    final animate = !_reduceMotion;

    return Semantics(
      button: true,
      label: _semanticLabel(),
      value: vpnStateLabel(widget.state),
      child: GestureDetector(
        onTap: _handleTap,
        onTapDown: (_) => setState(() => _pressed = true),
        onTapUp: (_) => setState(() => _pressed = false),
        onTapCancel: () => setState(() => _pressed = false),
        child: AnimatedScale(
          scale: _pressed ? 0.96 : 1.0,
          duration: animate ? const Duration(milliseconds: 130) : Duration.zero,
          curve: Curves.easeOut,
          child: AnimatedBuilder(
            animation: _controller,
            builder: (context, _) {
              final t = _controller.value;
              return SizedBox(
                width: widget.size,
                height: widget.size,
                child: Stack(
                  alignment: Alignment.center,
                  children: [
                    // Aro exterior (marcador del dial).
                    Container(
                      width: widget.size,
                      height: widget.size,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        border: Border.all(
                          color: _dialColor(stateColor, t, animate),
                          width: 1.2,
                        ),
                      ),
                    ),
                    // Arco giratorio mientras conecta.
                    if (widget.state == VpnState.connecting)
                      Positioned.fill(
                        child: CustomPaint(
                          painter: _ArcPainter(progress: animate ? t : 0.25, color: stateColor),
                        ),
                      ),
                    // Botón principal.
                    Container(
                      width: widget.size * 0.84,
                      height: widget.size * 0.84,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: AppColors.surfaceRaised,
                        border: Border.all(
                          color: _ringColor(stateColor, t, animate),
                          width: 1.6,
                        ),
                        boxShadow: _glow(stateColor, t, animate),
                      ),
                      child: Center(
                        child: Icon(
                          Icons.power_settings_new,
                          size: widget.size * 0.30,
                          color: _iconColor(stateColor),
                        ),
                      ),
                    ),
                  ],
                ),
              );
            },
          ),
        ),
      ),
    );
  }

  String _semanticLabel() {
    switch (widget.state) {
      case VpnState.active:
      case VpnState.connecting:
        return 'Desconectar la VPN';
      case VpnState.error:
      case VpnState.stopped:
        return 'Conectar la VPN';
    }
  }

  Color _dialColor(Color stateColor, double t, bool animate) {
    switch (widget.state) {
      case VpnState.active:
        final base = animate ? 0.30 + 0.25 * t : 0.45;
        return stateColor.withValues(alpha: base);
      case VpnState.connecting:
        return stateColor.withValues(alpha: animate ? 0.30 + 0.20 * t : 0.4);
      case VpnState.error:
        return stateColor.withValues(alpha: 0.35);
      case VpnState.stopped:
        return AppColors.outline;
    }
  }

  Color _ringColor(Color stateColor, double t, bool animate) {
    switch (widget.state) {
      case VpnState.active:
        return stateColor.withValues(alpha: animate ? 0.75 + 0.25 * t : 1.0);
      case VpnState.connecting:
        return stateColor.withValues(alpha: 0.9);
      case VpnState.error:
        return stateColor.withValues(alpha: 0.8);
      case VpnState.stopped:
        return AppColors.outline;
    }
  }

  Color _iconColor(Color stateColor) {
    switch (widget.state) {
      case VpnState.stopped:
        return AppColors.textMuted;
      case VpnState.active:
      case VpnState.connecting:
      case VpnState.error:
        return stateColor;
    }
  }

  List<BoxShadow> _glow(Color stateColor, double t, bool animate) {
    switch (widget.state) {
      case VpnState.active:
        final alpha = animate ? 0.16 + 0.14 * t : 0.22;
        return <BoxShadow>[
          BoxShadow(
            color: stateColor.withValues(alpha: alpha),
            blurRadius: 44 + (animate ? 20 * t : 0),
            spreadRadius: 2,
          ),
        ];
      case VpnState.connecting:
        return <BoxShadow>[
          BoxShadow(
            color: stateColor.withValues(alpha: 0.14),
            blurRadius: 34,
            spreadRadius: 1,
          ),
        ];
      case VpnState.error:
        return <BoxShadow>[
          BoxShadow(
            color: stateColor.withValues(alpha: 0.12),
            blurRadius: 30,
            spreadRadius: 1,
          ),
        ];
      case VpnState.stopped:
        return const <BoxShadow>[];
    }
  }
}

/// Arco de progreso giratorio (estado “conectando”).
class _ArcPainter extends CustomPainter {
  _ArcPainter({required this.progress, required this.color});

  final double progress;
  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    final rect = Offset.zero & size;
    final paint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2.6
      ..strokeCap = StrokeCap.round
      ..color = color.withValues(alpha: 0.9);
    final start = -math.pi / 2 + progress * 2 * math.pi;
    canvas.drawArc(rect.deflate(1.3), start, 1.45 * math.pi, false, paint);
  }

  @override
  bool shouldRepaint(_ArcPainter oldDelegate) =>
      oldDelegate.progress != progress || oldDelegate.color != color;
}
