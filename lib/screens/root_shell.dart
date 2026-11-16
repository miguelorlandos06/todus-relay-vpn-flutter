import 'package:flutter/material.dart';

import '../core/vpn_bridge.dart';
import 'home_screen.dart';
import 'log_screen.dart';
import 'stats_screen.dart';

/// Contenedor de las tres pestañas (Inicio · Datos · Registro).
///
/// IndexedStack mantiene vivas las pantallas para no perder la posición del
/// registro ni las estadísticas al cambiar de pestaña.
class RootShell extends StatefulWidget {
  const RootShell({super.key, required this.bridge});

  final VpnBridge bridge;

  @override
  State<RootShell> createState() => _RootShellState();
}

class _RootShellState extends State<RootShell> {
  int _index = 0;

  @override
  Widget build(BuildContext context) {
    final screens = <Widget>[
      HomeScreen(bridge: widget.bridge),
      StatsScreen(bridge: widget.bridge),
      LogScreen(bridge: widget.bridge),
    ];

    return Scaffold(
      body: IndexedStack(index: _index, children: screens),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _index,
        onDestinationSelected: (value) => setState(() => _index = value),
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.shield_outlined),
            selectedIcon: Icon(Icons.shield),
            label: 'Inicio',
          ),
          NavigationDestination(
            icon: Icon(Icons.bar_chart_outlined),
            selectedIcon: Icon(Icons.bar_chart),
            label: 'Datos',
          ),
          NavigationDestination(
            icon: Icon(Icons.receipt_long_outlined),
            selectedIcon: Icon(Icons.receipt_long),
            label: 'Registro',
          ),
        ],
      ),
    );
  }
}
