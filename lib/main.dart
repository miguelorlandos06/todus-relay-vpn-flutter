import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'core/vpn_bridge.dart';
import 'screens/root_shell.dart';
import 'theme/app_theme.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: Brightness.light,
      statusBarBrightness: Brightness.dark,
      systemNavigationBarColor: AppColors.surface,
      systemNavigationBarIconBrightness: Brightness.light,
    ),
  );
  SystemChrome.setPreferredOrientations(<DeviceOrientation>[
    DeviceOrientation.portraitUp,
  ]);
  final bridge = VpnBridge()..start();
  runApp(ToDusVpnApp(bridge: bridge));
}

/// Raíz de la app: tema oscuro + shell con pestañas.
class ToDusVpnApp extends StatefulWidget {
  const ToDusVpnApp({super.key, required this.bridge});

  /// Puente con el núcleo Kotlin. En producción lo crea `main()`; las pruebas
  /// pueden inyectar uno controlado.
  final VpnBridge bridge;

  @override
  State<ToDusVpnApp> createState() => _ToDusVpnAppState();
}

class _ToDusVpnAppState extends State<ToDusVpnApp> {
  @override
  void dispose() {
    widget.bridge.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'ToDus VPN',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.dark(),
      home: RootShell(bridge: widget.bridge),
    );
  }
}
