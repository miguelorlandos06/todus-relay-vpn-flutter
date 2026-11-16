/// Vocabulario visual del estado de la VPN: una sola fuente de verdad para
/// etiquetas, textos de apoyo y colores por estado.
library;

import 'package:flutter/material.dart';

import '../theme/app_theme.dart' show AppColors;
import 'vpn_bridge.dart';

/// Etiqueta corta para el chip de estado.
String vpnStateLabel(VpnState state) {
  switch (state) {
    case VpnState.active:
      return 'Conectado';
    case VpnState.connecting:
      return 'Conectando';
    case VpnState.error:
      return 'Error';
    case VpnState.stopped:
      return 'Sin conectar';
  }
}

/// Palabra grande bajo el orbe.
String vpnStatusWord(VpnState state) {
  switch (state) {
    case VpnState.active:
      return 'Protegido';
    case VpnState.connecting:
      return 'Conectando…';
    case VpnState.error:
      return 'Sin conexión';
    case VpnState.stopped:
      return 'Desconectado';
  }
}

/// Frase de apoyo bajo la palabra grande.
String vpnStatusHint(VpnState state) {
  switch (state) {
    case VpnState.active:
      return 'Todo tu tráfico viaja por el relay ToDus';
    case VpnState.connecting:
      return 'Negociando el túnel con el relay…';
    case VpnState.error:
      return 'No se pudo establecer la VPN';
    case VpnState.stopped:
      return 'Toca el botón para navegar libre';
  }
}

/// Color semántico del estado.
Color vpnStateColor(VpnState state, ColorScheme scheme) {
  switch (state) {
    case VpnState.active:
      return scheme.primary;
    case VpnState.connecting:
      return AppColors.warning;
    case VpnState.error:
      return scheme.error;
    case VpnState.stopped:
      return AppColors.textMuted;
  }
}
