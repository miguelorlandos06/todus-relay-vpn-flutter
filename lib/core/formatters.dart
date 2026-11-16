/// Formateadores compartidos — mismos criterios que la APK Kotlin original
/// (`formatDuration` y `formatBytes` de la vieja MainActivity).
library;

/// "hh:mm:ss" a partir de milisegundos (igual que la app original).
String formatDuration(int millis) {
  if (millis <= 0) return '00:00:00';
  final totalSeconds = millis ~/ 1000;
  final h = totalSeconds ~/ 3600;
  final m = (totalSeconds % 3600) ~/ 60;
  final s = totalSeconds % 60;
  String two(int v) => v.toString().padLeft(2, '0');
  return '${two(h)}:${two(m)}:${two(s)}';
}

/// "842 B", "12.4 KB", "1.8 MB", "940.05 GB" — igual que la app original.
String formatBytes(num bytes) {
  if (bytes < 1024) {
    return '${bytes.toInt()} B';
  }
  if (bytes < 1024 * 1024) {
    return '${(bytes / 1024).toStringAsFixed(1)} KB';
  }
  if (bytes < 1024 * 1024 * 1024) {
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }
  return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
}

/// Velocidad en bytes/segundo → "1.2 MB/s".
String formatSpeed(double bytesPerSecond) {
  if (bytesPerSecond <= 0) return '0 B/s';
  return '${formatBytes(bytesPerSecond)}/s';
}

/// Número con separador de miles (contadores de datagramas, sesiones…).
String formatCount(num value) {
  if (value < 10000) return value.toInt().toString();
  final digits = value.toInt().toString();
  final buffer = StringBuffer();
  for (var i = 0; i < digits.length; i++) {
    buffer.write(digits[i]);
    final remaining = digits.length - 1 - i;
    if (remaining > 0 && remaining % 3 == 0) {
      buffer.write(' ');
    }
  }
  return buffer.toString();
}
