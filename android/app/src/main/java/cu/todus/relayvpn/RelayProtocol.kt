package cu.todus.relayvpn

import org.json.JSONObject
import java.nio.ByteBuffer
import java.util.Locale
import java.util.zip.CRC32

/**
 * Puerto fiel de MOBILE/relay_protocol.py — protocolo binario común.
 *
 * Formatos (idénticos al Python, big-endian, sin alineación):
 *  - Frame TCP  : "TDV2"(4) version(1) sequence(8) length(4) crc32(4) = 21 bytes de cabecera + payload.
 *  - Lote UDP   : "TDU2"(4) version(1) sequence(8) count(2) = 15 bytes de cabecera;
 *                 ítem: port(2) atyp(1) hostLen(1) payloadLen(4) = 8 bytes + host + payload.
 *  - Contadores : ASCII decimal.
 *  - Objetivo   : JSON compacto con el mismo orden de campos que json.dumps() de Python.
 *
 * Las claves de objeto deben coincidir exactamente con las de la VPS.
 */
object RelayProtocol {
    private val MAGIC = byteArrayOf(0x54, 0x44, 0x56, 0x32) // "TDV2"
    private const val VERSION = 2
    const val FRAME_HEADER_SIZE = 21

    private val UDP_MAGIC = byteArrayOf(0x54, 0x44, 0x55, 0x32) // "TDU2"
    private const val UDP_VERSION = 1
    const val UDP_BATCH_HEADER_SIZE = 15
    const val UDP_ITEM_HEADER_SIZE = 8

    const val UDP_MAX_PACKET_SIZE_LIMIT = 65507

    class ProtocolException(message: String) : Exception(message)

    // ---------------------------------------------------------------- claves

    fun queueKey(slot: Int = 0): String = if (slot <= 0) "_v2_queue.txt" else "_v2_queue_$slot.txt"

    fun targetKey(sessionId: String): String = "_v2_target_$sessionId.json"

    fun statusKey(sessionId: String): String = "_v2_status_$sessionId.json"

    fun closeKey(sessionId: String): String = "_v2_close_$sessionId.txt"

    fun dataKey(direction: String, sessionId: String, sequence: Long): String {
        require(direction == "c2s" || direction == "s2c") { "dirección inválida" }
        return "_v2_${direction}_${sessionId}_${"%016d".format(sequence)}.bin"
    }

    fun udpDataKey(direction: String, sessionId: String, sequence: Long): String {
        require(direction == "c2s" || direction == "s2c") { "dirección inválida" }
        return "_v2_udp_${direction}_${sessionId}_${"%016d".format(sequence)}.bin"
    }

    fun ackKey(direction: String, sessionId: String): String {
        require(direction == "c2s" || direction == "s2c") { "dirección inválida" }
        return "_v2_ack_${direction}_$sessionId.txt"
    }

    fun finKey(direction: String, sessionId: String): String {
        require(direction == "c2s" || direction == "s2c") { "dirección inválida" }
        return "_v2_fin_${direction}_$sessionId.txt"
    }

    // ---------------------------------------------------------------- frames TCP

    fun encodeFrame(sequence: Long, payload: ByteArray): ByteArray {
        if (sequence < 0) throw ProtocolException("secuencia negativa")
        val crc = CRC32()
        crc.update(payload)
        val out = ByteArray(FRAME_HEADER_SIZE + payload.size)
        val buffer = ByteBuffer.wrap(out)
        buffer.put(MAGIC)
        buffer.put(VERSION.toByte())
        buffer.putLong(sequence)
        buffer.putInt(payload.size)
        buffer.putInt((crc.value and 0xFFFFFFFFL).toInt())
        System.arraycopy(payload, 0, out, FRAME_HEADER_SIZE, payload.size)
        return out
    }

    fun decodeFrame(raw: ByteArray, expectedSequence: Long): ByteArray {
        if (raw.size < FRAME_HEADER_SIZE) throw ProtocolException("fragmento truncado: falta cabecera")
        val buffer = ByteBuffer.wrap(raw, 0, FRAME_HEADER_SIZE)
        val magic = ByteArray(4)
        buffer.get(magic)
        val version = buffer.get().toInt() and 0xFF
        val sequence = buffer.long
        val length = buffer.int
        val checksum = buffer.int.toLong() and 0xFFFFFFFFL
        if (!magic.contentEquals(MAGIC) || version != VERSION) {
            throw ProtocolException("versión o firma del protocolo incorrecta")
        }
        if (sequence != expectedSequence) {
            throw ProtocolException("secuencia inesperada: $sequence, se esperaba $expectedSequence")
        }
        val payload = raw.copyOfRange(FRAME_HEADER_SIZE, raw.size)
        if (length != payload.size) throw ProtocolException("longitud del fragmento incorrecta")
        val crc = CRC32()
        crc.update(payload)
        if ((crc.value and 0xFFFFFFFFL) != checksum) throw ProtocolException("CRC32 incorrecto")
        return payload
    }

    // ---------------------------------------------------------------- lotes UDP

    class UdpRecord(val host: String, val port: Int, val payload: ByteArray)

    private fun encodeHost(host: String): Pair<Int, ByteArray> {
        val trimmed = host.trim()
        if (trimmed.isEmpty()) throw ProtocolException("destino UDP vacío")
        val ip = parseIpAddress(trimmed)
        if (ip != null) {
            return (if (ip.size == 4) 1 else 4) to ip
        }
        val encoded = trimmed.toByteArray(Charsets.UTF_8) // hostnames ASCII/IDNA
        if (encoded.size !in 1..255) throw ProtocolException("hostname UDP demasiado largo")
        return 3 to encoded
    }

    private fun decodeHost(atyp: Int, raw: ByteArray): String {
        when (atyp) {
            1 -> if (raw.size == 4) return raw.joinToString(".") { (it.toInt() and 0xFF).toString() }
            4 -> if (raw.size == 16) {
                // Dirección IPv6 canónica en minúsculas, como ipaddress.IPv6Address.
                val groups = IntArray(8)
                for (i in 0 until 8) {
                    groups[i] = ((raw[i * 2].toInt() and 0xFF) shl 8) or (raw[i * 2 + 1].toInt() and 0xFF)
                }
                return formatIpv6(groups)
            }
            3 -> if (raw.size in 1..255) return String(raw, Charsets.UTF_8)
        }
        throw ProtocolException("ATYP o longitud de destino UDP incorrectos")
    }

    private fun formatIpv6(groups: IntArray): String {
        // Compresión del tramo de ceros más largo (>= 2), como ipaddress.IPv6Address.
        var bestStart = -1
        var bestLen = 0
        var runStart = -1
        for (i in groups.indices) {
            if (groups[i] == 0) {
                if (runStart < 0) runStart = i
                val len = i - runStart + 1
                if (len > bestLen) {
                    bestLen = len
                    bestStart = runStart
                }
            } else {
                runStart = -1
            }
        }
        if (bestLen < 2) {
            return groups.joinToString(":") { String.format("%x", it) }
        }
        val left = groups.copyOfRange(0, bestStart)
        val right = groups.copyOfRange(bestStart + bestLen, groups.size)
        val leftStr = left.joinToString(":") { String.format("%x", it) }
        val rightStr = right.joinToString(":") { String.format("%x", it) }
        return leftStr + "::" + rightStr
    }

    /** Convierte una cadena IP literal (v4/v6) a bytes; null si no es IP. */
    fun parseIpAddress(text: String): ByteArray? {
        val value = text.trim()
        if (value.isEmpty()) return null
        if (value.contains(':')) return parseIpv6(value)
        if (!value.contains('.')) return null
        val parts = value.split(".")
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for (i in 0 until 4) {
            val part = parts[i]
            if (part.isEmpty() || part.length > 3) return null
            val n = part.toIntOrNull() ?: return null
            if (n < 0 || n > 255 || (part.length > 1 && part[0] == '0')) return null
            out[i] = n.toByte()
        }
        return out
    }

    private fun parseIpv6(text: String): ByteArray? {
        val s = text.trim().removePrefix("[").removeSuffix("]")
        if (s.isEmpty()) return null
        val doubleColon = s.indexOf("::")
        if (doubleColon >= 0 && s.indexOf("::", doubleColon + 1) >= 0) return null
        val leftPart: String
        val rightPart: String
        if (doubleColon >= 0) {
            leftPart = s.substring(0, doubleColon)
            rightPart = s.substring(doubleColon + 2)
        } else {
            leftPart = s
            rightPart = ""
        }
        // Un IPv4 embebido solo puede aparecer como último token de la parte derecha (o de toda la dirección).
        val leftGroups = parseIpv6Groups(leftPart, allowV4Tail = doubleColon < 0) ?: return null
        val rightGroups = parseIpv6Groups(rightPart, allowV4Tail = true) ?: return null
        if (doubleColon < 0) {
            if (leftGroups.size != 8) return null
        } else if (leftGroups.size + rightGroups.size > 7) {
            return null
        }
        val out = ByteArray(16)
        var index = 0
        for (g in leftGroups) {
            out[index++] = (g shr 8).toByte(); out[index++] = g.toByte()
        }
        index = 16 - rightGroups.size * 2
        for (g in rightGroups) {
            out[index++] = (g shr 8).toByte(); out[index++] = g.toByte()
        }
        return out
    }

    private fun parseIpv6Groups(part: String, allowV4Tail: Boolean): List<Int>? {
        if (part.isEmpty()) return emptyList()
        val tokens = part.split(":")
        val groups = ArrayList<Int>(8)
        for ((i, token) in tokens.withIndex()) {
            if (token.isEmpty()) return null
            val isLast = i == tokens.size - 1
            if (token.contains('.')) {
                if (!isLast || !allowV4Tail) return null
                val v4 = parseIpAddress(token) ?: return null
                groups.add(((v4[0].toInt() and 0xFF) shl 8) or (v4[1].toInt() and 0xFF))
                groups.add(((v4[2].toInt() and 0xFF) shl 8) or (v4[3].toInt() and 0xFF))
            } else {
                if (token.length > 4) return null
                val v = token.toIntOrNull(16) ?: return null
                if (v < 0 || v > 0xFFFF) return null
                groups.add(v)
            }
        }
        return groups
    }

    fun encodeUdpBatch(sequence: Long, items: List<UdpRecord>): ByteArray {
        if (sequence < 0) throw ProtocolException("secuencia UDP negativa")
        if (items.isEmpty() || items.size > 65535) {
            throw ProtocolException("lote UDP vacío o demasiado grande")
        }
        var total = UDP_BATCH_HEADER_SIZE
        for (item in items) {
            val (_, hostBytes) = encodeHost(item.host)
            total += UDP_ITEM_HEADER_SIZE + hostBytes.size + item.payload.size
        }
        val out = ByteArray(total)
        val buffer = ByteBuffer.wrap(out)
        buffer.put(UDP_MAGIC)
        buffer.put(UDP_VERSION.toByte())
        buffer.putLong(sequence)
        buffer.putShort(items.size.toShort())
        for (item in items) {
            val port = item.port
            if (port !in 1..65535) throw ProtocolException("puerto UDP no válido")
            val payload = item.payload
            if (payload.size > UDP_MAX_PACKET_SIZE_LIMIT) {
                throw ProtocolException("datagrama UDP supera el máximo IPv4")
            }
            val (atyp, hostBytes) = encodeHost(item.host)
            buffer.putShort(port.toShort())
            buffer.put(atyp.toByte())
            // Longitud de host: un solo byte (B) igual que el struct "!HBBI" de Python.
            buffer.put(hostBytes.size.toByte())
            buffer.putInt(payload.size)
            buffer.put(hostBytes)
            buffer.put(payload)
        }
        return out
    }

    fun decodeUdpBatch(raw: ByteArray, expectedSequence: Long): List<UdpRecord> {
        if (raw.size < UDP_BATCH_HEADER_SIZE) throw ProtocolException("lote UDP truncado")
        val buffer = ByteBuffer.wrap(raw, 0, UDP_BATCH_HEADER_SIZE)
        val magic = ByteArray(4)
        buffer.get(magic)
        val version = buffer.get().toInt() and 0xFF
        val sequence = buffer.long
        val count = buffer.short.toInt() and 0xFFFF
        if (!magic.contentEquals(UDP_MAGIC) || version != UDP_VERSION) {
            throw ProtocolException("versión o firma del lote UDP incorrecta")
        }
        if (sequence != expectedSequence) {
            throw ProtocolException("secuencia UDP inesperada: $sequence, se esperaba $expectedSequence")
        }
        if (count == 0) throw ProtocolException("lote UDP sin datagramas")
        val records = ArrayList<UdpRecord>(count)
        var offset = UDP_BATCH_HEADER_SIZE
        for (i in 0 until count) {
            if (raw.size - offset < UDP_ITEM_HEADER_SIZE) {
                throw ProtocolException("cabecera de datagrama UDP truncada")
            }
            val port = ((raw[offset].toInt() and 0xFF) shl 8) or (raw[offset + 1].toInt() and 0xFF)
            val atyp = raw[offset + 2].toInt() and 0xFF
            val hostLen = raw[offset + 3].toInt() and 0xFF
            val payloadLen = ((raw[offset + 4].toInt() and 0xFF) shl 24) or
                ((raw[offset + 5].toInt() and 0xFF) shl 16) or
                ((raw[offset + 6].toInt() and 0xFF) shl 8) or
                (raw[offset + 7].toInt() and 0xFF)
            val hostStart = offset + UDP_ITEM_HEADER_SIZE
            val payloadStart = hostStart + hostLen
            val payloadEnd = payloadStart + payloadLen
            if (payloadEnd > raw.size) throw ProtocolException("datagrama UDP truncado")
            val host = decodeHost(atyp, raw.copyOfRange(hostStart, payloadStart))
            val payload = raw.copyOfRange(payloadStart, payloadEnd)
            if (port !in 1..65535 || payloadLen > UDP_MAX_PACKET_SIZE_LIMIT) {
                throw ProtocolException("puerto o tamaño de datagrama UDP no válido")
            }
            records.add(UdpRecord(host, port, payload))
            offset = payloadEnd
        }
        if (offset != raw.size) {
            throw ProtocolException("datos sobrantes al final del lote UDP")
        }
        return records
    }

    // ---------------------------------------------------------------- JSON y contadores

    /**
     * Equivalente a json.dumps({"version":2,"mode":..,"host":..,"port":..,"created":..},
     * separators=(",",":"), ensure_ascii=False).encode("utf-8").
     */
    fun encodeTargetJson(mode: String, host: String?, port: Int?, createdSeconds: Double): ByteArray {
        val sb = StringBuilder()
        sb.append("{\"version\":2,\"mode\":").append(jsonString(mode))
        if (host != null) sb.append(",\"host\":").append(jsonString(host))
        if (port != null) sb.append(",\"port\":").append(port)
        sb.append(",\"created\":")
        sb.append(String.format(Locale.US, "%.6f", createdSeconds))
        sb.append("}")
        return sb.toString().toByteArray(Charsets.UTF_8)
    }

    private fun jsonString(value: String): String {
        val sb = StringBuilder("\"")
        for (ch in value) {
            when {
                ch == '"' -> sb.append("\\\"")
                ch == '\\' -> sb.append("\\\\")
                ch < ' ' -> sb.append(String.format("\\u%04x", ch.code))
                else -> sb.append(ch)
            }
        }
        sb.append("\"")
        return sb.toString()
    }

    /** Estado de la VPS: {"state": "ready"|"error", "message": .., "time": ..}. */
    fun decodeStatus(raw: ByteArray): JSONObject = JSONObject(String(raw, Charsets.UTF_8))

    fun encodeCounter(value: Long): ByteArray =
        maxOf(0L, value).toString().toByteArray(Charsets.US_ASCII)

    fun decodeCounter(raw: ByteArray?): Long {
        if (raw == null || raw.isEmpty()) return 0
        return try {
            maxOf(0L, String(raw, Charsets.US_ASCII).trim().toLong())
        } catch (e: NumberFormatException) {
            0
        }
    }
}
