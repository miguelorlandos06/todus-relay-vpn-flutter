package cu.todus.relayvpn.vpn

import java.util.concurrent.atomic.AtomicInteger

/**
 * Utilidades de nivel IP/TCP/UDP: análisis de paquetes que llegan del TUN,
 * construcción de paquetes que se escriben al TUN y checksums correctos
 * (IPv4 de cabecera, pseudo-cabecera para TCP/UDP en IPv4 e IPv6).
 */
object Ip {
    const val MTU = 1500

    const val PROTO_ICMP = 1
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    // Flags TCP
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10

    // ---------------------------------------------------------------- parseo

    class IpPacket(
        val ipv6: Boolean,
        val src: ByteArray,      // 4 u 16 bytes
        val dst: ByteArray,
        val proto: Int,
        val payloadOff: Int,
        val payloadLen: Int,
    )

    class TcpPacket(
        val ip: IpPacket,
        val srcPort: Int,
        val dstPort: Int,
        val seq: Long,
        val ack: Long,
        val flags: Int,
        val window: Int,
        val optionsOff: Int,
        val optionsLen: Int,
        val payloadOff: Int,
        val payloadLen: Int,
    ) {
        val syn: Boolean get() = (flags and SYN) != 0
        val ackFlag: Boolean get() = (flags and ACK) != 0
        val fin: Boolean get() = (flags and FIN) != 0
        val rst: Boolean get() = (flags and RST) != 0
        fun payload(buf: ByteArray): ByteArray = buf.copyOfRange(payloadOff, payloadOff + payloadLen)
    }

    class UdpPacket(
        val ip: IpPacket,
        val srcPort: Int,
        val dstPort: Int,
        val payloadOff: Int,
        val payloadLen: Int,
    ) {
        fun payload(buf: ByteArray): ByteArray = buf.copyOfRange(payloadOff, payloadOff + payloadLen)
    }

    fun u16(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)

    fun u32(buf: ByteArray, off: Int): Long =
        ((buf[off].toInt() and 0xFF).toLong() shl 24) or
            ((buf[off + 1].toInt() and 0xFF).toLong() shl 16) or
            ((buf[off + 2].toInt() and 0xFF).toLong() shl 8) or
            (buf[off + 3].toInt() and 0xFF).toLong()

    fun parseIp(buf: ByteArray, length: Int): IpPacket? {
        if (length < 1) return null
        val version = (buf[0].toInt() and 0xFF) shr 4
        if (version == 4) {
            if (length < 20) return null
            val ihl = (buf[0].toInt() and 0x0F) * 4
            if (ihl < 20 || ihl > length) return null
            val totalLen = u16(buf, 2)
            if (totalLen < ihl || totalLen > length) return null
            val proto = buf[9].toInt() and 0xFF
            val src = buf.copyOfRange(12, 16)
            val dst = buf.copyOfRange(16, 20)
            return IpPacket(false, src, dst, proto, ihl, totalLen - ihl)
        }
        if (version == 6) {
            if (length < 40) return null
            val payloadLen = u16(buf, 4)
            if (40 + payloadLen > length) return null
            var nextHeader = buf[6].toInt() and 0xFF
            var off = 40
            var remaining = if (payloadLen == 0) length - 40 else payloadLen
            // Saltar cabeceras de extensión habituales (hop-by-hop, routing, dest-opts, fragmento).
            var hops = 0
            while (nextHeader == 0 || nextHeader == 43 || nextHeader == 60 || nextHeader == 44) {
                if (hops++ > 8 || remaining < if (nextHeader == 44) 8 else 2) return null
                if (nextHeader == 44) { // fragmento
                    val fragOff = u16(buf, off + 2) and 0x1FFF
                    if (fragOff != 0) return null // fragmento no inicial: descartar
                    nextHeader = buf[off].toInt() and 0xFF
                    remaining -= 8
                    off += 8
                    continue
                }
                val hdrLen = ((buf[off + 1].toInt() and 0xFF) + 1) * 8
                if (remaining < hdrLen) return null
                nextHeader = buf[off].toInt() and 0xFF
                remaining -= hdrLen
                off += hdrLen
            }
            val src = buf.copyOfRange(8, 24)
            val dst = buf.copyOfRange(24, 40)
            if (nextHeader != PROTO_TCP && nextHeader != PROTO_UDP) return null
            return IpPacket(true, src, dst, nextHeader, off, remaining)
        }
        return null
    }

    fun parseTcp(ip: IpPacket, buf: ByteArray): TcpPacket? {
        val off = ip.payloadOff
        val end = off + ip.payloadLen
        if (ip.payloadLen < 20 || end > buf.size) return null
        val srcPort = u16(buf, off)
        val dstPort = u16(buf, off + 2)
        val seq = u32(buf, off + 4)
        val ack = u32(buf, off + 8)
        val dataOffset = ((buf[off + 12].toInt() and 0xF0) shr 4) * 4
        if (dataOffset < 20 || off + dataOffset > end) return null
        val flags = buf[off + 13].toInt() and 0xFF
        val window = u16(buf, off + 14)
        val payloadOff = off + dataOffset
        val payloadLen = end - payloadOff
        if (payloadLen < 0) return null
        return TcpPacket(
            ip = ip,
            srcPort = srcPort,
            dstPort = dstPort,
            seq = seq,
            ack = ack,
            flags = flags,
            window = window,
            optionsOff = off + 20,
            optionsLen = dataOffset - 20,
            payloadOff = payloadOff,
            payloadLen = payloadLen,
        )
    }

    fun parseUdp(ip: IpPacket, buf: ByteArray): UdpPacket? {
        val off = ip.payloadOff
        val end = off + ip.payloadLen
        if (ip.payloadLen < 8 || end > buf.size) return null
        val srcPort = u16(buf, off)
        val dstPort = u16(buf, off + 2)
        val lengthField = u16(buf, off + 4)
        if (lengthField < 8 || off + lengthField > end) return null
        return UdpPacket(ip, srcPort, dstPort, off + 8, lengthField - 8)
    }

    // ---------------------------------------------------------------- checksums

    fun checksum(buf: ByteArray, from: Int, to: Int): Int {
        var sum = 0L
        var i = from
        while (i + 1 < to) {
            sum += (((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        if (i < to) {
            sum += ((buf[i].toInt() and 0xFF) shl 8).toLong()
        }
        while ((sum shr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.toInt().inv() and 0xFFFF)
    }

    /**
     * Checksum de pseudo-cabecera + segmento TCP/UDP. `segOff`/`segEnd` delimitan el
     * segmento dentro de `buf` (el checksum dentro del segmento debe ir en 0 al llamar).
     */
    fun transportChecksum(
        ipv6: Boolean, src: ByteArray, dst: ByteArray, proto: Int,
        buf: ByteArray, segOff: Int, segEnd: Int,
    ): Int {
        var sum = 0L

        fun addByteArray(bytes: ByteArray) {
            var i = 0
            while (i + 1 < bytes.size) {
                sum += (((bytes[i].toInt() and 0xFF) shl 8) or (bytes[i + 1].toInt() and 0xFF)).toLong()
                i += 2
            }
            if (i < bytes.size) sum += ((bytes[i].toInt() and 0xFF) shl 8).toLong()
        }

        addByteArray(src)
        addByteArray(dst)

        val segLen = segEnd - segOff
        if (!ipv6) {
            // IPv4: cero(8) + proto(8) + longitud(16), como palabras de 16 bits.
            sum += (proto and 0xFF).toLong()
            sum += (segLen and 0xFFFF).toLong()
        } else {
            // IPv6: longitud de 32 bits + ceros(24) + siguiente cabecera(8).
            sum += ((segLen shr 16) and 0xFFFF).toLong()
            sum += (segLen and 0xFFFF).toLong()
            sum += (proto and 0xFF).toLong()
        }

        var i = segOff
        while (i + 1 < segEnd) {
            sum += (((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        if (i < segEnd) {
            sum += ((buf[i].toInt() and 0xFF) shl 8).toLong()
        }

        while ((sum shr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.toInt().inv() and 0xFFFF)
    }

    // ---------------------------------------------------------------- construcción

    private val ipId = AtomicInteger(0x1337)

    fun nextIpId(): Int = ipId.incrementAndGet() and 0xFFFF

    /**
     * Escribe la cabecera TCP (20 + opciones) desde la posición `off` de `out`.
     * Layout RFC 793: sport(2) dport(2) seq(4) ack(4) offset(1) flags(1) window(2) checksum(2) urgent(2).
     */
    fun writeTcpHeader(
        out: ByteArray, off: Int, sport: Int, dport: Int, seq: Long, ack: Long,
        flags: Int, window: Int, options: ByteArray?,
    ) {
        val optLen = options?.size ?: 0
        out[off] = (sport shr 8).toByte()
        out[off + 1] = sport.toByte()
        out[off + 2] = (dport shr 8).toByte()
        out[off + 3] = dport.toByte()
        out[off + 4] = ((seq shr 24) and 0xFF).toByte()
        out[off + 5] = ((seq shr 16) and 0xFF).toByte()
        out[off + 6] = ((seq shr 8) and 0xFF).toByte()
        out[off + 7] = (seq and 0xFF).toByte()
        out[off + 8] = ((ack shr 24) and 0xFF).toByte()
        out[off + 9] = ((ack shr 16) and 0xFF).toByte()
        out[off + 10] = ((ack shr 8) and 0xFF).toByte()
        out[off + 11] = (ack and 0xFF).toByte()
        out[off + 12] = (((20 + optLen) / 4 shl 4)).toByte()
        out[off + 13] = flags.toByte()
        out[off + 14] = (window shr 8).toByte()
        out[off + 15] = window.toByte()
        out[off + 16] = 0
        out[off + 17] = 0
        out[off + 18] = 0
        out[off + 19] = 0
        if (optLen > 0) {
            System.arraycopy(options!!, 0, out, off + 20, optLen)
        }
    }

    /** Construye el paquete IP+TCP completo hacia el dispositivo (nosotros somos el "remoto"). */
    fun buildTcpPacket(
        ipv6: Boolean, src: ByteArray, dst: ByteArray,
        sport: Int, dport: Int, seq: Long, ack: Long,
        flags: Int, window: Int, options: ByteArray?, payload: ByteArray?,
    ): ByteArray {
        val optLen = options?.size ?: 0
        val payloadLen = payload?.size ?: 0
        val tcpLen = 20 + optLen + payloadLen
        val ipHeaderLen = if (ipv6) 40 else 20
        val packet = ByteArray(ipHeaderLen + tcpLen)
        writeTcpHeader(packet, ipHeaderLen, sport, dport, seq, ack, flags, window, options)
        if (payloadLen > 0) {
            System.arraycopy(payload!!, 0, packet, ipHeaderLen + 20 + optLen, payloadLen)
        }

        val tsum = transportChecksum(ipv6, src, dst, PROTO_TCP, packet, ipHeaderLen, ipHeaderLen + tcpLen)
        packet[ipHeaderLen + 16] = (tsum shr 8).toByte()
        packet[ipHeaderLen + 17] = tsum.toByte()

        if (!ipv6) {
            val totalLen = ipHeaderLen + tcpLen
            packet[0] = 0x45
            packet[1] = 0
            packet[2] = (totalLen shr 8).toByte()
            packet[3] = totalLen.toByte()
            val id = nextIpId()
            packet[4] = (id shr 8).toByte()
            packet[5] = id.toByte()
            packet[6] = 0x40 // DF
            packet[7] = 0
            packet[8] = 64
            packet[9] = PROTO_TCP.toByte()
            packet[10] = 0
            packet[11] = 0
            System.arraycopy(src, 0, packet, 12, 4)
            System.arraycopy(dst, 0, packet, 16, 4)
            val isum = checksum(packet, 0, 20)
            packet[10] = (isum shr 8).toByte()
            packet[11] = isum.toByte()
        } else {
            packet[0] = (6 shl 4).toByte()
            packet[4] = (tcpLen shr 8).toByte()
            packet[5] = tcpLen.toByte()
            packet[6] = PROTO_TCP.toByte()
            packet[7] = 64
            System.arraycopy(src, 0, packet, 8, 16)
            System.arraycopy(dst, 0, packet, 24, 16)
        }
        return packet
    }

    /** Construye el paquete IP+UDP completo hacia el dispositivo. */
    fun buildUdpPacket(
        ipv6: Boolean, src: ByteArray, dst: ByteArray,
        sport: Int, dport: Int, payload: ByteArray,
    ): ByteArray {
        val udpLen = 8 + payload.size
        val ipHeaderLen = if (ipv6) 40 else 20
        val packet = ByteArray(ipHeaderLen + udpLen)
        packet[ipHeaderLen] = (sport shr 8).toByte()
        packet[ipHeaderLen + 1] = sport.toByte()
        packet[ipHeaderLen + 2] = (dport shr 8).toByte()
        packet[ipHeaderLen + 3] = dport.toByte()
        packet[ipHeaderLen + 4] = (udpLen shr 8).toByte()
        packet[ipHeaderLen + 5] = udpLen.toByte()
        packet[ipHeaderLen + 6] = 0
        packet[ipHeaderLen + 7] = 0
        System.arraycopy(payload, 0, packet, ipHeaderLen + 8, payload.size)
        val usum = transportChecksum(ipv6, src, dst, PROTO_UDP, packet, ipHeaderLen, ipHeaderLen + udpLen)
        packet[ipHeaderLen + 6] = (usum shr 8).toByte()
        packet[ipHeaderLen + 7] = usum.toByte()

        if (!ipv6) {
            val totalLen = ipHeaderLen + udpLen
            packet[0] = 0x45
            packet[1] = 0
            packet[2] = (totalLen shr 8).toByte()
            packet[3] = totalLen.toByte()
            val id = nextIpId()
            packet[4] = (id shr 8).toByte()
            packet[5] = id.toByte()
            packet[6] = 0x40 // DF
            packet[7] = 0
            packet[8] = 64
            packet[9] = PROTO_UDP.toByte()
            packet[10] = 0
            packet[11] = 0
            System.arraycopy(src, 0, packet, 12, 4)
            System.arraycopy(dst, 0, packet, 16, 4)
            val isum = checksum(packet, 0, 20)
            packet[10] = (isum shr 8).toByte()
            packet[11] = isum.toByte()
        } else {
            packet[0] = (6 shl 4).toByte()
            packet[4] = (udpLen shr 8).toByte()
            packet[5] = udpLen.toByte()
            packet[6] = PROTO_UDP.toByte()
            packet[7] = 64
            System.arraycopy(src, 0, packet, 8, 16)
            System.arraycopy(dst, 0, packet, 24, 16)
        }
        return packet
    }
}
