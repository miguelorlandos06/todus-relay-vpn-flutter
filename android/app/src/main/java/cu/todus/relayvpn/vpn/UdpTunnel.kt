package cu.todus.relayvpn.vpn

import cu.todus.relayvpn.AppLog
import java.io.IOException
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

/**
 * Túnel UDP del TUN hacia el SOCKS5 local:
 *  - Abre UNA asociación UDP ASSOCIATE contra 127.0.0.1:SOCKS_PORT (igual que
 *    haría Telegram con el script de Termux) y envía todos los datagramas del
 *    dispositivo con la cabecera SOCKS5 (RSV/FRAG/ATYP/dst/puerto).
 *  - Las respuestas llegan envueltas igual y se demultiplexan por (origen remoto)
 *    hacia cada socket local del dispositivo que escribió a ese destino.
 *  - El QUIC/UDP/443 pasa sin modificar (pass-through), igual que en MOBILE.
 *  - Si la asociación muere (idle en la VPS o cierre del control), se detecta y
 *    se reabre en segundo plano; los datagramas que lleguen mientras tanto se
 *    encolan brevemente.
 *  - Un "keepalive" cada ~110 s evita que la VPS cierre la asociación por
 *    inactividad (UDP_IDLE_TIMEOUT=180 s).
 */
class UdpTunnel(private val engine: VpnEngine) {
    private val settings = engine.settings
    private val stats = engine.stats

    @Volatile private var ready = false
    @Volatile private var ensuring = false
    @Volatile private var stopped = false

    private var control: Socket? = null
    private var udpSocket: DatagramSocket? = null
    private var relayAddress: InetSocketAddress? = null

    private class LocalFlow(val ip: ByteArray, val port: Int, @Volatile var lastSeen: Long)

    private class CachedDns(val response: ByteArray, val expiresAt: Long)
    private val dnsCache = ConcurrentHashMap<String, CachedDns>()

    private fun extractDnsQuestionKey(data: ByteArray): String? {
        if (data.size <= 12) return null
        var idx = 12
        while (idx < data.size) {
            val len = data[idx].toInt() and 0xFF
            if (len == 0) {
                idx++
                break
            }
            if ((len and 0xC0) == 0xC0) {
                idx += 2
                break
            }
            idx += 1 + len
        }
        idx += 4
        if (idx > data.size) return null
        val qbytes = data.copyOfRange(12, idx)
        return qbytes.joinToString("-") { (it.toInt() and 0xFF).toString() }
    }

    private fun lookupDnsCache(query: ByteArray): ByteArray? {
        val qKey = extractDnsQuestionKey(query) ?: return null
        val cached = dnsCache[qKey] ?: return null
        if (System.currentTimeMillis() > cached.expiresAt) {
            dnsCache.remove(qKey)
            return null
        }
        val out = cached.response.copyOf()
        out[0] = query[0]
        out[1] = query[1]
        return out
    }

    private fun recordDnsCache(response: ByteArray) {
        if (response.size <= 12) return
        val flags = ((response[2].toInt() and 0xFF) shl 8) or (response[3].toInt() and 0xFF)
        val qr = (flags and 0x8000) != 0
        val rcode = flags and 0x000F
        val ancount = ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)
        if (!qr || rcode != 0 || ancount <= 0) return
        val qKey = extractDnsQuestionKey(response) ?: return
        dnsCache[qKey] = CachedDns(response.copyOf(), System.currentTimeMillis() + 300_000L)
    }

    private class PendingDatagram(
        val dstIp: ByteArray, val dstPort: Int, val srcIp: ByteArray, val srcPort: Int, val payload: ByteArray,
    )

    /** remote -> lista de sockets locales del dispositivo que escribieron a ese remoto. */
    private val flowMap = ConcurrentHashMap<String, MutableList<LocalFlow>>()
    private val pendingQueue = ArrayBlockingQueue<PendingDatagram>(256)

    @Volatile private var lastActivity = System.currentTimeMillis()
    @Volatile private var lastKeepalive = System.currentTimeMillis()
    private var lastFlowSweep = 0L

    // ---------------------------------------------------------------- ciclo de vida

    fun onDevicePacket(pkt: Ip.UdpPacket, buf: ByteArray) {
        if (stopped) return
        val data = pkt.payload(buf)
        if (pkt.dstPort == 53 && data.size > 12) {
            val cached = lookupDnsCache(data)
            if (cached != null) {
                stats.udpDatagramsOut.incrementAndGet()
                stats.udpDatagramsIn.incrementAndGet()
                engine.emitUdpPacket(pkt.ip.dst, pkt.dstPort, pkt.ip.src, pkt.srcPort, cached)
                return
            }
        }
        stats.udpDatagramsOut.incrementAndGet()
        if (!ready) {
            if (!pendingQueue.offer(PendingDatagram(pkt.ip.dst, pkt.dstPort, pkt.ip.src, pkt.srcPort, data))) {
                stats.udpOversizeDropped.incrementAndGet()
            }
            ensureAssociation()
            return
        }
        sendWrapped(pkt.ip.dst, pkt.dstPort, pkt.ip.src, pkt.srcPort, data)
    }

    fun ensureAssociation() {
        if (stopped || ready || ensuring) return
        ensuring = true
        thread(name = "udp-ensure", isDaemon = true) {
            try {
                if (!stopped && !ready) {
                    establish()
                }
            } catch (e: Exception) {
                AppLog.w("[udp] asociación: ${e.message}")
            } finally {
                ensuring = false
            }
        }
    }

    private fun establish() {
        closeSockets()

        val socket = Socket()
        socket.tcpNoDelay = true
        socket.connect(InetSocketAddress(engine.socksHost, engine.socksPort), 15_000)
        val input = socket.getInputStream()
        val output = socket.getOutputStream()

        // Saludo.
        output.write(byteArrayOf(0x05, 0x01, 0x00))
        output.flush()
        val method = readExactly(input, 2)
        if (method[0] != 0x05.toByte() || method[1] != 0x00.toByte()) {
            throw IOException("método SOCKS5 rechazado")
        }

        // UDP ASSOCIATE con 0.0.0.0:0 (sin filtro de origen, como un cliente normal).
        output.write(byteArrayOf(0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
        output.flush()
        val head = readExactly(input, 4)
        if (head[0] != 0x05.toByte() || head[1] != 0x00.toByte()) {
            throw IOException("UDP ASSOCIATE rechazado (rep=${head[1].toInt() and 0xFF})")
        }
        val atyp = head[3].toInt() and 0xFF
        val relayIp: ByteArray = when (atyp) {
            1 -> readExactly(input, 4)
            4 -> readExactly(input, 16)
            3 -> {
                val size = readExactly(input, 1)[0].toInt() and 0xFF
                readExactly(input, size)
            }
            else -> throw IOException("ATYP SOCKS5 inesperado")
        }
        val portBytes = readExactly(input, 2)
        val relayPort = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
        val relayInet = InetAddress.getByAddress(relayIp)
        relayAddress = InetSocketAddress(relayInet, relayPort)

        // Socket UDP desde el que salen todos los datagramas del dispositivo.
        val datagram = DatagramSocket(InetSocketAddress(InetAddress.getByName(engine.socksHost), 0))
        datagram.soTimeout = 500

        control = socket
        udpSocket = datagram
        ready = true
        lastActivity = System.currentTimeMillis()
        lastKeepalive = System.currentTimeMillis()
        AppLog.i("[udp] asociación SOCKS UDP activa (relay ${relayInet.hostAddress}:$relayPort)")

        // Drenar datagramas encolados mientras se abría la asociación.
        while (true) {
            val pending = pendingQueue.poll() ?: break
            sendWrapped(pending.dstIp, pending.dstPort, pending.srcIp, pending.srcPort, pending.payload)
        }

        thread(name = "udp-rx", isDaemon = true) { receiveLoop(datagram) }
        thread(name = "udp-monitor", isDaemon = true) { controlMonitor(socket, input) }
    }

    private fun readExactly(input: InputStream, count: Int): ByteArray {
        val out = ByteArray(count)
        var read = 0
        while (read < count) {
            val n = input.read(out, read, count - read)
            if (n < 0) throw IOException("EOF del SOCKS local")
            read += n
        }
        return out
    }

    // ---------------------------------------------------------------- envío

    private fun sendWrapped(dstIp: ByteArray, dstPort: Int, srcIp: ByteArray, srcPort: Int, payload: ByteArray) {
        if (!ready || stopped) return
        val socket = udpSocket ?: return
        val relay = relayAddress ?: return
        if (payload.size > settings.udpMaxPacketSize) {
            stats.udpOversizeDropped.incrementAndGet()
            return
        }
        try {
            val atyp = if (dstIp.size == 4) 1 else 4
            val wrapped = ByteArray(4 + dstIp.size + 2 + payload.size)
            wrapped[0] = 0
            wrapped[1] = 0
            wrapped[2] = 0 // FRAG = 0
            wrapped[3] = atyp.toByte()
            System.arraycopy(dstIp, 0, wrapped, 4, dstIp.size)
            wrapped[4 + dstIp.size] = (dstPort shr 8).toByte()
            wrapped[5 + dstIp.size] = dstPort.toByte()
            System.arraycopy(payload, 0, wrapped, 6 + dstIp.size, payload.size)
            socket.send(DatagramPacket(wrapped, wrapped.size, relay))
            upsertFlow(dstIp, dstPort, srcIp, srcPort)
            lastActivity = System.currentTimeMillis()
        } catch (e: IOException) {
            AppLog.w("[udp] envío: ${e.message}")
        }
    }

    private fun upsertFlow(dstIp: ByteArray, dstPort: Int, srcIp: ByteArray, srcPort: Int) {
        val key = flowKey(dstIp, dstPort)
        val now = System.currentTimeMillis()
        val list = flowMap.computeIfAbsent(key) { ArrayList(4) }
        synchronized(list) {
            var found: LocalFlow? = null
            for (flow in list) {
                if (flow.port == srcPort && flow.ip.contentEquals(srcIp)) {
                    found = flow
                    break
                }
            }
            if (found != null) {
                found.lastSeen = now
            } else {
                if (list.size >= 8) list.removeAt(0)
                list.add(LocalFlow(srcIp, srcPort, now))
            }
        }
    }

    private fun flowKey(ip: ByteArray, port: Int): String =
        ip.joinToString("-") { (it.toInt() and 0xFF).toString() } + ":" + port

    // ---------------------------------------------------------------- recepción

    private fun receiveLoop(datagram: DatagramSocket) {
        val buffer = ByteArray(65560)
        val packet = DatagramPacket(buffer, buffer.size)
        while (ready && !stopped) {
            try {
                packet.length = buffer.size
                datagram.receive(packet)
            } catch (e: java.net.SocketTimeoutException) {
                continue
            } catch (e: IOException) {
                break
            }
            try {
                deliverResponse(buffer, packet.length)
            } catch (e: Exception) {
                AppLog.w("[udp] respuesta: ${e.message}")
            }
        }
    }

    private fun deliverResponse(buffer: ByteArray, length: Int) {
        if (length < 4) return
        if (buffer[0] != 0x00.toByte() || buffer[1] != 0x00.toByte()) return
        val frag = buffer[2].toInt() and 0xFF
        if (frag != 0) return // no fragmentamos; ignorar fragmentos.
        val atyp = buffer[3].toInt() and 0xFF
        var offset = 4
        val remoteIp: ByteArray = when (atyp) {
            1 -> {
                if (length < offset + 4) return
                offset += 4; buffer.copyOfRange(4, offset)
            }
            4 -> {
                if (length < offset + 16) return
                offset += 16; buffer.copyOfRange(4, offset)
            }
            3 -> {
                if (length < offset + 1) return
                val size = buffer[offset].toInt() and 0xFF
                offset++
                if (size == 0 || length < offset + size) return
                // hostname: no esperado en respuestas; ignorar.
                return
            }
            else -> return
        }
        if (length < offset + 2) return
        val remotePort = ((buffer[offset].toInt() and 0xFF) shl 8) or (buffer[offset + 1].toInt() and 0xFF)
        offset += 2
        val payload = buffer.copyOfRange(offset, length)
        if (payload.isEmpty()) return

        if (remotePort == 53) {
            recordDnsCache(payload)
        }

        stats.udpDatagramsIn.incrementAndGet()
        val key = flowKey(remoteIp, remotePort)
        val list = flowMap[key] ?: return
        val now = System.currentTimeMillis()
        synchronized(list) {
            for (flow in list) {
                flow.lastSeen = now
                val overhead = if (flow.ip.size == 16) 48 else 28
                if (payload.size > Ip.MTU - overhead) {
                    stats.udpOversizeDropped.incrementAndGet()
                    continue
                }
                engine.emitUdpPacket(remoteIp, remotePort, flow.ip, flow.port, payload)
            }
        }
        lastActivity = now
    }

    /** Vigila el socket de control: si el relay lo cierra (EOF), reabrir la asociación. */
    private fun controlMonitor(socket: Socket, input: InputStream) {
        try {
            socket.soTimeout = 0
            while (true) {
                val first = input.read()
                if (first == -1) break // EOF: el relay cerró el control
                // Cualquier otro dato de control se descarta (como en el script).
            }
        } catch (e: IOException) {
            // cae al tratamiento común de cierre
        }
        if (ready && !stopped) {
            onControlClosed()
        }
    }

    private fun onControlClosed() {
        if (stopped) return
        ready = false
        AppLog.w("[udp] el relay cerró la asociación; se reabrirá")
        closeSockets()
        if (!stopped) {
            ensureAssociation()
        }
    }

    // ---------------------------------------------------------------- ciclo de reloj

    fun tick() {
        if (stopped) return
        val now = System.currentTimeMillis()

        // Keepalive: 1 byte al puerto discard de la propia VPS mantiene viva la
        // asociación en el lado móvil (last_activity de la VPS).
        if (ready && now - lastKeepalive > 110_000 && now - lastActivity > 100_000) {
            lastKeepalive = now
            sendWrapped(byteArrayOf(127, 0, 0, 1), 9, byteArrayOf(127, 0, 0, 1), 9, byteArrayOf(0x6B))
        }

        // Depurar flujos viejos.
        if (now - lastFlowSweep > 1_000) {
            lastFlowSweep = now
            val iterator = flowMap.entries.iterator()
            while (iterator.hasNext()) {
                val entry = iterator.next()
                val list = entry.value
                synchronized(list) {
                    list.removeAll { now - it.lastSeen > 60_000 }
                }
                if (list.isEmpty()) iterator.remove()
            }
            if (flowMap.size > 2048) {
                flowMap.clear()
            }
        }
    }

    fun stop() {
        stopped = true
        ready = false
        closeSockets()
    }

    private fun closeSockets() {
        ready = false
        try {
            control?.close()
        } catch (e: IOException) {
            // ignorar
        }
        try {
            udpSocket?.close()
        } catch (e: IOException) {
            // ignorar
        }
        control = null
        udpSocket = null
        relayAddress = null
    }

    fun isReady(): Boolean = ready

    fun pendingCount(): Int = pendingQueue.size
}