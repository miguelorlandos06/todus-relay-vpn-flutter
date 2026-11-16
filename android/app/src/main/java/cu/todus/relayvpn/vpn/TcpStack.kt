package cu.todus.relayvpn.vpn

import kotlin.random.Random

import cu.todus.relayvpn.AppLog
import cu.todus.relayvpn.VpnStats
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.util.ArrayDeque
import java.util.TreeMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * Pila TCP del lado TUN: cada conexión TCP del dispositivo se termina en esta
 * clase (nuestro SYN-ACK, ventana, retransmisiones, FIN/RST) y su payload viaja
 * por el SOCKS5 local (SocksServer), que a su vez lo publica en ToDus igual que
 * MOBILE/movil_proxy.py. El otro extremo real es la VPS.
 *
 * Es una pila simplificada tipo go-back-N pensada para el TUN local:
 *  - recibimos datos en orden con reordenación limitada (TreeMap),
 *  - la ventana que anunciamos refleja la capacidad de la cola de subida,
 *  - RTO base 300 ms con backoff exponencial hasta 8 s,
 *  - FIN de ambos lados y cierre diferido (TIME_WAIT corto).
 */
class TcpStack(private val engine: VpnEngine) {
    val sessions = LinkedHashMap<String, TcpSession>()
    private val sessionsLock = Any()
    private val random = SecureRandom()
    val stats: VpnStats get() = engine.stats

    companion object {
        const val HARD_MAX_SESSIONS = 512
        fun binKey(bytes: ByteArray): String = bytes.joinToString("-") { (it.toInt() and 0xFF).toString() }
        fun keyOf(pkt: Ip.TcpPacket): String =
            "${binKey(pkt.ip.src)}:${pkt.srcPort}>${binKey(pkt.ip.dst)}:${pkt.dstPort}"

        /** Diferencia de secuencias módulo 2^32: >0 si «a» va por delante de «b» (< 2^31). */
        fun seqDiff(a: Long, b: Long): Long = ((a - b) and 0xFFFFFFFFL)

        fun seqAheadOf(a: Long, b: Long): Boolean = seqDiff(a, b) in 1..0x7FFFFFFFL

        fun seqAtOrAhead(a: Long, b: Long): Boolean = seqDiff(a, b) < 0x80000000L
    }

    /** Tope de sesiones TCP activas: respeta `settings.maxSessions`. */
    private val maxSessions: Int
        get() = engine.settings.maxSessions.coerceIn(2, HARD_MAX_SESSIONS)

    fun onTcp(pkt: Ip.TcpPacket, buf: ByteArray) {
        val key = keyOf(pkt)
        val session: TcpSession?
        synchronized(sessionsLock) {
            session = sessions[key]
        }
        if (session == null) {
            if (pkt.syn && !pkt.ackFlag) {
                synchronized(sessionsLock) {
                    if (sessions.size >= maxSessions) {
                        // Tope de concurrencia alcanzado: descartar el SYN con un
                        // RST para que la app origen reintente más tarde, en
                        // lugar de seguir aceptando SYN y saturar el motor.
                        stats.sessionsRejectedByLimit.incrementAndGet()
                        engine.sendRstFor(pkt)
                        return
                    }
                    val created = TcpSession(this, engine, pkt, buf, key)
                    sessions[key] = created
                    stats.tcpSessionsActive.incrementAndGet()
                    stats.tcpSessionsTotal.incrementAndGet()
                }
            } else if (!pkt.rst) {
                engine.sendRstFor(pkt)
            }
            return
        }
        if (pkt.rst) {
            session.destroy("RST del dispositivo")
            removeSession(key)
            return
        }
        try {
            session.onSegment(pkt, buf)
        } catch (e: Exception) {
            AppLog.w("[tcp ${key.take(24)}] ${e.message}")
            session.destroy("error de sesión")
        }
        if (session.isDestroyed()) {
            removeSession(key)
        }
    }

    fun removeSession(key: String) {
        synchronized(sessionsLock) {
            sessions.remove(key)
        }
    }

    fun tick() {
        val snapshot = synchronized(sessionsLock) { sessions.values.toList() }
        for (session in snapshot) {
            session.tick()
            if (session.isDestroyed()) {
                removeSession(session.sessionKey)
            }
        }
    }

    fun closeAll() {
        val snapshot = synchronized(sessionsLock) { sessions.values.toList() }
        for (session in snapshot) {
            session.destroy("VPN detenida")
        }
        synchronized(sessionsLock) { sessions.clear() }
    }

    fun activeCount(): Int = synchronized(sessionsLock) { sessions.size }
}

/**
 * Una sesión TCP del dispositivo, terminada localmente y conectada al SOCKS5.
 */
class TcpSession(
    private val stack: TcpStack,
    private val engine: VpnEngine,
    syn: Ip.TcpPacket,
    buf: ByteArray,
    val sessionKey: String,
) {
    private val settings = engine.settings
    private val stats = engine.stats

    // Lado dispositivo (nosotros somos el "servidor remoto" que el dispositivo cree contactar).
    private val localIp: ByteArray = syn.ip.src.copyOf()
    private val localPort: Int = syn.srcPort
    private val remoteIp: ByteArray = syn.ip.dst.copyOf()
    private val remotePort: Int = syn.dstPort
    private val ipv6: Boolean = remoteIp.size == 16

    private val ourMss: Int = if (ipv6) Ip.MTU - 60 else Ip.MTU - 40

    // Números de secuencia de NUESTRO flujo (hacia el dispositivo).
    private val iss: Long = (Random.nextInt().toLong() and 0xFFFFFFFFL)
    private var sndUna: Long = iss          // SYN sin confirmar al principio
    private var sndNxt: Long = iss + 1

    // Búfer de envío: bytes pendientes (desde sndUna) + segmentos por retransmitir.
    private val sendLock = Any()
    private val outBuf = ArrayDeque<ByteArray>()
    private var outHeadSkip = 0
    private var outTotal = 0L
    private var finQueued = false           // no hay más datos que enviar (EOF del SOCKS)
    @Volatile private var finSent = false
    private var finSeq = -1L
    @Volatile private var finAcked = false

    // Recepción desde el dispositivo.
    private var rxSeq: Long = 0             // siguiente SEQ esperado (RCV.NXT)
    private val rxReorder = TreeMap<Long, ByteArray>()
    @Volatile private var peerFinReceived = false
    private var peerWindowScale = 0
    @Volatile private var peerWindow = 65535L

    // Subida al SOCKS (datos del dispositivo).
    private val upQueue = LinkedBlockingQueue<ByteArray>(512)
    private val upQueuedBytes = AtomicInteger(0)

    // Socket SOCKS5 local y sus bombas.
    @Volatile private var socks: Socket? = null
    @Volatile private var socksIn: InputStream? = null
    @Volatile private var socksOut: OutputStream? = null
    @Volatile private var socksReady = false
    @Volatile private var socksFailed = false

    private val destroyed = AtomicBoolean(false)

    // Temporizadores.
    private var rtoMs = 300L
    private var rtoAt = 0L                  // 0 = desarmado
    private var lastActivity = System.currentTimeMillis()
    private var closeAt = 0L

    init {
        // MSS y window scale del SYN del dispositivo.
        var i = syn.optionsOff
        val end = syn.optionsOff + syn.optionsLen
        while (i + 1 < end) {
            val kind = buf[i].toInt() and 0xFF
            if (kind == 0) break
            val len = buf[i + 1].toInt() and 0xFF
            if (len < 2 || i + len > end) break
            if (kind == 2 && len == 4) {
                // MSS del par (no lo usamos para limitar; el TUN ya acota los paquetes).
            }
            if (kind == 3 && len == 3) {
                val scale = buf[i + 2].toInt() and 0xFF
                peerWindowScale = scale.coerceIn(0, 14)
            }
            i += len
        }
        rxSeq = (syn.seq + 1) and 0xFFFFFFFFL
        peerWindow = syn.window.toLong() shl peerWindowScale
        emitSynAck()
        armRto()
        if (syn.payloadLen > 0) {
            // SYN con datos (TFO): se acepta como datos en orden.
            acceptData(syn.payload(buf))
        }
        startSocksConnect()
    }

    // ---------------------------------------------------------------- emisión básica

    private fun sendToDevice(
        seq: Long, ack: Long, flags: Int, options: ByteArray?, payload: ByteArray?,
    ) {
        engine.sendTcpSegment(
            ipv6, remoteIp, localIp, remotePort, localPort,
            seq, ack, flags, advertisedWindow(), options, payload,
        )
    }

    private fun advertisedWindow(): Int {
        val queued = upQueuedBytes.get()
        val capacity = 512 * 1024
        val avail = maxOf(0, capacity - queued)
        return minOf(65535, avail shr 3)
    }

    private fun emitSynAck() {
        // Mantener las opciones negociadas con navegadores modernos: MSS,
        // window scale y SACK permitido. Con WS = 3, la ventana efectiva sube a ~512 KiB.
        val options = byteArrayOf(
            2, 4, (ourMss shr 8).toByte(), ourMss.toByte(),
            3, 3, 3, // Window Scale = 3 (ventana local de hasta ~512 KiB)
            4, 2,     // SACK permitted
        )
        sendToDevice(iss, rxSeq, Ip.SYN or Ip.ACK, options, null)
    }

    private fun sendAck() {
        sendToDevice(sndNxt, rxSeq, Ip.ACK, null, null)
    }

    private fun sendRstNow() {
        sendToDevice(sndNxt, rxSeq, Ip.RST or Ip.ACK, null, null)
    }

    // ---------------------------------------------------------------- recepción

    fun onSegment(pkt: Ip.TcpPacket, buf: ByteArray) {
        if (destroyed.get()) return
        lastActivity = System.currentTimeMillis()

        if (pkt.syn && !pkt.ackFlag) {
            // Retransmisión del SYN: responder de nuevo.
            if (rxSeq == ((pkt.seq + 1) and 0xFFFFFFFFL)) {
                synchronized(sendLock) { emitSynAck() }
            }
            return
        }

        if (pkt.ackFlag) {
            val a = pkt.ack
            synchronized(sendLock) {
                if (TcpStack.seqAheadOf(a, sndUna)) {
                    consumeOut(TcpStack.seqDiff(a, sndUna))
                    sndUna = a
                    rtoMs = 300
                    if (finSent && !finAcked && TcpStack.seqAtOrAhead(a, (finSeq + 1) and 0xFFFFFFFFL)) {
                        finAcked = true
                        maybeScheduleClose()
                    }
                }
                peerWindow = pkt.window.toLong() shl peerWindowScale
                flushLocked()
                armRtoLocked()
            }
        } else {
            peerWindow = pkt.window.toLong() shl peerWindowScale
        }

        if (pkt.payloadLen > 0) {
            val payload = pkt.payload(buf)
            if (pkt.seq == rxSeq) {
                acceptData(payload)
                sendAck()
            } else if (TcpStack.seqAheadOf(pkt.seq, rxSeq)) {
                // Segmento adelantado: guardar por si llega el hueco.
                if (reorderBytes() + payload.size <= 64 * 1024) {
                    rxReorder[pkt.seq] = payload
                } else {
                    stats.tcpSegmentsDropped.incrementAndGet()
                }
                sendAck() // ACK duplicado para avisar del hueco.
            } else {
                // Segmento viejo/retransmisión: reconfirmar.
                sendAck()
            }
        }

        if (pkt.fin && !peerFinReceived) {
            val finEnd = (pkt.seq + pkt.payloadLen) and 0xFFFFFFFFL
            if (finEnd == rxSeq) {
                rxSeq = (finEnd + 1) and 0xFFFFFFFFL
                drainReorder()
                peerFinReceived = true
                sendAck()
            }
            // FIN fuera de orden: el ACK duplicado hará que el par reenvíe.
        }
    }

    private fun reorderBytes(): Int {
        var total = 0
        for (chunk in rxReorder.values) total += chunk.size
        return total
    }

    private fun acceptData(payload: ByteArray) {
        rxSeq = (rxSeq + payload.size) and 0xFFFFFFFFL
        deliverUp(payload)
        drainReorder()
    }

    private fun drainReorder() {
        while (true) {
            val chunk = rxReorder.remove(rxSeq) ?: break
            rxSeq = (rxSeq + chunk.size) and 0xFFFFFFFFL
            deliverUp(chunk)
        }
    }

    private fun deliverUp(payload: ByteArray) {
        if (payload.isEmpty()) return
        if (upQueue.offer(payload)) {
            upQueuedBytes.addAndGet(payload.size)
        } else {
            // La ventana anunciada evita esto; por si ocurre, se pierde y cuenta.
            stats.tcpSegmentsDropped.incrementAndGet()
        }
    }

    // ---------------------------------------------------------------- envío hacia el dispositivo

    /** Datos que llegan del SOCKS (VPS) y deben entregarse al dispositivo. */
    fun send(data: ByteArray) {
        if (destroyed.get() || data.isEmpty()) return
        synchronized(sendLock) {
            outBuf.addLast(data)
            outTotal += data.size
            flushLocked()
        }
    }

    private fun flushLocked() {
        if (destroyed.get()) return
        while (true) {
            val inFlight = TcpStack.seqDiff(sndNxt, sndUna)
            val remaining = outTotal - inFlight
            if (remaining <= 0) break
            val edge = (sndUna + peerWindow) and 0xFFFFFFFFL
            val windowAvail = TcpStack.seqDiff(edge, sndNxt)
            if (windowAvail <= 0 || windowAvail >= 0x80000000L) break
            val n = minOf(ourMss.toLong(), remaining, windowAvail).toInt()
            val offset = TcpStack.seqDiff(sndNxt, sndUna).toInt()
            val segment = readOutRange(offset, n)
            sendToDevice(sndNxt, rxSeq, Ip.ACK, null, segment)
            sndNxt = (sndNxt + n) and 0xFFFFFFFFL
        }
        // FIN después de que todo el búfer esté en vuelo.
        if (finQueued && !finSent && TcpStack.seqDiff(sndNxt, sndUna) >= outTotal) {
            finSeq = sndNxt
            finSent = true
            sndNxt = (sndNxt + 1) and 0xFFFFFFFFL
            sendToDevice(finSeq, rxSeq, Ip.FIN or Ip.ACK, null, null)
        }
    }

    private fun readOutRange(offsetFromUna: Int, n: Int): ByteArray {
        val out = ByteArray(n)
        var copied = 0
        var index = 0
        var skip = outHeadSkip
        var toSkip = offsetFromUna
        while (toSkip > 0 && index < outBuf.size) {
            val chunk = outBuf.elementAt(index)
            val avail = chunk.size - skip
            if (toSkip >= avail) {
                toSkip -= avail
                index++
                skip = 0
            } else {
                skip += toSkip
                toSkip = 0
            }
        }
        while (copied < n && index < outBuf.size) {
            val chunk = outBuf.elementAt(index)
            val take = minOf(n - copied, chunk.size - skip)
            System.arraycopy(chunk, skip, out, copied, take)
            copied += take
            index++
            skip = 0
        }
        return out
    }

    private fun consumeOut(bytes: Long) {
        var remaining = bytes
        while (remaining > 0 && outTotal > 0) {
            val first = outBuf.peekFirst() ?: break
            val avail = (first.size - outHeadSkip).toLong()
            if (remaining >= avail) {
                outBuf.pollFirst()
                remaining -= avail
                outTotal -= avail
                outHeadSkip = 0
            } else {
                outHeadSkip += remaining.toInt()
                outTotal -= remaining
                remaining = 0
            }
        }
    }

    private fun armRtoLocked() {
        // Hay segmentos sin confirmar (SYN-ACK, datos o FIN) si sndNxt va delante de sndUna.
        if (TcpStack.seqAheadOf(sndNxt, sndUna)) {
            if (rtoAt == 0L) rtoAt = System.currentTimeMillis() + rtoMs
        } else {
            rtoAt = 0L
        }
    }

    private fun armRto() {
        synchronized(sendLock) { armRtoLocked() }
    }

    // ---------------------------------------------------------------- ciclo de reloj

    fun tick() {
        if (destroyed.get()) return
        val now = System.currentTimeMillis()
        if (closeAt != 0L && now >= closeAt) {
            destroy("cierre diferido")
            return
        }
        if (now - lastActivity > 300_000) {
            destroy("inactividad (300 s)")
            return
        }
        synchronized(sendLock) {
            if (rtoAt != 0L && now >= rtoAt) {
                if (sndUna == iss && sndNxt == iss + 1) {
                    // Solo el SYN-ACK en vuelo.
                    emitSynAck()
                    } else if (TcpStack.seqAheadOf(sndNxt, sndUna)) {
                    // Go-back-N: reenviar todo lo no confirmado (incluye re-FIN).
                    sndNxt = sndUna
                    finSent = false
                    finSeq = -1
                    flushLocked()
                }
                rtoMs = minOf(rtoMs * 2, 8000)
                rtoAt = now + rtoMs
            }
        }
    }

    private fun maybeScheduleClose() {
        if (finAcked && peerFinReceived) {
            closeAt = System.currentTimeMillis() + 3_000
        }
    }

    // ---------------------------------------------------------------- conexión SOCKS5 (cliente hacia 127.0.0.1:1080)

    private fun startSocksConnect() {
        thread(name = "tcp-socks-$sessionKey", isDaemon = true) {
            try {
                val socket = Socket()
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(engine.socksHost, engine.socksPort), 15_000)
                val input = socket.getInputStream()
                val output = socket.getOutputStream()

                // Saludo SOCKS5 sin autenticación.
                output.write(byteArrayOf(0x05, 0x01, 0x00))
                output.flush()
                val method = readExactly(input, 2)
                if (method[0] != 0x05.toByte() || method[1] != 0x00.toByte()) {
                    throw IOException("método SOCKS5 rechazado")
                }

                // CONNECT hacia el destino original del SYN.
                val atyp = if (ipv6) 4 else 1
                val request = ByteArrayOutputStream()
                request.write(byteArrayOf(0x05, 0x01, 0x00, atyp.toByte()))
                request.write(remoteIp)
                request.write(byteArrayOf((remotePort shr 8).toByte(), remotePort.toByte()))
                output.write(request.toByteArray())
                output.flush()

                val head = readExactly(input, 4)
                if (head[0] != 0x05.toByte()) throw IOException("respuesta SOCKS5 inválida")
                val replyAtyp = head[3].toInt() and 0xFF
                when (replyAtyp) {
                    1 -> readExactly(input, 4)
                    4 -> readExactly(input, 16)
                    3 -> {
                        val size = readExactly(input, 1)[0].toInt() and 0xFF
                        readExactly(input, size)
                    }
                    else -> throw IOException("ATYP SOCKS5 inesperado")
                }
                readExactly(input, 2)
                if (head[1] != 0x00.toByte()) {
                    throw IOException("CONNECT rechazado por el relay (rep=${head[1].toInt() and 0xFF})")
                }

                socks = socket
                socksIn = input
                socksOut = output
                socksReady = true
                startPumps()
            } catch (e: Exception) {
                socksFailed = true
                AppLog.w("[tcp ${sessionKey.take(24)}] SOCKS: ${e.message}")
                sendRstNow()
                destroy("fallo SOCKS")
            }
        }
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

    private fun startPumps() {
        thread(name = "tcp-up-$sessionKey", isDaemon = true) { upPump() }
        thread(name = "tcp-down-$sessionKey", isDaemon = true) { downPump() }
    }

    /** Cola del dispositivo -> SOCKS (hasta que el cierre de subida del dispositivo drene). */
    private fun upPump() {
        val output = socksOut ?: return
        try {
            while (true) {
                val chunk = upQueue.poll(200, TimeUnit.MILLISECONDS)
                if (chunk != null) {
                    output.write(chunk)
                    upQueuedBytes.addAndGet(-chunk.size)
                    continue
                }
                if (destroyed.get()) return
                if (peerFinReceived && upQueue.isEmpty()) {
                    try {
                        socks?.shutdownOutput()
                    } catch (e: IOException) {
                        // ignorar
                    }
                    return
                }
            }
        } catch (e: IOException) {
            if (!destroyed.get()) {
                AppLog.w("[tcp ${sessionKey.take(24)}] subida: ${e.message}")
                destroy("fallo de subida")
            }
        }
    }

    /** SOCKS -> dispositivo. EOF del SOCKS == FIN nuestro hacia el dispositivo. */
    private fun downPump() {
        val input = socksIn ?: return
        val buffer = ByteArray(16384)
        try {
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                if (n > 0) send(buffer.copyOf(n))
            }
        } catch (e: IOException) {
            if (!destroyed.get()) {
                AppLog.w("[tcp ${sessionKey.take(24)}] bajada: ${e.message}")
            }
        } finally {
            onSocksEof()
        }
    }

    private fun onSocksEof() {
        if (destroyed.get()) return
        synchronized(sendLock) {
            if (!finQueued) {
                finQueued = true
                flushLocked()
            }
        }
        maybeScheduleClose()
    }

    // ---------------------------------------------------------------- cierre

    fun isDestroyed(): Boolean = destroyed.get()

    fun destroy(reason: String) {
        if (!destroyed.compareAndSet(false, true)) return
        closeAt = 0
        try {
            socks?.close()
        } catch (e: IOException) {
            // ignorar
        }
        stats.tcpSessionsActive.decrementAndGet()
        stack.removeSession(sessionKey)
        AppLog.i("[tcp ${sessionKey.take(24)}] cerrada: $reason")
    }
}
