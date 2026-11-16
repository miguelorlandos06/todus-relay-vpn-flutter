package cu.todus.relayvpn

import cu.todus.relayvpn.RelayProtocol.UdpRecord
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.ArrayDeque
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Future
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.Semaphore
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * Puerto de MOBILE/movil_proxy.py: SOCKS5 CONNECT + UDP ASSOCIATE sobre el
 * relay de objetos ToDus. El protocolo con la VPS (claves, ventanas, FIN/CLOSE,
 * lotes UDP, HMAC) se mantiene idéntico.
 *
 * Optimizaciones de estabilidad añadidas:
 *  - **Semáforo de sesiones**: limita el número de sockets SOCKS5 atendidos a
 *    la vez (`maxSessions`); los excedentes reciben un SOCKS failure inmediato
 *    en lugar de saturar el ThreadPool y agotar memoria.
 *  - **Batching TCP en subida**: los `read()` pequeños del cliente se
 *    acumulan en un búfer durante `tcpBatchDelayMs` (o hasta `tcpBatchMaxBytes`)
 *    y se publican como un único frame más grande, reduciendo drásticamente el
 *    número de peticiones PUT a ToDus en tráfico interactivo.
 *  - **Backoff en `waitForVps`**: si la VPS no responde tras varios sondeos,
 *    se duplica el intervalo de sondeo hasta `queuePollInterval`, evitando
 *    bucles destructivos cuando la red está caída.
 */
class SocksServer(
    private val settings: RelaySettings,
    private val store: TodusStore,
    private val stats: VpnStats,
) {
    private var server: ServerSocket? = null
    private var acceptThread: Thread? = null
    private val queueLock = Any()
    private val activeSessions = AtomicInteger(0)
    @Volatile var running = false
        private set

    private lateinit var pool: ThreadPoolExecutor

    /**
     * Semáforo que acota las sesiones activas (sockets SOCKS5 atendidos
     * simultáneamente). Cuando se agota, la nueva conexión se rechaza con un
     * SOCKS general failure en lugar de encolarse indefinidamente.
     */
    private val sessionSemaphore = Semaphore(settings.maxSessions.coerceAtLeast(1), false)

    fun start() {
        val address = InetAddress.getByName(settings.socksHost)
        server = ServerSocket(settings.socksPort, settings.maxSessions.coerceAtLeast(16), address)
        // Pool de hilos coherente con maxSessions: nunca más hilos que sesiones.
        val threads = settings.maxSessions.coerceAtLeast(2)
        pool = ThreadPoolExecutor(
            threads, threads, 30, TimeUnit.SECONDS,
            LinkedBlockingQueue<Runnable>(threads * 2),
        ) { r -> Thread(r, "socks-sesion-${threadCounter.incrementAndGet()}") }
        // Política de rechazo: si la cola se llena, el acceptLoop encola y el
        // semáforo rechaza. Aquí usamos CallerRuns para no perder el socket pero
        // el semáforo garantiza el tope real.
        pool.rejectedExecutionHandler = ThreadPoolExecutor.DiscardPolicy()
        running = true
        AppLog.i(
            "[*] SOCKS5 ToDus Relay v3 en ${settings.socksHost}:${settings.socksPort} | " +
                "maxSesiones=${settings.maxSessions} | maxHTTP=${settings.maxConcurrentHttp} | " +
                "TCP batch=${settings.tcpBatchDelayMs}ms/${settings.tcpBatchMaxBytes}B | " +
                "UDP batch=${settings.udpBatchCount}/${settings.udpBatchMaxBytes}B | " +
                "poll=${settings.pollInterval}s"
        )
        acceptThread = thread(name = "socks-accept") { acceptLoop() }
    }

    fun stop() {
        running = false
        try {
            server?.close()
        } catch (e: IOException) {
            // ya cerrado
        }
        pool.shutdownNow()
    }

    private fun acceptLoop() {
        val listener = server ?: return
        while (running) {
            try {
                val client = listener.accept()
                pool.execute { handleClient(client) }
            } catch (e: IOException) {
                if (running) AppLog.w("[socks] accept: ${e.message}")
            }
        }
    }

    // ---------------------------------------------------------------- utilidades

    private fun readFully(input: InputStream, count: Int): ByteArray {
        val out = ByteArray(count)
        var read = 0
        while (read < count) {
            val n = input.read(out, read, count - read)
            if (n < 0) throw EOFException("el cliente cerró durante el saludo SOCKS5")
            read += n
        }
        return out
    }

    private fun readSocksAddress(input: InputStream, atyp: Int): String {
        when (atyp) {
            1 -> {
                val raw = readFully(input, 4)
                return raw.joinToString(".") { (it.toInt() and 0xFF).toString() }
            }
            3 -> {
                val size = readFully(input, 1)[0].toInt() and 0xFF
                if (size == 0) throw IOException("hostname SOCKS5 vacío")
                return String(readFully(input, size), Charsets.US_ASCII)
            }
            4 -> {
                val raw = readFully(input, 16)
                val groups = IntArray(8)
                for (i in 0 until 8) {
                    groups[i] = ((raw[i * 2].toInt() and 0xFF) shl 8) or (raw[i * 2 + 1].toInt() and 0xFF)
                }
                return formatIpv6(groups)
            }
        }
        throw IOException("ATYP SOCKS5 no soportado")
    }

    private fun formatIpv6(groups: IntArray): String {
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
        if (bestLen < 2) return groups.joinToString(":") { String.format("%x", it) }
        val left = groups.copyOfRange(0, bestStart).joinToString(":") { String.format("%x", it) }
        val right = groups.copyOfRange(bestStart + bestLen, groups.size).joinToString(":") { String.format("%x", it) }
        return "$left::$right"
    }

    private fun replyGeneralFailure(output: OutputStream) {
        output.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
    }

    private fun replyHostUnreachable(output: OutputStream) {
        output.write(byteArrayOf(0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
    }

    // ---------------------------------------------------------------- cola y estado

    private fun queueSession(sessionId: String): Boolean {
        synchronized(queueLock) {
            val slot = (sessionId.hashCode() and 0x7FFFFFFF) % 4
            val qKey = RelayProtocol.queueKey(slot)
            val raw = store.get(qKey) ?: ByteArray(0)
            val entries = String(raw, Charsets.US_ASCII).split("\n").map { it.trim() }.filter { it.isNotEmpty() }
                .toMutableList()
            if (sessionId !in entries) entries.add(sessionId)
            val trimmed = if (entries.size > 24) entries.takeLast(24) else entries
            return store.put(qKey, (trimmed.joinToString("\n") + "\n").toByteArray(Charsets.US_ASCII))
        }
    }

    private fun waitForVps(sessionId: String): org.json.JSONObject? {
        val deadline = System.currentTimeMillis() + (settings.connectTimeout * 1000).toLong()
        var missedPolls = 0
        var currentInterval = settings.pollInterval
        while (System.currentTimeMillis() < deadline) {
            val raw = store.get(RelayProtocol.statusKey(sessionId))
            if (raw != null) {
                try {
                    val status = RelayProtocol.decodeStatus(raw)
                    val state = status.optString("state", "")
                    if (state == "ready" || state == "error") return status
                } catch (e: org.json.JSONException) {
                    // objeto corrupto: seguir intentando
                }
            } else {
                // No hay estado todavía: contar y aplicar backoff creciente
                // para no saturar la API con GETs en bucle cuando la red está
                // caída. Se duplica el intervalo cada 3 fallos hasta el tope
                // queuePollInterval.
                missedPolls++
                if (missedPolls % 3 == 0 && currentInterval < settings.queuePollInterval) {
                    currentInterval = (currentInterval * 2).coerceAtMost(settings.queuePollInterval)
                }
            }
            sleepQuiet(currentInterval)
        }
        return null
    }

    private fun sleepQuiet(seconds: Double) {
        try {
            Thread.sleep((seconds * 1000).toLong())
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    // ---------------------------------------------------------------- CONNECT (TCP)

    private fun handleClient(sock: Socket) {
        val sessionId = UUID.randomUUID().toString().replace("-", "")
        // Semáforo de concurrencia: si ya hay `maxSessions` activas, rechazar
        // inmediatamente con un SOCKS general failure en lugar de encolar y
        // saturar el motor. El tráfico excedente típicamente es ruido (apps
        // de fondo) y puede esperar al siguiente reintento del sistema.
        if (!sessionSemaphore.tryAcquire()) {
            stats.sessionsRejectedByLimit.incrementAndGet()
            try {
                sock.soTimeout = 3_000
                val output = sock.getOutputStream()
                // Saludo mínimo: si el cliente envía SOCKS5 sin auth, le
                // respondemos 0x05 0xFF y luego un general failure.
                val input = sock.getInputStream()
                try {
                    val greeting = readFully(input, 2)
                    if (greeting[0] == 0x05.toByte() && greeting[1] > 0) {
                        readFully(input, greeting[1].toInt())
                        output.write(byteArrayOf(0x05, 0x00))
                        readFully(input, 4)
                        // ATYP variable: leer lo mínimo y responder failure.
                    }
                } catch (_: Exception) { /* sin tiempo */ }
                replyGeneralFailure(output)
            } catch (_: Exception) { /* socket roto */ } finally {
                try { sock.close() } catch (_: IOException) {}
            }
            return
        }
        activeSessions.incrementAndGet()
        try {
            sock.soTimeout = 10_000
            sock.tcpNoDelay = true
            val input = sock.getInputStream()
            val output = sock.getOutputStream()

            val greeting = readFully(input, 2)
            if (greeting[0] != 0x05.toByte() || greeting[1] == 0x00.toByte()) return
            val methods = readFully(input, greeting[1].toInt())
            if (!methods.contains(0x00.toByte())) {
                output.write(byteArrayOf(0x05, 0xFF.toByte()))
                return
            }
            output.write(byteArrayOf(0x05, 0x00))

            val request = readFully(input, 4)
            val version = request[0].toInt() and 0xFF
            val command = request[1].toInt() and 0xFF
            val atyp = request[3].toInt() and 0xFF
            if (version != 5) return
            val requestedHost = readSocksAddress(input, atyp)
            val portBytes = readFully(input, 2)
            val requestedPort = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)

            if (command == 3) {
                handleUdpAssociate(sock, sessionId, requestedHost, requestedPort)
                return
            }
            if (command != 1) {
                output.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                return
            }
            if (requestedPort !in 1..65535) {
                replyGeneralFailure(output)
                return
            }

            val target = RelayProtocol.encodeTargetJson(
                "tcp", requestedHost, requestedPort, System.currentTimeMillis() / 1000.0
            )
            if (!store.put(RelayProtocol.targetKey(sessionId), target) || !queueSession(sessionId)) {
                replyGeneralFailure(output)
                return
            }
            AppLog.i("[+] CONNECT $requestedHost:$requestedPort [${sessionId.take(8)}]")
            val status = waitForVps(sessionId)
            if (status == null || status.optString("state") != "ready") {
                AppLog.w("[VPS ${sessionId.take(8)}] ${status ?: "timeout esperando conexión"}")
                replyHostUnreachable(output)
                return
            }
            output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            relayClient(sock, sessionId)
        } catch (e: Exception) {
            AppLog.w("[cliente ${sessionId.take(8)}] ${e.message}")
        } finally {
            activeSessions.decrementAndGet()
            sessionSemaphore.release()
            try {
                sock.close()
            } catch (e: IOException) {
                // ignorar
            }
        }
    }

    private fun waitWindowC2s(sessionId: String, sequence: Long, lastAck: LongArray): Boolean {
        while (sequence - lastAck[0] >= settings.windowSize) {
            val raw = store.get(RelayProtocol.ackKey("c2s", sessionId))
            if (raw != null) {
                lastAck[0] = maxOf(lastAck[0], RelayProtocol.decodeCounter(raw))
            }
            if (sequence - lastAck[0] < settings.windowSize) return true
            if (store.get(RelayProtocol.closeKey(sessionId)) != null) return false
            sleepQuiet(settings.pollInterval)
        }
        return true
    }

    private fun relayClient(sock: Socket, sessionId: String) {
        val stopped = AtomicBoolean(false)
        val uplinkDone = AtomicBoolean(false)
        val downlinkDone = AtomicBoolean(false)

        // El socket tiene soTimeout=250ms para que el read() en la subida pueda
        // despertar periódicamente y volcar el búfer de batching aunque el
        // cliente no escriba más.
        sock.soTimeout = 250

        val uplink = thread(name = "c2s-$sessionId", isDaemon = true) {
            var sequence = 0L
            val lastAck = LongArray(1)
            try {
                val input = sock.getInputStream()
                val buffer = ByteArray(settings.chunkSize)
                // Búfer de batching: acumula reads pequeños y los vuelca como un
                // único frame cada `tcpBatchDelayMs` o cuando se llena
                // (`tcpBatchMaxBytes`). Para tráfico de bulk (descargas) el
                // read() entrega cerca de chunkSize de golpe y el búfer no
                // añade latencia; para tráfico interactivo (TLS, keystrokes)
                // convierte N PUTs pequeños en 1 PUT más grande.
                val batch = ByteArrayOutputStream(settings.tcpBatchMaxBytes)
                var batchStartedAt = 0L
                val batchDeadlineMs = settings.tcpBatchDelayMs.toLong()
                val batchMaxBytes = settings.tcpBatchMaxBytes

                fun flushBatch(reason: String): Boolean {
                    if (batch.size() == 0) return true
                    val payload = batch.toByteArray()
                    batch.reset()
                    batchStartedAt = 0L
                    if (!waitWindowC2s(sessionId, sequence, lastAck)) {
                        stopped.set(true)
                        return false
                    }
                    val frame = RelayProtocol.encodeFrame(sequence, payload)
                    if (!store.put(RelayProtocol.dataKey("c2s", sessionId, sequence), frame)) {
                        throw IOException("no se pudo publicar un fragmento móvil→VPS")
                    }
                    sequence++
                    stats.tcpBatchesSent.incrementAndGet()
                    return true
                }

                while (!stopped.get()) {
                    val n = try {
                        input.read(buffer)
                    } catch (e: SocketTimeoutException) {
                        // Timeout: si el búfer tiene algo y la ventana de tiempo
                        // del batch ya pasó, volcar ahora.
                        if (batch.size() > 0 &&
                            System.currentTimeMillis() - batchStartedAt >= batchDeadlineMs
                        ) {
                            if (!flushBatch("timeout")) break
                        }
                        continue
                    }
                    if (n < 0) {
                        // EOF del cliente: volcar lo pendiente y FIN.
                        flushBatch("eof")
                        break
                    }
                    if (n == 0) continue
                    if (batch.size() == 0) {
                        batchStartedAt = System.currentTimeMillis()
                    }
                    batch.write(buffer, 0, n)
                    // Si supera el tamaño máximo, volcar inmediatamente.
                    if (batch.size() >= batchMaxBytes ||
                        System.currentTimeMillis() - batchStartedAt >= batchDeadlineMs
                    ) {
                        if (!flushBatch("full-or-time")) break
                    }
                }
                // Asegurar que el último bloque parcial se publica (si no se abortó).
                if (!stopped.get()) {
                    flushBatch("final")
                }
                store.put(RelayProtocol.finKey("c2s", sessionId), RelayProtocol.encodeCounter(sequence))
            } catch (e: Exception) {
                AppLog.w("[subida ${sessionId.take(8)}] ${e.message}")
                stopped.set(true)
            } finally {
                uplinkDone.set(true)
            }
        }

        val downlink = thread(name = "s2c-$sessionId", isDaemon = true) {
            var sequence = 0L
            var sinceAck = 0
            var lastAckTime = System.currentTimeMillis()
            var missedPolls = 0
            try {
                val output = sock.getOutputStream()
                while (!stopped.get()) {
                    val raw = store.get(RelayProtocol.dataKey("s2c", sessionId, sequence))
                    if (raw != null) {
                        val payload = RelayProtocol.decodeFrame(raw, sequence)
                        if (payload.isNotEmpty()) {
                            output.write(payload)
                        }
                        if (settings.deleteAfterRead) {
                            store.delete(RelayProtocol.dataKey("s2c", sessionId, sequence))
                        }
                        sequence++
                        sinceAck++
                        missedPolls = 0
                        if (sinceAck >= settings.ackEvery || System.currentTimeMillis() - lastAckTime > 1000L) {
                            store.put(RelayProtocol.ackKey("s2c", sessionId), RelayProtocol.encodeCounter(sequence))
                            sinceAck = 0
                            lastAckTime = System.currentTimeMillis()
                        }
                        continue
                    }
                    val finRaw = store.get(RelayProtocol.finKey("s2c", sessionId))
                    if (finRaw != null && sequence >= RelayProtocol.decodeCounter(finRaw)) {
                        if (sinceAck > 0) {
                            store.put(RelayProtocol.ackKey("s2c", sessionId), RelayProtocol.encodeCounter(sequence))
                        }
                        try {
                            sock.shutdownOutput()
                        } catch (e: IOException) {
                            // ignorar
                        }
                        break
                    }
                    if (store.get(RelayProtocol.closeKey(sessionId)) != null) break
                    // Backoff ligero en la bajada: si no llega nada, esperar
                    // `pollInterval` y duplicarlo cada 3 fallos (tope: 2 s) para
                    // no quemar CPU ni red cuando la VPS no tenga nada que decir.
                    missedPolls++
                    val dlInterval = if (missedPolls < 3) settings.pollInterval
                        else minOf(settings.pollInterval * (1 shl (missedPolls / 3).coerceAtMost(4)), 2.0)
                    sleepQuiet(dlInterval)
                }
            } catch (e: Exception) {
                AppLog.w("[descarga ${sessionId.take(8)}] ${e.message}")
                stopped.set(true)
            } finally {
                downlinkDone.set(true)
            }
        }

        while (!stopped.get()) {
            if (uplinkDone.get() && downlinkDone.get()) break
            if (!uplink.isAlive && !downlink.isAlive) break
            sleepQuiet(0.1)
        }
        stopped.set(true)
        store.put(RelayProtocol.closeKey(sessionId), "client-finished".toByteArray(Charsets.US_ASCII))
    }

    // ---------------------------------------------------------------- UDP ASSOCIATE

    private fun handleUdpAssociate(
        sock: Socket, sessionId: String, expectedClientHost: String, expectedClientPort: Int,
    ) {
        val output = sock.getOutputStream()
        val target = RelayProtocol.encodeTargetJson("udp", null, null, System.currentTimeMillis() / 1000.0)
        if (!store.put(RelayProtocol.targetKey(sessionId), target) || !queueSession(sessionId)) {
            replyGeneralFailure(output)
            return
        }
        val status = waitForVps(sessionId)
        if (status == null || status.optString("state") != "ready") {
            AppLog.w("[UDP VPS ${sessionId.take(8)}] ${status ?: "timeout esperando VPS"}")
            replyHostUnreachable(output)
            return
        }

        val localIp: InetAddress = sock.localAddress ?: InetAddress.getByName("127.0.0.1")
        val udpSock = DatagramSocket(InetSocketAddress(localIp, 0))
        try {
            val udpPort = udpSock.localPort
            val atyp = if (localIp is java.net.Inet6Address) 4 else 1
            val addressBytes = localIp.address
            val reply = ByteArrayOutputStream()
            reply.write(byteArrayOf(0x05, 0x00, 0x00, atyp.toByte()))
            reply.write(addressBytes)
            reply.write(byteArrayOf((udpPort shr 8).toByte(), udpPort.toByte()))
            output.write(reply.toByteArray())
            AppLog.i("[+] UDP ASSOCIATE relay=${localIp.hostAddress}:$udpPort [${sessionId.take(8)}]")
            relayUdpAssociation(sock, udpSock, sessionId, expectedClientHost, expectedClientPort)
        } finally {
            udpSock.close()
        }
    }

    /** Paquete SOCKS UDP de respuesta (RSV/FRAG/ATYP/addr/puerto + payload). */
    private fun buildSocksUdpPacket(host: String, port: Int, payload: ByteArray): ByteArray {
        val ip = RelayProtocol.parseIpAddress(host)
        val atyp: Int
        val encoded: ByteArray
        if (ip != null) {
            atyp = if (ip.size == 4) 1 else 4
            encoded = ip
        } else {
            val hostBytes = host.toByteArray(Charsets.US_ASCII)
            if (hostBytes.size !in 1..255) throw IOException("hostname de respuesta UDP demasiado largo")
            atyp = 3
            encoded = hostBytes
        }
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0x00, 0x00, 0x00, atyp.toByte()))
        out.write(encoded)
        out.write(byteArrayOf((port shr 8).toByte(), port.toByte()))
        out.write(payload)
        return out.toByteArray()
    }

    private fun relayUdpAssociation(
        control: Socket, udpSock: DatagramSocket, sessionId: String,
        expectedClientHost: String, expectedClientPort: Int,
    ) {
        val controlPeer = control.inetAddress?.hostAddress ?: ""
        var clientAddr: InetSocketAddress? = null
        var upSequence = 0L
        var downSequence = 0L
        val pending = ArrayDeque<Pair<Long, Future<Boolean>>>()
        val pool = ThreadPoolExecutor(
            settings.udpUploadWorkers, settings.udpUploadWorkers, 30, TimeUnit.SECONDS,
            LinkedBlockingQueue<Runnable>(),
        ) { r -> Thread(r, "udp-put-${sessionId.take(8)}") }
        val assembler = SocksUdpFragmentAssembler(settings.udpMaxPacketSize)
        var lastActivity = System.currentTimeMillis()
        var finalCount: Long? = null

        val controlInput = control.getInputStream()
        val udpPollMs = (settings.udpPollInterval * 1000).toLong().coerceAtLeast(1)
        val controlInputTimeoutMs = 1L

        try {
            control.soTimeout = controlInputTimeoutMs.toInt()
            udpSock.soTimeout = udpPollMs.toInt()
            val packetBuffer = ByteArray(65535)
            val udpPacket = DatagramPacket(packetBuffer, packetBuffer.size)
            mainLoop@ while (System.currentTimeMillis() - lastActivity < (settings.udpIdleTimeout * 1000).toLong()) {
                // ---- dato en el socket de control (se descarta, como en el script)
                try {
                    val firstByte = controlInput.read()
                    if (firstByte == -1) break@mainLoop
                    while (controlInput.available() > 0) controlInput.read()
                } catch (e: SocketTimeoutException) {
                    // sin datos de control
                }

                // ---- datagrama del cliente (motor TUN)
                try {
                    udpPacket.setLength(packetBuffer.size)
                    udpSock.receive(udpPacket)
                    val sourceAddress = udpPacket.address
                    val sourcePort = udpPacket.port
                    val sourceHost = sourceAddress?.hostAddress ?: ""

                    // Filtros del script: origen = par del control TCP y lo que pidió el cliente.
                    val fromControlPeer = sourceAddress != null && sourceHost == controlPeer
                    val hostFilterPass = expectedClientHost.isEmpty() ||
                        expectedClientHost == "0.0.0.0" || expectedClientHost == "::" ||
                        sourceHost == expectedClientHost
                    val portFilterPass = expectedClientPort == 0 || sourcePort == expectedClientPort
                    // El primer datagrama FIJA clientAddr y también se procesa (como en Python).
                    val firstFromClient = clientAddr == null
                    val fromKnownClient = !firstFromClient && sourceAddress == clientAddr!!.address &&
                        sourcePort == clientAddr!!.port

                    if (fromControlPeer && hostFilterPass && portFilterPass && (firstFromClient || fromKnownClient)) {
                        if (firstFromClient) {
                            clientAddr = InetSocketAddress(sourceAddress, sourcePort)
                        }
                            val packetBytes = packetBuffer.copyOf(udpPacket.length)
                            val first = assembler.feed(packetBytes)
                            val records = ArrayList<UdpRecord>(1)
                            if (first != null) records.add(first)
                            var batchBytes = udpPacket.length

                            // Agrupar datagramas hasta límite de tiempo/tamaño/cantidad.
                            val deadline = System.currentTimeMillis() + settings.udpBatchDelayMs
                            while (records.size < settings.udpBatchCount && batchBytes < settings.udpBatchMaxBytes) {
                                val remaining = deadline - System.currentTimeMillis()
                                if (remaining <= 0) break
                                udpSock.soTimeout = remaining.toInt().coerceAtLeast(1)
                                try {
                                    udpPacket.setLength(packetBuffer.size)
                                    udpSock.receive(udpPacket)
                                } catch (e: SocketTimeoutException) {
                                    break
                                } catch (e: SocketException) {
                                    break
                                }
                                val sameClient = udpPacket.address != null &&
                                    udpPacket.address == clientAddr!!.address && udpPacket.port == clientAddr!!.port
                                if (!sameClient) continue
                                val more = assembler.feed(packetBuffer.copyOf(udpPacket.length))
                                if (more == null) continue
                                records.add(more)
                                batchBytes += udpPacket.length
                            }
                            udpSock.soTimeout = udpPollMs.toInt()

                            if (records.isNotEmpty()) {
                                val maxPending = settings.udpUploadWorkers * 4
                                while (pending.size >= maxPending) {
                                    val old = pending.removeFirst()
                                    val ok = try {
                                        old.second.get()
                                    } catch (e: Exception) {
                                        false
                                    }
                                    if (!ok) {
                                        finalCount = old.first
                                        AppLog.w("[UDP ${sessionId.take(8)}] fallo PUT del lote ${old.first}; se descartan los siguientes")
                                        break
                                    }
                                }
                                if (finalCount != null) break@mainLoop
                                val batchSequence = upSequence
                                val batchRecords = records.toList()
                                pending.addLast(
                                    batchSequence to pool.submit(
                                        Callable {
                                            val body = RelayProtocol.encodeUdpBatch(batchSequence, batchRecords)
                                            store.put(RelayProtocol.udpDataKey("c2s", sessionId, batchSequence), body)
                                        }
                                    )
                                )
                                upSequence++
                                lastActivity = System.currentTimeMillis()
                            }
                    }
                } catch (e: SocketTimeoutException) {
                    // sin datagramas: continuar al downlink
                } catch (e: IOException) {
                    AppLog.w("[UDP ${sessionId.take(8)}] recepción: ${e.message}")
                    if (!running) break@mainLoop
                }

                // ---- downlink: respuestas de la VPS
                var raw = store.get(RelayProtocol.udpDataKey("s2c", sessionId, downSequence))
                if (raw == null) {
                    val nextRaw = store.get(RelayProtocol.udpDataKey("s2c", sessionId, downSequence + 1))
                    if (nextRaw != null) {
                        downSequence++
                        raw = nextRaw
                    }
                }
                if (raw != null) {
                    val responses = RelayProtocol.decodeUdpBatch(raw, downSequence)
                    for (record in responses) {
                        if (clientAddr != null) {
                            try {
                                val wrapped = buildSocksUdpPacket(record.host, record.port, record.payload)
                                udpSock.send(DatagramPacket(wrapped, wrapped.size, clientAddr))
                                lastActivity = System.currentTimeMillis()
                            } catch (e: IOException) {
                                AppLog.w("[UDP ${sessionId.take(8)}] entrega local: ${e.message}")
                            }
                        }
                    }
                    if (settings.deleteAfterRead) {
                        store.delete(RelayProtocol.udpDataKey("s2c", sessionId, downSequence))
                    }
                    downSequence++
                } else if (store.get(RelayProtocol.closeKey(sessionId)) != null) {
                    break@mainLoop
                }
            }
        } catch (e: Exception) {
            AppLog.w("[UDP ${sessionId.take(8)}] asociación finalizada por error: ${e.message}")
        } finally {
            // Drenar los PUT pendientes en orden; el FIN marca el primer lote fallido.
            for ((batchSequence, future) in pending) {
                val ok = try {
                    future.get()
                } catch (e: Exception) {
                    false
                }
                if (!ok && (finalCount == null || batchSequence < finalCount)) {
                    finalCount = batchSequence
                }
            }
            if (finalCount == null) finalCount = upSequence
            store.put(RelayProtocol.finKey("c2s", sessionId), RelayProtocol.encodeCounter(finalCount))
            store.put(RelayProtocol.closeKey(sessionId), "mobile-udp-finished".toByteArray(Charsets.US_ASCII))
            pool.shutdown()
        }
    }

    // ---------------------------------------------------------------- ensamblador FRAG

    /** Puerto de SocksUDPFragmentAssembler: un datagrama ensamblado en orden. */
    class SocksUdpFragmentAssembler(private val maxPacketSize: Int) {
        private class AsmState(
            val host: String,
            val port: Int,
            var next: Int,
            val payload: ByteArrayOutputStream,
            val created: Long,
        )

        private var state: AsmState? = null

        fun feed(packet: ByteArray): UdpRecord? {
            val parsed = parseSocksUdpPacket(packet, maxPacketSize) ?: return null
            val (host, port, frag, payload) = parsed
            val now = System.currentTimeMillis()
            if (state != null && now - state!!.created > 5_000) {
                state = null
            }
            if (frag == 0) {
                // Un datagrama nuevo sin fragmentar invalida el ensamblado en curso.
                state = null
                return UdpRecord(host, port, payload)
            }

            val number = frag and 0x7F
            val isLast = (frag and 0x80) != 0
            if (number == 0) {
                state = null
                return null
            }
            if (number == 1) {
                val buffer = ByteArrayOutputStream(payload.size)
                buffer.write(payload)
                val newState = AsmState(host, port, 2, buffer, now)
                state = newState
                if (isLast) {
                    val result = UdpRecord(host, port, newState.payload.toByteArray())
                    state = null
                    return result
                }
                return null
            }

            val current = state
            if (current == null || current.host != host || current.port != port || number != current.next) {
                state = null
                return null
            }
            current.payload.write(payload)
            if (current.payload.size() > maxPacketSize) {
                state = null
                return null
            }
            current.next++
            if (isLast) {
                val result = UdpRecord(host, port, current.payload.toByteArray())
                state = null
                return result
            }
            return null
        }

        companion object {
            /** RFC 1928: RSV(2) FRAG(1) ATYP DST.ADDR DST.PORT DATA. */
            fun parseSocksUdpPacket(packet: ByteArray, maxPacketSize: Int): ParsedPacket? {
                if (packet.size < 4) return null
                if (packet[0] != 0x00.toByte() || packet[1] != 0x00.toByte()) return null
                val frag = packet[2].toInt() and 0xFF

                var offset = 3
                val atyp = packet[offset].toInt() and 0xFF
                offset++
                val host: String
                when (atyp) {
                    1 -> {
                        if (packet.size < offset + 4) return null
                        host = packet.copyOfRange(offset, offset + 4).joinToString(".") {
                            (it.toInt() and 0xFF).toString()
                        }
                        offset += 4
                    }
                    4 -> {
                        if (packet.size < offset + 16) return null
                        val groups = IntArray(8)
                        val raw = packet.copyOfRange(offset, offset + 16)
                        for (i in 0 until 8) {
                            groups[i] = ((raw[i * 2].toInt() and 0xFF) shl 8) or (raw[i * 2 + 1].toInt() and 0xFF)
                        }
                        host = compressIpv6(groups)
                        offset += 16
                    }
                    3 -> {
                        if (packet.size < offset + 1) return null
                        val size = packet[offset].toInt() and 0xFF
                        offset++
                        if (size == 0 || packet.size < offset + size) return null
                        host = String(packet.copyOfRange(offset, offset + size), Charsets.US_ASCII)
                        offset += size
                    }
                    else -> return null
                }
                if (packet.size < offset + 2) return null
                val port = ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
                offset += 2
                if (port !in 1..65535) return null
                val payload = packet.copyOfRange(offset, packet.size)
                if (payload.size > maxPacketSize) return null
                return ParsedPacket(host, port, frag, payload)
            }

            private fun compressIpv6(groups: IntArray): String {
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
                if (bestLen < 2) return groups.joinToString(":") { String.format("%x", it) }
                val left = groups.copyOfRange(0, bestStart).joinToString(":") { String.format("%x", it) }
                val right = groups.copyOfRange(bestStart + bestLen, groups.size).joinToString(":") { String.format("%x", it) }
                return "$left::$right"
            }

            data class ParsedPacket(val host: String, val port: Int, val frag: Int, val payload: ByteArray)
        }
    }

    companion object {
        private val threadCounter = AtomicInteger(0)
    }
}
