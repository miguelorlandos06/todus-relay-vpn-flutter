package cu.todus.relayvpn

import android.net.VpnService
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import kotlin.math.pow
import kotlin.random.Random

/**
 * Cliente del almacenamiento de objetos ToDus con sobre "TDS2" + HMAC-SHA256.
 *
 * Diferencias respecto a la versión original:
 *  - **Semáforo HTTP**: limita las peticiones PUT/GET simultáneas con un
 *    `Semaphore(maxConcurrentHttp)` para evitar picos que disparan rate limits.
 *  - **Backoff exponencial real**: cada reintento espera
 *    `min(initial * factor^attempt, max) + jitter` (1s, 2s, 4s, 8s… con techo).
 *  - **Circuit breaker**: tras `circuitFailThreshold` fallos consecutivos se
 *    abre el circuito y se rechazan nuevas peticiones durante `circuitOpenMs`,
 *    evitando tormentas cuando ToDus está caído.
 *  - **Reintentos en GET**: antes el GET no reintentaba; ahora sí, con backoff.
 *
 * Todos los sockets se crean protegidos con VpnService.protect() para que el
 * tráfico HTTP hacia ToDus nunca regrese por la propia VPN (evita el bucle).
 */
class TodusStore(
    private val settings: RelaySettings,
    private val vpn: VpnService?,
    private val stats: VpnStats,
) {
    private val envelopeMagic = byteArrayOf(0x54, 0x44, 0x53, 0x32) // "TDS2"
    private val tagSize = 32
    private val threadLocalMac = ThreadLocal.withInitial {
        try {
            javax.crypto.Mac.getInstance("HmacSHA256").apply {
                init(javax.crypto.spec.SecretKeySpec(settings.sharedSecret, "HmacSHA256"))
            }
        } catch (e: Exception) {
            throw IllegalStateException("HmacSHA256 no disponible", e)
        }
    }

    private val client: OkHttpClient = buildClient()

    /**
     * Semáforo que limita las peticiones HTTP simultáneas. Adquirir antes de
     * cada `client.newCall(...).execute()` y liberar siempre al terminar.
     * Justo (fair=true) para evitar inanición de sesiones nuevas.
     */
    private val httpSemaphore = Semaphore(settings.maxConcurrentHttp.coerceAtLeast(1), true)

    // ─── Circuit breaker ────────────────────────────────────────────────────
    @Volatile private var consecutiveFailures = 0
    @Volatile private var circuitOpenUntil: Long = 0L

    private fun buildClient(): OkHttpClient {
        val timeoutSeconds = settings.httpTimeout.toLong()
        // Pool más pequeño para no acumular sockets abiertos contra un servidor
        // con rate limit (cada socket consume memoria y FD).
        val pool = okhttp3.ConnectionPool(
            maxIdleConnections = settings.maxConcurrentHttp.coerceAtLeast(4),
            keepAliveDuration = 3,
            TimeUnit.MINUTES,
        )
        val dispatcher = okhttp3.Dispatcher().apply {
            // El dispatcher de OkHttp también acota la concurrencia global; lo
            // dejamos coherente con el semáforo.
            maxRequests = settings.maxConcurrentHttp.coerceAtLeast(4)
            maxRequestsPerHost = settings.maxConcurrentHttp.coerceAtLeast(4)
        }
        val builder = OkHttpClient.Builder()
            .dispatcher(dispatcher)
            .connectionPool(pool)
            .connectTimeout(timeoutSeconds, TimeUnit.SECONDS)
            .readTimeout(timeoutSeconds, TimeUnit.SECONDS)
            .writeTimeout(timeoutSeconds, TimeUnit.SECONDS)
            // Apagamos el reintento automático de OkHttp: lo gestionamos nosotros
            // con backoff + circuit breaker para no duplicar peticiones.
            .retryOnConnectionFailure(false)
        if (vpn != null) {
            builder.socketFactory(ProtectedSocketFactory(vpn))
        }
        if (!settings.verifyTls) {
            val trustManager = trustAllManager()
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, arrayOf(trustManager), SecureRandom())
            builder.sslSocketFactory(sslContext.socketFactory, trustManager)
            builder.hostnameVerifier { _, _ -> true }
        }
        return builder.build()
    }

    private fun trustAllManager(): X509TrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    /** SocketFactory que marca cada socket con protect() ANTES de conectar. */
    class ProtectedSocketFactory(private val vpn: VpnService) : SocketFactory() {
        override fun createSocket(): Socket = Socket().also { vpn.protect(it) }

        override fun createSocket(host: String, port: Int): Socket {
            val socket = Socket()
            vpn.protect(socket)
            socket.connect(InetSocketAddress(host, port), 0)
            return socket
        }

        override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket {
            val socket = Socket()
            vpn.protect(socket)
            socket.bind(java.net.InetSocketAddress(localHost, localPort))
            socket.connect(java.net.InetSocketAddress(host, port), 0)
            return socket
        }

        override fun createSocket(host: InetAddress, port: Int): Socket {
            val socket = Socket()
            vpn.protect(socket)
            socket.connect(java.net.InetSocketAddress(host, port), 0)
            return socket
        }

        override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket {
            val socket = Socket()
            vpn.protect(socket)
            socket.bind(java.net.InetSocketAddress(localAddress, localPort))
            socket.connect(java.net.InetSocketAddress(address, port), 0)
            return socket
        }
    }

    // ------------------------------------------------------------------ URL y sobre

    private fun url(key: String): String {
        val safeKey = key.split("/").joinToString("/") { percentEncode(it) }
        return "${settings.baseUrl}/$safeKey"
    }

    private fun percentEncode(part: String): String {
        val sb = StringBuilder()
        for (b in part.toByteArray(Charsets.UTF_8)) {
            val c = b.toInt() and 0xFF
            if (c in 'A'.code..'Z'.code || c in 'a'.code..'z'.code || c in '0'.code..'9'.code ||
                c == '-'.code || c == '.'.code || c == '_'.code || c == '~'.code
            ) {
                sb.append(c.toChar())
            } else {
                sb.append(String.format(Locale.US, "%%%02X", c))
            }
        }
        return sb.toString()
    }

    private fun seal(key: String, data: ByteArray): ByteArray {
        val message = key.toByteArray(Charsets.UTF_8) + ZERO + data
        val tag = threadLocalMac.get().doFinal(message)
        return envelopeMagic + tag + data
    }

    private fun open(key: String, envelope: ByteArray): ByteArray? {
        if (envelope.size < 4 + tagSize || !envelope.copyOfRange(0, 4).contentEquals(envelopeMagic)) {
            AppLog.w("[ToDus AUTH] sobre inválido: $key")
            return null
        }
        val tag = envelope.copyOfRange(4, 4 + tagSize)
        val data = envelope.copyOfRange(4 + tagSize, envelope.size)
        val message = key.toByteArray(Charsets.UTF_8) + ZERO + data
        val expected = threadLocalMac.get().doFinal(message)
        if (!java.security.MessageDigest.isEqual(tag, expected)) {
            AppLog.w("[ToDus AUTH] firma no válida: $key")
            return null
        }
        return data
    }

    private fun baseRequestBuilder(): Request.Builder {
        val builder = Request.Builder()
            .header("User-Agent", "curl/8.23.0")
        if (settings.hostHeader != null) {
            builder.header("Host", settings.hostHeader)
        }
        return builder
    }

    // ------------------------------------------------------------------ Backoff y circuit breaker

    /**
     * `true` si el circuito está abierto y la petición debería fallar rápido.
     * Abre tras `circuitFailThreshold` fallos consecutivos y se cierra pasado
     * `circuitOpenMs`.
     */
    private fun isCircuitOpen(): Boolean {
        val until = circuitOpenUntil
        if (until == 0L) return false
        if (System.currentTimeMillis() >= until) {
            // half-open: dejamos pasar la próxima petición
            circuitOpenUntil = 0L
            return false
        }
        return true
    }

    private fun recordSuccess() {
        consecutiveFailures = 0
        circuitOpenUntil = 0L
    }

    private fun recordFailure() {
        consecutiveFailures++
        if (consecutiveFailures >= settings.circuitFailThreshold && circuitOpenUntil == 0L) {
            circuitOpenUntil = System.currentTimeMillis() + settings.circuitOpenMs
            stats.circuitOpenCount.incrementAndGet()
            AppLog.w("[ToDus] circuito abierto durante ${settings.circuitOpenMs}ms " +
                "(fallos consecutivos=$consecutiveFailures)")
        }
    }

    /** Espera exponencial: `min(initial * factor^attempt, max) + jitter`. */
    private fun backoffSleep(attempt: Int): Boolean {
        val raw = settings.backoffInitialMs *
            settings.backoffFactor.pow(attempt.coerceAtMost(20))
        val capped = raw.toLong().coerceAtMost(settings.backoffMaxMs)
        val jitter = if (settings.backoffJitterMs > 0) {
            Random.nextLong(0, settings.backoffJitterMs)
        } else 0L
        val total = (capped + jitter).coerceAtLeast(1L)
        stats.backoffEvents.incrementAndGet()
        AppLog.w("[ToDus] backoff intento #${attempt + 1}: esperando ${total}ms")
        return try {
            Thread.sleep(total)
            true
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
    }

    /**
     * Adquiere el semáforo HTTP con un timeout proporcional al de la petición.
     * Devuelve `true` si se adquirió; `false` si se interrumpió o agotó.
     */
    private fun acquireHttpSlot(): Boolean {
        if (httpSemaphore.availablePermits() == 0) {
            stats.httpSemaphoreWait.incrementAndGet()
        }
        return try {
            httpSemaphore.tryAcquire(settings.httpTimeout.toLong(), TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
    }

    private fun releaseHttpSlot() {
        httpSemaphore.release()
    }

    // ------------------------------------------------------------------ GET/PUT/DELETE

    fun get(key: String): ByteArray? {
        if (isCircuitOpen()) {
            AppLog.w("[ToDus GET] circuito abierto; se ignora: $key")
            return null
        }
        if (!acquireHttpSlot()) {
            AppLog.w("[ToDus GET] semáforo HTTP agotado: $key")
            stats.storeGetFail.incrementAndGet()
            return null
        }
        try {
            val attempts = settings.httpRetries + 1
            for (attempt in 0 until attempts) {
                if (attempt > 0 && !backoffSleep(attempt - 1)) return null
                try {
                    val request = baseRequestBuilder().url(url(key)).get().build()
                    client.newCall(request).execute().use { response ->
                        return when {
                            response.code == 200 -> {
                                val body = response.body?.bytes() ?: ByteArray(0)
                                val opened = open(key, body)
                                if (opened != null) {
                                    recordSuccess()
                                    stats.storeGetOk.incrementAndGet()
                                } else {
                                    recordFailure()
                                    stats.storeGetFail.incrementAndGet()
                                }
                                opened
                            }
                            response.code == 403 || response.code == 404 -> {
                                // Ausencia legítima: no es un fallo de red.
                                recordSuccess()
                                null
                            }
                            else -> {
                                AppLog.w("[ToDus GET] HTTP ${response.code}: $key")
                                recordFailure()
                                stats.storeGetFail.incrementAndGet()
                                if (response.code < 500) return null
                                // 5xx: dejar que el bucle reintente con backoff.
                                null
                            }
                        }
                    }
                } catch (e: IOException) {
                    AppLog.w("[ToDus GET] $key: ${e.message}")
                    recordFailure()
                    if (attempt >= settings.httpRetries) {
                        stats.storeGetFail.incrementAndGet()
                        return null
                    }
                }
            }
        } finally {
            releaseHttpSlot()
        }
        stats.storeGetFail.incrementAndGet()
        return null
    }

    fun put(key: String, data: ByteArray): Boolean {
        if (isCircuitOpen()) {
            AppLog.w("[ToDus PUT] circuito abierto; se ignora: $key")
            stats.storePutFail.incrementAndGet()
            return false
        }
        if (!acquireHttpSlot()) {
            AppLog.w("[ToDus PUT] semáforo HTTP agotado: $key")
            stats.storePutFail.incrementAndGet()
            return false
        }
        val payload = seal(key, data)
        try {
            val attempts = settings.httpRetries + 1
            for (attempt in 0 until attempts) {
                if (attempt > 0 && !backoffSleep(attempt - 1)) {
                    stats.storePutFail.incrementAndGet()
                    return false
                }
                try {
                    val request = baseRequestBuilder()
                        .url(url(key))
                        .put(payload.toRequestBody(null))
                        .build()
                    client.newCall(request).execute().use { response ->
                        if (response.code in 200..299) {
                            recordSuccess()
                            stats.storePutOk.incrementAndGet()
                            return true
                        }
                        AppLog.w("[ToDus PUT] HTTP ${response.code}: $key")
                        recordFailure()
                        if (response.code < 500) {
                            stats.storePutFail.incrementAndGet()
                            return false
                        }
                    }
                } catch (e: IOException) {
                    AppLog.w("[ToDus PUT] $key: ${e.message}")
                    recordFailure()
                    if (attempt >= settings.httpRetries) {
                        stats.storePutFail.incrementAndGet()
                        return false
                    }
                }
            }
        } finally {
            releaseHttpSlot()
        }
        stats.storePutFail.incrementAndGet()
        return false
    }

    fun delete(key: String): Boolean {
        if (isCircuitOpen()) return false
        if (!acquireHttpSlot()) return false
        try {
            return try {
                val request = baseRequestBuilder().url(url(key)).delete().build()
                client.newCall(request).execute().use { response ->
                    if (response.code == 200 || response.code == 202 || response.code == 204 || response.code == 404) {
                        recordSuccess()
                        stats.storeDeleteOk.incrementAndGet()
                        true
                    } else {
                        if (response.code != 403 && response.code != 405 && response.code != 501) {
                            AppLog.w("[ToDus DELETE] HTTP ${response.code}: $key")
                        }
                        recordFailure()
                        false
                    }
                }
            } catch (e: IOException) {
                AppLog.w("[ToDus DELETE] $key: ${e.message}")
                recordFailure()
                false
            }
        } finally {
            releaseHttpSlot()
        }
    }

    companion object {
        private val ZERO = byteArrayOf(0)
    }
}
