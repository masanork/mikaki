package app.mikaki.attestation

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.nio.file.Path
import java.security.MessageDigest
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

internal fun server(verifier: Verification, token: String, address: InetSocketAddress): HttpServer {
  require(b64url(token).size == 32)
  val expected = MessageDigest.getInstance("SHA-256").digest("Bearer $token".toByteArray())
  return HttpServer.create(address, 16).apply {
    executor =
      ThreadPoolExecutor(
        4,
        4,
        0,
        TimeUnit.SECONDS,
        ArrayBlockingQueue(8),
        ThreadPoolExecutor.AbortPolicy(),
      )
    createContext("/verify") { exchange ->
      var code = 400
      var body = "{\"verified\":false}".toByteArray()
      try {
        val auth = exchange.requestHeaders.getFirst("Authorization").orEmpty()
        val actual = MessageDigest.getInstance("SHA-256").digest(auth.toByteArray())
        if (auth.length > 512 || !MessageDigest.isEqual(actual, expected)) {
          code = 401
        } else if (
          exchange.requestMethod != "POST" || exchange.requestURI.toString() != "/verify"
        ) {
          code = 404
        } else if (
          exchange.requestHeaders.getFirst("Content-Type")?.substringBefore(';')?.trim() !=
            "application/json"
        ) {
          code = 415
        } else {
          val bytes = exchange.requestBody.use { it.readNBytes(65537) }
          require(bytes.size <= 65536)
          body = verifier.verify(strictJson(bytes)).toString().toByteArray()
          code = 200
        }
      } catch (_: StatusUnavailable) {
        code = 503
      } catch (_: Exception) {
        code = 400
      }
      // Fixed errors; no certificates, device properties, challenge or exception diagnostics in
      // logs.
      exchange.use {
        it.responseHeaders.set("Content-Type", "application/json")
        it.responseHeaders.set("Cache-Control", "no-store")
        it.sendResponseHeaders(code, body.size.toLong())
        it.responseBody.use { stream -> stream.write(body) }
      }
    }
  }
}

fun main(args: Array<String>) {
  val path = System.getenv("MIKAKI_ANDROID_POLICY_FILE") ?: error("Missing policy file")
  val policy = Policy.read(Path.of(path))
  if (args.contentEquals(arrayOf("--policy-hash"))) {
    println(policy.hash)
    return
  }
  require(args.isEmpty())
  val token = System.getenv("MIKAKI_ANDROID_VERIFIER_TOKEN") ?: error("Missing verifier token")
  System.setProperty("sun.net.httpserver.maxReqTime", "5")
  System.setProperty("sun.net.httpserver.maxRspTime", "5")
  System.setProperty("sun.net.httpserver.maxIdleConnections", "16")
  val port = System.getenv("PORT")?.toInt() ?: 8080
  val host = System.getenv("BIND_ADDRESS") ?: "127.0.0.1"
  server(
      Verification(policy, GoogleStatus(policy.maxStatusAge)),
      token,
      InetSocketAddress(host, port),
    )
    .start()
}
