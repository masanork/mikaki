package app.mikaki.attestation

import java.net.HttpURLConnection
import java.net.URI
import java.time.Instant

internal class StatusUnavailable : Exception()

internal data class Status(val blocked: Set<String>, val until: Instant)

internal class GoogleStatus(
  private val maxAge: Long,
  private val clock: () -> Instant = Instant::now,
  private val connect: () -> HttpURLConnection = {
    URI.create("https://android.googleapis.com/attestation/status").toURL().openConnection()
      as HttpURLConnection
  },
) : () -> Status {
  private var cached: Status? = null

  @Synchronized
  override fun invoke(): Status {
    val now = clock()
    cached?.let { if (now < it.until) return it }
    try {
      val c = connect()
      c.instanceFollowRedirects = false
      c.connectTimeout = 2000
      c.readTimeout = 2000
      try {
        require(c.responseCode == 200)
        require(c.contentType?.substringBefore(';')?.trim() == "application/json")
        val directives =
          c.getHeaderField("Cache-Control")?.split(',')?.map { it.trim() } ?: emptyList()
        require(directives.none { it.equals("no-cache", true) || it.equals("no-store", true) })
        val ages = directives.filter { it.matches(Regex("max-age=[0-9]+")) }
        require(ages.size == 1)
        val seconds = ages.single().substringAfter('=').toLong()
        val age = c.getHeaderField("Age")?.toLong() ?: 0
        require(age >= 0 && seconds > age)
        val until = now.plusSeconds(minOf(maxAge, seconds - age))
        val deadline = System.nanoTime() + java.time.Duration.ofSeconds(4).toNanos()
        val bytes =
          c.inputStream.use { stream ->
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
              require(System.nanoTime() < deadline)
              val n = stream.read(buffer)
              if (n < 0) break
              require(output.size() + n <= 1048576)
              output.write(buffer, 0, n)
            }
            output.toByteArray()
          }
        val blocked = parseStatus(bytes)
        require(clock() < until)
        return Status(blocked, until).also { cached = it }
      } finally {
        c.disconnect()
      }
    } catch (_: Exception) {
      throw StatusUnavailable()
    }
  }
}

internal fun parseStatus(bytes: ByteArray): Set<String> {
  val o = strictJson(bytes)
  checkKeys(o, setOf("entries"))
  val entries = o["entries"].asJsonObject
  require(entries.size() <= 20000)
  return entries
    .entrySet()
    .map { (serial, value) ->
      require(serial.matches(Regex("[1-9a-f][0-9a-f]{0,127}")))
      val e = value.asJsonObject
      checkKeys(e, setOf("status"), setOf("expires", "reason", "comment"))
      // Both statuses mean unavailable. Unknown future statuses fail the entire snapshot closed.
      require(text(e, "status") in setOf("REVOKED", "SUSPENDED"))
      if (e.has("expires")) java.time.LocalDate.parse(text(e, "expires"))
      if (e.has("reason"))
        require(
          text(e, "reason") in
            setOf("UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE", "SUPERSEDED", "SOFTWARE_FLAW")
        )
      if (e.has("comment")) require(text(e, "comment").length <= 140)
      serial
    }
    .toSet()
}
