package app.mikaki.attestation

import com.android.keyattestation.verifier.*
import com.android.keyattestation.verifier.testing.FakeCalendar
import com.android.keyattestation.verifier.testing.KeyAttestationCertPathFactory
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.protobuf.ByteString
import java.math.BigInteger
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyPairGenerator
import java.security.cert.TrustAnchor
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.time.LocalDate
import java.time.YearMonth
import java.util.Base64
import kotlin.test.*

class VerificationTest {
  private val at = Instant.parse("2026-10-03T00:00:00Z")
  private val policy =
    Policy.parse(
      """{"format":"mikaki-android-verifier-policy-v1","client_id":"native-fixture","package_name":"app.tossa.mikaki","signing_certificate_sha256":["${"11".repeat(32)}"],"minimum_version":10,"minimum_os_version":140000,"minimum_os_patch":"2026-09","minimum_vendor_patch":"2026-09","minimum_boot_patch":"2026-09","security_level":"tee","max_status_age_seconds":900}"""
        .toByteArray()
    )
  private val factory = KeyAttestationCertPathFactory(FakeCalendar(LocalDate.of(2026, 10, 3)))
  private val key =
    KeyPairGenerator.getInstance("EC")
      .apply { initialize(ECGenParameterSpec("secp256r1")) }
      .generateKeyPair()
      .public as ECPublicKey
  private val nonce = ByteArray(32) { 7 }

  private fun description() =
    KeyDescription(
      4.toBigInteger(),
      SecurityLevel.TRUSTED_ENVIRONMENT,
      41.toBigInteger(),
      SecurityLevel.TRUSTED_ENVIRONMENT,
      ByteString.copyFrom(nonce),
      ByteString.EMPTY,
      AuthorizationList(
        attestationApplicationId =
          AttestationApplicationId(
            setOf(AttestationPackageInfo("app.tossa.mikaki", 10.toBigInteger())),
            setOf(ByteString.copyFrom(ByteArray(32) { 0x11 })),
          )
      ),
      AuthorizationList(
        purposes = setOf(BigInteger.TWO),
        algorithms = 3.toBigInteger(),
        keySize = 256.toBigInteger(),
        digests = setOf(4.toBigInteger()),
        ecCurve = BigInteger.ONE,
        noAuthRequired = true,
        origin = Origin.GENERATED,
        rootOfTrust =
          RootOfTrust(
            ByteString.copyFrom(ByteArray(32) { 1 }),
            true,
            VerifiedBootState.VERIFIED,
            ByteString.copyFrom(ByteArray(32) { 2 }),
          ),
        osVersion = 140000.toBigInteger(),
        osPatchLevel = PatchLevel(YearMonth.of(2026, 9)),
        vendorPatchLevel = PatchLevel(YearMonth.of(2026, 9), 1),
        bootPatchLevel = PatchLevel(YearMonth.of(2026, 9), 1),
      ),
    )

  private fun request(d: KeyDescription = description(), remote: Boolean = false): JsonObject {
    val chain = factory.generateCertPath(d, remote, key).certificatesWithAnchor
    val b64 = Base64.getUrlEncoder().withoutPadding()
    fun coord(n: BigInteger): String {
      val raw = n.toByteArray().takeLast(32).toByteArray()
      return b64.encodeToString(ByteArray(32 - raw.size) + raw)
    }
    return JsonObject().apply {
      addProperty("format", "android-key-attestation-verification-v1")
      addProperty("client_id", policy.client)
      addProperty("purpose", "client")
      addProperty("verifier_policy_hash", policy.hash)
      add(
        "evidence",
        JsonObject().apply {
          addProperty("challenge", b64.encodeToString(nonce))
          add(
            "public_key",
            JsonObject().apply {
              addProperty("kty", "EC")
              addProperty("crv", "P-256")
              addProperty("x", coord(key.w.affineX))
              addProperty("y", coord(key.w.affineY))
            },
          )
          add(
            "certificate_chain",
            JsonArray().apply {
              chain.forEach { add(Base64.getEncoder().encodeToString(it.encoded)) }
            },
          )
        },
      )
    }
  }

  private fun verifier(blocked: Set<String> = emptySet(), until: Instant = at.plusSeconds(900)) =
    Verification(
      policy,
      { Status(blocked, until) },
      { setOf(TrustAnchor(factory.root, null)) },
      { at },
    )

  @Test
  fun officialVerifierAcceptsBoundFixtureForFactoryAndRemoteChains() {
    for (remote in listOf(false, true)) for (purpose in listOf("client", "holder")) {
      val body = request(remote = remote).apply { addProperty("purpose", purpose) }
      val result = verifier().verify(body)
      assertTrue(result["verified"].asBoolean)
      assertEquals(at.epochSecond + 60, result["expires_at"].asLong)
      assertEquals(body["evidence"].asJsonObject["public_key"], result["public_key"])
      assertEquals(8, result.size())
    }
  }

  @Test
  fun rejectsWrongContextChallengeKeyTamperingAndUntrustedRoot() {
    for (field in listOf("client_id", "purpose", "verifier_policy_hash", "format")) {
      assertFails { verifier().verify(request().apply { addProperty(field, "wrong") }) }
    }
    assertFails {
      verifier()
        .verify(
          request().apply {
            getAsJsonObject("evidence")
              .addProperty(
                "challenge",
                Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 8 }),
              )
          }
        )
    }
    assertFails {
      verifier()
        .verify(
          request().apply {
            getAsJsonObject("evidence")
              .getAsJsonObject("public_key")
              .addProperty(
                "x",
                Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32)),
              )
          }
        )
    }
    assertFails {
      Verification(policy, { Status(emptySet(), at.plusSeconds(900)) }, clock = { at })
        .verify(request())
    }
    val tampered = request()
    val chain = tampered.getAsJsonObject("evidence").getAsJsonArray("certificate_chain")
    val der = Base64.getDecoder().decode(chain[0].asString)
    der[der.lastIndex] = (der.last().toInt() xor 1).toByte()
    chain.set(0, com.google.gson.JsonPrimitive(Base64.getEncoder().encodeToString(der)))
    assertFails { verifier().verify(tampered) }
  }

  @Test
  fun rejectsMissingWrongAndDowngradedHardwareAppAndPatchAttributes() {
    val d = description()
    val h = d.hardwareEnforced
    val s = d.softwareEnforced
    val app = s.attestationApplicationId!!
    val wrongApps =
      listOf(
        null,
        AttestationApplicationId(
          setOf(AttestationPackageInfo("other.app", 10.toBigInteger())),
          app.signatures,
        ),
        app.copy(packages = setOf(AttestationPackageInfo("app.tossa.mikaki", BigInteger.ONE))),
        app.copy(signatures = setOf(ByteString.copyFrom(ByteArray(32) { 9 }))),
        app.copy(packages = app.packages + AttestationPackageInfo("other.app", 10.toBigInteger())),
      )
    val bad =
      listOf(
        d.copy(attestationSecurityLevel = SecurityLevel.SOFTWARE),
        d.copy(keyMintSecurityLevel = SecurityLevel.SOFTWARE),
        d.copy(uniqueId = ByteString.copyFromUtf8("identifier")),
        d.copy(hardwareEnforced = h.copy(purposes = setOf(BigInteger.ZERO))),
        d.copy(hardwareEnforced = h.copy(digests = setOf(BigInteger.TWO))),
        d.copy(hardwareEnforced = h.copy(origin = Origin.IMPORTED)),
        d.copy(hardwareEnforced = h.copy(noAuthRequired = false)),
        d.copy(hardwareEnforced = h.copy(rootOfTrust = h.rootOfTrust!!.copy(deviceLocked = false))),
        d.copy(
          hardwareEnforced =
            h.copy(
              rootOfTrust = h.rootOfTrust!!.copy(verifiedBootState = VerifiedBootState.UNVERIFIED)
            )
        ),
        d.copy(hardwareEnforced = h.copy(osVersion = 130000.toBigInteger())),
        d.copy(hardwareEnforced = h.copy(osPatchLevel = PatchLevel(YearMonth.of(2026, 8)))),
        d.copy(hardwareEnforced = h.copy(vendorPatchLevel = null)),
        d.copy(hardwareEnforced = h.copy(bootPatchLevel = PatchLevel(YearMonth.of(2027, 1)))),
        d.copy(softwareEnforced = s.copy(purposes = setOf(BigInteger.TWO))),
      ) + wrongApps.map { d.copy(softwareEnforced = s.copy(attestationApplicationId = it)) }
    for (item in bad) assertFails { verifier().verify(request(item)) }
  }

  @Test
  fun statusFailsClosedForSuspendedRevokedStaleUnknownAndDuplicates() {
    val body = request()
    val serial = factory.root.serialNumber.toString(16)
    for (status in listOf("REVOKED", "SUSPENDED")) {
      val blocked = parseStatus("""{"entries":{"$serial":{"status":"$status"}}}""".toByteArray())
      assertFails { verifier(blocked).verify(body) }
    }
    assertFails { verifier(until = at).verify(body) }
    assertFails { parseStatus("""{"entries":{"abc":{"status":"UNKNOWN"}}}""".toByteArray()) }
    assertFails { strictJson("""{"entries":{},"entries":{}}""".toByteArray()) }
    assertFails { strictJson("""{"a":1} trailing""".toByteArray()) }
    assertEquals(emptySet(), parseStatus("""{"entries":{}}""".toByteArray()))
  }

  @Test
  fun httpRequiresAuthorizationAndHasNoDetailedErrorResponse() {
    val token = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 9 })
    val server = server(verifier(), token, InetSocketAddress("127.0.0.1", 0))
    server.start()
    try {
      val client = HttpClient.newHttpClient()
      val uri = URI.create("http://127.0.0.1:${server.address.port}/verify")
      fun call(auth: String, body: String = request().toString(), path: URI = uri) =
        client.send(
          HttpRequest.newBuilder(path)
            .header("Authorization", auth)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build(),
          HttpResponse.BodyHandlers.ofString(),
        )
      assertEquals(401, call("Bearer wrong").statusCode())
      assertEquals(200, call("Bearer $token").statusCode())
      val bad = call("Bearer $token", "{}")
      assertEquals(400, bad.statusCode())
      assertEquals("{\"verified\":false}", bad.body())
      assertEquals("no-store", bad.headers().firstValue("cache-control").get())
      assertEquals(404, call("Bearer $token", path = URI.create("$uri?other")).statusCode())
      assertEquals(400, call("Bearer $token", "x".repeat(65537)).statusCode())
    } finally {
      server.stop(0)
      (server.executor as java.util.concurrent.ExecutorService).shutdownNow()
    }
  }

  @Test
  fun duplicateAndUnorderedSignedAuthorizationTagsAreRejected() {
    val original = description().encodeToAsn1()
    strictAuthorizationDescription(original)
    val root = org.bouncycastle.asn1.ASN1Sequence.getInstance(original)
    val hardware = org.bouncycastle.asn1.ASN1Sequence.getInstance(root.getObjectAt(7))
    val fields = hardware.toArray().toList()
    for (changed in listOf(listOf(fields.first()) + fields, fields.reversed())) {
      val parts = root.toArray()
      parts[7] = org.bouncycastle.asn1.DERSequence(changed.toTypedArray())
      assertFails {
        strictAuthorizationDescription(org.bouncycastle.asn1.DERSequence(parts).getEncoded("DER"))
      }
    }
  }

  @Test
  fun statusCacheHonorsHttpAgeAndDoesNotReuseExpiredStatusAfterFetchFailure() {
    var time = at
    var calls = 0
    var statusCode = 200
    var directives = "public, max-age=600"
    var age = "500"
    val source =
      GoogleStatus(900, { time }) {
        calls++
        object :
          java.net.HttpURLConnection(
            java.net.URI.create("https://android.googleapis.com/attestation/status").toURL()
          ) {
          override fun connect() {}

          override fun disconnect() {}

          override fun usingProxy() = false

          override fun getResponseCode() = statusCode

          override fun getContentType() = "application/json"

          override fun getHeaderField(name: String) =
            when (name) {
              "Cache-Control" -> directives
              "Age" -> age
              else -> null
            }

          override fun getInputStream() = """{"entries":{}}""".byteInputStream()
        }
      }
    assertEquals(at.plusSeconds(100), source().until)
    time = at.plusSeconds(99)
    source()
    assertEquals(1, calls)
    time = at.plusSeconds(100)
    statusCode = 503
    assertFailsWith<StatusUnavailable> { source() }
    assertEquals(2, calls)
    statusCode = 200
    age = "600"
    assertFailsWith<StatusUnavailable> { source() }
    age = "0"
    directives = "no-store, max-age=600"
    assertFailsWith<StatusUnavailable> { source() }
    directives = "max-age=600, max-age=700"
    assertFailsWith<StatusUnavailable> { source() }
    directives = "max-age=86400"
    assertEquals(time.plusSeconds(900), source().until)
  }
}
