package app.mikaki.attestation

import com.android.keyattestation.verifier.*
import com.android.keyattestation.verifier.testing.FakeCalendar
import com.android.keyattestation.verifier.testing.KeyAttestationCertPathFactory
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.protobuf.ByteString
import java.math.BigInteger
import java.net.InetSocketAddress
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.cert.TrustAnchor
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.time.Instant
import java.time.LocalDate
import java.time.YearMonth
import java.time.ZoneOffset
import java.util.Base64
import java.util.concurrent.ExecutorService
import java.util.concurrent.atomic.AtomicReference

/**
 * Test-only PKI and status source. The real verifier and HTTP handler run without verdict mocks.
 */
fun main() {
  val today = LocalDate.now(ZoneOffset.UTC)
  val patch = YearMonth.from(today)
  val policy =
    Policy.parse(
      """{"format":"mikaki-android-verifier-policy-v1","client_id":"native-fixture","package_name":"app.tossa.mikaki","signing_certificate_sha256":["${"11".repeat(32)}"],"minimum_version":10,"minimum_os_version":140000,"minimum_os_patch":"$patch","minimum_vendor_patch":"$patch","minimum_boot_patch":"$patch","security_level":"tee","max_status_age_seconds":900}"""
        .toByteArray()
    )
  val factory = KeyAttestationCertPathFactory(FakeCalendar(today))
  val status = AtomicReference("good")
  val token = System.getenv("MIKAKI_ANDROID_VERIFIER_TOKEN") ?: error("Missing test token")
  val verifier =
    Verification(
      policy,
      {
        when (status.get()) {
          "unavailable" -> throw StatusUnavailable()
          "stale" -> Status(emptySet(), Instant.now().minusSeconds(1))
          "revoked" ->
            Status(setOf(factory.root.serialNumber.toString(16)), Instant.now().plusSeconds(900))
          else -> Status(emptySet(), Instant.now().plusSeconds(900))
        }
      },
      { setOf(TrustAnchor(factory.root, null)) },
    )
  val http = server(verifier, token, InetSocketAddress("127.0.0.1", 0))
  http.start()
  println(
    JsonObject().apply {
      addProperty("verify_url", "http://127.0.0.1:${http.address.port}/verify")
      addProperty("policy_hash", policy.hash)
    }
  )
  try {
    while (true) {
      // Bound the test control protocol too; commands contain public keys, never wallet secrets.
      val bytes = ArrayList<Byte>()
      var end = false
      while (true) {
        val value = System.`in`.read()
        if (value == -1) {
          end = true
          break
        }
        if (value == 10) break
        require(bytes.size < 4096)
        bytes.add(value.toByte())
      }
      if (end) break
      val command = strictJson(bytes.toByteArray())
      val result =
        when (text(command, "command")) {
          "status" -> {
            val mode = text(command, "mode")
            require(mode in setOf("good", "unavailable", "stale", "revoked"))
            status.set(mode)
            JsonObject().apply { addProperty("ok", true) }
          }
          "certificate" -> {
            val nonce = b64url(text(command, "challenge")).also { require(it.size == 32) }
            val jwk = command.getAsJsonObject("public_key")
            checkKeys(jwk, setOf("kty", "crv", "x", "y"))
            require(text(jwk, "kty") == "EC" && text(jwk, "crv") == "P-256")
            fun coordinate(name: String) =
              BigInteger(1, b64url(text(jwk, name)).also { require(it.size == 32) })
            val params =
              AlgorithmParameters.getInstance("EC")
                .apply { init(ECGenParameterSpec("secp256r1")) }
                .getParameterSpec(ECParameterSpec::class.java)
            val key =
              KeyFactory.getInstance("EC")
                .generatePublic(ECPublicKeySpec(ECPoint(coordinate("x"), coordinate("y")), params))
            val badApp = command["bad_app"]?.asBoolean ?: false
            val description =
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
                      setOf(
                        AttestationPackageInfo(
                          if (badApp) "other.app" else policy.packageName,
                          10.toBigInteger(),
                        )
                      ),
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
                  osPatchLevel = PatchLevel(patch),
                  vendorPatchLevel = PatchLevel(patch, 1),
                  bootPatchLevel = PatchLevel(patch, 1),
                ),
              )
            val remote = command["remote"]?.asBoolean ?: false
            JsonObject().apply {
              add(
                "certificate_chain",
                JsonArray().apply {
                  factory
                    .generateCertPath(description, remote, key)
                    .certificatesWithAnchor
                    .forEach { add(Base64.getEncoder().encodeToString(it.encoded)) }
                },
              )
            }
          }
          else -> error("Unknown test command")
        }
      println(result)
    }
  } finally {
    http.stop(0)
    (http.executor as ExecutorService).shutdownNow()
  }
}
