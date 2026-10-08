package app.mikaki.attestation

import com.android.keyattestation.verifier.GoogleTrustAnchors
import com.google.gson.JsonObject
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.YearMonth
import java.util.Base64

internal const val REVISION = "3f550f94a9e3c010dda7cdcad8bca764cd76d4f4"

internal fun checkKeys(o: JsonObject, required: Set<String>, optional: Set<String> = emptySet()) {
  require(o.keySet().containsAll(required) && o.keySet().all { it in required || it in optional })
}

internal fun text(o: JsonObject, k: String): String {
  val p = o[k].asJsonPrimitive
  require(p.isString)
  return p.asString
}

internal fun number(o: JsonObject, k: String): BigInteger {
  val p = o[k].asJsonPrimitive
  require(p.isNumber && p.toString().matches(Regex("0|[1-9][0-9]{0,17}")))
  return p.asBigInteger
}

internal fun b64url(s: String): ByteArray {
  val b = Base64.getUrlDecoder().decode(s)
  require(Base64.getUrlEncoder().withoutPadding().encodeToString(b) == s)
  return b
}

internal fun digest(b: ByteArray): String =
  Base64.getUrlEncoder()
    .withoutPadding()
    .encodeToString(MessageDigest.getInstance("SHA-256").digest(b))

internal data class Policy(
  val client: String,
  val packageName: String,
  val signatures: Set<String>,
  val minimumVersion: BigInteger,
  val minimumOs: BigInteger,
  val minimumOsPatch: YearMonth,
  val minimumVendorPatch: YearMonth,
  val minimumBootPatch: YearMonth,
  val security: String,
  val maxStatusAge: Long,
  val hash: String,
) {
  companion object {
    fun parse(bytes: ByteArray): Policy {
      require(bytes.size in 1..16384)
      val o = strictJson(bytes)
      checkKeys(
        o,
        setOf(
          "format",
          "client_id",
          "package_name",
          "signing_certificate_sha256",
          "minimum_version",
          "minimum_os_version",
          "minimum_os_patch",
          "minimum_vendor_patch",
          "minimum_boot_patch",
          "security_level",
          "max_status_age_seconds",
        ),
      )
      require(text(o, "format") == "mikaki-android-verifier-policy-v1")
      val client = text(o, "client_id").also { require(it.length in 1..256) }
      val packageName =
        text(o, "package_name").also {
          require(
            it.length <= 256 &&
              it.matches(Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+"))
          )
        }
      val signatures =
        o["signing_certificate_sha256"].asJsonArray.map {
          require(it.asJsonPrimitive.isString)
          it.asString.also { s -> require(s.matches(Regex("[0-9a-f]{64}"))) }
        }
      require(signatures.size in 1..8 && signatures.toSet().size == signatures.size)
      val minimumVersion = number(o, "minimum_version").also { require(it.signum() > 0) }
      val minimumOs =
        number(o, "minimum_os_version").also {
          require(it >= BigInteger.valueOf(100000) && it <= BigInteger.valueOf(990000))
        }
      fun patch(name: String) =
        YearMonth.parse(text(o, name)).also { require(it.year in 2020..2100) }
      val security = text(o, "security_level").also { require(it in setOf("tee", "strongbox")) }
      val age =
        number(o, "max_status_age_seconds").longValueExact().also { require(it in 60..3600) }
      // Policy identity binds exact operator bytes, pinned implementation and built-in Google
      // roots.
      val roots =
        GoogleTrustAnchors().map { digest(it.trustedCert.encoded) }.sorted().joinToString(",")
      val hash =
        digest(
          "mikaki-native-verifier-v1\n$REVISION\nbouncycastle-1.86\n$roots\n".toByteArray() + bytes
        )
      return Policy(
        client,
        packageName,
        signatures.toSet(),
        minimumVersion,
        minimumOs,
        patch("minimum_os_patch"),
        patch("minimum_vendor_patch"),
        patch("minimum_boot_patch"),
        security,
        age,
        hash,
      )
    }

    fun read(path: Path): Policy =
      Files.newInputStream(path).use {
        val b = it.readNBytes(16385)
        require(b.size <= 16384)
        parse(b)
      }
  }
}
