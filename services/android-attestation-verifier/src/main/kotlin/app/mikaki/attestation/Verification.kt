package app.mikaki.attestation

import com.android.keyattestation.verifier.*
import com.android.keyattestation.verifier.challengecheckers.ChallengeMatcher
import com.google.common.collect.ImmutableList
import com.google.gson.JsonObject
import com.google.protobuf.ByteString
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.cert.CertificateFactory
import java.security.cert.TrustAnchor
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.time.Instant
import java.time.YearMonth
import java.time.ZoneOffset
import java.util.Base64

internal class NativePolicy(private val p: Policy, private val at: Instant) {
  fun matches(d: KeyDescription): Boolean {
    val h = d.hardwareEnforced
    val s = d.softwareEnforced
    val app = s.attestationApplicationId
    val wanted =
      if (p.security == "strongbox") SecurityLevel.STRONG_BOX else SecurityLevel.TRUSTED_ENVIRONMENT
    val root = h.rootOfTrust
    val month = YearMonth.from(at.atZone(ZoneOffset.UTC))
    fun patch(actual: PatchLevel?, min: YearMonth) =
      actual != null && actual.yearMonth >= min && actual.yearMonth <= month
    fun absentSoftwareKey() =
      s.purposes == null &&
        s.algorithms == null &&
        s.keySize == null &&
        s.digests == null &&
        s.ecCurve == null &&
        s.origin == null &&
        s.rootOfTrust == null &&
        s.osVersion == null &&
        s.osPatchLevel == null &&
        s.vendorPatchLevel == null &&
        s.bootPatchLevel == null
    fun noIdentifiers(a: AuthorizationList) =
      listOf(
          a.attestationIdBrand,
          a.attestationIdDevice,
          a.attestationIdProduct,
          a.attestationIdSerial,
          a.attestationIdImei,
          a.attestationIdMeid,
          a.attestationIdManufacturer,
          a.attestationIdModel,
          a.attestationIdSecondImei,
        )
        .all { it == null }
    val ok =
      noIdentifiers(h) &&
        noIdentifiers(s) &&
        d.attestationVersion in setOf(3, 4, 100, 200, 300, 400, 500).map { it.toBigInteger() } &&
        d.uniqueId.isEmpty &&
        d.attestationSecurityLevel == wanted &&
        d.keyMintSecurityLevel == wanted &&
        absentSoftwareKey() &&
        h.purposes == setOf(BigInteger.TWO) &&
        h.algorithms == BigInteger.valueOf(3) &&
        h.keySize == BigInteger.valueOf(256) &&
        h.digests == setOf(BigInteger.valueOf(4)) &&
        h.ecCurve == BigInteger.ONE &&
        h.origin == Origin.GENERATED &&
        h.noAuthRequired == true &&
        h.userAuthType == null &&
        h.authTimeout == null &&
        s.userAuthType == null &&
        s.authTimeout == null &&
        root != null &&
        root.deviceLocked &&
        root.verifiedBootState == VerifiedBootState.VERIFIED &&
        root.verifiedBootKey.size() == 32 &&
        root.verifiedBootHash?.size() == 32 &&
        h.osVersion?.let { it >= p.minimumOs } == true &&
        patch(h.osPatchLevel, p.minimumOsPatch) &&
        patch(h.vendorPatchLevel, p.minimumVendorPatch) &&
        patch(h.bootPatchLevel, p.minimumBootPatch) &&
        app != null &&
        app.packages.size == 1 &&
        app.packages.single().name == p.packageName &&
        app.packages.single().version >= p.minimumVersion &&
        app.signatures.isNotEmpty() &&
        app.signatures.all { b ->
          b.size() == 32 && b.toByteArray().joinToString("") { "%02x".format(it) } in p.signatures
        }
    return ok
  }
}

internal class Verification(
  private val p: Policy,
  private val status: () -> Status,
  private val anchors: () -> Set<TrustAnchor> = GoogleTrustAnchors,
  private val clock: () -> Instant = Instant::now,
) {
  fun verify(b: JsonObject): JsonObject {
    checkKeys(b, setOf("format", "client_id", "purpose", "verifier_policy_hash", "evidence"))
    require(text(b, "format") == "android-key-attestation-verification-v1")
    require(text(b, "client_id") == p.client && text(b, "verifier_policy_hash") == p.hash)
    val purpose = text(b, "purpose").also { require(it in setOf("client", "holder")) }
    val e = b["evidence"].asJsonObject
    checkKeys(e, setOf("challenge", "public_key", "certificate_chain"))
    val challenge = text(e, "challenge")
    val nonce = b64url(challenge).also { require(it.size == 32) }
    val key = e["public_key"].asJsonObject
    checkKeys(key, setOf("kty", "crv", "x", "y"))
    require(text(key, "kty") == "EC" && text(key, "crv") == "P-256")
    val x = b64url(text(key, "x")).also { require(it.size == 32) }
    val y = b64url(text(key, "y")).also { require(it.size == 32) }
    val raw =
      e["certificate_chain"].asJsonArray.map { j ->
        require(j.asJsonPrimitive.isString && j.asString.length <= 10924)
        Base64.getDecoder().decode(j.asString).also {
          require(it.size in 1..8192 && Base64.getEncoder().encodeToString(it) == j.asString)
        }
      }
    require(
      raw.size in 2..8 &&
        raw.sumOf { it.size } <= 32768 &&
        raw.map(::digest).toSet().size == raw.size
    )
    val factory = CertificateFactory.getInstance("X.509")
    val chain =
      raw.map { der ->
        val c = factory.generateCertificate(der.inputStream()) as java.security.cert.X509Certificate
        require(c.encoded.contentEquals(der))
        c
      }
    // Unsupported critical extension semantics fail closed. The JDK parser rejects duplicate X.509
    // extensions.
    require(
      chain.all {
        it.criticalExtensionOIDs.orEmpty().all { oid -> oid in setOf("2.5.29.15", "2.5.29.19") }
      }
    )
    val trusted = anchors()
    require(trusted.any { it.trustedCert.encoded.contentEquals(chain.last().encoded) })
    require(
      chain.all { c ->
        c.sigAlgName.uppercase() in
          setOf(
            "SHA256WITHECDSA",
            "SHA384WITHECDSA",
            "SHA256WITHRSA",
            "SHA384WITHRSA",
            "SHA512WITHRSA",
          ) &&
          when (val k = c.publicKey) {
            is java.security.interfaces.RSAPublicKey -> k.modulus.bitLength() in 2048..4096
            is ECPublicKey -> k.params.curve.field.fieldSize in setOf(256, 384)
            else -> false
          }
      }
    )
    val at = clock()
    val snapshot = status()
    if (at >= snapshot.until) throw StatusUnavailable()
    require(chain.none { it.serialNumber.toString(16) in snapshot.blocked })
    val constraints =
      ConstraintConfig(
        attestationApplicationId = AttestationApplicationIdConstraint.STRICT,
        securityLevel =
          SecurityLevelConstraint.STRICT(
            if (p.security == "strongbox") SecurityLevel.STRONG_BOX
            else SecurityLevel.TRUSTED_ENVIRONMENT
          ),
        additionalConstraints =
          ImmutableList.of(
            TagOrderConstraint.STRICT,
            AttributeConstraint.STRICT("Mikaki native signing policy", true) {
              NativePolicy(p, at).matches(it)
            },
          ),
      )
    val result =
      Verifier({ trusted }, { snapshot.blocked }, { at }, constraintConfig = constraints)
        .verify(chain, ChallengeMatcher(ByteString.copyFrom(nonce)))
    require(result is VerificationResult.Success)
    strictDescription(chain.first())
    val actual = result.publicKey as ECPublicKey
    val params =
      AlgorithmParameters.getInstance("EC")
        .apply { init(ECGenParameterSpec("secp256r1")) }
        .getParameterSpec(ECParameterSpec::class.java)
    require(
      actual.params.curve == params.curve &&
        actual.params.order == params.order &&
        actual.params.generator == params.generator &&
        actual.params.cofactor == params.cofactor
    )
    require(actual.w.affineX == BigInteger(1, x) && actual.w.affineY == BigInteger(1, y))
    val until = minOf(at.plusSeconds(60), snapshot.until)
    if (clock() >= until) throw StatusUnavailable()
    return JsonObject().apply {
      addProperty("format", "android-key-attestation-verdict-v1")
      addProperty("verified", true)
      addProperty("client_id", p.client)
      addProperty("purpose", purpose)
      addProperty("challenge", challenge)
      add("public_key", key.deepCopy())
      addProperty("verifier_policy_hash", p.hash)
      addProperty("expires_at", until.epochSecond)
    }
  }
}

// Upstream AuthorizationList parsing normalizes tags into a map. Reject ambiguity
// in the signed encoding as well, rather than accepting overwritten duplicates.
internal fun strictDescription(c: java.security.cert.X509Certificate) {
  val wrapped = c.getExtensionValue("1.3.6.1.4.1.11129.2.1.17") ?: error("Missing attestation")
  val bytes = org.bouncycastle.asn1.ASN1OctetString.getInstance(wrapped).octets
  strictAuthorizationDescription(bytes)
}

internal fun strictAuthorizationDescription(bytes: ByteArray) {
  val root = org.bouncycastle.asn1.ASN1Sequence.getInstance(bytes)
  require(root.size() == 8 && root.getEncoded("DER").contentEquals(bytes))
  for (index in listOf(6, 7)) {
    val list = org.bouncycastle.asn1.ASN1Sequence.getInstance(root.getObjectAt(index))
    var previous = -1
    for (field in list) {
      val tag = field as org.bouncycastle.asn1.ASN1TaggedObject
      require(
        tag.tagClass == org.bouncycastle.asn1.BERTags.CONTEXT_SPECIFIC &&
          tag.isExplicit &&
          tag.tagNo > previous
      )
      previous = tag.tagNo
    }
  }
}
