package org.multipaz.mdoc.response

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.Simple
import org.multipaz.cbor.addCborArray
import org.multipaz.cbor.buildCborArray
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcPublicKey
import org.multipaz.sdjwt.SdJwtKb
import org.multipaz.util.Logger
import org.multipaz.util.fromBase64Url
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Unmodified SDK validators consume a synthetic native Rust presentation; no private holder key is supplied. */
class MikakiPresentationTest {
    @Test
    fun verifiesNativeMixedPresentation() = runBlocking {
        val bridge = System.getenv("MIKAKI_MULTIPAZ_BRIDGE") ?: error("Missing test bridge")
        val secret = System.getenv("MIKAKI_MULTIPAZ_BRIDGE_SECRET") ?: error("Missing bridge authorization")
        val printer = Logger.logPrinter
        Logger.logPrinter = Logger.LogPrinter { _, _, _, _ -> }
        try {
            val response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(bridge)).header("Authorization", "Bearer $secret").GET().build(),
                HttpResponse.BodyHandlers.ofString()
            )
            assertEquals(200, response.statusCode())
            val input = Json.parseToJsonElement(response.body()).jsonObject
            fun text(name: String) = input[name]!!.jsonPrimitive.content
            val at = text("at").toLong()
            val issuerKey = EcPublicKey.fromJwk(input["issuer_key"]!!.jsonObject)
            val sd = SdJwtKb.fromCompactSerialization(text("sd"))
            val claims = sd.verify(
                issuerKey = issuerKey,
                checkNonce = { it == text("nonce") },
                checkAudience = { it == "fixture" },
                checkCreationTime = { it.epochSeconds == at }
            )
            assertEquals("Fixture", claims["name"]!!.jsonPrimitive.content)
            assertFalse(claims.containsKey("birthdate"))
            assertFalse(claims.containsKey("address"))
            assertEquals(text("issuer"), claims["iss"]!!.jsonPrimitive.content)
            assertEquals("${text("issuer")}/types/linked-document", claims["vct"]!!.jsonPrimitive.content)
            assertTrue(claims["exp"]!!.jsonPrimitive.content.toLong() > at)
            assertEquals(EcPublicKey.fromJwk(input["holder_sd"]!!.jsonObject), sd.sdJwt.kbKey)
            assertFailsWith<IllegalStateException> { sd.verify(issuerKey, checkNonce = { false }) }
            assertFailsWith<IllegalStateException> { sd.verify(issuerKey, checkAudience = { false }) }
            assertFailsWith<IllegalStateException> { sd.verify(issuerKey, checkCreationTime = { false }) }

            suspend fun transcript(nonce: String, responseUri: String, thumbprint: ByteArray): ByteArray {
                val info = Cbor.encode(buildCborArray {
                    add("fixture")
                    add(nonce)
                    add(thumbprint)
                    add(responseUri)
                })
                val digest = Crypto.digest(Algorithm.SHA256, info)
                return Cbor.encode(buildCborArray {
                    add(Simple.NULL)
                    add(Simple.NULL)
                    addCborArray {
                        add("OpenID4VPHandover")
                        add(digest)
                    }
                })
            }
            val thumbprint = text("recipient_thumbprint").fromBase64Url()
            val mdoc = text("mdoc").fromBase64Url()
            suspend fun parse(nonce: String, uri: String, thumb: ByteArray) =
                DeviceResponseParser(mdoc, transcript(nonce, uri, thumb)).parse()
            val parsed = parse(text("nonce"), "https://verifier.example/response", thumbprint)
            assertEquals(0L, parsed.status)
            assertEquals("1.0", parsed.version)
            val doc = parsed.documents.single()
            val namespace = "app.tossa.mikaki.linked_document.1"
            assertEquals(namespace, doc.docType)
            assertTrue(doc.issuerSignedAuthenticated)
            assertTrue(doc.deviceSignedAuthenticated)
            assertTrue(doc.deviceSignedAuthenticatedViaSignature)
            assertEquals(0, doc.numIssuerEntryDigestMatchFailures)
            assertEquals(setOf(namespace), doc.issuerNamespaces.toSet())
            assertEquals(setOf("birthdate"), doc.getIssuerEntryNames(namespace).toSet())
            assertEquals("1990-02-28", doc.getIssuerEntryString(namespace, "birthdate"))
            assertTrue(doc.getIssuerEntryDigestMatch(namespace, "birthdate"))
            assertEquals(EcPublicKey.fromJwk(input["holder_mdoc"]!!.jsonObject), doc.deviceKey)
            assertTrue(doc.validityInfoValidFrom.epochSeconds <= at)
            assertTrue(at < doc.validityInfoValidUntil.epochSeconds)
            for (changed in listOf(
                parse("wrong-nonce", "https://verifier.example/response", thumbprint),
                parse(text("nonce"), "https://verifier.example/wrong", thumbprint),
                parse(text("nonce"), "https://verifier.example/response", ByteArray(32))
            )) {
                assertTrue(changed.documents.single().issuerSignedAuthenticated)
                assertFalse(changed.documents.single().deviceSignedAuthenticated)
            }
        } finally {
            Logger.logPrinter = printer
        }
    }
}
