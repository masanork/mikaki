package org.multipaz.provisioning.openid4vci

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.Simple
import org.multipaz.cbor.addCborArray
import org.multipaz.cbor.buildCborArray
import org.multipaz.cose.CoseSign1
import org.multipaz.mdoc.devicesigned.buildDeviceNamespaces
import org.multipaz.mdoc.issuersigned.IssuerNamespaces
import org.multipaz.mdoc.response.DeviceResponse
import org.multipaz.request.MdocRequestedClaim
import org.multipaz.sdjwt.SdJwt
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url
import org.multipaz.provisioning.AuthorizationChallenge
import org.multipaz.provisioning.AuthorizationResponse
import org.multipaz.provisioning.KeyBindingInfo
import org.multipaz.rpc.backend.BackendEnvironment
import org.multipaz.securearea.SecureAreaProvider
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.ephemeral.EphemeralStorage
import org.multipaz.util.Logger
import org.multipaz.webtoken.buildJwt
import java.net.URI
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.Base64
import kotlin.reflect.KClass
import kotlin.reflect.cast
import kotlin.test.Test
import kotlin.test.assertEquals

/** Uses the unchanged Multipaz provisioning client; only its network engine is bridged to workerd. */
class MikakiIssuanceTest {
    private val bridge = System.getenv("MIKAKI_MULTIPAZ_BRIDGE") ?: error("Missing test bridge")
    private val secret = System.getenv("MIKAKI_MULTIPAZ_BRIDGE_SECRET") ?: error("Missing bridge authorization")
    private val transport = java.net.http.HttpClient.newBuilder().build()

    private fun call(path: String, request: JsonObject): JsonObject {
        val message = HttpRequest.newBuilder(URI.create("$bridge$path"))
            .header("Authorization", "Bearer $secret")
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(request.toString())).build()
        val response = transport.send(message, HttpResponse.BodyHandlers.ofString())
        assertEquals(200, response.statusCode())
        return Json.parseToJsonElement(response.body()).jsonObject
    }

    @Test
    fun walletReceivesBothFormats() = runBlocking {
        val printer = Logger.logPrinter
        Logger.logPrinter = Logger.LogPrinter { _, _, _, _ -> }
        val storage = EphemeralStorage()
        val secureArea = SoftwareSecureArea.create(storage)
        val provider = SecureAreaProvider(Dispatchers.Default) { secureArea }
        val client = HttpClient(MockEngine { request ->
            val body = (request.body as? OutgoingContent.ByteArrayContent)?.bytes() ?: ByteArray(0)
            val result = call("/fetch", buildJsonObject {
                put("url", request.url.toString())
                put("method", request.method.value)
                put("headers", buildJsonObject {
                    request.headers.entries().forEach { (name, values) -> put(name, values.joinToString(",")) }
                    request.body.contentType?.let { put("Content-Type", it.toString()) }
                })
                put("body", Base64.getEncoder().encodeToString(body))
            })
            val headers = HeadersBuilder().apply {
                result["headers"]!!.jsonObject.forEach { (name, value) -> append(name, value.jsonPrimitive.content) }
            }.build()
            respond(Base64.getDecoder().decode(result["body"]!!.jsonPrimitive.content),
                HttpStatusCode.fromValue(result["status"]!!.jsonPrimitive.content.toInt()), headers)
        })
        val env = object : BackendEnvironment {
            override fun <T : Any> getInterface(clazz: KClass<T>): T? = when (clazz) {
                HttpClient::class -> clazz.cast(client)
                SecureAreaProvider::class -> clazz.cast(provider)
                else -> null
            }
        }
        try {
            withContext(env) {
                for (configuration in listOf("linked_document", "linked_document_mdoc")) {
                    val preferences = OpenID4VCIClientPreferences("independent-wallet", "https://wallet.example/callback",
                        listOf("ja"), listOf(Algorithm.ESP256))
                    val wallet = OpenID4VCI.createClientCredentialId("https://issuer.example/identity/issuer", configuration, preferences)
                    val challenge = wallet.getAuthorizationChallenges().single() as AuthorizationChallenge.OAuth
                    val callback = call("/approve", buildJsonObject { put("url", challenge.url) })["callback"]!!.jsonPrimitive.content
                    wallet.authorize(AuthorizationResponse.OAuth(challenge.id, callback))
                    val nonce = wallet.getKeyBindingChallenge()
                    val key = Crypto.createEcPrivateKey(EcCurve.P256)
                    val proof = buildJwt("openid4vci-proof+jwt", AsymmetricKey.AnonymousExplicit(key), header = {
                        put("jwk", key.publicKey.toJwk())
                    }) { put("aud", "https://issuer.example/identity/issuer"); put("iss", preferences.clientId); put("nonce", nonce) }
                    val receipt = wallet.obtainCredentials(KeyBindingInfo.OpenidProofOfPossession(listOf(proof)))
                    assertEquals(1, receipt.certifications.size)
                    val verified = call("/verify", buildJsonObject {
                        put("configuration", configuration)
                        put("holder", key.publicKey.toJwk())
                        put("credential", Base64.getEncoder().encodeToString(receipt.certifications.single().issuerData.toByteArray()))
                    })
                    assertEquals("true", verified["verified"]!!.jsonPrimitive.content)
                    fun challenge(name: String) = verified[name]!!.jsonPrimitive.content
                    val issuerData = receipt.certifications.single().issuerData.toByteArray()
                    val presentation = if (configuration == "linked_document") {
                        SdJwt.fromCompactSerialization(issuerData.decodeToString()).filter(
                            listOf("name", "birthdate").map { JsonArray(listOf(JsonPrimitive(it))) }
                        ).present(AsymmetricKey.AnonymousExplicit(key), challenge("nonce"), challenge("audience"))
                            .compactSerialization
                    } else {
                        val namespace = "app.tossa.mikaki.linked_document.1"
                        val info = Cbor.encode(buildCborArray {
                            add(challenge("audience"))
                            add(challenge("nonce"))
                            add(challenge("recipient_thumbprint").fromBase64Url())
                            add(challenge("response_uri"))
                        })
                        val digest = Crypto.digest(Algorithm.SHA256, info)
                        val transcript = buildCborArray {
                            add(Simple.NULL)
                            add(Simple.NULL)
                            addCborArray { add("OpenID4VPHandover"); add(digest) }
                        }
                        val signed = Cbor.decode(issuerData)
                        val namespaces = IssuerNamespaces.fromDataItem(signed["nameSpaces"]).filter(
                            listOf("name", "birthdate").map {
                                MdocRequestedClaim(docType = namespace, namespaceName = namespace,
                                    dataElementName = it, intentToRetain = false)
                            }
                        )
                        val builder = DeviceResponse.Builder(transcript, DeviceResponse.STATUS_OK, version = "1.0")
                        builder.addDocument(namespace, CoseSign1.fromDataItem(signed["issuerAuth"]), namespaces,
                            buildDeviceNamespaces {}, AsymmetricKey.AnonymousExplicit(key))
                        Cbor.encode(builder.build().toDataItem()).toBase64Url()
                    }
                    val presented = call("/present", buildJsonObject {
                        put("configuration", configuration)
                        put("presentation", presentation)
                    })
                    assertEquals("true", presented["verified"]!!.jsonPrimitive.content)
                    key.close()
                }
            }
        } finally {
            client.close()
            Logger.logPrinter = printer
        }
    }
}
