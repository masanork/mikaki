package app.mikaki.native_dpop

import android.app.Activity
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

@InvokeArg
class SignArgs { lateinit var input: String }

@TauriPlugin
class NativeDpopPlugin(activity: Activity): Plugin(activity) {
    private val alias = "mikaki.vault.dpop.v1"

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    @Synchronized
    private fun pair(): KeyStore.PrivateKeyEntry {
        val store = keyStore()
        if (!store.containsAlias(alias)) {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
                .build()
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                .apply { initialize(spec) }.generateKeyPair()
        }
        return keyStore().getEntry(alias, null) as KeyStore.PrivateKeyEntry
    }

    private fun b64(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    private fun coordinate(value: java.math.BigInteger): String {
        val source = value.toByteArray()
        require(source.size <= 33 && (source.size != 33 || source[0] == 0.toByte()))
        return b64(ByteArray(32).also { source.copyInto(it, 32 - minOf(source.size, 32), maxOf(0, source.size - 32)) })
    }

    @Command
    fun publicKey(invoke: Invoke) {
        try {
            val point = (pair().certificate.publicKey as ECPublicKey).w
            invoke.resolve(JSObject().apply {
                put("x", coordinate(point.affineX))
                put("y", coordinate(point.affineY))
            })
        } catch (_: Exception) { invoke.reject("OS DPoP key unavailable") }
    }

    @Command
    fun sign(invoke: Invoke) {
        try {
            val input = invoke.parseArgs(SignArgs::class.java).input
            require(input.length <= 4096)
            require(input.all { it.code < 128 })
            val der = Signature.getInstance("SHA256withECDSA").run {
                initSign(pair().privateKey)
                update(input.toByteArray(Charsets.US_ASCII))
                sign()
            }
            invoke.resolve(JSObject().apply { put("der", b64(der)) })
        } catch (_: Exception) { invoke.reject("OS DPoP signature unavailable") }
    }
}
