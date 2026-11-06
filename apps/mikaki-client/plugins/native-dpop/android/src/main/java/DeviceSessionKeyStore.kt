package app.mikaki.native_dpop

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/** Separate installation-session key. It is not an MLS key or Wallet holder. */
internal class DeviceSessionKeyStore {
    companion object { private val lock = Any() }

    private fun store(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun alias(id: String): String {
        require(id.length == 32 && id.all { it in '0'..'9' || it in 'a'..'f' })
        return "mikaki.session.device.v1.$id"
    }
    private fun entry(id: String): KeyStore.PrivateKeyEntry =
        store().getEntry(alias(id), null) as? KeyStore.PrivateKeyEntry ?: error("device key absent")

    fun create(id: String): ECPublicKey = synchronized(lock) {
        val name = alias(id)
        val keys = store()
        require(!keys.containsAlias(name))
        try {
            val spec = KeyGenParameterSpec.Builder(name, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                // Session proof may be needed in the background. This key is
                // not an operation approval or a local biometric unlock.
                .setUserAuthenticationRequired(false)
                .build()
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                .apply { initialize(spec) }.generateKeyPair()
            entry(id).certificate.publicKey as ECPublicKey
        } catch (error: Exception) {
            try { keys.deleteEntry(name) } catch (_: Exception) { }
            throw error
        }
    }

    fun publicKey(id: String): ECPublicKey = synchronized(lock) {
        entry(id).certificate.publicKey as ECPublicKey
    }

    fun sign(id: String, input: String): ByteArray = synchronized(lock) {
        require(input.length in 3..8192)
        val parts = input.split('.')
        require(parts.size == 2 && parts.all { part ->
            part.isNotEmpty() && part.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }
        })
        Signature.getInstance("SHA256withECDSA").run {
            initSign(entry(id).privateKey)
            update(input.toByteArray(Charsets.US_ASCII))
            sign()
        }
    }

    fun delete(id: String) = synchronized(lock) { store().deleteEntry(alias(id)) }
}
