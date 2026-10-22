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
class HolderArgs { lateinit var id: String; var input: String = ""; var payload: String = "" }

@InvokeArg
class AttestedHolderArgs { lateinit var id: String; lateinit var challenge: String }

@InvokeArg
class DocumentArgs { lateinit var owner: String; var payload: String = "" }

@TauriPlugin
class NativeDpopPlugin(private val activity: Activity): Plugin(activity) {
    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun b64(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    private fun coordinate(value: java.math.BigInteger): String {
        val source = value.toByteArray()
        require(source.size <= 33 && (source.size != 33 || source[0] == 0.toByte()))
        return b64(ByteArray(32).also { source.copyInto(it, 32 - minOf(source.size, 32), maxOf(0, source.size - 32)) })
    }

    private fun holderAlias(id: String): String {
        require(id.length == 32 && id.all { it in '0'..'9' || it in 'a'..'f' })
        return "mikaki.identity.holder.v1.$id"
    }
    private fun holder(id: String): KeyStore.PrivateKeyEntry =
        keyStore().getEntry(holderAlias(id), null) as? KeyStore.PrivateKeyEntry ?: error("holder absent")
    private fun publicResult(key: KeyStore.PrivateKeyEntry): JSObject {
        val point = (key.certificate.publicKey as ECPublicKey).w
        return JSObject().apply { put("x", coordinate(point.affineX)); put("y", coordinate(point.affineY)) }
    }
    @Command @Synchronized
    fun createHolder(invoke: Invoke) {
        try {
            val id = invoke.parseArgs(HolderArgs::class.java).id
            val alias = holderAlias(id)
            require(!keyStore().containsAlias(alias))
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256).setUserAuthenticationRequired(false).build()
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                .apply { initialize(spec) }.generateKeyPair()
            invoke.resolve(publicResult(holder(id)))
        } catch (_: Exception) { invoke.reject("wallet_key_unavailable") }
    }
    // Native Rust only. Evidence is sent to an independent attester; it is not a
    // hardware-assurance decision and must not be exposed as a WebView command.
    @Command @Synchronized
    fun createAttestedHolder(invoke: Invoke) {
        var cleanupAlias: String? = null
        var challenge: ByteArray? = null
        try {
            val args = invoke.parseArgs(AttestedHolderArgs::class.java)
            val alias = holderAlias(args.id)
            require(!keyStore().containsAlias(alias))
            require(args.challenge.length == 43)
            val bytes = Base64.decode(args.challenge, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
            challenge = bytes
            require(bytes.size == 32 && b64(bytes) == args.challenge)
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
                .setAttestationChallenge(bytes)
                .build()
            cleanupAlias = alias
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                .apply { initialize(spec) }.generateKeyPair()
            val chain = keyStore().getCertificateChain(alias) ?: error("attestation absent")
            require(chain.size in 2..8)
            var total = 0
            val certificates = org.json.JSONArray()
            for (certificate in chain) {
                val der = certificate.encoded
                require(der.size in 1..8192)
                total += der.size; require(total <= 32768)
                certificates.put(Base64.encodeToString(der, Base64.NO_WRAP))
            }
            val result = publicResult(holder(args.id)).apply { put("certificateChain", certificates) }
            invoke.resolve(result)
            cleanupAlias = null
        } catch (_: Exception) {
            cleanupAlias?.let { try { keyStore().deleteEntry(it) } catch (_: Exception) {} }
            invoke.reject("wallet_attestation_unavailable")
        } finally { challenge?.fill(0) }
    }
    @Command @Synchronized
    fun holderPublicKey(invoke: Invoke) {
        try { invoke.resolve(publicResult(holder(invoke.parseArgs(HolderArgs::class.java).id))) }
        catch (_: Exception) { invoke.reject("wallet_key_unavailable") }
    }
    @Command @Synchronized
    fun signHolder(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(HolderArgs::class.java)
            require(args.input.length <= 16384 && args.input.all { it.code < 128 })
            val der = Signature.getInstance("SHA256withECDSA").run {
                initSign(holder(args.id).privateKey); update(args.input.toByteArray(Charsets.US_ASCII)); sign()
            }
            invoke.resolve(JSObject().apply { put("der", b64(der)) })
        } catch (_: Exception) { invoke.reject("wallet_key_unavailable") }
    }
    @Command @Synchronized
    fun signHolderBytes(invoke: Invoke) {
        var bytes: ByteArray? = null
        try {
            val args = invoke.parseArgs(HolderArgs::class.java)
            require(args.input.length <= 16384)
            val decoded = Base64.decode(args.input, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            bytes = decoded; require(decoded.size <= 12288)
            val der = Signature.getInstance("SHA256withECDSA").run {
                initSign(holder(args.id).privateKey); update(decoded); sign()
            }
            invoke.resolve(JSObject().apply { put("der", b64(der)) })
        } catch (_: Exception) { invoke.reject("wallet_key_unavailable") }
        finally { bytes?.fill(0) }
    }
    @Command @Synchronized
    fun deleteHolder(invoke: Invoke) {
        try { keyStore().deleteEntry(holderAlias(invoke.parseArgs(HolderArgs::class.java).id)); invoke.resolve() }
        catch (_: Exception) { invoke.reject("wallet_key_unavailable") }
    }
    private fun walletFile() = android.util.AtomicFile(java.io.File(activity.noBackupFilesDir, "identity-wallet.v1.bin"))
    private fun wrappingKey(create: Boolean, alias: String = "mikaki.identity.storage.v1"): javax.crypto.SecretKey {
        val store = keyStore()
        if (!store.containsAlias(alias)) {
            require(create)
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).setUserAuthenticationRequired(false).build()
            javax.crypto.KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                .apply { init(spec) }.generateKey()
        }
        return (keyStore().getEntry(alias, null) as KeyStore.SecretKeyEntry).secretKey
    }
    @Command @Synchronized
    fun storeWallet(invoke: Invoke) {
        var plain: ByteArray? = null
        try {
            val args = invoke.parseArgs(HolderArgs::class.java)
            holder(args.id) // Fail if the nonexportable holder key was lost.
            require(args.payload.length <= 512000)
            plain = Base64.decode(args.payload, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            require(plain.size <= 384000)
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, wrappingKey(true))
            cipher.updateAAD("mikaki.identity.wallet.v1".toByteArray(Charsets.US_ASCII))
            val encrypted = cipher.doFinal(plain)
            require(cipher.iv.size == 12)
            val packet = byteArrayOf(1) + cipher.iv + encrypted
            val file = walletFile(); val stream = file.startWrite()
            try { stream.write(packet); file.finishWrite(stream) }
            catch (error: Exception) { file.failWrite(stream); throw error }
            // A presentation may retire the last receipt. Acknowledge only the
            // exact committed ciphertext, never a stale backup or failed rename.
            require(file.openRead().use { require(it.channel.size() == packet.size.toLong()); it.readBytes().contentEquals(packet) })
            invoke.resolve()
        } catch (_: Exception) { invoke.reject("wallet_storage_unavailable") }
        finally { plain?.fill(0) }
    }
    @Command @Synchronized
    fun loadWallet(invoke: Invoke) {
        var plain: ByteArray? = null
        try {
            val file = walletFile()
            if (!file.baseFile.exists() && !java.io.File(file.baseFile.path + ".bak").exists()) { invoke.resolve(JSObject().apply { put("payload", org.json.JSONObject.NULL) }); return }
            val bytes = file.openRead().use { stream ->
                val buffer = ByteArray(384030); var total = 0
                while (total < buffer.size) { val n = stream.read(buffer, total, buffer.size-total); if (n < 0) break; total += n }
                require(total <= 384029); buffer.copyOf(total)
            }
            require(bytes.size in 30..384029 && bytes[0] == 1.toByte())
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, wrappingKey(false), javax.crypto.spec.GCMParameterSpec(128, bytes.copyOfRange(1,13)))
            cipher.updateAAD("mikaki.identity.wallet.v1".toByteArray(Charsets.US_ASCII))
            val decrypted = cipher.doFinal(bytes.copyOfRange(13,bytes.size))
            plain = decrypted
            invoke.resolve(JSObject().apply { put("payload", b64(decrypted)) })
        } catch (_: Exception) { invoke.reject("wallet_storage_unavailable") }
        finally { plain?.fill(0) }
    }
    @Command @Synchronized
    fun eraseWallet(invoke: Invoke) {
        try {
            walletFile().delete()
            val store = keyStore()
            store.aliases().toList().filter { it.startsWith("mikaki.identity.holder.v1.") }
                .forEach { store.deleteEntry(it) }
            store.deleteEntry("mikaki.identity.storage.v1")
            invoke.resolve()
        } catch (_: Exception) { invoke.reject("wallet_storage_unavailable") }
    }
    @Command @Synchronized
    fun deleteWallet(invoke: Invoke) {
        try {
            walletFile().delete()
            val store = keyStore()
            store.deleteEntry("mikaki.identity.storage.v1")
            invoke.resolve()
        } catch (_: Exception) { invoke.reject("wallet_storage_unavailable") }
    }

    // Native-only, account-scoped read summaries. They are never presentation credentials.
    private fun documentAlias(owner: String): String {
        require(owner.length == 64 && owner.all { it in '0'..'9' || it in 'a'..'f' })
        return "mikaki.identity.documents.v1.$owner"
    }
    private fun documentFile(owner: String): android.util.AtomicFile {
        documentAlias(owner)
        return android.util.AtomicFile(java.io.File(activity.noBackupFilesDir, "identity-documents-$owner.v1.bin"))
    }
    @Command @Synchronized
    fun storeDocuments(invoke: Invoke) {
        var plain: ByteArray? = null
        try {
            val args = invoke.parseArgs(DocumentArgs::class.java)
            val alias = documentAlias(args.owner)
            require(args.payload.length <= 32768)
            val decoded = Base64.decode(args.payload, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            plain = decoded; require(decoded.size <= 24576)
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, wrappingKey(true, alias))
            cipher.updateAAD(alias.toByteArray(Charsets.US_ASCII))
            val encrypted = cipher.doFinal(decoded)
            require(cipher.iv.size == 12)
            val file = documentFile(args.owner); val stream = file.startWrite()
            try { stream.write(byteArrayOf(1)); stream.write(cipher.iv); stream.write(encrypted); file.finishWrite(stream) }
            catch (error: Exception) { file.failWrite(stream); throw error }
            invoke.resolve()
        } catch (_: Exception) { invoke.reject("document_storage_unavailable") }
        finally { plain?.fill(0) }
    }
    @Command @Synchronized
    fun loadDocuments(invoke: Invoke) {
        var plain: ByteArray? = null
        try {
            val args = invoke.parseArgs(DocumentArgs::class.java)
            val alias = documentAlias(args.owner); val file = documentFile(args.owner)
            if (!file.baseFile.exists() && !java.io.File(file.baseFile.path + ".bak").exists()) {
                invoke.resolve(JSObject().apply { put("payload", org.json.JSONObject.NULL) }); return
            }
            val bytes = file.openRead().use { stream ->
                val buffer = ByteArray(24606); var total = 0
                while (total < buffer.size) { val n = stream.read(buffer, total, buffer.size-total); if (n < 0) break; total += n }
                require(total <= 24605); buffer.copyOf(total)
            }
            require(bytes.size in 30..24605 && bytes[0] == 1.toByte())
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, wrappingKey(false, alias), javax.crypto.spec.GCMParameterSpec(128, bytes.copyOfRange(1,13)))
            cipher.updateAAD(alias.toByteArray(Charsets.US_ASCII))
            val decoded = cipher.doFinal(bytes.copyOfRange(13,bytes.size)); plain = decoded
            invoke.resolve(JSObject().apply { put("payload", b64(decoded)) })
        } catch (_: Exception) { invoke.reject("document_storage_unavailable") }
        finally { plain?.fill(0) }
    }
    @Command @Synchronized
    fun deleteDocuments(invoke: Invoke) {
        try {
            val owner = invoke.parseArgs(DocumentArgs::class.java).owner
            documentFile(owner).delete(); keyStore().deleteEntry(documentAlias(owner)); invoke.resolve()
        } catch (_: Exception) { invoke.reject("document_storage_unavailable") }
    }

}
