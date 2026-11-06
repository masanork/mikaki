package app.mikaki.native_dpop

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.io.RandomAccessFile
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Authenticated CAS storage for one installation; no external rollback witness. */
internal class InstallationRecoveryStore(private val context: Context, private val id: String) {
    companion object { private val processLock = Any(); private const val LIMIT = 4096 }
    private val alias: String
    private val file: AtomicFile
    private val lockFile: File

    init {
        require(id.length == 32 && id.all { it in '0'..'9' || it in 'a'..'f' })
        alias = "mikaki.session.recovery.v1.$id"
        file = AtomicFile(File(context.noBackupFilesDir, "installation-recovery-$id.v1.bin"))
        lockFile = File(context.noBackupFilesDir, "installation-recovery-$id.v1.lock")
    }

    private fun <T> locked(action: () -> T): T = synchronized(processLock) {
        RandomAccessFile(lockFile, "rw").use { lock -> lock.channel.lock().use { action() } }
    }
    private fun store(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun existingFile(): Boolean = file.baseFile.exists() || File(file.baseFile.path + ".bak").exists()
    private fun key(create: Boolean): SecretKey {
        val ks = store()
        if (!ks.containsAlias(alias)) {
            require(create)
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).setUserAuthenticationRequired(false).build()
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                .apply { init(spec) }.generateKey()
        }
        return (store().getEntry(alias, null) as KeyStore.SecretKeyEntry).secretKey
    }
    private fun read(): ByteArray? {
        if (!existingFile()) {
            // A missing file after key creation is an unknown outcome, not a
            // fresh slot; fail closed until an explicit recovery policy exists.
            check(!store().containsAlias(alias))
            return null
        }
        val packet = file.openRead().use { input ->
            val bytes = ByteArray(LIMIT + 30)
            var size = 0
            while (size < bytes.size) { val n = input.read(bytes, size, bytes.size - size); if (n < 0) break; size += n }
            require(size in 30..LIMIT + 29)
            bytes.copyOf(size)
        }
        require(packet[0] == 1.toByte())
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(false), GCMParameterSpec(128, packet.copyOfRange(1, 13)))
        cipher.updateAAD(alias.toByteArray(Charsets.US_ASCII))
        return cipher.doFinal(packet.copyOfRange(13, packet.size)).also { require(it.size in 1..LIMIT) }
    }
    fun load(): ByteArray? = locked { DeviceSessionKeyStore().publicKey(id); read() }

    /** Expected is SHA-256 of the last authenticated plaintext, or null on create. */
    fun compareAndSet(expected: ByteArray?, value: ByteArray) = locked {
        require(value.size in 1..LIMIT)
        require(expected == null || expected.size == 32)
        DeviceSessionKeyStore().publicKey(id)
        val prior = read()
        try {
            if (prior == null) require(expected == null)
            else require(expected != null && MessageDigest.isEqual(expected, MessageDigest.getInstance("SHA-256").digest(prior)))
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key(prior == null))
            cipher.updateAAD(alias.toByteArray(Charsets.US_ASCII))
            val packet = byteArrayOf(1) + cipher.iv + cipher.doFinal(value)
            require(cipher.iv.size == 12)
            val stream = file.startWrite()
            try { stream.write(packet); file.finishWrite(stream) }
            catch (error: Exception) { file.failWrite(stream); throw error }
            val committed = file.openRead().use { input -> input.readBytes() }
            check(MessageDigest.isEqual(packet, committed))
        } finally { prior?.fill(0) }
    }
}
