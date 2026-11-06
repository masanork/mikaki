package app.mikaki.native_dpop

import androidx.test.ext.junit.runners.AndroidJUnit4
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DeviceSessionKeyStoreTest {
    @Test fun concurrentCreateDoesNotReplaceTheWinningKey() {
        val id = UUID.randomUUID().toString().replace("-", "")
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        try {
            val futures = (1..2).map {
                executor.submit<java.security.interfaces.ECPublicKey?> {
                    start.await()
                    try { DeviceSessionKeyStore().create(id) } catch (_: IllegalArgumentException) { null }
                }
            }
            start.countDown()
            val results = futures.map { it.get(30, TimeUnit.SECONDS) }.filterNotNull()
            assertEquals(1, results.size)
            assertEquals(results.single(), DeviceSessionKeyStore().publicKey(id))
        } finally {
            executor.shutdownNow()
            DeviceSessionKeyStore().delete(id)
        }
    }

    @Test fun separatePersistentNonExportableKeySignsAndDeletes() {
        val id = UUID.randomUUID().toString().replace("-", "")
        val session = DeviceSessionKeyStore()
        try {
            val publicKey = session.create(id)
            val alias = "mikaki.session.device.v1.$id"
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val privateKey = (store.getEntry(alias, null) as KeyStore.PrivateKeyEntry).privateKey
            assertNull(privateKey.encoded)
            assertEquals(publicKey, DeviceSessionKeyStore().publicKey(id))
            assertThrows(IllegalArgumentException::class.java) { session.create(id) }
            val input = "ZXhhbXBsZQ.cGF5bG9hZA"
            val signature = session.sign(id, input)
            assertTrue(Signature.getInstance("SHA256withECDSA").run {
                initVerify(publicKey); update(input.toByteArray(Charsets.US_ASCII)); verify(signature)
            })
            assertFalse(Signature.getInstance("SHA256withECDSA").run {
                initVerify(publicKey); update("ZXhhbXBsZQ.YWx0ZXJlZA".toByteArray(Charsets.US_ASCII)); verify(signature)
            })
            for (bad in listOf("", "abc", "a.b.c", "a.é", ".b", "a.")) {
                assertThrows(IllegalArgumentException::class.java) { session.sign(id, bad) }
            }
            assertThrows(IllegalArgumentException::class.java) { session.sign(id, "a." + "x".repeat(8192)) }
            assertThrows(IllegalArgumentException::class.java) { session.publicKey("../../wallet") }
            session.delete(id)
            assertFalse(store.containsAlias(alias))
            assertThrows(IllegalStateException::class.java) { session.publicKey(id) }
            assertThrows(IllegalStateException::class.java) { session.sign(id, input) }
        } finally { session.delete(id) }
    }

    @Test fun deletingSessionKeyDoesNotDeleteWalletHolderWithSameId() {
        val id = UUID.randomUUID().toString().replace("-", "")
        val holderAlias = "mikaki.identity.holder.v1.$id"
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        try {
            val spec = KeyGenParameterSpec.Builder(holderAlias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256).build()
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                .apply { initialize(spec) }.generateKeyPair()
            DeviceSessionKeyStore().create(id)
            DeviceSessionKeyStore().delete(id)
            assertTrue(store.containsAlias(holderAlias))
        } finally {
            DeviceSessionKeyStore().delete(id)
            store.deleteEntry(holderAlias)
        }
    }
}
