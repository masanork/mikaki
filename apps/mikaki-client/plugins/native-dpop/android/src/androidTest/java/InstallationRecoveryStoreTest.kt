package app.mikaki.native_dpop

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class InstallationRecoveryStoreTest {
    @Test fun authenticatedCasSurvivesReopenAndRejectsConcurrentStaleAndCorruptWrites() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val id = UUID.randomUUID().toString().replace("-", "")
        val device = DeviceSessionKeyStore()
        val file = File(context.noBackupFilesDir, "installation-recovery-$id.v1.bin")
        val alias = "mikaki.session.recovery.v1.$id"
        val executor = Executors.newFixedThreadPool(2)
        try {
            device.create(id)
            val first = "first checkpoint".toByteArray()
            val store = InstallationRecoveryStore(context, id)
            assertNull(store.load())
            store.compareAndSet(null, first)
            assertArrayEquals(first, InstallationRecoveryStore(context, id).load())
            val digest = MessageDigest.getInstance("SHA-256").digest(first)
            val latch = CountDownLatch(1)
            val futures = (1..2).map { n -> executor.submit<Boolean> {
                latch.await()
                try { InstallationRecoveryStore(context, id).compareAndSet(digest, "next-$n".toByteArray()); true }
                catch (_: IllegalArgumentException) { false }
            } }
            latch.countDown()
            assertEquals(1, futures.count { it.get() })
            assertThrows(IllegalArgumentException::class.java) { store.compareAndSet(digest, first) }
            val raw = file.readBytes(); raw[raw.lastIndex] = (raw.last().toInt() xor 1).toByte(); file.writeBytes(raw)
            assertThrows(Exception::class.java) { store.load() }
            assertThrows(Exception::class.java) { store.compareAndSet(null, first) }
            file.delete()
            assertThrows(IllegalStateException::class.java) { store.load() }
            assertThrows(IllegalStateException::class.java) { store.compareAndSet(null, first) }
        } finally {
            executor.shutdownNow()
            device.delete(id)
            KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }
            file.delete(); File(file.path + ".bak").delete(); File(file.path + ".new").delete()
            File(context.noBackupFilesDir, "installation-recovery-$id.v1.lock").delete()
        }
    }
}
