package app.mikaki.native_dpop

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Fixture only: invoked in separate instrumentation processes. */
@RunWith(AndroidJUnit4::class)
class InstallationRecoveryProbeTest {
    @Test fun perform() {
        val args = InstrumentationRegistry.getArguments()
        val id = requireNotNull(args.getString("probe_id"))
        val mode = requireNotNull(args.getString("probe_mode"))
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val store = InstallationRecoveryStore(context, id)
        val device = DeviceSessionKeyStore()
        when (mode) {
            "create" -> { device.create(id); store.compareAndSet(null, "first".toByteArray()) }
            "advance" -> {
                val value = requireNotNull(store.load())
                assertEquals("first", value.toString(Charsets.UTF_8))
                store.compareAndSet(MessageDigest.getInstance("SHA-256").digest(value), "second".toByteArray())
            }
            "verify" -> assertEquals("second", requireNotNull(store.load()).toString(Charsets.UTF_8))
            "cleanup" -> {
                device.delete(id)
                KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry("mikaki.session.recovery.v1.$id") }
                val file = File(context.noBackupFilesDir, "installation-recovery-$id.v1.bin")
                file.delete(); File(file.path + ".bak").delete(); File(file.path + ".new").delete()
                File(context.noBackupFilesDir, "installation-recovery-$id.v1.lock").delete()
            }
            else -> error("invalid mode")
        }
    }
}
