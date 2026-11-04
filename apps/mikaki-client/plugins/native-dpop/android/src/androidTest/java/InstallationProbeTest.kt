package app.mikaki.native_dpop

import android.os.Bundle
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.math.BigInteger
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Local test-only IPC for a synthetic Keystore-to-Worker qualification. */
@RunWith(AndroidJUnit4::class)
class InstallationProbeTest {
    private fun b64(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    private fun coordinate(n: BigInteger): String {
        val bytes = n.toByteArray()
        require(bytes.size <= 33 && (bytes.size != 33 || bytes[0] == 0.toByte()))
        return b64(ByteArray(32).also { bytes.copyInto(it, 32 - minOf(bytes.size, 32), maxOf(0, bytes.size - 32)) })
    }
    @Test fun perform() {
        val args = InstrumentationRegistry.getArguments()
        val mode = args.getString("probe_mode")
        assumeTrue(mode != null)
        val id = requireNotNull(args.getString("probe_id"))
        val keys = DeviceSessionKeyStore()
        val result = when (mode) {
            "create" -> keys.create(id).let { "${coordinate(it.w.affineX)}.${coordinate(it.w.affineY)}" }
            "sign" -> b64(keys.sign(id, requireNotNull(args.getString("probe_input"))))
            "delete" -> { keys.delete(id); "deleted" }
            else -> error("invalid probe mode")
        }
        InstrumentationRegistry.getInstrumentation().sendStatus(2, Bundle().apply { putString("probe_result", result) })
    }
}
