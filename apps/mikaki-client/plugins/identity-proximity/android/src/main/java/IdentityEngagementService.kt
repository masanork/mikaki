package app.mikaki.identity_proximity

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.os.SystemClock

/** System-only HCE routing. No engagement is published unless an active native flow arms it. */
class IdentityEngagementService : HostApduService() {
    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray? = if(NfcDataState.active()&&NfcDataState.routes(commandApdu)) NfcDataState.exchange(this,commandApdu) else EngagementState.exchange(commandApdu)
    override fun onDeactivated(reason: Int) { if(NfcDataState.active()) NfcDataState.deactivate() else EngagementState.reset() }
}

internal object EngagementState {
    private var id: String? = null
    private var deadline = 0L
    private var tag: NdefType4? = null
    private var negotiation: NegotiatedHandover? = null
    private var failed: (() -> Unit)? = null
    @Synchronized fun arm(sessionId: String, message: ByteArray) {
        negotiation = null; failed = null; tag = NdefType4(message); id = sessionId; deadline = SystemClock.elapsedRealtime() + 120000
    }
    @Synchronized fun armNegotiated(sessionId: String, request: (ByteArray) -> Unit, failure: () -> Unit) {
        val flow = NegotiatedHandover(request)
        negotiation = flow; tag = flow.tag; failed = failure
        id = sessionId; deadline = SystemClock.elapsedRealtime() + 120000
    }
    @Synchronized fun publish(sessionId: String, message: ByteArray) {
        require(id == sessionId && SystemClock.elapsedRealtime() < deadline)
        (negotiation ?: error("no_negotiation")).publish(message)
    }
    @Synchronized fun clear(sessionId: String) {
        if (id == sessionId) { tag = null; id = null; deadline = 0; negotiation = null; failed = null }
    }
    @Synchronized fun reset() {
        if (negotiation != null && negotiation?.complete != true) {
            val callback = failed; id?.let { clear(it) }; callback?.invoke()
        } else tag?.reset()
    }
    @Synchronized fun exchange(command: ByteArray): ByteArray {
        if (SystemClock.elapsedRealtime() >= deadline) { tag = null; id = null }
        val result = tag?.exchange(command) ?: byteArrayOf(0x6a, 0x82.toByte())
        if (tag?.failed == true) { val callback = failed; id?.let { clear(it) }; callback?.invoke() }
        return result
    }
}
