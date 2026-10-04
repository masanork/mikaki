package app.mikaki.identity_reader

import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Handler
import android.os.Looper
import android.util.Base64
import androidx.appcompat.app.AppCompatActivity
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

/** IsoDep connection pattern adapted from madowi NfcPlugin.kt (MIT/Apache-2.0).
 * Rust owns the card protocol. No PIN, identity data, UID, or APDU is logged.
 * Every callback is tied to a session so cancellation cannot affect a later read.
 */
@InvokeArg
class SessionArgs { var sessionId: String = "" }

@InvokeArg
class TransmitArgs {
    var sessionId: String = ""
    var apduBase64: String = ""
}

@TauriPlugin
class IdentityReaderPlugin(private val activity: Activity) : Plugin(activity) {
    private val adapter = NfcAdapter.getDefaultAdapter(activity)
    private val main = Handler(Looper.getMainLooper())
    private val lock = Any()
    private var foreground = true
    private class Session(val id: String, var pending: Invoke?) {
        var iso: IsoDep? = null
        var connecting = false
        var deadline: Runnable? = null
    }
    private var current: Session? = null
    // Handles close arriving before open, including Rust cancellation races.
    private val closed = ArrayDeque<String>()

    @Command
    fun open(invoke: Invoke) {
        val args = invoke.parseArgs(SessionArgs::class.java)
        val session: Session
        synchronized(lock) {
            if (args.sessionId.length != 32) { invoke.reject("invalid_session"); return }
            if (closed.contains(args.sessionId) || !foreground) { invoke.reject("cancelled"); return }
            if (current != null) { invoke.reject("reader_busy"); return }
            if (adapter == null) { invoke.reject("nfc_unavailable"); return }
            if (!adapter.isEnabled) { invoke.reject("nfc_disabled"); return }
            session = Session(args.sessionId, invoke)
            current = session
        }
        main.post {
            synchronized(lock) {
                if (current !== session) return@post
                try {
                    adapter!!.enableReaderMode(activity, { tag -> detected(session, tag) },
                        NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or
                            NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null)
                    // Overall session deadline bounds waiting and card operations.
                    val deadline = Runnable { end(session.id, "read_timeout") }
                    session.deadline = deadline
                    main.postDelayed(deadline, 60_000)
                } catch (_: Exception) { end(session.id, "transport_error") }
            }
        }
    }

    private fun detected(session: Session, tag: Tag) {
        synchronized(lock) {
            if (current !== session || session.connecting || session.iso != null) return
            session.connecting = true
        }
        Thread {
            val iso = IsoDep.get(tag)
            if (iso == null) { end(session.id, "unsupported_card"); return@Thread }
            try {
                iso.connect()
                iso.timeout = 10_000
                synchronized(lock) {
                    if (current !== session) { iso.close(); return@Thread }
                    session.iso = iso
                    session.pending?.resolve()
                    session.pending = null
                }
            } catch (_: Exception) {
                try { iso.close() } catch (_: Exception) {}
                end(session.id, "card_removed")
            }
        }.start()
    }

    @Command
    fun transmit(invoke: Invoke) {
        val args = invoke.parseArgs(TransmitArgs::class.java)
        val iso = synchronized(lock) {
            current?.takeIf { it.id == args.sessionId }?.iso
        }
        if (iso == null) { invoke.reject("cancelled"); return }
        if (args.apduBase64.length > 1400) { invoke.reject("invalid_apdu"); return }
        Thread {
            var apdu: ByteArray? = null
            try {
                apdu = Base64.decode(args.apduBase64, Base64.NO_WRAP)
                args.apduBase64 = ""
                if (apdu.size < 4 || apdu.size > 1024) { invoke.reject("invalid_apdu"); return@Thread }
                val response = iso.transceive(apdu)
                if (response.size < 2 || response.size > 4098) { invoke.reject("invalid_response"); return@Thread }
                synchronized(lock) {
                    if (current?.id != args.sessionId) { invoke.reject("cancelled"); return@Thread }
                    val result = JSObject()
                    result.put("apduBase64", Base64.encodeToString(response, Base64.NO_WRAP))
                    invoke.resolve(result)
                }
                response.fill(0)
            } catch (_: Exception) {
                val cancelled = synchronized(lock) { current?.id != args.sessionId }
                invoke.reject(if (cancelled) "cancelled" else "card_removed")
                end(args.sessionId, "card_removed")
            } finally { apdu?.fill(0); args.apduBase64 = "" }
        }.start()
    }

    @Command
    fun close(invoke: Invoke) {
        end(invoke.parseArgs(SessionArgs::class.java).sessionId, "cancelled")
        invoke.resolve()
    }

    private fun end(id: String, reason: String) {
        synchronized(lock) {
            if (!closed.contains(id)) {
                closed.addLast(id)
                while (closed.size > 16) closed.removeFirst()
            }
            val session = current?.takeIf { it.id == id } ?: return
            current = null
            session.deadline?.let { main.removeCallbacks(it) }
            session.pending?.reject(reason)
            session.pending = null
            try { session.iso?.close() } catch (_: Exception) {}
            session.iso = null
            main.post {
                synchronized(lock) {
                    if (current == null) {
                        try { adapter?.disableReaderMode(activity) } catch (_: Exception) {}
                    }
                }
            }
        }
    }

    override fun onPause(activity: AppCompatActivity) {
        synchronized(lock) { foreground = false; current?.let { end(it.id, "cancelled") } }
    }
    override fun onResume(activity: AppCompatActivity) { synchronized(lock) { foreground = true } }
    override fun onDestroy(activity: AppCompatActivity) { onPause(activity) }
}
