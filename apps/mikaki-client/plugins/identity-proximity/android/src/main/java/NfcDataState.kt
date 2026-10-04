package app.mikaki.identity_proximity

import android.nfc.cardemulation.HostApduService
import android.os.SystemClock

/** Main-thread confined. Session-bound callbacks cannot deliver into a replacement flow. */
internal object NfcDataState {
    private var id: String? = null
    private var routing: NfcDataRouting? = null
    private var deadline=0L
    private var protocol: NfcDataProtocol? = null
    private var service: HostApduService? = null
    private var request: ((ByteArray)->Unit)? = null
    private var finished: (()->Unit)? = null
    private var failed: (()->Unit)? = null
    fun arm(sessionId: String,onRequest:(ByteArray)->Unit,onFinished:()->Unit,onFailure:()->Unit, afterHandover: Boolean = false) {
        check(id==null);id=sessionId;deadline=SystemClock.elapsedRealtime()+120000
        routing=NfcDataRouting(afterHandover);protocol=NfcDataProtocol();request=onRequest;finished=onFinished;failed=onFailure
    }
    fun active() = id!=null
    fun routes(apdu:ByteArray) = routing?.route(apdu)==true
    fun clear(sessionId: String) {
        if(id!=sessionId)return
        val pending=protocol?.waiting==true
        protocol?.close();protocol=null;routing=null;id=null;request=null;finished=null;failed=null
        if(pending)try{service?.sendResponseApdu(byteArrayOf(0x69,0x85.toByte()))}catch(_:Exception){}
        service=null
    }
    fun deactivate() {val session=id?:return;val callback=if(protocol?.done==true)null else failed;clear(session);callback?.invoke()}
    fun exchange(host:HostApduService,apdu:ByteArray):ByteArray? {
        val p=protocol ?:return byteArrayOf(0x6a,0x82.toByte())
        if(SystemClock.elapsedRealtime()>=deadline){deactivate();return byteArrayOf(0x69,0x85.toByte())}
        service=host
        val response=p.exchangeAt(apdu,System.currentTimeMillis(),SystemClock.elapsedRealtime())
        val packet=p.takeRequest()
        if(packet!=null)request?.invoke(packet)
        if(p.closed){val session=id;val callback=failed;if(session!=null)clear(session);callback?.invoke()}
        else if(p.done){val callback=finished;finished=null;callback?.invoke()}
        return response
    }
    fun limitTransfer(sessionId:String,expiry:TransferDeadline) {
        check(id==sessionId)
        (protocol ?:error("closed")).limitTransfer(expiry)
    }
    fun send(sessionId:String,packet:ByteArray) {
        check(id==sessionId && SystemClock.elapsedRealtime()<deadline)
        val p=protocol ?:error("closed")
        val response=p.respondAt(packet,System.currentTimeMillis(),SystemClock.elapsedRealtime())
        (service ?:error("disconnected")).sendResponseApdu(response)
        if(p.done){val callback=finished;finished=null;callback?.invoke()}
    }
}
