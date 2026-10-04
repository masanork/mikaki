package app.mikaki.identity_proximity

import java.io.ByteArrayOutputStream

/** One bounded ISO mdoc NFC exchange. Only encrypted SessionEstablishment/SessionData enter it. */
internal class NfcDataProtocol {
    private enum class Phase { SELECT, RECEIVE, WAIT, SEND, DONE, CLOSED }
    private var phase = Phase.SELECT
    private val incoming = ByteArrayOutputStream()
    private var request: ByteArray? = null
    private var outgoing: ByteArray? = null
    private var transferDeadline: TransferDeadline? = null
    private var offset = 0
    private var responseLe = 0
    val waiting: Boolean get() = phase == Phase.WAIT
    val done: Boolean get() = phase == Phase.DONE
    val closed: Boolean get() = phase == Phase.CLOSED
    private fun sw(n: Int) = byteArrayOf((n shr 8).toByte(), n.toByte())
    fun close() { phase = Phase.CLOSED; transferDeadline=null; incoming.reset(); request?.fill(0); request = null; outgoing?.fill(0); outgoing = null }
    private fun fail(n: Int): ByteArray { close(); return sw(n) }
    fun takeRequest(): ByteArray? { val r=request;request=null;return r }
    fun limitTransfer(expiry:TransferDeadline) {
        check(waiting && transferDeadline==null)
        transferDeadline=expiry
    }
    fun exchangeAt(apdu:ByteArray,wall:Long,elapsed:Long):ByteArray? {
        if(transferDeadline?.expired(wall,elapsed)==true)return fail(0x6985)
        return exchange(apdu)
    }
    fun respondAt(packet:ByteArray,wall:Long,elapsed:Long):ByteArray {
        if(transferDeadline?.expired(wall,elapsed)!=false){close();error("presentation_expired")}
        return respond(packet)
    }
    fun exchange(apdu: ByteArray): ByteArray? {
        if (closed || done) return sw(0x6985)
        if (apdu.size !in 4..261) return fail(0x6700)
        val cla=apdu[0].toInt() and 255
        val ins=apdu[1].toInt() and 255
        if (phase == Phase.SELECT) {
            val select=byteArrayOf(0,0xa4.toByte(),4,0,7,0xa0.toByte(),0,0,2,0x48,4,0)
            if (!(apdu.contentEquals(select) || apdu.contentEquals(select+byteArrayOf(0)))) return fail(0x6a82)
            phase=Phase.RECEIVE;return sw(0x9000)
        }
        if (apdu[2].toInt()!=0 || apdu[3].toInt()!=0) return fail(0x6a86)
        if (phase == Phase.SEND && cla==0 && ins==0xc0) {
            if (apdu.size!=5) return fail(0x6700)
            return next((apdu[4].toInt() and 255).let {if(it==0)256 else it})
        }
        if (phase != Phase.RECEIVE || ins != 0xc3 || cla !in listOf(0,0x10)) return fail(0x6985)
        if (apdu.size<6) return fail(0x6700)
        val lc=apdu[4].toInt() and 255
        if (lc==0 || apdu.size != 5+lc+(if(cla==0)1 else 0)) return fail(0x6700)
        if (incoming.size()+lc>32004) return fail(0x6700)
        incoming.write(apdu,5,lc)
        if (cla==0x10) return sw(0x9000)
        responseLe=(apdu.last().toInt() and 255).let {if(it==0)256 else it}
        val envelope=incoming.toByteArray();incoming.reset()
        val decoded=decodeDo53(envelope) ?:return fail(0x6a80)
        request=decoded;phase=Phase.WAIT
        return null // User consent and native cryptography happen outside the HCE main-thread handler.
    }
    fun respond(packet: ByteArray): ByteArray {
        check(waiting && packet.isNotEmpty() && packet.size<=32000)
        outgoing=encodeDo53(packet);offset=0;phase=Phase.SEND
        return next(responseLe)
    }
    private fun next(le: Int): ByteArray {
        val data=outgoing ?:return fail(0x6985)
        val count=minOf(le,data.size-offset)
        val chunk=data.copyOfRange(offset,offset+count);offset+=count
        val remaining=data.size-offset
        if (remaining==0) { data.fill(0);outgoing=null;phase=Phase.DONE }
        return chunk+sw(if(remaining==0)0x9000 else 0x6100+if(remaining<=255)remaining else 0)
    }
    companion object {
        fun encodeDo53(data: ByteArray): ByteArray {
            require(data.isNotEmpty() && data.size<=32000)
            val length=data.size
            val header=if(length<128)byteArrayOf(0x53,length.toByte()) else if(length<256)byteArrayOf(0x53,0x81.toByte(),length.toByte()) else byteArrayOf(0x53,0x82.toByte(),(length shr 8).toByte(),length.toByte())
            return header+data
        }
        fun decodeDo53(data: ByteArray): ByteArray? {
            if (data.size !in 3..32004 || data[0].toInt()!=0x53) return null
            val marker=data[1].toInt() and 255
            val header:Int;val length:Int
            when {
                marker<128 -> {header=2;length=marker}
                marker==0x81 && data.size>=3 -> {header=3;length=data[2].toInt() and 255;if(length<128)return null}
                marker==0x82 && data.size>=4 -> {header=4;length=((data[2].toInt() and 255) shl 8) or (data[3].toInt() and 255);if(length<256)return null}
                else -> return null
            }
            if(length !in 1..32000 || data.size!=header+length)return null
            return data.copyOfRange(header,data.size)
        }
    }
}
