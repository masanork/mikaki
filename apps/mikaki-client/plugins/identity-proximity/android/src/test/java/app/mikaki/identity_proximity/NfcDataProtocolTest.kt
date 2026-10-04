package app.mikaki.identity_proximity

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream

class NfcDataProtocolTest {
    private fun hex(s:String)=s.chunked(2).map{it.toInt(16).toByte()}.toByteArray()
    private fun start(p:NfcDataProtocol){assertArrayEquals(hex("9000"),p.exchange(hex("00a4040007a000000248040000")))}
    private fun envelope(p:NfcDataProtocol,data:ByteArray,le:Int=256) {
        val header=when {data.size<128->byteArrayOf(0x53,data.size.toByte());data.size<256->byteArrayOf(0x53,0x81.toByte(),data.size.toByte());else->byteArrayOf(0x53,0x82.toByte(),(data.size shr 8).toByte(),data.size.toByte())}
        val wire=header+data
        for((i,chunk) in wire.asList().chunked(255).withIndex()) {
            val last=(i+1)*255>=wire.size
            val apdu=byteArrayOf(if(last)0 else 0x10,0xc3.toByte(),0,0,chunk.size.toByte())+chunk.toByteArray()+(if(last)byteArrayOf(le.toByte())else byteArrayOf())
            val result=p.exchange(apdu)
            if(last)assertNull(result) else assertArrayEquals(hex("9000"),result)
        }
    }
    @Test fun expirationDuringGetResponseDiscardsRemainingCiphertext() {
        val p=NfcDataProtocol();start(p);envelope(p,hex("a0"),100)
        p.limitTransfer(TransferDeadline.fromEpochSeconds(101,100000,8000))
        assertEquals(102,p.respondAt(ByteArray(1800){42},100999,8999).size)
        val get=hex("00c0000000")
        assertArrayEquals(hex("6985"),p.exchangeAt(get,90000,9000))
        assertTrue(p.closed);assertFalse(p.done)
        assertArrayEquals(hex("6985"),p.exchangeAt(get,90000,9001))
        try{p.respondAt(byteArrayOf(1),90000,9001);fail("expired response restarted")}
        catch(_:IllegalStateException){}
    }
    @Test fun expiredApprovalCannotReleaseFirstNfcResponse() {
        val p=NfcDataProtocol();start(p);envelope(p,hex("a0"))
        p.limitTransfer(TransferDeadline.fromEpochSeconds(101,100000,8000))
        try{p.respondAt(ByteArray(100){42},101000,8500);fail("expired response")}
        catch(_:IllegalStateException){}
        assertTrue(p.closed)
    }
    @Test fun chainsRequestAndDefersResponseUntilNativeApproval() {
        val p=NfcDataProtocol();start(p);val packet=ByteArray(1000){it.toByte()}
        envelope(p,packet);assertTrue(p.waiting);assertArrayEquals(packet,p.takeRequest());assertNull(p.takeRequest())
        val response=ByteArray(1800){(it*3).toByte()};val out=ByteArrayOutputStream()
        var chunk=p.respond(response)
        while(true) {
            out.write(chunk,0,chunk.size-2)
            val sw=((chunk[chunk.size-2].toInt() and 255) shl 8) or (chunk.last().toInt() and 255)
            if(sw==0x9000)break
            assertEquals(0x6100,sw and 0xff00)
            val remaining=sw and 255
            chunk=p.exchange(byteArrayOf(0,0xc0.toByte(),0,0,remaining.toByte()))!!
        }
        assertArrayEquals(hex("53820708")+response,out.toByteArray())
        assertTrue(p.done);assertArrayEquals(hex("6985"),p.exchange(hex("00c0000000")))
        try{p.respond(response);fail("replayed response")}catch(_:IllegalStateException){}
    }
    @Test fun honorsEachGetResponseLeAndStatusRemainingWithoutSkippingBytes() {
        val p=NfcDataProtocol();start(p);envelope(p,hex("a0"),100)
        val packet=ByteArray(400){it.toByte()};var reply=p.respond(packet)
        assertEquals(102,reply.size);assertArrayEquals(hex("6100"),reply.takeLast(2).toByteArray())
        val out=ByteArrayOutputStream();out.write(reply,0,reply.size-2)
        for(le in listOf(75,128,200)) {
            reply=p.exchange(byteArrayOf(0,0xc0.toByte(),0,0,le.toByte()))!!
            out.write(reply,0,reply.size-2)
        }
        assertArrayEquals(hex("9000"),reply.takeLast(2).toByteArray())
        assertArrayEquals(hex("53820190")+packet,out.toByteArray())
    }
    @Test fun rejectsPrematureResponseDuplicateRequestMalformedChainAndOversize() {
        val p=NfcDataProtocol();start(p)
        try{p.respond(hex("a0"));fail("response without request")}catch(_:IllegalStateException){}
        assertArrayEquals(hex("6985"),p.exchange(hex("00c0000000")));assertTrue(p.closed)
        for(wire in listOf(hex("53800000"),hex("53810100"),hex("5382000100"),hex("530200"),hex("530100ff"))) {
            val q=NfcDataProtocol();start(q)
            assertArrayEquals(hex("6a80"),q.exchange(byteArrayOf(0,0xc3.toByte(),0,0,wire.size.toByte())+wire+byteArrayOf(0)))
            assertTrue(q.closed);assertNull(q.takeRequest())
        }
        val q=NfcDataProtocol();start(q);envelope(q,hex("a0"))
        assertArrayEquals(hex("6985"),q.exchange(hex("00c30000035301a000")));assertNull(q.takeRequest());assertTrue(q.closed)
        val r=NfcDataProtocol();start(r)
        assertArrayEquals(hex("6700"),r.exchange(hex("10c30000015300")));assertTrue(r.closed)
        val s=NfcDataProtocol();start(s)
        assertArrayEquals(hex("6700"),s.exchange(hex("00c300000000035301a00000")));assertTrue(s.closed)
        val t=NfcDataProtocol();start(t)
        assertArrayEquals(hex("6700"),t.exchange(ByteArray(100000)));assertTrue(t.closed)
    }
    @Test fun deactivationAndCancellationEraseRequestAndPendingResponse() {
        val p=NfcDataProtocol();start(p);envelope(p,hex("a0"));p.close()
        assertNull(p.takeRequest());assertTrue(p.closed);assertArrayEquals(hex("6985"),p.exchange(hex("00a4040007a0000002480400")))
        val q=NfcDataProtocol();start(q);envelope(q,hex("a0"));q.respond(ByteArray(1000));q.close()
        assertArrayEquals(hex("6985"),q.exchange(hex("00c0000000")))
    }
    @Test fun advertisedMaximumTransfersFitAndExcessiveChainingCloses() {
        val p=NfcDataProtocol();start(p);val packet=ByteArray(32000){it.toByte()};envelope(p,packet)
        assertArrayEquals(packet,p.takeRequest())
        val q=NfcDataProtocol();start(q)
        val chunk=byteArrayOf(0x10,0xc3.toByte(),0,0,0xff.toByte())+ByteArray(255)
        for(i in 0 until 125)assertArrayEquals(hex("9000"),q.exchange(chunk))
        assertArrayEquals(hex("6700"),q.exchange(chunk));assertTrue(q.closed);assertNull(q.takeRequest())
    }
    @Test fun do53UsesCanonicalDefiniteLengthsAtBoundaries() {
        for(size in listOf(1,127,128,255,256,32000)) {
            val data=ByteArray(size){it.toByte()};assertArrayEquals(data,NfcDataProtocol.decodeDo53(NfcDataProtocol.encodeDo53(data)))
        }
        assertNull(NfcDataProtocol.decodeDo53(byteArrayOf(0x53,0)))
        assertNull(NfcDataProtocol.decodeDo53(byteArrayOf(0x53,0x83.toByte(),0,0,1,0)))
        try{NfcDataProtocol.encodeDo53(ByteArray(32001));fail("unbounded")}catch(_:IllegalArgumentException){}
    }
}
