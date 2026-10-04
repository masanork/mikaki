package app.mikaki.identity_proximity

import org.junit.Assert.*
import org.junit.Test

class NfcDataRoutingTest {
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    @Test fun handoverRemainsReadableAndOnlyDataSelectionCanDeliverEncryptedRequest() {
        var hr:ByteArray?=null
        val flow=NegotiatedHandover {hr=it}
        val tag=flow.tag
        assertArrayEquals(hex("9000"),tag.exchange(hex("00a4040007d276000085010100")))
        assertArrayEquals(hex("9000"),tag.exchange(hex("00a4000c02e104")))
        fun write(message:ByteArray) {
            val data=byteArrayOf(0,message.size.toByte())+message
            assertArrayEquals(hex("9000"),tag.exchange(byteArrayOf(0,0xd6.toByte(),0,0,data.size.toByte())+data))
        }
        write(NegotiatedHandover.select());write(hex("919203"))
        assertArrayEquals(hex("919203"),hr)
        val hs=NegotiatedHandover.record("Hs",byteArrayOf(0x15))
        flow.publish(hs)
        val routing=NfcDataRouting(true);val protocol=NfcDataProtocol()
        fun exchange(command:ByteArray):ByteArray? = if(routing.route(command))protocol.exchange(command)else tag.exchange(command)
        assertArrayEquals(hs+hex("9000"),exchange(byteArrayOf(0,0xb0.toByte(),0,2,hs.size.toByte())))
        assertNull(protocol.takeRequest())
        assertArrayEquals(hex("9000"),exchange(hex("00a4040007a0000002480400")))
        assertNull(exchange(hex("00c30000035301aa00")))
        assertArrayEquals(hex("aa"),protocol.takeRequest());assertTrue(protocol.waiting)
        assertArrayEquals(hex("5301bb9000"),protocol.respond(hex("bb")));assertTrue(protocol.done)
        assertArrayEquals(hex("6985"),exchange(hex("00b0000002")))
    }
    @Test fun keepsNdefReadableUntilDataAidAndThenNeverFallsBack() {
        for (le in listOf("", "00")) {
            val routing = NfcDataRouting(true)
            val selectNdef = hex("00a4040007d276000085010100")
            val read = hex("00b0000002")
            assertFalse(routing.route(selectNdef));assertFalse(routing.route(read))
            assertFalse(routing.route(hex("00a4040007a0000002480401")))
            assertTrue(routing.route(hex("00a4040007a0000002480400"+le)))
            assertTrue(routing.route(hex("10c300000153")))
            assertTrue(routing.route(selectNdef));assertTrue(routing.route(read))
            // Once on data, a NDEF reselect is rejected by the data protocol, rather than revealing Hs again.
            val protocol = NfcDataProtocol()
            assertArrayEquals(hex("9000"),protocol.exchange(hex("00a4040007a0000002480400"+le)))
            assertArrayEquals(hex("6a86"),protocol.exchange(selectNdef));assertTrue(protocol.closed)
        }
    }
    @Test fun qrRetrievalRoutesEveryCommandToDataWithoutEngagementFallback() {
        val routing=NfcDataRouting(false)
        assertTrue(routing.route(hex("00b0000002")))
        assertTrue(routing.route(hex("00a4040007d276000085010100")))
    }
}
