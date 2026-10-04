package app.mikaki.identity_proximity

import org.junit.Assert.*
import org.junit.Test

class NegotiatedHandoverTest {
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun select(tag: NdefType4) {
        assertArrayEquals(hex("9000"),tag.exchange(hex("00a4040007d276000085010100")))
        assertArrayEquals(hex("9000"),tag.exchange(hex("00a4000c02e104")))
    }
    private fun write(tag: NdefType4, message: ByteArray) {
        assertArrayEquals(hex("9000"),tag.exchange(hex("00d60000020000")))
        for (offset in message.indices step 255) {
            val part = message.copyOfRange(offset,minOf(offset+255,message.size))
            val address = offset+2
            assertArrayEquals(hex("9000"),tag.exchange(byteArrayOf(0,0xd6.toByte(),(address shr 8).toByte(),address.toByte(),part.size.toByte())+part))
        }
        assertArrayEquals(hex("9000"),tag.exchange(hex("00d6000002")+byteArrayOf((message.size shr 8).toByte(),message.size.toByte())))
    }
    @Test fun writableTnepExchangesTsTeAndPreservesOpaqueHrUntilRustPublishesHs() {
        var request: ByteArray? = null
        val flow = NegotiatedHandover { request = it }
        val tag = flow.tag; select(tag)
        assertArrayEquals(hex("9000"),tag.exchange(hex("00a4000c02e103")))
        assertArrayEquals(hex("000f20010000ff0406e104100000009000"),tag.exchange(hex("00b000000f")))
        select(tag);write(tag,NegotiatedHandover.select())
        val te=NegotiatedHandover.record("Te",byteArrayOf(0))
        assertArrayEquals(te+hex("9000"),tag.exchange(byteArrayOf(0,0xb0.toByte(),0,2,te.size.toByte())))
        val hr=ByteArray(600){it.toByte()};write(tag,hr)
        assertArrayEquals(hr,request)
        assertArrayEquals(hex("00009000"),tag.exchange(hex("00b0000002")))
        assertFalse(flow.complete)
        val hs=NegotiatedHandover.record("Hs",byteArrayOf(0x15))
        flow.publish(hs);assertTrue(flow.complete)
        assertArrayEquals(hs+hex("9000"),tag.exchange(byteArrayOf(0,0xb0.toByte(),0,2,hs.size.toByte())))
        try { flow.publish(hs);fail("duplicate Hs") } catch (_: IllegalArgumentException) {}
        assertArrayEquals(hex("6985"),tag.exchange(hex("00d60000030001ff")))
        assertTrue(tag.failed)
    }
    @Test fun rejectsUnknownServiceNoncontiguousWritesDuplicateResetAndLengthMismatch() {
        for (bad in listOf(hex("00d6000301ff"),hex("00d60000020000"),hex("00d60000020002"))) {
            val tag=NegotiatedHandover{}.tag;select(tag)
            assertArrayEquals(hex("9000"),tag.exchange(hex("00d60000020000")))
            assertFalse(tag.exchange(bad).contentEquals(hex("9000")));assertTrue(tag.failed)
        }
        val flow=NegotiatedHandover{};select(flow.tag)
        assertArrayEquals(hex("6985"),flow.tag.exchange(hex("00d60000030001ff")))
        assertTrue(flow.tag.failed)
    }
    @Test fun oneShotUpdateAndMaximumMessageAreBounded() {
        val flow=NegotiatedHandover{};val tag=flow.tag;select(tag)
        val ts=NegotiatedHandover.select()
        val data=byteArrayOf(0,ts.size.toByte())+ts
        assertArrayEquals(hex("9000"),tag.exchange(byteArrayOf(0,0xd6.toByte(),0,0,data.size.toByte())+data))
        write(tag,ByteArray(4094){7})
        flow.publish(NegotiatedHandover.record("Hs",byteArrayOf(0x15)))
        val oversized=NegotiatedHandover{}.tag;select(oversized)
        assertArrayEquals(hex("9000"),oversized.exchange(hex("00d60000020000")))
        assertArrayEquals(hex("6b00"),oversized.exchange(hex("00d6100001ff")))
    }
}
