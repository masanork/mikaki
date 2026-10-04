package app.mikaki.identity_proximity

import org.junit.Assert.*
import org.junit.Test

class NdefType4Test {
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun select(tag: NdefType4) {
        assertArrayEquals(hex("9000"),tag.exchange(hex("00a4040007d276000085010100")))
        assertArrayEquals(hex("9000"),tag.exchange(hex("00a4000c02e104")))
    }
    @Test fun readsExactPublicNdefWithLengthAndOffsets() {
        val message=ByteArray(300){it.toByte()};val tag=NdefType4(message)
        select(tag)
        assertArrayEquals(hex("012c9000"),tag.exchange(hex("00b0000002")))
        assertArrayEquals(message.copyOfRange(0,256)+hex("9000"),tag.exchange(hex("00b0000200")))
        assertArrayEquals(message.copyOfRange(256,300)+hex("9000"),tag.exchange(hex("00b001022c")))
        assertArrayEquals(hex("6b00"),tag.exchange(hex("00b001022d")))
        assertArrayEquals(hex("6986"),tag.exchange(hex("00d600000100")))
    }
    @Test fun selectionResetAndUnknownFilesNeverRevealStaleNdef() {
        val tag=NdefType4(hex("d00000"))
        assertArrayEquals(hex("6985"),tag.exchange(hex("00b0000002")))
        select(tag);tag.reset()
        assertArrayEquals(hex("6985"),tag.exchange(hex("00b0000002")))
        select(tag)
        assertArrayEquals(hex("6a82"),tag.exchange(hex("00a4000c02ffff")))
        assertArrayEquals(hex("6985"),tag.exchange(hex("00b0000002")))
        select(tag)
        assertArrayEquals(hex("6a82"),tag.exchange(hex("00a4040001ff")))
        assertArrayEquals(hex("6985"),tag.exchange(hex("00a4000c02e104")))
    }
    @Test fun rejectsMalformedExtendedAndUnboundedCommands() {
        val tag=NdefType4(hex("d00000"));select(tag)
        assertArrayEquals(hex("6e00"),tag.exchange(hex("01b0000002")))
        assertArrayEquals(hex("6700"),tag.exchange(hex("00b00000000002")))
        assertArrayEquals(hex("6a86"),tag.exchange(hex("00b0800002")))
        assertArrayEquals(hex("6700"),tag.exchange(ByteArray(100000)))
        assertArrayEquals(hex("6700"),tag.exchange(hex("00a4040007d276")))
        assertArrayEquals(hex("6985"),tag.exchange(hex("00b0000002")))
    }
    @Test fun capabilityContainerMatchesReadOnlyFileLimits() {
        val tag=NdefType4(hex("d00000"));select(tag)
        assertArrayEquals(hex("9000"),tag.exchange(hex("00a4000c02e103")))
        assertArrayEquals(hex("000f20010001000406e104100000ff9000"),tag.exchange(hex("00b000000f")))
        try { NdefType4(ByteArray(4095));fail("unbounded NDEF") } catch (_: IllegalArgumentException) {}
    }
}
