package app.mikaki.identity_proximity

/** Read-only, bounded short-APDU NFC Type 4 tag. Contains only public engagement. */
internal class NdefType4(message: ByteArray, private val onWrite: ((ByteArray) -> ByteArray)? = null) {
    private var ndef: ByteArray = byteArrayOf()
    private var writing: java.io.ByteArrayOutputStream? = null
    var failed = false; private set
    private var application = false
    private var selected = 0
    private val aid = byteArrayOf(0xd2.toByte(), 0x76, 0, 0, 0x85.toByte(), 1, 1)
    private val cc = byteArrayOf(0, 15, 0x20, 1, 0, 1, 0, 4, 6, 0xe1.toByte(), 4, 0x10, 0, 0, 0xff.toByte())
    init {
        require(message.isNotEmpty() && message.size <= 4094)
        replace(message)
        if (onWrite != null) { cc[5] = 0; cc[6] = 0xff.toByte(); cc[14] = 0 }
    }
    fun replace(message: ByteArray) {
        require(message.size <= 4094)
        ndef = byteArrayOf((message.size shr 8).toByte(), message.size.toByte()) + message
    }
    fun reset() { application = false; selected = 0; writing = null }
    private fun fail(value: Int): ByteArray { failed = true; reset(); return status(value) }
    private fun status(value: Int) = byteArrayOf((value shr 8).toByte(), value.toByte())
    fun exchange(command: ByteArray): ByteArray {
        if (command.size !in 4..260) return status(0x6700)
        if (command[0].toInt() != 0) return status(0x6e00)
        val ins = command[1].toInt() and 255
        val p1 = command[2].toInt() and 255
        val p2 = command[3].toInt() and 255
        if (ins == 0xa4) {
            if (onWrite != null && writing != null) return fail(0x6985)
            // Failed selects invalidate the old selection; no stale-file reads.
            selected = 0
            if (command.size < 5) { application = false; return status(0x6700) }
            val lc = command[4].toInt() and 255
            if (lc == 0 || (command.size != 5 + lc && command.size != 6 + lc)) {
                application = false; return status(0x6700)
            }
            val data = command.copyOfRange(5,5+lc)
            if (p1 == 4 && p2 == 0) {
                application = data.contentEquals(aid)
                return status(if (application) 0x9000 else 0x6a82)
            }
            if (!application) return status(0x6985)
            if (p1 != 0 || p2 !in listOf(0,12) || data.size != 2) return status(0x6a86)
            val file = ((data[0].toInt() and 255) shl 8) or (data[1].toInt() and 255)
            if (file != 0xe103 && file != 0xe104) return status(0x6a82)
            selected = file
            return status(0x9000)
        }
        if (ins == 0xd6) {
            if (onWrite == null) return status(0x6986)
            if (failed || !application || selected != 0xe104) return fail(0x6985)
            if (p1 >= 128 || command.size < 6) return fail(0x6700)
            val lc = command[4].toInt() and 255
            if (lc == 0 || command.size != lc + 5) return fail(0x6700)
            val offset = (p1 shl 8) or p2
            val data = command.copyOfRange(5, command.size)
            try {
                if (offset == 0) {
                    if (data.size < 2) return fail(0x6700)
                    val length = ((data[0].toInt() and 255) shl 8) or (data[1].toInt() and 255)
                    if (length == 0) {
                        if (data.size != 2 || writing != null) return fail(0x6985)
                        writing = java.io.ByteArrayOutputStream(); replace(byteArrayOf())
                    } else {
                        val message = if (data.size == 2) {
                            val buffer = writing ?: return fail(0x6985)
                            if (buffer.size() != length) return fail(0x6700)
                            buffer.toByteArray()
                        } else {
                            if (writing != null || data.size != length + 2) return fail(0x6700)
                            data.copyOfRange(2, data.size)
                        }
                        if (length > 4094) return fail(0x6700)
                        writing = null; replace(onWrite(message))
                    }
                } else {
                    val buffer = writing ?: return fail(0x6985)
                    if (offset != buffer.size() + 2 || buffer.size() + data.size > 4094) return fail(0x6b00)
                    buffer.write(data)
                }
                return status(0x9000)
            } catch (_: Exception) { return fail(0x6985) }
        }
        if (ins != 0xb0) return status(0x6d00)
        if (!application || selected == 0) return status(0x6985)
        if (command.size != 5) return status(0x6700)
        if (p1 >= 128) return status(0x6a86) // No short-file identifier addressing.
        val offset = (p1 shl 8) or p2
        val length = (command[4].toInt() and 255).let { if (it == 0) 256 else it }
        val file = if (selected == 0xe103) cc else ndef
        if (offset > file.size || length > file.size - offset) return status(0x6b00)
        return file.copyOfRange(offset, offset + length) + status(0x9000)
    }
}
