package app.mikaki.identity_proximity

/** Only public engagement crosses this state machine. Rust validates the exact Hr before Hs. */
internal class NegotiatedHandover(private val request: (ByteArray) -> Unit) {
    companion object {
        private val service = "urn:nfc:sn:handover".toByteArray(Charsets.US_ASCII)
        fun record(type: String, payload: ByteArray): ByteArray {
            require(payload.size <= 255)
            val kind = type.toByteArray(Charsets.US_ASCII)
            return byteArrayOf(0xd1.toByte(),kind.size.toByte(),payload.size.toByte()) + kind + payload
        }
        fun initial(): ByteArray = record("Tp",byteArrayOf(0x10,service.size.toByte()) + service + byteArrayOf(0,32,15,0x0f,0xfe.toByte()))
        fun select(): ByteArray = record("Ts",byteArrayOf(service.size.toByte()) + service)
    }
    private var phase = 0
    var complete = false; private set
    val tag = NdefType4(initial()) { message ->
        when (phase) {
            0 -> { require(message.contentEquals(select())); phase = 1; record("Te",byteArrayOf(0)) }
            1 -> { require(message.isNotEmpty()); phase = 2; request(message.copyOf()); byteArrayOf() }
            else -> throw IllegalStateException("handover_consumed")
        }
    }
    fun publish(message: ByteArray) {
        require(phase == 2 && !tag.failed && message.isNotEmpty() && message.size <= 4094)
        tag.replace(message); phase = 3; complete = true
    }
}
