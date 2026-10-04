package app.mikaki.identity_proximity

/** Negotiated retrieval keeps Hs readable until the reader selects the mdoc data AID. */
internal class NfcDataRouting(private val afterHandover: Boolean) {
    private var selected = false
    fun route(command: ByteArray): Boolean {
        if (!afterHandover || selected) return true
        val aid = byteArrayOf(0,0xa4.toByte(),4,0,7,0xa0.toByte(),0,0,2,0x48,4,0)
        if (command.contentEquals(aid) || command.contentEquals(aid+byteArrayOf(0))) {
            selected = true
            return true
        }
        return false
    }
}
