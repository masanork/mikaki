package app.mikaki.identity_proximity

/** Immutable native approval limit anchored at session creation: clock rollback cannot extend it. */
internal class TransferDeadline private constructor(private val wallEnd:Long, private val elapsedEnd:Long) {
    fun remainingMillis(wall:Long,elapsed:Long):Long = minOf(wallEnd-wall,elapsedEnd-elapsed).coerceAtLeast(0)
    fun expired(wall:Long,elapsed:Long) = remainingMillis(wall,elapsed)==0L
    companion object {
        fun fromEpochSeconds(expiresAt:Long,wall:Long,elapsed:Long):TransferDeadline {
            require(expiresAt in 1..Long.MAX_VALUE/1000 && wall>=0 && elapsed>=0)
            val remaining=(expiresAt*1000-wall).coerceAtMost(120000)
            require(remaining>0 && wall<=Long.MAX_VALUE-remaining && elapsed<=Long.MAX_VALUE-remaining)
            return TransferDeadline(wall+remaining,elapsed+remaining)
        }
    }
}
