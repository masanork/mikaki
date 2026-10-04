package app.mikaki.identity_proximity

import org.junit.Assert.*
import org.junit.Test

class TransferDeadlineTest {
    @Test fun expiryStopsContinuationAndClockRollbackDoesNotExtendIt() {
        val limit=TransferDeadline.fromEpochSeconds(101,100000,8000)
        assertFalse(limit.expired(100999,8999))
        assertTrue(limit.expired(101000,8500)) // Wall clock moves forward.
        assertTrue(limit.expired(90000,9000)) // Wall clock moves backward.
        assertEquals(1L,limit.remainingMillis(90000,8999))
    }
    @Test fun rollbackBeforeSubmissionStillUsesTheOriginalSessionClock() {
        // Approval is submitted after 900 ms with a rolled-back wall clock.
        val limit=TransferDeadline.fromEpochSeconds(101,100000,8000)
        assertEquals(100L,limit.remainingMillis(90000,8900))
        assertTrue(limit.expired(90000,9000))
    }
    @Test fun transportNeverOutlivesItsTwoMinuteCap() {
        val limit=TransferDeadline.fromEpochSeconds(1000,100000,8000)
        assertFalse(limit.expired(100000,127999))
        assertTrue(limit.expired(100000,128000))
    }
    @Test fun invalidOrAlreadyExpiredApprovalCannotStartTransfer() {
        for(expiry in listOf(0L,-1L,100L,Long.MAX_VALUE)) {
            try { TransferDeadline.fromEpochSeconds(expiry,100000,8000);fail("accepted $expiry") }
            catch(_:IllegalArgumentException) {}
        }
    }
}
