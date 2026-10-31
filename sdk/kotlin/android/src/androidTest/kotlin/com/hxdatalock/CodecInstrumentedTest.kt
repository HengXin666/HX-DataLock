package com.hxdatalock

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CodecInstrumentedTest {
    @Test
    fun userLocksAndOpensOnDevice() {
        val password = "correct horse battery staple for hx datalock"
        val keyring = HxDataLock.createKeyring(
            password,
            CreateKeyringOptions(scryptN = 16384, allowLowScryptN = true),
        )
        val user = HxDataLock.makeUserDataLock(keyring, password)
        val envelope = user.lockText("android instrumented")
        assertEquals("android instrumented", user.openText(envelope))
        user.close()
    }
}
