package fixture

import java.security.SecureRandom
import javax.crypto.spec.IvParameterSpec

class Ivs {
    fun iv(): IvParameterSpec {
        val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }
        return IvParameterSpec(iv)
    }
}
