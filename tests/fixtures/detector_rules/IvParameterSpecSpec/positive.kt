package fixture

import java.security.SecureRandom
import javax.crypto.spec.IvParameterSpec

class Ivs {
    fun iv(): IvParameterSpec {
        return IvParameterSpec(ByteArray(16))
    }
}
