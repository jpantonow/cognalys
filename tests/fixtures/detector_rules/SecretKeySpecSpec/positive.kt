package fixture

import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class Keys {
    fun key(): SecretKey {
        return SecretKeySpec("0123456789abcdef".toByteArray(Charsets.UTF_8), "AES")
    }
}
