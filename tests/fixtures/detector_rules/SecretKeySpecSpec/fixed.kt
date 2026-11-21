package fixture

import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class Keys {
    fun key(): SecretKey {
        return KeyGenerator.getInstance("AES").generateKey()
    }
}
