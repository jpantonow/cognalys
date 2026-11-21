package fixture

import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class Kdf {
    fun derive(password: CharArray, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(password, salt, 4096, 256)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
    }
}
