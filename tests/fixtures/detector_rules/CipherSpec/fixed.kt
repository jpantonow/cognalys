package fixture

import javax.crypto.Cipher
import javax.crypto.SecretKey

class Sealer {
    fun seal(key: SecretKey, data: ByteArray): ByteArray {
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            return cipher.doFinal(data)
        } catch (e: Exception) {
            return ByteArray(0)
        }
    }
}
