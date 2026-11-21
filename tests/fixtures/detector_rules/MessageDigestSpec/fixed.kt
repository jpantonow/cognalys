import java.security.MessageDigest

class Fingerprints {
    fun fingerprint(input: ByteArray): ByteArray {
        try {
            return MessageDigest.getInstance("SHA-512").digest(input)
        } catch (e: Exception) {
            return ByteArray(0)
        }
    }
}
