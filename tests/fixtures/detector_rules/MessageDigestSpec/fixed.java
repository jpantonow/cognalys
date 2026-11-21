import java.security.MessageDigest;

class Checksums {
    byte[] hash(byte[] input) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(input);
    }
}
