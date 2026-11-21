import java.security.MessageDigest;

class Checksums {
    byte[] hash(byte[] input) throws Exception {
        return MessageDigest.getInstance("MD5").digest(input);
    }
}
