package fixture;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

class Kdf {
    byte[] derive(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 1000, 256);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }
}
