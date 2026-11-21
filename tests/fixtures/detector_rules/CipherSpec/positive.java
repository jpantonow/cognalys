package fixture;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

class Box {
    byte[] encrypt(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }
}
