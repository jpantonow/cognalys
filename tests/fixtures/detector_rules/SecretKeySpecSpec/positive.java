package fixture;

import java.nio.charset.StandardCharsets;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class Keys {
    SecretKey key() throws Exception {
        return new SecretKeySpec("0123456789abcdef".getBytes(StandardCharsets.UTF_8), "AES");
    }
}
