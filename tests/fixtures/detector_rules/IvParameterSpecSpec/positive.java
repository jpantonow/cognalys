package fixture;

import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;

class Ivs {
    IvParameterSpec iv() {
        return new IvParameterSpec(new byte[16]);
    }
}
