package crypto;

import java.security.SecureRandom;

public class RandomIVGenerator {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // Generate a fresh 16-byte IV for AES-CBC.
    public byte[] generateIV() {
        byte[] iv = new byte[AESConstants.BLOCK_SIZE];
        SECURE_RANDOM.nextBytes(iv);
        return iv;
    }
}
