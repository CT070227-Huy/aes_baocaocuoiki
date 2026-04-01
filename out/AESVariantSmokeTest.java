import crypto.AESBlockCipher;
import crypto.AESKeySchedule;
import crypto.AESVariant;

public class AESVariantSmokeTest {
    public static void main(String[] args) {
        verify(
                AESVariant.AES_128,
                "000102030405060708090A0B0C0D0E0F",
                "00112233445566778899AABBCCDDEEFF",
                "69C4E0D86A7B0430D8CDB78070B4C55A"
        );
        verify(
                AESVariant.AES_192,
                "000102030405060708090A0B0C0D0E0F1011121314151617",
                "00112233445566778899AABBCCDDEEFF",
                "DDA97CA4864CDFE06EAF70A0EC0D7191"
        );
        verify(
                AESVariant.AES_256,
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                "00112233445566778899AABBCCDDEEFF",
                "8EA2B7CA516745BFEAFC49904B496089"
        );

        System.out.println("AES variant smoke test passed.");
    }

    private static void verify(AESVariant variant, String keyHex, String plainHex, String expectedCipherHex) {
        AESKeySchedule keySchedule = new AESKeySchedule(variant);
        AESBlockCipher blockCipher = new AESBlockCipher(variant);

        byte[] key = fromHex(keyHex);
        byte[] plainText = fromHex(plainHex);
        byte[] expandedKey = keySchedule.expandKey(key);
        byte[] cipherText = blockCipher.encryptBlock(plainText, expandedKey);

        if (!toHex(cipherText).equals(expectedCipherHex)) {
            throw new AssertionError("Unexpected ciphertext for " + variant + ": " + toHex(cipherText));
        }

        byte[] decrypted = blockCipher.decryptBlock(cipherText, expandedKey);
        if (!toHex(decrypted).equals(plainHex)) {
            throw new AssertionError("Unexpected plaintext for " + variant + ": " + toHex(decrypted));
        }
    }

    private static byte[] fromHex(String hex) {
        byte[] result = new byte[hex.length() / 2];

        for (int i = 0; i < result.length; i++) {
            int index = i * 2;
            result[i] = (byte) Integer.parseInt(hex.substring(index, index + 2), 16);
        }

        return result;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);

        for (byte value : bytes) {
            builder.append(String.format("%02X", value));
        }

        return builder.toString();
    }
}
