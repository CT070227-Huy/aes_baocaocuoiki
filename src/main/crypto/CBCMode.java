package crypto;

public class CBCMode {
    private final AESKeySchedule keySchedule = new AESKeySchedule();
    private final AESBlockCipher blockCipher = new AESBlockCipher();

    public byte[] encrypt(byte[] plainText, byte[] key, byte[] iv) {
        validateInput(plainText, "Plaintext");
        validateKey(key);
        validateIv(iv);

        byte[] expandedKey = keySchedule.expandKey(key);
        byte[] cipherText = new byte[plainText.length];
        byte[] previousBlock = copyBlock(iv, 0);

        for (int offset = 0; offset < plainText.length; offset += AESConstants.BLOCK_SIZE) {
            byte[] plainBlock = copyBlock(plainText, offset);
            byte[] xoredBlock = xorBlocks(plainBlock, previousBlock);
            byte[] encryptedBlock = blockCipher.encryptBlock(xoredBlock, expandedKey);

            System.arraycopy(encryptedBlock, 0, cipherText, offset, AESConstants.BLOCK_SIZE);
            previousBlock = encryptedBlock;
        }

        return cipherText;
    }

    public byte[] decrypt(byte[] cipherText, byte[] key, byte[] iv) {
        validateInput(cipherText, "Ciphertext");
        validateKey(key);
        validateIv(iv);

        byte[] expandedKey = keySchedule.expandKey(key);
        byte[] plainText = new byte[cipherText.length];
        byte[] previousBlock = copyBlock(iv, 0);

        for (int offset = 0; offset < cipherText.length; offset += AESConstants.BLOCK_SIZE) {
            byte[] cipherBlock = copyBlock(cipherText, offset);
            byte[] decryptedBlock = blockCipher.decryptBlock(cipherBlock, expandedKey);
            byte[] plainBlock = xorBlocks(decryptedBlock, previousBlock);

            System.arraycopy(plainBlock, 0, plainText, offset, AESConstants.BLOCK_SIZE);
            previousBlock = cipherBlock;
        }

        return plainText;
    }

    private void validateInput(byte[] data, String label) {
        if (data == null) {
            throw new IllegalArgumentException(label + " must not be null.");
        }

        if (data.length % AESConstants.BLOCK_SIZE != 0) {
            throw new IllegalArgumentException(label + " length must be a multiple of 16 bytes.");
        }
    }

    private void validateKey(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("AES-128 key must not be null.");
        }

        if (key.length != AESConstants.KEY_SIZE) {
            throw new IllegalArgumentException("AES-128 key must be exactly 16 bytes.");
        }
    }

    private void validateIv(byte[] iv) {
        if (iv == null) {
            throw new IllegalArgumentException("IV must not be null.");
        }

        if (iv.length != AESConstants.BLOCK_SIZE) {
            throw new IllegalArgumentException("IV must be exactly 16 bytes.");
        }
    }

    private byte[] xorBlocks(byte[] left, byte[] right) {
        byte[] result = new byte[AESConstants.BLOCK_SIZE];

        for (int i = 0; i < AESConstants.BLOCK_SIZE; i++) {
            result[i] = (byte) ((left[i] ^ right[i]) & 0xFF);
        }

        return result;
    }

    private byte[] copyBlock(byte[] source, int offset) {
        byte[] block = new byte[AESConstants.BLOCK_SIZE];
        System.arraycopy(source, offset, block, 0, AESConstants.BLOCK_SIZE);
        return block;
    }
}
