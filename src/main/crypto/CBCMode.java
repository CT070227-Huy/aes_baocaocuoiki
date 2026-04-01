package crypto;

import java.util.Objects;

public class CBCMode {
    private final AESVariant variant;
    private final AESKeySchedule keySchedule;
    private final AESBlockCipher blockCipher;

    public CBCMode() {
        this(AESConstants.DEFAULT_VARIANT);
    }

    public CBCMode(AESVariant variant) {
        this.variant = Objects.requireNonNull(variant, "AES variant must not be null.");
        this.keySchedule = new AESKeySchedule(variant);
        this.blockCipher = new AESBlockCipher(variant);
    }

    public byte[] encrypt(byte[] plainText, byte[] key, byte[] iv) {
        return encrypt(plainText, key, iv, variant);
    }

    // CBC chaining is unchanged; only the AES variant is configurable.
    public byte[] encrypt(byte[] plainText, byte[] key, byte[] iv, AESVariant variant) {
        AESVariant resolvedVariant = Objects.requireNonNull(variant, "AES variant must not be null.");
        validateInput(plainText, "Plaintext");
        validateKey(key, resolvedVariant);
        validateIv(iv);

        byte[] expandedKey = keySchedule.expandKey(key, resolvedVariant);
        byte[] cipherText = new byte[plainText.length];
        byte[] previousBlock = copyBlock(iv, 0);

        for (int offset = 0; offset < plainText.length; offset += AESConstants.BLOCK_SIZE) {
            byte[] plainBlock = copyBlock(plainText, offset);
            byte[] xoredBlock = xorBlocks(plainBlock, previousBlock);
            byte[] encryptedBlock = blockCipher.encryptBlock(xoredBlock, expandedKey, resolvedVariant);

            System.arraycopy(encryptedBlock, 0, cipherText, offset, AESConstants.BLOCK_SIZE);
            previousBlock = encryptedBlock;
        }

        return cipherText;
    }

    public byte[] decrypt(byte[] cipherText, byte[] key, byte[] iv) {
        return decrypt(cipherText, key, iv, variant);
    }

    // CBC chaining is unchanged; only the AES variant is configurable.
    public byte[] decrypt(byte[] cipherText, byte[] key, byte[] iv, AESVariant variant) {
        AESVariant resolvedVariant = Objects.requireNonNull(variant, "AES variant must not be null.");
        validateInput(cipherText, "Ciphertext");
        validateKey(key, resolvedVariant);
        validateIv(iv);

        byte[] expandedKey = keySchedule.expandKey(key, resolvedVariant);
        byte[] plainText = new byte[cipherText.length];
        byte[] previousBlock = copyBlock(iv, 0);

        for (int offset = 0; offset < cipherText.length; offset += AESConstants.BLOCK_SIZE) {
            byte[] cipherBlock = copyBlock(cipherText, offset);
            byte[] decryptedBlock = blockCipher.decryptBlock(cipherBlock, expandedKey, resolvedVariant);
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
            throw new IllegalArgumentException(
                    label + " length must be a multiple of " + AESConstants.BLOCK_SIZE + " bytes."
            );
        }
    }

    private void validateKey(byte[] key, AESVariant variant) {
        if (key == null) {
            throw new IllegalArgumentException("AES key must not be null.");
        }

        if (key.length != variant.getKeyLengthBytes()) {
            throw new IllegalArgumentException(
                    "AES key must be exactly " + variant.getKeyLengthBytes() + " bytes."
            );
        }
    }

    private void validateIv(byte[] iv) {
        if (iv == null) {
            throw new IllegalArgumentException("IV must not be null.");
        }

        if (iv.length != AESConstants.BLOCK_SIZE) {
            throw new IllegalArgumentException(
                    "IV must be exactly " + AESConstants.BLOCK_SIZE + " bytes."
            );
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
