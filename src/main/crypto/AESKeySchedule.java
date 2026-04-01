package crypto;

import java.util.Objects;

public class AESKeySchedule {
    private static final int WORD_SIZE = 4;
    private static final int BLOCK_WORDS = AESConstants.BLOCK_SIZE / WORD_SIZE;

    private final AESVariant variant;

    public AESKeySchedule() {
        this(AESConstants.DEFAULT_VARIANT);
    }

    public AESKeySchedule(AESVariant variant) {
        this.variant = Objects.requireNonNull(variant, "Biến thể AES không được để trống.");
    }

    // Backward-compatible overload that uses the instance's configured variant.
    public byte[] expandKey(byte[] key) {
        return expandKey(key, variant);
    }

    // Expand the raw key into round keys for the requested AES variant.
    public byte[] expandKey(byte[] key, AESVariant variant) {
        AESVariant resolvedVariant = Objects.requireNonNull(variant, "Biến thể AES không được để trống.");
        validateKey(key, resolvedVariant);

        int nk = resolvedVariant.getNk();
        int nr = resolvedVariant.getNr();
        int totalWords = BLOCK_WORDS * (nr + 1);
        byte[] expandedKey = new byte[resolvedVariant.getExpandedKeyLengthBytes()];
        System.arraycopy(key, 0, expandedKey, 0, resolvedVariant.getKeyLengthBytes());

        for (int i = nk; i < totalWords; i++) {
            byte[] tempWord = getWord(expandedKey, i - 1);

            if (i % nk == 0) {
                tempWord = xorWord(subWord(rotWord(tempWord)), rconWord(i / nk));
            } else if (resolvedVariant == AESVariant.AES_256 && i % nk == 4) {
                // AES-256 applies an extra SubWord in the middle of each key block.
                tempWord = subWord(tempWord);
            }

            byte[] previousKeyWord = getWord(expandedKey, i - nk);
            byte[] newWord = xorWord(previousKeyWord, tempWord);
            setWord(expandedKey, i, newWord);
        }

        return expandedKey;
    }

    private void validateKey(byte[] key, AESVariant variant) {
        if (key == null) {
            throw new IllegalArgumentException("Khóa AES không được để trống.");
        }

        if (key.length != variant.getKeyLengthBytes()) {
            throw new IllegalArgumentException(
                    "Khóa AES phải có đúng " + variant.getKeyLengthBytes() + " byte."
            );
        }
    }

    // Rotate a 4-byte word left by one byte.
    private byte[] rotWord(byte[] word) {
        return new byte[] {word[1], word[2], word[3], word[0]};
    }

    // Substitute each byte of the word through the AES S-Box.
    private byte[] subWord(byte[] word) {
        byte[] substituted = new byte[WORD_SIZE];

        for (int i = 0; i < WORD_SIZE; i++) {
            substituted[i] = (byte) AESConstants.S_BOX[word[i] & 0xFF];
        }

        return substituted;
    }

    // XOR two 4-byte words.
    private byte[] xorWord(byte[] left, byte[] right) {
        byte[] result = new byte[WORD_SIZE];

        for (int i = 0; i < WORD_SIZE; i++) {
            result[i] = (byte) ((left[i] ^ right[i]) & 0xFF);
        }

        return result;
    }

    private byte[] getWord(byte[] expandedKey, int wordIndex) {
        byte[] word = new byte[WORD_SIZE];
        System.arraycopy(expandedKey, wordIndex * WORD_SIZE, word, 0, WORD_SIZE);
        return word;
    }

    private void setWord(byte[] expandedKey, int wordIndex, byte[] word) {
        System.arraycopy(word, 0, expandedKey, wordIndex * WORD_SIZE, WORD_SIZE);
    }

    private byte[] rconWord(int round) {
        return new byte[] {(byte) AESConstants.RCON[round], 0x00, 0x00, 0x00};
    }
}
