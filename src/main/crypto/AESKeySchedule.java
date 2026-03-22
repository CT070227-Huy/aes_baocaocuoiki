package crypto;

public class AESKeySchedule {
    private static final int WORD_SIZE = 4;
    private static final int KEY_WORDS = AESConstants.KEY_SIZE / WORD_SIZE;
    private static final int TOTAL_WORDS = (AESConstants.NUMBER_OF_ROUNDS + 1) * KEY_WORDS;
    private static final int EXPANDED_KEY_SIZE = TOTAL_WORDS * WORD_SIZE;

    // Expand one 16-byte AES-128 key into 11 round keys (176 bytes).
    public byte[] expandKey(byte[] key) {
        validateKey(key);

        byte[] expandedKey = new byte[EXPANDED_KEY_SIZE];
        System.arraycopy(key, 0, expandedKey, 0, AESConstants.KEY_SIZE);

        for (int wordIndex = KEY_WORDS; wordIndex < TOTAL_WORDS; wordIndex++) {
            byte[] tempWord = getWord(expandedKey, wordIndex - 1);

            // Every 4th word applies RotWord, SubWord, then XOR with RCON.
            if (wordIndex % KEY_WORDS == 0) {
                tempWord = xorWord(subWord(rotWord(tempWord)), rconWord(wordIndex / KEY_WORDS));
            }

            byte[] previousKeyWord = getWord(expandedKey, wordIndex - KEY_WORDS);
            byte[] newWord = xorWord(previousKeyWord, tempWord);
            setWord(expandedKey, wordIndex, newWord);
        }

        return expandedKey;
    }

    private void validateKey(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("AES-128 key must not be null.");
        }

        if (key.length != AESConstants.KEY_SIZE) {
            throw new IllegalArgumentException("AES-128 key must be exactly 16 bytes.");
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
