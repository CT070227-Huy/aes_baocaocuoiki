package crypto;

public class AESBlockCipher {
    private static final int STATE_SIZE = 4;
    private static final int EXPANDED_KEY_SIZE =
            (AESConstants.NUMBER_OF_ROUNDS + 1) * AESConstants.BLOCK_SIZE;

    public byte[] encryptBlock(byte[] inputBlock, byte[] expandedKey) {
        validateBlock(inputBlock);
        validateExpandedKey(expandedKey);

        int[][] state = toState(inputBlock);

        addRoundKey(state, expandedKey, 0);

        for (int round = 1; round < AESConstants.NUMBER_OF_ROUNDS; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, expandedKey, round);
        }

        subBytes(state);
        shiftRows(state);
        addRoundKey(state, expandedKey, AESConstants.NUMBER_OF_ROUNDS);

        return fromState(state);
    }

    public byte[] decryptBlock(byte[] inputBlock, byte[] expandedKey) {
        validateBlock(inputBlock);
        validateExpandedKey(expandedKey);

        int[][] state = toState(inputBlock);

        addRoundKey(state, expandedKey, AESConstants.NUMBER_OF_ROUNDS);

        for (int round = AESConstants.NUMBER_OF_ROUNDS - 1; round >= 1; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, expandedKey, round);
            invMixColumns(state);
        }

        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, expandedKey, 0);

        return fromState(state);
    }

    private void validateBlock(byte[] inputBlock) {
        if (inputBlock == null) {
            throw new IllegalArgumentException("Input block must not be null.");
        }

        if (inputBlock.length != AESConstants.BLOCK_SIZE) {
            throw new IllegalArgumentException("Input block must be exactly 16 bytes.");
        }
    }

    private void validateExpandedKey(byte[] expandedKey) {
        if (expandedKey == null) {
            throw new IllegalArgumentException("Expanded key must not be null.");
        }

        if (expandedKey.length != EXPANDED_KEY_SIZE) {
            throw new IllegalArgumentException("Expanded key must be exactly 176 bytes.");
        }
    }

    // AES maps the block column by column into a 4x4 state matrix.
    private int[][] toState(byte[] block) {
        int[][] state = new int[STATE_SIZE][STATE_SIZE];

        for (int column = 0; column < STATE_SIZE; column++) {
            for (int row = 0; row < STATE_SIZE; row++) {
                state[row][column] = block[column * STATE_SIZE + row] & 0xFF;
            }
        }

        return state;
    }

    private byte[] fromState(int[][] state) {
        byte[] block = new byte[AESConstants.BLOCK_SIZE];

        for (int column = 0; column < STATE_SIZE; column++) {
            for (int row = 0; row < STATE_SIZE; row++) {
                block[column * STATE_SIZE + row] = (byte) (state[row][column] & 0xFF);
            }
        }

        return block;
    }

    private void addRoundKey(int[][] state, byte[] expandedKey, int round) {
        int roundOffset = round * AESConstants.BLOCK_SIZE;

        for (int column = 0; column < STATE_SIZE; column++) {
            for (int row = 0; row < STATE_SIZE; row++) {
                state[row][column] ^= expandedKey[roundOffset + column * STATE_SIZE + row] & 0xFF;
            }
        }
    }

    private void subBytes(int[][] state) {
        for (int row = 0; row < STATE_SIZE; row++) {
            for (int column = 0; column < STATE_SIZE; column++) {
                state[row][column] = AESConstants.S_BOX[state[row][column] & 0xFF];
            }
        }
    }

    private void invSubBytes(int[][] state) {
        for (int row = 0; row < STATE_SIZE; row++) {
            for (int column = 0; column < STATE_SIZE; column++) {
                state[row][column] = AESConstants.INV_S_BOX[state[row][column] & 0xFF];
            }
        }
    }

    private void shiftRows(int[][] state) {
        for (int row = 1; row < STATE_SIZE; row++) {
            int[] shiftedRow = new int[STATE_SIZE];

            for (int column = 0; column < STATE_SIZE; column++) {
                shiftedRow[column] = state[row][(column + row) % STATE_SIZE];
            }

            System.arraycopy(shiftedRow, 0, state[row], 0, STATE_SIZE);
        }
    }

    private void invShiftRows(int[][] state) {
        for (int row = 1; row < STATE_SIZE; row++) {
            int[] shiftedRow = new int[STATE_SIZE];

            for (int column = 0; column < STATE_SIZE; column++) {
                shiftedRow[column] = state[row][(column - row + STATE_SIZE) % STATE_SIZE];
            }

            System.arraycopy(shiftedRow, 0, state[row], 0, STATE_SIZE);
        }
    }

    private void mixColumns(int[][] state) {
        for (int column = 0; column < STATE_SIZE; column++) {
            int s0 = state[0][column];
            int s1 = state[1][column];
            int s2 = state[2][column];
            int s3 = state[3][column];

            state[0][column] = multiply(0x02, s0) ^ multiply(0x03, s1) ^ s2 ^ s3;
            state[1][column] = s0 ^ multiply(0x02, s1) ^ multiply(0x03, s2) ^ s3;
            state[2][column] = s0 ^ s1 ^ multiply(0x02, s2) ^ multiply(0x03, s3);
            state[3][column] = multiply(0x03, s0) ^ s1 ^ s2 ^ multiply(0x02, s3);
        }
    }

    private void invMixColumns(int[][] state) {
        for (int column = 0; column < STATE_SIZE; column++) {
            int s0 = state[0][column];
            int s1 = state[1][column];
            int s2 = state[2][column];
            int s3 = state[3][column];

            state[0][column] = multiply(0x0E, s0) ^ multiply(0x0B, s1)
                    ^ multiply(0x0D, s2) ^ multiply(0x09, s3);
            state[1][column] = multiply(0x09, s0) ^ multiply(0x0E, s1)
                    ^ multiply(0x0B, s2) ^ multiply(0x0D, s3);
            state[2][column] = multiply(0x0D, s0) ^ multiply(0x09, s1)
                    ^ multiply(0x0E, s2) ^ multiply(0x0B, s3);
            state[3][column] = multiply(0x0B, s0) ^ multiply(0x0D, s1)
                    ^ multiply(0x09, s2) ^ multiply(0x0E, s3);
        }
    }

    private int multiply(int coefficient, int value) {
        return GaloisField.multiply(coefficient, value) & 0xFF;
    }
}
