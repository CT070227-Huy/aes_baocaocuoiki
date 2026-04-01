package crypto;

// Shared AES parameters for the supported key sizes.
public enum AESVariant {
    AES_128(16, 4, 10),
    AES_192(24, 6, 12),
    AES_256(32, 8, 14);

    private final int keyLengthBytes;
    private final int nk;
    private final int nr;

    AESVariant(int keyLengthBytes, int nk, int nr) {
        this.keyLengthBytes = keyLengthBytes;
        this.nk = nk;
        this.nr = nr;
    }

    public int getKeyLengthBytes() {
        return keyLengthBytes;
    }

    public int getNk() {
        return nk;
    }

    public int getNr() {
        return nr;
    }

    public int getExpandedKeyLengthBytes() {
        return AESConstants.BLOCK_SIZE * (nr + 1);
    }
}
