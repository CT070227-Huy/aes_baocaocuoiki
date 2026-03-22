package crypto;

public class PKCS7Padding {
    public byte[] pad(byte[] data, int blockSize) {
        validateBlockSize(blockSize);
        validateData(data);

        int paddingLength = blockSize - (data.length % blockSize);
        if (paddingLength == 0) {
            paddingLength = blockSize;
        }

        byte[] padded = new byte[data.length + paddingLength];
        System.arraycopy(data, 0, padded, 0, data.length);

        for (int i = data.length; i < padded.length; i++) {
            padded[i] = (byte) paddingLength;
        }

        return padded;
    }

    public byte[] unpad(byte[] data, int blockSize) {
        validateBlockSize(blockSize);
        validateData(data);

        if (data.length == 0) {
            throw new IllegalArgumentException("Padded data must not be empty.");
        }

        if (data.length % blockSize != 0) {
            throw new IllegalArgumentException("Padded data length must be a multiple of block size.");
        }

        int paddingLength = data[data.length - 1] & 0xFF;
        if (paddingLength < 1 || paddingLength > blockSize) {
            throw new IllegalArgumentException("Invalid PKCS#7 padding length.");
        }

        int paddingStart = data.length - paddingLength;
        for (int i = paddingStart; i < data.length; i++) {
            if ((data[i] & 0xFF) != paddingLength) {
                throw new IllegalArgumentException("Invalid PKCS#7 padding bytes.");
            }
        }

        byte[] unpadded = new byte[paddingStart];
        System.arraycopy(data, 0, unpadded, 0, paddingStart);
        return unpadded;
    }

    // PKCS#7 supports block sizes from 1 to 255.
    private void validateBlockSize(int blockSize) {
        if (blockSize <= 0 || blockSize > 255) {
            throw new IllegalArgumentException("Block size must be in range 1..255.");
        }
    }

    private void validateData(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data must not be null.");
        }
    }
}
