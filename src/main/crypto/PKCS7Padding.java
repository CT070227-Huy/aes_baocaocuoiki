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
            throw new IllegalArgumentException("Dữ liệu đã đệm không được rỗng.");
        }

        if (data.length % blockSize != 0) {
            throw new IllegalArgumentException("Độ dài dữ liệu đã đệm phải là bội số của kích thước block.");
        }

        int paddingLength = data[data.length - 1] & 0xFF;
        if (paddingLength < 1 || paddingLength > blockSize) {
            throw new IllegalArgumentException("Độ dài đệm PKCS#7 không hợp lệ.");
        }

        int paddingStart = data.length - paddingLength;
        for (int i = paddingStart; i < data.length; i++) {
            if ((data[i] & 0xFF) != paddingLength) {
                throw new IllegalArgumentException("Byte đệm PKCS#7 không hợp lệ.");
            }
        }

        byte[] unpadded = new byte[paddingStart];
        System.arraycopy(data, 0, unpadded, 0, paddingStart);
        return unpadded;
    }

    // PKCS#7 supports block sizes from 1 to 255.
    private void validateBlockSize(int blockSize) {
        if (blockSize <= 0 || blockSize > 255) {
            throw new IllegalArgumentException("Kích thước block phải trong khoảng 1..255.");
        }
    }

    private void validateData(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Dữ liệu không được để trống.");
        }
    }
}
