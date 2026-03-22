package file;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

// .enc layout:
// [4-byte magic][1-byte version][2-byte file-name length][n-byte file name][16-byte IV][8-byte cipher length][m-byte cipher text]
public final class EncryptedFileFormat {
    public static final String MAGIC_HEADER = "AESF";
    public static final byte VERSION = 1;
    public static final int MAGIC_HEADER_LENGTH = 4;
    public static final int VERSION_LENGTH = 1;
    public static final int FILE_NAME_LENGTH_BYTES = 2;
    public static final int IV_LENGTH = 16;
    public static final int CIPHER_TEXT_LENGTH_BYTES = 8;
    public static final int FIXED_METADATA_LENGTH = MAGIC_HEADER_LENGTH + VERSION_LENGTH
            + FILE_NAME_LENGTH_BYTES + IV_LENGTH + CIPHER_TEXT_LENGTH_BYTES;

    private EncryptedFileFormat() {
    }

    public static byte[] magicHeaderBytes() {
        return MAGIC_HEADER.getBytes(StandardCharsets.US_ASCII);
    }

    public static boolean isValidHeader(byte[] header) {
        return header != null
                && header.length == MAGIC_HEADER_LENGTH
                && Arrays.equals(header, magicHeaderBytes());
    }

    public static boolean isSupportedVersion(byte version) {
        return version == VERSION;
    }
}
