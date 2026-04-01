package file;

import crypto.AESVariant;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

// .enc layouts:
// V1: [4-byte magic][1-byte version][2-byte file-name length][n-byte file name][16-byte IV][8-byte cipher length][m-byte cipher text]
// V2: [4-byte magic][1-byte version][1-byte AES variant][2-byte file-name length][n-byte file name][16-byte IV][8-byte cipher length][m-byte cipher text]
public final class EncryptedFileFormat {
    public static final String MAGIC_HEADER = "AESF";
    public static final byte VERSION_1 = 1;
    public static final byte VERSION_2 = 2;
    public static final byte VERSION = VERSION_2;
    public static final int MAGIC_HEADER_LENGTH = 4;
    public static final int VERSION_LENGTH = 1;
    public static final int VARIANT_LENGTH = 1;
    public static final int FILE_NAME_LENGTH_BYTES = 2;
    public static final int IV_LENGTH = 16;
    public static final int CIPHER_TEXT_LENGTH_BYTES = 8;
    public static final int FIXED_METADATA_LENGTH_V1 = MAGIC_HEADER_LENGTH + VERSION_LENGTH
            + FILE_NAME_LENGTH_BYTES + IV_LENGTH + CIPHER_TEXT_LENGTH_BYTES;
    public static final int FIXED_METADATA_LENGTH_V2 = MAGIC_HEADER_LENGTH + VERSION_LENGTH + VARIANT_LENGTH
            + FILE_NAME_LENGTH_BYTES + IV_LENGTH + CIPHER_TEXT_LENGTH_BYTES;
    public static final int MINIMUM_FIXED_METADATA_LENGTH = FIXED_METADATA_LENGTH_V1;

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
        return version == VERSION_1 || version == VERSION_2;
    }

    public static boolean usesVariantMetadata(byte version) {
        return version >= VERSION_2;
    }

    public static int fixedMetadataLength(byte version) {
        return usesVariantMetadata(version) ? FIXED_METADATA_LENGTH_V2 : FIXED_METADATA_LENGTH_V1;
    }

    public static byte variantCode(AESVariant variant) {
        return switch (variant) {
            case AES_128 -> 1;
            case AES_192 -> 2;
            case AES_256 -> 3;
        };
    }

    public static AESVariant variantFromCode(byte code) {
        return switch (code) {
            case 1 -> AESVariant.AES_128;
            case 2 -> AESVariant.AES_192;
            case 3 -> AESVariant.AES_256;
            default -> throw new IllegalArgumentException("Unsupported AES variant code: " + (code & 0xFF));
        };
    }
}
