package util;

import crypto.AESConstants;
import crypto.AESVariant;
import exception.InvalidKeyException;

import java.nio.file.Files;
import java.nio.file.Path;

// Utility helpers for common validation checks.
public final class ValidationUtils {
    private static final int AES_128_HEX_LENGTH = AESVariant.AES_128.getKeyLengthBytes() * 2;
    private static final int AES_192_HEX_LENGTH = AESVariant.AES_192.getKeyLengthBytes() * 2;
    private static final int AES_256_HEX_LENGTH = AESVariant.AES_256.getKeyLengthBytes() * 2;

    private ValidationUtils() {
    }

    public static void validateAesKeyString(String key) throws InvalidKeyException {
        validateAesKeyHex(key, AESConstants.DEFAULT_VARIANT);
    }

    public static void validateAesKeyString(String key, AESVariant variant) throws InvalidKeyException {
        validateAesKeyHex(key, variant);
    }

    public static void validateAesKeyHex(String key) throws InvalidKeyException {
        validateAesKeyHex(key, AESConstants.DEFAULT_VARIANT);
    }

    public static void validateAesKeyHex(String key, AESVariant variant) throws InvalidKeyException {
        parseAesKeyHex(key, variant);
    }

    public static void validateAesKeyHexFormat(String key) throws InvalidKeyException {
        if (key == null || key.isBlank()) {
            throw new InvalidKeyException("Vui lòng nhập khóa bí mật.");
        }

        if (!isSupportedAesHexLength(key.length())) {
            throw new InvalidKeyException(
                    "Khóa bí mật phải là chuỗi HEX gồm 32, 48 hoặc 64 ký tự."
            );
        }

        ensureHexCharacters(key);
    }

    public static void validateSecretKeyPresent(String key) throws InvalidKeyException {
        if (key == null || key.isBlank()) {
            throw new InvalidKeyException("Vui lòng nhập khóa bí mật.");
        }
    }

    public static byte[] parseAesKeyHex(String key, AESVariant variant) throws InvalidKeyException {
        validateSecretKeyPresent(key);

        int expectedHexLength = variant.getKeyLengthBytes() * 2;
        if (key.length() != expectedHexLength) {
            throw new InvalidKeyException(
                    "Khóa bí mật phải có đúng " + expectedHexLength + " ký tự hex cho " + variant + "."
            );
        }

        ensureHexCharacters(key);

        byte[] keyBytes = HexUtils.fromHex(key);
        if (keyBytes.length != variant.getKeyLengthBytes()) {
            throw new InvalidKeyException(
                    "Khóa bí mật phải giải mã thành đúng " + variant.getKeyLengthBytes() + " byte cho " + variant + "."
            );
        }

        return keyBytes;
    }

    private static boolean isSupportedAesHexLength(int keyLength) {
        return keyLength == AES_128_HEX_LENGTH
                || keyLength == AES_192_HEX_LENGTH
                || keyLength == AES_256_HEX_LENGTH;
    }

    private static void ensureHexCharacters(String key) throws InvalidKeyException {
        try {
            HexUtils.fromHex(key);
        } catch (IllegalArgumentException exception) {
            throw new InvalidKeyException(
                    "Khóa bí mật chỉ được chứa ký tự hex hợp lệ (0-9, A-F).",
                    exception
            );
        }
    }

    public static void validateBlockSize(int size) {
        if (size <= 0 || size > 255) {
            throw new IllegalArgumentException("Kích thước block phải trong khoảng 1..255.");
        }
    }

    public static void validateFileExists(Path path) {
        if (path == null) {
            throw new IllegalArgumentException("Vui lòng chọn tệp.");
        }

        if (!Files.exists(path)) {
            throw new IllegalArgumentException("Tệp không tồn tại: " + path);
        }

        if (!Files.isRegularFile(path)) {
            throw new IllegalArgumentException("Đường dẫn phải trỏ tới một tệp hợp lệ: " + path);
        }
    }
}
