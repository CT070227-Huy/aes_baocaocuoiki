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
            throw new InvalidKeyException("Secret key must not be null or blank.");
        }

        if (!isSupportedAesHexLength(key.length())) {
            throw new InvalidKeyException(
                    "Secret key must be a HEX string with 32, 48, or 64 characters."
            );
        }

        ensureHexCharacters(key);
    }

    public static void validateSecretKeyPresent(String key) throws InvalidKeyException {
        if (key == null || key.isBlank()) {
            throw new InvalidKeyException("Secret key must not be null or blank.");
        }
    }

    public static byte[] parseAesKeyHex(String key, AESVariant variant) throws InvalidKeyException {
        validateSecretKeyPresent(key);

        int expectedHexLength = variant.getKeyLengthBytes() * 2;
        if (key.length() != expectedHexLength) {
            throw new InvalidKeyException(
                    "Secret key must be exactly " + expectedHexLength + " hex characters for " + variant + "."
            );
        }

        ensureHexCharacters(key);

        byte[] keyBytes = HexUtils.fromHex(key);
        if (keyBytes.length != variant.getKeyLengthBytes()) {
            throw new InvalidKeyException(
                    "Secret key must decode to exactly " + variant.getKeyLengthBytes() + " bytes for " + variant + "."
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
                    "Secret key must contain only hexadecimal characters (0-9, A-F).",
                    exception
            );
        }
    }

    public static void validateBlockSize(int size) {
        if (size <= 0 || size > 255) {
            throw new IllegalArgumentException("Block size must be in range 1..255.");
        }
    }

    public static void validateFileExists(Path path) {
        if (path == null) {
            throw new IllegalArgumentException("File path must not be null.");
        }

        if (!Files.exists(path)) {
            throw new IllegalArgumentException("File does not exist: " + path);
        }

        if (!Files.isRegularFile(path)) {
            throw new IllegalArgumentException("Path must point to a regular file: " + path);
        }
    }
}
