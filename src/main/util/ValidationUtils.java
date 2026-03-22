package util;

import exception.InvalidKeyException;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

// Utility helpers for common validation checks.
public final class ValidationUtils {
    private static final int AES_128_KEY_LENGTH = 16;

    private ValidationUtils() {
    }

    public static void validateAesKeyString(String key) throws InvalidKeyException {
        if (key == null || key.isBlank()) {
            throw new InvalidKeyException("Secret key must not be null or blank.");
        }

        int keyLength = key.getBytes(StandardCharsets.UTF_8).length;
        if (keyLength != AES_128_KEY_LENGTH) {
            throw new InvalidKeyException("Secret key must be exactly 16 bytes in UTF-8 for AES-128.");
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
