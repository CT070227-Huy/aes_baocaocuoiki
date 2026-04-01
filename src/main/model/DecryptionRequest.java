package model;

import crypto.AESConstants;
import crypto.AESVariant;

import java.nio.file.Path;
import java.util.Objects;

// Model that carries input data for file decryption.
public class DecryptionRequest {
    private final Path encryptedFile;
    private final Path outputFile;
    private final String secretKey;
    private final AESVariant variant;

    public DecryptionRequest(Path encryptedFile, Path outputFile, String secretKey) {
        this(encryptedFile, outputFile, secretKey, AESConstants.DEFAULT_VARIANT);
    }

    public DecryptionRequest(Path encryptedFile, Path outputFile, String secretKey, AESVariant variant) {
        this.encryptedFile = encryptedFile;
        this.outputFile = outputFile;
        this.secretKey = secretKey;
        this.variant = Objects.requireNonNull(variant, "Biến thể AES không được để trống.");
    }

    public Path getEncryptedFile() {
        return encryptedFile;
    }

    public Path getOutputFile() {
        return outputFile;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public AESVariant getVariant() {
        return variant;
    }
}
