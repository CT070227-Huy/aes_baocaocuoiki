package model;

import crypto.AESConstants;
import crypto.AESVariant;

import java.nio.file.Path;
import java.util.Objects;

// Model that carries input data for file encryption.
public class EncryptionRequest {
    private final Path inputFile;
    private final Path outputFile;
    private final String secretKey;
    private final AESVariant variant;

    public EncryptionRequest(Path inputFile, Path outputFile, String secretKey) {
        this(inputFile, outputFile, secretKey, AESConstants.DEFAULT_VARIANT);
    }

    public EncryptionRequest(Path inputFile, Path outputFile, String secretKey, AESVariant variant) {
        this.inputFile = inputFile;
        this.outputFile = outputFile;
        this.secretKey = secretKey;
        this.variant = Objects.requireNonNull(variant, "AES variant must not be null.");
    }

    public Path getInputFile() {
        return inputFile;
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
