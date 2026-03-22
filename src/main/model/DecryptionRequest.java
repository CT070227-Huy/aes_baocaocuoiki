package model;

import java.nio.file.Path;

// Model that carries input data for file decryption.
public class DecryptionRequest {
    private final Path encryptedFile;
    private final Path outputFile;
    private final String secretKey;

    public DecryptionRequest(Path encryptedFile, Path outputFile, String secretKey) {
        this.encryptedFile = encryptedFile;
        this.outputFile = outputFile;
        this.secretKey = secretKey;
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
}
