package model;

import java.nio.file.Path;

// Model that carries input data for file encryption.
public class EncryptionRequest {
    private final Path inputFile;
    private final Path outputFile;
    private final String secretKey;

    public EncryptionRequest(Path inputFile, Path outputFile, String secretKey) {
        this.inputFile = inputFile;
        this.outputFile = outputFile;
        this.secretKey = secretKey;
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
}
