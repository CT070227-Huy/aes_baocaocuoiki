package model;

import java.nio.file.Path;

// Model that represents the result of an encrypt/decrypt operation.
public class OperationResult {
    private final boolean success;
    private final String message;
    private final Path outputPath;
    private final String exceptionMessage;

    public OperationResult(boolean success, String message, Path outputPath) {
        this(success, message, outputPath, null);
    }

    public OperationResult(boolean success, String message, Path outputPath, String exceptionMessage) {
        this.success = success;
        this.message = message;
        this.outputPath = outputPath;
        this.exceptionMessage = exceptionMessage;
    }

    public boolean isSuccess() {
        return success;
    }

    public String getMessage() {
        return message;
    }

    public Path getOutputPath() {
        return outputPath;
    }

    public String getExceptionMessage() {
        return exceptionMessage;
    }

    public static OperationResult success(String message, Path outputPath) {
        return new OperationResult(true, message, outputPath, null);
    }

    public static OperationResult failure(String message) {
        return new OperationResult(false, message, null, null);
    }

    public static OperationResult failure(String message, String exceptionMessage) {
        return new OperationResult(false, message, null, exceptionMessage);
    }
}
