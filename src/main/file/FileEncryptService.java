package file;

import crypto.AESConstants;
import crypto.CBCMode;
import crypto.PKCS7Padding;
import crypto.RandomIVGenerator;
import exception.InvalidKeyException;
import model.EncryptedPackage;
import model.EncryptionRequest;
import model.OperationResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class FileEncryptService {
    private final PKCS7Padding padding = new PKCS7Padding();
    private final CBCMode cbcMode = new CBCMode();
    private final RandomIVGenerator ivGenerator = new RandomIVGenerator();
    private final EncryptedFileWriter fileWriter = new EncryptedFileWriter();

    public OperationResult encryptFile(EncryptionRequest request) {
        try {
            validateRequest(request);

            Path inputFile = request.getInputFile();
            Path outputPath = resolveOutputPath(request);
            byte[] plainBytes = Files.readAllBytes(inputFile);
            byte[] secretKeyBytes = resolveSecretKey(request.getSecretKey());
            byte[] iv = ivGenerator.generateIV();
            byte[] paddedPlainBytes = padding.pad(plainBytes, AESConstants.BLOCK_SIZE);
            byte[] cipherText = cbcMode.encrypt(paddedPlainBytes, secretKeyBytes, iv);

            EncryptedPackage encryptedPackage = new EncryptedPackage(
                    inputFile.getFileName().toString(),
                    iv,
                    cipherText,
                    EncryptedFileFormat.VERSION
            );

            fileWriter.write(outputPath, encryptedPackage);

            return OperationResult.success("File encrypted successfully.", outputPath);
        } catch (InvalidKeyException | IllegalArgumentException exception) {
            return OperationResult.failure("Unable to encrypt file: " + exception.getMessage(), exception.getMessage());
        } catch (IOException exception) {
            return OperationResult.failure(
                    "Unable to encrypt file because the input or output file could not be accessed.",
                    exception.getMessage()
            );
        } catch (Exception exception) {
            return OperationResult.failure("Unexpected error while encrypting file.", exception.toString());
        }
    }

    private void validateRequest(EncryptionRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Encryption request must not be null.");
        }

        Path inputFile = request.getInputFile();
        if (inputFile == null) {
            throw new IllegalArgumentException("Input file must not be null.");
        }

        if (!Files.exists(inputFile)) {
            throw new IllegalArgumentException("Input file does not exist.");
        }

        if (!Files.isRegularFile(inputFile)) {
            throw new IllegalArgumentException("Input path must point to a file.");
        }

        if (inputFile.getFileName() == null) {
            throw new IllegalArgumentException("Input file name could not be determined.");
        }
    }

    private byte[] resolveSecretKey(String secretKey) throws InvalidKeyException {
        if (secretKey == null || secretKey.isBlank()) {
            throw new InvalidKeyException("Secret key must not be null or blank.");
        }

        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length != AESConstants.KEY_SIZE) {
            throw new InvalidKeyException("Secret key must be exactly 16 bytes in UTF-8 for AES-128.");
        }

        return keyBytes;
    }

    private Path resolveOutputPath(EncryptionRequest request) {
        Path outputPath = request.getOutputFile();
        if (outputPath == null) {
            outputPath = request.getInputFile().resolveSibling(request.getInputFile().getFileName() + ".enc");
        }

        if (Files.exists(outputPath) && Files.isDirectory(outputPath)) {
            throw new IllegalArgumentException("Output path must point to a file, not a directory.");
        }

        if (outputPath.equals(request.getInputFile())) {
            throw new IllegalArgumentException("Output file must be different from the input file.");
        }

        return outputPath;
    }
}
