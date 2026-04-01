package file;

import crypto.AESConstants;
import crypto.AESVariant;
import crypto.CBCMode;
import crypto.PKCS7Padding;
import exception.InvalidFormatException;
import exception.InvalidKeyException;
import model.DecryptionRequest;
import model.EncryptedPackage;
import model.OperationResult;
import util.ValidationUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileDecryptService {
    private final EncryptedFileReader fileReader = new EncryptedFileReader();
    private final CBCMode cbcMode = new CBCMode();
    private final PKCS7Padding padding = new PKCS7Padding();

    public OperationResult decryptFile(DecryptionRequest request) {
        try {
            validateRequest(request);

            EncryptedPackage encryptedPackage = fileReader.read(request.getEncryptedFile());
            AESVariant variant = resolveVariant(request, encryptedPackage);
            byte[] secretKeyBytes = resolveSecretKey(request.getSecretKey(), variant);
            byte[] decryptedBytes = cbcMode.decrypt(
                    encryptedPackage.getCipherText(),
                    secretKeyBytes,
                    encryptedPackage.getIv(),
                    variant
            );
            byte[] plainBytes = padding.unpad(decryptedBytes, AESConstants.BLOCK_SIZE);
            Path outputPath = resolveOutputPath(request, encryptedPackage.getOriginalFileName());

            writeOutputFile(outputPath, plainBytes);

            return OperationResult.success("File decrypted successfully.", outputPath);
        } catch (InvalidFormatException exception) {
            return OperationResult.failure(
                    "Unable to decrypt file because the .enc file format is invalid.",
                    exception.getMessage()
            );
        } catch (InvalidKeyException exception) {
            return OperationResult.failure("Unable to decrypt file: " + exception.getMessage(), exception.getMessage());
        } catch (IllegalArgumentException exception) {
            return OperationResult.failure(
                    "Unable to decrypt file. The secret key may be incorrect or the encrypted data may be corrupted.",
                    exception.getMessage()
            );
        } catch (IOException exception) {
            return OperationResult.failure(
                    "Unable to save the decrypted file to the selected location.",
                    exception.getMessage()
            );
        } catch (Exception exception) {
            return OperationResult.failure("Unexpected error while decrypting file.", exception.toString());
        }
    }

    private void validateRequest(DecryptionRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Decryption request must not be null.");
        }

        Path encryptedFile = request.getEncryptedFile();
        if (encryptedFile == null) {
            throw new IllegalArgumentException("Encrypted file must not be null.");
        }

        if (!Files.exists(encryptedFile)) {
            throw new IllegalArgumentException("Encrypted file does not exist.");
        }

        if (!Files.isRegularFile(encryptedFile)) {
            throw new IllegalArgumentException("Encrypted path must point to a file.");
        }
    }

    private byte[] resolveSecretKey(String secretKey, AESVariant variant) throws InvalidKeyException {
        return ValidationUtils.parseAesKeyHex(secretKey, variant);
    }

    private AESVariant resolveVariant(DecryptionRequest request, EncryptedPackage encryptedPackage) {
        AESVariant fileVariant = encryptedPackage.getVariant();
        AESVariant selectedVariant = request.getVariant();

        if (selectedVariant != null && selectedVariant != fileVariant) {
            throw new IllegalArgumentException("Selected algorithm does not match the encrypted file metadata.");
        }

        return fileVariant;
    }

    private Path resolveOutputPath(DecryptionRequest request, String originalFileName) throws InvalidFormatException {
        String restoredFileName = normalizeOriginalFileName(originalFileName);
        Path requestedOutputPath = request.getOutputFile();

        Path outputPath;
        if (requestedOutputPath == null) {
            outputPath = request.getEncryptedFile().resolveSibling(restoredFileName);
        } else if (Files.exists(requestedOutputPath) && Files.isDirectory(requestedOutputPath)) {
            outputPath = requestedOutputPath.resolve(restoredFileName);
        } else {
            outputPath = requestedOutputPath;
        }

        if (outputPath.equals(request.getEncryptedFile())) {
            throw new IllegalArgumentException("Output file must be different from the encrypted input file.");
        }

        if (Files.exists(outputPath) && Files.isDirectory(outputPath)) {
            throw new IllegalArgumentException("Output path must point to a file, not a directory.");
        }

        return outputPath;
    }

    private String normalizeOriginalFileName(String originalFileName) throws InvalidFormatException {
        if (originalFileName == null || originalFileName.isBlank()) {
            throw new InvalidFormatException("Encrypted file does not contain a valid original file name.");
        }

        try {
            Path fileNamePath = Paths.get(originalFileName).getFileName();
            if (fileNamePath == null || fileNamePath.toString().isBlank()) {
                throw new InvalidFormatException("Encrypted file does not contain a valid original file name.");
            }

            return fileNamePath.toString();
        } catch (InvalidPathException exception) {
            throw new InvalidFormatException("Original file name inside the encrypted file is invalid.", exception);
        }
    }

    private void writeOutputFile(Path outputPath, byte[] plainBytes) throws IOException {
        Path parent = outputPath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        Files.write(outputPath, plainBytes);
    }
}
