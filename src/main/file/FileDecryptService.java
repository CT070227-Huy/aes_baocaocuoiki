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

            return OperationResult.success("Giải mã tệp thành công.", outputPath);
        } catch (InvalidFormatException exception) {
            return OperationResult.failure(
                    "Không thể giải mã vì định dạng tệp .enc không hợp lệ.",
                    exception.getMessage()
            );
        } catch (InvalidKeyException exception) {
            return OperationResult.failure("Không thể giải mã tệp: " + exception.getMessage(), exception.getMessage());
        } catch (IllegalArgumentException exception) {
            return OperationResult.failure(
                    "Không thể giải mã tệp. Khóa bí mật có thể không đúng hoặc dữ liệu đã bị hỏng.",
                    exception.getMessage()
            );
        } catch (IOException exception) {
            return OperationResult.failure(
                    "Không thể lưu tệp đã giải mã vào vị trí đã chọn.",
                    exception.getMessage()
            );
        } catch (Exception exception) {
            return OperationResult.failure("Có lỗi không mong muốn khi giải mã tệp.", exception.toString());
        }
    }

    private void validateRequest(DecryptionRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Yêu cầu giải mã không được để trống.");
        }

        Path encryptedFile = request.getEncryptedFile();
        if (encryptedFile == null) {
            throw new IllegalArgumentException("Vui lòng chọn tệp mã hóa.");
        }

        if (!Files.exists(encryptedFile)) {
            throw new IllegalArgumentException("Tệp mã hóa không tồn tại.");
        }

        if (!Files.isRegularFile(encryptedFile)) {
            throw new IllegalArgumentException("Đường dẫn tệp mã hóa phải trỏ tới một tệp.");
        }
    }

    private byte[] resolveSecretKey(String secretKey, AESVariant variant) throws InvalidKeyException {
        return ValidationUtils.parseAesKeyHex(secretKey, variant);
    }

    private AESVariant resolveVariant(DecryptionRequest request, EncryptedPackage encryptedPackage) {
        AESVariant fileVariant = encryptedPackage.getVariant();
        AESVariant selectedVariant = request.getVariant();

        if (selectedVariant != null && selectedVariant != fileVariant) {
            throw new IllegalArgumentException("Thuật toán đã chọn không khớp với metadata của tệp mã hóa.");
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
            throw new IllegalArgumentException("Tệp đầu ra phải khác tệp mã hóa đầu vào.");
        }

        if (Files.exists(outputPath) && Files.isDirectory(outputPath)) {
            throw new IllegalArgumentException("Đường dẫn đầu ra phải là tệp, không phải thư mục.");
        }

        return outputPath;
    }

    private String normalizeOriginalFileName(String originalFileName) throws InvalidFormatException {
        if (originalFileName == null || originalFileName.isBlank()) {
            throw new InvalidFormatException("Tệp mã hóa không chứa tên tệp gốc hợp lệ.");
        }

        try {
            Path fileNamePath = Paths.get(originalFileName).getFileName();
            if (fileNamePath == null || fileNamePath.toString().isBlank()) {
                throw new InvalidFormatException("Tệp mã hóa không chứa tên tệp gốc hợp lệ.");
            }

            return fileNamePath.toString();
        } catch (InvalidPathException exception) {
            throw new InvalidFormatException("Tên tệp gốc trong tệp mã hóa không hợp lệ.", exception);
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
