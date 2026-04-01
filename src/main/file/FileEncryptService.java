package file;

import crypto.AESConstants;
import crypto.AESVariant;
import crypto.CBCMode;
import crypto.PKCS7Padding;
import crypto.RandomIVGenerator;
import exception.InvalidKeyException;
import model.EncryptedPackage;
import model.EncryptionRequest;
import model.OperationResult;
import util.ValidationUtils;

import java.io.IOException;
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
            AESVariant variant = request.getVariant();
            byte[] plainBytes = Files.readAllBytes(inputFile);
            byte[] secretKeyBytes = resolveSecretKey(request.getSecretKey(), variant);
            byte[] iv = ivGenerator.generateIV();
            byte[] paddedPlainBytes = padding.pad(plainBytes, AESConstants.BLOCK_SIZE);
            byte[] cipherText = cbcMode.encrypt(paddedPlainBytes, secretKeyBytes, iv, variant);

            EncryptedPackage encryptedPackage = new EncryptedPackage(
                    inputFile.getFileName().toString(),
                    iv,
                    cipherText,
                    variant,
                    EncryptedFileFormat.VERSION
            );

            fileWriter.write(outputPath, encryptedPackage);

            return OperationResult.success("Mã hóa tệp thành công.", outputPath);
        } catch (InvalidKeyException | IllegalArgumentException exception) {
            return OperationResult.failure("Không thể mã hóa tệp: " + exception.getMessage(), exception.getMessage());
        } catch (IOException exception) {
            return OperationResult.failure(
                    "Không thể mã hóa tệp vì không truy cập được tệp đầu vào hoặc đầu ra.",
                    exception.getMessage()
            );
        } catch (Exception exception) {
            return OperationResult.failure("Có lỗi không mong muốn khi mã hóa tệp.", exception.toString());
        }
    }

    private void validateRequest(EncryptionRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Yêu cầu mã hóa không được để trống.");
        }

        Path inputFile = request.getInputFile();
        if (inputFile == null) {
            throw new IllegalArgumentException("Vui lòng chọn tệp đầu vào.");
        }

        if (!Files.exists(inputFile)) {
            throw new IllegalArgumentException("Tệp đầu vào không tồn tại.");
        }

        if (!Files.isRegularFile(inputFile)) {
            throw new IllegalArgumentException("Đường dẫn đầu vào phải trỏ tới một tệp.");
        }

        if (inputFile.getFileName() == null) {
            throw new IllegalArgumentException("Không xác định được tên tệp đầu vào.");
        }
    }

    private byte[] resolveSecretKey(String secretKey, AESVariant variant) throws InvalidKeyException {
        return ValidationUtils.parseAesKeyHex(secretKey, variant);
    }

    private Path resolveOutputPath(EncryptionRequest request) {
        Path outputPath = request.getOutputFile();
        if (outputPath == null) {
            outputPath = request.getInputFile().resolveSibling(request.getInputFile().getFileName() + ".enc");
        }

        if (Files.exists(outputPath) && Files.isDirectory(outputPath)) {
            throw new IllegalArgumentException("Đường dẫn đầu ra phải là tệp, không phải thư mục.");
        }

        if (outputPath.equals(request.getInputFile())) {
            throw new IllegalArgumentException("Tệp đầu ra phải khác tệp đầu vào.");
        }

        return outputPath;
    }
}
