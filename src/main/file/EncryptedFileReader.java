package file;

import crypto.AESConstants;
import crypto.AESVariant;
import exception.InvalidFormatException;
import model.EncryptedPackage;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class EncryptedFileReader {
    public EncryptedPackage read(Path inputPath) throws InvalidFormatException {
        validateInputPath(inputPath);

        byte[] fileContent;
        try {
            fileContent = Files.readAllBytes(inputPath);
        } catch (IOException exception) {
            throw new InvalidFormatException("Không thể đọc tệp mã hóa: " + inputPath, exception);
        }

        if (fileContent.length < EncryptedFileFormat.MINIMUM_FIXED_METADATA_LENGTH) {
            throw new InvalidFormatException("Tệp mã hóa quá ngắn và không đúng định dạng .enc.");
        }

        ByteBuffer buffer = ByteBuffer.wrap(fileContent);

        byte[] header = readBytes(buffer, EncryptedFileFormat.MAGIC_HEADER_LENGTH, "magic header");
        if (!EncryptedFileFormat.isValidHeader(header)) {
            throw new InvalidFormatException("Magic header của tệp .enc không hợp lệ.");
        }

        byte version = buffer.get();
        if (!EncryptedFileFormat.isSupportedVersion(version)) {
            throw new InvalidFormatException("Phiên bản .enc không được hỗ trợ: " + version);
        }

        if (fileContent.length < EncryptedFileFormat.fixedMetadataLength(version)) {
            throw new InvalidFormatException("Tệp mã hóa quá ngắn đối với phiên bản .enc " + version + ".");
        }

        AESVariant variant = readVariant(buffer, version);

        int originalFileNameLength = Short.toUnsignedInt(buffer.getShort());
        if (originalFileNameLength == 0) {
            throw new InvalidFormatException("Độ dài tên tệp gốc phải lớn hơn 0.");
        }

        byte[] originalFileNameBytes = readBytes(buffer, originalFileNameLength, "tên tệp gốc");
        String originalFileName = decodeFileName(originalFileNameBytes);

        byte[] iv = readBytes(buffer, EncryptedFileFormat.IV_LENGTH, "IV");

        if (buffer.remaining() < EncryptedFileFormat.CIPHER_TEXT_LENGTH_BYTES) {
            throw new InvalidFormatException("Tệp mã hóa thiếu trường độ dài ciphertext.");
        }

        long cipherTextLength = buffer.getLong();
        if (cipherTextLength <= 0) {
            throw new InvalidFormatException("Độ dài ciphertext phải lớn hơn 0.");
        }

        if (cipherTextLength > Integer.MAX_VALUE) {
            throw new InvalidFormatException("Ciphertext quá lớn để nạp vào bộ nhớ.");
        }

        byte[] cipherText = readBytes(buffer, (int) cipherTextLength, "dữ liệu mã hóa");

        if (buffer.hasRemaining()) {
            throw new InvalidFormatException("Tệp mã hóa chứa dữ liệu dư không mong muốn.");
        }

        return new EncryptedPackage(originalFileName, iv, cipherText, variant, version);
    }

    private void validateInputPath(Path inputPath) throws InvalidFormatException {
        if (inputPath == null) {
            throw new IllegalArgumentException("Đường dẫn đầu vào không được để trống.");
        }

        if (!Files.exists(inputPath)) {
            throw new InvalidFormatException("Tệp mã hóa không tồn tại: " + inputPath);
        }

        if (!Files.isRegularFile(inputPath)) {
            throw new InvalidFormatException("Đường dẫn đầu vào không phải là tệp hợp lệ: " + inputPath);
        }
    }

    private byte[] readBytes(ByteBuffer buffer, int length, String fieldName) throws InvalidFormatException {
        if (length < 0 || buffer.remaining() < length) {
            throw new InvalidFormatException("Tệp mã hóa bị thiếu dữ liệu khi đọc " + fieldName + ".");
        }

        byte[] bytes = new byte[length];
        buffer.get(bytes);
        return bytes;
    }

    private AESVariant readVariant(ByteBuffer buffer, byte version) throws InvalidFormatException {
        if (!EncryptedFileFormat.usesVariantMetadata(version)) {
            return AESConstants.DEFAULT_VARIANT;
        }

        if (buffer.remaining() < EncryptedFileFormat.VARIANT_LENGTH) {
            throw new InvalidFormatException("Tệp mã hóa thiếu trường biến thể AES.");
        }

        byte variantCode = buffer.get();

        try {
            return EncryptedFileFormat.variantFromCode(variantCode);
        } catch (IllegalArgumentException exception) {
            throw new InvalidFormatException(exception.getMessage(), exception);
        }
    }

    private String decodeFileName(byte[] fileNameBytes) throws InvalidFormatException {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);

        try {
            return decoder.decode(ByteBuffer.wrap(fileNameBytes)).toString();
        } catch (CharacterCodingException exception) {
            throw new InvalidFormatException("Tên tệp gốc không phải UTF-8 hợp lệ.", exception);
        }
    }
}
