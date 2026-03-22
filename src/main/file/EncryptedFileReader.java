package file;

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
            throw new InvalidFormatException("Failed to read encrypted file: " + inputPath, exception);
        }

        if (fileContent.length < EncryptedFileFormat.FIXED_METADATA_LENGTH) {
            throw new InvalidFormatException("Encrypted file is too short to match the .enc format.");
        }

        ByteBuffer buffer = ByteBuffer.wrap(fileContent);

        byte[] header = readBytes(buffer, EncryptedFileFormat.MAGIC_HEADER_LENGTH, "magic header");
        if (!EncryptedFileFormat.isValidHeader(header)) {
            throw new InvalidFormatException("Invalid .enc magic header.");
        }

        byte version = buffer.get();
        if (!EncryptedFileFormat.isSupportedVersion(version)) {
            throw new InvalidFormatException("Unsupported .enc version: " + version);
        }

        int originalFileNameLength = Short.toUnsignedInt(buffer.getShort());
        if (originalFileNameLength == 0) {
            throw new InvalidFormatException("Original file name length must be greater than zero.");
        }

        byte[] originalFileNameBytes = readBytes(buffer, originalFileNameLength, "original file name");
        String originalFileName = decodeFileName(originalFileNameBytes);

        byte[] iv = readBytes(buffer, EncryptedFileFormat.IV_LENGTH, "IV");

        if (buffer.remaining() < EncryptedFileFormat.CIPHER_TEXT_LENGTH_BYTES) {
            throw new InvalidFormatException("Encrypted file is missing the ciphertext length field.");
        }

        long cipherTextLength = buffer.getLong();
        if (cipherTextLength <= 0) {
            throw new InvalidFormatException("Ciphertext length must be greater than zero.");
        }

        if (cipherTextLength > Integer.MAX_VALUE) {
            throw new InvalidFormatException("Ciphertext is too large to be loaded into memory.");
        }

        byte[] cipherText = readBytes(buffer, (int) cipherTextLength, "ciphertext");

        if (buffer.hasRemaining()) {
            throw new InvalidFormatException("Encrypted file contains unexpected trailing data.");
        }

        return new EncryptedPackage(originalFileName, iv, cipherText, version);
    }

    private void validateInputPath(Path inputPath) throws InvalidFormatException {
        if (inputPath == null) {
            throw new IllegalArgumentException("Input path must not be null.");
        }

        if (!Files.exists(inputPath)) {
            throw new InvalidFormatException("Encrypted file does not exist: " + inputPath);
        }

        if (!Files.isRegularFile(inputPath)) {
            throw new InvalidFormatException("Input path is not a regular file: " + inputPath);
        }
    }

    private byte[] readBytes(ByteBuffer buffer, int length, String fieldName) throws InvalidFormatException {
        if (length < 0 || buffer.remaining() < length) {
            throw new InvalidFormatException("Encrypted file is truncated while reading " + fieldName + ".");
        }

        byte[] bytes = new byte[length];
        buffer.get(bytes);
        return bytes;
    }

    private String decodeFileName(byte[] fileNameBytes) throws InvalidFormatException {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);

        try {
            return decoder.decode(ByteBuffer.wrap(fileNameBytes)).toString();
        } catch (CharacterCodingException exception) {
            throw new InvalidFormatException("Original file name is not valid UTF-8.", exception);
        }
    }
}
