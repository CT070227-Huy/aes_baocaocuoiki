package file;

import crypto.AESConstants;
import crypto.AESVariant;
import model.EncryptedPackage;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class EncryptedFileWriter {
    public void write(Path outputPath, EncryptedPackage encryptedPackage) throws IOException {
        validateOutputPath(outputPath);
        validatePackage(encryptedPackage);

        byte[] fileNameBytes = encryptedPackage.getOriginalFileName().getBytes(StandardCharsets.UTF_8);
        byte[] iv = encryptedPackage.getIv();
        byte[] cipherText = encryptedPackage.getCipherText();
        AESVariant variant = encryptedPackage.getVariant();

        validateSerializedFields(fileNameBytes, iv, cipherText, variant, encryptedPackage.getVersion());

        byte[] fileContent = serialize(fileNameBytes, iv, cipherText, variant, encryptedPackage.getVersion());

        Path parent = outputPath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        try (BufferedOutputStream outputStream = new BufferedOutputStream(Files.newOutputStream(outputPath))) {
            outputStream.write(fileContent);
        }
    }

    private void validateOutputPath(Path outputPath) {
        if (outputPath == null) {
            throw new IllegalArgumentException("Output path must not be null.");
        }
    }

    private void validatePackage(EncryptedPackage encryptedPackage) {
        if (encryptedPackage == null) {
            throw new IllegalArgumentException("Encrypted package must not be null.");
        }

        if (encryptedPackage.getOriginalFileName() == null || encryptedPackage.getOriginalFileName().isEmpty()) {
            throw new IllegalArgumentException("Original file name must not be null or empty.");
        }

        if (encryptedPackage.getIv() == null) {
            throw new IllegalArgumentException("IV must not be null.");
        }

        if (encryptedPackage.getCipherText() == null) {
            throw new IllegalArgumentException("Ciphertext must not be null.");
        }

        if (encryptedPackage.getVariant() == null) {
            throw new IllegalArgumentException("AES variant must not be null.");
        }
    }

    private void validateSerializedFields(byte[] fileNameBytes, byte[] iv, byte[] cipherText, AESVariant variant, byte version) {
        if (!EncryptedFileFormat.isSupportedVersion(version)) {
            throw new IllegalArgumentException("Unsupported encrypted file version: " + version);
        }

        if (EncryptedFileFormat.usesVariantMetadata(version)) {
            EncryptedFileFormat.variantCode(variant);
        } else if (variant != AESConstants.DEFAULT_VARIANT) {
            throw new IllegalArgumentException("Version 1 .enc files only support AES-128.");
        }

        if (fileNameBytes.length > 0xFFFF) {
            throw new IllegalArgumentException("Original file name is too long for the .enc format.");
        }

        if (iv.length != EncryptedFileFormat.IV_LENGTH) {
            throw new IllegalArgumentException("IV must be exactly 16 bytes.");
        }

        if (cipherText.length == 0) {
            throw new IllegalArgumentException("Ciphertext must not be empty.");
        }
    }

    private byte[] serialize(byte[] fileNameBytes, byte[] iv, byte[] cipherText, AESVariant variant, byte version)
            throws IOException {
        try (ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
             DataOutputStream dataStream = new DataOutputStream(byteStream)) {
            dataStream.write(EncryptedFileFormat.magicHeaderBytes());
            dataStream.writeByte(version & 0xFF);
            if (EncryptedFileFormat.usesVariantMetadata(version)) {
                dataStream.writeByte(EncryptedFileFormat.variantCode(variant) & 0xFF);
            }
            dataStream.writeShort(fileNameBytes.length);
            dataStream.write(fileNameBytes);
            dataStream.write(iv);
            dataStream.writeLong(cipherText.length);
            dataStream.write(cipherText);
            dataStream.flush();
            return byteStream.toByteArray();
        }
    }
}
