package model;

import crypto.AESConstants;
import crypto.AESVariant;

import java.util.Arrays;
import java.util.Objects;

// Model that represents the payload stored inside an .enc file.
public class EncryptedPackage {
    private final String originalFileName;
    private final byte[] iv;
    private final byte[] cipherText;
    private final AESVariant variant;
    private final byte version;

    public EncryptedPackage(String originalFileName, byte[] iv, byte[] cipherText, byte version) {
        this(originalFileName, iv, cipherText, AESConstants.DEFAULT_VARIANT, version);
    }

    public EncryptedPackage(String originalFileName, byte[] iv, byte[] cipherText, AESVariant variant, byte version) {
        this.originalFileName = originalFileName;
        this.iv = copy(iv);
        this.cipherText = copy(cipherText);
        this.variant = Objects.requireNonNull(variant, "Biến thể AES không được để trống.");
        this.version = version;
    }

    public String getOriginalFileName() {
        return originalFileName;
    }

    public byte[] getIv() {
        return copy(iv);
    }

    public byte[] getCipherText() {
        return copy(cipherText);
    }

    public AESVariant getVariant() {
        return variant;
    }

    public byte getVersion() {
        return version;
    }

    private byte[] copy(byte[] data) {
        return data == null ? null : Arrays.copyOf(data, data.length);
    }
}
