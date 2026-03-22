package util;

import java.util.Arrays;

// Utility helpers for common byte array operations.
public final class ByteUtils {
    private ByteUtils() {
    }

    public static byte[] xor(byte[] a, byte[] b) {
        validateArray(a, "First byte array");
        validateArray(b, "Second byte array");

        if (a.length != b.length) {
            throw new IllegalArgumentException("Byte arrays must have the same length.");
        }

        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) ((a[i] ^ b[i]) & 0xFF);
        }

        return result;
    }

    public static int unsignedByte(byte b) {
        return b & 0xFF;
    }

    public static byte[] copyOf(byte[] source) {
        validateArray(source, "Source byte array");
        return Arrays.copyOf(source, source.length);
    }

    private static void validateArray(byte[] source, String label) {
        if (source == null) {
            throw new IllegalArgumentException(label + " must not be null.");
        }
    }
}
