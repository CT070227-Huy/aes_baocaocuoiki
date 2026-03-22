package util;

// Utility helpers for converting between bytes and hexadecimal strings.
public final class HexUtils {
    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();

    private HexUtils() {
    }

    public static String toHex(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Byte array must not be null.");
        }

        char[] hexChars = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int value = data[i] & 0xFF;
            hexChars[i * 2] = HEX_DIGITS[value >>> 4];
            hexChars[i * 2 + 1] = HEX_DIGITS[value & 0x0F];
        }

        return new String(hexChars);
    }

    public static byte[] fromHex(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("Hex string must not be null.");
        }

        if ((hex.length() & 1) != 0) {
            throw new IllegalArgumentException("Hex string must have an even number of characters.");
        }

        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            int high = hexValue(hex.charAt(i));
            int low = hexValue(hex.charAt(i + 1));
            result[i / 2] = (byte) ((high << 4) | low);
        }

        return result;
    }

    private static int hexValue(char hexChar) {
        if (hexChar >= '0' && hexChar <= '9') {
            return hexChar - '0';
        }

        if (hexChar >= 'A' && hexChar <= 'F') {
            return hexChar - 'A' + 10;
        }

        if (hexChar >= 'a' && hexChar <= 'f') {
            return hexChar - 'a' + 10;
        }

        throw new IllegalArgumentException("Invalid hex character: '" + hexChar + "'.");
    }
}
