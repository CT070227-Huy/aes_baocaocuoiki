package crypto;

public class GaloisField {
    private static final int AES_IRREDUCIBLE_POLYNOMIAL = 0x11B;
    // In 8-bit form, reducing by 0x11B becomes XOR with 0x1B.
    private static final int AES_REDUCTION_BYTE = AES_IRREDUCIBLE_POLYNOMIAL & 0xFF;

    private GaloisField() {
    }

    // Multiply by x in GF(2^8), then reduce with the AES polynomial.
    public static int xtime(int value) {
        int byteValue = value & 0xFF;
        int shifted = (byteValue << 1) & 0xFF;

        if ((byteValue & 0x80) != 0) {
            shifted ^= AES_REDUCTION_BYTE;
        }

        return shifted & 0xFF;
    }

    // Multiply two bytes with the AES shift-and-add rule in GF(2^8).
    public static int multiply(int a, int b) {
        int multiplicand = a & 0xFF;
        int multiplier = b & 0xFF;
        int result = 0;

        for (int bit = 0; bit < 8; bit++) {
            if ((multiplier & 0x01) != 0) {
                result ^= multiplicand;
            }

            multiplicand = xtime(multiplicand);
            multiplier >>>= 1;
        }

        return result & 0xFF;
    }

    // Quick example:
    // 0x57 * 0x13 = 0xFE
    public static void main(String[] args) {
        printExample(0x57, 0x13);

        // Common AES coefficients for MixColumns / InvMixColumns.
        printExample(0x57, 0x02);
        printExample(0x57, 0x03);
        printExample(0x57, 0x09);
        printExample(0x57, 0x0B);
        printExample(0x57, 0x0D);
        printExample(0x57, 0x0E);
    }

    private static void printExample(int a, int b) {
        System.out.printf("0x%02X * 0x%02X = 0x%02X%n", a & 0xFF, b & 0xFF, multiply(a, b));
    }
}
