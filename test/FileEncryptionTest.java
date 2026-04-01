package test;

import crypto.AESVariant;
import file.EncryptedFileFormat;
import file.EncryptedFileReader;
import file.FileDecryptService;
import file.FileEncryptService;
import model.DecryptionRequest;
import model.EncryptedPackage;
import model.EncryptionRequest;
import model.OperationResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;

// Manual end-to-end verification for AES-CBC file encryption and decryption.
public class FileEncryptionTest {
    private final FileEncryptService encryptService = new FileEncryptService();
    private final FileDecryptService decryptService = new FileDecryptService();
    private final EncryptedFileReader encryptedFileReader = new EncryptedFileReader();

    public static void main(String[] args) throws Exception {
        new FileEncryptionTest().run();
    }

    private void run() throws Exception {
        Path testRoot = Files.createTempDirectory(Paths.get("out"), "file-encryption-test-");

        try {
            testRoundTripForAllVariants(testRoot);
            testEncryptRejectsWrongKeyLength(testRoot);
            testDecryptRejectsWrongKeyLength(testRoot);
            testDecryptRejectsMismatchedVariant(testRoot);

            System.out.println("All FileEncryptionTest checks passed.");
        } finally {
            deleteRecursively(testRoot);
        }
    }

    private void testRoundTripForAllVariants(Path testRoot) throws Exception {
        Map<String, byte[]> payloads = new LinkedHashMap<>();
        payloads.put("small-file", "Hi".getBytes(StandardCharsets.UTF_8));
        payloads.put("exact-block", "1234567890ABCDEF".getBytes(StandardCharsets.UTF_8));
        payloads.put("longer-than-one-block", createPatternBytes(64));
        payloads.put("non-aligned", createPatternBytes(37));

        int passedCases = 0;
        for (AESVariant variant : AESVariant.values()) {
            for (Map.Entry<String, byte[]> entry : payloads.entrySet()) {
                runRoundTripCase(testRoot, variant, entry.getKey(), entry.getValue());
                passedCases++;
            }
        }

        System.out.println("Round-trip cases passed: " + passedCases);
    }

    private void runRoundTripCase(Path testRoot, AESVariant variant, String caseName, byte[] originalBytes) throws Exception {
        Path caseDir = testRoot.resolve(variant.name().toLowerCase()).resolve(caseName);
        Files.createDirectories(caseDir);

        Path inputFile = caseDir.resolve("input.bin");
        Path encryptedFile = caseDir.resolve("encrypted.enc");
        Path decryptedFile = caseDir.resolve("decrypted.bin");

        Files.write(inputFile, originalBytes);

        String keyHex = sampleKeys().get(variant);
        OperationResult encryptResult = encryptService.encryptFile(
                new EncryptionRequest(inputFile, encryptedFile, keyHex, variant)
        );
        assertSuccess(encryptResult, "encrypt " + variant + " / " + caseName);

        EncryptedPackage encryptedPackage = encryptedFileReader.read(encryptedFile);
        assertEquals(variant, encryptedPackage.getVariant(), "stored variant for " + variant + " / " + caseName);
        assertEquals(EncryptedFileFormat.VERSION, encryptedPackage.getVersion(), "stored format version");

        OperationResult decryptResult = decryptService.decryptFile(
                new DecryptionRequest(encryptedFile, decryptedFile, keyHex, variant)
        );
        assertSuccess(decryptResult, "decrypt " + variant + " / " + caseName);

        byte[] decryptedBytes = Files.readAllBytes(decryptedFile);
        assertBytesEqual(originalBytes, decryptedBytes, "round-trip bytes for " + variant + " / " + caseName);
    }

    private void testEncryptRejectsWrongKeyLength(Path testRoot) throws Exception {
        Path inputFile = testRoot.resolve("invalid-encrypt-key-input.bin");
        Path encryptedFile = testRoot.resolve("invalid-encrypt-key.enc");
        Files.write(inputFile, "invalid key length".getBytes(StandardCharsets.UTF_8));

        for (AESVariant variant : AESVariant.values()) {
            String invalidKey = sampleKeys().get(variant).substring(0, sampleKeys().get(variant).length() - 2);
            OperationResult result = encryptService.encryptFile(
                    new EncryptionRequest(inputFile, encryptedFile, invalidKey, variant)
            );

            int expectedHexLength = variant.getKeyLengthBytes() * 2;
            assertFailureContains(
                    result,
                    "exactly " + expectedHexLength + " hex characters",
                    "encrypt invalid key length for " + variant
            );
        }

        System.out.println("Invalid encrypt key-length cases passed.");
    }

    private void testDecryptRejectsWrongKeyLength(Path testRoot) throws Exception {
        for (AESVariant variant : AESVariant.values()) {
            Path caseDir = testRoot.resolve("invalid-decrypt-key").resolve(variant.name().toLowerCase());
            Files.createDirectories(caseDir);

            Path inputFile = caseDir.resolve("input.bin");
            Path encryptedFile = caseDir.resolve("encrypted.enc");
            Path decryptedFile = caseDir.resolve("decrypted.bin");

            Files.write(inputFile, createPatternBytes(23));

            String validKey = sampleKeys().get(variant);
            OperationResult encryptResult = encryptService.encryptFile(
                    new EncryptionRequest(inputFile, encryptedFile, validKey, variant)
            );
            assertSuccess(encryptResult, "prepare decrypt invalid key-length case for " + variant);

            String invalidKey = validKey.substring(0, validKey.length() - 2);
            OperationResult decryptResult = decryptService.decryptFile(
                    new DecryptionRequest(encryptedFile, decryptedFile, invalidKey, variant)
            );

            int expectedHexLength = variant.getKeyLengthBytes() * 2;
            assertFailureContains(
                    decryptResult,
                    "exactly " + expectedHexLength + " hex characters",
                    "decrypt invalid key length for " + variant
            );
        }

        System.out.println("Invalid decrypt key-length cases passed.");
    }

    private void testDecryptRejectsMismatchedVariant(Path testRoot) throws Exception {
        AESVariant fileVariant = AESVariant.AES_256;
        AESVariant selectedVariant = AESVariant.AES_128;

        Path caseDir = testRoot.resolve("variant-mismatch");
        Files.createDirectories(caseDir);

        Path inputFile = caseDir.resolve("input.bin");
        Path encryptedFile = caseDir.resolve("encrypted.enc");
        Path decryptedFile = caseDir.resolve("decrypted.bin");

        Files.write(inputFile, createPatternBytes(48));

        OperationResult encryptResult = encryptService.encryptFile(
                new EncryptionRequest(inputFile, encryptedFile, sampleKeys().get(fileVariant), fileVariant)
        );
        assertSuccess(encryptResult, "prepare decrypt variant mismatch case");

        OperationResult decryptResult = decryptService.decryptFile(
                new DecryptionRequest(encryptedFile, decryptedFile, sampleKeys().get(selectedVariant), selectedVariant)
        );

        assertFailureContains(
                decryptResult,
                "Selected algorithm does not match the encrypted file metadata.",
                "decrypt variant mismatch"
        );

        System.out.println("Variant metadata mismatch case passed.");
    }

    private Map<AESVariant, String> sampleKeys() {
        Map<AESVariant, String> keys = new EnumMap<>(AESVariant.class);
        keys.put(AESVariant.AES_128, "00112233445566778899AABBCCDDEEFF");
        keys.put(AESVariant.AES_192, "00112233445566778899AABBCCDDEEFF0001020304050607");
        keys.put(AESVariant.AES_256, "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
        return keys;
    }

    private byte[] createPatternBytes(int length) {
        byte[] bytes = new byte[length];

        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) ('A' + (i % 26));
        }

        return bytes;
    }

    private void assertSuccess(OperationResult result, String label) {
        if (result == null || !result.isSuccess()) {
            String details = result == null ? "null result" : result.getMessage() + " / " + result.getExceptionMessage();
            throw new AssertionError("Expected success for " + label + ", but got: " + details);
        }
    }

    private void assertFailureContains(OperationResult result, String expectedMessage, String label) {
        if (result == null || result.isSuccess()) {
            throw new AssertionError("Expected failure for " + label + ", but operation succeeded.");
        }

        String combinedMessage = String.valueOf(result.getMessage()) + " " + String.valueOf(result.getExceptionMessage());
        if (!combinedMessage.contains(expectedMessage)) {
            throw new AssertionError(
                    "Expected failure message for " + label + " to contain '" + expectedMessage + "', but got: " + combinedMessage
            );
        }
    }

    private void assertEquals(Object expected, Object actual, String label) {
        if ((expected == null && actual != null) || (expected != null && !expected.equals(actual))) {
            throw new AssertionError("Expected " + label + " to be '" + expected + "', but got '" + actual + "'.");
        }
    }

    private void assertBytesEqual(byte[] expected, byte[] actual, String label) {
        if (expected.length != actual.length) {
            throw new AssertionError(
                    "Expected " + label + " length " + expected.length + ", but got " + actual.length + "."
            );
        }

        for (int i = 0; i < expected.length; i++) {
            if (expected[i] != actual[i]) {
                throw new AssertionError("Mismatch in " + label + " at byte index " + i + ".");
            }
        }
    }

    private void deleteRecursively(Path root) throws IOException {
        if (root == null || !Files.exists(root)) {
            return;
        }

        try (var paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder())
                    .forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (IOException exception) {
                            throw new RuntimeException("Failed to delete test artifact: " + path, exception);
                        }
                    });
        } catch (RuntimeException exception) {
            if (exception.getCause() instanceof IOException ioException) {
                throw ioException;
            }

            throw exception;
        }
    }
}
