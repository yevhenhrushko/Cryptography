package com.cryptography.rsa;

import com.cryptography.FileCryptoDemo;
import com.cryptography.generator.PrimeCandidateGenerator;
import com.cryptography.primality.MillerRabinTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class RsaFileCipherTest {

    private static final Path IMAGE = Path.of("src/main/resources/Svema FN64-24.jpg");

    private static RsaHelper.RsaKeyPair keyPair;

    @BeforeAll
    static void generateKeys() {
        // 2048-битный модуль: достаточно для проверки корректности и быстро в тестах
        BigInteger p = randomPrime(1024);
        BigInteger q = randomPrime(1024);
        while (q.equals(p)) {
            q = randomPrime(1024);
        }
        keyPair = RsaHelper.generateKeyPair(p, q, RsaHelper.PROJECT_PUBLIC_EXPONENT);
    }

    @Test
    @DisplayName("Изображение после шифрования и расшифрования идентично оригиналу (байты, SHA-256, пиксели)")
    void testImageRoundTripIsIdentical(@TempDir Path tempDir) throws IOException {
        assertTrue(Files.exists(IMAGE), "Не найдено исходное изображение: " + IMAGE);
        Path encrypted = tempDir.resolve("image.jpg.enc");
        Path decrypted = tempDir.resolve("image.decrypted.jpg");

        RsaFileCipher.encryptFile(IMAGE, encrypted, keyPair.publicKey());
        RsaFileCipher.decryptFile(encrypted, decrypted, keyPair.privateKey());

        byte[] original = Files.readAllBytes(IMAGE);
        byte[] cipherBody = Files.readAllBytes(encrypted);
        assertFalse(Arrays.equals(original, Arrays.copyOfRange(cipherBody, 5, 5 + original.length)),
                "Шифротекст не должен совпадать с открытым текстом");
        assertImagesIdentical(IMAGE, decrypted);
    }

    @Test
    @DisplayName("Расшифрованный файл рядом с оригиналом в resources идентичен оригиналу")
    void testDecryptedImageNextToOriginalIsIdentical() throws IOException {
        Path decrypted = FileCryptoDemo.decryptedPathFor(IMAGE);
        assumeTrue(Files.exists(decrypted), "Файл " + decrypted + " еще не создан (запустите ./gradlew cryptFile)");
        assertImagesIdentical(IMAGE, decrypted);
    }

    @ParameterizedTest(name = "длина данных = {0}")
    @ValueSource(ints = {0, 1, 189, 190, 191, 380, 1000})
    @DisplayName("Корректная обработка границ блоков и ведущих нулевых байтов")
    void testBlockBoundariesAndLeadingZeros(int length) {
        // OAEP с SHA-256: k - 2 * 32 - 2 = 256 - 66 = 190 байт полезных данных на блок
        int blockSize = RsaFileCipher.plainBlockSize(keyPair.publicKey().n());
        assertEquals(190, blockSize);

        byte[] data = new byte[length];
        new Random(length).nextBytes(data);
        // Нулевые байты в начале данных и в начале каждого блока
        for (int i = 0; i < length; i += blockSize) {
            data[i] = 0;
            if (i + 1 < length) {
                data[i + 1] = 0;
            }
        }

        byte[] encrypted = RsaFileCipher.encrypt(data, keyPair.publicKey());
        assertArrayEquals(data, RsaFileCipher.decrypt(encrypted, keyPair.privateKey()));
    }

    @Test
    @DisplayName("Расшифрование по CRT совпадает с классическим c^d mod n")
    void testCrtMatchesClassicDecryption() {
        RsaHelper.RsaPrivateKey crtKey = keyPair.privateKey();
        RsaHelper.RsaPrivateKey plainKey = new RsaHelper.RsaPrivateKey(crtKey.d(), crtKey.n());
        assertTrue(crtKey.hasCrtParameters());
        assertFalse(plainKey.hasCrtParameters());

        BigInteger message = new BigInteger("123456789012345678901234567890");
        BigInteger cipher = RsaHelper.encrypt(message, keyPair.publicKey());
        assertEquals(message, RsaHelper.decrypt(cipher, crtKey));
        assertEquals(message, RsaHelper.decrypt(cipher, plainKey));
    }

    @Test
    @DisplayName("#2 OAEP: одинаковые данные дают разный шифротекст, а одинаковые блоки не повторяются")
    void testOaepIsRandomized() {
        int blockSize = RsaFileCipher.plainBlockSize(keyPair.publicKey().n());
        int k = RsaFileCipher.cipherBlockSize(keyPair.publicKey().n());
        // Три одинаковых блока из одних нулей — в «учебном» RSA каждый зашифровался бы в 0
        byte[] zeros = new byte[blockSize * 3];

        byte[] first = RsaFileCipher.encrypt(zeros, keyPair.publicKey());
        byte[] second = RsaFileCipher.encrypt(zeros, keyPair.publicKey());
        assertFalse(Arrays.equals(first, second), "Повторное шифрование тех же данных должно давать другой результат");

        byte[] block0 = Arrays.copyOfRange(first, 5, 5 + k);
        byte[] block1 = Arrays.copyOfRange(first, 5 + k, 5 + 2 * k);
        assertFalse(Arrays.equals(block0, block1), "Одинаковые блоки открытого текста не должны давать одинаковый шифротекст");
        assertFalse(new BigInteger(1, block0).equals(BigInteger.ZERO), "Нулевой блок не должен шифроваться в 0");

        assertArrayEquals(zeros, RsaFileCipher.decrypt(first, keyPair.privateKey()));
        assertArrayEquals(zeros, RsaFileCipher.decrypt(second, keyPair.privateKey()));
    }

    @Test
    @DisplayName("#6 Повреждённый файл даёт понятную IllegalArgumentException")
    void testCorruptedFileIsRejected() {
        byte[] encrypted = RsaFileCipher.encrypt(new byte[500], keyPair.publicKey());

        byte[] truncated = Arrays.copyOf(encrypted, encrypted.length - 7);
        assertThrows(IllegalArgumentException.class, () -> RsaFileCipher.decrypt(truncated, keyPair.privateKey()));

        byte[] badMagic = encrypted.clone();
        badMagic[0] = 'X';
        assertThrows(IllegalArgumentException.class, () -> RsaFileCipher.decrypt(badMagic, keyPair.privateKey()));

        byte[] flipped = encrypted.clone();
        flipped[encrypted.length - 1] ^= 0x01;
        assertThrows(IllegalArgumentException.class, () -> RsaFileCipher.decrypt(flipped, keyPair.privateKey()));

        assertThrows(IllegalArgumentException.class, () -> RsaFileCipher.decrypt(new byte[2], keyPair.privateKey()));
    }

    @Test
    @DisplayName("#7 Неверный ключ даёт понятную IllegalArgumentException, а не мусор")
    void testWrongKeyIsRejected() {
        RsaHelper.RsaKeyPair otherKeys = RsaHelper.generateKeyPair(randomPrime(1024), randomPrime(1024),
                RsaHelper.PROJECT_PUBLIC_EXPONENT);
        byte[] encrypted = RsaFileCipher.encrypt("Секретные данные".getBytes(), keyPair.publicKey());

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> RsaFileCipher.decrypt(encrypted, otherKeys.privateKey()));
        assertTrue(error.getMessage().contains("неверный ключ"));
    }

    private static void assertImagesIdentical(Path expected, Path actual) throws IOException {
        assertEquals(Files.size(expected), Files.size(actual), "Размеры файлов различаются");
        assertEquals(-1L, Files.mismatch(expected, actual), "Файлы различаются побайтово");
        assertEquals(sha256(expected), sha256(actual), "SHA-256 различаются");

        BufferedImage expectedImage = ImageIO.read(expected.toFile());
        BufferedImage actualImage = ImageIO.read(actual.toFile());
        assertNotNull(expectedImage, "Не удалось декодировать оригинал как изображение");
        assertNotNull(actualImage, "Не удалось декодировать расшифрованный файл как изображение");
        assertEquals(expectedImage.getWidth(), actualImage.getWidth());
        assertEquals(expectedImage.getHeight(), actualImage.getHeight());
        int w = expectedImage.getWidth();
        int h = expectedImage.getHeight();
        assertArrayEquals(expectedImage.getRGB(0, 0, w, h, null, 0, w),
                actualImage.getRGB(0, 0, w, h, null, 0, w), "Пиксели изображений различаются");
    }

    private static String sha256(Path path) throws IOException {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static BigInteger randomPrime(int bits) {
        BigInteger candidate = PrimeCandidateGenerator.generateCandidate(bits);
        while (!MillerRabinTest.isProbablePrime(candidate, 10)) {
            candidate = PrimeCandidateGenerator.generateCandidate(bits);
        }
        return candidate;
    }
}
