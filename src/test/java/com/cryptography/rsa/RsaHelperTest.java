package com.cryptography.rsa;

import com.cryptography.generator.PrimeCandidateGenerator;
import com.cryptography.primality.MillerRabinTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class RsaHelperTest {

    @Test
    @DisplayName("Проверка шифрования и расшифрования с известными небольшими простыми числами (p=61, q=53, e=17)")
    void testKnownTextbookValues() {
        BigInteger p = BigInteger.valueOf(61);
        BigInteger q = BigInteger.valueOf(53);
        BigInteger e = BigInteger.valueOf(17);

        RsaHelper.RsaKeyPair keyPair = RsaHelper.generateKeyPair(p, q, e);

        // n = 61 * 53 = 3233
        assertEquals(BigInteger.valueOf(3233), keyPair.publicKey().n());
        // phi = 60 * 52 = 3120, d = 17^(-1) mod 3120 = 2753
        assertEquals(BigInteger.valueOf(2753), keyPair.privateKey().d());

        // Проверяем число m = 65
        BigInteger message = BigInteger.valueOf(65);
        BigInteger ciphertext = RsaHelper.encrypt(message, keyPair.publicKey());
        // 65^17 mod 3233 = 2790
        assertEquals(BigInteger.valueOf(2790), ciphertext);

        BigInteger decrypted = RsaHelper.decrypt(ciphertext, keyPair.privateKey());
        assertEquals(message, decrypted);
    }

    @Test
    @DisplayName("Проверка шифрования и расшифрования текста (включая кириллицу и спецсимволы)")
    void testTextEncryptionDecryption() {
        BigInteger p = PrimeCandidateGenerator.generateCandidate(512);
        while (!MillerRabinTest.isProbablePrime(p, 10)) {
            p = PrimeCandidateGenerator.generateCandidate(512);
        }

        BigInteger q = PrimeCandidateGenerator.generateCandidate(512);
        while (!MillerRabinTest.isProbablePrime(q, 10) || q.equals(p)) {
            q = PrimeCandidateGenerator.generateCandidate(512);
        }

        RsaHelper.RsaKeyPair keyPair = RsaHelper.generateKeyPair(p, q);

        String originalText = "Тестовое сообщение RSA с поддержкой UTF-8: 1234567890 !?@#$%^&*()_+";
        BigInteger ciphertext = RsaHelper.encryptText(originalText, keyPair.publicKey());
        assertNotNull(ciphertext);

        String decryptedText = RsaHelper.decryptText(ciphertext, keyPair.privateKey());
        assertEquals(originalText, decryptedText);
    }

    @Test
    @DisplayName("Выброс исключения, если сообщение больше либо равно модулю n")
    void testMessageTooLarge() {
        BigInteger p = BigInteger.valueOf(61);
        BigInteger q = BigInteger.valueOf(53);
        RsaHelper.RsaKeyPair keyPair = RsaHelper.generateKeyPair(p, q, BigInteger.valueOf(17));

        BigInteger tooLarge = keyPair.publicKey().n().add(BigInteger.ONE);
        assertThrows(IllegalArgumentException.class, () -> RsaHelper.encrypt(tooLarge, keyPair.publicKey()));
    }

    @Test
    @DisplayName("Выброс исключения при недопустимых простых числах (p == q или p <= 1)")
    void testInvalidPrimes() {
        BigInteger p = BigInteger.valueOf(17);
        assertThrows(IllegalArgumentException.class, () -> RsaHelper.generateKeyPair(p, p));
        assertThrows(IllegalArgumentException.class, () -> RsaHelper.generateKeyPair(BigInteger.ONE, p));
    }

    @Test
    @DisplayName("Проверка сохранения и загрузки ключей из файлов")
    void testSaveAndLoadKeys(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tempDir) throws java.io.IOException {
        BigInteger p = BigInteger.valueOf(61);
        BigInteger q = BigInteger.valueOf(53);
        java.nio.file.Path pubKeyPath = tempDir.resolve("test_public.key");
        java.nio.file.Path privKeyPath = tempDir.resolve("test_private.key");

        RsaHelper.RsaKeyPair keyPair = RsaHelper.createAndSaveKeys(p, q, pubKeyPath, privKeyPath);

        assertTrue(java.nio.file.Files.exists(pubKeyPath));
        assertTrue(java.nio.file.Files.exists(privKeyPath));

        RsaHelper.RsaPublicKey loadedPub = RsaHelper.loadPublicKey(pubKeyPath);
        RsaHelper.RsaPrivateKey loadedPriv = RsaHelper.loadPrivateKey(privKeyPath);

        assertEquals(keyPair.publicKey().e(), loadedPub.e());
        assertEquals(keyPair.publicKey().n(), loadedPub.n());
        assertEquals(keyPair.privateKey().d(), loadedPriv.d());
        assertEquals(keyPair.privateKey().n(), loadedPriv.n());

        // Проверяем шифрование и расшифрование с загруженными ключами
        BigInteger msg = BigInteger.valueOf(42);
        BigInteger cipher = RsaHelper.encrypt(msg, loadedPub);
        BigInteger plain = RsaHelper.decrypt(cipher, loadedPriv);
        assertEquals(msg, plain);
    }

    @Test
    @DisplayName("Проверка создания ключей с timestamp в заданной папке и шифрования 'Hello World!'")
    void testTimestampedKeysInFolder(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tempDir) throws java.io.IOException {
        BigInteger p = PrimeCandidateGenerator.generateCandidate(512);
        while (!MillerRabinTest.isProbablePrime(p, 10)) {
            p = PrimeCandidateGenerator.generateCandidate(512);
        }

        BigInteger q = PrimeCandidateGenerator.generateCandidate(512);
        while (!MillerRabinTest.isProbablePrime(q, 10) || q.equals(p)) {
            q = PrimeCandidateGenerator.generateCandidate(512);
        }

        RsaHelper.SavedRsaKeyPair saved = RsaHelper.createAndSaveTimestampedKeys(
                p, q, RsaHelper.PROJECT_PUBLIC_EXPONENT, tempDir);

        assertTrue(java.nio.file.Files.exists(saved.publicKeyPath()));
        assertTrue(java.nio.file.Files.exists(saved.privateKeyPath()));
        assertTrue(saved.publicKeyPath().getFileName().toString().endsWith("_public.key"));
        assertTrue(saved.privateKeyPath().getFileName().toString().endsWith("_private.key"));

        // Шифрование и дешифрование "Hello World!"
        String text = "Hello World!";
        BigInteger cipher = RsaHelper.encryptText(text, saved.publicKey());
        String decrypted = RsaHelper.decryptText(cipher, saved.privateKey());
        assertEquals(text, decrypted);
    }

    @Test
    @DisplayName("#1 Ошибка загрузки ключа не раскрывает содержимое файла (d, p, q)")
    void testMissingFieldErrorDoesNotLeakKey(@TempDir Path tempDir) throws IOException {
        Path broken = tempDir.resolve("broken_private.key");
        String secret = "987654321987654321987654321";
        Files.writeString(broken, "-----BEGIN RSA PRIVATE KEY-----\nPrivate-Exponent:\n" + secret
                + "\nPrime1 (p):\n" + secret + "\n-----END RSA PRIVATE KEY-----\n");

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> RsaHelper.loadPrivateKey(broken));
        assertFalse(error.getMessage().contains(secret), "Сообщение об ошибке содержит секретные данные ключа");
    }

    @Test
    @DisplayName("#3 Файл закрытого ключа доступен только владельцу (600)")
    void testPrivateKeyPermissionsAreOwnerOnly(@TempDir Path tempDir) throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"),
                "POSIX-права не поддерживаются этой файловой системой");
        RsaHelper.SavedRsaKeyPair saved = RsaHelper.createAndSaveTimestampedKeys(
                BigInteger.valueOf(61), BigInteger.valueOf(53), BigInteger.valueOf(17), tempDir);

        assertEquals(PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(saved.privateKeyPath()));
    }

    @Test
    @DisplayName("#8 Две генерации ключей в одну секунду не перезаписывают друг друга")
    void testTimestampedKeysDoNotOverwrite(@TempDir Path tempDir) throws IOException {
        RsaHelper.SavedRsaKeyPair first = RsaHelper.createAndSaveTimestampedKeys(
                BigInteger.valueOf(61), BigInteger.valueOf(53), BigInteger.valueOf(17), tempDir);
        RsaHelper.SavedRsaKeyPair second = RsaHelper.createAndSaveTimestampedKeys(
                BigInteger.valueOf(67), BigInteger.valueOf(71), BigInteger.valueOf(17), tempDir);

        assertNotEquals(first.publicKeyPath(), second.publicKeyPath());
        assertNotEquals(first.privateKeyPath(), second.privateKeyPath());
        assertEquals(first.publicKey().n(), RsaHelper.loadPublicKey(first.publicKeyPath()).n(),
                "Первая пара ключей была перезаписана");
        assertEquals(second.publicKey().n(), RsaHelper.loadPublicKey(second.publicKeyPath()).n());
    }

    @Test
    @DisplayName("#9 Загрузка ключа отклоняет p и q, не соответствующие модулю n")
    void testMismatchedPrimesAreRejected(@TempDir Path tempDir) throws IOException {
        Path pub = tempDir.resolve("pub.key");
        Path priv = tempDir.resolve("priv.key");
        RsaHelper.RsaKeyPair keyPair = RsaHelper.createAndSaveKeys(
                BigInteger.valueOf(61), BigInteger.valueOf(53), pub, priv);
        assertEquals(keyPair.privateKey().d(), RsaHelper.loadPrivateKey(priv).d());

        String tampered = Files.readString(priv).replace("Prime1 (p):\n61", "Prime1 (p):\n67");
        assertNotEquals(Files.readString(priv), tampered, "Подмена p не сработала");
        Files.writeString(priv, tampered);
        assertThrows(IllegalArgumentException.class, () -> RsaHelper.loadPrivateKey(priv));
    }
}
