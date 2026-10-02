package com.cryptography;

import com.cryptography.rsa.RsaFileCipher;
import com.cryptography.rsa.RsaHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.Comparator;
import java.util.stream.Stream;

/**
 * Шифрует файл последней сгенерированной парой ключей из папки "Keys",
 * кладет рядом зашифрованный (*.enc) и расшифрованный (*.decrypted.*) файлы, не трогая оригинал.
 */
public class FileCryptoDemo {

    private static final Logger log = LoggerFactory.getLogger(FileCryptoDemo.class);

    private static final Path DEFAULT_SOURCE = Path.of("src/main/resources/Svema FN64-24.jpg");

    public static void main(String[] args) throws IOException {
        Path source = args.length > 0 ? Path.of(args[0]) : DEFAULT_SOURCE;
        Path encrypted = encryptedPathFor(source);
        Path decrypted = decryptedPathFor(source);

        Path publicKeyPath = latestKey("_public.key");
        Path privateKeyPath = Path.of(publicKeyPath.toString().replace("_public.key", "_private.key"));
        log.info("Открытый ключ: {}", publicKeyPath);
        log.info("Закрытый ключ: {}", privateKeyPath);

        RsaHelper.RsaPublicKey publicKey = RsaHelper.loadPublicKey(publicKeyPath);
        RsaHelper.RsaPrivateKey privateKey = RsaHelper.loadPrivateKey(privateKeyPath);
        log.info("Модуль n: {} бит, e = {}, CRT: {}", publicKey.bitLength(), publicKey.e(), privateKey.hasCrtParameters());

        long start = System.currentTimeMillis();
        RsaFileCipher.encryptFile(source, encrypted, publicKey);
        log.info("Зашифровано: {} ({} байт) за {} мс", encrypted, Files.size(encrypted), System.currentTimeMillis() - start);

        start = System.currentTimeMillis();
        RsaFileCipher.decryptFile(encrypted, decrypted, privateKey);
        log.info("Расшифровано: {} ({} байт) за {} мс", decrypted, Files.size(decrypted), System.currentTimeMillis() - start);

        boolean identical = Files.mismatch(source, decrypted) == -1;
        log.info("Сравнение с оригиналом: {}", identical ? "ИДЕНТИЧНЫ" : "РАЗЛИЧАЮТСЯ");
    }

    /**
     * "photo.jpg" -> "photo.jpg.enc"
     */
    public static Path encryptedPathFor(Path source) {
        return source.resolveSibling(source.getFileName() + ".enc");
    }

    /**
     * "photo.jpg" -> "photo.decrypted.jpg"
     */
    public static Path decryptedPathFor(Path source) {
        String name = source.getFileName().toString();
        int dot = name.lastIndexOf('.');
        String decryptedName = dot > 0
                ? name.substring(0, dot) + ".decrypted" + name.substring(dot)
                : name + ".decrypted";
        return source.resolveSibling(decryptedName);
    }

    private static Path latestKey(String suffix) throws IOException {
        if (!Files.isDirectory(RsaHelper.KEYS_DIRECTORY)) {
            throw new IOException("Папка " + RsaHelper.KEYS_DIRECTORY.toAbsolutePath()
                    + " не найдена. Сначала сгенерируйте ключи: ./gradlew run");
        }
        try (Stream<Path> files = Files.list(RsaHelper.KEYS_DIRECTORY)) {
            // Сравниваем по времени изменения: имена с суффиксом (_1_, _2_) нельзя упорядочить лексикографически
            return files.filter(p -> p.getFileName().toString().endsWith(suffix))
                    .max(Comparator.comparing(FileCryptoDemo::lastModified))
                    .orElseThrow(() -> new IOException("В папке Keys нет ключей. Сначала запустите ./gradlew run"));
        }
    }

    private static FileTime lastModified(Path path) {
        try {
            return Files.getLastModifiedTime(path);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
