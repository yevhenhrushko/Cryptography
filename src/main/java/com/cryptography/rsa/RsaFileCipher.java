package com.cryptography.rsa;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.IntStream;

/**
 * Поблочное шифрование и расшифрование файлов алгоритмом RSA с паддингом OAEP
 * (PKCS#1 v2.2, RSAES-OAEP, хеш SHA-256, генератор маски MGF1-SHA-256).
 * <p>
 * В отличие от «учебного» RSA без паддинга, OAEP:
 * <ul>
 *   <li>добавляет в каждый блок случайный seed, поэтому одинаковые блоки дают разный шифротекст;</li>
 *   <li>исключает тривиальные блоки m = 0 и m = 1, которые шифруются сами в себя;</li>
 *   <li>проверяет целостность блока при расшифровании, так что неверный ключ или
 *       повреждённый файл обнаруживаются, а не дают молча неверные данные.</li>
 * </ul>
 * Формат зашифрованного файла:
 * <pre>
 *   [4 байта] сигнатура "RSAO"
 *   [1 байт]  версия формата
 *   [N блоков по k байт] шифротексты блоков, k = ceil(bitLength(n) / 8)
 * </pre>
 * Каждый блок сам хранит длину своих данных, поэтому заголовок с исходной длиной не нужен.
 * Блоки обрабатываются параллельно на всех ядрах процессора.
 */
public class RsaFileCipher {

    private static final byte[] MAGIC = {'R', 'S', 'A', 'O'};
    private static final byte FORMAT_VERSION = 1;
    private static final int HEADER_LENGTH = MAGIC.length + 1;

    private static final String HASH_ALGORITHM = "SHA-256";
    private static final int HASH_LENGTH = 32;

    /**
     * Хеш пустой метки L (label) из OAEP. Метка не используется, поэтому хеш постоянный.
     */
    private static final byte[] LABEL_HASH = sha256(new byte[0]);

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Единое сообщение для любых ошибок расшифрования. Одинаковый текст не позволяет атакующему
     * различать причины отказа (защита от атак по оракулу паддинга, например атаки Мангера).
     */
    private static final String DECRYPTION_ERROR = "Не удалось расшифровать: неверный ключ или повреждённый файл";

    private RsaFileCipher() {
    }

    /**
     * Максимальный размер блока открытого текста в байтах для модуля n: k - 2 * hLen - 2.
     */
    public static int plainBlockSize(BigInteger n) {
        int size = cipherBlockSize(n) - 2 * HASH_LENGTH - 2;
        if (size < 1) {
            throw new IllegalArgumentException("Модуль RSA слишком мал для OAEP с SHA-256");
        }
        return size;
    }

    /**
     * Размер блока шифротекста в байтах для модуля n: k = ceil(bitLength(n) / 8).
     */
    public static int cipherBlockSize(BigInteger n) {
        return (n.bitLength() + 7) / 8;
    }

    /**
     * Шифрует файл source открытым ключом и записывает результат в target.
     */
    public static void encryptFile(Path source, Path target, RsaHelper.RsaPublicKey publicKey) throws IOException {
        byte[] data = Files.readAllBytes(source);
        Files.write(target, encrypt(data, publicKey));
    }

    /**
     * Расшифровывает файл source закрытым ключом и записывает результат в target.
     */
    public static void decryptFile(Path source, Path target, RsaHelper.RsaPrivateKey privateKey) throws IOException {
        byte[] data = Files.readAllBytes(source);
        Files.write(target, decrypt(data, privateKey));
    }

    /**
     * Шифрует массив байт поблочно с паддингом OAEP.
     */
    public static byte[] encrypt(byte[] data, RsaHelper.RsaPublicKey publicKey) {
        int plainSize = plainBlockSize(publicKey.n());
        int k = cipherBlockSize(publicKey.n());
        int blocks = (data.length + plainSize - 1) / plainSize;

        byte[] result = new byte[HEADER_LENGTH + blocks * k];
        System.arraycopy(MAGIC, 0, result, 0, MAGIC.length);
        result[MAGIC.length] = FORMAT_VERSION;

        IntStream.range(0, blocks).parallel().forEach(i -> {
            int from = i * plainSize;
            int to = Math.min(from + plainSize, data.length);
            byte[] encoded = oaepEncode(Arrays.copyOfRange(data, from, to), k);
            BigInteger c = RsaHelper.encrypt(new BigInteger(1, encoded), publicKey);
            writeFixedLength(c, result, HEADER_LENGTH + i * k, k);
        });
        return result;
    }

    /**
     * Расшифровывает массив байт, полученный методом {@link #encrypt(byte[], RsaHelper.RsaPublicKey)}.
     *
     * @throws IllegalArgumentException если файл повреждён или ключ не подходит
     */
    public static byte[] decrypt(byte[] encrypted, RsaHelper.RsaPrivateKey privateKey) {
        int k = cipherBlockSize(privateKey.n());
        if (encrypted.length < HEADER_LENGTH
                || !Arrays.equals(Arrays.copyOf(encrypted, MAGIC.length), MAGIC)
                || encrypted[MAGIC.length] != FORMAT_VERSION) {
            throw new IllegalArgumentException("Файл не является зашифрованным файлом RSA-OAEP этого формата");
        }
        int bodyLength = encrypted.length - HEADER_LENGTH;
        if (bodyLength % k != 0) {
            throw new IllegalArgumentException(DECRYPTION_ERROR);
        }
        int blocks = bodyLength / k;

        byte[][] parts = new byte[blocks][];
        IntStream.range(0, blocks).parallel().forEach(i -> {
            int from = HEADER_LENGTH + i * k;
            BigInteger c = new BigInteger(1, Arrays.copyOfRange(encrypted, from, from + k));
            if (c.compareTo(privateKey.n()) >= 0) {
                throw new IllegalArgumentException(DECRYPTION_ERROR);
            }
            BigInteger m = RsaHelper.decrypt(c, privateKey);
            byte[] encoded = new byte[k];
            writeFixedLength(m, encoded, 0, k);
            parts[i] = oaepDecode(encoded, k);
        });

        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] plain = new byte[total];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, plain, offset, part.length);
            offset += part.length;
        }
        return plain;
    }

    /**
     * Кодирование EME-OAEP: EM = 0x00 || maskedSeed || maskedDB, где DB = lHash || PS || 0x01 || M.
     */
    private static byte[] oaepEncode(byte[] message, int k) {
        int dbLength = k - HASH_LENGTH - 1;
        byte[] db = new byte[dbLength];
        System.arraycopy(LABEL_HASH, 0, db, 0, HASH_LENGTH);
        // PS — нулевые байты (массив уже заполнен нулями), затем разделитель 0x01 и само сообщение
        db[dbLength - message.length - 1] = 0x01;
        System.arraycopy(message, 0, db, dbLength - message.length, message.length);

        byte[] seed = new byte[HASH_LENGTH];
        RANDOM.nextBytes(seed);

        xorInPlace(db, mgf1(seed, dbLength));
        byte[] maskedSeed = seed.clone();
        xorInPlace(maskedSeed, mgf1(db, HASH_LENGTH));

        byte[] em = new byte[k];
        // em[0] = 0x00 гарантирует, что число меньше модуля n
        System.arraycopy(maskedSeed, 0, em, 1, HASH_LENGTH);
        System.arraycopy(db, 0, em, 1 + HASH_LENGTH, dbLength);
        return em;
    }

    /**
     * Декодирование EME-OAEP. Все проверки сводятся к одной ошибке, чтобы не раскрывать причину отказа.
     */
    private static byte[] oaepDecode(byte[] em, int k) {
        int dbLength = k - HASH_LENGTH - 1;
        byte[] maskedSeed = Arrays.copyOfRange(em, 1, 1 + HASH_LENGTH);
        byte[] db = Arrays.copyOfRange(em, 1 + HASH_LENGTH, k);

        byte[] seed = maskedSeed.clone();
        xorInPlace(seed, mgf1(db, HASH_LENGTH));
        xorInPlace(db, mgf1(seed, dbLength));

        boolean valid = em[0] == 0;
        valid &= MessageDigest.isEqual(Arrays.copyOf(db, HASH_LENGTH), LABEL_HASH);

        // Ищем разделитель 0x01 после нулевого заполнения PS
        int separator = -1;
        for (int i = HASH_LENGTH; i < dbLength; i++) {
            if (db[i] == 0x01) {
                separator = i;
                break;
            }
            if (db[i] != 0x00) {
                valid = false;
                break;
            }
        }
        if (!valid || separator < 0) {
            throw new IllegalArgumentException(DECRYPTION_ERROR);
        }
        return Arrays.copyOfRange(db, separator + 1, dbLength);
    }

    /**
     * Генератор маски MGF1 на основе SHA-256: T = Hash(seed || C0) || Hash(seed || C1) || ...
     */
    private static byte[] mgf1(byte[] seed, int length) {
        MessageDigest digest = newDigest();
        byte[] mask = new byte[length];
        byte[] counter = new byte[4];
        int offset = 0;
        for (int i = 0; offset < length; i++) {
            counter[0] = (byte) (i >>> 24);
            counter[1] = (byte) (i >>> 16);
            counter[2] = (byte) (i >>> 8);
            counter[3] = (byte) i;
            digest.update(seed);
            digest.update(counter);
            byte[] hash = digest.digest();
            int chunk = Math.min(hash.length, length - offset);
            System.arraycopy(hash, 0, mask, offset, chunk);
            offset += chunk;
        }
        return mask;
    }

    private static void xorInPlace(byte[] target, byte[] mask) {
        for (int i = 0; i < target.length; i++) {
            target[i] ^= mask[i];
        }
    }

    private static byte[] sha256(byte[] data) {
        return newDigest().digest(data);
    }

    private static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance(HASH_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 недоступен в этой JVM", e);
        }
    }

    /**
     * Записывает число value в target[offset .. offset + length) с ведущими нулями (big-endian).
     */
    private static void writeFixedLength(BigInteger value, byte[] target, int offset, int length) {
        byte[] raw = value.toByteArray();
        int start = (raw.length > length && raw[0] == 0) ? 1 : 0;
        int significant = raw.length - start;
        if (significant > length) {
            throw new IllegalArgumentException(DECRYPTION_ERROR);
        }
        System.arraycopy(raw, start, target, offset + length - significant, significant);
    }
}
