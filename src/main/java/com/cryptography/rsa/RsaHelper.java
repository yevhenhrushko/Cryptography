package com.cryptography.rsa;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Хелпер для криптографического алгоритма RSA.
 * Предоставляет методы для генерации ключей, шифрования и расшифрования чисел, байтов и строк,
 * а также сохранения и загрузки ключей в файлы.
 */
public class RsaHelper {

    /**
     * Стандартная общепринятая открытая экспонента (четвертое число Ферма: 2^16 + 1).
     */
    public static final BigInteger DEFAULT_PUBLIC_EXPONENT = BigInteger.valueOf(65537);

    /**
     * Увеличенная открытая экспонента порядка 6553765537 (33 бита, 13 единиц).
     * Дает всего ~44 операции Square-and-Multiply против 17 для 65537 (замедление всего в ~2.6 раза, строго < 10 раз).
     */
    public static final BigInteger PROJECT_PUBLIC_EXPONENT = new BigInteger("6553765537");

    /**
     * Директория по умолчанию для хранения сгенерированных ключей.
     */
    public static final Path KEYS_DIRECTORY = Path.of("Keys");

    /**
     * Имя файла открытого ключа по умолчанию в корне проекта.
     */
    public static final Path DEFAULT_PUBLIC_KEY_FILE = Path.of("public.key");

    /**
     * Имя файла закрытого ключа по умолчанию в корне проекта.
     */
    public static final Path DEFAULT_PRIVATE_KEY_FILE = Path.of("private.key");

    /**
     * Открытый ключ RSA (e, n).
     */
    public record RsaPublicKey(BigInteger e, BigInteger n) {
        public int bitLength() {
            return n.bitLength();
        }
    }

    /**
     * Закрытый ключ RSA (d, n). Простые множители p и q необязательны (могут быть null);
     * если они известны, расшифрование выполняется по китайской теореме об остатках (CRT), что в ~3-4 раза быстрее.
     */
    public record RsaPrivateKey(BigInteger d, BigInteger n, BigInteger p, BigInteger q) {
        public RsaPrivateKey(BigInteger d, BigInteger n) {
            this(d, n, null, null);
        }

        public int bitLength() {
            return n.bitLength();
        }

        public boolean hasCrtParameters() {
            return p != null && q != null;
        }
    }

    /**
     * Пара ключей RSA (открытый и закрытый).
     */
    public record RsaKeyPair(RsaPublicKey publicKey, RsaPrivateKey privateKey) {
        public int bitLength() {
            return publicKey.bitLength();
        }
    }

    /**
     * Контейнер для сохраненной пары ключей с путями к созданным файлам.
     */
    public record SavedRsaKeyPair(RsaKeyPair keyPair, Path publicKeyPath, Path privateKeyPath) {
        public RsaPublicKey publicKey() {
            return keyPair.publicKey();
        }

        public RsaPrivateKey privateKey() {
            return keyPair.privateKey();
        }
    }

    /**
     * Генерирует пару ключей RSA по двум простым числам p и q со стандартной экспонентой e = 65537.
     *
     * @param p первое простое число
     * @param q второе простое число
     * @return пара ключей RsaKeyPair (открытый и закрытый)
     */
    public static RsaKeyPair generateKeyPair(BigInteger p, BigInteger q) {
        return generateKeyPair(p, q, DEFAULT_PUBLIC_EXPONENT);
    }

    /**
     * Генерирует пару ключей RSA по двум простым числам p и q с заданной открытой экспонентой e.
     *
     * @param p               первое простое число
     * @param q               второе простое число
     * @param publicExponent  открытая экспонента e (обычно 65537)
     * @return пара ключей RsaKeyPair
     */
    public static RsaKeyPair generateKeyPair(BigInteger p, BigInteger q, BigInteger publicExponent) {
        if (p == null || q == null || publicExponent == null) {
            throw new IllegalArgumentException("Параметры p, q и publicExponent не должны быть null");
        }
        if (p.compareTo(BigInteger.ONE) <= 0 || q.compareTo(BigInteger.ONE) <= 0) {
            throw new IllegalArgumentException("Простые числа p и q должны быть строго больше 1");
        }
        if (p.equals(q)) {
            throw new IllegalArgumentException("Простые числа p и q должны быть различными");
        }

        // 1. Вычисляем модуль RSA: n = p * q
        BigInteger n = p.multiply(q);

        // 2. Вычисляем функцию Эйлера: phi(n) = (p - 1) * (q - 1)
        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        BigInteger qMinusOne = q.subtract(BigInteger.ONE);
        BigInteger phi = pMinusOne.multiply(qMinusOne);

        // 3. Проверяем взаимную простоту e и phi(n)
        BigInteger e = publicExponent;
        if (!e.gcd(phi).equals(BigInteger.ONE)) {
            // Если выбранное e не взаимно просто с phi, ищем ближайшее следующее нечетное число,
            // чтобы сохранить порядок величины e (и стоимость шифрования)
            e = e.testBit(0) ? e.add(BigInteger.TWO) : e.add(BigInteger.ONE);
            while (!e.gcd(phi).equals(BigInteger.ONE)) {
                e = e.add(BigInteger.valueOf(2));
            }
        }

        // 4. Вычисляем секретную экспоненту: d = e^(-1) mod phi(n)
        BigInteger d = e.modInverse(phi);

        RsaPublicKey publicKey = new RsaPublicKey(e, n);
        RsaPrivateKey privateKey = new RsaPrivateKey(d, n, p, q);
        return new RsaKeyPair(publicKey, privateKey);
    }

    /**
     * Шифрует числовое сообщение m с использованием открытого ключа: c = m^e mod n.
     *
     * @param message   числовое сообщение (0 <= m < n)
     * @param publicKey открытый ключ
     * @return зашифрованное числовое сообщение c
     */
    public static BigInteger encrypt(BigInteger message, RsaPublicKey publicKey) {
        if (message == null || publicKey == null) {
            throw new IllegalArgumentException("Параметры message и publicKey не могут быть null");
        }
        if (message.compareTo(BigInteger.ZERO) < 0) {
            throw new IllegalArgumentException("Сообщение должно быть неотрицательным числом");
        }
        if (message.compareTo(publicKey.n()) >= 0) {
            throw new IllegalArgumentException("Сообщение слишком велико для данного модуля RSA (m >= n)");
        }
        return message.modPow(publicKey.e(), publicKey.n());
    }

    /**
     * Расшифровывает шифротекст c с использованием закрытого ключа: m = c^d mod n.
     *
     * @param ciphertext зашифрованное число
     * @param privateKey закрытый ключ
     * @return расшифрованное числовое сообщение m
     */
    public static BigInteger decrypt(BigInteger ciphertext, RsaPrivateKey privateKey) {
        if (ciphertext == null || privateKey == null) {
            throw new IllegalArgumentException("Параметры ciphertext и privateKey не могут быть null");
        }
        if (ciphertext.compareTo(BigInteger.ZERO) < 0 || ciphertext.compareTo(privateKey.n()) >= 0) {
            throw new IllegalArgumentException("Шифротекст должен находиться в диапазоне [0, n - 1]");
        }
        if (privateKey.hasCrtParameters()) {
            return decryptCrt(ciphertext, privateKey);
        }
        return ciphertext.modPow(privateKey.d(), privateKey.n());
    }

    /**
     * Расшифрование по китайской теореме об остатках (алгоритм Гарнера):
     * m1 = c^(d mod (p-1)) mod p, m2 = c^(d mod (q-1)) mod q, m = m2 + q * (q^(-1) * (m1 - m2) mod p).
     */
    private static BigInteger decryptCrt(BigInteger ciphertext, RsaPrivateKey privateKey) {
        BigInteger p = privateKey.p();
        BigInteger q = privateKey.q();
        BigInteger dp = privateKey.d().mod(p.subtract(BigInteger.ONE));
        BigInteger dq = privateKey.d().mod(q.subtract(BigInteger.ONE));
        BigInteger qInv = q.modInverse(p);

        BigInteger m1 = ciphertext.modPow(dp, p);
        BigInteger m2 = ciphertext.modPow(dq, q);
        BigInteger h = qInv.multiply(m1.subtract(m2)).mod(p);
        return m2.add(h.multiply(q));
    }

    /**
     * Шифрует массив байт в шифротекст BigInteger.
     *
     * @param data      исходные байты
     * @param publicKey открытый ключ
     * @return зашифрованное число c
     */
    public static BigInteger encryptBytes(byte[] data, RsaPublicKey publicKey) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Данные для шифрования не могут быть пустыми");
        }
        BigInteger message = new BigInteger(1, data);
        return encrypt(message, publicKey);
    }

    /**
     * Расшифровывает шифротекст BigInteger обратно в массив байт.
     *
     * @param ciphertext зашифрованное число
     * @param privateKey закрытый ключ
     * @return расшифрованные байты
     */
    public static byte[] decryptBytes(BigInteger ciphertext, RsaPrivateKey privateKey) {
        BigInteger decryptedNumber = decrypt(ciphertext, privateKey);
        return toByteArrayUnsigned(decryptedNumber);
    }

    /**
     * Шифрует текстовую строку (UTF-8) в шифротекст BigInteger.
     *
     * @param plaintext исходный текст
     * @param publicKey открытый ключ
     * @return шифротекст BigInteger
     */
    public static BigInteger encryptText(String plaintext, RsaPublicKey publicKey) {
        if (plaintext == null) {
            throw new IllegalArgumentException("Текст не может быть null");
        }
        byte[] bytes = plaintext.getBytes(StandardCharsets.UTF_8);
        return encryptBytes(bytes, publicKey);
    }

    /**
     * Расшифровывает шифротекст BigInteger в исходную строку UTF-8.
     *
     * @param ciphertext зашифрованное число
     * @param privateKey закрытый ключ
     * @return расшифрованная текстовая строка
     */
    public static String decryptText(BigInteger ciphertext, RsaPrivateKey privateKey) {
        byte[] decryptedBytes = decryptBytes(ciphertext, privateKey);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    /**
     * Вспомогательный метод для извлечения беззнакового массива байтов из BigInteger
     * (удаляет ведущий нулевой байт знака, если он присутствует).
     */
    private static byte[] toByteArrayUnsigned(BigInteger bi) {
        byte[] bytes = bi.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] stripped = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, stripped, 0, stripped.length);
            return stripped;
        }
        return bytes;
    }

    /**
     * Создает пару ключей RSA на основе простых чисел p и q и сохраняет их в корне проекта
     * в файлы public.key и private.key по умолчанию.
     *
     * @param p первое простое число
     * @param q второе простое число
     * @return сгенерированная пара ключей RsaKeyPair
     * @throws IOException при ошибках записи файлов
     */
    public static RsaKeyPair createAndSaveKeysInProjectRoot(BigInteger p, BigInteger q) throws IOException {
        return createAndSaveKeys(p, q, DEFAULT_PUBLIC_KEY_FILE, DEFAULT_PRIVATE_KEY_FILE);
    }

    /**
     * Создает пару ключей RSA на основе простых чисел p и q и сохраняет их по указанным путям.
     *
     * @param p              первое простое число
     * @param q              второе простое число
     * @param publicKeyPath  путь к файлу открытого ключа
     * @param privateKeyPath путь к файлу закрытого ключа
     * @return сгенерированная пара ключей RsaKeyPair
     * @throws IOException при ошибках записи файлов
     */
    public static RsaKeyPair createAndSaveKeys(BigInteger p, BigInteger q, Path publicKeyPath, Path privateKeyPath) throws IOException {
        RsaKeyPair keyPair = generateKeyPair(p, q);
        savePublicKey(keyPair.publicKey(), publicKeyPath);
        savePrivateKey(keyPair.privateKey(), p, q, privateKeyPath);
        return keyPair;
    }

    /**
     * Создает пару ключей RSA с заданной открытой экспонентой и сохраняет их в папку "Keys"
     * с именами файлов &lt;timestamp&gt;_public.key и &lt;timestamp&gt;_private.key.
     *
     * @param p              первое простое число
     * @param q              второе простое число
     * @param publicExponent открытая экспонента (например, PROJECT_PUBLIC_EXPONENT)
     * @return объект SavedRsaKeyPair с парой ключей и точными путями к созданным файлам
     * @throws IOException при ошибках создания директории или записи файлов
     */
    public static SavedRsaKeyPair createAndSaveTimestampedKeys(BigInteger p, BigInteger q, BigInteger publicExponent) throws IOException {
        return createAndSaveTimestampedKeys(p, q, publicExponent, KEYS_DIRECTORY);
    }

    /**
     * Создает пару ключей RSA и сохраняет их в указанную директорию
     * с именами файлов &lt;timestamp&gt;_public.key и &lt;timestamp&gt;_private.key.
     *
     * @param p              первое простое число
     * @param q              второе простое число
     * @param publicExponent открытая экспонента
     * @param targetDir      папка для сохранения ключей
     * @return объект SavedRsaKeyPair с парой ключей и точными путями к созданным файлам
     * @throws IOException при ошибках создания директории или записи файлов
     */
    public static SavedRsaKeyPair createAndSaveTimestampedKeys(BigInteger p, BigInteger q, BigInteger publicExponent, Path targetDir) throws IOException {
        Files.createDirectories(targetDir);
        String timestamp = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss").format(LocalDateTime.now());

        // Если в ту же секунду уже создавалась пара, добавляем суффикс, чтобы не перезаписать прежние ключи
        Path publicKeyPath = targetDir.resolve(timestamp + "_public.key");
        Path privateKeyPath = targetDir.resolve(timestamp + "_private.key");
        for (int suffix = 1; Files.exists(publicKeyPath) || Files.exists(privateKeyPath); suffix++) {
            publicKeyPath = targetDir.resolve(timestamp + "_" + suffix + "_public.key");
            privateKeyPath = targetDir.resolve(timestamp + "_" + suffix + "_private.key");
        }

        RsaKeyPair keyPair = generateKeyPair(p, q, publicExponent);
        savePublicKey(keyPair.publicKey(), publicKeyPath);
        savePrivateKey(keyPair.privateKey(), p, q, privateKeyPath);
        return new SavedRsaKeyPair(keyPair, publicKeyPath, privateKeyPath);
    }

    /**
     * Сохраняет открытый ключ в файл в читаемом PEM-подобном формате.
     *
     * @param publicKey открытый ключ (e, n)
     * @param path      путь для сохранения
     * @throws IOException при ошибке записи
     */
    public static void savePublicKey(RsaPublicKey publicKey, Path path) throws IOException {
        if (publicKey == null || path == null) {
            throw new IllegalArgumentException("Параметры publicKey и path не могут быть null");
        }
        String content = String.format(
                "-----BEGIN RSA PUBLIC KEY-----%n" +
                "Bit-Length: %d%n" +
                "Public-Exponent: %s%n" +
                "Modulus:%n%s%n" +
                "-----END RSA PUBLIC KEY-----%n",
                publicKey.bitLength(),
                publicKey.e(),
                publicKey.n()
        );
        Files.writeString(path, content, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    /**
     * Сохраняет закрытый ключ в файл.
     *
     * @param privateKey закрытый ключ (d, n)
     * @param path       путь для сохранения
     * @throws IOException при ошибке записи
     */
    public static void savePrivateKey(RsaPrivateKey privateKey, Path path) throws IOException {
        savePrivateKey(privateKey, null, null, path);
    }

    /**
     * Сохраняет закрытый ключ в файл с возможностью сохранения исходных простых чисел p и q.
     *
     * @param privateKey закрытый ключ (d, n)
     * @param p          первое простое число (может быть null)
     * @param q          второе простое число (может быть null)
     * @param path       путь для сохранения
     * @throws IOException при ошибке записи
     */
    public static void savePrivateKey(RsaPrivateKey privateKey, BigInteger p, BigInteger q, Path path) throws IOException {
        if (privateKey == null || path == null) {
            throw new IllegalArgumentException("Параметры privateKey и path не могут быть null");
        }
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN RSA PRIVATE KEY-----\n");
        sb.append("Bit-Length: ").append(privateKey.bitLength()).append("\n");
        sb.append("Private-Exponent:\n").append(privateKey.d()).append("\n");
        sb.append("Modulus:\n").append(privateKey.n()).append("\n");
        if (p != null) {
            sb.append("Prime1 (p):\n").append(p).append("\n");
        }
        if (q != null) {
            sb.append("Prime2 (q):\n").append(q).append("\n");
        }
        sb.append("-----END RSA PRIVATE KEY-----\n");

        Files.writeString(path, sb.toString(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        restrictToOwner(path);
    }

    /**
     * Ограничивает права доступа к файлу только владельцем (rw-------, то есть 600) на POSIX-системах.
     * На файловых системах без POSIX-прав (например, Windows) операция тихо пропускается.
     *
     * @param path путь к файлу закрытого ключа
     */
    private static void restrictToOwner(Path path) {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException ignored) {
            // POSIX-права недоступны на этой ФС — оставляем права по умолчанию
        }
    }

    /**
     * Загружает открытый ключ RSA из файла.
     *
     * @param path путь к файлу ключа
     * @return восстановленный объект RsaPublicKey
     * @throws IOException при ошибке чтения файла
     */
    public static RsaPublicKey loadPublicKey(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path);
        BigInteger e = extractValue(lines, "Public-Exponent:");
        BigInteger n = extractValue(lines, "Modulus:");
        return new RsaPublicKey(e, n);
    }

    /**
     * Загружает закрытый ключ RSA из файла.
     *
     * @param path путь к файлу ключа
     * @return восстановленный объект RsaPrivateKey
     * @throws IOException при ошибке чтения файла
     */
    public static RsaPrivateKey loadPrivateKey(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path);
        BigInteger d = extractValue(lines, "Private-Exponent:");
        BigInteger n = extractValue(lines, "Modulus:");
        BigInteger p = findValue(lines, "Prime1 (p):");
        BigInteger q = findValue(lines, "Prime2 (q):");
        // CRT-расшифрование верно только при p * q == n; иначе отбрасываем p и q,
        // чтобы не получить молча неверный результат (расшифруем классическим способом)
        if (p != null && q != null && !p.multiply(q).equals(n)) {
            throw new IllegalArgumentException("Простые множители p и q в файле ключа не соответствуют модулю n");
        }
        return new RsaPrivateKey(d, n, p, q);
    }

    private static BigInteger extractValue(List<String> lines, String header) {
        BigInteger value = findValue(lines, header);
        if (value == null) {
            // Намеренно НЕ выводим содержимое файла: в закрытом ключе это раскрыло бы d, p и q
            throw new IllegalArgumentException("Поле '" + header + "' не найдено в файле ключа");
        }
        return value;
    }

    private static BigInteger findValue(List<String> lines, String header) {
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.startsWith(header)) {
                String remainder = line.substring(header.length()).trim();
                if (!remainder.isEmpty()) {
                    return new BigInteger(remainder);
                } else if (i + 1 < lines.size()) {
                    return new BigInteger(lines.get(i + 1).trim());
                }
            }
        }
        return null;
    }
}

