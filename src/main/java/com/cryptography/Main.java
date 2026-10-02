package com.cryptography;

import com.cryptography.generator.PrimeCandidateGenerator;
import com.cryptography.primality.MillerRabinTest;
import com.cryptography.rsa.RsaHelper;
import com.cryptography.rsa.RsaKeyValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    private static final int DEFAULT_BIT_LENGTH = 8192;
    private static final int MR_ROUNDS = 10;

    /**
     * Минимальная битовая длина простого числа. Для совсем малых значений (например, 2 бита)
     * генератор возвращает единственное число 3, и цикл поиска различных p и q не завершается.
     */
    private static final int MIN_BIT_LENGTH = 16;

    /**
     * Сколько раз пробуем сгенерировать ключ, прошедший все проверки RsaKeyValidator.
     */
    private static final int MAX_KEY_ATTEMPTS = 5;

    /**
     * Метод Hello World
     */
    public static void helloWorld() {
        log.info("Hello, World!");
    }

    /**
     * Цикл генерации кандидатов до тех пор, пока не будет найдено вероятно простое число.
     * Использует пул потоков для параллельной проверки кандидатов (актуально для 8192 бит).
     *
     * @param bitLength битовая длина числа
     * @param rounds    количество раундов теста Миллера — Рабина
     * @param primeName название/номер числа для информативного логирования
     * @return найденное простое число
     */
    public static BigInteger generateProbablePrime(int bitLength, int rounds, String primeName) {
        if (bitLength < MIN_BIT_LENGTH) {
            throw new IllegalArgumentException(
                    "Битовая длина должна быть не менее " + MIN_BIT_LENGTH + " бит, получено: " + bitLength);
        }
        log.info("Запуск поиска для {} ({} бит, {} раундов Миллера — Рабина)...", primeName, bitLength, rounds);
        long start = System.currentTimeMillis();
        int threads = Math.max(1, Runtime.getRuntime().availableProcessors());
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        AtomicBoolean found = new AtomicBoolean(false);
        AtomicLong totalAttempts = new AtomicLong(0);
        CompletableFuture<BigInteger> resultFuture = new CompletableFuture<>();

        for (int i = 0; i < threads; i++) {
            executor.submit(() -> {
                try {
                    while (!found.get() && !Thread.currentThread().isInterrupted()) {
                        long current = totalAttempts.incrementAndGet();
                        BigInteger candidate = PrimeCandidateGenerator.generateCandidate(bitLength);

                        if (MillerRabinTest.isProbablePrime(candidate, rounds)) {
                            if (found.compareAndSet(false, true)) {
                                resultFuture.complete(candidate);
                            }
                            break;
                        }

                        if (current % 500 == 0) {
                            log.info("Поиск {}: суммарно проверено {} кандидатов (прошло {} мс)...",
                                    primeName, current, System.currentTimeMillis() - start);
                        }
                    }
                } catch (Throwable t) {
                    // Иначе исключение потеряется внутри submit, и resultFuture.get() будет ждать вечно
                    resultFuture.completeExceptionally(t);
                }
            });
        }

        try {
            BigInteger prime = resultFuture.get();
            long duration = System.currentTimeMillis() - start;
            log.info("{} найдено за {} попыток! Затраченное время: {} мс", primeName, totalAttempts.get(), duration);
            return prime;
        } catch (InterruptedException | ExecutionException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Ошибка при поиске простого числа: " + e.getMessage(), e);
        } finally {
            executor.shutdownNow();
        }
    }

    private static void logReport(RsaKeyValidator.Report report, int attempt) {
        log.info("Проверка параметров ключа (попытка {}):", attempt);
        for (RsaKeyValidator.Check check : report.checks()) {
            if (check.passed()) {
                log.info("  [OK]   {}: {}", check.type().title(), check.details());
            } else {
                log.warn("  [FAIL] {}: {}", check.type().title(), check.details());
            }
        }
        log.info(report.isValid() ? "Все проверки пройдены." : "Ключ отбракован, генерируем новые p и q.");
        log.info("--------------------------------------------------");
    }

    public static void main(String[] args) {
        helloWorld();

        int bitLength = DEFAULT_BIT_LENGTH;
        if (args.length > 0) {
            try {
                bitLength = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                log.warn("Некорректный аргумент битовой длины '{}', используется значение по умолчанию: {}",
                        args[0], DEFAULT_BIT_LENGTH);
            }
            if (bitLength < MIN_BIT_LENGTH) {
                log.warn("Битовая длина {} меньше минимальной ({}), используется значение по умолчанию: {}",
                        bitLength, MIN_BIT_LENGTH, DEFAULT_BIT_LENGTH);
                bitLength = DEFAULT_BIT_LENGTH;
            }
        }

        log.info("--------------------------------------------------");
        log.info("Старт генерации пары простых чисел (разрядность: {} бит)", bitLength);
        log.info("--------------------------------------------------");

        try {
            BigInteger customE = RsaHelper.PROJECT_PUBLIC_EXPONENT; // 6553765537 (замедление ~2.6x, строго < 10x)
            List<BigInteger> existingModuli = RsaKeyValidator.loadExistingModuli(RsaHelper.KEYS_DIRECTORY);

            BigInteger prime1 = null;
            BigInteger prime2 = null;
            for (int attempt = 1; attempt <= MAX_KEY_ATTEMPTS && prime2 == null; attempt++) {
                // 1. Поиск первого простого числа
                BigInteger candidate1 = generateProbablePrime(bitLength, MR_ROUNDS, "Число #1");
                // Значения p и q не выводим: по ним сразу вычисляется закрытый ключ
                log.info("Число #1: битовая длина {}, десятичных знаков {}",
                        candidate1.bitLength(), candidate1.toString().length());
                log.info("--------------------------------------------------");

                // 2. Поиск второго простого числа (убеждаемся, что числа различны)
                BigInteger candidate2;
                do {
                    candidate2 = generateProbablePrime(bitLength, MR_ROUNDS, "Число #2");
                } while (candidate2.equals(candidate1));

                log.info("Число #2: битовая длина {}, десятичных знаков {}",
                        candidate2.bitLength(), candidate2.toString().length());
                log.info("--------------------------------------------------");

                // 3. Проверка параметров ключа перед сохранением
                RsaKeyValidator.Report report = RsaKeyValidator.validate(candidate1, candidate2, customE, existingModuli);
                logReport(report, attempt);
                if (report.isValid()) {
                    prime1 = candidate1;
                    prime2 = candidate2;
                }
            }
            if (prime2 == null) {
                log.error("Не удалось сгенерировать ключ, прошедший все проверки, за {} попыток", MAX_KEY_ATTEMPTS);
                return;
            }

            log.info("Пара простых чисел успешно получена и проверена.");
            log.info("--------------------------------------------------");

            // 4. Создание и сохранение пары ключей в папке "Keys" с именами timestamp_public.key и timestamp_private.key
            log.info("Создание пары ключей RSA с открытой экспонентой e = {} (замедление ~2.6x, < 10x)...", customE);
            RsaHelper.SavedRsaKeyPair savedKeys = RsaHelper.createAndSaveTimestampedKeys(prime1, prime2, customE);

            log.info("Открытый ключ сохранен в: {}", savedKeys.publicKeyPath().toAbsolutePath());
            log.info("Закрытый ключ сохранен в: {}", savedKeys.privateKeyPath().toAbsolutePath());
            log.info("Битовая длина модуля RSA n: {} бит", savedKeys.keyPair().bitLength());
            log.info("Открытая экспонента e: {}", savedKeys.publicKey().e());
            log.info("--------------------------------------------------");

            // 5. Загрузка ключей из созданных файлов
            RsaHelper.RsaPublicKey loadedPublicKey = RsaHelper.loadPublicKey(savedKeys.publicKeyPath());
            RsaHelper.RsaPrivateKey loadedPrivateKey = RsaHelper.loadPrivateKey(savedKeys.privateKeyPath());

            // 6. Шифрование и дешифрование сообщения "Hello World!"
            String originalMessage = "Hello World!";
            log.info("Исходное сообщение: \"{}\"", originalMessage);

            long encryptStart = System.currentTimeMillis();
            BigInteger ciphertext = RsaHelper.encryptText(originalMessage, loadedPublicKey);
            long encryptDuration = System.currentTimeMillis() - encryptStart;
            log.info("Зашифрованное сообщение (шифротекст BigInteger): {}", ciphertext);
            log.info("Время шифрования: {} мс", encryptDuration);

            long decryptStart = System.currentTimeMillis();
            String decryptedMessage = RsaHelper.decryptText(ciphertext, loadedPrivateKey);
            long decryptDuration = System.currentTimeMillis() - decryptStart;
            log.info("Расшифрованное (дешифрованное) сообщение: \"{}\"", decryptedMessage);
            log.info("Время дешифрования: {} мс", decryptDuration);

            boolean isMatch = originalMessage.equals(decryptedMessage);
            log.info("Результат проверки шифрования/дешифрования: {}",
                    isMatch ? "УСПЕШНО (сообщения полностью совпадают)" : "ОШИБКА (сообщения не совпадают)");
            log.info("--------------------------------------------------");
        } catch (IOException e) {
            log.error("Ошибка при работе с файлами ключей: {}", e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            log.error("Некорректные параметры RSA: {}", e.getMessage());
        }
    }
}
