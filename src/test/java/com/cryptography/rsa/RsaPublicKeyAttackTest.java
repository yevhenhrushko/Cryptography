package com.cryptography.rsa;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

/** Запускается явно отдельной Gradle-задачей; обычные unit-тесты не читают пользовательские ключи. */
@Tag("rsa-key-benchmark")
@EnabledIfSystemProperty(named = "rsa.attack.enabled", matches = "true")
class RsaPublicKeyAttackTest {

    @Test
    void attackHelloWorldWithConfiguredMeasurement() {
        int seconds = Integer.parseInt(System.getProperty("rsa.attack.seconds",
                Long.toString(RsaFermatBenchmark.DEFAULT_DURATION.toSeconds())));
        assertTrue(seconds >= 1 && seconds <= RsaFermatBenchmark.MAX_DURATION.toSeconds(),
                "Допустимо от 1 до " + RsaFermatBenchmark.MAX_DURATION.toSeconds() + " секунд для самого замера Ферма");
        assertTimeoutPreemptively(Duration.ofSeconds(seconds + 20L), () -> runExperiment(seconds));
    }

    private void runExperiment(int seconds) throws Exception {
        long experimentStarted = System.nanoTime();
        int availableProcessors = Runtime.getRuntime().availableProcessors();
        String configuredThreads = System.getProperty("rsa.attack.threads", "auto");
        int threads = configuredThreads.equals("auto") ? availableProcessors : Integer.parseInt(configuredThreads);
        assertTrue(threads >= 1 && threads <= 256, "Допустимо от 1 до 256 рабочих потоков");
        Path selected = Path.of(System.getProperty("rsa.publicKey")).toRealPath();
        Path directory = RsaHelper.KEYS_DIRECTORY.toRealPath();
        assertEquals(directory, selected.getParent(), "Открытый ключ должен находиться непосредственно в Keys");
        assertTrue(selected.getFileName().toString().endsWith("_public.key")
                || selected.getFileName().toString().equals("public.key"), "Нужно явно выбрать публичный ключ");
        var key = RsaHelper.loadPublicKey(selected);
        assertTrue(key.bitLength() <= 32768, "Этот ограниченный по времени эксперимент рассчитан на n до 32768 бит");

        String message = "Hello World";
        long encryptStarted = System.nanoTime();
        BigInteger ciphertext = RsaHelper.encryptText(message, key);
        long encryptionNanos = System.nanoTime() - encryptStarted;
        BigInteger expected = new BigInteger(1, message.getBytes(StandardCharsets.UTF_8));
        var report = new ArrayList<String>();
        report.add("Учебный эксперимент RSA / " + Instant.now());
        report.add("Публичный ключ: " + selected);
        report.add("n: " + key.bitLength() + " бит; e: " + key.e());
        report.add("Логических процессоров, доступных JVM: " + availableProcessors + "; потоков Ферма: " + threads);
        report.add("Заданный бюджет замера Ферма: " + seconds + " с; подготовка и сохранение отчёта учитываются отдельно.");
        report.add("Оптимизации: динамические блоки по 256 кандидатов; фильтр квадратов mod 4032 перед sqrt.");
        report.add("SHA-256(n, unsigned bytes): " + sha256(unsignedBytes(key.n())));
        report.add("Сообщение заново зашифровано методом RsaHelper.encryptText: Hello World (UTF-8, без padding).");
        report.add("Время шифрования: " + (encryptionNanos / 1_000_000.0) + " мс");
        report.add("SHA-256(c, unsigned bytes): " + sha256(unsignedBytes(ciphertext)));

        // Проверка одного известного кандидата — отдельная атака на детерминированное шифрование.
        long guessStarted = System.nanoTime();
        boolean candidateMatches = RsaHelper.encryptText("Hello World", key).equals(ciphertext);
        long guessNanos = System.nanoTime() - guessStarted;
        report.add("Проверка известного кандидата Hello World: " + candidateMatches + ", "
                + guessNanos / 1_000_000.0 + " мс; это не восстановление приватного ключа.");
        assertTrue(candidateMatches);

        var preliminary = List.of(RsaAttackHelper.lowExponent(key, ciphertext), RsaAttackHelper.wiener(key, ciphertext));
        boolean recovered = false;
        for (var attack : preliminary) {
            report.add(attack.type() + ": " + (attack.recoveredMessage().isPresent() ? "сообщение восстановлено" : "не восстановлено"));
            if (attack.recoveredMessage().isPresent()) {
                assertEquals(expected, attack.recoveredMessage().orElseThrow());
                recovered = true;
            }
        }

        RsaFermatBenchmark.Measurement measurement = null;
        if (!recovered) {
            System.out.println("Запущен Ферма: n = " + key.bitLength() + " бит, потоков = " + threads
                    + ", длительность замера = " + seconds + " секунд.");
            measurement = RsaFermatBenchmark.measure(key, ciphertext, Duration.ofSeconds(seconds), threads);
            appendMeasurement(report, measurement);
            if (measurement.recoveredMessage().isPresent()) {
                assertEquals(expected, measurement.recoveredMessage().orElseThrow());
            }
        } else {
            report.add("Ферма не нужен: одна из предварительных атак уже восстановила сообщение.");
        }
        double totalSeconds = (System.nanoTime() - experimentStarted) / 1_000_000_000.0;
        report.add("Общее время эксперимента: " + totalSeconds + " с");
        appendSummary(report, measurement, totalSeconds, guessNanos);
        report.add("ВЕРДИКТ: эксперимент не доказывает криптостойкость. Проход теста означает корректное выполнение измерения.");
        report.add("Textbook RSA позволяет подтвердить известное короткое сообщение публичным ключом; для шифрования нужен padding.");
        report.add("Локальные источники и оригинальные URL: docs/sources/README.md");

        Path reportPath = Path.of("docs/rsa-key-benchmark-latest.txt");
        String stamp = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS").withZone(ZoneOffset.UTC).format(Instant.now());
        Path archive = Path.of("docs/benchmarks/rsa-" + stamp + "-" + threads + "threads.txt");
        Files.createDirectories(archive.getParent());
        String text = String.join(System.lineSeparator(), report) + System.lineSeparator();
        Files.writeString(archive, text);
        Files.writeString(reportPath, text);
        Files.writeString(Path.of("docs/rsa-current-ciphertext.txt"), ciphertext + System.lineSeparator());
        report.forEach(System.out::println);
        System.out.println("Сохранены отчёты: " + reportPath + " и " + archive);
        assertTrue(System.nanoTime() - experimentStarted < Duration.ofSeconds(seconds + 20L).toNanos(),
                "Превышены " + seconds + " секунд замера и 20 секунд резерва");
    }

    private static void appendMeasurement(List<String> report, RsaFermatBenchmark.Measurement measurement) {
        report.add("Ферма: " + measurement.stopReason());
        report.add("Проверено кандидатов a: " + measurement.attempts());
        report.add("Извлечений квадратного корня: " + measurement.squareRoots());
        report.add("Кандидаты, отброшенные фильтром остатков: " + (measurement.attempts() - measurement.squareRoots()));
        report.add("Длительность Ферма: " + measurement.elapsed().toNanos() / 1_000_000_000.0 + " с");
        report.add("Скорость: " + measurement.attemptsPerSecond().map(RsaPublicKeyAttackTest::scientific).orElse("нет измерения") + " кандидатов/с");
        report.add("Активных рабочих потоков: " + measurement.workers().stream().filter(worker -> worker.attempts() > 0).count()
                + "/" + measurement.workers().size());
        report.add("Средняя занятость CPU рабочих потоков (в эквиваленте ядер): "
                + measurement.averageCpuCores().map(RsaPublicKeyAttackTest::scientific).orElse("JVM не предоставляет CPU-время"));
        for (var worker : measurement.workers()) {
            report.add("  Поток " + (worker.index() + 1) + ": кандидатов = " + worker.attempts()
                    + ", sqrt = " + worker.squareRoots() + ", CPU = "
                    + (worker.cpuTime().isNegative() ? "недоступно" : worker.cpuTime().toNanos() / 1_000_000_000.0 + " с"));
        }
        measurement.projectedBalancedRangeYears().ifPresent(years -> {
            report.add("УСЛОВНАЯ модель: p/q < 2 при p > q; a от ceil(sqrt(n)) до floor(sqrt(9n/8)).");
            report.add("Оставшийся полный диапазон этой модели: "
                    + scientific(new BigDecimal(measurement.remainingBalancedCandidates())) + " кандидатов.");
            report.add("Полный диапазон при постоянной измеренной скорости: " + scientific(years) + " лет.");
            report.add("Чувствительность к скорости x2 / x0.5: " + scientific(years.divide(BigDecimal.TWO))
                    + " — " + scientific(years.multiply(BigDecimal.TWO)) + " лет (НЕ доверительный интервал).");
            report.add("Это НЕ прогноз времени взлома: p и q неизвестны, ранний успех возможен на следующем шаге.");
            report.add("При дальнем продолжении стоимость шага меняется. GNFS и другие методы здесь не измерялись.");
            report.add("Скорость включает точное отбрасывание неквадратов фильтром; счётчик не равен числу sqrt.");
        });
        if (measurement.recoveredMessage().isPresent()) {
            report.add("Ферма восстановил исходное Hello World; ключ уязвим к этой атаке.");
        }
    }

    private static void appendSummary(List<String> report, RsaFermatBenchmark.Measurement measurement,
                                      double seconds, long guessNanos) {
        Locale locale = Locale.forLanguageTag("ru-RU");
        report.add("");
        report.add(String.format(locale, "Эксперимент завершился за %.2f секунды.", seconds));
        if (measurement != null) {
            report.add(String.format(locale, "Ферма проверил %,d кандидатов со скоростью около %,.0f в секунду; %s.",
                    measurement.attempts(), measurement.attemptsPerSecond().orElse(BigDecimal.ZERO),
                    measurement.recoveredMessage().isPresent() ? "сообщение восстановлено" : "сообщение не восстановлено"));
            measurement.projectedBalancedRangeYears().ifPresent(years -> report.add(
                    "Условная экстраполяция полного диапазона Ферма: " + scientific(years) + " лет; это не прогноз взлома."));
        }
        report.add(String.format(locale, "Проверка известного Hello World публичным ключом заняла %.2f мс: "
                + "подтверждение догадки о сообщении, а не восстановление приватного ключа.", guessNanos / 1_000_000.0));
        report.add("");
    }

    private static String scientific(BigDecimal number) {
        String formatted = number.round(new MathContext(4)).stripTrailingZeros().toString().replace('.', ',');
        int exponentIndex = formatted.indexOf('E');
        if (exponentIndex < 0) {
            return formatted;
        }
        String exponent = formatted.substring(exponentIndex + 1).replace("+", "");
        StringBuilder superscript = new StringBuilder();
        for (char digit : exponent.toCharArray()) {
            superscript.append(digit == '-' ? '⁻' : "⁰¹²³⁴⁵⁶⁷⁸⁹".charAt(digit - '0'));
        }
        return formatted.substring(0, exponentIndex) + " × 10" + superscript;
    }

    private static byte[] unsignedBytes(BigInteger number) {
        byte[] bytes = number.toByteArray();
        return bytes.length > 1 && bytes[0] == 0 ? java.util.Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
