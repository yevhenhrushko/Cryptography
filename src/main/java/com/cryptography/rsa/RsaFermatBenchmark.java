package com.cryptography.rsa;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.TWO;

/** Замер ограниченного поиска Ферма. Экстраполяция этого поиска не оценивает стойкость RSA в целом. */
public final class RsaFermatBenchmark {

    public static final Duration DEFAULT_DURATION = Duration.ofMinutes(3);
    public static final Duration MAX_DURATION = Duration.ofHours(1);

    public enum StopReason {
        RECOVERED, TIME_LIMIT, INTERRUPTED, UNSUPPORTED_FACTORIZATION
    }

    /** cpuTime отрицательно, если JVM не предоставляет CPU-время потока. */
    public record WorkerMeasurement(int index, long attempts, long squareRoots, long balancedAttempts,
                                    Duration cpuTime) {
    }

    public record Measurement(BigInteger modulus, Duration elapsed, StopReason stopReason,
                              Optional<BigInteger> recoveredMessage, List<WorkerMeasurement> workers) {
        public Measurement {
            workers = List.copyOf(workers);
        }

        public long attempts() {
            return workers.stream().mapToLong(WorkerMeasurement::attempts).sum();
        }

        public long squareRoots() {
            return workers.stream().mapToLong(WorkerMeasurement::squareRoots).sum();
        }

        /** Сумма CPU-времени рабочих потоков / общее wall time: фактическая средняя занятость ядер. */
        public Optional<BigDecimal> averageCpuCores() {
            if (elapsed.isZero() || workers.isEmpty() || workers.stream().anyMatch(worker -> worker.cpuTime().isNegative())) {
                return Optional.empty();
            }
            long cpuNanos = workers.stream().mapToLong(worker -> worker.cpuTime().toNanos()).sum();
            return Optional.of(BigDecimal.valueOf(cpuNanos)
                    .divide(BigDecimal.valueOf(elapsed.toNanos()), MathContext.DECIMAL64));
        }

        public Optional<BigDecimal> attemptsPerSecond() {
            if (attempts() == 0 || elapsed.isZero()) {
                return Optional.empty();
            }
            return Optional.of(BigDecimal.valueOf(attempts()).multiply(BILLION)
                    .divide(BigDecimal.valueOf(elapsed.toNanos()), MathContext.DECIMAL64));
        }

        /**
         * Верхняя граница размера диапазона Ферма ПРИ УСЛОВИИ 1 < p/q < 2 (p > q).
         * Тогда (p+q)/2 <= sqrt(9n/8). Близость настоящих множителей по n не установлена.
         */
        public BigInteger balancedRangeCandidates() {
            BigInteger lastA = modulus.multiply(BigInteger.valueOf(9)).divide(BigInteger.valueOf(8)).sqrt();
            return lastA.subtract(ceilSqrt(modulus)).add(ONE).max(BigInteger.ZERO);
        }

        public BigInteger remainingBalancedCandidates() {
            long checked = workers.stream().mapToLong(WorkerMeasurement::balancedAttempts).sum();
            return balancedRangeCandidates().subtract(BigInteger.valueOf(checked)).max(BigInteger.ZERO);
        }

        /**
         * Условные годы для оставшегося полного диапазона, при постоянной измеренной скорости.
         * Это не среднее время нахождения множителей, не доверительный интервал и не оценка GNFS.
         */
        public Optional<BigDecimal> projectedBalancedRangeYears() {
            if (attempts() == 0 || elapsed.isZero() || stopReason != StopReason.TIME_LIMIT) {
                return Optional.empty();
            }
            BigDecimal elapsedSeconds = BigDecimal.valueOf(elapsed.toNanos(), 9);
            BigDecimal denominator = BigDecimal.valueOf(attempts()).multiply(SECONDS_PER_YEAR);
            return Optional.of(new BigDecimal(remainingBalancedCandidates()).multiply(elapsedSeconds)
                    .divide(denominator, MathContext.DECIMAL64));
        }
    }

    private static final BigDecimal BILLION = new BigDecimal("1000000000");
    private static final BigDecimal SECONDS_PER_YEAR = new BigDecimal("31557600");
    private static final int BLOCK_SIZE = 256;
    // 4032 = 64 * 63: квадрат по этому модулю необходим для целого квадратного корня.
    private static final int RESIDUE_MODULUS = 4032;
    private static final boolean[] SQUARE_RESIDUES = squareResidues();
    private static final ThreadMXBean THREAD_BEAN = ManagementFactory.getThreadMXBean();

    private RsaFermatBenchmark() {
    }

    /**
     * Измеряет Ферма на открытых данных всеми доступными JVM процессорами.
     * Потоки динамически забирают непересекающиеся блоки кандидатов; фильтр остатков сокращает sqrt.
     * Проверяет монотонные часы перед каждым кандидатом
     * и завершает поиск по лимиту или interrupt. Одна операция BigInteger неделима;
     * вызывающий процесс может дополнительно ограничить полное время выполнения.
     * @param budget положительная длительность не более одного часа
     * @throws IllegalArgumentException при недопустимых параметрах RSA, шифротексте или времени
     */
    public static Measurement measure(RsaHelper.RsaPublicKey key, BigInteger ciphertext, Duration budget) {
        return measure(key, ciphertext, budget, Runtime.getRuntime().availableProcessors());
    }

    /** Явное число рабочих потоков (1..256), например 1 для сравнения с параллельным запуском. */
    public static Measurement measure(RsaHelper.RsaPublicKey key, BigInteger ciphertext, Duration budget, int threads) {
        validate(key, ciphertext, budget);
        if (threads < 1 || threads > 256) {
            throw new IllegalArgumentException("Количество потоков должно быть от 1 до 256");
        }
        var search = new Search(key, ciphertext, budget, System::nanoTime);
        if (Thread.currentThread().isInterrupted()) {
            return search.result(List.of(), StopReason.INTERRUPTED);
        }
        if (threads == 1) {
            return search.result(List.of(search.worker(0)), null);
        }
        var threadNumber = new AtomicLong();
        var executor = Executors.newFixedThreadPool(threads, runnable -> {
            Thread thread = new Thread(runnable, "rsa-fermat-" + threadNumber.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });
        var futures = new ArrayList<Future<WorkerMeasurement>>();
        try {
            for (int i = 0; i < threads; i++) {
                final int index = i;
                futures.add(executor.submit(() -> search.worker(index)));
            }
            var results = new ArrayList<WorkerMeasurement>();
            for (var future : futures) {
                results.add(future.get());
            }
            return search.result(results, null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Измерение Ферма прервано", e);
        } catch (ExecutionException e) {
            throw new IllegalStateException("Рабочий поток Ферма завершился с ошибкой", e.getCause());
        } finally {
            search.cancelled.set(true);
            executor.shutdownNow();
            boolean interrupted = Thread.interrupted();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Рабочие потоки Ферма не завершились за резервные 5 секунд");
                }
            } catch (InterruptedException e) {
                interrupted = true;
            } finally {
                if (interrupted) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    static Measurement measure(RsaHelper.RsaPublicKey key, BigInteger ciphertext, Duration budget, LongSupplier clock) {
        validate(key, ciphertext, budget);
        var search = new Search(key, ciphertext, budget, clock);
        return search.result(List.of(search.worker(0)), Thread.currentThread().isInterrupted() ? StopReason.INTERRUPTED : null);
    }

    static boolean isSquareResidue(int residue) {
        return SQUARE_RESIDUES[residue];
    }

    private record Found(StopReason reason, Optional<BigInteger> message) {
    }

    private static final class Search {
        private final RsaHelper.RsaPublicKey key;
        private final BigInteger ciphertext;
        private final LongSupplier clock;
        private final long started;
        private final long budgetNanos;
        private final BigInteger firstA;
        private final BigInteger lastBalancedA;
        private final AtomicLong nextBlock = new AtomicLong();
        private final AtomicReference<Found> found = new AtomicReference<>();
        private final AtomicBoolean cancelled = new AtomicBoolean();

        private Search(RsaHelper.RsaPublicKey key, BigInteger ciphertext, Duration budget, LongSupplier clock) {
            this.key = key;
            this.ciphertext = ciphertext;
            this.clock = clock;
            this.started = clock.getAsLong();
            this.budgetNanos = budget.toNanos();
            this.firstA = ceilSqrt(key.n());
            this.lastBalancedA = key.n().multiply(BigInteger.valueOf(9)).divide(BigInteger.valueOf(8)).sqrt();
        }

        private WorkerMeasurement worker(int index) {
            long cpuStarted = currentCpuNanos();
            long attempts = 0;
            long squareRoots = 0;
            long balancedAttempts = 0;
            search:
            while (!cancelled.get() && found.get() == null && !Thread.currentThread().isInterrupted()) {
                long block = nextBlock.getAndIncrement();
                BigInteger a = firstA.add(BigInteger.valueOf(block).multiply(BigInteger.valueOf(BLOCK_SIZE)));
                BigInteger difference = a.multiply(a).subtract(key.n());
                int aResidue = a.mod(BigInteger.valueOf(RESIDUE_MODULUS)).intValue();
                int residue = difference.mod(BigInteger.valueOf(RESIDUE_MODULUS)).intValue();
                for (int offset = 0; offset < BLOCK_SIZE; offset++) {
                    if (cancelled.get() || found.get() != null || Thread.currentThread().isInterrupted()
                            || clock.getAsLong() - started >= budgetNanos) {
                        break search;
                    }
                    attempts++;
                    if (a.compareTo(lastBalancedA) <= 0) {
                        balancedAttempts++;
                    }
                    if (isSquareResidue(residue)) {
                        squareRoots++;
                        BigInteger b = difference.sqrt();
                        if (b.multiply(b).equals(difference)) {
                            var message = recover(key, ciphertext, a.subtract(b), a.add(b));
                            found.compareAndSet(null, new Found(message.isPresent()
                                    ? StopReason.RECOVERED : StopReason.UNSUPPORTED_FACTORIZATION, message));
                            break search;
                        }
                    }
                    residue = (residue + 2 * aResidue + 1) % RESIDUE_MODULUS;
                    aResidue = (aResidue + 1) % RESIDUE_MODULUS;
                    difference = difference.add(a.shiftLeft(1)).add(ONE);
                    a = a.add(ONE);
                }
            }
            long cpuEnd = currentCpuNanos();
            return new WorkerMeasurement(index, attempts, squareRoots, balancedAttempts,
                    Duration.ofNanos(cpuStarted < 0 || cpuEnd < 0 ? -1 : cpuEnd - cpuStarted));
        }

        private Measurement result(List<WorkerMeasurement> workers, StopReason override) {
            Found success = found.get();
            StopReason reason = override != null ? override : success == null ? StopReason.TIME_LIMIT : success.reason();
            return new Measurement(key.n(), Duration.ofNanos(clock.getAsLong() - started), reason,
                    success == null ? Optional.empty() : success.message(), workers);
        }
    }

    private static boolean[] squareResidues() {
        boolean[] residues = new boolean[RESIDUE_MODULUS];
        for (int i = 0; i < RESIDUE_MODULUS; i++) {
            residues[i * i % RESIDUE_MODULUS] = true;
        }
        return residues;
    }

    private static long currentCpuNanos() {
        return THREAD_BEAN.isCurrentThreadCpuTimeSupported() && THREAD_BEAN.isThreadCpuTimeEnabled()
                ? THREAD_BEAN.getCurrentThreadCpuTime() : -1;
    }

    private static Optional<BigInteger> recover(RsaHelper.RsaPublicKey key, BigInteger ciphertext,
                                               BigInteger p, BigInteger q) {
        if (p.equals(q) || !p.isProbablePrime(80) || !q.isProbablePrime(80)) {
            return Optional.empty();
        }
        BigInteger phi = p.subtract(ONE).multiply(q.subtract(ONE));
        if (!key.e().gcd(phi).equals(ONE)) {
            return Optional.empty();
        }
        BigInteger message = ciphertext.modPow(key.e().modInverse(phi), key.n());
        return message.modPow(key.e(), key.n()).equals(ciphertext) ? Optional.of(message) : Optional.empty();
    }

    private static BigInteger ceilSqrt(BigInteger n) {
        BigInteger root = n.sqrt();
        return root.multiply(root).equals(n) ? root : root.add(ONE);
    }

    private static void validate(RsaHelper.RsaPublicKey key, BigInteger ciphertext, Duration budget) {
        if (key == null || key.n() == null || key.e() == null || key.n().compareTo(BigInteger.valueOf(3)) <= 0
                || !key.n().testBit(0) || key.e().compareTo(TWO) < 0 || !key.e().testBit(0)
                || key.e().compareTo(key.n()) >= 0 || ciphertext == null || ciphertext.signum() < 0
                || ciphertext.compareTo(key.n()) >= 0) {
            throw new IllegalArgumentException("Нужны нечетный n > 3, нечетная 1 < e < n и 0 <= c < n");
        }
        if (budget == null || budget.isNegative() || budget.isZero() || budget.compareTo(MAX_DURATION) > 0) {
            throw new IllegalArgumentException("Время поиска должно быть положительным и не превышать "
                    + MAX_DURATION.toSeconds() + " секунд");
        }
    }
}
