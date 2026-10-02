package com.cryptography.rsa;

import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Duration;
import java.util.Optional;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class RsaFermatBenchmarkTest {

    @Test
    void recoversKnownCiphertextWithoutPrivateKey() {
        var key = new RsaHelper.RsaPublicKey(BigInteger.valueOf(17), BigInteger.valueOf(3599));
        var ciphertext = BigInteger.valueOf(65).modPow(key.e(), key.n());

        var result = RsaFermatBenchmark.measure(key, ciphertext, Duration.ofSeconds(1), 1);

        assertEquals(RsaFermatBenchmark.StopReason.RECOVERED, result.stopReason());
        assertEquals(1, result.attempts());
        assertEquals(BigInteger.valueOf(65), result.recoveredMessage().orElseThrow());
    }

    @Test
    void parallelSearchRecoversFactorsBeyondFirstBlock() {
        var keys = RsaHelper.generateKeyPair(BigInteger.valueOf(101), BigInteger.valueOf(10007));
        var ciphertext = RsaHelper.encrypt(BigInteger.valueOf(65), keys.publicKey());

        var result = RsaFermatBenchmark.measure(keys.publicKey(), ciphertext, Duration.ofSeconds(2), 4);

        assertEquals(RsaFermatBenchmark.StopReason.RECOVERED, result.stopReason());
        assertEquals(BigInteger.valueOf(65), result.recoveredMessage().orElseThrow());
        assertEquals(4, result.workers().size());
        assertTrue(result.attempts() > 256);
        assertTrue(result.squareRoots() < result.attempts());
    }

    @Test
    void parallelDeadlineStopsEveryWorkerAndRecordsActualWork() {
        BigInteger n = BigInteger.ONE.shiftLeft(1024).nextProbablePrime();
        var key = new RsaHelper.RsaPublicKey(BigInteger.valueOf(65537), n);

        var result = RsaFermatBenchmark.measure(key, BigInteger.TWO, Duration.ofMillis(300), 4);

        assertEquals(RsaFermatBenchmark.StopReason.TIME_LIMIT, result.stopReason());
        assertEquals(4, result.workers().stream().filter(worker -> worker.attempts() > 0).count());
        assertTrue(result.recoveredMessage().isEmpty());
        assertTrue(result.elapsed().compareTo(Duration.ofSeconds(3)) < 0);
        assertTrue(Thread.getAllStackTraces().keySet().stream()
                .noneMatch(thread -> thread.isAlive() && thread.getName().startsWith("rsa-fermat-")));
    }

    @Test
    void residueFilterNeverRejectsSquaresInOneCompletePeriod() {
        for (int i = 0; i < 4032; i++) {
            assertTrue(RsaFermatBenchmark.isSquareResidue(i * i % 4032));
        }
        assertFalse(RsaFermatBenchmark.isSquareResidue(2));
    }

    @Test
    void stopsAtMonotonicDeadlineAndCountsOnlyCompletedCandidates() {
        var key = new RsaHelper.RsaPublicKey(BigInteger.valueOf(17), BigInteger.valueOf(101909));
        var clock = new AtomicLong();

        var result = RsaFermatBenchmark.measure(key, BigInteger.TWO, Duration.ofNanos(4), clock::getAndIncrement);

        assertEquals(RsaFermatBenchmark.StopReason.TIME_LIMIT, result.stopReason());
        assertEquals(3, result.attempts());
        assertTrue(result.recoveredMessage().isEmpty());
    }

    @Test
    void respectsInterruptionWithoutStartingFactorization() {
        var key = new RsaHelper.RsaPublicKey(BigInteger.valueOf(17), BigInteger.valueOf(101909));
        Thread.currentThread().interrupt();
        try {
            var result = RsaFermatBenchmark.measure(key, BigInteger.TWO, Duration.ofSeconds(1));
            assertEquals(RsaFermatBenchmark.StopReason.INTERRUPTED, result.stopReason());
            assertEquals(0, result.attempts());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void acceptsFullThreeMinuteBudgetAndStopsEarlyAfterRecovery() {
        var key = new RsaHelper.RsaPublicKey(BigInteger.valueOf(17), BigInteger.valueOf(3599));
        var ciphertext = BigInteger.valueOf(65).modPow(key.e(), key.n());

        var result = RsaFermatBenchmark.measure(key, ciphertext, Duration.ofMinutes(3), 1);

        assertEquals(RsaFermatBenchmark.StopReason.RECOVERED, result.stopReason());
        assertEquals(BigInteger.valueOf(65), result.recoveredMessage().orElseThrow());
    }

    @Test
    void acceptsFiveMinuteBudgetAndHonorsItsDeadline() {
        var key = new RsaHelper.RsaPublicKey(BigInteger.valueOf(17), BigInteger.valueOf(101909));
        var clock = new AtomicLong();

        var result = RsaFermatBenchmark.measure(key, BigInteger.TWO, Duration.ofSeconds(300),
                () -> clock.getAndAdd(Duration.ofSeconds(100).toNanos()));

        assertEquals(RsaFermatBenchmark.StopReason.TIME_LIMIT, result.stopReason());
        assertEquals(2, result.attempts()); // Candidates at 100s and 200s; stop at 300s.
    }

    @Test
    void rejectsInvalidInputsAndBudgetsAboveOneHour() {
        var key = new RsaHelper.RsaPublicKey(BigInteger.valueOf(17), BigInteger.valueOf(3599));

        assertThrows(IllegalArgumentException.class,
                () -> RsaFermatBenchmark.measure(key, BigInteger.TWO, Duration.ofSeconds(3601)));
        assertThrows(IllegalArgumentException.class,
                () -> RsaFermatBenchmark.measure(key, BigInteger.TWO, Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> RsaFermatBenchmark.measure(key, key.n(), Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class,
                () -> RsaFermatBenchmark.measure(null, BigInteger.TWO, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class,
                () -> RsaFermatBenchmark.measure(key, BigInteger.TWO, Duration.ofSeconds(1), 0));
    }

    @Test
    void estimatesOnlyUnsearchedBalancedRangeUsingMeasuredRate() {
        // For n = 101 * 1009: ceil(sqrt(n)) = 320, floor(sqrt(9*n/8)) = 338.
        // This model assumes p/q < 2; these actual factors intentionally do not satisfy it.
        var result = measurement(BigInteger.valueOf(101909), 3, Duration.ofSeconds(1));

        assertEquals(BigInteger.valueOf(19), result.balancedRangeCandidates());
        assertEquals(BigInteger.valueOf(16), result.remainingBalancedCandidates());
        assertEquals(0, new BigDecimal("3").compareTo(result.attemptsPerSecond().orElseThrow()));
        BigDecimal expectedYears = new BigDecimal("16").divide(new BigDecimal("94672800"),
                java.math.MathContext.DECIMAL64);
        assertEquals(0, expectedYears.compareTo(result.projectedBalancedRangeYears().orElseThrow()));
    }

    @Test
    void handlesHugeModuliWithoutFloatingPointInfinityAndNoMeasurementsWithoutDivisionByZero() {
        BigInteger huge = BigInteger.ONE.shiftLeft(16383).add(BigInteger.ONE);
        var result = measurement(huge, 10, Duration.ofSeconds(1));

        assertTrue(result.projectedBalancedRangeYears().orElseThrow().compareTo(BigDecimal.ONE) > 0);
        var empty = measurement(huge, 0, Duration.ZERO);
        assertTrue(empty.attemptsPerSecond().isEmpty());
        assertTrue(empty.projectedBalancedRangeYears().isEmpty());
    }

    @Test
    void projectionSubtractsOnlyCandidatesInsideAssumedRange() {
        var worker = new RsaFermatBenchmark.WorkerMeasurement(0, 25, 3, 10, Duration.ofMillis(500));
        var measurement = new RsaFermatBenchmark.Measurement(BigInteger.valueOf(101909), Duration.ofSeconds(1),
                RsaFermatBenchmark.StopReason.TIME_LIMIT, Optional.empty(), List.of(worker));

        assertEquals(BigInteger.valueOf(9), measurement.remainingBalancedCandidates());
    }

    private static RsaFermatBenchmark.Measurement measurement(BigInteger modulus, long attempts, Duration elapsed) {
        var worker = new RsaFermatBenchmark.WorkerMeasurement(0, attempts, attempts, attempts, Duration.ZERO);
        return new RsaFermatBenchmark.Measurement(modulus, elapsed, RsaFermatBenchmark.StopReason.TIME_LIMIT,
                Optional.empty(), List.of(worker));
    }
}
