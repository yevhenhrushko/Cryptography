package com.cryptography.rsa;

import com.cryptography.generator.PrimeCandidateGenerator;
import com.cryptography.primality.MillerRabinTest;
import com.cryptography.rsa.RsaKeyValidator.CheckType;
import com.cryptography.rsa.RsaKeyValidator.Report;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

class RsaKeyValidatorTest {

    private static final BigInteger E = RsaHelper.PROJECT_PUBLIC_EXPONENT;
    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    @DisplayName("Случайно сгенерированный ключ проходит все проверки")
    void testRandomKeyIsValid() {
        // e = 6553765537 = 11 * 9091 * 65537 составное, поэтому у ~19% случайных пар 11 | φ(n)
        // и ключ построить нельзя. В Main такой ключ просто перегенерируется; здесь подбираем валидную пару.
        BigInteger p = randomPrime(1024);
        BigInteger q = coprimePrime(p, 1024, E);
        List<BigInteger> others = List.of(randomPrime(512).multiply(randomPrime(512)));

        Report report = RsaKeyValidator.validate(p, q, E, others);

        assertTrue(report.isValid(), () -> "Неожиданные ошибки: " + report.failures());
        assertEquals(CheckType.values().length, report.checks().size());
    }

    /**
     * Подбирает простое q (длиной bits), для которого gcd(e, (p-1)(q-1)) = 1, то есть ключ с e строится.
     */
    private static BigInteger coprimePrime(BigInteger p, int bits, BigInteger e) {
        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        while (true) {
            BigInteger q = randomPrime(bits);
            BigInteger phi = pMinus1.multiply(q.subtract(BigInteger.ONE));
            if (!q.equals(p) && e.gcd(phi).equals(BigInteger.ONE)) {
                return q;
            }
        }
    }

    @Test
    @DisplayName("Пояснения в отчете не содержат значений p и q")
    void testReportDoesNotLeakPrimes() {
        BigInteger p = randomPrime(512);
        BigInteger q = randomPrime(512);

        Report report = RsaKeyValidator.validate(p, q, E);

        for (RsaKeyValidator.Check check : report.checks()) {
            assertFalse(check.details().contains(p.toString()), check.type() + " раскрывает p");
            assertFalse(check.details().contains(q.toString()), check.type() + " раскрывает q");
        }
    }

    @Test
    @DisplayName("Составное число вместо p отбраковывается")
    void testCompositeIsRejected() {
        BigInteger composite = randomPrime(256).multiply(randomPrime(256));
        Report report = RsaKeyValidator.validate(composite, randomPrime(512), E);
        assertFailed(report, CheckType.PRIMALITY);
    }

    @Test
    @DisplayName("Одинаковые p и q отбраковываются")
    void testEqualPrimesAreRejected() {
        BigInteger p = randomPrime(512);
        Report report = RsaKeyValidator.validate(p, p, E);
        assertFailed(report, CheckType.DISTINCT);
    }

    @Test
    @DisplayName("p и q разной длины отбраковываются")
    void testUnbalancedPrimesAreRejected() {
        Report report = RsaKeyValidator.validate(randomPrime(512), randomPrime(520), E);
        assertFailed(report, CheckType.BALANCED);
    }

    @Test
    @DisplayName("Соседние простые числа (|p − q| мало) отбраковываются")
    void testClosePrimesAreRejected() {
        BigInteger q = randomPrime(512);
        BigInteger p = q.nextProbablePrime();

        Report report = RsaKeyValidator.validate(p, q, E);

        assertFailed(report, CheckType.DISTANCE);
        assertTrue(report.check(CheckType.BALANCED).passed());
    }

    @Test
    @DisplayName("Недопустимая открытая экспонента отбраковывается: мала, четна или слишком велика")
    void testBadPublicExponentIsRejected() {
        BigInteger p = randomPrime(512);
        BigInteger q = coprimePrime(p, 512, RsaHelper.DEFAULT_PUBLIC_EXPONENT);

        assertFailed(RsaKeyValidator.validate(p, q, BigInteger.valueOf(3)), CheckType.PUBLIC_EXPONENT);
        assertFailed(RsaKeyValidator.validate(p, q, BigInteger.valueOf(65536 * 2)), CheckType.PUBLIC_EXPONENT);
        assertFailed(RsaKeyValidator.validate(p, q, BigInteger.TWO.pow(300).add(BigInteger.ONE)),
                CheckType.PUBLIC_EXPONENT);
        assertTrue(RsaKeyValidator.validate(p, q, RsaHelper.DEFAULT_PUBLIC_EXPONENT).isValid());
    }

    @Test
    @DisplayName("Слишком маленькая секретная экспонента d отбраковывается")
    void testSmallPrivateExponentIsRejected() {
        BigInteger p = randomPrime(512);
        BigInteger q = randomPrime(512);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Выбираем маленькое d и вычисляем по нему e — так получаются ключи с опасно малым d
        BigInteger smallD = BigInteger.valueOf(1_000_003);
        while (!smallD.gcd(phi).equals(BigInteger.ONE)) {
            smallD = smallD.nextProbablePrime();
        }
        BigInteger e = smallD.modInverse(phi);

        Report report = RsaKeyValidator.validate(p, q, e);

        assertFailed(report, CheckType.PRIVATE_EXPONENT);
    }

    @Test
    @DisplayName("Простое p, у которого p − 1 состоит только из малых множителей, отбраковывается")
    void testSmoothPrimeIsRejected() {
        BigInteger smooth = smoothPrime(512);
        BigInteger q = randomPrime(512);

        Report report = RsaKeyValidator.validate(smooth, q, E);

        assertTrue(report.check(CheckType.PRIMALITY).passed());
        assertFailed(report, CheckType.SMOOTHNESS);
    }

    @Test
    @DisplayName("Ключ с общим простым множителем с ранее созданным ключом отбраковывается")
    void testSharedFactorIsRejected() {
        BigInteger p = randomPrime(512);
        BigInteger q = randomPrime(512);
        BigInteger otherModulus = p.multiply(randomPrime(512));

        Report report = RsaKeyValidator.validate(p, q, E, List.of(otherModulus));

        assertFailed(report, CheckType.SHARED_FACTOR);
    }

    @Test
    @DisplayName("Модули ранее созданных ключей загружаются из папки; отсутствующая папка дает пустой список")
    void testLoadExistingModuli(@TempDir Path tempDir) throws IOException {
        assertEquals(List.of(), RsaKeyValidator.loadExistingModuli(tempDir.resolve("missing")));

        RsaHelper.SavedRsaKeyPair first = RsaHelper.createAndSaveTimestampedKeys(
                BigInteger.valueOf(61), BigInteger.valueOf(53), BigInteger.valueOf(17), tempDir);
        RsaHelper.SavedRsaKeyPair second = RsaHelper.createAndSaveTimestampedKeys(
                BigInteger.valueOf(67), BigInteger.valueOf(71), BigInteger.valueOf(17), tempDir);

        List<BigInteger> moduli = RsaKeyValidator.loadExistingModuli(tempDir);

        assertEquals(2, moduli.size());
        assertTrue(moduli.contains(first.publicKey().n()));
        assertTrue(moduli.contains(second.publicKey().n()));
    }

    /**
     * Проверяет, что указанная проверка не прошла.
     */
    private static void assertFailed(Report report, CheckType type) {
        assertFalse(report.isValid(), "Ключ должен быть отбракован");
        assertFalse(report.check(type).passed(),
                () -> "Ожидался отказ проверки " + type + ", отчет: " + report.checks());
    }

    /**
     * Строит простое p заданной длины, у которого p − 1 = 2 · (произведение простых меньше 1000).
     */
    private static BigInteger smoothPrime(int bits) {
        int[] smallPrimes = IntStream.range(3, 1000).filter(i -> BigInteger.valueOf(i).isProbablePrime(30)).toArray();
        while (true) {
            // Каждый множитель меньше 2^10, поэтому m не превысит bits − 1 бит; добиваем длину степенями двойки
            BigInteger m = BigInteger.TWO;
            while (m.bitLength() < bits - 10) {
                m = m.multiply(BigInteger.valueOf(smallPrimes[RANDOM.nextInt(smallPrimes.length)]));
            }
            while (m.bitLength() < bits) {
                m = m.multiply(BigInteger.TWO);
            }
            BigInteger candidate = m.add(BigInteger.ONE);
            if (MillerRabinTest.isProbablePrime(candidate, 10)) {
                return candidate;
            }
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
