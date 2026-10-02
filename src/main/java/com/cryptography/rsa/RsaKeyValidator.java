package com.cryptography.rsa;

import com.cryptography.primality.MillerRabinTest;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

/**
 * Проверка параметров RSA перед сохранением ключа. Отбраковывает слабые ключи и объясняет причину.
 * <p>
 * Пороговые значения соответствуют требованиям NIST FIPS 186-5 (раздел A.1) к генерации ключей RSA:
 * <ul>
 *   <li>p и q — простые, различные и одинаковой битовой длины;</li>
 *   <li>|p − q| &gt; 2^(nlen/2 − 100) — иначе p и q слишком близки к √n;</li>
 *   <li>e нечетное, 2^16 &lt; e &lt; 2^256 и взаимно просто с φ(n);</li>
 *   <li>d &gt; 2^(nlen/2) — слишком маленькая секретная экспонента недопустима.</li>
 * </ul>
 * Дополнительно проверяются:
 * <ul>
 *   <li>p − 1 и q − 1 не состоят только из малых множителей (не являются «гладкими»);</li>
 *   <li>модуль n не имеет общих простых множителей с ранее созданными ключами.</li>
 * </ul>
 */
public final class RsaKeyValidator {

    /**
     * Граница для «малых» простых при проверке гладкости p − 1 и q − 1.
     */
    static final int SMOOTHNESS_BOUND = 100_000;

    private static final int PRIMALITY_ROUNDS = 10;
    private static final BigInteger MIN_PUBLIC_EXPONENT = BigInteger.TWO.pow(16);
    private static final BigInteger MAX_PUBLIC_EXPONENT = BigInteger.TWO.pow(256);
    private static final int[] SMALL_PRIMES = sieve(SMOOTHNESS_BOUND);

    private RsaKeyValidator() {
    }

    /**
     * Вид проверки.
     */
    public enum CheckType {
        PRIMALITY("p и q простые"),
        DISTINCT("p ≠ q"),
        BALANCED("p и q одинаковой длины"),
        DISTANCE("p и q не слишком близки"),
        PUBLIC_EXPONENT("открытая экспонента e"),
        PRIVATE_EXPONENT("размер секретной экспоненты d"),
        SMOOTHNESS("p − 1 и q − 1 не гладкие"),
        SHARED_FACTOR("нет общих множителей с другими ключами");

        private final String title;

        CheckType(String title) {
            this.title = title;
        }

        public String title() {
            return title;
        }
    }

    /**
     * Результат одной проверки. Поле details не содержит значений p, q и d.
     */
    public record Check(CheckType type, boolean passed, String details) {
    }

    /**
     * Результат всех проверок.
     */
    public record Report(List<Check> checks) {
        public boolean isValid() {
            return checks.stream().allMatch(Check::passed);
        }

        public List<Check> failures() {
            return checks.stream().filter(c -> !c.passed()).toList();
        }

        public Check check(CheckType type) {
            return checks.stream().filter(c -> c.type() == type).findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("Проверка " + type + " не выполнялась"));
        }
    }

    /**
     * Проверяет параметры ключа без сравнения с другими ключами.
     */
    public static Report validate(BigInteger p, BigInteger q, BigInteger e) {
        return validate(p, q, e, List.of());
    }

    /**
     * Проверяет параметры ключа.
     *
     * @param p              первое простое число
     * @param q              второе простое число
     * @param e              открытая экспонента
     * @param existingModuli модули ранее созданных ключей (для проверки общих множителей)
     * @return отчет со всеми проверками
     */
    public static Report validate(BigInteger p, BigInteger q, BigInteger e, Collection<BigInteger> existingModuli) {
        if (p == null || q == null || e == null || existingModuli == null) {
            throw new IllegalArgumentException("Параметры p, q, e и existingModuli не должны быть null");
        }
        List<Check> checks = new ArrayList<>();
        BigInteger n = p.multiply(q);
        int nlen = n.bitLength();

        boolean primes = p.compareTo(BigInteger.ONE) > 0 && q.compareTo(BigInteger.ONE) > 0
                && MillerRabinTest.isProbablePrime(p, PRIMALITY_ROUNDS)
                && MillerRabinTest.isProbablePrime(q, PRIMALITY_ROUNDS);
        checks.add(new Check(CheckType.PRIMALITY, primes,
                primes ? "оба числа прошли тест Миллера — Рабина (" + PRIMALITY_ROUNDS + " раундов)"
                        : "хотя бы одно из чисел составное"));

        boolean distinct = !p.equals(q);
        checks.add(new Check(CheckType.DISTINCT, distinct,
                distinct ? "числа различны" : "p = q, тогда n = p² и √n сразу дает p"));

        boolean balanced = p.bitLength() == q.bitLength();
        checks.add(new Check(CheckType.BALANCED, balanced,
                "длины p и q: " + p.bitLength() + " и " + q.bitLength() + " бит"));

        checks.add(checkDistance(p, q, nlen));
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        checks.add(checkPublicExponent(e, phi));
        checks.add(checkPrivateExponent(e, phi, nlen));
        checks.add(checkSmoothness(p, q));
        checks.add(checkSharedFactors(n, existingModuli));
        return new Report(List.copyOf(checks));
    }

    private static Check checkDistance(BigInteger p, BigInteger q, int nlen) {
        int thresholdBits = Math.max(0, nlen / 2 - 100);
        int distanceBits = p.subtract(q).abs().bitLength();
        boolean passed = p.subtract(q).abs().compareTo(BigInteger.TWO.pow(thresholdBits)) > 0;
        return new Check(CheckType.DISTANCE, passed,
                "|p − q| ≈ 2^" + distanceBits + ", требуется больше 2^" + thresholdBits);
    }

    private static Check checkPublicExponent(BigInteger e, BigInteger phi) {
        if (!e.testBit(0)) {
            return new Check(CheckType.PUBLIC_EXPONENT, false, "e четное");
        }
        if (e.compareTo(MIN_PUBLIC_EXPONENT) <= 0) {
            return new Check(CheckType.PUBLIC_EXPONENT, false, "e = " + e + " не больше 2^16");
        }
        if (e.compareTo(MAX_PUBLIC_EXPONENT) >= 0) {
            return new Check(CheckType.PUBLIC_EXPONENT, false, "e длиной " + e.bitLength() + " бит не меньше 2^256");
        }
        if (phi.signum() <= 0 || !e.gcd(phi).equals(BigInteger.ONE)) {
            return new Check(CheckType.PUBLIC_EXPONENT, false, "e не взаимно просто с φ(n), ключ построить нельзя");
        }
        return new Check(CheckType.PUBLIC_EXPONENT, true, "e = " + e + " (" + e.bitLength() + " бит)");
    }

    private static Check checkPrivateExponent(BigInteger e, BigInteger phi, int nlen) {
        if (phi.signum() <= 0 || !e.gcd(phi).equals(BigInteger.ONE)) {
            return new Check(CheckType.PRIVATE_EXPONENT, false, "d не существует: e не взаимно просто с φ(n)");
        }
        // d вычисляется так же, как в RsaHelper.generateKeyPair
        BigInteger d = e.modInverse(phi);
        int thresholdBits = nlen / 2;
        boolean passed = d.compareTo(BigInteger.TWO.pow(thresholdBits)) > 0;
        return new Check(CheckType.PRIVATE_EXPONENT, passed,
                "длина d: " + d.bitLength() + " бит, требуется больше " + thresholdBits);
    }

    private static Check checkSmoothness(BigInteger p, BigInteger q) {
        int pRough = roughPartBits(p.subtract(BigInteger.ONE));
        int qRough = roughPartBits(q.subtract(BigInteger.ONE));
        // После удаления всех простых множителей меньше границы должна остаться хотя бы половина битов
        boolean passed = pRough * 2 >= p.bitLength() && qRough * 2 >= q.bitLength();
        return new Check(CheckType.SMOOTHNESS, passed,
                "после удаления множителей < " + SMOOTHNESS_BOUND + " остается: у p − 1 " + pRough
                        + " бит из " + p.bitLength() + ", у q − 1 " + qRough + " бит из " + q.bitLength());
    }

    private static Check checkSharedFactors(BigInteger n, Collection<BigInteger> existingModuli) {
        int conflicts = 0;
        for (BigInteger other : existingModuli) {
            if (!n.gcd(other).equals(BigInteger.ONE)) {
                conflicts++;
            }
        }
        return new Check(CheckType.SHARED_FACTOR, conflicts == 0,
                conflicts == 0
                        ? "проверено ключей: " + existingModuli.size()
                        : "общий множитель найден с " + conflicts + " из " + existingModuli.size() + " ключей");
    }

    /**
     * Битовая длина части числа, которая остается после удаления всех простых множителей меньше границы.
     */
    private static int roughPartBits(BigInteger value) {
        if (value.signum() <= 0) {
            return 0;
        }
        BigInteger rest = value;
        for (int prime : SMALL_PRIMES) {
            BigInteger divisor = BigInteger.valueOf(prime);
            BigInteger[] qr = rest.divideAndRemainder(divisor);
            while (qr[1].signum() == 0) {
                rest = qr[0];
                qr = rest.divideAndRemainder(divisor);
            }
        }
        return rest.equals(BigInteger.ONE) ? 0 : rest.bitLength();
    }

    /**
     * Загружает модули n всех открытых ключей из папки (для проверки общих множителей).
     * Если папки нет, возвращает пустой список.
     */
    public static List<BigInteger> loadExistingModuli(Path keysDirectory) throws IOException {
        if (!Files.isDirectory(keysDirectory)) {
            return List.of();
        }
        List<BigInteger> moduli = new ArrayList<>();
        try (Stream<Path> files = Files.list(keysDirectory)) {
            for (Path file : files.filter(f -> f.getFileName().toString().endsWith("_public.key")).toList()) {
                moduli.add(RsaHelper.loadPublicKey(file).n());
            }
        }
        return moduli;
    }

    private static int[] sieve(int bound) {
        boolean[] composite = new boolean[bound];
        List<Integer> primes = new ArrayList<>();
        for (int i = 2; i < bound; i++) {
            if (!composite[i]) {
                primes.add(i);
                for (long j = (long) i * i; j < bound; j += i) {
                    composite[(int) j] = true;
                }
            }
        }
        return primes.stream().mapToInt(Integer::intValue).toArray();
    }
}
