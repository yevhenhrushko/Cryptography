package com.cryptography.rsa;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.TWO;
import static java.math.BigInteger.ZERO;

/**
 * Учебные атаки на textbook RSA (без padding). Методы атак принимают только открытые данные.
 * Пустой результат означает, что конкретный метод не восстановил сообщение, а не безопасность ключа.
 * Для всех атак нужны n > 3 (нечетное), нечетное 1 < e < n и 0 <= c < n.
 * Некорректные входные данные отклоняются с IllegalArgumentException.
 */
public final class RsaAttackHelper {

    public enum AttackType {
        FERMAT, SHARED_PRIME, LOW_EXPONENT, HASTAD, WIENER,
        POLLARD_P_MINUS_ONE, COMMON_MODULUS, FRANKLIN_REITER
    }

    /** Восстановленное число m и вычисленные шаги; исходного сообщения у атак нет. */
    public record AttackResult(AttackType type, Optional<BigInteger> recoveredMessage, List<String> steps) {
        public AttackResult {
            steps = List.copyOf(steps);
        }
    }

    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FOUR = BigInteger.valueOf(4);
    private static final int TRACE_LIMIT = 8;

    private RsaAttackHelper() {
    }

    /**
     * Проверяет шифрование/расшифрование заданной непустой строки своей парой ключей в памяти,
     * затем запускает Ферма, малую e и Винера на открытой части и шифротексте.
     * Для sharedPrime/hastad нужны дополнительные открытые ключи, поэтому они вызываются отдельно.
     * Контроль строки не является полной валидацией RSA-ключа. Файлы не читаются и не создаются.
     * @throws IllegalArgumentException если строка не помещается в n, контроль не совпал,
     *                                  параметры ключей некорректны или maxFermatIterations <= 0
     */
    public static List<AttackResult> checkKeyPair(String message, RsaHelper.RsaKeyPair keys,
                                                int maxFermatIterations) {
        if (message == null || message.isEmpty() || keys == null || keys.privateKey() == null) {
            throw new IllegalArgumentException("Нужны непустое сообщение и пара ключей в памяти");
        }
        validatePublicKey(keys.publicKey());
        var privateKey = keys.privateKey();
        if (!keys.publicKey().n().equals(privateKey.n()) || privateKey.d() == null || privateKey.d().signum() <= 0) {
            throw new IllegalArgumentException("Проверьте модуль и закрытую экспоненту пары ключей");
        }
        if (maxFermatIterations <= 0) {
            throw new IllegalArgumentException("Лимит Ферма должен быть положительным");
        }
        BigInteger ciphertext = RsaHelper.encryptText(message, keys.publicKey());
        // Контроль зависит только от d и n, необязательные CRT-поля здесь не используются.
        var controlKey = new RsaHelper.RsaPrivateKey(privateKey.d(), privateKey.n());
        if (!message.equals(RsaHelper.decryptText(ciphertext, controlKey))) {
            throw new IllegalArgumentException("Контрольное расшифрование не совпало с исходной строкой");
        }
        return List.of(fermat(keys.publicKey(), ciphertext, maxFermatIterations),
                lowExponent(keys.publicKey(), ciphertext), wiener(keys.publicKey(), ciphertext));
    }

    /**
     * Ферма: n = a² - b² = (a-b)(a+b). Быстро работает для близких p и q.
     * @param maxIterations максимальное число проверяемых a, начиная с ceil(sqrt(n)); строго > 0
     */
    public static AttackResult fermat(RsaHelper.RsaPublicKey key, BigInteger ciphertext, int maxIterations) {
        validateCiphertext(key, ciphertext);
        if (maxIterations <= 0) {
            throw new IllegalArgumentException("Лимит Ферма должен быть положительным");
        }
        var steps = new ArrayList<String>();
        BigInteger a = key.n().sqrt();
        if (a.multiply(a).compareTo(key.n()) < 0) {
            a = a.add(ONE);
        }
        steps.add("Ищем n = a² - b²; начинаем с a = ceil(sqrt(n)) = " + a);
        for (int iteration = 0; iteration < maxIterations; iteration++, a = a.add(ONE)) {
            BigInteger bSquared = a.multiply(a).subtract(key.n());
            BigInteger b = bSquared.sqrt();
            if (iteration < TRACE_LIMIT) {
                steps.add("a = " + a + ", a² - n = " + bSquared);
            }
            if (b.multiply(b).equals(bSquared)) {
                steps.add("Квадрат найден на проверке " + (iteration + 1) + ": b = " + b);
                return recoverFromFactors(AttackType.FERMAT, key, ciphertext, a.subtract(b), a.add(b), steps);
            }
        }
        steps.add("Лимит исчерпан: проверено " + maxIterations + " значений a. Это не доказательство стойкости.");
        return failure(AttackType.FERMAT, steps);
    }

    /** Общий простой множитель: gcd(n1, n2) раскрывает p, если 1 < gcd < n1. */
    public static AttackResult sharedPrime(RsaHelper.RsaPublicKey key, BigInteger ciphertext,
                                           RsaHelper.RsaPublicKey otherKey) {
        validateCiphertext(key, ciphertext);
        validatePublicKey(otherKey);
        BigInteger factor = key.n().gcd(otherKey.n());
        var steps = new ArrayList<String>();
        steps.add("n2 = " + otherKey.n());
        steps.add("gcd(n1, n2) = " + factor);
        if (factor.equals(ONE) || factor.equals(key.n())) {
            steps.add("Нетривиальный множитель n1 не найден; одинаковые модули не дают факторизацию этим методом.");
            return failure(AttackType.SHARED_PRIME, steps);
        }
        return recoverFromFactors(AttackType.SHARED_PRIME, key, ciphertext,
                factor, key.n().divide(factor), steps);
    }

    /**
     * Поллард p−1: один проход с основанием 2, простыми r <= bound и степенями r^k <= n
     * (HAC, алгоритм 3.14). Проверяем gcd после каждого шага, не строя общий показатель Q.
     * Если p−1 делит Q, а 2^Q != 1 mod q, то gcd(2^Q−1,n) раскрывает p.
     * @param bound граница малых простых от 2 до 100000; не лимит времени
     */
    public static AttackResult pollardPMinusOne(RsaHelper.RsaPublicKey key, BigInteger ciphertext, int bound) {
        validateCiphertext(key, ciphertext);
        if (bound < 2 || bound > 100_000) {
            throw new IllegalArgumentException("Граница Полларда должна быть от 2 до 100000");
        }
        var steps = new ArrayList<String>();
        steps.add("Поллард p−1: основание 2, B = " + bound + "; степени малых простых не превосходят n.");
        boolean[] composite = new boolean[bound + 1];
        BigInteger a = TWO;
        int tested = 0;
        for (int prime = 2; prime <= bound; prime++) {
            if (composite[prime]) {
                continue;
            }
            for (long multiple = (long) prime * prime; multiple <= bound; multiple += prime) {
                composite[(int) multiple] = true;
            }
            BigInteger r = BigInteger.valueOf(prime);
            BigInteger power = ONE;
            BigInteger limit = key.n().divide(r);
            while (power.compareTo(limit) <= 0) {
                power = power.multiply(r);
            }
            a = a.modPow(power, key.n());
            BigInteger factor = a.subtract(ONE).gcd(key.n());
            tested++;
            if (tested <= TRACE_LIMIT || !factor.equals(ONE)) {
                steps.add("r = " + prime + ", r^k = " + power + ", gcd(a−1, n) = " + factor);
            }
            if (factor.equals(key.n())) {
                steps.add("gcd равен n: этот проход не разделил множители; иное основание может дать другой результат.");
                return failure(AttackType.POLLARD_P_MINUS_ONE, steps);
            }
            if (!factor.equals(ONE)) {
                return recoverFromFactors(AttackType.POLLARD_P_MINUS_ONE, key, ciphertext,
                        factor, key.n().divide(factor), steps);
            }
        }
        steps.add("Проверено малых простых: " + tested + "; граница исчерпана без нетривиального множителя.");
        return failure(AttackType.POLLARD_P_MINUS_ONE, steps);
    }

    /** Малая e и m^e < n: c = m^e как обычное целое; подходит любая допустимая e. */
    public static AttackResult lowExponent(RsaHelper.RsaPublicKey key, BigInteger ciphertext) {
        validateCiphertext(key, ciphertext);
        var steps = new ArrayList<String>();
        if (ciphertext.compareTo(ONE) <= 0) {
            steps.add("Тривиальное сообщение: 0 и 1 сохраняются при возведении в любую положительную степень.");
            return success(AttackType.LOW_EXPONENT, ciphertext, steps);
        }
        if (key.e().compareTo(BigInteger.valueOf(ciphertext.bitLength())) >= 0) {
            steps.add("e >= bitLength(c): даже 2^e > c, поэтому целого корня >= 2 нет.");
            return failure(AttackType.LOW_EXPONENT, steps);
        }
        int degree = key.e().intValueExact();
        BigInteger root = integerRootFloor(ciphertext, degree);
        steps.add("Если m^e < n, mod n ничего не меняет. Целочисленный корень степени " + degree + ": " + root);
        if (!root.pow(degree).equals(ciphertext)) {
            steps.add("c не является точной степенью e. Целочисленный корень не восстановил m.");
            return failure(AttackType.LOW_EXPONENT, steps);
        }
        steps.add("Проверка: m^e = c = " + ciphertext + "; приватный ключ не понадобился.");
        return success(AttackType.LOW_EXPONENT, root, steps);
    }

    /**
     * Общий модуль: одинаковое m, один n, gcd(e1,e2)=1 и обратимые c1,c2.
     * Находим u*e1 + v*e2 = 1 и m = c1^u * c2^v mod n, без факторизации.
     * Необратимые шифротексты в этой демонстрации дают пустой результат.
     */
    public static AttackResult commonModulus(RsaHelper.RsaPublicKey firstKey, BigInteger firstCiphertext,
                                             RsaHelper.RsaPublicKey secondKey, BigInteger secondCiphertext) {
        validateCiphertext(firstKey, firstCiphertext);
        validateCiphertext(secondKey, secondCiphertext);
        var steps = new ArrayList<String>();
        BigInteger n = firstKey.n();
        if (!n.equals(secondKey.n()) || !firstKey.e().gcd(secondKey.e()).equals(ONE)) {
            steps.add("Требуются общий n и взаимно простые e1, e2.");
            return failure(AttackType.COMMON_MODULUS, steps);
        }
        if (!firstCiphertext.gcd(n).equals(ONE) || !secondCiphertext.gcd(n).equals(ONE)) {
            steps.add("Шифротекст не обратим по модулю n; вариант с отрицательной степенью неприменим.");
            return failure(AttackType.COMMON_MODULUS, steps);
        }
        BigInteger oldR = firstKey.e();
        BigInteger r = secondKey.e();
        BigInteger oldU = ONE;
        BigInteger u = ZERO;
        BigInteger oldV = ZERO;
        BigInteger v = ONE;
        while (r.signum() != 0) {
            BigInteger quotient = oldR.divide(r);
            BigInteger nextR = oldR.subtract(quotient.multiply(r));
            BigInteger nextU = oldU.subtract(quotient.multiply(u));
            BigInteger nextV = oldV.subtract(quotient.multiply(v));
            oldR = r;
            r = nextR;
            oldU = u;
            u = nextU;
            oldV = v;
            v = nextV;
        }
        steps.add("e2 = " + secondKey.e() + ", c2 = " + secondCiphertext);
        steps.add("Безу: (" + oldU + ") * e1 + (" + oldV + ") * e2 = 1.");
        // BigInteger.modPow supports negative exponents when the base is invertible modulo n.
        BigInteger message = firstCiphertext.modPow(oldU, n).multiply(secondCiphertext.modPow(oldV, n)).mod(n);
        if (!message.modPow(firstKey.e(), n).equals(firstCiphertext)
                || !message.modPow(secondKey.e(), n).equals(secondCiphertext)) {
            steps.add("Кандидат не прошёл повторное шифрование под обоими e; сообщения могли различаться.");
            return failure(AttackType.COMMON_MODULUS, steps);
        }
        steps.add("m = c1^u * c2^v mod n = " + message + "; оба шифротекста проверены.");
        return success(AttackType.COMMON_MODULUS, message, steps);
    }

    /**
     * Franklin–Reiter для e=3: m2 = a*m1+b mod n, известны a,b,c1,c2 и один открытый ключ.
     * Возвращает m1 из линейного gcd(x³−c1, (a*x+b)³−c2) над Z_n[x].
     * Необратимые коэффициенты или нелинейный gcd дают объяснённый пустой результат.
     */
    public static AttackResult franklinReiter(RsaHelper.RsaPublicKey key, BigInteger firstCiphertext,
                                              BigInteger secondCiphertext, BigInteger a, BigInteger b) {
        validateCiphertext(key, firstCiphertext);
        validateCiphertext(key, secondCiphertext);
        if (a == null || b == null) {
            throw new IllegalArgumentException("Нужны известные коэффициенты a и b связи сообщений");
        }
        var steps = new ArrayList<String>();
        BigInteger n = key.n();
        a = a.mod(n);
        b = b.mod(n);
        if (!key.e().equals(THREE) || !a.gcd(n).equals(ONE) || b.equals(ZERO)) {
            steps.add("Демонстрация требует e=3, обратимый a и b != 0 mod n.");
            return failure(AttackType.FRANKLIN_REITER, steps);
        }
        steps.add("Известно m2 = " + a + " * m1 + " + b + " mod n; c2 = " + secondCiphertext);
        steps.add("Ищем gcd(x³−c1, (a*x+b)³−c2) в Z_n[x].");
        BigInteger[] left = {firstCiphertext.negate().mod(n), ZERO, ZERO, ONE};
        BigInteger[] right = {b.pow(3).subtract(secondCiphertext).mod(n),
                THREE.multiply(a).multiply(b.pow(2)).mod(n),
                THREE.multiply(a.pow(2)).multiply(b).mod(n), a.pow(3).mod(n)};
        while (right.length > 0) {
            BigInteger leading = right[right.length - 1];
            BigInteger divisor = leading.gcd(n);
            if (!divisor.equals(ONE)) {
                steps.add("Старший коэффициент не обратим: gcd(coefficient,n) = " + divisor
                        + "; обычный алгоритм Евклида над полем здесь неприменим.");
                return failure(AttackType.FRANKLIN_REITER, steps);
            }
            BigInteger inverse = leading.modInverse(n);
            for (int i = 0; i < right.length; i++) {
                right[i] = right[i].multiply(inverse).mod(n);
            }
            BigInteger[] remainder = polynomialRemainder(left, right, n);
            steps.add("Евклид: степени " + (left.length - 1) + " и " + (right.length - 1)
                    + "; степень остатка " + (remainder.length - 1) + " (−1 означает ноль).");
            left = right;
            right = remainder;
        }
        if (left.length != 2) {
            steps.add("gcd не линейный: однозначное сообщение этим методом не получено.");
            return failure(AttackType.FRANKLIN_REITER, steps);
        }
        BigInteger message = left[0].negate().mod(n); // gcd is monic: x - m1.
        BigInteger related = a.multiply(message).add(b).mod(n);
        if (!message.modPow(THREE, n).equals(firstCiphertext)
                || !related.modPow(THREE, n).equals(secondCiphertext)) {
            steps.add("Корень не прошёл проверку обоих шифротекстов.");
            return failure(AttackType.FRANKLIN_REITER, steps);
        }
        steps.add("Линейный gcd = x−m1; m1 = " + message + "; оба шифротекста проверены.");
        return success(AttackType.FRANKLIN_REITER, message, steps);
    }

    // Coefficients are ordered by ascending powers. The divisor must be monic.
    private static BigInteger[] polynomialRemainder(BigInteger[] dividend, BigInteger[] divisor, BigInteger n) {
        BigInteger[] remainder = dividend.clone();
        for (int degree = remainder.length - 1; degree >= divisor.length - 1; degree--) {
            BigInteger factor = remainder[degree];
            int offset = degree - divisor.length + 1;
            for (int i = 0; i < divisor.length; i++) {
                remainder[offset + i] = remainder[offset + i].subtract(factor.multiply(divisor[i])).mod(n);
            }
        }
        int length = remainder.length;
        while (length > 0 && remainder[length - 1].signum() == 0) {
            length--;
        }
        return Arrays.copyOf(remainder, length);
    }

    /**
     * Хастад: одно и то же m у трех получателей с e = 3 и попарно взаимно простыми n.
     * CRT восстанавливает m³, затем берется точный целочисленный кубический корень.
     * @param keys ровно три открытых ключа
     * @param ciphertexts ровно три шифротекста в том же порядке
     */
    public static AttackResult hastad(List<RsaHelper.RsaPublicKey> keys, List<BigInteger> ciphertexts) {
        if (keys == null || ciphertexts == null || keys.size() != 3 || ciphertexts.size() != 3) {
            throw new IllegalArgumentException("Для демонстрации Хастада нужны ровно три ключа и три шифротекста");
        }
        for (int i = 0; i < 3; i++) {
            validateCiphertext(keys.get(i), ciphertexts.get(i));
        }
        var steps = new ArrayList<String>();
        if (keys.stream().anyMatch(key -> !key.e().equals(THREE))) {
            steps.add("У всех трех получателей должна быть e = 3.");
            return failure(AttackType.HASTAD, steps);
        }
        for (int i = 0; i < 3; i++) {
            steps.add("Получатель " + (i + 1) + ": n = " + keys.get(i).n() + ", c = " + ciphertexts.get(i));
            for (int j = 0; j < i; j++) {
                if (!keys.get(i).n().gcd(keys.get(j).n()).equals(ONE)) {
                    steps.add("Модули не взаимно просты. Для общего множителя используйте sharedPrime.");
                    return failure(AttackType.HASTAD, steps);
                }
            }
        }
        BigInteger product = keys.stream().map(RsaHelper.RsaPublicKey::n).reduce(ONE, BigInteger::multiply);
        BigInteger combined = ZERO;
        for (int i = 0; i < 3; i++) {
            BigInteger modulus = keys.get(i).n();
            BigInteger partialProduct = product.divide(modulus);
            BigInteger inverse = partialProduct.modInverse(modulus);
            steps.add("CRT: N" + (i + 1) + " = " + partialProduct + ", N_i^(-1) mod n_i = " + inverse);
            combined = combined.add(ciphertexts.get(i).multiply(partialProduct).multiply(inverse));
        }
        combined = combined.mod(product);
        steps.add("CRT: C = sum(c_i * N_i * inverse_i) mod (n1*n2*n3) = " + combined);
        BigInteger root = integerRootFloor(combined, 3);
        if (!root.pow(3).equals(combined) || keys.stream().anyMatch(key -> root.compareTo(key.n()) >= 0)) {
            steps.add("Нет точного кубического корня, подходящего всем модулям. Сообщение не восстановлено.");
            return failure(AttackType.HASTAD, steps);
        }
        steps.add("При одинаковом m < min(n_i) имеем m³ < n1*n2*n3. Точный cuberoot(C) = " + root);
        return success(AttackType.HASTAD, root, steps);
    }

    /**
     * Винер: перебор подходящих дробей k/d цепной дроби e/n.
     * Классическая достаточная граница: q < p < 2q и d < n^(1/4)/3 при ed = 1 mod phi(n).
     * Каждая гипотеза проверяется восстановлением настоящих множителей n; одного сходства дробей мало.
     */
    public static AttackResult wiener(RsaHelper.RsaPublicKey key, BigInteger ciphertext) {
        validateCiphertext(key, ciphertext);
        var steps = new ArrayList<String>();
        BigInteger numerator = key.e();
        BigInteger denominator = key.n();
        BigInteger previousK = ZERO;
        BigInteger k = ONE;
        BigInteger previousD = ONE;
        BigInteger d = ZERO;
        int tested = 0;
        while (denominator.signum() != 0) {
            BigInteger[] division = numerator.divideAndRemainder(denominator);
            BigInteger nextK = division[0].multiply(k).add(previousK);
            BigInteger nextD = division[0].multiply(d).add(previousD);
            previousK = k;
            previousD = d;
            k = nextK;
            d = nextD;
            numerator = denominator;
            denominator = division[1];
            tested++;
            if (tested <= TRACE_LIMIT) {
                steps.add("Подходящая дробь k/d = " + k + "/" + d);
            }
            if (k.signum() == 0) {
                continue;
            }
            BigInteger[] phiDivision = key.e().multiply(d).subtract(ONE).divideAndRemainder(k);
            if (phiDivision[1].signum() != 0) {
                continue;
            }
            BigInteger sum = key.n().subtract(phiDivision[0]).add(ONE);
            BigInteger discriminant = sum.multiply(sum).subtract(FOUR.multiply(key.n()));
            if (sum.signum() <= 0 || discriminant.signum() < 0) {
                continue;
            }
            BigInteger root = discriminant.sqrt();
            if (!root.multiply(root).equals(discriminant) || sum.add(root).testBit(0)) {
                continue;
            }
            BigInteger p = sum.add(root).divide(TWO);
            BigInteger q = sum.subtract(root).divide(TWO);
            if (p.compareTo(ONE) > 0 && q.compareTo(ONE) > 0 && p.multiply(q).equals(key.n())) {
                steps.add("Кандидат d = " + d + ", phi(n) = (e*d - 1)/k = " + phiDivision[0]);
                steps.add("p + q = n - phi(n) + 1 = " + sum + ", дискриминант = " + discriminant);
                return recoverFromFactors(AttackType.WIENER, key, ciphertext, p, q, steps);
            }
        }
        steps.add("Проверено подходящих дробей: " + tested + ". Малое d не восстановлено; это не оценка стойкости.");
        return failure(AttackType.WIENER, steps);
    }

    private static AttackResult recoverFromFactors(AttackType type, RsaHelper.RsaPublicKey key,
                                                   BigInteger ciphertext, BigInteger p, BigInteger q,
                                                   List<String> steps) {
        if (p.equals(q) || !p.isProbablePrime(80) || !q.isProbablePrime(80) || !p.multiply(q).equals(key.n())) {
            steps.add("Не получено разложение n на два различных простых числа.");
            return failure(type, steps);
        }
        BigInteger phi = p.subtract(ONE).multiply(q.subtract(ONE));
        if (!key.e().gcd(phi).equals(ONE)) {
            steps.add("e не имеет обратного по модулю phi(n): некорректный RSA-ключ.");
            return failure(type, steps);
        }
        BigInteger d = key.e().modInverse(phi);
        BigInteger message = ciphertext.modPow(d, key.n());
        steps.add("Восстановлено: p = " + p + ", q = " + q);
        steps.add("phi(n) = (p-1)(q-1) = " + phi);
        steps.add("d = e^(-1) mod phi(n) = " + d);
        steps.add("m = c^d mod n = " + message);
        return success(type, message, steps);
    }

    private static BigInteger integerRootFloor(BigInteger value, int degree) {
        BigInteger low = ZERO;
        BigInteger high = ONE.shiftLeft((value.bitLength() - 1) / degree + 1);
        while (high.subtract(low).compareTo(ONE) > 0) {
            BigInteger middle = low.add(high).shiftRight(1);
            if (middle.pow(degree).compareTo(value) <= 0) {
                low = middle;
            } else {
                high = middle;
            }
        }
        return low;
    }

    private static void validatePublicKey(RsaHelper.RsaPublicKey key) {
        if (key == null || key.n() == null || key.e() == null || key.n().compareTo(THREE) <= 0
                || !key.n().testBit(0) || key.e().compareTo(ONE) <= 0 || !key.e().testBit(0)
                || key.e().compareTo(key.n()) >= 0) {
            throw new IllegalArgumentException("Нужны нечетный n > 3 и нечетная экспонента 1 < e < n");
        }
    }

    private static void validateCiphertext(RsaHelper.RsaPublicKey key, BigInteger ciphertext) {
        validatePublicKey(key);
        if (ciphertext == null || ciphertext.signum() < 0 || ciphertext.compareTo(key.n()) >= 0) {
            throw new IllegalArgumentException("Шифротекст должен находиться в диапазоне 0 <= c < n");
        }
    }

    private static AttackResult success(AttackType type, BigInteger message, List<String> steps) {
        return new AttackResult(type, Optional.of(message), steps);
    }

    private static AttackResult failure(AttackType type, List<String> steps) {
        return new AttackResult(type, Optional.empty(), steps);
    }
}
