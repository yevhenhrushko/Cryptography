package com.cryptography.primality;

import com.cryptography.generator.PrimeCandidateGenerator;

import java.math.BigInteger;

/**
 * Отдельный класс реализации вероятностного теста простоты Миллера — Рабина.
 * Оптимизирован для корректной работы с числами произвольного порядка (включая 8192 бита).
 */
public class MillerRabinTest {

    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);

    /**
     * Первые простые числа для быстрого отсеивания очевидно составных чисел
     * перед выполнением ресурсоемких раундов Миллера — Рабина.
     */
    private static final int[] SMALL_PRIMES = {
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
        101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
        211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331,
        337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457,
        461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599,
        601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
        739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877,
        881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997
    };

    /**
     * Проверяет число n на простоту тестом Миллера — Рабина.
     *
     * @param n          Проверяемое число
     * @param iterations Количество раундов (независимых свидетелей)
     * @return true, если число вероятно простое; false — если гарантированно составное.
     */
    public static boolean isProbablePrime(BigInteger n, int iterations) {
        if (n.compareTo(BigInteger.ONE) <= 0) {
            return false;
        }
        if (n.equals(TWO) || n.equals(THREE)) {
            return true;
        }
        if (!n.testBit(0)) {
            return false; // Четные числа > 2
        }

        // Быстрое отсеивание составных чисел делением на первые простые числа
        for (int p : SMALL_PRIMES) {
            BigInteger pVal = BigInteger.valueOf(p);
            if (n.equals(pVal)) {
                return true;
            }
            if (n.remainder(pVal).signum() == 0) {
                return false;
            }
        }

        // Представляем n - 1 = 2^s * d, где d — нечетное
        BigInteger nMinusOne = n.subtract(BigInteger.ONE);
        int s = nMinusOne.getLowestSetBit();
        BigInteger d = nMinusOne.shiftRight(s);

        BigInteger nMinusTwo = n.subtract(TWO);

        for (int i = 0; i < iterations; i++) {
            // Выбираем случайное основание a в диапазоне [2, n - 2] с помощью хелпера
            BigInteger a = PrimeCandidateGenerator.getRandomInRange(TWO, nMinusTwo, n.bitLength());

            // x = a^d mod n
            BigInteger x = a.modPow(d, n);

            if (x.equals(BigInteger.ONE) || x.equals(nMinusOne)) {
                continue;
            }

            boolean composite = true;
            for (int r = 1; r < s; r++) {
                x = x.modPow(TWO, n);

                if (x.equals(nMinusOne)) {
                    composite = false;
                    break;
                }
                if (x.equals(BigInteger.ONE)) {
                    return false;
                }
            }

            if (composite) {
                return false;
            }
        }

        return true;
    }
}
