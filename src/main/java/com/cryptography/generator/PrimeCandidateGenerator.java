package com.cryptography.generator;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Хелпер для генерации больших случайных чисел (включая кандидатов в простые числа).
 */
public class PrimeCandidateGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Генерирует случайное нечетное число порядка ровно 8192 бита.
     * Старший бит (8191) устанавливается в 1, чтобы гарантировать точный порядок.
     * Младший бит (0) устанавливается в 1, чтобы отсеять четные числа.
     */
    public static BigInteger generate8192BitCandidate() {
        return generateCandidate(8192);
    }

    /**
     * Генерирует нечетного кандидата заданной битовой длины.
     *
     * @param bitLength битовая длина числа (должна быть >= 2)
     */
    public static BigInteger generateCandidate(int bitLength) {
        if (bitLength < 2) {
            throw new IllegalArgumentException("Битовая длина должна быть >= 2");
        }
        BigInteger number = new BigInteger(bitLength, RANDOM);
        number = number.setBit(bitLength - 1); // Старший бит = 1
        number = number.setBit(0);             // Нечетное число
        return number;
    }

    /**
     * Выбирает случайное число в диапазоне [min, max] без статистического смещения (rejection sampling).
     */
    public static BigInteger getRandomInRange(BigInteger min, BigInteger max, int bitLength) {
        BigInteger range = max.subtract(min).add(BigInteger.ONE);
        BigInteger result;
        do {
            result = new BigInteger(bitLength, RANDOM);
        } while (result.compareTo(range) >= 0);
        return result.add(min);
    }
}
