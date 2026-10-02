package com.cryptography;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class MainTest {

    @ParameterizedTest(name = "bitLength = {0}")
    @ValueSource(ints = {-5, 0, 1, 2, 15})
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    @DisplayName("#4 #5 Слишком малая битовая длина сразу отклоняется, а не вешает программу")
    void testTooSmallBitLengthIsRejected(int bitLength) {
        assertThrows(IllegalArgumentException.class, () -> Main.generateProbablePrime(bitLength, 10, "тест"));
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    @DisplayName("Минимальная допустимая длина (16 бит) генерирует простое число нужной длины")
    void testMinimalBitLengthWorks() {
        BigInteger prime = Main.generateProbablePrime(16, 10, "тест");
        assertEquals(16, prime.bitLength());
        assertTrue(prime.isProbablePrime(50));
    }
}
