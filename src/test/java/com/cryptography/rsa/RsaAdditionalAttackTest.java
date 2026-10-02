package com.cryptography.rsa;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.math.BigInteger;
import java.util.List;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(20)
class RsaAdditionalAttackTest {

    @Test
    void pollardExploitsSmoothnessRejectedByValidator() {
        BigInteger p = BigInteger.valueOf(5281);
        BigInteger q = BigInteger.valueOf(3607);
        var keys = RsaHelper.generateKeyPair(p, q);
        assertFalse(RsaKeyValidator.validate(p, q, keys.publicKey().e())
                .check(RsaKeyValidator.CheckType.SMOOTHNESS).passed());

        var result = RsaAttackHelper.pollardPMinusOne(keys.publicKey(), encrypt(65, keys), 19);

        assertEquals(BigInteger.valueOf(65), result.recoveredMessage().orElseThrow());
        assertEquals(RsaAttackHelper.AttackType.POLLARD_P_MINUS_ONE, result.type());
    }

    @Test
    void pollardStopsWhenBoundIsTooSmallOrGcdIsWholeModulus() {
        var keys = pair(5281, 3607, 65537);
        assertTrue(RsaAttackHelper.pollardPMinusOne(keys.publicKey(), encrypt(65, keys), 2)
                .recoveredMessage().isEmpty());
        var bothSmooth = pair(17, 257, 3);
        assertTrue(RsaAttackHelper.pollardPMinusOne(bothSmooth.publicKey(), encrypt(65, bothSmooth), 2)
                .recoveredMessage().isEmpty());
        assertThrows(IllegalArgumentException.class,
                () -> RsaAttackHelper.pollardPMinusOne(keys.publicKey(), ONE, 1));
        assertThrows(IllegalArgumentException.class,
                () -> RsaAttackHelper.pollardPMinusOne(keys.publicKey(), ONE, 100_001));
    }

    @Test
    void commonModulusHandlesNegativeBezoutExponentInEitherPosition() {
        var first = pair(61, 53, 17);
        var second = pair(61, 53, 7);
        BigInteger c1 = encrypt(65, first);
        BigInteger c2 = encrypt(65, second);

        assertEquals(BigInteger.valueOf(65), RsaAttackHelper.commonModulus(
                first.publicKey(), c1, second.publicKey(), c2).recoveredMessage().orElseThrow());
        assertEquals(BigInteger.valueOf(65), RsaAttackHelper.commonModulus(
                second.publicKey(), c2, first.publicKey(), c1).recoveredMessage().orElseThrow());
    }

    @Test
    void commonModulusRejectsMissingConditionsAndChecksBothCiphertexts() {
        var first = pair(61, 53, 17);
        var second = pair(61, 53, 7);
        BigInteger c = encrypt(65, first);
        assertTrue(RsaAttackHelper.commonModulus(first.publicKey(), c, first.publicKey(), c)
                .recoveredMessage().isEmpty());
        var differentModulus = pair(59, 47, 7);
        assertTrue(RsaAttackHelper.commonModulus(first.publicKey(), c,
                differentModulus.publicKey(), encrypt(65, differentModulus)).recoveredMessage().isEmpty());
        assertTrue(RsaAttackHelper.commonModulus(first.publicKey(), c,
                second.publicKey(), encrypt(66, second)).recoveredMessage().isEmpty());
        assertTrue(RsaAttackHelper.commonModulus(first.publicKey(), encrypt(61, first),
                second.publicKey(), encrypt(61, second)).recoveredMessage().isEmpty());
    }

    @Test
    void franklinReiterRecoversFirstMessageWithNontrivialAffineRelation() {
        var keys = pair(101, 113, 3);
        assertTrue(BigInteger.valueOf(65).pow(3).compareTo(keys.publicKey().n()) > 0);
        var result = RsaAttackHelper.franklinReiter(keys.publicKey(), encrypt(65, keys),
                encrypt(137, keys), BigInteger.TWO, BigInteger.valueOf(7));

        assertEquals(BigInteger.valueOf(65), result.recoveredMessage().orElseThrow());
        assertEquals(RsaAttackHelper.AttackType.FRANKLIN_REITER, result.type());
    }

    @Test
    void franklinReiterSupportsRelationWrappingModuloNAndZeroMessage() {
        var keys = pair(101, 113, 3);
        BigInteger n = keys.publicKey().n();
        BigInteger first = n.subtract(ONE);
        BigInteger second = first.multiply(BigInteger.TWO).add(BigInteger.valueOf(7)).mod(n);
        assertEquals(first, RsaAttackHelper.franklinReiter(keys.publicKey(),
                RsaHelper.encrypt(first, keys.publicKey()), RsaHelper.encrypt(second, keys.publicKey()),
                BigInteger.TWO, BigInteger.valueOf(7)).recoveredMessage().orElseThrow());
        assertEquals(ZERO, RsaAttackHelper.franklinReiter(keys.publicKey(), ZERO,
                encrypt(7, keys), ONE, BigInteger.valueOf(7)).recoveredMessage().orElseThrow());
    }

    @Test
    void franklinReiterRejectsIncorrectOrDegenerateRelations() {
        var keys = pair(101, 113, 3);
        BigInteger c = encrypt(65, keys);
        assertTrue(RsaAttackHelper.franklinReiter(keys.publicKey(), c, encrypt(137, keys),
                BigInteger.TWO, BigInteger.valueOf(8)).recoveredMessage().isEmpty());
        assertTrue(RsaAttackHelper.franklinReiter(keys.publicKey(), c, c, ONE, ZERO)
                .recoveredMessage().isEmpty());
        assertTrue(RsaAttackHelper.franklinReiter(keys.publicKey(), c, c, BigInteger.valueOf(101), ONE)
                .recoveredMessage().isEmpty());
        // Zn is not a field: a non-invertible intermediate coefficient must not crash the demo.
        var small = pair(5, 11, 3);
        assertTrue(RsaAttackHelper.franklinReiter(small.publicKey(), encrypt(2, small),
                encrypt(7, small), ONE, BigInteger.valueOf(5)).recoveredMessage().isEmpty());
        assertThrows(IllegalArgumentException.class,
                () -> RsaAttackHelper.franklinReiter(keys.publicKey(), c, c, null, ONE));
    }

    @Test
    void lowExponentRecoversExactRootsBeyondCubes() {
        for (int exponent : new int[]{3, 5, 7, 17}) {
            BigInteger e = BigInteger.valueOf(exponent);
            var key = new RsaHelper.RsaPublicKey(e, ONE.shiftLeft(128).subtract(ONE));
            assertEquals(BigInteger.valueOf(5), RsaAttackHelper.lowExponent(key, BigInteger.valueOf(5).pow(exponent))
                    .recoveredMessage().orElseThrow());
            assertTrue(RsaAttackHelper.lowExponent(key, BigInteger.valueOf(5).pow(exponent).add(ONE))
                    .recoveredMessage().isEmpty());
        }
    }

    @Test
    void lowExponentHandlesTrivialMessagesAndHugeExponentWithoutOverflow() {
        var key = new RsaHelper.RsaPublicKey(ONE.shiftLeft(80).add(ONE), ONE.shiftLeft(128).subtract(ONE));
        assertEquals(ZERO, RsaAttackHelper.lowExponent(key, ZERO).recoveredMessage().orElseThrow());
        assertEquals(ONE, RsaAttackHelper.lowExponent(key, ONE).recoveredMessage().orElseThrow());
        assertTrue(RsaAttackHelper.lowExponent(key, BigInteger.TWO).recoveredMessage().isEmpty());
    }

    @Test
    void allAttacksDeclineWhenTheirWeaknessConditionsAreAbsent() {
        BigInteger p = ONE.shiftLeft(1023).nextProbablePrime();
        BigInteger q = ONE.shiftLeft(1023).add(ONE.shiftLeft(1022)).nextProbablePrime();
        var keys = RsaHelper.generateKeyPair(p, q);
        assertTrue(RsaKeyValidator.validate(p, q, keys.publicKey().e()).isValid());
        var key = keys.publicKey();
        BigInteger c = RsaHelper.encryptText("Hello World", key);
        var other = pair(101, 113, 17);
        // This is a reproducible control fixture, not a claim of security or production key generation.
        var results = List.of(
                RsaAttackHelper.fermat(key, c, 100),
                RsaAttackHelper.pollardPMinusOne(key, c, 19),
                RsaAttackHelper.sharedPrime(key, c, other.publicKey()),
                RsaAttackHelper.lowExponent(key, c),
                RsaAttackHelper.wiener(key, c),
                RsaAttackHelper.hastad(List.of(key, key, key), List.of(c, c, c)),
                RsaAttackHelper.commonModulus(key, c, key, c),
                RsaAttackHelper.franklinReiter(key, c, c, ONE, ONE));
        for (var result : results) {
            assertTrue(result.recoveredMessage().isEmpty(), result.type().toString());
        }
    }

    private static RsaHelper.RsaKeyPair pair(long p, long q, long e) {
        return RsaHelper.generateKeyPair(BigInteger.valueOf(p), BigInteger.valueOf(q), BigInteger.valueOf(e));
    }

    private static BigInteger encrypt(long message, RsaHelper.RsaKeyPair keys) {
        return RsaHelper.encrypt(BigInteger.valueOf(message), keys.publicKey());
    }
}
