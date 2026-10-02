package com.cryptography.rsa;

import com.cryptography.RsaAttackDemo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static java.math.BigInteger.ONE;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(10)
class RsaAttackHelperTest {

    @Test
    void fermatRecoversMessageFromClosePrimesUsingOnlyPublicData() {
        var keys = pair(59, 61, 17);
        var result = RsaAttackHelper.fermat(keys.publicKey(), encrypt(65, keys), 1);

        assertEquals(BigInteger.valueOf(65), result.recoveredMessage().orElseThrow());
        assertFalse(result.steps().isEmpty());
    }

    @Test
    void fermatStopsAtBudgetWithoutClaimingSecurity() {
        var keys = pair(101, 1009, 17);
        var result = RsaAttackHelper.fermat(keys.publicKey(), encrypt(65, keys), 1);

        assertTrue(result.recoveredMessage().isEmpty());
        assertThrows(IllegalArgumentException.class,
                () -> RsaAttackHelper.fermat(keys.publicKey(), encrypt(65, keys), 0));
    }

    @Test
    void sharedPrimeRecoversMessageFromTwoPublicModuli() {
        var keys = pair(61, 53, 17);
        var other = pair(61, 47, 17);
        var result = RsaAttackHelper.sharedPrime(keys.publicKey(), encrypt(65, keys), other.publicKey());

        assertEquals(BigInteger.valueOf(65), result.recoveredMessage().orElseThrow());
    }

    @Test
    void sharedPrimeDoesNotTreatIdenticalOrCoprimeModuliAsFactorization() {
        var keys = pair(61, 53, 17);
        var ciphertext = encrypt(65, keys);

        assertTrue(RsaAttackHelper.sharedPrime(keys.publicKey(), ciphertext, keys.publicKey())
                .recoveredMessage().isEmpty());
        assertTrue(RsaAttackHelper.sharedPrime(keys.publicKey(), ciphertext, pair(47, 59, 17).publicKey())
                .recoveredMessage().isEmpty());
    }

    @Test
    void lowExponentRecoversExactIntegerCubeRoot() {
        var keys = pair(11, 17, 3);

        assertEquals(BigInteger.valueOf(5), RsaAttackHelper.lowExponent(keys.publicKey(), encrypt(5, keys))
                .recoveredMessage().orElseThrow());
    }

    @Test
    void lowExponentDoesNotRoundNonPerfectCubeOrUseWrongExponent() {
        var keys = pair(11, 17, 3);

        assertTrue(RsaAttackHelper.lowExponent(keys.publicKey(), encrypt(6, keys)).recoveredMessage().isEmpty());
        var other = pair(61, 53, 17);
        assertTrue(RsaAttackHelper.lowExponent(other.publicKey(), encrypt(65, other))
                .recoveredMessage().isEmpty());
    }

    @Test
    void hastadRecoversMessageEvenWhenEveryCiphertextWasReducedModuloN() {
        var keys = List.of(pair(5, 11, 3), pair(17, 23, 3), pair(29, 41, 3));
        var publicKeys = keys.stream().map(RsaHelper.RsaKeyPair::publicKey).toList();
        var ciphertexts = keys.stream().map(key -> encrypt(42, key)).toList();
        assertTrue(publicKeys.stream().allMatch(key -> BigInteger.valueOf(42).pow(3).compareTo(key.n()) > 0));

        assertEquals(BigInteger.valueOf(42), RsaAttackHelper.hastad(publicKeys, ciphertexts)
                .recoveredMessage().orElseThrow());
    }

    @Test
    void hastadRejectsMissingRecipientsSharedFactorsAndDifferentExponents() {
        var keys = List.of(pair(5, 11, 3), pair(17, 23, 3), pair(29, 41, 3));
        var publicKeys = keys.stream().map(RsaHelper.RsaKeyPair::publicKey).toList();
        var ciphertexts = keys.stream().map(key -> encrypt(42, key)).toList();

        assertThrows(IllegalArgumentException.class,
                () -> RsaAttackHelper.hastad(publicKeys.subList(0, 2), ciphertexts.subList(0, 2)));
        assertTrue(RsaAttackHelper.hastad(List.of(publicKeys.getFirst(), publicKeys.getFirst(), publicKeys.getLast()),
                List.of(ciphertexts.getFirst(), ciphertexts.getFirst(), ciphertexts.getLast()))
                .recoveredMessage().isEmpty());
        assertTrue(RsaAttackHelper.hastad(List.of(publicKeys.getFirst(), publicKeys.get(1),
                pair(29, 41, 17).publicKey()), ciphertexts).recoveredMessage().isEmpty());
    }

    @Test
    void hastadDoesNotRecoverWhenRecipientsReceivedDifferentMessages() {
        var keys = List.of(pair(5, 11, 3), pair(17, 23, 3), pair(29, 41, 3));
        var ciphertexts = List.of(encrypt(42, keys.get(0)), encrypt(43, keys.get(1)), encrypt(44, keys.get(2)));

        assertTrue(RsaAttackHelper.hastad(keys.stream().map(RsaHelper.RsaKeyPair::publicKey).toList(), ciphertexts)
                .recoveredMessage().isEmpty());
    }

    @Test
    void wienerRecoversKnownSmallPrivateExponent() {
        var publicKey = new RsaHelper.RsaPublicKey(BigInteger.valueOf(17993), BigInteger.valueOf(90581));
        var ciphertext = BigInteger.valueOf(65).modPow(publicKey.e(), publicKey.n());

        assertEquals(BigInteger.valueOf(65), RsaAttackHelper.wiener(publicKey, ciphertext)
                .recoveredMessage().orElseThrow());
    }

    @Test
    void wienerDoesNotAcceptAnUnverifiedContinuedFractionCandidate() {
        var keys = pair(61, 53, 17);

        assertTrue(RsaAttackHelper.wiener(keys.publicKey(), encrypt(65, keys)).recoveredMessage().isEmpty());
    }

    @Test
    void invalidPublicInputsAreRejected() {
        var key = pair(61, 53, 17).publicKey();

        assertThrows(IllegalArgumentException.class, () -> RsaAttackHelper.lowExponent(key, ONE.negate()));
        assertThrows(IllegalArgumentException.class, () -> RsaAttackHelper.wiener(key, key.n()));
        assertThrows(IllegalArgumentException.class, () -> RsaAttackHelper.fermat(null, ONE, 1));
        assertThrows(IllegalArgumentException.class, () -> RsaAttackHelper.wiener(
                new RsaHelper.RsaPublicKey(ONE, key.n()), ONE));
        assertThrows(IllegalArgumentException.class, () -> RsaAttackHelper.sharedPrime(key, ONE, null));
        assertThrows(IllegalArgumentException.class, () -> RsaAttackHelper.hastad(null, List.of()));
    }

    @Test
    void keyPairCheckUsesProvidedMessageAndVerifiesPrivateKeyBeforeAttacks() {
        var p = ONE.shiftLeft(48).nextProbablePrime();
        var keys = RsaHelper.generateKeyPair(p, p.nextProbablePrime());
        String message = "Hello World";
        var expected = new BigInteger(1, message.getBytes(StandardCharsets.UTF_8));

        var results = RsaAttackHelper.checkKeyPair(message, keys, 1);

        assertEquals(3, results.size());
        assertEquals(expected, results.getFirst().recoveredMessage().orElseThrow());
        var wrongKeys = new RsaHelper.RsaKeyPair(keys.publicKey(), new RsaHelper.RsaPrivateKey(ONE, keys.publicKey().n()));
        assertThrows(IllegalArgumentException.class, () -> RsaAttackHelper.checkKeyPair(message, wrongKeys, 1));
        assertThrows(IllegalArgumentException.class, () -> RsaAttackHelper.checkKeyPair("", keys, 1));
        assertThrows(IllegalArgumentException.class, () -> RsaAttackHelper.checkKeyPair(null, keys, 1));
        assertThrows(IllegalArgumentException.class, () -> RsaAttackHelper.checkKeyPair(message, pair(61, 53, 17), 1));
    }

    @Test
    void allEightExamplesRecoverExactlyHelloWorldAndPassPrivateKeyControl() {
        var examples = RsaAttackDemo.runExamples();

        assertEquals(8, examples.size());
        assertEquals(8, examples.stream().map(example -> example.attack().type()).distinct().count());
        for (var example : examples) {
            assertEquals("Hello World", example.originalMessage());
            assertEquals("Hello World", example.decryptedMessage());
            assertEquals("Hello World", example.recoveredText());
            assertTrue(example.recoveredOriginal(), example.attack().type().toString());
        }
    }

    private static RsaHelper.RsaKeyPair pair(long p, long q, long e) {
        return RsaHelper.generateKeyPair(BigInteger.valueOf(p), BigInteger.valueOf(q), BigInteger.valueOf(e));
    }

    private static BigInteger encrypt(long message, RsaHelper.RsaKeyPair keys) {
        return RsaHelper.encrypt(BigInteger.valueOf(message), keys.publicKey());
    }
}
