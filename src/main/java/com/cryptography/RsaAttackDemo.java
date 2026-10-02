package com.cryptography;

import com.cryptography.rsa.RsaAttackHelper;
import com.cryptography.rsa.RsaAttackHelper.AttackResult;
import com.cryptography.rsa.RsaHelper;
import com.cryptography.rsa.RsaKeyValidator;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static java.math.BigInteger.ONE;

/** Воспроизводимая лабораторная работа: искусственно слабые ключи создаются только в памяти. */
public final class RsaAttackDemo {

    public static final String MESSAGE = "Hello World";

    public record Example(String weakness, RsaHelper.RsaPublicKey publicKey, BigInteger ciphertext,
                          String originalMessage, String decryptedMessage, AttackResult attack) {
        public boolean recoveredOriginal() {
            return attack.recoveredMessage()
                    .filter(new BigInteger(1, originalMessage.getBytes(StandardCharsets.UTF_8))::equals).isPresent();
        }

        public String recoveredText() {
            return attack.recoveredMessage().map(number -> {
                byte[] bytes = number.toByteArray();
                if (bytes.length > 1 && bytes[0] == 0) {
                    bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
                }
                return new String(bytes, StandardCharsets.UTF_8);
            }).orElse("Сообщение не восстановлено");
        }
    }

    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FIVE = BigInteger.valueOf(5);

    private RsaAttackDemo() {
    }

    /** Возвращает восемь атак с проверками исходного Hello World штатным приватным ключом и атакой. */
    public static List<Example> runExamples() {
        return List.of(fermatExample(), sharedPrimeExample(), lowExponentExample(), hastadExample(), wienerExample(),
                pollardExample(), commonModulusExample(), franklinReiterExample());
    }

    public static void main(String[] args) {
        System.out.println("Учебные атаки RSA: искусственно слабые параметры, textbook RSA без padding.");
        System.out.println("Все ключи создаются в памяти; приватная часть используется только для контрольной проверки.");
        System.out.println("Сообщение: \"" + MESSAGE + "\", m = "
                + new BigInteger(1, MESSAGE.getBytes(StandardCharsets.UTF_8)));
        int passed = 0;
        List<Example> examples = runExamples();
        for (Example example : examples) {
            System.out.println("\n=== " + example.attack().type() + " ===");
            System.out.println("Слабость: " + example.weakness());
            System.out.println("Открытые данные: n = " + example.publicKey().n()
                    + " (" + example.publicKey().bitLength() + " бит), e = " + example.publicKey().e());
            System.out.println("c = " + example.ciphertext());
            System.out.println("Контрольное расшифрование: \"" + example.decryptedMessage() + "\"");
            example.attack().steps().forEach(step -> System.out.println("  " + step));
            System.out.println("Восстановлено атакой: \"" + example.recoveredText() + "\"");
            boolean matches = example.originalMessage().equals(example.decryptedMessage()) && example.recoveredOriginal();
            System.out.println("Совпадение: " + (matches ? "OK" : "FAIL"));
            if (matches) {
                passed++;
            }
        }
        System.out.println("\nРезультат: " + passed + "/" + examples.size() + " атак восстановили Hello World.");
        if (passed != examples.size()) {
            throw new IllegalStateException("Учебные примеры не прошли контрольную проверку");
        }
    }

    private static Example fermatExample() {
        BigInteger p = ONE.shiftLeft(48).nextProbablePrime();
        var keys = RsaHelper.generateKeyPair(p, p.nextProbablePrime());
        BigInteger ciphertext = RsaHelper.encryptText(MESSAGE, keys.publicKey());
        return example("p и q — соседние простые числа, поэтому разность квадратов находится сразу.",
                keys, ciphertext, RsaAttackHelper.fermat(keys.publicKey(), ciphertext, 100));
    }

    private static Example sharedPrimeExample() {
        BigInteger p = ONE.shiftLeft(48).nextProbablePrime();
        BigInteger q = ONE.shiftLeft(49).nextProbablePrime();
        BigInteger r = ONE.shiftLeft(50).nextProbablePrime();
        var keys = RsaHelper.generateKeyPair(p, q);
        var other = RsaHelper.generateKeyPair(p, r);
        BigInteger ciphertext = RsaHelper.encryptText(MESSAGE, keys.publicKey());
        return example("Две разные пары ключей используют один простой множитель p.", keys, ciphertext,
                RsaAttackHelper.sharedPrime(keys.publicKey(), ciphertext, other.publicKey()));
    }

    private static Example lowExponentExample() {
        var keys = pairForExponent(ONE.shiftLeft(224), ONE.shiftLeft(225), FIVE);
        BigInteger ciphertext = RsaHelper.encryptText(MESSAGE, keys.publicKey());
        return example("e = 5, padding отсутствует, а Hello World настолько короткое, что m⁵ < n.",
                keys, ciphertext, RsaAttackHelper.lowExponent(keys.publicKey(), ciphertext));
    }

    private static Example hastadExample() {
        var keys = List.of(
                pairForExponent(ONE.shiftLeft(48), ONE.shiftLeft(49), THREE),
                pairForExponent(ONE.shiftLeft(50), ONE.shiftLeft(51), THREE),
                pairForExponent(ONE.shiftLeft(52), ONE.shiftLeft(53), THREE));
        var publicKeys = keys.stream().map(RsaHelper.RsaKeyPair::publicKey).toList();
        var ciphertexts = keys.stream().map(key -> RsaHelper.encryptText(MESSAGE, key.publicKey())).toList();
        for (int i = 0; i < keys.size(); i++) {
            if (!MESSAGE.equals(RsaHelper.decryptText(ciphertexts.get(i), keys.get(i).privateKey()))) {
                throw new IllegalStateException("Не прошла контрольная проверка получателя Хастада");
            }
        }
        return example("Одинаковое сообщение без padding отправлено трем получателям с e = 3; m³ > каждого n_i.",
                keys.getFirst(), ciphertexts.getFirst(), RsaAttackHelper.hastad(publicKeys, ciphertexts));
    }

    private static Example wienerExample() {
        BigInteger p = primeForExponent(ONE.shiftLeft(48), FIVE);
        BigInteger q = primeForExponent(ONE.shiftLeft(48).add(ONE.shiftLeft(47)), FIVE);
        BigInteger phi = p.subtract(ONE).multiply(q.subtract(ONE));
        BigInteger e = FIVE.modInverse(phi);
        var keys = RsaHelper.generateKeyPair(p, q, e);
        if (!keys.privateKey().d().equals(FIVE)) {
            throw new IllegalStateException("Для примера Винера должна сохраниться d = 5");
        }
        BigInteger ciphertext = RsaHelper.encryptText(MESSAGE, keys.publicKey());
        return example("Специально выбрано d = 5 при сбалансированных p и q; e вычислена как 5^(-1) mod phi(n).",
                keys, ciphertext, RsaAttackHelper.wiener(keys.publicKey(), ciphertext));
    }

    private static Example pollardExample() {
        // p−1 = 2^5 * 3^5 * 5^3 * 7^2 * 11 * 13 * 17.
        BigInteger p = new BigInteger("115783668001");
        BigInteger q = primeForExponent(ONE.shiftLeft(64), BigInteger.valueOf(65537));
        var keys = RsaHelper.generateKeyPair(p, q);
        var smoothness = RsaKeyValidator.validate(p, q, keys.publicKey().e())
                .check(RsaKeyValidator.CheckType.SMOOTHNESS);
        if (smoothness.passed()) {
            throw new IllegalStateException("Валидатор должен заметить гладкое p−1 учебного ключа");
        }
        BigInteger ciphertext = RsaHelper.encryptText(MESSAGE, keys.publicKey());
        return example("p−1 состоит из простых <= 17. Проверка SMOOTHNESS отклонила ключ: " + smoothness.details(),
                keys, ciphertext, RsaAttackHelper.pollardPMinusOne(keys.publicKey(), ciphertext, 17));
    }

    private static Example commonModulusExample() {
        BigInteger e1 = BigInteger.valueOf(17);
        BigInteger e2 = BigInteger.valueOf(65537);
        BigInteger p = primeForExponent(ONE.shiftLeft(48), e1.multiply(e2));
        BigInteger q = primeForExponent(ONE.shiftLeft(49), e1.multiply(e2));
        var keys = RsaHelper.generateKeyPair(p, q, e1);
        var other = RsaHelper.generateKeyPair(p, q, e2);
        BigInteger ciphertext = RsaHelper.encryptText(MESSAGE, keys.publicKey());
        BigInteger otherCiphertext = RsaHelper.encryptText(MESSAGE, other.publicKey());
        if (!MESSAGE.equals(RsaHelper.decryptText(otherCiphertext, other.privateKey()))) {
            throw new IllegalStateException("Не прошла контрольная проверка второго получателя общего модуля");
        }
        return example("Один n и одно сообщение без padding, но e1 = 17 и e2 = 65537 взаимно просты.",
                keys, ciphertext, RsaAttackHelper.commonModulus(keys.publicKey(), ciphertext,
                        other.publicKey(), otherCiphertext));
    }

    private static Example franklinReiterExample() {
        var keys = pairForExponent(ONE.shiftLeft(48), ONE.shiftLeft(49), THREE);
        BigInteger message = new BigInteger(1, MESSAGE.getBytes(StandardCharsets.UTF_8));
        BigInteger a = BigInteger.TWO;
        BigInteger b = BigInteger.valueOf(7);
        BigInteger related = a.multiply(message).add(b).mod(keys.publicKey().n());
        BigInteger ciphertext = RsaHelper.encryptText(MESSAGE, keys.publicKey());
        BigInteger relatedCiphertext = RsaHelper.encrypt(related, keys.publicKey());
        if (!related.equals(RsaHelper.decrypt(relatedCiphertext, keys.privateKey()))) {
            throw new IllegalStateException("Не прошла контрольная проверка связанного сообщения");
        }
        return example("Один n, e = 3 и известная связь m2 = 2*m1+7 mod n; m1³ > n.",
                keys, ciphertext, RsaAttackHelper.franklinReiter(keys.publicKey(), ciphertext, relatedCiphertext, a, b));
    }

    private static Example example(String weakness, RsaHelper.RsaKeyPair keys,
                                   BigInteger ciphertext, AttackResult attack) {
        return new Example(weakness, keys.publicKey(), ciphertext, MESSAGE,
                RsaHelper.decryptText(ciphertext, keys.privateKey()), attack);
    }

    private static RsaHelper.RsaKeyPair pairForExponent(BigInteger firstStart, BigInteger secondStart, BigInteger e) {
        var keys = RsaHelper.generateKeyPair(primeForExponent(firstStart, e), primeForExponent(secondStart, e), e);
        if (!keys.publicKey().e().equals(e)) {
            throw new IllegalStateException("Экспонента учебного примера неожиданно изменилась");
        }
        return keys;
    }

    // Детерминированный подбор для лабораторной работы, не генератор настоящих ключей.
    private static BigInteger primeForExponent(BigInteger start, BigInteger exponent) {
        BigInteger prime = start.nextProbablePrime();
        while (!prime.subtract(ONE).gcd(exponent).equals(ONE)) {
            prime = prime.nextProbablePrime();
        }
        return prime;
    }
}
