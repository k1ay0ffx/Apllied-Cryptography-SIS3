import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/**
 * RSAEngineStub — временная заглушка для IRSAEngine.
 *
 * ╔══════════════════════════════════════════════════════════╗
 * ║  ЗАГЛУШКА — ТОЛЬКО ДО ПУША ДРУГОГО РАЗРАБОТЧИКА          ║
 * ║                                                          ║
 * ║  Использует BigInteger.probablePrime() вместо            ║
 * ║  кастомного теста Миллера-Рабина.                        ║
 * ║                                                          ║
 * ║  После того как другой разработчик реализует RSAEngine:  ║
 * ║  В Main.java замени:                                     ║
 * ║    new RSAEngineStub()  →  new RSAEngine()               ║
 * ╚══════════════════════════════════════════════════════════╝
 *
 * Использует только стандартные BigInteger-операции (не криптолибы).
 */
public class RSAEngineStub implements IRSAEngine {

    private static final BigInteger ONE  = BigInteger.ONE;
    private static final BigInteger TWO  = BigInteger.TWO;
    private static final BigInteger E    = BigInteger.valueOf(65537);

    // Random используется только для генерации чисел в заглушке
    // ДРУГОЙ РАЗРАБОТЧИК заменит это на CryptoPRNG + Miller-Rabin
    private final Random rng = new Random(System.nanoTime());

    // ── isPrime ───────────────────────────────────────────────────────────────

    /**
     * STUB: использует BigInteger.isProbablePrime().
     * ДРУГОЙ РАЗРАБОТЧИК реализует Miller-Rabin вручную.
     */
    @Override
    public boolean isPrime(BigInteger n, int rounds) {
        if (n.compareTo(TWO) < 0) return false;
        if (n.equals(TWO))        return true;
        if (!n.testBit(0))        return false;
        // TODO [OTHER DEV]: заменить на собственный Miller-Rabin тест
        return n.isProbablePrime(rounds * 2);
    }

    // ── generatePrime ─────────────────────────────────────────────────────────

    /**
     * STUB: использует BigInteger.probablePrime().
     * ДРУГОЙ РАЗРАБОТЧИК реализует генерацию через собственный isPrime.
     */
    @Override
    public BigInteger generatePrime(int bits) {
        // TODO [OTHER DEV]: генерировать случайные нечётные числа
        // и проверять isPrime() в цикле
        return BigInteger.probablePrime(bits, rng);
    }

    // ── modExp ────────────────────────────────────────────────────────────────

    /**
     * STUB: делегирует BigInteger.modPow().
     * ДРУГОЙ РАЗРАБОТЧИК реализует Square-and-Multiply вручную.
     */
    @Override
    public BigInteger modExp(BigInteger base, BigInteger exp, BigInteger mod) {
        // TODO [OTHER DEV]: Square-and-Multiply алгоритм
        return base.modPow(exp, mod);
    }

    // ── extendedGCD ───────────────────────────────────────────────────────────

    /**
     * STUB: возвращает [gcd, x, y] через рекурсивный алгоритм.
     * Реализован корректно — другой разработчик может оставить или заменить.
     */
    @Override
    public BigInteger[] extendedGCD(BigInteger a, BigInteger b) {
        // TODO [OTHER DEV]: реализовать итеративно
        if (b.equals(BigInteger.ZERO)) {
            return new BigInteger[]{ a, ONE, BigInteger.ZERO };
        }
        BigInteger[] r = extendedGCD(b, a.mod(b));
        BigInteger gcd = r[0];
        BigInteger x   = r[2];
        BigInteger y   = r[1].subtract(a.divide(b).multiply(r[2]));
        return new BigInteger[]{ gcd, x, y };
    }

    // ── modInverse ────────────────────────────────────────────────────────────

    /**
     * STUB: делегирует BigInteger.modInverse().
     * ДРУГОЙ РАЗРАБОТЧИК реализует через extendedGCD вручную.
     */
    @Override
    public BigInteger modInverse(BigInteger a, BigInteger m) {
        // TODO [OTHER DEV]: использовать extendedGCD(a, m)[1].mod(m)
        return a.modInverse(m);
    }

    // ── generateKeyPair ───────────────────────────────────────────────────────

    /**
     * STUB: генерирует корректную пару ключей используя BigInteger.probablePrime.
     * ДРУГОЙ РАЗРАБОТЧИК заменит generatePrime() на собственную реализацию.
     */
    @Override
    public RSAKeyPair generateKeyPair(int bits) {
        // TODO [OTHER DEV]: использовать собственный generatePrime()
        int halfBits = bits / 2;

        BigInteger p, q, n;
        do {
            p = generatePrime(halfBits);
            q = generatePrime(halfBits);
            n = p.multiply(q);
        } while (p.equals(q)
                || n.bitLength() != bits
                || p.subtract(q).abs().bitLength() < halfBits / 2);

        // λ(n) = lcm(p-1, q-1) [функция Кармайкла]
        BigInteger pm1    = p.subtract(ONE);
        BigInteger qm1    = q.subtract(ONE);
        BigInteger lambda = pm1.divide(pm1.gcd(qm1)).multiply(qm1);

        BigInteger e = E;
        // Убедиться что gcd(e, λ(n)) = 1
        while (!e.gcd(lambda).equals(ONE)) {
            e = e.add(TWO);
        }

        BigInteger d = modInverse(e, lambda);

        return new RSAKeyPair(n, e, d, p, q);
    }

    // ── validateKeyPair ───────────────────────────────────────────────────────

    /**
     * Проверяет пару ключей: e×d ≡ 1 mod λ(n) и n = p×q если есть p, q.
     */
    @Override
    public boolean validateKeyPair(RSAKeyPair kp) {
        if (!kp.hasPrivateKey()) return false;
        try {
            // Тест 1: encrypt-decrypt roundtrip
            BigInteger testMsg = BigInteger.valueOf(42);
            BigInteger cipher  = modExp(testMsg, kp.e, kp.n);
            BigInteger plain   = modExp(cipher,  kp.d, kp.n);
            if (!plain.equals(testMsg)) return false;

            // Тест 2: n = p × q
            if (kp.hasFactors()) {
                if (!kp.p.multiply(kp.q).equals(kp.n)) return false;
            }
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    // ── encryptPKCS1 ──────────────────────────────────────────────────────────

    /**
     * STUB реализация PKCS#1 v1.5 шифрования.
     * TODO [OTHER DEV]: реализовать полностью с нужным паддингом.
     */
    @Override
    public byte[] encryptPKCS1(byte[] message, RSAKeyPair pub) {
        // TODO [OTHER DEV]: реализовать PKCS#1 v1.5 encryption padding
        // 0x00 || 0x02 || PS || 0x00 || message
        int keyLen = (pub.n.bitLength() + 7) / 8;
        int maxMsg = keyLen - 11;
        if (message.length > maxMsg)
            throw new IllegalArgumentException("Message too long: max " + maxMsg + " bytes");

        byte[] em = new byte[keyLen];
        em[0] = 0x00;
        em[1] = 0x02;
        // PS: случайные ненулевые байты
        int psLen = keyLen - message.length - 3;
        for (int i = 0; i < psLen; i++) {
            int b;
            do { b = rng.nextInt(256); } while (b == 0);
            em[2 + i] = (byte) b;
        }
        em[2 + psLen] = 0x00;
        System.arraycopy(message, 0, em, 3 + psLen, message.length);

        BigInteger m = new BigInteger(1, em);
        BigInteger c = modExp(m, pub.e, pub.n);
        return toFixedBytes(c, keyLen);
    }

    /**
     * STUB реализация PKCS#1 v1.5 дешифрования.
     */
    @Override
    public byte[] decryptPKCS1(byte[] ciphertext, RSAKeyPair priv) {
        // TODO [OTHER DEV]: реализовать полностью
        int keyLen = (priv.n.bitLength() + 7) / 8;
        BigInteger c  = new BigInteger(1, ciphertext);
        BigInteger m  = modExp(c, priv.d, priv.n);
        byte[]     em = toFixedBytes(m, keyLen);

        if (em[0] != 0x00 || em[1] != 0x02)
            throw new IllegalArgumentException("Invalid PKCS#1 padding");

        int i = 2;
        while (i < em.length && em[i] != 0x00) i++;
        if (i >= em.length) throw new IllegalArgumentException("Padding error: no 0x00 separator");

        byte[] result = new byte[em.length - i - 1];
        System.arraycopy(em, i + 1, result, 0, result.length);
        return result;
    }

    /**
     * STUB реализация OAEP шифрования.
     * TODO [OTHER DEV]: реализовать RSA-OAEP-SHA256.
     */
    @Override
    public byte[] encryptOAEP(byte[] message, RSAKeyPair pub) {
        // TODO [OTHER DEV]: реализовать OAEP (MGF1, SHA-256 label hash, XOR)
        throw new UnsupportedOperationException(
                "[STUB] OAEP не реализован — ждём другого разработчика");
    }

    /**
     * STUB реализация OAEP дешифрования.
     */
    @Override
    public byte[] decryptOAEP(byte[] ciphertext, RSAKeyPair priv) {
        // TODO [OTHER DEV]: реализовать OAEP декодирование
        throw new UnsupportedOperationException(
                "[STUB] OAEP не реализован — ждём другого разработчика");
    }

    // ── Вспомогательный метод ─────────────────────────────────────────────────

    /**
     * Конвертирует BigInteger в массив байт фиксированной длины.
     * BigInteger.toByteArray() добавляет ведущий 0x00 для положительных чисел —
     * нам нужна строго указанная длина.
     */
    static byte[] toFixedBytes(BigInteger v, int length) {
        byte[] raw = v.toByteArray();
        if (raw.length == length) return raw;
        byte[] out = new byte[length];
        if (raw.length > length) {
            // Убираем ведущий 0x00 байт (знак)
            System.arraycopy(raw, raw.length - length, out, 0, length);
        } else {
            // Дополняем нулями слева
            System.arraycopy(raw, 0, out, length - raw.length, raw.length);
        }
        return out;
    }
}