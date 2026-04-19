import java.math.BigInteger;

public class RSAEngine implements IRSAEngine {

    // Единственный экземпляр генератора простых — хранит SecureRandom внутри
    private final PrimeGenerator primeGen = new PrimeGenerator();

    // ── isPrime ───────────────────────────────────────────────────────────────

    /**
     * Проверка простоты через тест Миллера–Рабина.
     * Делегирует в PrimeGenerator.millerRabin() — реализован вручную.
     *
     * Вероятность ошибки: ≤ 4^(-rounds).
     */
    @Override
    public boolean isPrime(BigInteger n, int rounds) {
        return primeGen.millerRabin(n, rounds);
    }

    // ── generatePrime ─────────────────────────────────────────────────────────

    /**
     * Генерирует случайное простое число точно {@code bits} бит длиной.
     * Делегирует в PrimeGenerator.generatePrime():
     *   1. Генерирует случайное нечётное число нужной длины.
     *   2. Проверяет Miller-Rabin (40 раундов для 512 бит, 64 — для ≥1024).
     *   3. Повторяет до нахождения простого.
     */
    @Override
    public BigInteger generatePrime(int bits) {
        return primeGen.generatePrime(bits);
    }

    // ── modExp ────────────────────────────────────────────────────────────────

    /**
     * Быстрое возведение в степень по модулю (Square-and-Multiply, right-to-left).
     * Делегирует в ModularArithmetic.modExp() — единственная каноническая реализация,
     * которую используют и PrimeGenerator, и RSAMath.
     */
    @Override
    public BigInteger modExp(BigInteger base, BigInteger exp, BigInteger mod) {
        return ModularArithmetic.modExp(base, exp, mod);
    }

    // ── extendedGCD ───────────────────────────────────────────────────────────

    /**
     * Расширенный алгоритм Евклида (итеративный).
     * Возвращает [gcd, x, y] такие что a*x + b*y = gcd(a, b).
     * Делегирует в ModularArithmetic.extGCD().
     */
    @Override
    public BigInteger[] extendedGCD(BigInteger a, BigInteger b) {
        ModularArithmetic.ExtGCDResult r = ModularArithmetic.extGCD(a, b);
        return new BigInteger[]{ r.gcd, r.x, r.y };
    }

    // ── modInverse ────────────────────────────────────────────────────────────

    /**
     * Модульный обратный элемент: x такой что (a * x) mod m == 1.
     * Делегирует в ModularArithmetic.modInverse() — реализован через extGCD.
     *
     * @throws ArithmeticException если gcd(a, m) ≠ 1
     */
    @Override
    public BigInteger modInverse(BigInteger a, BigInteger m) {
        return ModularArithmetic.modInverse(a, m);
    }

    // ── generateKeyPair ───────────────────────────────────────────────────────

    /**
     * Генерирует RSA ключевую пару нужного размера.
     *
     * Использует PrimeGenerator для получения криптостойких простых,
     * затем RSAKeyGenerator.generate() для сборки ключа:
     *   1. n = p * q
     *   2. φ(n) = (p-1)(q-1)
     *   3. e = 65537, d = e^(-1) mod φ(n) через ModularArithmetic.modInverse()
     *   4. Предвычисление CRT-параметров (dp, dq, qInv) для быстрого дешифрования
     */
    @Override
    public RSAKeyPair generateKeyPair(int bits) {
        int halfBits = bits / 2;

        while (true) {
            BigInteger p = generatePrime(halfBits);
            BigInteger q = generatePrime(halfBits);

            if (p.equals(q)) continue;

            try {
                // RSAKeyGenerator валидирует простые и собирает полный ключ
                return RSAKeyGenerator.generate(p, q, bits);
            } catch (IllegalArgumentException e) {
                // Простые слишком близкие или другая ошибка валидации — пробуем снова
            }
        }
    }

    // ── validateKeyPair ───────────────────────────────────────────────────────

    /**
     * Проверяет корректность ключевой пары:
     *   1. Encrypt-decrypt roundtrip через ModularArithmetic.modExp()
     *   2. Если доступны множители p и q — проверяет n = p * q
     */
    @Override
    public boolean validateKeyPair(RSAKeyPair kp) {
        if (kp.getD() == null) return false;
        try {
            BigInteger testMsg = BigInteger.valueOf(42);
            BigInteger cipher  = ModularArithmetic.modExp(testMsg, kp.getE(), kp.getN());
            BigInteger plain   = ModularArithmetic.modExp(cipher,  kp.getD(), kp.getN());
            if (!plain.equals(testMsg)) return false;

            if (kp.hasCRTParams()) {
                if (!kp.getP().multiply(kp.getQ()).equals(kp.getN())) return false;
            }
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    // ── encryptPKCS1 ──────────────────────────────────────────────────────────

    /**
     * RSA шифрование с PKCS#1 v1.5 паддингом.
     * Делегирует в RSAEncryption.encryptPKCS().
     * Формат: 0x00 | 0x02 | PS (≥8 ненулевых байт) | 0x00 | message
     */
    @Override
    public byte[] encryptPKCS1(byte[] message, RSAKeyPair pub) {
        return RSAEncryption.encryptPKCS(message, pub);
    }

    // ── decryptPKCS1 ──────────────────────────────────────────────────────────

    /**
     * RSA дешифрование с PKCS#1 v1.5 паддингом.
     * Делегирует в RSAEncryption.decryptPKCS() — использует CRT если доступно.
     */
    @Override
    public byte[] decryptPKCS1(byte[] ciphertext, RSAKeyPair priv) {
        return RSAEncryption.decryptPKCS(ciphertext, priv);
    }

    // ── encryptOAEP ───────────────────────────────────────────────────────────

    /**
     * RSA шифрование с OAEP паддингом (SHA-256 + MGF1).
     * Делегирует в RSAEncryption.encryptOAEP().
     * Пустой label соответствует стандарту PKCS#1 v2.2.
     */
    @Override
    public byte[] encryptOAEP(byte[] message, RSAKeyPair pub) {
        return RSAEncryption.encryptOAEP(message, pub, new byte[0]);
    }

    // ── decryptOAEP ───────────────────────────────────────────────────────────

    /**
     * RSA дешифрование с OAEP паддингом (SHA-256 + MGF1).
     * Делегирует в RSAEncryption.decryptOAEP().
     */
    @Override
    public byte[] decryptOAEP(byte[] ciphertext, RSAKeyPair priv) {
        return RSAEncryption.decryptOAEP(ciphertext, priv, new byte[0]);
    }
}