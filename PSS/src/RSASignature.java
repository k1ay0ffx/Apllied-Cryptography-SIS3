import java.math.BigInteger;
import java.util.Base64;

/**
 * RSASignature — цифровые подписи RSA.
 *
 * Реализует две схемы подписи (RFC 8017):
 *   1. RSASSA-PKCS1-v1_5  — классическая детерминированная схема
 *   2. RSASSA-PSS          — вероятностная схема (рекомендована)
 *
 * Обе схемы используют SHA-256 для хеширования сообщений.
 *
 * ── Как работает RSA подпись ─────────────────────────────────────────────────
 *
 *   Подписание (приватный ключ d):
 *     1. hash = SHA256(message)
 *     2. em   = Padding(hash, keyLen)    // PKCS1 или PSS
 *     3. S    = em^d mod n               // RSA private operation
 *
 *   Верификация (публичный ключ e):
 *     1. hash = SHA256(message)
 *     2. em'  = S^e mod n                // RSA public operation
 *     3. Проверить что em' = Padding(hash, keyLen)
 *
 * Используемые классы (все без криптолибов):
 *   • SHA256.java           — хеш-функция
 *   • PKCS1v15Signature.java — паддинг PKCS#1 v1.5
 *   • PSSPadding.java        — паддинг PSS + MGF1
 *   • CryptoPRNG.java        — PRNG для соли в PSS
 */
public final class RSASignature {

    // ── Константы ─────────────────────────────────────────────────────────────

    /** Схемы паддинга подписи. */
    public enum Scheme { PKCS1_V1_5, PSS }

    /** PRNG для генерации соли в PSS. */
    private static final CryptoPRNG PRNG = new CryptoPRNG();

    /** Длина соли PSS = длина хеша SHA-256 = 32 байта. */
    private static final int PSS_SALT_LEN = 32;

    // ── RSASSA-PKCS1-v1_5 ────────────────────────────────────────────────────

    /**
     * Подписывает сообщение схемой RSASSA-PKCS1-v1_5.
     *
     * Алгоритм (RFC 8017 §8.2.1):
     *   1. hash = SHA-256(message)
     *   2. EM   = PKCS1v15Encode(hash, emLen)
     *   3. m    = OS2IP(EM)          // EM как большое целое число
     *   4. s    = m^d mod n          // RSA sign
     *   5. S    = I2OSP(s, emLen)    // результат как байты
     *
     * @param message     подписываемое сообщение
     * @param privateKey  приватный ключ
     * @return            подпись (байты длиной keyLen)
     */
    public static byte[] signPKCS1(byte[] message, RSAKeyPair privateKey) {
        if (!privateKey.hasPrivateKey())
            throw new IllegalArgumentException("Private key required for signing");

        int    emLen = keyLenBytes(privateKey);
        byte[] hash  = SHA256.hash(message);
        byte[] em    = PKCS1v15Signature.encode(hash, emLen);

        // RSA sign: s = em^d mod n
        BigInteger m = new BigInteger(1, em);        // 1 = положительный знак
        BigInteger s = m.modPow(privateKey.d, privateKey.n); // BigInteger — стандартная арифметика
        return RSAEngineStub.toFixedBytes(s, emLen);
    }

    /**
     * Верифицирует подпись RSASSA-PKCS1-v1_5.
     *
     * Алгоритм (RFC 8017 §8.2.2):
     *   1. hash = SHA-256(message)
     *   2. s    = OS2IP(signature)
     *   3. m    = s^e mod n           // RSA verify (public operation)
     *   4. EM   = I2OSP(m, emLen)
     *   5. Проверить PKCS1v15Decode(EM) == hash
     *
     * @param message    оригинальное сообщение
     * @param signature  подпись для проверки
     * @param publicKey  публичный ключ подписавшего
     * @return           true если подпись корректна
     */
    public static boolean verifyPKCS1(byte[] message, byte[] signature, RSAKeyPair publicKey) {
        try {
            int    emLen = keyLenBytes(publicKey);
            byte[] hash  = SHA256.hash(message);

            BigInteger s  = new BigInteger(1, signature);
            BigInteger m  = s.modPow(publicKey.e, publicKey.n); // RSA public op
            byte[]     em = RSAEngineStub.toFixedBytes(m, emLen);

            return PKCS1v15Signature.verify(em, hash, emLen);
        } catch (Exception e) {
            return false;
        }
    }

    // ── RSASSA-PSS ────────────────────────────────────────────────────────────

    /**
     * Подписывает сообщение схемой RSASSA-PSS.
     *
     * Алгоритм (RFC 8017 §8.1.1):
     *   1. mHash = SHA-256(message)
     *   2. EM    = PSS-Encode(mHash, emBits, sLen)   // случайная соль!
     *   3. m     = OS2IP(EM)
     *   4. s     = m^d mod n
     *   5. S     = I2OSP(s, emLen)
     *
     * Каждый вызов даёт РАЗНУЮ подпись (из-за случайной соли).
     *
     * @param message     подписываемое сообщение
     * @param privateKey  приватный ключ
     * @return            подпись (байты длиной keyLen)
     */
    public static byte[] signPSS(byte[] message, RSAKeyPair privateKey) {
        if (!privateKey.hasPrivateKey())
            throw new IllegalArgumentException("Private key required for signing");

        int    emLen  = keyLenBytes(privateKey);
        int    emBits = privateKey.n.bitLength() - 1; // emBits = modBits - 1
        byte[] mHash  = SHA256.hash(message);
        byte[] em     = PSSPadding.encode(mHash, emBits, PSS_SALT_LEN, PRNG);

        BigInteger m = new BigInteger(1, em);
        BigInteger s = m.modPow(privateKey.d, privateKey.n);
        return RSAEngineStub.toFixedBytes(s, emLen);
    }

    /**
     * Верифицирует подпись RSASSA-PSS.
     *
     * Алгоритм (RFC 8017 §8.1.2):
     *   1. mHash = SHA-256(message)
     *   2. s     = OS2IP(signature)
     *   3. m     = s^e mod n
     *   4. EM    = I2OSP(m, emLen)
     *   5. PSS-Verify(mHash, EM, emBits, sLen)
     *
     * @param message    оригинальное сообщение
     * @param signature  подпись для проверки
     * @param publicKey  публичный ключ подписавшего
     * @return           true если подпись корректна
     */
    public static boolean verifyPSS(byte[] message, byte[] signature, RSAKeyPair publicKey) {
        try {
            int    emLen  = keyLenBytes(publicKey);
            int    emBits = publicKey.n.bitLength() - 1;
            byte[] mHash  = SHA256.hash(message);

            BigInteger s  = new BigInteger(1, signature);
            BigInteger m  = s.modPow(publicKey.e, publicKey.n);
            byte[]     em = RSAEngineStub.toFixedBytes(m, emLen);

            return PSSPadding.verify(mHash, em, emBits, PSS_SALT_LEN);
        } catch (Exception e) {
            return false;
        }
    }

    // ── Унифицированный API ───────────────────────────────────────────────────

    /**
     * Подписывает сообщение выбранной схемой.
     *
     * @param message    подписываемое сообщение
     * @param privateKey приватный ключ
     * @param scheme     PKCS1_V1_5 или PSS
     * @return           подпись в байтах
     */
    public static byte[] sign(byte[] message, RSAKeyPair privateKey, Scheme scheme) {
        return switch (scheme) {
            case PKCS1_V1_5 -> signPKCS1(message, privateKey);
            case PSS        -> signPSS(message, privateKey);
        };
    }

    /**
     * Верифицирует подпись выбранной схемой.
     *
     * @param message    оригинальное сообщение
     * @param signature  подпись
     * @param publicKey  публичный ключ
     * @param scheme     PKCS1_V1_5 или PSS
     * @return           true если подпись корректна
     */
    public static boolean verify(byte[] message, byte[] signature,
                                 RSAKeyPair publicKey, Scheme scheme) {
        return switch (scheme) {
            case PKCS1_V1_5 -> verifyPKCS1(message, signature, publicKey);
            case PSS        -> verifyPSS(message, signature, publicKey);
        };
    }

    // ── Информация о подписи ──────────────────────────────────────────────────

    /**
     * Возвращает форматированное описание подписи для отображения.
     *
     * @param signature  байты подписи
     * @param scheme     схема паддинга
     * @param keyBits    размер ключа в битах
     */
    public static String formatSignatureInfo(byte[] signature, Scheme scheme, int keyBits) {
        StringBuilder sb = new StringBuilder();
        sb.append("Scheme     : ").append(scheme == Scheme.PSS ? "RSASSA-PSS" : "RSASSA-PKCS1-v1_5").append("\n");
        sb.append("Key Size   : ").append(keyBits).append(" bits\n");
        sb.append("Sig Length : ").append(signature.length).append(" bytes (").append(signature.length * 8).append(" bits)\n");
        sb.append("Hash Alg   : SHA-256\n");
        if (scheme == Scheme.PSS) sb.append("Salt Length: ").append(PSS_SALT_LEN).append(" bytes\n");
        sb.append("Sig (hex)  : ").append(SHA256.toHex(signature)).append("\n");
        sb.append("Sig (b64)  : ").append(Base64.getEncoder().encodeToString(signature)).append("\n");
        return sb.toString();
    }

    // ── Вспомогательные методы ────────────────────────────────────────────────

    /** Длина ключа в байтах = ceil(n.bitLength / 8). */
    private static int keyLenBytes(RSAKeyPair kp) {
        return (kp.n.bitLength() + 7) / 8;
    }
}