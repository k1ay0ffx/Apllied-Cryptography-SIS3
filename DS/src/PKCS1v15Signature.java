import java.util.Arrays;

/**
 * PKCS1v15Signature — паддинг для цифровых подписей по PKCS#1 v1.5.
 * Стандарт: RFC 8017 §9.2
 *
 * Структура EM (encoded message):
 *   EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo
 *
 * Где:
 *   0x00 0x01   — маркер типа (тип 1 = подпись)
 *   PS          — строка 0xFF байт (минимум 8 байт)
 *   0x00        — разделитель
 *   DigestInfo  — ASN.1 структура: идентификатор алгоритма + хеш
 *
 * DigestInfo для SHA-256 (19 байт + 32 байта хеша = 51 байт):
 *   30 31          — SEQUENCE, длина 49
 *   30 0d          — SEQUENCE, длина 13
 *   06 09          — OID, длина 9
 *   60 86 48 01    — SHA-256 OID (2.16.840.1.101.3.4.2.1)
 *   65 03 04 02 01
 *   05 00          — NULL параметры
 *   04 20          — OCTET STRING, длина 32
 *   [32 bytes]     — сам хеш
 */
public final class PKCS1v15Signature {

    private PKCS1v15Signature() {}

    /**
     * ASN.1 DigestInfo заголовок для SHA-256.
     * После него следуют 32 байта хеша.
     */
    public static final byte[] SHA256_DIGEST_INFO = {
            0x30, 0x31,             // SEQUENCE
            0x30, 0x0d,             // SEQUENCE (алгоритм)
            0x06, 0x09,             // OID
            0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            0x05, 0x00,             // NULL
            0x04, 0x20              // OCTET STRING длиной 32
    };

    /** Длина DigestInfo + хеш SHA-256: 19 + 32 = 51 байт. */
    public static final int DIGEST_INFO_TOTAL = SHA256_DIGEST_INFO.length + 32;

    // ── Кодирование (Encoding) ────────────────────────────────────────────────

    /**
     * Применяет PKCS#1 v1.5 паддинг для подписи.
     *
     * Алгоритм (RFC 8017 §9.2 шаг 2):
     *   1. Сформировать DigestInfo = SHA256_DIGEST_INFO || hash
     *   2. EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo
     *   3. PS = (emLen - len(DigestInfo) - 3) байт 0xFF
     *
     * @param hash    32-байтный SHA-256 хеш сообщения
     * @param emLen   длина ключа в байтах = ceil(keySizeBits / 8)
     * @return        EM — дополненное сообщение размером emLen байт
     * @throws IllegalArgumentException если ключ слишком короткий
     */
    public static byte[] encode(byte[] hash, int emLen) {
        if (hash.length != 32)
            throw new IllegalArgumentException("SHA-256 hash must be 32 bytes, got " + hash.length);

        // Длина PS = emLen - 3 - DigestInfoTotal
        // Минимальная PS = 8 байт (RFC 8017 требование)
        int psLen = emLen - 3 - DIGEST_INFO_TOTAL;
        if (psLen < 8) {
            throw new IllegalArgumentException(
                    "Key too short for PKCS#1 v1.5: emLen=" + emLen +
                            ", need at least " + (DIGEST_INFO_TOTAL + 11) + " bytes");
        }

        byte[] em = new byte[emLen];

        // Позиция 0: 0x00
        em[0] = 0x00;
        // Позиция 1: 0x01 (тип подписи)
        em[1] = 0x01;
        // Позиции 2..(2+psLen-1): 0xFF
        Arrays.fill(em, 2, 2 + psLen, (byte) 0xFF);
        // Позиция 2+psLen: 0x00 разделитель
        em[2 + psLen] = 0x00;
        // DigestInfo заголовок
        System.arraycopy(SHA256_DIGEST_INFO, 0, em, 3 + psLen, SHA256_DIGEST_INFO.length);
        // Хеш
        System.arraycopy(hash, 0, em, 3 + psLen + SHA256_DIGEST_INFO.length, 32);

        return em;
    }

    // ── Декодирование / Верификация ───────────────────────────────────────────

    /**
     * Извлекает хеш из PKCS#1 v1.5 паддинга и сравнивает с ожидаемым.
     *
     * Алгоритм проверки (RFC 8017 §9.2 шаг 3):
     *   1. Проверить: EM[0] == 0x00, EM[1] == 0x01
     *   2. Пропустить все 0xFF байты (PS)
     *   3. Проверить: следующий байт == 0x00
     *   4. Проверить DigestInfo заголовок
     *   5. Извлечь и вернуть 32-байтный хеш
     *
     * @param em      дополненное сообщение (результат RSA c^e mod n)
     * @param emLen   ожидаемая длина в байтах
     * @return        32-байтный хеш если паддинг корректен
     * @throws IllegalArgumentException при неверном паддинге
     */
    public static byte[] decode(byte[] em, int emLen) {
        if (em.length < emLen) {
            // Если короче — дополнить нулями слева (leading zeros)
            byte[] padded = new byte[emLen];
            System.arraycopy(em, 0, padded, emLen - em.length, em.length);
            em = padded;
        }

        // Шаг 1: проверить маркеры
        if (em[0] != 0x00)
            throw new IllegalArgumentException("PKCS1 decode: em[0] must be 0x00");
        if (em[1] != 0x01)
            throw new IllegalArgumentException("PKCS1 decode: em[1] must be 0x01 (signature type)");

        // Шаг 2: пропустить PS (все 0xFF)
        int i = 2;
        while (i < em.length && em[i] == (byte) 0xFF) i++;

        // Шаг 3: проверить разделитель 0x00
        if (i >= em.length || em[i] != 0x00)
            throw new IllegalArgumentException("PKCS1 decode: missing 0x00 separator after PS");
        i++; // пропустить 0x00

        // Шаг 4: проверить минимальную длину PS
        int psLen = i - 3; // 2 маркера + psLen FF + 1 нуль = i
        if (psLen < 8)
            throw new IllegalArgumentException("PKCS1 decode: PS too short (" + psLen + " bytes, need ≥ 8)");

        // Шаг 5: проверить DigestInfo заголовок
        if (i + SHA256_DIGEST_INFO.length + 32 > em.length)
            throw new IllegalArgumentException("PKCS1 decode: message too short for DigestInfo");

        for (int j = 0; j < SHA256_DIGEST_INFO.length; j++) {
            if (em[i + j] != SHA256_DIGEST_INFO[j])
                throw new IllegalArgumentException(
                        "PKCS1 decode: DigestInfo mismatch at byte " + j);
        }
        i += SHA256_DIGEST_INFO.length;

        // Шаг 6: извлечь хеш
        byte[] hash = new byte[32];
        System.arraycopy(em, i, hash, 0, 32);
        return hash;
    }

    /**
     * Проверяет что encoded message содержит заданный хеш.
     *
     * @param em      восстановленное EM (из RSA)
     * @param hash    ожидаемый хеш сообщения
     * @param emLen   длина ключа в байтах
     * @return true если хеш совпадает
     */
    public static boolean verify(byte[] em, byte[] hash, int emLen) {
        try {
            byte[] extracted = decode(em, emLen);
            return constantTimeEquals(extracted, hash);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** Сравнение за постоянное время — предотвращает timing атаки. */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}