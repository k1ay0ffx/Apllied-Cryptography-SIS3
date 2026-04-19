import java.util.Arrays;

/**
 * PSSPadding — вероятностная схема паддинга подписей (PSS).
 * Стандарт: RFC 8017 §9.1 (RSASSA-PSS)
 *
 * PSS надёжнее PKCS#1 v1.5 потому что:
 *   • Использует случайную соль — одно сообщение, разные подписи
 *   • Доказуемо безопасна в random oracle model
 *   • Рекомендована для новых систем
 *
 * Используемые примитивы (все реализованы без криптолибов):
 *   • SHA-256 (в SHA256.java)
 *   • MGF1 — маскирующая функция на основе SHA-256
 *   • CryptoPRNG — для генерации соли
 *
 * ── Схема PSS-кодирования (emBits бит) ──────────────────────────────────────
 *
 *  EM = maskedDB (emLen-hLen-1 bytes) || H (hLen bytes) || 0xbc
 *
 *  Где:
 *    M' = 0x00*8 || mHash || salt          // padding zeros + hash + salt
 *    H  = SHA256(M')                       // хеш дополненного сообщения
 *    DB = PS || 0x01 || salt               // data block
 *    PS = 0x00 * (emLen - sLen - hLen - 2) // нули-разделитель
 *    dbMask  = MGF1(H, emLen-hLen-1)       // маска из хеша
 *    maskedDB = DB XOR dbMask              // замаскированный DB
 *
 * ── Схема PSS-верификации ────────────────────────────────────────────────────
 *
 *  Обратная операция: восстанавливаем DB, извлекаем соль,
 *  пересчитываем H' и сравниваем с H из EM.
 */
public final class PSSPadding {

    private PSSPadding() {}

    /** Длина хеша SHA-256 в байтах. */
    private static final int H_LEN = 32;

    /** Рекомендуемая длина соли (равна длине хеша). */
    public static final int DEFAULT_SALT_LEN = H_LEN;

    // ── PSS Кодирование ───────────────────────────────────────────────────────

    /**
     * Применяет PSS паддинг к хешу сообщения.
     *
     * @param mHash   SHA-256 хеш исходного сообщения (32 байта)
     * @param emBits  размер модуля - 1 (= keySizeBits - 1)
     * @param sLen    длина соли в байтах (обычно 32)
     * @param prng    источник случайных байт для соли
     * @return        EM — закодированное сообщение
     */
    public static byte[] encode(byte[] mHash, int emBits, int sLen, CryptoPRNG prng) {
        if (mHash.length != H_LEN)
            throw new IllegalArgumentException("mHash must be " + H_LEN + " bytes");

        int emLen = (emBits + 7) / 8;

        // Минимальная длина: hLen + sLen + 2
        if (emLen < H_LEN + sLen + 2)
            throw new IllegalArgumentException("Modulus too small for PSS with sLen=" + sLen);

        // 1. Генерируем случайную соль
        byte[] salt = prng.nextBytes(sLen);

        // 2. M' = (8 нулей) || mHash || salt
        byte[] mPrime = new byte[8 + H_LEN + sLen];
        // 8 нулей — уже есть (Java инициализирует нулями)
        System.arraycopy(mHash, 0, mPrime, 8,         H_LEN);
        System.arraycopy(salt,  0, mPrime, 8 + H_LEN, sLen);

        // 3. H = SHA256(M')
        byte[] H = SHA256.hash(mPrime);

        // 4. PS = нули длиной (emLen - sLen - hLen - 2)
        int psLen = emLen - sLen - H_LEN - 2;

        // 5. DB = PS || 0x01 || salt
        byte[] DB = new byte[emLen - H_LEN - 1];
        DB[psLen] = 0x01;  // разделитель
        System.arraycopy(salt, 0, DB, psLen + 1, sLen);

        // 6. dbMask = MGF1(H, длина DB)
        byte[] dbMask = mgf1(H, DB.length);

        // 7. maskedDB = DB XOR dbMask
        byte[] maskedDB = new byte[DB.length];
        for (int i = 0; i < DB.length; i++) maskedDB[i] = (byte)(DB[i] ^ dbMask[i]);

        // 8. Обнуляем верхние (8*emLen - emBits) бит maskedDB[0]
        int topBits = 8 * emLen - emBits;
        maskedDB[0] &= (byte)(0xFF >>> topBits);

        // 9. EM = maskedDB || H || 0xbc
        byte[] em = new byte[emLen];
        System.arraycopy(maskedDB, 0, em, 0,            maskedDB.length);
        System.arraycopy(H,        0, em, maskedDB.length, H_LEN);
        em[emLen - 1] = (byte) 0xBC;

        return em;
    }

    // ── PSS Верификация ───────────────────────────────────────────────────────

    /**
     * Проверяет PSS паддинг.
     *
     * @param mHash   SHA-256 хеш проверяемого сообщения (32 байта)
     * @param em      восстановленный EM (из RSA: s^e mod n)
     * @param emBits  размер модуля - 1
     * @param sLen    ожидаемая длина соли
     * @return        true если подпись корректна
     */
    public static boolean verify(byte[] mHash, byte[] em, int emBits, int sLen) {
        if (mHash.length != H_LEN) return false;

        int emLen = (emBits + 7) / 8;

        // Шаг 1: проверить длину
        if (em.length < emLen) {
            byte[] padded = new byte[emLen];
            System.arraycopy(em, 0, padded, emLen - em.length, em.length);
            em = padded;
        }

        // Шаг 2: проверить минимальный размер
        if (emLen < H_LEN + sLen + 2) return false;

        // Шаг 3: проверить финальный байт 0xBC
        if ((em[emLen - 1] & 0xFF) != 0xBC) return false;

        // Шаг 4: разделить на maskedDB и H
        int dbLen = emLen - H_LEN - 1;
        byte[] maskedDB = Arrays.copyOfRange(em, 0, dbLen);
        byte[] H        = Arrays.copyOfRange(em, dbLen, dbLen + H_LEN);

        // Шаг 5: проверить верхние биты maskedDB[0]
        int topBits = 8 * emLen - emBits;
        if ((maskedDB[0] & (byte)(0xFF << (8 - topBits))) != 0) return false;

        // Шаг 6: dbMask = MGF1(H, dbLen)
        byte[] dbMask = mgf1(H, dbLen);

        // Шаг 7: DB = maskedDB XOR dbMask
        byte[] DB = new byte[dbLen];
        for (int i = 0; i < dbLen; i++) DB[i] = (byte)(maskedDB[i] ^ dbMask[i]);

        // Шаг 8: обнулить верхние биты DB[0]
        DB[0] &= (byte)(0xFF >>> topBits);

        // Шаг 9: проверить PS — все нули до 0x01
        int psLen = dbLen - sLen - 1;
        for (int i = 0; i < psLen; i++) {
            if (DB[i] != 0x00) return false;
        }
        if ((DB[psLen] & 0xFF) != 0x01) return false;

        // Шаг 10: извлечь соль
        byte[] salt = Arrays.copyOfRange(DB, psLen + 1, psLen + 1 + sLen);

        // Шаг 11: M' = (8 нулей) || mHash || salt
        byte[] mPrime = new byte[8 + H_LEN + sLen];
        System.arraycopy(mHash, 0, mPrime, 8,         H_LEN);
        System.arraycopy(salt,  0, mPrime, 8 + H_LEN, sLen);

        // Шаг 12: H' = SHA256(M')
        byte[] hPrime = SHA256.hash(mPrime);

        // Шаг 13: сравнить H == H' за постоянное время
        return constantTimeEquals(H, hPrime);
    }

    // ── MGF1 — маскирующая функция ────────────────────────────────────────────

    /**
     * MGF1 (Mask Generation Function 1) на основе SHA-256.
     * RFC 8017, Appendix B.2.1
     *
     * Схема: для каждого counter = 0, 1, 2, ...
     *   блок = SHA256(seed || I2OSP(counter, 4))
     *   конкатенировать блоки до нужной длины
     *
     * Используется в PSS для маскирования DB и восстановления соли.
     *
     * @param seed    исходный массив (обычно хеш H)
     * @param length  желаемая длина маски в байтах
     * @return        маска длиной length байт
     */
    public static byte[] mgf1(byte[] seed, int length) {
        byte[] mask   = new byte[length];
        int    filled = 0;
        int    ctr    = 0;

        byte[] input = new byte[seed.length + 4];
        System.arraycopy(seed, 0, input, 0, seed.length);

        while (filled < length) {
            // Записываем счётчик как 4 байта big-endian
            input[seed.length    ] = (byte)(ctr >>> 24);
            input[seed.length + 1] = (byte)(ctr >>> 16);
            input[seed.length + 2] = (byte)(ctr >>>  8);
            input[seed.length + 3] = (byte) ctr;
            ctr++;

            byte[] block = SHA256.hash(input);
            int n = Math.min(H_LEN, length - filled);
            System.arraycopy(block, 0, mask, filled, n);
            filled += n;
        }
        return mask;
    }

    /** Сравнение за постоянное время — предотвращает timing атаки. */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}