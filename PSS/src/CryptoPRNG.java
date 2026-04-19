import java.util.Arrays;

/**
 * CryptoPRNG — SHA-256 Counter-Mode PRNG.
 *
 * Используется для генерации случайных байт без java.security.SecureRandom.
 * Нужен для: соль в PSS-паддинге, PS в PKCS#1 паддинге.
 *
 * Схема работы:
 *   seed = несколько источников энтропии (время, память, хеши)
 *   каждый блок = SHA-256(seed || counter)
 *   после каждого вызова nextBytes() seed обновляется
 */
public final class CryptoPRNG {

    private byte[] seed;   // текущее состояние (32 байта)
    private long   ctr;    // счётчик блоков

    // ── Конструктор ───────────────────────────────────────────────────────────

    /**
     * Инициализирует PRNG из нескольких источников энтропии:
     * системное время (наносекунды + миллисекунды),
     * состояние памяти JVM, хеши объектов в памяти.
     */
    public CryptoPRNG() {
        // Собираем энтропию из разных источников
        byte[] entropy = new byte[64];
        long t1 = System.nanoTime();
        long t2 = System.currentTimeMillis();
        long m1 = Runtime.getRuntime().freeMemory();
        long m2 = Runtime.getRuntime().totalMemory();
        long id = Thread.currentThread().getId();
        long h1 = System.identityHashCode(new Object());
        long h2 = System.identityHashCode(entropy);
        long h3 = System.identityHashCode(Thread.currentThread());

        // Упаковываем в 64-байтный массив
        pack(entropy,  0, t1); pack(entropy,  8, t2);
        pack(entropy, 16, m1); pack(entropy, 24, m2);
        pack(entropy, 32, id); pack(entropy, 40, h1);
        pack(entropy, 48, h2); pack(entropy, 56, h3);

        this.seed = SHA256.hash(entropy);
        this.ctr  = 0;
    }

    /**
     * Инициализирует PRNG из заданного начального значения.
     * Используется для воспроизводимых тестов.
     */
    public CryptoPRNG(byte[] initialSeed) {
        this.seed = SHA256.hash(initialSeed);
        this.ctr  = 0;
    }

    // ── Генерация байт ────────────────────────────────────────────────────────

    /**
     * Генерирует count случайных байт.
     *
     * Каждые 32 байта = SHA-256(seed || counter).
     * После генерации seed обновляется для forward secrecy.
     *
     * @param count  количество байт
     * @return массив случайных байт
     */
    public byte[] nextBytes(int count) {
        byte[] output = new byte[count];
        int    filled = 0;

        while (filled < count) {
            // Блок = SHA-256(seed || 8-байтный счётчик)
            byte[] ctrBytes = new byte[8];
            long c = ctr++;
            for (int i = 7; i >= 0; i--) { ctrBytes[i] = (byte)(c & 0xFF); c >>= 8; }

            byte[] input = new byte[seed.length + 8];
            System.arraycopy(seed,     0, input, 0,           seed.length);
            System.arraycopy(ctrBytes, 0, input, seed.length, 8);

            byte[] block = SHA256.hash(input);
            int n = Math.min(32, count - filled);
            System.arraycopy(block, 0, output, filled, n);
            filled += n;
        }

        // Forward secrecy: обновляем seed после каждого вызова
        byte[] newSeedInput = new byte[seed.length + 8];
        System.arraycopy(seed, 0, newSeedInput, 0, seed.length);
        pack(newSeedInput, seed.length, System.nanoTime());
        seed = SHA256.hash(newSeedInput);

        return output;
    }

    /**
     * Генерирует случайный байт в диапазоне [0, 255].
     */
    public int nextByte() {
        return nextBytes(1)[0] & 0xFF;
    }

    /**
     * Генерирует случайные ненулевые байты (для PS в PKCS#1).
     */
    public byte[] nextNonZeroBytes(int count) {
        byte[] result = new byte[count];
        int filled = 0;
        while (filled < count) {
            for (byte b : nextBytes(count)) {
                if (b != 0) {
                    result[filled++] = b;
                    if (filled == count) break;
                }
            }
        }
        return result;
    }

    // ── Вспомогательный метод ─────────────────────────────────────────────────

    /** Записывает long как 8 байт big-endian в массив начиная с offset. */
    private static void pack(byte[] buf, int offset, long v) {
        for (int i = 7; i >= 0; i--) { buf[offset + i] = (byte)(v & 0xFF); v >>= 8; }
    }
}