import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * SHA-256 — реализация с нуля без криптографических библиотек.
 * Стандарт: NIST FIPS PUB 180-4
 *
 * Используется в:
 *   • PKCS#1 v1.5 подпись  — хеш сообщения перед подписью
 *   • PSS паддинг          — MGF1 маска и хеш M'
 *   • RSASignature         — основная хеш-функция
 *   • CryptoPRNG           — генерация псевдослучайных байт
 */
public final class SHA256 {

    // ── Константы раундов K[0..63] ────────────────────────────────────────────
    // Первые 32 бита дробных частей кубических корней первых 64 простых чисел
    private static final int[] K = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    // ── Начальные значения H0[0..7] ───────────────────────────────────────────
    // Первые 32 бита дробных частей квадратных корней первых 8 простых чисел
    private static final int[] H0 = {
            0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
            0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };

    // ── Публичный API ─────────────────────────────────────────────────────────

    /** Вычисляет SHA-256 хеш массива байт → 32 байта. */
    public static byte[] hash(byte[] message) {
        byte[] padded = pad(message);
        int[]  H      = H0.clone();
        for (int off = 0; off < padded.length; off += 64)
            compress(padded, off, H);
        return toBytes(H);
    }

    /** Вычисляет SHA-256 хеш строки (UTF-8) → 32 байта. */
    public static byte[] hash(String text) {
        return hash(text.getBytes(StandardCharsets.UTF_8));
    }

    /** Вычисляет SHA-256 хеш → 64-символьная hex-строка. */
    public static String hashHex(byte[] message) {
        return toHex(hash(message));
    }

    /** Вычисляет SHA-256 хеш строки → 64-символьная hex-строка. */
    public static String hashHex(String text) {
        return toHex(hash(text));
    }

    /** Конвертирует байты в hex-строку нижнего регистра. */
    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }

    /** Конвертирует hex-строку в байты. */
    public static byte[] fromHex(String hex) {
        hex = hex.replaceAll("\\s", "");
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte)((Character.digit(hex.charAt(i*2), 16) << 4)
                    + Character.digit(hex.charAt(i*2+1), 16));
        return out;
    }

    // ── Дополнение сообщения (Padding) ────────────────────────────────────────

    /**
     * Дополняет сообщение до кратного 512 битам (64 байтам).
     *
     * Структура: [сообщение] [0x80] [нули...] [длина в битах 8 байт]
     * Итого кратно 64 байтам.
     */
    static byte[] pad(byte[] message) {
        long bitLen     = (long) message.length * 8;
        int  totalLen   = message.length + 1 + 8;
        if (totalLen % 64 != 0) totalLen += 64 - (totalLen % 64);

        byte[] padded = new byte[totalLen];
        System.arraycopy(message, 0, padded, 0, message.length);
        padded[message.length] = (byte) 0x80;
        for (int i = 0; i < 8; i++)
            padded[totalLen - 8 + i] = (byte)(bitLen >>> (56 - i * 8));
        return padded;
    }

    // ── Функция компрессии (64 раунда) ────────────────────────────────────────

    /**
     * Обрабатывает один 512-битный блок.
     * Обновляет массив H[] (8 × 32-бит = 256-бит хеш-состояние).
     */
    static void compress(byte[] msg, int off, int[] H) {
        int[] W = new int[64];
        // Загружаем 16 слов из блока (big-endian)
        for (int t = 0; t < 16; t++)
            W[t] = ((msg[off+t*4]&0xFF)<<24)|((msg[off+t*4+1]&0xFF)<<16)
                    |((msg[off+t*4+2]&0xFF)<<8)|(msg[off+t*4+3]&0xFF);
        // Расширяем до 64 слов через σ-функции
        for (int t = 16; t < 64; t++) {
            int s0 = rotr(W[t-15],7) ^ rotr(W[t-15],18) ^ (W[t-15]>>>3);
            int s1 = rotr(W[t-2],17) ^ rotr(W[t-2],19)  ^ (W[t-2]>>>10);
            W[t] = W[t-16] + s0 + W[t-7] + s1;
        }
        int a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
        for (int t = 0; t < 64; t++) {
            int S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
            int ch=(e&f)^(~e&g);
            int t1=h+S1+ch+K[t]+W[t];
            int S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
            int maj=(a&b)^(a&c)^(b&c);
            int t2=S0+maj;
            h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        H[0]+=a;H[1]+=b;H[2]+=c;H[3]+=d;H[4]+=e;H[5]+=f;H[6]+=g;H[7]+=h;
    }

    // ── Вспомогательные методы ────────────────────────────────────────────────

    /** Циклический сдвиг вправо (ROTR) для 32-бит. */
    private static int rotr(int x, int n) { return (x >>> n) | (x << (32 - n)); }

    /** Преобразует 8 int-значений (хеш) в 32-байтный массив (big-endian). */
    private static byte[] toBytes(int[] H) {
        byte[] out = new byte[32];
        for (int i = 0; i < 8; i++) {
            out[i*4]=(byte)(H[i]>>>24); out[i*4+1]=(byte)(H[i]>>>16);
            out[i*4+2]=(byte)(H[i]>>>8); out[i*4+3]=(byte)H[i];
        }
        return out;
    }
}