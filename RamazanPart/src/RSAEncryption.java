import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * RSA Encryption and Decryption.
 *
 * Supports:
 *   - Raw RSA (textbook): C = M^e mod n / M = C^d mod n
 *   - PKCS#1 v1.5 padding (10 pts)
 *   - OAEP padding with SHA-256 (5 pts)
 *
 * NO crypto libraries used. All operations from scratch.
 */
public class RSAEncryption {

    private static final SecureRandom RANDOM = new SecureRandom();

    // PKCS#1 v1.5 constants
    private static final byte PKCS_ZERO     = 0x00;
    private static final byte PKCS_ENC_TYPE = 0x02; // encryption padding type
    private static final int  PKCS_MIN_PS   = 8;    // minimum padding string length

    // OAEP constants
    private static final int SHA256_LEN = 32; // SHA-256 output length in bytes

    // =========================================================================
    //  PUBLIC API
    // =========================================================================

    /**
     * Encrypts a message using RSA with PKCS#1 v1.5 padding.
     *
     * @param message   plaintext bytes
     * @param keyPair   RSA key pair (uses n and e)
     * @return          ciphertext bytes
     */
    public static byte[] encryptPKCS(byte[] message, RSAKeyPair keyPair) {
        int keyBytes = keyPair.getKeySize() / 8;
        byte[] padded = pkcsV15Pad(message, keyBytes);
        return rsaRaw(padded, keyPair.getE(), keyPair.getN(), keyBytes);
    }

    /**
     * Decrypts a message using RSA with PKCS#1 v1.5 padding.
     * Uses CRT if available (faster), otherwise standard decryption.
     *
     * @param ciphertext    encrypted bytes
     * @param keyPair       RSA key pair (uses n and d)
     * @return              original plaintext bytes
     */
    public static byte[] decryptPKCS(byte[] ciphertext, RSAKeyPair keyPair) {
        int keyBytes = keyPair.getKeySize() / 8;
        byte[] padded = rsaRawDecrypt(ciphertext, keyPair, keyBytes);
        return pkcsV15Unpad(padded);
    }

    /**
     * Encrypts a message using RSA with OAEP padding (SHA-256).
     * Requires SHA256 implementation from teammate.
     *
     * @param message   plaintext bytes
     * @param keyPair   RSA key pair
     * @param label     optional label (can be empty byte array)
     * @return          ciphertext bytes
     */
    public static byte[] encryptOAEP(byte[] message, RSAKeyPair keyPair, byte[] label) {
        int keyBytes = keyPair.getKeySize() / 8;
        byte[] padded = oaepPad(message, keyBytes, label);
        return rsaRaw(padded, keyPair.getE(), keyPair.getN(), keyBytes);
    }

    /**
     * Decrypts a message using RSA with OAEP padding (SHA-256).
     *
     * @param ciphertext    encrypted bytes
     * @param keyPair       RSA key pair
     * @param label         optional label (must match encryption label)
     * @return              original plaintext bytes
     */
    public static byte[] decryptOAEP(byte[] ciphertext, RSAKeyPair keyPair, byte[] label) {
        int keyBytes = keyPair.getKeySize() / 8;
        byte[] padded = rsaRawDecrypt(ciphertext, keyPair, keyBytes);
        return oaepUnpad(padded, keyBytes, label);
    }

    // =========================================================================
    //  RAW RSA OPERATIONS
    // =========================================================================

    /**
     * Raw RSA encryption: C = M^e mod n
     * Converts padded bytes → BigInteger → modExp → bytes
     */
    private static byte[] rsaRaw(byte[] padded, BigInteger exp, BigInteger mod, int keyBytes) {
        BigInteger m = new BigInteger(1, padded); // 1 = positive sign

        if (m.compareTo(mod) >= 0) {
            throw new IllegalArgumentException("Message too large for key size");
        }

        BigInteger c = RSAMath.modExp(m, exp, mod);
        return toFixedBytes(c, keyBytes);
    }

    /**
     * Raw RSA decryption — uses CRT if available, otherwise standard M = C^d mod n
     */
    private static byte[] rsaRawDecrypt(byte[] ciphertext, RSAKeyPair keyPair, int keyBytes) {
        BigInteger c = new BigInteger(1, ciphertext);

        BigInteger m;
        if (keyPair.hasCRTParams()) {
            m = RSACrt.decryptCRT(c, keyPair);
        } else {
            m = RSAMath.modExp(c, keyPair.getD(), keyPair.getN());
        }

        return toFixedBytes(m, keyBytes);
    }

    // =========================================================================
    //  PKCS#1 v1.5 PADDING
    //  Format: 0x00 | 0x02 | PS (random, min 8 bytes) | 0x00 | Message
    // =========================================================================

    /**
     * Applies PKCS#1 v1.5 encryption padding.
     * Total padded length = key size in bytes.
     */
    static byte[] pkcsV15Pad(byte[] message, int keyBytes) {
        // max message length = keyBytes - 11 (3 fixed bytes + min 8 PS bytes)
        int maxMsgLen = keyBytes - 11;
        if (message.length > maxMsgLen) {
            throw new IllegalArgumentException(String.format(
                    "Message too long for PKCS#1 v1.5: max %d bytes, got %d", maxMsgLen, message.length
            ));
        }

        int psLen = keyBytes - message.length - 3; // padding string length
        byte[] padded = new byte[keyBytes];

        // Structure: 0x00 | 0x02 | PS | 0x00 | M
        padded[0] = PKCS_ZERO;
        padded[1] = PKCS_ENC_TYPE;

        // PS: random non-zero bytes
        byte[] ps = generateNonZeroRandomBytes(psLen);
        System.arraycopy(ps, 0, padded, 2, psLen);

        padded[2 + psLen] = PKCS_ZERO; // separator

        // Message
        System.arraycopy(message, 0, padded, 3 + psLen, message.length);

        return padded;
    }

    /**
     * Removes PKCS#1 v1.5 encryption padding.
     * Validates structure and returns the original message.
     */
    static byte[] pkcsV15Unpad(byte[] padded) {
        // Validate header bytes
        if (padded[0] != PKCS_ZERO || padded[1] != PKCS_ENC_TYPE) {
            throw new IllegalArgumentException("Invalid PKCS#1 v1.5 padding: wrong header");
        }

        // Find the 0x00 separator after PS
        int separatorIdx = -1;
        for (int i = 2; i < padded.length; i++) {
            if (padded[i] == 0x00) {
                separatorIdx = i;
                break;
            }
        }

        if (separatorIdx == -1) {
            throw new IllegalArgumentException("Invalid PKCS#1 v1.5 padding: no separator found");
        }

        int psLen = separatorIdx - 2;
        if (psLen < PKCS_MIN_PS) {
            throw new IllegalArgumentException(String.format(
                    "Invalid PKCS#1 v1.5 padding: PS too short (%d bytes, min %d)", psLen, PKCS_MIN_PS
            ));
        }

        // Extract message
        int msgStart = separatorIdx + 1;
        return Arrays.copyOfRange(padded, msgStart, padded.length);
    }

    // =========================================================================
    //  OAEP PADDING (Optimal Asymmetric Encryption Padding)
    //  Uses SHA-256 + MGF1
    //  Format: 0x00 | maskedSeed (32 bytes) | maskedDB
    // =========================================================================

    /**
     * Applies OAEP padding with SHA-256.
     *
     * Structure of DB (data block):
     *   lHash | PS (zero bytes) | 0x01 | message
     */
    static byte[] oaepPad(byte[] message, int keyBytes, byte[] label) {
        int hLen   = SHA256_LEN;
        int maxMsg = keyBytes - 2 * hLen - 2;

        if (message.length > maxMsg) {
            throw new IllegalArgumentException(String.format(
                    "Message too long for OAEP: max %d bytes, got %d", maxMsg, message.length
            ));
        }

        // lHash = SHA-256(label)
        byte[] lHash = SHA256.hash(label);

        // DB = lHash | PS | 0x01 | message
        int dbLen = keyBytes - hLen - 1;
        byte[] db = new byte[dbLen];
        System.arraycopy(lHash, 0, db, 0, hLen);
        // PS is zeros (already initialized)
        db[dbLen - message.length - 1] = 0x01; // separator
        System.arraycopy(message, 0, db, dbLen - message.length, message.length);

        // Random seed (hLen bytes)
        byte[] seed = new byte[hLen];
        RANDOM.nextBytes(seed);

        // dbMask = MGF1(seed, dbLen)
        byte[] dbMask = mgf1(seed, dbLen);

        // maskedDB = DB XOR dbMask
        byte[] maskedDB = xorBytes(db, dbMask);

        // seedMask = MGF1(maskedDB, hLen)
        byte[] seedMask = mgf1(maskedDB, hLen);

        // maskedSeed = seed XOR seedMask
        byte[] maskedSeed = xorBytes(seed, seedMask);

        // EM = 0x00 | maskedSeed | maskedDB
        byte[] em = new byte[keyBytes];
        em[0] = 0x00;
        System.arraycopy(maskedSeed, 0, em, 1, hLen);
        System.arraycopy(maskedDB, 0, em, 1 + hLen, dbLen);

        return em;
    }

    /**
     * Removes OAEP padding and returns the original message.
     */
    static byte[] oaepUnpad(byte[] em, int keyBytes, byte[] label) {
        int hLen = SHA256_LEN;

        if (em[0] != 0x00) {
            throw new IllegalArgumentException("Invalid OAEP: first byte is not 0x00");
        }

        byte[] maskedSeed = Arrays.copyOfRange(em, 1, 1 + hLen);
        byte[] maskedDB   = Arrays.copyOfRange(em, 1 + hLen, keyBytes);

        // Recover seed
        byte[] seedMask = mgf1(maskedDB, hLen);
        byte[] seed     = xorBytes(maskedSeed, seedMask);

        // Recover DB
        byte[] dbMask = mgf1(seed, maskedDB.length);
        byte[] db     = xorBytes(maskedDB, dbMask);

        // Verify lHash
        byte[] lHash         = SHA256.hash(label);
        byte[] lHashFromPad  = Arrays.copyOfRange(db, 0, hLen);
        if (!Arrays.equals(lHash, lHashFromPad)) {
            throw new IllegalArgumentException("Invalid OAEP: label hash mismatch");
        }

        // Find 0x01 separator
        int separatorIdx = -1;
        for (int i = hLen; i < db.length; i++) {
            if (db[i] == 0x01) { separatorIdx = i; break; }
            if (db[i] != 0x00) throw new IllegalArgumentException("Invalid OAEP: bad DB structure");
        }

        if (separatorIdx == -1) {
            throw new IllegalArgumentException("Invalid OAEP: no 0x01 separator found");
        }

        return Arrays.copyOfRange(db, separatorIdx + 1, db.length);
    }

    // =========================================================================
    //  MGF1 — Mask Generation Function (used in OAEP)
    //  MGF1(seed, length) using SHA-256
    // =========================================================================

    /**
     * Generates a pseudo-random mask of given length using SHA-256.
     * MGF1 works by hashing (seed || counter) repeatedly.
     */
    static byte[] mgf1(byte[] seed, int length) {
        int hLen    = SHA256_LEN;
        int numReps = (length + hLen - 1) / hLen; // ceil(length / hLen)
        byte[] result = new byte[numReps * hLen];

        for (int i = 0; i < numReps; i++) {
            // C = i encoded as 4-byte big-endian
            byte[] counter = {
                    (byte)(i >> 24), (byte)(i >> 16), (byte)(i >> 8), (byte)i
            };

            // Hash(seed || counter)
            byte[] input = concat(seed, counter);
            byte[] hash  = SHA256.hash(input);
            System.arraycopy(hash, 0, result, i * hLen, hLen);
        }

        return Arrays.copyOf(result, length);
    }

    // =========================================================================
    //  HELPER METHODS
    // =========================================================================

    /** Generates n random bytes, none of which are zero. */
    private static byte[] generateNonZeroRandomBytes(int length) {
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            byte b;
            do { b = (byte) RANDOM.nextInt(256); } while (b == 0);
            result[i] = b;
        }
        return result;
    }

    /** XORs two byte arrays of equal length. */
    private static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte)(a[i] ^ b[i]);
        }
        return result;
    }

    /** Concatenates two byte arrays. */
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    /**
     * Converts BigInteger to fixed-length byte array.
     * BigInteger.toByteArray() can add a leading 0x00 sign byte — we strip it.
     */
    private static byte[] toFixedBytes(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] result = new byte[length];

        if (raw.length <= length) {
            // Pad with leading zeros on the left
            System.arraycopy(raw, 0, result, length - raw.length, raw.length);
        } else {
            // Strip the leading 0x00 sign byte
            System.arraycopy(raw, raw.length - length, result, 0, length);
        }

        return result;
    }
}