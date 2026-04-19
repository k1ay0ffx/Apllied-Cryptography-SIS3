import java.math.BigInteger;

/**
 * RSA Decryption using Chinese Remainder Theorem (CRT).
 *
 * Standard decryption: M = C^d mod n   — slow (d is huge, ~2048 bits)
 * CRT decryption:      ~4x faster by splitting into two smaller exponentiations
 *
 * Bonus: +4 points
 *
 * Required CRT parameters (precomputed in RSAKeyPair):
 *   dp   = d mod (p-1)
 *   dq   = d mod (q-1)
 *   qInv = q^(-1) mod p
 */
public class RSACrt {

    private RSACrt() {}

    /**
     * Decrypts ciphertext using the Chinese Remainder Theorem.
     *
     * Algorithm:
     *   1. m1 = C^dp mod p        (small exponent, small modulus)
     *   2. m2 = C^dq mod q        (small exponent, small modulus)
     *   3. h  = qInv * (m1 - m2) mod p
     *   4. M  = m2 + h * q
     *
     * Why it's faster:
     *   - Instead of one C^d mod n  (d = 2048 bits, n = 2048 bits)
     *   - We do two C^dp mod p + C^dq mod q  (each 1024 bits)
     *   - Each sub-operation is ~4x faster → total ~4x speedup
     *
     * @param ciphertext  C as BigInteger
     * @param keyPair     must have CRT params (dp, dq, qInv, p, q)
     * @return            decrypted message M as BigInteger
     */
    public static BigInteger decryptCRT(BigInteger ciphertext, RSAKeyPair keyPair) {
        if (!keyPair.hasCRTParams()) {
            throw new IllegalStateException(
                    "CRT parameters not available — use standard decryption instead"
            );
        }

        BigInteger p    = keyPair.getP();
        BigInteger q    = keyPair.getQ();
        BigInteger dp   = keyPair.getDp();
        BigInteger dq   = keyPair.getDq();
        BigInteger qInv = keyPair.getQInv();

        // Step 1: m1 = C^dp mod p
        BigInteger m1 = RSAMath.modExp(ciphertext.mod(p), dp, p);

        // Step 2: m2 = C^dq mod q
        BigInteger m2 = RSAMath.modExp(ciphertext.mod(q), dq, q);

        // Step 3: h = qInv * (m1 - m2) mod p
        // Note: (m1 - m2) can be negative → add p to ensure positive
        BigInteger diff = m1.subtract(m2);
        if (diff.signum() < 0) {
            diff = diff.add(p);
        }
        BigInteger h = qInv.multiply(diff).mod(p);

        // Step 4: M = m2 + h * q
        return m2.add(h.multiply(q));
    }

    /**
     * Runs a performance benchmark comparing standard vs CRT decryption.
     * Prints timing results to console.
     *
     * @param keyPair    key pair with CRT params
     * @param ciphertext sample ciphertext to decrypt
     * @param rounds     number of decryption rounds to average
     */
    public static void benchmark(RSAKeyPair keyPair, BigInteger ciphertext, int rounds) {
        System.out.println("=== CRT Benchmark (" + keyPair.getKeySize() + "-bit key, " + rounds + " rounds) ===");

        // Standard decryption
        long startStd = System.currentTimeMillis();
        for (int i = 0; i < rounds; i++) {
            RSAMath.modExp(ciphertext, keyPair.getD(), keyPair.getN());
        }
        long timeStd = System.currentTimeMillis() - startStd;

        // CRT decryption
        long startCrt = System.currentTimeMillis();
        for (int i = 0; i < rounds; i++) {
            decryptCRT(ciphertext, keyPair);
        }
        long timeCrt = System.currentTimeMillis() - startCrt;

        System.out.printf("Standard : %d ms total, %.1f ms/op%n",
                timeStd, (double) timeStd / rounds);
        System.out.printf("CRT      : %d ms total, %.1f ms/op%n",
                timeCrt, (double) timeCrt / rounds);
        System.out.printf("Speedup  : %.2fx%n", (double) timeStd / timeCrt);
        System.out.println("==========================================");
    }

    /**
     * Verifies CRT result matches standard decryption.
     * Used for testing correctness.
     *
     * @return true if both methods produce the same result
     */
    public static boolean verify(BigInteger ciphertext, RSAKeyPair keyPair) {
        BigInteger standard = RSAMath.modExp(ciphertext, keyPair.getD(), keyPair.getN());
        BigInteger crt      = decryptCRT(ciphertext, keyPair);
        return standard.equals(crt);
    }
}