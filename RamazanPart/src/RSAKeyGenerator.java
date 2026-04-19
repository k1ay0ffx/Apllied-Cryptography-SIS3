import java.math.BigInteger;

/**
 * RSA Key Generator.
 * Takes two primes p and q (from teammate's PrimeGenerator),
 * and produces a complete RSAKeyPair.
 *
 * Supports: 1024, 2048, 4096-bit RSA.
 */
public class RSAKeyGenerator {

    // Standard public exponent — used in all real-world RSA (e.g. OpenSSL)
    private static final BigInteger E = BigInteger.valueOf(65537);

    // Allowed key sizes
    private static final int[] VALID_KEY_SIZES = {1024, 2048, 4096};

    // -------------------------------------------------------------------------
    //  Main entry point
    // -------------------------------------------------------------------------

    /**
     * Generates an RSA key pair from two primes provided by teammate.
     *
     * @param p       first prime  (512 bits for 1024-bit RSA, etc.)
     * @param q       second prime (same bit length as p)
     * @param keySize total key size in bits (1024, 2048, or 4096)
     * @return complete RSAKeyPair with CRT parameters
     */
    public static RSAKeyPair generate(BigInteger p, BigInteger q, int keySize) {
        validateKeySize(keySize);
        validatePrimes(p, q, keySize);

        // Step 1: n = p * q
        BigInteger n = p.multiply(q);

        // Step 2: φ(n) = (p-1)(q-1)
        BigInteger phi = computePhi(p, q);

        // Step 3: Choose e = 65537, verify gcd(e, φ(n)) = 1
        BigInteger e = choosePublicExponent(phi);

        // Step 4: d = e^(-1) mod φ(n)
        BigInteger d = RSAMath.modInverse(e, phi);

        // Step 5: Verify correctness
        if (!RSAMath.verifyKeyPair(e, d, phi)) {
            throw new IllegalStateException("Key generation failed: e*d mod phi != 1");
        }

        // Step 6: Build and return key pair (CRT params computed inside constructor)
        return new RSAKeyPair(p, q, e, d, keySize);
    }

    // -------------------------------------------------------------------------
    //  Key generation steps
    // -------------------------------------------------------------------------

    /**
     * Computes Euler's totient: φ(n) = (p-1)(q-1)
     */
    private static BigInteger computePhi(BigInteger p, BigInteger q) {
        return p.subtract(BigInteger.ONE)
                .multiply(q.subtract(BigInteger.ONE));
    }

    /**
     * Selects public exponent e.
     * We always try e = 65537 first (standard choice).
     * If gcd(e, phi) != 1 (very rare), we search for next valid e.
     */
    private static BigInteger choosePublicExponent(BigInteger phi) {
        BigInteger e = E;

        // 65537 almost always works, but just in case:
        while (!RSAMath.gcd(e, phi).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.TWO); // try next odd number
        }

        return e;
    }

    // -------------------------------------------------------------------------
    //  Validation
    // -------------------------------------------------------------------------

    /**
     * Validates that p and q are suitable for RSA key generation.
     */
    private static void validatePrimes(BigInteger p, BigInteger q, int keySize) {
        int halfKeySize = keySize / 2;

        // p and q must be distinct
        if (p.equals(q)) {
            throw new IllegalArgumentException("p and q must be distinct primes");
        }

        // Each prime should be approximately keySize/2 bits
        int pBits = p.bitLength();
        int qBits = q.bitLength();
        if (pBits != halfKeySize || qBits != halfKeySize) {
            throw new IllegalArgumentException(String.format(
                    "Expected %d-bit primes, got p=%d bits, q=%d bits",
                    halfKeySize, pBits, qBits
            ));
        }

        // |p - q| must be large enough to resist Fermat's factorization
        if (!RSAMath.primesAreSafe(p, q, keySize)) {
            throw new IllegalArgumentException(
                    "Primes p and q are too close — vulnerable to Fermat factorization"
            );
        }
    }

    /**
     * Checks that requested key size is one of the supported values.
     */
    private static void validateKeySize(int keySize) {
        for (int valid : VALID_KEY_SIZES) {
            if (keySize == valid) return;
        }
        throw new IllegalArgumentException(
                "Unsupported key size: " + keySize + ". Use 1024, 2048, or 4096."
        );
    }

    // -------------------------------------------------------------------------
    //  Info display
    // -------------------------------------------------------------------------

    /**
     * Prints key pair info to console (for debugging/demo purposes).
     */
    public static void printKeyInfo(RSAKeyPair keyPair) {
        System.out.println("=== RSA Key Info ===");
        System.out.println("Key size : " + keyPair.getKeySize() + " bits");
        System.out.println("e        : " + keyPair.getEHex());
        System.out.println("n        : " + keyPair.getNHex().substring(0, 32) + "...");
        System.out.println("d        : " + keyPair.getDHex().substring(0, 32) + "...");
        System.out.println("CRT      : " + (keyPair.hasCRTParams() ? "enabled" : "disabled"));
        System.out.println("====================");
    }
}
