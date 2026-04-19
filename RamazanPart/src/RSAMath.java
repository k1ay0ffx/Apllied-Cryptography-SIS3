import java.math.BigInteger;

/**
 * Low-level math utilities for RSA.
 * All operations implemented from scratch — no crypto libraries.
 */
public class RSAMath {

    private RSAMath() {} // utility class, no instances

    // -------------------------------------------------------------------------
    //  Extended Euclidean Algorithm
    //  Finds x such that: a*x ≡ 1 (mod m)
    //  Used to compute private exponent d = e^(-1) mod φ(n)
    // -------------------------------------------------------------------------

    /**
     * Computes the modular multiplicative inverse of a modulo m.
     * i.e. returns x such that (a * x) mod m == 1.
     *
     * @throws ArithmeticException if inverse does not exist (gcd(a, m) != 1)
     */
    public static BigInteger modInverse(BigInteger a, BigInteger m) {
        BigInteger[] result = extendedGcd(a, m);
        BigInteger gcd = result[0];
        BigInteger x   = result[1];

        if (!gcd.equals(BigInteger.ONE)) {
            throw new ArithmeticException(
                    "Modular inverse does not exist: gcd(" + a + ", " + m + ") = " + gcd
            );
        }

        // x might be negative — bring it into [0, m)
        return x.mod(m);
    }

    /**
     * Extended Euclidean Algorithm.
     * Returns [gcd, x, y] such that: a*x + m*y = gcd(a, m)
     *
     * Algorithm:
     *   Base case: gcd(a, 0) = a, x=1, y=0
     *   Recursive: gcd(a, m) = gcd(m, a mod m)
     *              x = y1
     *              y = x1 - (a/m)*y1
     */
    public static BigInteger[] extendedGcd(BigInteger a, BigInteger m) {
        // Base case
        if (m.equals(BigInteger.ZERO)) {
            return new BigInteger[]{ a, BigInteger.ONE, BigInteger.ZERO };
        }

        // Recursive call with (m, a mod m)
        BigInteger[] prev = extendedGcd(m, a.mod(m));
        BigInteger gcd = prev[0];
        BigInteger x1  = prev[1];
        BigInteger y1  = prev[2];

        // Back-substitute
        BigInteger x = y1;
        BigInteger y = x1.subtract(a.divide(m).multiply(y1));

        return new BigInteger[]{ gcd, x, y };
    }

    // -------------------------------------------------------------------------
    //  GCD — standard Euclidean algorithm
    // -------------------------------------------------------------------------

    /**
     * Computes GCD of a and b using Euclidean algorithm.
     * Used to verify gcd(e, φ(n)) == 1 during key generation.
     */
    public static BigInteger gcd(BigInteger a, BigInteger b) {
        while (!b.equals(BigInteger.ZERO)) {
            BigInteger temp = b;
            b = a.mod(b);
            a = temp;
        }
        return a;
    }

    // -------------------------------------------------------------------------
    //  Modular Exponentiation — square-and-multiply
    //  C = M^e mod n
    // -------------------------------------------------------------------------

    /**
     * Fast modular exponentiation using the square-and-multiply algorithm.
     * Time complexity: O(log exponent) multiplications.
     *
     * Used for:
     *   - Encryption:  C = M^e mod n
     *   - Decryption:  M = C^d mod n
     *   - Signatures:  S = H^d mod n, M' = S^e mod n
     */
    public static BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus) {
        if (modulus.equals(BigInteger.ONE)) {
            return BigInteger.ZERO; // anything mod 1 = 0
        }

        BigInteger result = BigInteger.ONE;
        base = base.mod(modulus); // reduce base first

        while (exponent.compareTo(BigInteger.ZERO) > 0) {
            // If current bit of exponent is 1 → multiply result by base
            if (exponent.testBit(0)) {
                result = result.multiply(base).mod(modulus);
            }
            // Square the base and shift exponent right by 1 bit
            exponent = exponent.shiftRight(1);
            base = base.multiply(base).mod(modulus);
        }

        return result;
    }

    // -------------------------------------------------------------------------
    //  Validation helpers
    // -------------------------------------------------------------------------

    /**
     * Verifies that e and d are valid key pair components:
     * (e * d) mod phi == 1
     */
    public static boolean verifyKeyPair(BigInteger e, BigInteger d, BigInteger phi) {
        return e.multiply(d).mod(phi).equals(BigInteger.ONE);
    }

    /**
     * Checks that two primes are sufficiently different.
     * |p - q| must be > 2^(keySize/2 - 100) to avoid Fermat factorization.
     */
    public static boolean primesAreSafe(BigInteger p, BigInteger q, int keySize) {
        BigInteger diff = p.subtract(q).abs();
        BigInteger threshold = BigInteger.TWO.pow(keySize / 2 - 100);
        return diff.compareTo(threshold) > 0;
    }
}