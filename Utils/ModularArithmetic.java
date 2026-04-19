import java.math.BigInteger;

/**
 * Modular Arithmetic Operations — Section 2.2
 *
 * Provides all modular arithmetic primitives needed for RSA:
 *   2.2.1  Modular exponentiation  (square-and-multiply)
 *   2.2.2  Extended Euclidean algorithm  (→ modular inverse)
 *   2.2.3  GCD  (Euclidean algorithm)
 *
 * No cryptographic libraries used. Only BigInteger basic arithmetic.
 */
public class ModularArithmetic {

    // Convenience constants
    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE  = BigInteger.ONE;
    private static final BigInteger TWO  = BigInteger.TWO;

    // =========================================================================
    // 2.2.1  Modular Exponentiation  (square-and-multiply, right-to-left)
    // =========================================================================

    /**
     * Computes  base^exponent mod modulus  efficiently.
     *
     * Algorithm (right-to-left binary method):
     *
     *   result = 1
     *   base   = base mod modulus
     *   while exponent > 0:
     *       if exponent is odd:
     *           result = (result × base) mod modulus
     *       exponent = exponent >> 1          // drop the lowest bit
     *       base     = (base × base) mod modulus   // square
     *   return result
     *
     * Why it works: we decompose the exponent bit-by-bit from LSB to MSB.
     * Each iteration either includes or skips the current power-of-two factor
     * of base, accumulating the product only for bits that are 1.
     *
     * Complexity: O(log exponent) multiplications mod modulus.
     *
     * @param base      the base  (≥ 0)
     * @param exponent  the exponent  (≥ 0)
     * @param modulus   the modulus  (> 1)
     * @return          base^exponent mod modulus
     */
    public static BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus) {
        if (modulus.equals(ONE)) return ZERO;         // everything mod 1 == 0
        if (exponent.signum() < 0) {
            throw new IllegalArgumentException("Negative exponents require modular inverse; use modInverse() first.");
        }

        BigInteger result = ONE;
        base = base.mod(modulus);       // reduce base first

        while (exponent.signum() > 0) {

            if (exponent.testBit(0)) {                          // bit is 1 → multiply in
                result = result.multiply(base).mod(modulus);
            }

            exponent = exponent.shiftRight(1);                  // exponent >>= 1
            base     = base.multiply(base).mod(modulus);        // base = base^2 mod m
        }

        return result;
    }

    // =========================================================================
    // 2.2.3  GCD  (placed before 2.2.2 because ExtGCD builds on it)
    // =========================================================================

    /**
     * Computes GCD(a, b) using the iterative Euclidean algorithm.
     *
     * Algorithm:
     *   while b ≠ 0:
     *       temp = b
     *       b    = a mod b
     *       a    = temp
     *   return a
     *
     * Key insight: GCD(a, b) == GCD(b, a mod b).
     * We keep replacing the larger number with the remainder until the
     * remainder is 0; the last non-zero value is the GCD.
     *
     * @param a  first operand  (≥ 0)
     * @param b  second operand  (≥ 0)
     * @return   GCD(a, b)
     */
    public static BigInteger gcd(BigInteger a, BigInteger b) {
        a = a.abs();
        b = b.abs();

        while (!b.equals(ZERO)) {
            BigInteger temp = b;
            b = a.mod(b);
            a = temp;
        }

        return a;   // a holds GCD when b reaches 0
    }

    // =========================================================================
    // 2.2.2  Extended Euclidean Algorithm  →  Modular Multiplicative Inverse
    // =========================================================================

    /**
     * Result carrier for the Extended Euclidean Algorithm.
     *
     * Holds (gcd, x, y) such that:   a*x + b*y = gcd(a, b)
     */
    public static class ExtGCDResult {
        public final BigInteger gcd;   // GCD(a, b)
        public final BigInteger x;     // Bézout coefficient for a
        public final BigInteger y;     // Bézout coefficient for b

        ExtGCDResult(BigInteger gcd, BigInteger x, BigInteger y) {
            this.gcd = gcd;
            this.x   = x;
            this.y   = y;
        }

        @Override
        public String toString() {
            return String.format("ExtGCDResult { gcd=%s, x=%s, y=%s }", gcd, x, y);
        }
    }

    /**
     * Extended Euclidean Algorithm.
     *
     * Finds (gcd, x, y) satisfying the Bézout identity:
     *        a*x + b*y = gcd(a, b)
     *
     * Algorithm (iterative, avoids recursion-stack issues for large inputs):
     *
     *   (old_r, r) = (a, b)
     *   (old_s, s) = (1, 0)      ← tracks Bézout coeff for a
     *   (old_t, t) = (0, 1)      ← tracks Bézout coeff for b
     *
     *   while r ≠ 0:
     *       q      = old_r div r
     *       (old_r, r) = (r, old_r - q*r)
     *       (old_s, s) = (s, old_s - q*s)
     *       (old_t, t) = (t, old_t - q*t)
     *
     *   return (old_r, old_s, old_t)   // (gcd, x, y)
     *
     * @param a  first operand
     * @param b  second operand
     * @return   ExtGCDResult with gcd, x, y
     */
    public static ExtGCDResult extGCD(BigInteger a, BigInteger b) {
        BigInteger oldR = a, r = b;
        BigInteger oldS = ONE,  s = ZERO;   // Bézout coeff for a
        BigInteger oldT = ZERO, t = ONE;    // Bézout coeff for b

        while (!r.equals(ZERO)) {
            BigInteger q = oldR.divide(r);

            BigInteger tempR = r;
            r    = oldR.subtract(q.multiply(r));
            oldR = tempR;

            BigInteger tempS = s;
            s    = oldS.subtract(q.multiply(s));
            oldS = tempS;

            BigInteger tempT = t;
            t    = oldT.subtract(q.multiply(t));
            oldT = tempT;
        }

        // Bézout identity: a*oldS + b*oldT == oldR (== gcd)
        return new ExtGCDResult(oldR, oldS, oldT);
    }

    /**
     * Computes the modular multiplicative inverse of {@code a} modulo {@code m}.
     *
     * Finds x such that:   a * x ≡ 1 (mod m)
     *
     * This is used in RSA to compute:   d = e^(-1) mod φ(n)
     *
     * Throws ArithmeticException if the inverse does not exist
     * (i.e. GCD(a, m) ≠ 1 — a and m are not coprime).
     *
     * @param a  the value to invert  (must be coprime with m)
     * @param m  the modulus  (> 1)
     * @return   x ∈ [1, m-1] such that (a * x) mod m == 1
     */
    public static BigInteger modInverse(BigInteger a, BigInteger m) {
        if (m.compareTo(ONE) <= 0) {
            throw new IllegalArgumentException("Modulus must be > 1.");
        }

        a = a.mod(m);   // normalize a into [0, m-1]

        ExtGCDResult result = extGCD(a, m);

        if (!result.gcd.equals(ONE)) {
            throw new ArithmeticException(
                String.format("Modular inverse does not exist: GCD(%s, %s) = %s ≠ 1",
                    a, m, result.gcd));
        }

        // result.x might be negative; bring it into [0, m-1]
        return result.x.mod(m);
    }

    // =========================================================================
    // Demo / Self-test
    // =========================================================================

    public static void main(String[] args) {
        System.out.println("=== 2.2.1  Modular Exponentiation ===");
        runModExpTests();

        System.out.println("\n=== 2.2.3  GCD ===");
        runGCDTests();

        System.out.println("\n=== 2.2.2  Extended GCD & Modular Inverse ===");
        runExtGCDTests();

        System.out.println("\n=== RSA Key-gen dry run (d = e^-1 mod φ(n)) ===");
        runRSADryRun();
    }

    // -------------------------------------------------------------------------

    private static void runModExpTests() {
        // Known results (easy to verify by hand or calculator):
        //   2^10 mod 1000 = 1024 mod 1000 = 24
        //   3^200 mod 50 = ?  (Fermat/Euler: 3^20 ≡ 1 mod 50 → 3^200 ≡ 1)
        //   5^0  mod 7   = 1
        //   0^0  mod 99  = 1  (convention)

        long[][] cases = {
            {2, 10, 1000,  24},
            {3, 200, 50,    1},
            {5, 0,   7,     1},
            {7, 1,   13,    7},
            {12, 3,  97,   (12L*12*12) % 97},   // 1728 % 97 = 63
        };

        for (long[] c : cases) {
            BigInteger base = BigInteger.valueOf(c[0]);
            BigInteger exp  = BigInteger.valueOf(c[1]);
            BigInteger mod  = BigInteger.valueOf(c[2]);
            BigInteger expected = BigInteger.valueOf(c[3]);

            BigInteger result = modExp(base, exp, mod);
            String status = result.equals(expected) ? "PASS ✓" : "FAIL ✗";
            System.out.printf("  %s^%s mod %s = %s  (expected %s) [%s]%n",
                base, exp, mod, result, expected, status);
        }

        // Large number test: Fermat's little theorem — a^(p-1) ≡ 1 (mod p) for prime p
        BigInteger p = new BigInteger("104729");  // a prime
        BigInteger a = BigInteger.valueOf(12345);
        BigInteger fermat = modExp(a, p.subtract(ONE), p);
        System.out.printf("  Fermat check: %s^(p-1) mod %s = %s  [%s]%n",
            a, p, fermat, fermat.equals(ONE) ? "PASS ✓" : "FAIL ✗");
    }

    // -------------------------------------------------------------------------

    private static void runGCDTests() {
        long[][] cases = {
            {48,  18,  6},
            {100, 75, 25},
            {17,  13,  1},    // coprime
            {0,   5,   5},
            {252, 198, 18},
        };

        for (long[] c : cases) {
            BigInteger a = BigInteger.valueOf(c[0]);
            BigInteger b = BigInteger.valueOf(c[1]);
            BigInteger expected = BigInteger.valueOf(c[2]);

            BigInteger result = gcd(a, b);
            String status = result.equals(expected) ? "PASS ✓" : "FAIL ✗";
            System.out.printf("  GCD(%s, %s) = %s  (expected %s) [%s]%n",
                a, b, result, expected, status);
        }
    }

    // -------------------------------------------------------------------------

    private static void runExtGCDTests() {
        // extGCD: verify Bézout identity  a*x + b*y == gcd
        long[][] pairs = {{35, 15}, {17, 13}, {240, 46}, {1000, 999}};

        for (long[] p : pairs) {
            BigInteger a = BigInteger.valueOf(p[0]);
            BigInteger b = BigInteger.valueOf(p[1]);
            ExtGCDResult r = extGCD(a, b);

            BigInteger check = a.multiply(r.x).add(b.multiply(r.y));
            boolean ok = check.equals(r.gcd);
            System.out.printf("  extGCD(%s,%s): gcd=%s, x=%s, y=%s  →  %s*x+%s*y=%s [%s]%n",
                a, b, r.gcd, r.x, r.y, a, b, check, ok ? "PASS ✓" : "FAIL ✗");
        }

        System.out.println();

        // modInverse tests: verify  (a * inv) mod m == 1
        long[][] invCases = {
            {3, 7},    // 3*5=15 ≡ 1 (mod 7)   → 5
            {17, 3120}, // RSA-like: e=17, φ(n)=3120 → classic textbook example
            {65537, 999999937},  // common RSA public exponent e, arbitrary prime modulus
        };

        for (long[] c : invCases) {
            BigInteger a = BigInteger.valueOf(c[0]);
            BigInteger m = BigInteger.valueOf(c[1]);
            try {
                BigInteger inv = modInverse(a, m);
                BigInteger verify = a.multiply(inv).mod(m);
                boolean ok = verify.equals(ONE);
                System.out.printf("  modInverse(%s, %s) = %s  →  verify=%s [%s]%n",
                    a, m, inv, verify, ok ? "PASS ✓" : "FAIL ✗");
            } catch (ArithmeticException ex) {
                System.out.printf("  modInverse(%s, %s): %s%n", a, m, ex.getMessage());
            }
        }

        // Edge case: inverse doesn't exist
        try {
            modInverse(BigInteger.valueOf(6), BigInteger.valueOf(9));  // GCD(6,9)=3
            System.out.println("  [FAIL] Should have thrown for GCD≠1");
        } catch (ArithmeticException ex) {
            System.out.printf("  Expected exception: %s [PASS ✓]%n", ex.getMessage());
        }
    }

    // -------------------------------------------------------------------------

    private static void runRSADryRun() {
        // Mini RSA with small primes to verify the whole pipeline end-to-end:
        //   p=61, q=53  →  n=3233, φ(n)=(61-1)(53-1)=3120, e=17
        //   d = 17^(-1) mod 3120 = 2753
        //   Encrypt 65:  65^17 mod 3233 = 2790
        //   Decrypt:     2790^2753 mod 3233 = 65

        BigInteger p     = BigInteger.valueOf(61);
        BigInteger q     = BigInteger.valueOf(53);
        BigInteger n     = p.multiply(q);
        BigInteger phi   = p.subtract(ONE).multiply(q.subtract(ONE));
        BigInteger e     = BigInteger.valueOf(17);
        BigInteger d     = modInverse(e, phi);

        System.out.printf("  p=%s, q=%s, n=%s, φ(n)=%s%n", p, q, n, phi);
        System.out.printf("  e=%s, d=%s  (verify e*d mod φ(n) = %s)%n",
            e, d, e.multiply(d).mod(phi));

        BigInteger msg       = BigInteger.valueOf(65);
        BigInteger cipher    = modExp(msg, e, n);
        BigInteger decrypted = modExp(cipher, d, n);

        System.out.printf("  Plaintext:  %s%n", msg);
        System.out.printf("  Ciphertext: %s%n", cipher);
        System.out.printf("  Decrypted:  %s  [%s]%n",
            decrypted, decrypted.equals(msg) ? "PASS ✓" : "FAIL ✗");
    }
}