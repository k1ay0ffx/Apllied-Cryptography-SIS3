import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Prime Number Generation System
 * Implements random prime generation using the Miller-Rabin primality test.
 * No cryptographic libraries used — all operations implemented from scratch.
 */
public class PrimeGenerator {

    // Cryptographically strong RNG (satisfies "from SIS 1 or improved" requirement)
    private final SecureRandom rng;

    // Small primes for fast pre-screening before Miller-Rabin
    private static final int[] SMALL_PRIMES = {
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
        53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
        109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
        173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233
    };

    public PrimeGenerator() {
        this.rng = new SecureRandom();
    }

    // -------------------------------------------------------------------------
    // 2.1.1  Random Odd Number Generation
    // -------------------------------------------------------------------------

    /**
     * Generates a random odd number of exactly {@code bitLength} bits.
     * <ul>
     *   <li>MSB (bit index bitLength-1) is set → guarantees the number is
     *       exactly bitLength bits wide.</li>
     *   <li>LSB (bit index 0) is set → guarantees the number is odd.</li>
     * </ul>
     *
     * @param bitLength  512, 1024, or 2048 (any positive value works)
     * @return           a BigInteger that is odd and exactly bitLength bits
     */
    public BigInteger generateRandomOddNumber(int bitLength) {
        if (bitLength < 3) {
            throw new IllegalArgumentException("Bit length must be at least 3.");
        }

        // Fill with random bits
        byte[] bytes = new byte[(bitLength + 7) / 8];
        rng.nextBytes(bytes);

        BigInteger candidate = new BigInteger(1, bytes); // positive

        // Mask to exactly bitLength bits (clear any extra high bits)
        BigInteger mask = BigInteger.ONE.shiftLeft(bitLength).subtract(BigInteger.ONE);
        candidate = candidate.and(mask);

        // Set the MSB  → ensures exactly bitLength bits
        candidate = candidate.setBit(bitLength - 1);

        // Set the LSB  → ensures the number is odd
        candidate = candidate.setBit(0);

        return candidate;
    }

    // -------------------------------------------------------------------------
    // 2.1.2  Miller-Rabin Primality Test
    // -------------------------------------------------------------------------

    /**
     * Performs the Miller-Rabin probabilistic primality test.
     *
     * Algorithm:
     *   1. Reject if n is even.
     *   2. Write n-1 = 2^r * d  (d odd).
     *   3. Repeat k times:
     *        a = random in [2, n-2]
     *        x = a^d mod n
     *        if x == 1 or x == n-1: continue (witness passed)
     *        for i in 1..r-1:
     *            x = x^2 mod n
     *            if x == n-1: break (witness passed)
     *        else: return COMPOSITE
     *   4. Return PROBABLY PRIME
     *
     * @param n  the candidate to test (must be odd and > 2)
     * @param k  number of witness rounds
     * @return   true  → probably prime (error prob ≤ 4^-k)
     *           false → definitely composite
     */
    public boolean millerRabin(BigInteger n, int k) {
        // --- Step 1: handle trivial cases ---
        if (n.compareTo(BigInteger.TWO) < 0)  return false;
        if (n.equals(BigInteger.TWO))          return true;
        if (n.mod(BigInteger.TWO).equals(BigInteger.ZERO)) return false;  // even → composite

        // Small prime pre-screen (fast rejection)
        for (int sp : SMALL_PRIMES) {
            BigInteger spBig = BigInteger.valueOf(sp);
            if (n.equals(spBig)) return true;
            if (n.mod(spBig).equals(BigInteger.ZERO)) return false;
        }

        // --- Step 2: write n-1 = 2^r * d ---
        BigInteger nMinus1 = n.subtract(BigInteger.ONE);
        int r = 0;
        BigInteger d = nMinus1;

        while (d.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            d = d.shiftRight(1);
            r++;
        }
        // invariant: n-1 == 2^r * d,  d is odd

        // --- Step 3: witness loop ---
        BigInteger nMinus2 = n.subtract(BigInteger.TWO);

        for (int i = 0; i < k; i++) {

            // Pick random witness a ∈ [2, n-2]
            BigInteger a = generateRandomInRange(BigInteger.TWO, nMinus2);

            // x = a^d mod n   (modular exponentiation — implemented below)
            BigInteger x = modPow(a, d, n);

            if (x.equals(BigInteger.ONE) || x.equals(nMinus1)) {
                continue; // this witness passed
            }

            boolean passedWitness = false;
            for (int j = 0; j < r - 1; j++) {
                x = modPow(x, BigInteger.TWO, n);   // x = x^2 mod n
                if (x.equals(nMinus1)) {
                    passedWitness = true;
                    break;
                }
            }

            if (!passedWitness) {
                return false; // definitely COMPOSITE
            }
        }

        return true; // PROBABLY PRIME
    }

    // -------------------------------------------------------------------------
    // 2.1.3  Prime Generation Process
    // -------------------------------------------------------------------------

    /**
     * Generates a prime of the given bit length.
     *
     * Process:
     *   1. Generate a random odd n-bit number.
     *   2. Test with Miller-Rabin using the required number of rounds.
     *   3. If composite, try again.
     *
     * @param bitLength  must be 512, 1024, or 2048 (any positive value accepted)
     * @return           a probably-prime BigInteger of exactly bitLength bits
     */
    public BigInteger generatePrime(int bitLength) {
        // Minimum rounds per spec:
        //   40 rounds for 512-bit
        //   64 rounds for 1024-bit and above
        int rounds = (bitLength >= 1024) ? 64 : 40;

        int attempts = 0;
        while (true) {
            attempts++;
            BigInteger candidate = generateRandomOddNumber(bitLength);

            if (millerRabin(candidate, rounds)) {
                System.out.printf("  Found prime after %d attempt(s).%n", attempts);
                return candidate;
            }
            // composite → try next candidate
        }
    }

    // -------------------------------------------------------------------------
    // Helper: Modular Exponentiation — delegates to ModularArithmetic (§2.2.1)
    // -------------------------------------------------------------------------

    /**
     * Computes base^exp mod m.
     * Delegates to {@link ModularArithmetic#modExp} so there is a single
     * canonical implementation used by both prime generation and RSA.
     */
    public BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
        return ModularArithmetic.modExp(base, exp, mod);
    }

    // -------------------------------------------------------------------------
    // Helper: Random BigInteger in [low, high] (inclusive)
    // -------------------------------------------------------------------------

    private BigInteger generateRandomInRange(BigInteger low, BigInteger high) {
        BigInteger range = high.subtract(low).add(BigInteger.ONE);
        int bits = range.bitLength();

        BigInteger result;
        do {
            result = new BigInteger(bits, rng);
        } while (result.compareTo(range) >= 0);

        return result.add(low);
    }

    // -------------------------------------------------------------------------
    // Demo / Test
    // -------------------------------------------------------------------------

    public static void main(String[] args) {
        PrimeGenerator pg = new PrimeGenerator();

        int[] bitSizes = {512, 1024, 2048};

        for (int bits : bitSizes) {
            System.out.printf("%n=== Generating %d-bit prime ===%n", bits);
            long start = System.currentTimeMillis();

            BigInteger prime = pg.generatePrime(bits);

            long elapsed = System.currentTimeMillis() - start;
            System.out.printf("  Bit length  : %d%n", prime.bitLength());
            System.out.printf("  Is odd      : %b%n", prime.testBit(0));
            System.out.printf("  MSB set     : %b%n", prime.testBit(bits - 1));
            System.out.printf("  Time (ms)   : %d%n", elapsed);
            System.out.printf("  Value (hex) : %s...%n",
                prime.toString(16).substring(0, Math.min(32, prime.toString(16).length())));

            // Sanity-check: re-run Miller-Rabin independently
            boolean check = pg.millerRabin(prime, 64);
            System.out.printf("  MR verify   : %s%n", check ? "PROBABLY PRIME ✓" : "FAILED ✗");
        }
    }
}