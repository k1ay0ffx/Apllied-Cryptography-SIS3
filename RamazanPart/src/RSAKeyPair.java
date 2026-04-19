import java.math.BigInteger;


public class RSAKeyPair {

    // --- Public key ---
    private final BigInteger n;  // modulus
    private final BigInteger e;  // public exponent (usually 65537)

    // --- Private key ---
    private final BigInteger d;  // private exponent

    // --- CRT parameters (optional, for fast decryption) ---
    private final BigInteger p;     // first prime
    private final BigInteger q;     // second prime
    private final BigInteger dp;    // d mod (p-1)
    private final BigInteger dq;    // d mod (q-1)
    private final BigInteger qInv;  // q^(-1) mod p

    // Bit length of the key (1024, 2048, 4096)
    private final int keySize;

    /**
     * Full constructor — used when p and q are known (normal key generation).
     */
    public RSAKeyPair(BigInteger p, BigInteger q, BigInteger e, BigInteger d, int keySize) {
        this.p = p;
        this.q = q;
        this.e = e;
        this.d = d;
        this.n = p.multiply(q);
        this.keySize = keySize;

        // Precompute CRT parameters
        this.dp   = d.mod(p.subtract(BigInteger.ONE));
        this.dq   = d.mod(q.subtract(BigInteger.ONE));
        this.qInv = RSAMath.modInverse(q, p); // q^(-1) mod p
    }

    /**
     * Minimal constructor — only n, e, d (no CRT).
     * Used when loading a public/private key from file.
     */
    public RSAKeyPair(BigInteger n, BigInteger e, BigInteger d, int keySize) {
        this.n = n;
        this.e = e;
        this.d = d;
        this.keySize = keySize;
        // CRT params unavailable
        this.p    = null;
        this.q    = null;
        this.dp   = null;
        this.dq   = null;
        this.qInv = null;
    }

    // -------------------------------------------------------------------------
    //  Getters
    // -------------------------------------------------------------------------

    public BigInteger getN()    { return n; }
    public BigInteger getE()    { return e; }
    public BigInteger getD()    { return d; }
    public BigInteger getP()    { return p; }
    public BigInteger getQ()    { return q; }
    public BigInteger getDp()   { return dp; }
    public BigInteger getDq()   { return dq; }
    public BigInteger getQInv() { return qInv; }
    public int getKeySize()     { return keySize; }

    /** Returns true if CRT parameters are available for fast decryption. */
    public boolean hasCRTParams() {
        return p != null && q != null && dp != null && dq != null && qInv != null;
    }

    // -------------------------------------------------------------------------
    //  Display helpers
    // -------------------------------------------------------------------------

    /** Returns modulus n as uppercase hex string. */
    public String getNHex() { return n.toString(16).toUpperCase(); }

    /** Returns public exponent e as uppercase hex string. */
    public String getEHex() { return e.toString(16).toUpperCase(); }

    /** Returns private exponent d as uppercase hex string. */
    public String getDHex() { return d.toString(16).toUpperCase(); }

    @Override
    public String toString() {
        return String.format(
                "RSAKeyPair {\n" +
                        "  keySize = %d bits\n" +
                        "  n       = %s...\n" +
                        "  e       = %s\n" +
                        "  d       = %s...\n" +
                        "  CRT     = %s\n" +
                        "}",
                keySize,
                getNHex().substring(0, Math.min(32, getNHex().length())),
                getEHex(),
                getDHex().substring(0, Math.min(32, getDHex().length())),
                hasCRTParams() ? "available" : "not available"
        );
    }
}
