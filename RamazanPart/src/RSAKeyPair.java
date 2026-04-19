import java.math.BigInteger;
import java.io.*;
import java.util.Properties;

public class RSAKeyPair {

    // -------------------------------------------------------------------------
    //  Public fields — accessed directly by RSAEngineStub, RSAConsole, RSASignature
    // -------------------------------------------------------------------------

    public final BigInteger n;       // modulus
    public final BigInteger e;       // public exponent (usually 65537)
    public final BigInteger d;       // private exponent (null for public-only key)
    public final BigInteger p;       // first prime  (null if not available)
    public final BigInteger q;       // second prime (null if not available)

    /** Key size in bits — accessed as field by RSAConsole and RSASignature. */
    public final int bitLength;

    // -------------------------------------------------------------------------
    //  CRT parameters (precomputed for fast decryption)
    // -------------------------------------------------------------------------

    private final BigInteger dp;    // d mod (p-1)
    private final BigInteger dq;    // d mod (q-1)
    private final BigInteger qInv;  // q^(-1) mod p

    // =========================================================================
    //  Constructors
    // =========================================================================

    /**
     * Full constructor with all five components.
     * Used by RSAKeyGenerator and RSAEngineStub: new RSAKeyPair(p, q, e, d, keySize)
     */
    public RSAKeyPair(BigInteger p, BigInteger q, BigInteger e, BigInteger d, int keySize) {
        this.p = p;
        this.q = q;
        this.e = e;
        this.d = d;
        this.n = p.multiply(q);
        this.bitLength = keySize;

        // Precompute CRT parameters
        this.dp   = d.mod(p.subtract(BigInteger.ONE));
        this.dq   = d.mod(q.subtract(BigInteger.ONE));
        this.qInv = ModularArithmetic.modInverse(q, p);
    }

    /**
     * Constructor with (n, e, d, p, q) — used by RSAEngineStub.generateKeyPair():
     *   return new RSAKeyPair(n, e, d, p, q);
     * keySize is derived from n.bitLength().
     */
    public RSAKeyPair(BigInteger n, BigInteger e, BigInteger d, BigInteger p, BigInteger q) {
        this.n = n;
        this.e = e;
        this.d = d;
        this.p = p;
        this.q = q;
        this.bitLength = n.bitLength();

        if (p != null && q != null && d != null) {
            this.dp   = d.mod(p.subtract(BigInteger.ONE));
            this.dq   = d.mod(q.subtract(BigInteger.ONE));
            this.qInv = ModularArithmetic.modInverse(q, p);
        } else {
            this.dp   = null;
            this.dq   = null;
            this.qInv = null;
        }
    }

    /**
     * Minimal constructor — only n, e, d (no CRT).
     * Used when loading a public/private key from file.
     */
    public RSAKeyPair(BigInteger n, BigInteger e, BigInteger d, int keySize) {
        this.n = n;
        this.e = e;
        this.d = d;
        this.p    = null;
        this.q    = null;
        this.dp   = null;
        this.dq   = null;
        this.qInv = null;
        this.bitLength = keySize;
    }

    /**
     * Public-only constructor — no private key.
     * Used when loading a public key from file.
     */
    public RSAKeyPair(BigInteger n, BigInteger e, int keySize) {
        this(n, e, null, keySize);
    }

    // =========================================================================
    //  Convenience queries
    // =========================================================================

    /** Returns true if the private exponent d is available. */
    public boolean hasPrivateKey() {
        return d != null;
    }

    /** Returns true if prime factors p and q are available. */
    public boolean hasFactors() {
        return p != null && q != null;
    }

    /** Returns true if all CRT parameters are available for fast decryption. */
    public boolean hasCRTParams() {
        return dp != null && dq != null && qInv != null;
    }

    // =========================================================================
    //  Getters (used by RSAEncryption, RSACrt, RSAKeyGenerator)
    // =========================================================================

    public BigInteger getN()    { return n; }
    public BigInteger getE()    { return e; }
    public BigInteger getD()    { return d; }
    public BigInteger getP()    { return p; }
    public BigInteger getQ()    { return q; }
    public BigInteger getDp()   { return dp; }
    public BigInteger getDq()   { return dq; }
    public BigInteger getQInv() { return qInv; }
    public int getKeySize()     { return bitLength; }

    // =========================================================================
    //  File I/O  (used by RSAConsole)
    // =========================================================================

    /**
     * Saves the public key (n, e) to a .properties file.
     */
    public void savePublicKey(String path) throws IOException {
        Properties props = new Properties();
        props.setProperty("n",       n.toString(16));
        props.setProperty("e",       e.toString(16));
        props.setProperty("keySize", String.valueOf(bitLength));
        try (OutputStream out = new FileOutputStream(path)) {
            props.store(out, "RSA Public Key");
        }
    }

    /**
     * Saves the full private key (n, e, d) to a .properties file.
     * Throws IllegalStateException if private key is not available.
     */
    public void savePrivateKey(String path) throws IOException {
        if (!hasPrivateKey()) {
            throw new IllegalStateException("No private key available to save.");
        }
        Properties props = new Properties();
        props.setProperty("n",       n.toString(16));
        props.setProperty("e",       e.toString(16));
        props.setProperty("d",       d.toString(16));
        props.setProperty("keySize", String.valueOf(bitLength));
        if (hasFactors()) {
            props.setProperty("p", p.toString(16));
            props.setProperty("q", q.toString(16));
        }
        try (OutputStream out = new FileOutputStream(path)) {
            props.store(out, "RSA Private Key");
        }
    }

    /**
     * Loads an RSAKeyPair from a .properties file.
     * Supports both public-only and full private key files.
     */
    public static RSAKeyPair loadFromFile(String path) throws IOException {
        Properties props = new Properties();
        try (InputStream in = new FileInputStream(path)) {
            props.load(in);
        }

        BigInteger n       = new BigInteger(props.getProperty("n"), 16);
        BigInteger e       = new BigInteger(props.getProperty("e"), 16);
        int        keySize = Integer.parseInt(props.getProperty("keySize",
                String.valueOf(n.bitLength())));

        String dHex = props.getProperty("d");
        if (dHex == null) {
            return new RSAKeyPair(n, e, keySize); // public only
        }

        BigInteger d = new BigInteger(dHex, 16);

        String pHex = props.getProperty("p");
        String qHex = props.getProperty("q");
        if (pHex != null && qHex != null) {
            BigInteger p = new BigInteger(pHex, 16);
            BigInteger q = new BigInteger(qHex, 16);
            return new RSAKeyPair(p, q, e, d, keySize);
        }

        return new RSAKeyPair(n, e, d, keySize);
    }

    // =========================================================================
    //  Display helpers
    // =========================================================================

    /** Returns modulus n as uppercase hex string. */
    public String getNHex() { return n.toString(16).toUpperCase(); }

    /** Returns public exponent e as uppercase hex string. */
    public String getEHex() { return e.toString(16).toUpperCase(); }

    /** Returns private exponent d as uppercase hex string. */
    public String getDHex() {
        return d != null ? d.toString(16).toUpperCase() : "(not available)";
    }

    /**
     * Human-readable summary — used by RSAConsole.toDisplayString().
     */
    public String toDisplayString() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== RSA Key (").append(bitLength).append("-bit) ===\n");
        sb.append("n = ").append(getNHex(), 0, Math.min(32, getNHex().length())).append("...\n");
        sb.append("e = ").append(getEHex()).append("\n");
        if (hasPrivateKey()) {
            sb.append("d = ").append(getDHex(), 0, Math.min(32, getDHex().length())).append("...\n");
        }
        sb.append("Private key : ").append(hasPrivateKey() ? "yes" : "no").append("\n");
        sb.append("Factors p,q : ").append(hasFactors()     ? "yes" : "no").append("\n");
        sb.append("CRT params  : ").append(hasCRTParams()   ? "yes" : "no").append("\n");
        return sb.toString();
    }

    @Override
    public String toString() {
        return String.format(
                "RSAKeyPair { %d-bit, e=%s, CRT=%s, private=%s }",
                bitLength, getEHex(), hasCRTParams(), hasPrivateKey()
        );
    }
}