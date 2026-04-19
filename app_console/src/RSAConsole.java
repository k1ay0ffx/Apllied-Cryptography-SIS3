import java.math.BigInteger;
import java.nio.charset.*;
import java.nio.file.*;
import java.util.*;
import java.util.Base64;
/**
 * RSAConsole — полнофункциональное консольное приложение для RSA.
 *
 * Разделы меню:
 *   1. Key Management       — генерация, импорт/экспорт, отображение
 *   2. Encryption/Decryption — шифрование с PKCS#1 v1.5 и OAEP
 *   3. Digital Signatures   — подпись и верификация (PKCS1/PSS)
 *   4. Test Vectors         — все тест-категории из задания
 *   5. Performance          — замер скорости
 *   6. Security Demos       — демонстрация уязвимостей
 *   7. Exit
 *
 * Подключение другого разработчика:
 *   В Main.java замените: new RSAEngineStub() → new RSAEngine()
 */
public class RSAConsole {

    // ── Состояние приложения ──────────────────────────────────────────────────

    private final IRSAEngine engine;      // RSA-движок (стаб или реальный)
    private final Scanner    in;
    private RSAKeyPair       currentKey;  // текущий загруженный ключ

    public RSAConsole(IRSAEngine engine) {
        this.engine = engine;
        this.in     = new Scanner(System.in);
    }

    // ── Точка входа ───────────────────────────────────────────────────────────

    public void run() {
        banner();
        boolean running = true;
        while (running) {
            mainMenu();
            int choice = readInt("Select", 1, 7);
            switch (choice) {
                case 1 -> keyManagement();
                case 2 -> encryptionMenu();
                case 3 -> signaturesMenu();
                case 4 -> testVectorsMenu();
                case 5 -> performanceMenu();
                case 6 -> securityDemosMenu();
                case 7 -> running = false;
            }
        }
        System.out.println("\nGoodbye.");
    }

    // ── Главное меню ──────────────────────────────────────────────────────────

    private void banner() {
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════╗");
        System.out.println("║          RSA Cryptography System                     ║");
        System.out.println("║                                                      ║");
        System.out.println("╚══════════════════════════════════════════════════════╝");
    }

    private void mainMenu() {
        System.out.println();
        section("MAIN MENU");
        String keyStatus = currentKey == null ? "none" :
                currentKey.bitLength + "-bit" + (currentKey.hasPrivateKey() ? " (full)" : " (public only)");
        System.out.println("  Current key: " + keyStatus);
        System.out.println("  1. Key Management");
        System.out.println("  2. Encryption / Decryption");
        System.out.println("  3. Digital Signatures");
        System.out.println("  4. Test Vectors & Validation");
        System.out.println("  5. Performance Benchmarks");
        System.out.println("  6. Security Demonstrations");
        System.out.println("  7. Exit");
    }

    // =========================================================================
    // 1. KEY MANAGEMENT
    // =========================================================================

    private void keyManagement() {
        section("KEY MANAGEMENT");
        System.out.println("  1. Generate Key Pair");
        System.out.println("  2. Load Key from File");
        System.out.println("  3. Save Current Key to File");
        System.out.println("  4. Display Key Info");
        System.out.println("  5. Validate Current Key");
        System.out.println("  6. Back");

        int c = readInt("Select", 1, 6);
        switch (c) {
            case 1 -> generateKey();
            case 2 -> loadKey();
            case 3 -> saveKey();
            case 4 -> displayKeyInfo();
            case 5 -> validateKey();
        }
    }

    private void generateKey() {
        System.out.println("\n── Generate Key Pair ──");
        System.out.println("  1. 1024 bits  (fast, not recommended for production)");
        System.out.println("  2. 2048 bits  (standard)");
        System.out.println("  3. 4096 bits  (high security, slow)");
        int c = readInt("Key size", 1, 3);
        int bits = switch (c) { case 1 -> 1024; case 2 -> 2048; default -> 4096; };

        System.out.println("\nGenerating " + bits + "-bit RSA key pair...");
        System.out.print("Progress: ");

        long start = System.currentTimeMillis();
        // Progress dots while generating
        Thread prog = new Thread(() -> {
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    System.out.print(".");
                    System.out.flush();
                    Thread.sleep(300);
                }
            } catch (InterruptedException ignored) {}
        });
        prog.setDaemon(true);
        prog.start();

        try {
            currentKey = engine.generateKeyPair(bits);
        } finally {
            prog.interrupt();
        }

        long elapsed = System.currentTimeMillis() - start;
        System.out.println(" done!\n");
        System.out.printf("Generated %d-bit key pair in %.2f seconds%n", bits, elapsed / 1000.0);
        System.out.println("n = " + currentKey.n.toString(16).substring(0, 32) + "...");
        System.out.println("e = " + currentKey.e.toString(16));
        System.out.println("d = " + currentKey.d.toString(16).substring(0, 32) + "...");
    }

    private void loadKey() {
        System.out.println("\n── Load Key from File ──");
        System.out.print("File path: ");
        String path = in.nextLine().trim();
        try {
            currentKey = RSAKeyPair.loadFromFile(path);
            System.out.println("Key loaded: " + currentKey);
        } catch (Exception e) {
            System.out.println("Error loading key: " + e.getMessage());
        }
    }

    private void saveKey() {
        System.out.println("\n── Save Key to File ──");
        if (currentKey == null) { System.out.println("No key loaded."); return; }
        System.out.println("  1. Save Public Key");
        System.out.println("  2. Save Private Key");
        System.out.println("  3. Save Both");
        int c = readInt("Select", 1, 3);
        try {
            if (c == 1 || c == 3) {
                System.out.print("Public key filename: ");
                String pub = in.nextLine().trim();
                currentKey.savePublicKey(pub);
                System.out.println("Public key saved to: " + pub);
            }
            if ((c == 2 || c == 3) && currentKey.hasPrivateKey()) {
                System.out.print("Private key filename: ");
                String priv = in.nextLine().trim();
                currentKey.savePrivateKey(priv);
                System.out.println("Private key saved to: " + priv);
            }
        } catch (Exception e) {
            System.out.println("Error saving key: " + e.getMessage());
        }
    }

    private void displayKeyInfo() {
        System.out.println("\n── Key Info ──");
        if (currentKey == null) { System.out.println("No key loaded."); return; }
        System.out.println(currentKey.toDisplayString());
        // Full hex display
        System.out.println("\nFull values (hex):");
        System.out.println("n = " + currentKey.n.toString(16));
        System.out.println("e = " + currentKey.e.toString(16));
        if (currentKey.hasPrivateKey())
            System.out.println("d = " + currentKey.d.toString(16));
    }

    private void validateKey() {
        System.out.println("\n── Validate Key ──");
        if (currentKey == null) { System.out.println("No key loaded."); return; }
        boolean valid = engine.validateKeyPair(currentKey);
        System.out.println("Key validation: " + (valid ? "VALID ✓" : "INVALID ✗"));
        if (valid) {
            System.out.println("  ✓ e × d ≡ 1 (mod λ(n))");
            if (currentKey.hasFactors()) System.out.println("  ✓ n = p × q");
        }
    }

    // =========================================================================
    // 2. ENCRYPTION / DECRYPTION
    // =========================================================================

    private void encryptionMenu() {
        section("ENCRYPTION / DECRYPTION");
        if (currentKey == null) { System.out.println("No key loaded — generate or load a key first."); return; }
        System.out.println("  1. Encrypt Text  (PKCS#1 v1.5)");
        System.out.println("  2. Decrypt Text  (PKCS#1 v1.5)");
        System.out.println("  3. Encrypt Text  (OAEP)");
        System.out.println("  4. Decrypt Text  (OAEP)");
        System.out.println("  5. Encrypt File");
        System.out.println("  6. Decrypt File");
        System.out.println("  7. Back");
        int c = readInt("Select", 1, 7);
        switch (c) {
            case 1 -> encryptText(false);
            case 2 -> decryptText(false);
            case 3 -> encryptText(true);
            case 4 -> decryptText(true);
            case 5 -> encryptFile();
            case 6 -> decryptFile();
        }
    }

    private void encryptText(boolean oaep) {
        System.out.println("\n── Encrypt (" + (oaep ? "OAEP" : "PKCS#1 v1.5") + ") ──");
        System.out.print("Enter message: ");
        String msg = in.nextLine();
        try {
            byte[] plain  = msg.getBytes(StandardCharsets.UTF_8);
            byte[] cipher = oaep
                    ? engine.encryptOAEP(plain, currentKey)
                    : engine.encryptPKCS1(plain, currentKey);
            System.out.println("Ciphertext (hex):    " + SHA256.toHex(cipher));
            System.out.println("Ciphertext (base64): " + Base64.getEncoder().encodeToString(cipher));
            System.out.println("Length: " + cipher.length + " bytes");
        } catch (UnsupportedOperationException e) {
            System.out.println("[STUB] " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Encryption error: " + e.getMessage());
        }
    }

    private void decryptText(boolean oaep) {
        System.out.println("\n── Decrypt (" + (oaep ? "OAEP" : "PKCS#1 v1.5") + ") ──");
        if (!currentKey.hasPrivateKey()) { System.out.println("Private key required."); return; }
        System.out.println("Input format: 1=hex  2=base64");
        int fmt = readInt("Format", 1, 2);
        System.out.print("Ciphertext: ");
        String input = in.nextLine().trim();
        try {
            byte[] cipher = (fmt == 1) ? SHA256.fromHex(input) : Base64.getDecoder().decode(input);
            byte[] plain  = oaep
                    ? engine.decryptOAEP(cipher, currentKey)
                    : engine.decryptPKCS1(cipher, currentKey);
            System.out.println("Plaintext: " + new String(plain, StandardCharsets.UTF_8));
        } catch (UnsupportedOperationException e) {
            System.out.println("[STUB] " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Decryption error: " + e.getMessage());
        }
    }

    private void encryptFile() {
        System.out.println("\n── Encrypt File ──");
        System.out.print("Input file: ");  String in_ = in.nextLine().trim();
        System.out.print("Output file: "); String out_= in.nextLine().trim();
        System.out.println("Padding: 1=PKCS1 v1.5  2=OAEP");
        boolean oaep = readInt("Padding", 1, 2) == 2;
        try {
            byte[] plain  = Files.readAllBytes(Path.of(in_));
            byte[] cipher = oaep ? engine.encryptOAEP(plain, currentKey)
                    : engine.encryptPKCS1(plain, currentKey);
            Files.write(Path.of(out_), cipher);
            System.out.println("Encrypted " + plain.length + " → " + cipher.length + " bytes");
        } catch (UnsupportedOperationException e) {
            System.out.println("[STUB] " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private void decryptFile() {
        System.out.println("\n── Decrypt File ──");
        if (!currentKey.hasPrivateKey()) { System.out.println("Private key required."); return; }
        System.out.print("Input file (encrypted): ");  String in_ = in.nextLine().trim();
        System.out.print("Output file (plaintext): "); String out_= in.nextLine().trim();
        System.out.println("Padding: 1=PKCS1 v1.5  2=OAEP");
        boolean oaep = readInt("Padding", 1, 2) == 2;
        try {
            byte[] cipher = Files.readAllBytes(Path.of(in_));
            byte[] plain  = oaep ? engine.decryptOAEP(cipher, currentKey)
                    : engine.decryptPKCS1(cipher, currentKey);
            Files.write(Path.of(out_), plain);
            System.out.println("Decrypted " + cipher.length + " → " + plain.length + " bytes");
        } catch (UnsupportedOperationException e) {
            System.out.println("[STUB] " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    // =========================================================================
    // 3. DIGITAL SIGNATURES
    // =========================================================================

    private void signaturesMenu() {
        section("DIGITAL SIGNATURES");
        if (currentKey == null) { System.out.println("No key loaded."); return; }
        System.out.println("  1. Sign Text     (PKCS#1 v1.5)");
        System.out.println("  2. Sign Text     (PSS)");
        System.out.println("  3. Verify Signature (PKCS#1 v1.5)");
        System.out.println("  4. Verify Signature (PSS)");
        System.out.println("  5. Sign File");
        System.out.println("  6. Verify File Signature");
        System.out.println("  7. Show SHA-256 Hash of Message");
        System.out.println("  8. Back");
        int c = readInt("Select", 1, 8);
        switch (c) {
            case 1 -> signText(RSASignature.Scheme.PKCS1_V1_5);
            case 2 -> signText(RSASignature.Scheme.PSS);
            case 3 -> verifyTextSig(RSASignature.Scheme.PKCS1_V1_5);
            case 4 -> verifyTextSig(RSASignature.Scheme.PSS);
            case 5 -> signFile();
            case 6 -> verifyFileSig();
            case 7 -> showHash();
        }
    }

    private void signText(RSASignature.Scheme scheme) {
        System.out.println("\n── Sign Text (" + scheme + ") ──");
        if (!currentKey.hasPrivateKey()) { System.out.println("Private key required."); return; }
        System.out.print("Message: ");
        byte[] msg = in.nextLine().getBytes(StandardCharsets.UTF_8);
        try {
            long start = System.nanoTime();
            byte[] sig = RSASignature.sign(msg, currentKey, scheme);
            long ns = System.nanoTime() - start;

            System.out.println("\n" + RSASignature.formatSignatureInfo(sig, scheme, currentKey.bitLength));
            System.out.printf("Signing time: %.2f ms%n", ns / 1e6);
        } catch (Exception e) {
            System.out.println("Signing error: " + e.getMessage());
        }
    }

    private void verifyTextSig(RSASignature.Scheme scheme) {
        System.out.println("\n── Verify Signature (" + scheme + ") ──");
        System.out.print("Message: ");
        byte[] msg = in.nextLine().getBytes(StandardCharsets.UTF_8);
        System.out.println("Signature format: 1=hex  2=base64");
        int fmt = readInt("Format", 1, 2);
        System.out.print("Signature: ");
        String sigInput = in.nextLine().trim();
        try {
            byte[] sig = (fmt == 1) ? SHA256.fromHex(sigInput) : Base64.getDecoder().decode(sigInput);
            long   start = System.nanoTime();
            boolean ok   = RSASignature.verify(msg, sig, currentKey, scheme);
            long ns = System.nanoTime() - start;

            System.out.println("\nResult: " + (ok ? "VALID ✓" : "INVALID ✗"));
            System.out.printf("Verification time: %.2f ms%n", ns / 1e6);
            if (!ok) System.out.println("  Message or signature has been tampered with.");
        } catch (Exception e) {
            System.out.println("Verification error: " + e.getMessage());
        }
    }

    private void signFile() {
        System.out.println("\n── Sign File ──");
        if (!currentKey.hasPrivateKey()) { System.out.println("Private key required."); return; }
        System.out.print("File to sign: "); String path = in.nextLine().trim();
        System.out.print("Signature output file: "); String sigPath = in.nextLine().trim();
        System.out.println("Scheme: 1=PKCS1 v1.5  2=PSS");
        RSASignature.Scheme scheme = readInt("Scheme", 1, 2) == 1
                ? RSASignature.Scheme.PKCS1_V1_5 : RSASignature.Scheme.PSS;
        try {
            byte[] data = Files.readAllBytes(Path.of(path));
            byte[] sig  = RSASignature.sign(data, currentKey, scheme);
            Files.write(Path.of(sigPath), sig);
            System.out.println("File signed. SHA-256: " + SHA256.hashHex(data));
            System.out.println("Signature written to: " + sigPath);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private void verifyFileSig() {
        System.out.println("\n── Verify File Signature ──");
        System.out.print("Original file: "); String filePath = in.nextLine().trim();
        System.out.print("Signature file: "); String sigPath = in.nextLine().trim();
        System.out.println("Scheme: 1=PKCS1 v1.5  2=PSS");
        RSASignature.Scheme scheme = readInt("Scheme", 1, 2) == 1
                ? RSASignature.Scheme.PKCS1_V1_5 : RSASignature.Scheme.PSS;
        try {
            byte[] data = Files.readAllBytes(Path.of(filePath));
            byte[] sig  = Files.readAllBytes(Path.of(sigPath));
            boolean ok  = RSASignature.verify(data, sig, currentKey, scheme);
            System.out.println("File: " + filePath);
            System.out.println("SHA-256: " + SHA256.hashHex(data));
            System.out.println("Result: " + (ok ? "VALID ✓" : "INVALID ✗"));
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private void showHash() {
        System.out.print("Message: ");
        String msg = in.nextLine();
        byte[] hash = SHA256.hash(msg);
        System.out.println("SHA-256: " + SHA256.toHex(hash));
        System.out.println("Base64:  " + Base64.getEncoder().encodeToString(hash));
    }

    // =========================================================================
    // 4. TEST VECTORS & VALIDATION
    // =========================================================================

    private void testVectorsMenu() {
        section("TEST VECTORS & VALIDATION");
        System.out.println("  1. Prime Generation Tests      (4.1)");
        System.out.println("  2. RSA Correctness Tests       (4.2)");
        System.out.println("  3. Signature Tests             (4.3)");
        System.out.println("  4. Security Tests              (4.4)");
        System.out.println("  5. SHA-256 NIST Vectors");
        System.out.println("  6. Run All Tests");
        System.out.println("  7. Back");
        int c = readInt("Select", 1, 7);
        switch (c) {
            case 1 -> testPrimes();
            case 2 -> testRSACorrectness();
            case 3 -> testSignatures();
            case 4 -> testSecurity();
            case 5 -> testSHA256();
            case 6 -> { testPrimes(); testRSACorrectness(); testSignatures(); testSecurity(); testSHA256(); }
        }
    }

    // 4.1 Prime Tests ─────────────────────────────────────────────────────────

    private void testPrimes() {
        System.out.println("\n── 4.1 Prime Generation Tests ──");

        // Known primes
        long[] knownPrimes = {2, 3, 5, 7, 11, 13, 17, 31, 127, 131071, 524287};
        System.out.println("Known primes:");
        for (long p : knownPrimes) {
            boolean result = engine.isPrime(BigInteger.valueOf(p), 20);
            check("  isPrime(" + p + ")", result, true);
        }

        // Known composites
        long[] composites = {1, 4, 6, 9, 15, 21, 25, 27, 91, 100};
        System.out.println("Known composites:");
        for (long c : composites) {
            boolean result = engine.isPrime(BigInteger.valueOf(c), 20);
            check("  isPrime(" + c + ")", result, false);
        }

        // Carmichael numbers (pseudoprimes — must be detected as composite)
        long[] carmichael = {561, 1105, 1729, 2465, 2821, 6601};
        System.out.println("Carmichael numbers (must be COMPOSITE):");
        for (long cn : carmichael) {
            boolean result = engine.isPrime(BigInteger.valueOf(cn), 20);
            check("  isPrime(" + cn + ") [Carmichael]", result, false);
        }

        // Large prime generation
        System.out.println("Large prime generation:");
        long t = System.currentTimeMillis();
        BigInteger p512 = engine.generatePrime(512);
        System.out.printf("  512-bit prime in %.1f ms, isPrime=%s%n",
                System.currentTimeMillis() - t * 1.0,
                engine.isPrime(p512, 20) ? "true ✓" : "false ✗");

        t = System.currentTimeMillis();
        BigInteger p1024 = engine.generatePrime(1024);
        System.out.printf("  1024-bit prime in %.1f ms, isPrime=%s%n",
                System.currentTimeMillis() - t * 1.0,
                engine.isPrime(p1024, 20) ? "true ✓" : "false ✗");
    }

    // 4.2 RSA Correctness Tests ───────────────────────────────────────────────

    private void testRSACorrectness() {
        System.out.println("\n── 4.2 RSA Correctness Tests ──");
        System.out.println("Generating 1024-bit test key...");
        RSAKeyPair testKey = engine.generateKeyPair(1024);

        // Test 1: Roundtrip encrypt-decrypt
        System.out.println("Roundtrip tests (PKCS#1 v1.5):");
        String[] msgs = {"Hello, World!", "A", "The quick brown fox jumps",
                "Test message with numbers 12345"};
        for (String msg : msgs) {
            try {
                byte[] plain  = msg.getBytes(StandardCharsets.UTF_8);
                byte[] cipher = engine.encryptPKCS1(plain, testKey);
                byte[] dec    = engine.decryptPKCS1(cipher, testKey);
                boolean ok    = Arrays.equals(plain, dec);
                check("  Roundtrip: \"" + msg + "\"", ok, true);
            } catch (Exception e) {
                System.out.println("  FAIL: " + msg + " → " + e.getMessage());
            }
        }

        // Test 2: Empty message
        try {
            byte[] empty  = new byte[0];
            byte[] cipher = engine.encryptPKCS1(empty, testKey);
            byte[] dec    = engine.decryptPKCS1(cipher, testKey);
            check("  Empty message roundtrip", Arrays.equals(empty, dec), true);
        } catch (Exception e) {
            System.out.println("  Empty msg: " + e.getMessage());
        }

        // Test 3: Max length message for 1024-bit key
        // Max = keyLen - 11 = 128 - 11 = 117 bytes
        try {
            byte[] maxMsg = new byte[117];
            Arrays.fill(maxMsg, (byte)'X');
            byte[] cipher = engine.encryptPKCS1(maxMsg, testKey);
            byte[] dec    = engine.decryptPKCS1(cipher, testKey);
            check("  Max-length message (117 bytes)", Arrays.equals(maxMsg, dec), true);
        } catch (Exception e) {
            System.out.println("  Max msg: " + e.getMessage());
        }

        // Test 4: Raw RSA (textbook): m^e^d mod n = m
        System.out.println("Textbook RSA (modular arithmetic):");
        BigInteger m = BigInteger.valueOf(42);
        BigInteger c = engine.modExp(m, testKey.e, testKey.n);
        BigInteger r = engine.modExp(c, testKey.d, testKey.n);
        check("  42^e^d mod n = 42", r.equals(m), true);

        // Test 5: Extended GCD
        System.out.println("Extended GCD tests:");
        BigInteger[] gcd1 = engine.extendedGCD(BigInteger.valueOf(48), BigInteger.valueOf(18));
        check("  gcd(48,18) = 6", gcd1[0].equals(BigInteger.valueOf(6)), true);
        check("  48*x + 18*y = 6", BigInteger.valueOf(48).multiply(gcd1[1])
                .add(BigInteger.valueOf(18).multiply(gcd1[2]))
                .equals(gcd1[0]), true);
    }

    // 4.3 Signature Tests ─────────────────────────────────────────────────────

    private void testSignatures() {
        System.out.println("\n── 4.3 Signature Tests ──");
        System.out.println("Generating 1024-bit test key...");
        RSAKeyPair testKey = engine.generateKeyPair(1024);

        for (RSASignature.Scheme scheme : RSASignature.Scheme.values()) {
            System.out.println("\n" + scheme + ":");

            // Test 1: Valid sign & verify
            byte[] msg = "Hello, RSA!".getBytes(StandardCharsets.UTF_8);
            byte[] sig = RSASignature.sign(msg, testKey, scheme);
            check("  Valid sign+verify", RSASignature.verify(msg, sig, testKey, scheme), true);

            // Test 2: Tampered message
            byte[] tampered = "Hello, RSA?".getBytes(StandardCharsets.UTF_8); // changed !→?
            check("  Tampered message fails", RSASignature.verify(tampered, sig, testKey, scheme), false);

            // Test 3: Tampered signature
            byte[] sigCopy = Arrays.copyOf(sig, sig.length);
            sigCopy[sig.length / 2] ^= 0xFF; // flip bits
            check("  Tampered signature fails", RSASignature.verify(msg, sigCopy, testKey, scheme), false);

            // Test 4: Wrong key
            RSAKeyPair wrongKey = engine.generateKeyPair(1024);
            check("  Wrong public key fails", RSASignature.verify(msg, sig, wrongKey, scheme), false);

            // Test 5: PSS produces different signatures each time
            if (scheme == RSASignature.Scheme.PSS) {
                byte[] sig2 = RSASignature.signPSS(msg, testKey);
                boolean diff = !Arrays.equals(sig, sig2);
                boolean both = RSASignature.verifyPSS(msg, sig, testKey)
                        && RSASignature.verifyPSS(msg, sig2, testKey);
                check("  PSS: two sigs are different", diff, true);
                check("  PSS: both sigs verify correctly", both, true);
            }

            // Test 6: PKCS1 is deterministic
            if (scheme == RSASignature.Scheme.PKCS1_V1_5) {
                byte[] sig2 = RSASignature.signPKCS1(msg, testKey);
                check("  PKCS1: same msg → same sig", Arrays.equals(sig, sig2), true);
            }

            // Test 7: Various message sizes
            System.out.println("  Various message sizes:");
            int[] sizes = {0, 1, 55, 56, 64, 100, 1000, 10000};
            for (int sz : sizes) {
                byte[] m = new byte[sz];
                Arrays.fill(m, (byte)'A');
                byte[] s = RSASignature.sign(m, testKey, scheme);
                boolean ok = RSASignature.verify(m, s, testKey, scheme);
                System.out.printf("    %5d bytes: %s%n", sz, ok ? "PASS ✓" : "FAIL ✗");
            }
        }
    }

    // 4.4 Security Tests ──────────────────────────────────────────────────────

    private void testSecurity() {
        System.out.println("\n── 4.4 Security Tests ──");
        System.out.println("Generating 1024-bit test key...");
        RSAKeyPair testKey = engine.generateKeyPair(1024);

        // Test 1: Same message encrypts to different ciphertext (random padding)
        System.out.println("Random padding test (PKCS#1 v1.5):");
        byte[] msg = "Hello".getBytes(StandardCharsets.UTF_8);
        try {
            byte[] c1 = engine.encryptPKCS1(msg, testKey);
            byte[] c2 = engine.encryptPKCS1(msg, testKey);
            check("  Same msg → different ciphertexts", !Arrays.equals(c1, c2), true);
            check("  Both decrypt correctly",
                    Arrays.equals(engine.decryptPKCS1(c1, testKey), msg)
                            && Arrays.equals(engine.decryptPKCS1(c2, testKey), msg), true);
        } catch (Exception e) {
            System.out.println("  Error: " + e.getMessage());
        }

        // Test 2: Invalid ciphertext rejected
        System.out.println("Invalid ciphertext handling:");
        try {
            byte[] garbage = new byte[128];
            Arrays.fill(garbage, (byte) 0xAA);
            engine.decryptPKCS1(garbage, testKey);
            System.out.println("  Garbage ciphertext: NOT rejected (expected exception) ✗");
        } catch (Exception e) {
            System.out.println("  Garbage ciphertext: Rejected gracefully ✓  (" + e.getClass().getSimpleName() + ")");
        }

        // Test 3: Padding validation
        System.out.println("Padding validation:");
        try {
            // Valid encrypt then corrupt padding byte
            byte[] c = engine.encryptPKCS1(msg, testKey);
            c[0] ^= 0x01; // corrupt first byte
            engine.decryptPKCS1(c, testKey);
            System.out.println("  Corrupted padding: NOT rejected ✗");
        } catch (Exception e) {
            System.out.println("  Corrupted padding: Rejected ✓  (" + e.getClass().getSimpleName() + ")");
        }

        // Test 4: Signature with wrong hash rejected
        System.out.println("Signature security:");
        byte[] m   = "Secure message".getBytes(StandardCharsets.UTF_8);
        byte[] sig = RSASignature.signPKCS1(m, testKey);
        // Corrupt one byte of signature
        byte[] sigCorrupt = Arrays.copyOf(sig, sig.length);
        sigCorrupt[5] ^= 0x01;
        check("  1-bit corrupted sig rejected", !RSASignature.verifyPKCS1(m, sigCorrupt, testKey), true);

        // Test 5: PSS salt randomness
        System.out.println("PSS salt randomness:");
        Set<String> sigs = new HashSet<>();
        for (int i = 0; i < 10; i++) sigs.add(SHA256.toHex(RSASignature.signPSS(m, testKey)));
        check("  10 PSS sigs are all unique", sigs.size() == 10, true);

        // Test 6: Key size effect on ciphertext size
        System.out.println("Ciphertext size vs key size:");
        for (int bits : new int[]{1024, 2048}) {
            RSAKeyPair k = engine.generateKeyPair(bits);
            byte[] ct = engine.encryptPKCS1(msg, k);
            System.out.printf("  %4d-bit key → %d-byte ciphertext%n", bits, ct.length);
        }
    }

    // SHA-256 NIST Vectors ────────────────────────────────────────────────────

    private void testSHA256() {
        System.out.println("\n── SHA-256 NIST Test Vectors ──");
        check("SHA256(\"abc\")",
                SHA256.hashHex("abc"),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        check("SHA256(\"\")",
                SHA256.hashHex(""),
                "e3b0c44298fc1c149afbf4c8996fb924 27ae41e4649b934ca495991b7852b855".replace(" ",""));
        check("SHA256(448-bit message)",
                SHA256.hashHex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        byte[] million = new byte[1_000_000];
        Arrays.fill(million, (byte)'a');
        check("SHA256(1M × 'a')",
                SHA256.hashHex(million),
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    // =========================================================================
    // 5. PERFORMANCE BENCHMARKS
    // =========================================================================

    private void performanceMenu() {
        section("PERFORMANCE BENCHMARKS");
        System.out.println("  1. Key Generation Speed");
        System.out.println("  2. Encryption/Decryption Speed");
        System.out.println("  3. Signature Speed");
        System.out.println("  4. SHA-256 Speed");
        System.out.println("  5. Run All Benchmarks");
        System.out.println("  6. Back");
        int c = readInt("Select", 1, 6);
        switch (c) {
            case 1 -> benchKeyGen();
            case 2 -> benchEncDec();
            case 3 -> benchSignatures();
            case 4 -> benchSHA256();
            case 5 -> { benchKeyGen(); benchEncDec(); benchSignatures(); benchSHA256(); }
        }
    }

    private void benchKeyGen() {
        System.out.println("\n── Key Generation Benchmark ──");
        int[] sizes = {1024, 2048};
        int   reps  = 3;
        System.out.printf("%-10s  %6s  %6s  %6s  %6s%n", "Key Size", "Run1", "Run2", "Run3", "Avg");
        System.out.println("-".repeat(45));
        for (int bits : sizes) {
            long total = 0;
            long[] times = new long[reps];
            for (int i = 0; i < reps; i++) {
                long t = System.currentTimeMillis();
                engine.generateKeyPair(bits);
                times[i] = System.currentTimeMillis() - t;
                total += times[i];
            }
            System.out.printf("%-10s  %5dms  %5dms  %5dms  %5dms%n",
                    bits + "-bit", times[0], times[1], times[2], total / reps);
        }
    }

    private void benchEncDec() {
        System.out.println("\n── Encryption/Decryption Speed ──");
        System.out.println("Generating test keys...");
        RSAKeyPair k1024 = engine.generateKeyPair(1024);
        RSAKeyPair k2048 = engine.generateKeyPair(2048);

        int reps = 100;
        System.out.printf("%-12s  %-10s  %-12s  %-12s%n", "Key", "Msg Size", "Enc (ops/s)", "Dec (ops/s)");
        System.out.println("-".repeat(52));

        for (RSAKeyPair kp : new RSAKeyPair[]{k1024, k2048}) {
            byte[] msg = new byte[32];
            Arrays.fill(msg, (byte)'A');
            byte[] ct = null;
            try { ct = engine.encryptPKCS1(msg, kp); } catch (Exception ignored) {}
            if (ct == null) continue;
            final byte[] ciphertext = ct;

            long t1 = System.nanoTime();
            for (int i = 0; i < reps; i++) engine.encryptPKCS1(msg, kp);
            double encOps = reps / ((System.nanoTime() - t1) / 1e9);

            long t2 = System.nanoTime();
            for (int i = 0; i < reps; i++) engine.decryptPKCS1(ciphertext, kp);
            double decOps = reps / ((System.nanoTime() - t2) / 1e9);

            System.out.printf("%-12s  %-10s  %-12.1f  %-12.1f%n",
                    kp.bitLength + "-bit", msg.length + "B", encOps, decOps);
        }
    }

    private void benchSignatures() {
        System.out.println("\n── Signature Speed ──");
        System.out.println("Generating 1024-bit and 2048-bit test keys...");
        RSAKeyPair k1024 = engine.generateKeyPair(1024);
        RSAKeyPair k2048 = engine.generateKeyPair(2048);

        int reps = 50;
        byte[] msg = "Benchmark message for RSA signature speed test".getBytes(StandardCharsets.UTF_8);

        System.out.printf("%-12s  %-15s  %-14s  %-14s%n", "Key", "Scheme", "Sign (ops/s)", "Verify (ops/s)");
        System.out.println("-".repeat(60));

        for (RSAKeyPair kp : new RSAKeyPair[]{k1024, k2048}) {
            for (RSASignature.Scheme scheme : RSASignature.Scheme.values()) {
                byte[] sig = RSASignature.sign(msg, kp, scheme);

                long t1 = System.nanoTime();
                for (int i = 0; i < reps; i++) RSASignature.sign(msg, kp, scheme);
                double signOps = reps / ((System.nanoTime() - t1) / 1e9);

                long t2 = System.nanoTime();
                for (int i = 0; i < reps; i++) RSASignature.verify(msg, sig, kp, scheme);
                double verifyOps = reps / ((System.nanoTime() - t2) / 1e9);

                System.out.printf("%-12s  %-15s  %-14.1f  %-14.1f%n",
                        kp.bitLength + "-bit", scheme, signOps, verifyOps);
            }
        }
    }

    private void benchSHA256() {
        System.out.println("\n── SHA-256 Speed ──");
        int[] sizes = {64, 1024, 65536, 1048576};
        System.out.printf("%-12s  %-12s  %-10s%n", "Input Size", "Time (ms)", "Speed (MB/s)");
        System.out.println("-".repeat(38));
        for (int sz : sizes) {
            byte[] data = new byte[sz];
            Arrays.fill(data, (byte)'A');
            int reps = Math.max(1, 10_000_000 / sz);
            long t = System.nanoTime();
            for (int i = 0; i < reps; i++) SHA256.hash(data);
            double ms  = (System.nanoTime() - t) / 1e6;
            double mbs = (sz * (long) reps) / (ms * 1000.0);
            System.out.printf("%-12s  %-12.1f  %-10.1f%n",
                    sz < 1024 ? sz+"B" : (sz/1024)+"KB",
                    ms / reps, mbs);
        }
    }

    // =========================================================================
    // 6. SECURITY DEMONSTRATIONS
    // =========================================================================

    private void securityDemosMenu() {
        section("SECURITY DEMONSTRATIONS");
        System.out.println("  1. Textbook RSA Vulnerability (no padding)");
        System.out.println("  2. Why Padding Is Essential");
        System.out.println("  3. PKCS#1 v1.5 vs PSS comparison");
        System.out.println("  4. Key Size Impact");
        System.out.println("  5. SHA-256 Avalanche Effect");
        System.out.println("  6. Back");
        int c = readInt("Select", 1, 6);
        switch (c) {
            case 1 -> demoTextbookRSA();
            case 2 -> demoPaddingEssential();
            case 3 -> demoPKCS1vsPSS();
            case 4 -> demoKeySizes();
            case 5 -> demoAvalanche();
        }
    }

    private void demoTextbookRSA() {
        System.out.println("\n── Textbook RSA Vulnerability ──");
        System.out.println("Textbook RSA: c = m^e mod n  (no padding)");
        System.out.println("Vulnerability: deterministic — same message = same ciphertext");
        System.out.println();
        System.out.println("Generating 512-bit demo key...");
        RSAKeyPair k = engine.generateKeyPair(512);

        BigInteger m = BigInteger.valueOf(42);
        System.out.println("Message m = 42");
        BigInteger c1 = engine.modExp(m, k.e, k.n);
        BigInteger c2 = engine.modExp(m, k.e, k.n);
        System.out.println("c1 = m^e mod n = " + c1.toString(16).substring(0, 20) + "...");
        System.out.println("c2 = m^e mod n = " + c2.toString(16).substring(0, 20) + "...");
        System.out.println("c1 == c2: " + c1.equals(c2) + "  ← ALWAYS SAME (dangerous!)");
        System.out.println();
        System.out.println("Attack: if attacker knows c and suspects m ∈ {1..100},");
        System.out.println("they compute m^e mod n for each candidate and compare to c.");
        System.out.println("→ No padding = no semantic security.");
    }

    private void demoPaddingEssential() {
        System.out.println("\n── Why Padding Is Essential ──");
        System.out.println("With PKCS#1 v1.5 padding:");
        System.out.println("  EM = 0x00 || 0x02 || [random bytes] || 0x00 || message");
        System.out.println("  Random bytes make every encryption unique!");
        System.out.println();
        System.out.println("Generating 1024-bit demo key...");
        RSAKeyPair k = engine.generateKeyPair(1024);
        byte[] msg = "hello".getBytes(StandardCharsets.UTF_8);
        try {
            byte[] c1 = engine.encryptPKCS1(msg, k);
            byte[] c2 = engine.encryptPKCS1(msg, k);
            byte[] c3 = engine.encryptPKCS1(msg, k);
            System.out.println("Same message \"hello\" encrypted 3 times:");
            System.out.println("  c1 = " + SHA256.toHex(c1).substring(0, 40) + "...");
            System.out.println("  c2 = " + SHA256.toHex(c2).substring(0, 40) + "...");
            System.out.println("  c3 = " + SHA256.toHex(c3).substring(0, 40) + "...");
            System.out.println("All equal? " + (Arrays.equals(c1,c2) && Arrays.equals(c2,c3)));
            System.out.println("→ All DIFFERENT due to random padding bytes.");
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private void demoPKCS1vsPSS() {
        System.out.println("\n── PKCS#1 v1.5 vs PSS for Signatures ──");
        System.out.println("Generating 1024-bit demo key...");
        RSAKeyPair k = engine.generateKeyPair(1024);
        byte[] msg = "Compare padding schemes".getBytes(StandardCharsets.UTF_8);

        byte[] sig1a = RSASignature.signPKCS1(msg, k);
        byte[] sig1b = RSASignature.signPKCS1(msg, k);
        byte[] sig2a = RSASignature.signPSS(msg, k);
        byte[] sig2b = RSASignature.signPSS(msg, k);

        System.out.println();
        System.out.println("PKCS#1 v1.5 (deterministic):");
        System.out.printf("  sig1 = %s...%n", SHA256.toHex(sig1a).substring(0, 40));
        System.out.printf("  sig2 = %s...%n", SHA256.toHex(sig1b).substring(0, 40));
        System.out.println("  sig1 == sig2: " + Arrays.equals(sig1a, sig1b) + "  ← always same");

        System.out.println();
        System.out.println("PSS (probabilistic — random salt):");
        System.out.printf("  sig1 = %s...%n", SHA256.toHex(sig2a).substring(0, 40));
        System.out.printf("  sig2 = %s...%n", SHA256.toHex(sig2b).substring(0, 40));
        System.out.println("  sig1 == sig2: " + Arrays.equals(sig2a, sig2b) + "  ← always different!");

        System.out.println();
        System.out.println("Both verify correctly:");
        System.out.println("  PKCS1 verify: " + RSASignature.verifyPKCS1(msg, sig1a, k));
        System.out.println("  PSS   verify: " + RSASignature.verifyPSS(msg, sig2a, k));

        System.out.println();
        System.out.println("PSS is recommended for new systems (provably secure).");
    }

    private void demoKeySizes() {
        System.out.println("\n── Key Size Impact ──");
        System.out.println("Generating keys of different sizes (may take a minute)...");
        System.out.printf("%-10s  %-15s  %-15s  %-12s%n", "Key Size", "Gen Time", "Sig Time", "CT Size");
        System.out.println("-".repeat(56));
        for (int bits : new int[]{1024, 2048}) {
            long t0 = System.currentTimeMillis();
            RSAKeyPair k = engine.generateKeyPair(bits);
            long genMs = System.currentTimeMillis() - t0;

            byte[] msg = "Test".getBytes(StandardCharsets.UTF_8);
            long t1 = System.nanoTime();
            byte[] sig = RSASignature.signPKCS1(msg, k);
            double sigMs = (System.nanoTime() - t1) / 1e6;

            int ctSize = (k.n.bitLength() + 7) / 8;
            System.out.printf("%-10s  %-15s  %-15s  %-12s%n",
                    bits + "-bit",
                    genMs + "ms",
                    String.format("%.1fms", sigMs),
                    ctSize + "B");
        }
    }

    private void demoAvalanche() {
        System.out.println("\n── SHA-256 Avalanche Effect ──");
        String base   = "Hello, World!";
        byte[] hashA  = SHA256.hash(base);
        byte[] bytes  = base.getBytes(StandardCharsets.UTF_8);
        bytes[0] ^= 0x01; // flip 1 bit
        byte[] hashB  = SHA256.hash(bytes);

        int diffBits = 0;
        for (int i = 0; i < 32; i++)
            diffBits += Integer.bitCount((hashA[i] & 0xFF) ^ (hashB[i] & 0xFF));

        System.out.println("Original : \"" + base + "\"");
        System.out.println("Modified : 1 bit flipped in first byte");
        System.out.println("Hash A   : " + SHA256.toHex(hashA));
        System.out.println("Hash B   : " + SHA256.toHex(hashB));
        System.out.printf("Changed  : %d / 256 bits  (%.1f%%)%n", diffBits, 100.0*diffBits/256);
        System.out.println("→ ~50% of bits change from a single bit flip — ideal avalanche!");
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    /** Печатает заголовок раздела. */
    private static void section(String name) {
        String line = "─".repeat(name.length() + 4);
        System.out.println("\n┌" + line + "┐");
        System.out.println("│  " + name + "  │");
        System.out.println("└" + line + "┘");
    }

    /** Проверяет условие и печатает PASS/FAIL. */
    private static void check(String name, boolean actual, boolean expected) {
        boolean pass = actual == expected;
        System.out.printf("  %-50s %s%n", name, pass ? "PASS ✓" : "FAIL ✗  (expected " + expected + ", got " + actual + ")");
    }

    /** Проверяет строковое равенство. */
    private static void check(String name, String actual, String expected) {
        boolean pass = actual.equals(expected);
        System.out.printf("  %-50s %s%n", name, pass ? "PASS ✓" : "FAIL ✗");
        if (!pass) {
            System.out.println("    expected: " + expected);
            System.out.println("    got:      " + actual);
        }
    }

    /** Читает целое число из консоли в диапазоне [min, max]. */
    private int readInt(String prompt, int min, int max) {
        while (true) {
            System.out.printf("%s [%d-%d]: ", prompt, min, max);
            try {
                String line = in.nextLine().trim();
                int    val  = Integer.parseInt(line);
                if (val >= min && val <= max) return val;
            } catch (NumberFormatException ignored) {}
            System.out.println("  Enter a number between " + min + " and " + max);
        }
    }
}