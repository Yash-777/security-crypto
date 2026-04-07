package com.github.yash777.securitycrypto.demo;

import com.github.yash777.securitycrypto.CryptoFacade;
import com.github.yash777.securitycrypto.cipher.CipherMode;
import com.github.yash777.securitycrypto.cipher.HybridCipher.HybridPayload;
import com.github.yash777.securitycrypto.crypto.PasswordBasedCrypto;
import com.github.yash777.securitycrypto.exception.InvalidCiphertextException;
import com.github.yash777.securitycrypto.key.KeyManager;
import com.github.yash777.securitycrypto.key.KeySize;
import com.github.yash777.securitycrypto.util.IvUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.security.KeyPair;
import java.util.Base64;
import java.util.Date;

/**
 * Standalone demonstration runner for the {@code security-crypto} library.
 *
 * <p>Exercises every public API in the library without requiring a test framework.
 * Run this class directly after building the JAR:
 * <pre>
 *   mvn package
 *   java -cp target/security-crypto-1.0.0.jar:... \
 *        com.github.yash777.securitycrypto.demo.CryptoFacadeRunner
 * </pre>
 *
 * <h2>Sections covered</h2>
 * <ol>
 *   <li>AES-GCM via {@link CryptoFacade} — recommended default</li>
 *   <li>AES-CBC with random IV — all key sizes</li>
 *   <li>AES-CBC with deterministic IV from string</li>
 *   <li>AES-CBC with IV from {@link Date} — matches CryptoService pattern</li>
 *   <li>AES-ECB — all key sizes (educational; not for production)</li>
 *   <li>All cipher modes × all key sizes matrix</li>
 *   <li>Key persistence — save to / load from disk</li>
 *   <li>Key encode / decode via Base64</li>
 *   <li>GCM tamper detection</li>
 *   <li>RSA encrypt / decrypt</li>
 *   <li>Hybrid RSA + AES-GCM — short and large payloads</li>
 *   <li>Password-based crypto — random IV (without date)</li>
 *   <li>Password-based crypto — IV from Date (with date)</li>
 *   <li>Password-based crypto — IV from date string</li>
 *   <li>Password-based crypto — legacy CryptoService mode</li>
 *   <li>Password-based crypto — PBKDF2-SHA256 with 256-bit key</li>
 *   <li>{@link IvUtils} — all factory methods</li>
 *   <li>Error handling — negative test paths</li>
 * </ol>
 *
 * @author  Yashwanth
 * @version 1.0.0
 * @since   1.0.0
 * @see     CryptoFacade
 * @see     PasswordBasedCrypto
 */
public class CryptoFacadeRunner {

    // -----------------------------------------------------------------------
    // Shared state
    // -----------------------------------------------------------------------

    private static final CryptoFacade CRYPTO  = new CryptoFacade();

    private static SecretKey aes128Key;
    private static SecretKey aes192Key;
    private static SecretKey aes256Key;
    private static KeyPair   rsaKeyPair;

    private static final String SAMPLE = "Hello JCE! Encrypt me with AES and RSA. \uD83D\uDD10";

    private static int passed = 0;
    private static int failed = 0;

    // -----------------------------------------------------------------------
    // Entry point
    // -----------------------------------------------------------------------

    /**
     * Runs all demonstration sections and prints a pass/fail summary.
     *
     * @param args command-line arguments (not used)
     */
    public static void main(String[] args) {
        banner("security-crypto 1.0.0 — Demonstration Runner");

        initialiseKeys();

        runSection("1.  AES-GCM via CryptoFacade (default)",      CryptoFacadeRunner::demoAesGcmDefault);
        runSection("2.  AES-CBC random IV — all key sizes",        CryptoFacadeRunner::demoAesCbcRandomIv);
        runSection("3.  AES-CBC with deterministic IV from string", CryptoFacadeRunner::demoAesCbcStringIv);
        runSection("4.  AES-CBC with IV from Date",                CryptoFacadeRunner::demoAesCbcDateIv);
        runSection("5.  AES-ECB — all key sizes",                  CryptoFacadeRunner::demoAesEcb);
        runSection("6.  All modes x all key sizes matrix",         CryptoFacadeRunner::demoAllModesAllKeySizes);
        runSection("7.  Key persistence (save/load)",              CryptoFacadeRunner::demoKeyPersistence);
        runSection("8.  Key Base64 encode/decode",                 CryptoFacadeRunner::demoKeyBase64);
        runSection("9.  GCM tamper detection",                     CryptoFacadeRunner::demoGcmTamperDetection);
        runSection("10. RSA encrypt/decrypt",                      CryptoFacadeRunner::demoRsa);
        runSection("11. Hybrid RSA + AES-GCM",                     CryptoFacadeRunner::demoHybrid);
        runSection("12. Password-based — random IV (without date)", CryptoFacadeRunner::demoPasswordBasedRandomIv);
        runSection("13. Password-based — IV from Date (with date)", CryptoFacadeRunner::demoPasswordBasedDateIv);
        runSection("14. Password-based — IV from date string",     CryptoFacadeRunner::demoPasswordBasedDateString);
        runSection("15. Password-based — legacy CryptoService mode",CryptoFacadeRunner::demoPasswordBasedLegacy);
        runSection("16. Password-based — SHA256 / 256-bit key",    CryptoFacadeRunner::demoPasswordBasedSha256);
        runSection("17. IvUtils — all factory methods",            CryptoFacadeRunner::demoIvUtils);
        runSection("18. Error handling — negative paths",          CryptoFacadeRunner::demoErrorHandling);

        banner("Results: PASSED=" + passed + "  FAILED=" + failed);
        if (failed > 0) System.exit(1);
    }

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------

    /**
     * Generates keys shared across all demonstration sections.
     */
    private static void initialiseKeys() {
        aes128Key = CRYPTO.generateAesKey(KeySize.AES_128);
        aes192Key = CRYPTO.generateAesKey(KeySize.AES_192);
        aes256Key = CRYPTO.generateAesKey(KeySize.AES_256);
        rsaKeyPair = CRYPTO.generateRsaKeyPair(2048);
        log("Keys initialised: AES-128, AES-192, AES-256, RSA-2048");
    }

    // -----------------------------------------------------------------------
    // Section 1 — AES-GCM default
    // -----------------------------------------------------------------------

    /**
     * Demonstrates AES-GCM encryption and decryption via the high-level facade.
     * A cryptographically random 12-byte nonce is generated automatically per call.
     */
    static void demoAesGcmDefault() throws Exception {
        String ct = CRYPTO.aesEncrypt(SAMPLE, aes256Key);
        check("GCM ciphertext not null", ct != null && !ct.isEmpty());
        check("GCM differs from plaintext", !SAMPLE.equals(ct));

        String plain = CRYPTO.aesDecrypt(ct, aes256Key);
        check("GCM round-trip", SAMPLE.equals(plain));

        // Random nonce: same plaintext must produce a different ciphertext each call
        String ct2 = CRYPTO.aesEncrypt(SAMPLE, aes256Key);
        check("GCM nonce uniqueness", !ct.equals(ct2));

        // Explicit mode call
        String ct3 = CRYPTO.aesEncrypt(SAMPLE, aes256Key, CipherMode.GCM);
        check("GCM explicit mode round-trip", SAMPLE.equals(CRYPTO.aesDecrypt(ct3, aes256Key, CipherMode.GCM)));
    }

    // -----------------------------------------------------------------------
    // Section 2 — AES-CBC random IV
    // -----------------------------------------------------------------------

    /**
     * Demonstrates AES-CBC with a random 16-byte IV for each of the three key sizes.
     * The IV is embedded in the returned Base64 payload.
     */
    static void demoAesCbcRandomIv() throws Exception {
        for (SecretKey key : new SecretKey[]{aes128Key, aes192Key, aes256Key}) {
            String label = "CBC-" + key.getEncoded().length * 8;
            String ct    = CRYPTO.aesEncrypt(SAMPLE, key, CipherMode.CBC);
            check(label + " round-trip", SAMPLE.equals(CRYPTO.aesDecrypt(ct, key, CipherMode.CBC)));
            // Random IV — two calls must differ
            check(label + " random IV uniqueness",
                    !ct.equals(CRYPTO.aesEncrypt(SAMPLE, key, CipherMode.CBC)));
        }
    }

    // -----------------------------------------------------------------------
    // Section 3 — AES-CBC with string IV
    // -----------------------------------------------------------------------

    /**
     * Demonstrates AES-CBC with a deterministic IV derived from a UTF-8 string.
     * The same string always produces the same IV → same ciphertext (deterministic).
     */
    static void demoAesCbcStringIv() throws Exception {
        IvParameterSpec iv16 = IvUtils.fromString("FixedIV-16bytes!"); // exactly 16
        IvParameterSpec iv8  = IvUtils.fromString("Short",       16);  // padded
        IvParameterSpec iv20 = IvUtils.fromString("ABCDEFGHIJKLMNOPQRST", 16); // truncated

        check("fromString 16-byte length",   iv16.getIV().length == 16);
        check("fromString padded length",    iv8.getIV().length  == 16);
        check("fromString truncated length", iv20.getIV().length == 16);

        String ct1 = CRYPTO.aesEncrypt(SAMPLE, aes256Key, CipherMode.CBC, iv16);
        String ct2 = CRYPTO.aesEncrypt(SAMPLE, aes256Key, CipherMode.CBC, iv16);
        check("CBC fixed IV determinism", ct1.equals(ct2));
        check("CBC fixed IV decrypt", SAMPLE.equals(CRYPTO.aesDecrypt(ct1, aes256Key, CipherMode.CBC)));
    }

    // -----------------------------------------------------------------------
    // Section 4 — AES-CBC IV from Date
    // -----------------------------------------------------------------------

    /**
     * Demonstrates the pattern from {@code CryptoService} in MyWorld: the IV is
     * derived from a record creation date formatted as {@code yyyy-MM-dd'T'HH:mm:ss}.
     * Both encrypting and decrypting sides independently compute the same IV from
     * the same date without transmitting it separately.
     */
    static void demoAesCbcDateIv() throws Exception {
        // Pattern from CryptoService: IV = first 16 bytes of formatted date string
        Date fixedDate = IvUtils.fromDate(new Date(0)) // epoch 0 gives all-zero IV
                         != null ? new Date(1703844574000L) : new Date(); // 2023-12-29T10:09:34

        IvParameterSpec iv = IvUtils.fromDate(fixedDate);
        check("fromDate length == 16", iv.getIV().length == 16);

        String ct = CRYPTO.aesEncrypt(SAMPLE, aes256Key, CipherMode.CBC, iv);
        // Decrypt re-derives the same IV from the same date
        IvParameterSpec ivRepro = IvUtils.fromDate(fixedDate);
        check("CBC date-IV round-trip",
                SAMPLE.equals(CRYPTO.aesDecrypt(ct, aes256Key, CipherMode.CBC)));

        // Epoch date
        IvParameterSpec ivEpoch = IvUtils.fromDate(new Date(0));
        String ctEpoch = CRYPTO.aesEncrypt(SAMPLE, aes128Key, CipherMode.CBC, ivEpoch);
        check("CBC epoch-date IV round-trip",
                SAMPLE.equals(CRYPTO.aesDecrypt(ctEpoch, aes128Key, CipherMode.CBC)));

        // fromDateString convenience method
        IvParameterSpec ivFromStr = IvUtils.fromDateString("2023-12-29T10:09:34");
        check("fromDateString length == 16", ivFromStr.getIV().length == 16);

        // Epoch millis variant
        IvParameterSpec ivMillis = IvUtils.fromDateEpochMillis(new Date(0));
        check("fromDateEpochMillis length == 16", ivMillis.getIV().length == 16);
    }

    // -----------------------------------------------------------------------
    // Section 5 — AES-ECB
    // -----------------------------------------------------------------------

    /**
     * Demonstrates AES-ECB mode for all three key sizes.
     * ECB is shown for educational purposes; it should not be used for non-trivial data
     * because identical plaintext blocks produce identical ciphertext blocks.
     */
    static void demoAesEcb() throws Exception {
        for (SecretKey key : new SecretKey[]{aes128Key, aes192Key, aes256Key}) {
            String label = "ECB-" + key.getEncoded().length * 8;
            String ct = CRYPTO.aesEncrypt(SAMPLE, key, CipherMode.ECB);
            check(label + " round-trip", SAMPLE.equals(CRYPTO.aesDecrypt(ct, key, CipherMode.ECB)));
            // ECB has no IV — same key + same plaintext always produces same ciphertext
            check(label + " deterministic", ct.equals(CRYPTO.aesEncrypt(SAMPLE, key, CipherMode.ECB)));
        }
    }

    // -----------------------------------------------------------------------
    // Section 6 — All modes × all key sizes
    // -----------------------------------------------------------------------

    /**
     * Runs every combination of {@link CipherMode} × {@link KeySize} (9 combinations).
     */
    static void demoAllModesAllKeySizes() throws Exception {
        for (KeySize size : KeySize.values()) {
            SecretKey key = CRYPTO.generateAesKey(size);
            for (CipherMode mode : CipherMode.values()) {
                String ct = CRYPTO.aesEncrypt(SAMPLE, key, mode);
                check(mode.name() + "/AES-" + size.bits,
                        SAMPLE.equals(CRYPTO.aesDecrypt(ct, key, mode)));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Section 7 — Key persistence
    // -----------------------------------------------------------------------

    /**
     * Demonstrates saving an AES key to a temp file, reloading it, and verifying
     * that ciphertext encrypted with the original key decrypts correctly with the
     * reloaded key.
     */
    static void demoKeyPersistence() throws Exception {
        File tmpDir = new File(System.getProperty("java.io.tmpdir"));
        SecretKey k1 = CRYPTO.getOrCreateAesKey(KeySize.AES_256, tmpDir);
        SecretKey k2 = CRYPTO.getOrCreateAesKey(KeySize.AES_256, tmpDir); // reload

        check("Key file created", new File(tmpDir, KeySize.AES_256.fileName()).exists());
        check("Reloaded key matches",
                KeyManager.encodeKeyToBase64(k1).equals(KeyManager.encodeKeyToBase64(k2)));

        String ct = CRYPTO.aesEncrypt(SAMPLE, k1, CipherMode.GCM);
        check("Cross-load GCM decrypt", SAMPLE.equals(CRYPTO.aesDecrypt(ct, k2, CipherMode.GCM)));
    }

    // -----------------------------------------------------------------------
    // Section 8 — Key Base64
    // -----------------------------------------------------------------------

    /**
     * Demonstrates encoding an AES key to Base64 and reconstructing it, then verifying
     * that the reconstructed key decrypts ciphertext encrypted with the original.
     */
    static void demoKeyBase64() throws Exception {
        SecretKey original = CRYPTO.generateAesKey(KeySize.AES_256);
        String b64 = KeyManager.encodeKeyToBase64(original);
        check("Base64 not empty", b64 != null && !b64.isEmpty());
        check("Base64 length (AES-256 = 44 chars)", b64.length() == 44);

        SecretKey restored = KeyManager.decodeAesKeyFromBase64(b64, KeySize.AES_256);
        check("Restored key equals original",
                b64.equals(KeyManager.encodeKeyToBase64(restored)));

        String ct = CRYPTO.aesEncrypt(SAMPLE, original, CipherMode.GCM);
        check("Decrypt with Base64-restored key",
                SAMPLE.equals(CRYPTO.aesDecrypt(ct, restored, CipherMode.GCM)));
    }

    // -----------------------------------------------------------------------
    // Section 9 — GCM tamper detection
    // -----------------------------------------------------------------------

    /**
     * Demonstrates that AES-GCM detects any modification to the ciphertext payload.
     * Tampering causes {@link InvalidCiphertextException} to be thrown on decrypt.
     */
    static void demoGcmTamperDetection() {
        String ct = CRYPTO.aesEncrypt(SAMPLE, aes256Key, CipherMode.GCM);

        // Tamper 1: flip a bit near the end
        char[] chars = ct.toCharArray();
        chars[chars.length - 5] ^= 0x01;
        assertThrowsICE(new String(chars), aes256Key, CipherMode.GCM, "GCM bit-flip tamper");

        // Tamper 2: wrong key
        assertThrowsICE(ct, CRYPTO.generateAesKey(KeySize.AES_256), CipherMode.GCM, "GCM wrong key");

        // Tamper 3: invalid Base64
        assertThrowsICE("!!!not-base64!!!", aes256Key, CipherMode.GCM, "GCM invalid Base64");

        // Tamper 4: truncated payload
        String tiny = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3});
        assertThrowsICE(tiny, aes256Key, CipherMode.GCM, "GCM truncated payload");
    }

    // -----------------------------------------------------------------------
    // Section 10 — RSA
    // -----------------------------------------------------------------------

    /**
     * Demonstrates RSA encryption with the public key and decryption with the
     * private key, including wrong-key rejection.
     */
    static void demoRsa() throws Exception {
        String secret = "RSA secret token";
        String ct = CRYPTO.rsaEncrypt(secret, rsaKeyPair.getPublic());
        check("RSA ciphertext not empty", ct != null && !ct.isEmpty());

        String plain = CRYPTO.rsaDecrypt(ct, rsaKeyPair.getPrivate());
        check("RSA round-trip", secret.equals(plain));

        // OAEP is probabilistic — same plaintext must produce different ciphertexts
        check("RSA non-deterministic (OAEP)", !ct.equals(CRYPTO.rsaEncrypt(secret, rsaKeyPair.getPublic())));

        // Wrong key
        KeyPair other = CRYPTO.generateRsaKeyPair(2048);
        try {
            CRYPTO.rsaDecrypt(ct, other.getPrivate());
            check("RSA wrong-key rejected", false);
        } catch (InvalidCiphertextException e) {
            check("RSA wrong-key rejected", true);
        }
    }

    // -----------------------------------------------------------------------
    // Section 11 — Hybrid RSA + AES-GCM
    // -----------------------------------------------------------------------

    /**
     * Demonstrates hybrid RSA + AES-GCM encryption for short and large payloads.
     * A fresh AES-256 session key is generated per message and RSA-wrapped.
     */
    static void demoHybrid() throws Exception {
        HybridPayload p = CRYPTO.hybridEncrypt(SAMPLE, rsaKeyPair.getPublic());
        check("Hybrid wrappedKey not empty", p.wrappedKey() != null && !p.wrappedKey().isEmpty());
        check("Hybrid ciphertext not empty", p.ciphertext() != null && !p.ciphertext().isEmpty());
        check("Hybrid short round-trip", SAMPLE.equals(CRYPTO.hybridDecrypt(p, rsaKeyPair.getPrivate())));

        // Large payload (10 KB) — impossible directly with RSA
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10000; i++) sb.append((char) ('A' + i % 26));
        String large = sb.toString();
        HybridPayload pl = CRYPTO.hybridEncrypt(large, rsaKeyPair.getPublic());
        check("Hybrid 10KB round-trip", large.equals(CRYPTO.hybridDecrypt(pl, rsaKeyPair.getPrivate())));

        // Unique session keys per call
        HybridPayload p2 = CRYPTO.hybridEncrypt(SAMPLE, rsaKeyPair.getPublic());
        check("Hybrid unique ciphertexts", !p.ciphertext().equals(p2.ciphertext()));
        check("Hybrid unique wrapped keys", !p.wrappedKey().equals(p2.wrappedKey()));

        // Wrong private key
        try {
            CRYPTO.hybridDecrypt(p, CRYPTO.generateRsaKeyPair(2048).getPrivate());
            check("Hybrid wrong-key rejected", false);
        } catch (InvalidCiphertextException e) {
            check("Hybrid wrong-key rejected", true);
        }
    }

    // -----------------------------------------------------------------------
    // Section 12 — Password-based, random IV
    // -----------------------------------------------------------------------

    /**
     * Demonstrates {@link PasswordBasedCrypto#encryptWithRandomIv} and
     * {@link PasswordBasedCrypto#decryptWithRandomIv}. The IV is embedded in
     * the output — no date or external parameter required on decrypt.
     */
    static void demoPasswordBasedRandomIv() throws Exception {
        PasswordBasedCrypto pbc = new PasswordBasedCrypto();
        String pass = "myS3cr3tPassphrase!";
        String salt = "user@example.com";

        String ct = pbc.encryptWithRandomIv(SAMPLE, pass, salt);
        check("PBC random-IV ciphertext not empty", ct != null && !ct.isEmpty());
        check("PBC random-IV differs from plaintext", !SAMPLE.equals(ct));

        String plain = pbc.decryptWithRandomIv(ct, pass, salt);
        check("PBC random-IV round-trip", SAMPLE.equals(plain));

        // Random IV — two encryptions must differ
        check("PBC random-IV uniqueness", !ct.equals(pbc.encryptWithRandomIv(SAMPLE, pass, salt)));

        // Wrong passphrase
        try {
            pbc.decryptWithRandomIv(ct, "wrongPassphrase", salt);
            check("PBC wrong passphrase rejected", false);
        } catch (InvalidCiphertextException e) {
            check("PBC wrong passphrase rejected", true);
        }
    }

    // -----------------------------------------------------------------------
    // Section 13 — Password-based, IV from Date
    // -----------------------------------------------------------------------

    /**
     * Demonstrates {@link PasswordBasedCrypto#encryptWithDateIv(String, String, String, Date)}
     * and {@link PasswordBasedCrypto#decryptWithDateIv(String, String, String, Date)}.
     * The IV is derived from the supplied {@link Date} — both sides must use the same date.
     * This matches the approach in {@code CryptoService.encode()} from MyWorld.
     */
    static void demoPasswordBasedDateIv() throws Exception {
        PasswordBasedCrypto pbc = new PasswordBasedCrypto();
        String pass = "B&^0QUV^?^SQ.{D|}";
        String salt = "svallepu@example.com";
        Date enrollDate = PasswordBasedCrypto.parseDate("2023-12-29T10:09:34",
                PasswordBasedCrypto.DEFAULT_DATE_FORMAT);

        String ct = pbc.encryptWithDateIv(SAMPLE, pass, salt, enrollDate);
        check("PBC date-IV ciphertext not empty", ct != null && !ct.isEmpty());

        // Date IV is deterministic — same inputs must produce the same ciphertext
        String ct2 = pbc.encryptWithDateIv(SAMPLE, pass, salt, enrollDate);
        check("PBC date-IV determinism", ct.equals(ct2));

        String plain = pbc.decryptWithDateIv(ct, pass, salt, enrollDate);
        check("PBC date-IV round-trip", SAMPLE.equals(plain));

        // Wrong date → different IV → decryption fails
        Date otherDate = new Date();
        try {
            pbc.decryptWithDateIv(ct, pass, salt, otherDate);
            check("PBC wrong-date rejected", false);
        } catch (InvalidCiphertextException e) {
            check("PBC wrong-date rejected", true);
        }
    }

    // -----------------------------------------------------------------------
    // Section 14 — Password-based, IV from date string
    // -----------------------------------------------------------------------

    /**
     * Demonstrates the date-string overload of {@link PasswordBasedCrypto}
     * where the date is supplied as a formatted string instead of a {@link Date} object.
     */
    static void demoPasswordBasedDateString() throws Exception {
        PasswordBasedCrypto pbc = new PasswordBasedCrypto();
        String pass       = "secretPass";
        String salt       = "rbuyya@example.com";
        String dateString = "2023-12-29T10:09:34";

        String ct    = pbc.encryptWithDateIv(SAMPLE, pass, salt, dateString);
        String plain = pbc.decryptWithDateIv(ct, pass, salt, dateString);
        check("PBC date-string round-trip", SAMPLE.equals(plain));

        // IvUtils.fromDateString convenience method
        IvParameterSpec ivFromStr = IvUtils.fromDateString(dateString);
        check("IvUtils.fromDateString length", ivFromStr.getIV().length == 16);

        // Custom date format
        String customDate   = "29/12/2023 10:09:34";
        String customFormat = "dd/MM/yyyy HH:mm:ss";
        String ctCustom     = pbc.encryptWithDateIv(SAMPLE, pass, salt, PasswordBasedCrypto.parseDate(customDate, customFormat), customFormat);
        String plainCustom  = pbc.decryptWithDateIv(ctCustom, pass, salt, PasswordBasedCrypto.parseDate(customDate, customFormat), customFormat);
        check("PBC custom date-format round-trip", SAMPLE.equals(plainCustom));
    }

    // -----------------------------------------------------------------------
    // Section 15 — Password-based, legacy CryptoService mode
    // -----------------------------------------------------------------------

    /**
     * Demonstrates {@link PasswordBasedCrypto#legacyMode()} which reproduces the
     * PBKDF2-HMAC-SHA1 / 1024 iterations / 128-bit key configuration from the
     * original {@code CryptoService.encode()} in the MyWorld project.
     */
    static void demoPasswordBasedLegacy() throws Exception {
        PasswordBasedCrypto pbc  = PasswordBasedCrypto.legacyMode();
        String pass              = "B&^0QUV^?^SQ.{D|]C[[(+hm'^e7|FJ}Ga-4$T54:(bgpyD,)K{fpE8~M,YMzvu";
        String salt              = "ymerugu@example.com";
        Date   creationDate      = PasswordBasedCrypto.parseDate("2023-12-29T10:09:34",
                                       PasswordBasedCrypto.DEFAULT_DATE_FORMAT);

        check("Legacy mode iterations == 1024", pbc.getIterations() == 1024);
        check("Legacy mode keyLength == 128",   pbc.getKeyLengthBits() == 128);
        check("Legacy mode algorithm == SHA1",
                PasswordBasedCrypto.Algorithm.PBKDF2_HMAC_SHA1 == pbc.getAlgorithm());

        // Encrypt with date IV (CryptoService pattern)
        String encoded = pbc.encryptWithDateIv("Yash@001", pass, salt, creationDate);
        check("Legacy encode not empty", encoded != null && !encoded.isEmpty());

        // Round-trip
        String decoded = pbc.decryptWithDateIv(encoded, pass, salt, creationDate);
        check("Legacy encode/decode round-trip", "Yash@001".equals(decoded));

        // Deterministic
        String encoded2 = pbc.encryptWithDateIv("Yash@001", pass, salt, creationDate);
        check("Legacy encode deterministic", encoded.equals(encoded2));
    }

    // -----------------------------------------------------------------------
    // Section 16 — Password-based, SHA-256 / 256-bit key
    // -----------------------------------------------------------------------

    /**
     * Demonstrates the recommended PBKDF2-HMAC-SHA256 / 65536 iterations / 256-bit key
     * configuration via {@link PasswordBasedCrypto} default constructor.
     */
    static void demoPasswordBasedSha256() throws Exception {
        // Default constructor = SHA256 / 65536 iterations / 256-bit key
        PasswordBasedCrypto pbc = new PasswordBasedCrypto();
        String pass = "P@ssw0rd$ecure!";
        String salt = "sparupati@example.com";

        check("Default iterations == 65536",  pbc.getIterations() == 65536);
        check("Default keyLength == 256",     pbc.getKeyLengthBits() == 256);
        check("Default algorithm == SHA256",
                PasswordBasedCrypto.Algorithm.PBKDF2_HMAC_SHA256 == pbc.getAlgorithm());

        // Random IV
        String ct    = pbc.encryptWithRandomIv("D$Pr^0@dm!n%)", pass, salt);
        String plain = pbc.decryptWithRandomIv(ct, pass, salt);
        check("SHA256 random-IV round-trip", "D$Pr^0@dm!n%)".equals(plain));

        // Explicit constructor
        PasswordBasedCrypto custom = new PasswordBasedCrypto(
                PasswordBasedCrypto.Algorithm.PBKDF2_HMAC_SHA256, 100000, 256);
        String ctCustom = custom.encryptWithRandomIv(SAMPLE, pass, salt);
        check("SHA256 custom-iterations round-trip",
                SAMPLE.equals(custom.decryptWithRandomIv(ctCustom, pass, salt)));
    }

    // -----------------------------------------------------------------------
    // Section 17 — IvUtils
    // -----------------------------------------------------------------------

    /**
     * Exercises all {@link IvUtils} factory methods and verifies the resulting
     * IV lengths and determinism properties.
     */
    static void demoIvUtils() {
        // generateRandom(int)
        check("generateRandom(16) length", IvUtils.generateRandom(16).getIV().length == 16);
        check("generateRandom(12) length", IvUtils.generateRandom(12).getIV().length == 12);

        // generateRandom() — default 16 bytes
        check("generateRandom() length", IvUtils.generateRandom().getIV().length == 16);

        // generateRandomGcm() — 12 bytes
        check("generateRandomGcm() length", IvUtils.generateRandomGcm().getIV().length == 12);

        // fromString(str, len) — pad
        check("fromString pad length",      IvUtils.fromString("Short", 16).getIV().length == 16);
        // fromString(str, len) — truncate
        check("fromString truncate length", IvUtils.fromString("ABCDEFGHIJKLMNOPQRST", 16).getIV().length == 16);
        // fromString(str) — default 16
        check("fromString default length",  IvUtils.fromString("hello").getIV().length == 16);

        // fromDate
        check("fromDate length", IvUtils.fromDate(new Date()).getIV().length == 16);
        // Determinism
        Date fixed = new Date(1000000L);
        byte[] a = IvUtils.fromDate(fixed).getIV();
        byte[] b = IvUtils.fromDate(fixed).getIV();
        boolean same = true;
        for (int i = 0; i < a.length; i++) { if (a[i] != b[i]) { same = false; break; } }
        check("fromDate deterministic", same);

        // fromDateString
        check("fromDateString length", IvUtils.fromDateString("2023-12-29T10:09:34").getIV().length == 16);
        check("fromDateString custom format",
                IvUtils.fromDateString("29/12/2023", "dd/MM/yyyy").getIV().length == 16);

        // fromDateEpochMillis
        check("fromDateEpochMillis length", IvUtils.fromDateEpochMillis(new Date()).getIV().length == 16);

        // fromBytes
        check("fromBytes(12) length", IvUtils.fromBytes(new byte[12]).getIV().length == 12);
        check("fromBytes(16) length", IvUtils.fromBytes(new byte[16]).getIV().length == 16);

        // fromBytes null guard
        try { IvUtils.fromBytes(null);    check("fromBytes(null) guard", false); }
        catch (IllegalArgumentException e) { check("fromBytes(null) guard", true); }
        // fromBytes empty guard
        try { IvUtils.fromBytes(new byte[0]); check("fromBytes([]) guard", false); }
        catch (IllegalArgumentException e) { check("fromBytes([]) guard", true); }

        // toBytes round-trip
        IvParameterSpec iv = IvUtils.generateRandom();
        check("toBytes length", IvUtils.toBytes(iv).length == 16);
    }

    // -----------------------------------------------------------------------
    // Section 18 — Error handling
    // -----------------------------------------------------------------------

    /**
     * Exercises the exception paths for all cipher modes and password-based crypto.
     */
    static void demoErrorHandling() throws Exception {
        // GCM: invalid Base64
        assertThrowsICE("%%%INVALID%%%",  aes256Key, CipherMode.GCM, "GCM invalid Base64");

        // GCM: truncated (too short for nonce)
        assertThrowsICE(Base64.getEncoder().encodeToString(new byte[4]),
                         aes256Key, CipherMode.GCM, "GCM truncated");

        // CBC: truncated (too short for IV)
        assertThrowsICE(Base64.getEncoder().encodeToString(new byte[8]),
                         aes256Key, CipherMode.CBC, "CBC truncated");

        // GCM: null IV via AesCipher direct — CryptoOperationException expected
        try {
            CRYPTO.aesEncrypt(SAMPLE, aes256Key, CipherMode.GCM, null);
            check("GCM null IV rejected", false);
        } catch (com.github.yash777.securitycrypto.exception.CryptoOperationException e) {
            check("GCM null IV rejected", true);
        }

        // Password-based: invalid Base64
        PasswordBasedCrypto pbc = new PasswordBasedCrypto();
        try {
            pbc.decryptWithRandomIv("NOT_VALID_BASE64!!!", "pass", "salt");
            check("PBC invalid Base64 rejected", false);
        } catch (InvalidCiphertextException e) {
            check("PBC invalid Base64 rejected", true);
        }

        // Password-based: truncated payload
        try {
            pbc.decryptWithRandomIv(Base64.getEncoder().encodeToString(new byte[4]),
                    "pass", "salt");
            check("PBC truncated rejected", false);
        } catch (InvalidCiphertextException e) {
            check("PBC truncated rejected", true);
        }

        // IvUtils: fromDateString with bad format
        try {
            IvUtils.fromDateString("not-a-date");
            check("fromDateString bad date rejected", false);
        } catch (IllegalArgumentException e) {
            check("fromDateString bad date rejected", true);
        }
    }

    // -----------------------------------------------------------------------
    // Internal test helpers
    // -----------------------------------------------------------------------

    /**
     * Asserts that decrypting {@code ciphertext} with {@code key} and {@code mode}
     * throws {@link InvalidCiphertextException}, marking the check as pass or fail.
     *
     * @param ciphertext the tampered / invalid Base64 payload
     * @param key        the AES key to attempt decryption with
     * @param mode       the cipher mode to use
     * @param label      human-readable description of this check
     */
    private static void assertThrowsICE(String ciphertext, SecretKey key,
                                        CipherMode mode, String label) {
        try {
            CRYPTO.aesDecrypt(ciphertext, key, mode);
            check(label, false);
        } catch (InvalidCiphertextException e) {
            check(label, true);
        }
    }

    /**
     * Records a single pass/fail check and prints the result.
     *
     * @param label     human-readable name for this assertion
     * @param condition the boolean result to verify
     */
    private static void check(String label, boolean condition) {
        if (condition) {
            System.out.println("  [PASS] " + label);
            passed++;
        } else {
            System.out.println("  [FAIL] " + label);
            failed++;
        }
    }

    /**
     * Runs a named section, catching any unexpected exceptions as failures.
     *
     * @param name    section heading
     * @param section the section lambda / method reference to run
     */
    private static void runSection(String name, ThrowingRunnable section) {
        System.out.println("\n── " + name + " ──");
        try {
            section.run();
        } catch (Exception e) {
            System.out.println("  [FAIL] Unexpected exception: " + e);
            failed++;
        }
    }

    private static void log(String msg) {
        System.out.println("  " + msg);
    }

    private static void banner(String msg) {
//        System.out.println("\n" + "══════════════════════════════════════════════════════════════════════");
        System.out.println("  " + msg);
//        System.out.println("══════════════════════════════════════════════════════════════════════");
    }

    /**
     * Functional interface for section runners that may throw checked exceptions.
     */
    @FunctionalInterface
    interface ThrowingRunnable {
        /** Runs this section, potentially throwing any exception. */
        void run() throws Exception;
    }
}
