package com.github.yash777.securitycrypto.demo;

import com.github.yash777.securitycrypto.cipher.AesCbcFixedKeyCipher;
import com.github.yash777.securitycrypto.cipher.AesCryptoManager;
import com.github.yash777.securitycrypto.cipher.RsaCryptoManager;
import com.github.yash777.securitycrypto.crypto.PasswordBasedCrypto;
import com.github.yash777.securitycrypto.crypto.PasswordBasedCrypto.Algorithm;
import com.github.yash777.securitycrypto.crypto.SecretKeyGenerator;
import com.github.yash777.securitycrypto.exception.InvalidCiphertextException;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.SecretKey;

/**
 * Demonstrates {@link SecretKeyGenerator} — how to generate a
 * {@code SECRET_PASSWORD_KEY} (PBKDF2 passphrase), random salts, and
 * user-specific salts, then use them end-to-end with {@link PasswordBasedCrypto}.
 *
 * <h2>What this shows</h2>
 * <ol>
 *   <li>Generate a 64-char master passphrase (equivalent to {@code SecurityCryptoTest.SECRET_PASSWORD_KEY})</li>
 *   <li>Generate a random salt (per-record, not linked to any user)</li>
 *   <li>Generate a user-specific salt (username + timestamp + random bytes)</li>
 *   <li>Save passphrase + salt to a key file, reload and verify</li>
 *   <li>Encrypt / decrypt with {@link PasswordBasedCrypto#encryptWithRandomIv} using generated keys</li>
 *   <li>Encrypt / decrypt with {@link PasswordBasedCrypto#encryptWithDateIv} using generated keys</li>
 *   <li>Encrypt / decrypt with {@link PasswordBasedCrypto#encryptWithSaltIvPrefix} using generated keys</li>
 * </ol>
 *
 * @author Yashwanth
 * @see    SecretKeyGenerator
 * @see    PasswordBasedCrypto
 */
public class SecretKeyGeneratorTest {

    private static final String DATE_FORMAT          = "yyyy-MM-dd'T'HH:mm:ss";
    private static final String CREATION_DATE_STRING = "2023-12-29T10:09:34";

    /**
     * Entry point — runs all generator demos in sequence.
     *
     * @param args not used
     * @throws Exception on any failure
     */
    public static void main(String[] args) throws Exception {
    	
        // PBKDF2 settings matching original CryptoService
        PasswordBasedCrypto pbc = new PasswordBasedCrypto(Algorithm.PBKDF2_HMAC_SHA1, 1024, 128);
        Date enrollDate = new SimpleDateFormat(DATE_FORMAT).parse(CREATION_DATE_STRING);

        separator("1. Passphrase (SECRET_PASSWORD_KEY) generation");
        demoPassphraseGeneration();

        separator("2. Random salt generation");
        demoRandomSalt();

        separator("3. User-specific salt generation");
        demoUserSpecificSalt();

        separator("4. Save passphrase + salt to file, reload and verify");
        demoFilePersistence();

        separator("5. Encrypt / decrypt — generated passphrase + random salt — encryptWithRandomIv");
        demoEncryptWithGeneratedKeysRandomIv(pbc);

        separator("6. Encrypt / decrypt — generated passphrase + random salt — encryptWithDateIv");
        demoEncryptWithGeneratedKeysDateIv(pbc, enrollDate);

        separator("7. Encrypt / decrypt — generated passphrase + random salt — encryptWithSaltIvPrefix");
        demoEncryptWithGeneratedKeysSaltIvPrefix(pbc, enrollDate);

        separator("8. Full lifecycle: generate → save → load → encrypt → decrypt");
        demoFullLifecycle(pbc, enrollDate);
        
        separator("9.  PBKDF2 Key Derivation — SHA1 (legacy) and SHA256 (recommended)");
        derivePbkdf2KeyAndEncrypt(pbc);

        separator("10. AES Symmetric Key Generation — 128 / 192 / 256-bit + Base64 round-trip");
        generateAesKeyAndRoundTrip();

        separator("11. AES/CBC with Pre-Shared Fixed Key and IV — encrypt, decrypt, passthrough");
        encryptDecryptWithFixedKeyIv();

        separator("12. AES-GCM (symmetric) and RSA (asymmetric) static encryption helpers");
        encryptDecryptWithGcmAndRsa();
    }

    // -----------------------------------------------------------------------
    // Section 1 — Passphrase generation
    // -----------------------------------------------------------------------

    /**
     * Generates master passphrases at different lengths and prints them.
     * The 64-char output is equivalent to the hardcoded {@code CryptoService.key}.
     */
    static void demoPassphraseGeneration() {
        System.out.println("Character pool length : " + SecretKeyGenerator.CHARACTERS.length());
        System.out.println("Entropy per char      : ~" +
                String.format("%.1f", Math.log(SecretKeyGenerator.CHARACTERS.length()) / Math.log(2))
                + " bits");
        System.out.println();

        // Default 64 chars — same length as CryptoService.key
        String key64 = SecretKeyGenerator.generatePassphrase();
        System.out.println("64-char passphrase (default) : " + key64);
        System.out.println("  Length : " + key64.length());
        System.out.println("  Entropy: ~" + (int)(Math.log(SecretKeyGenerator.CHARACTERS.length())
                / Math.log(2) * key64.length()) + " bits");
        System.out.println();

        // Custom lengths
        String key32  = SecretKeyGenerator.generatePassphrase(32);
        String key128 = SecretKeyGenerator.generatePassphrase(128);
        System.out.println("32-char  passphrase : " + key32);
        System.out.println("128-char passphrase : " + key128.substring(0, 32) + "...");

        // Two calls must produce different values
        String a = SecretKeyGenerator.generatePassphrase();
        String b = SecretKeyGenerator.generatePassphrase();
        System.out.println();
        System.out.println("Uniqueness check (two calls must differ): "
                + (!a.equals(b) ? "PASS" : "FAIL"));
    }

    // -----------------------------------------------------------------------
    // Section 2 — Random salt
    // -----------------------------------------------------------------------

    /**
     * Generates random salts at various byte sizes and prints the Base64 output lengths.
     */
    static void demoRandomSalt() {
        // Default (24 bytes → 32-char Base64)
        String salt24 = SecretKeyGenerator.generateRandomSalt();
        System.out.println("24-byte salt (default) : " + salt24
                + "  [len=" + salt24.length() + "]");

        // Various sizes
        String salt16 = SecretKeyGenerator.generateRandomSalt(16);
        String salt32 = SecretKeyGenerator.generateRandomSalt(32);
        System.out.println("16-byte salt           : " + salt16 + "  [len=" + salt16.length() + "]");
        System.out.println("32-byte salt           : " + salt32 + "  [len=" + salt32.length() + "]");

        // Two salts must be different
        String s1 = SecretKeyGenerator.generateRandomSalt();
        String s2 = SecretKeyGenerator.generateRandomSalt();
        System.out.println();
        System.out.println("Uniqueness check: " + (!s1.equals(s2) ? "PASS" : "FAIL"));
    }

    // -----------------------------------------------------------------------
    // Section 3 — User-specific salt
    // -----------------------------------------------------------------------

    /**
     * Generates user-specific salts for several usernames and shows that
     * two calls for the same user produce different salts (timestamp + random bytes).
     */
    static void demoUserSpecificSalt() {
        String[] users = {
            "ymerugu@innominds.com",
            "svallepu@innominds.com",
            "Yash@gmail.com"
        };

        for (String user : users) {
            String salt1 = SecretKeyGenerator.generateUserSpecificSalt(user);
            String salt2 = SecretKeyGenerator.generateUserSpecificSalt(user, 32);
            System.out.println("User : " + user);
            System.out.println("  Salt-1 (24B default) : " + salt1 + "  [len=" + salt1.length() + "]");
            System.out.println("  Salt-2 (32B)         : " + salt2 + "  [len=" + salt2.length() + "]");
            System.out.println("  Unique across calls  : " + (!salt1.equals(salt2) ? "PASS" : "FAIL"));
        }
    }

    // -----------------------------------------------------------------------
    // Section 4 — File persistence
    // -----------------------------------------------------------------------

    /**
     * Saves a generated passphrase + salt to a temp key file, reloads them,
     * and verifies the round-trip is lossless.
     */
    static void demoFilePersistence() throws Exception {
        String passphrase = SecretKeyGenerator.generatePassphrase();
        String salt       = SecretKeyGenerator.generateRandomSalt();
        File   keyFile    = File.createTempFile("security-crypto-demo-", ".key");
        keyFile.deleteOnExit();

        System.out.println("Generated passphrase : " + passphrase.substring(0, 20) + "...");
        System.out.println("Generated salt       : " + salt);
        System.out.println("Key file             : " + keyFile.getAbsolutePath());

        // Save
        SecretKeyGenerator.saveToFile(passphrase, salt, keyFile);
        System.out.println("Saved to file        : OK");

        // Reload
        String[] loaded = SecretKeyGenerator.loadFromFile(keyFile);
        System.out.println("Loaded passphrase    : " + loaded[0].substring(0, 20) + "...");
        System.out.println("Loaded salt          : " + loaded[1]);

        boolean pass = passphrase.equals(loaded[0]) && salt.equals(loaded[1]);
        System.out.println("Round-trip check     : " + (pass ? "PASS" : "FAIL"));
    }

    // -----------------------------------------------------------------------
    // Section 5 — Encrypt with generated keys — encryptWithRandomIv
    // -----------------------------------------------------------------------

    /**
     * Generates a fresh passphrase and random salt, then encrypts/decrypts
     * using {@link PasswordBasedCrypto#encryptWithRandomIv}.
     */
    static void demoEncryptWithGeneratedKeysRandomIv(PasswordBasedCrypto pbc)
            throws InvalidCiphertextException {

        String passphrase = SecretKeyGenerator.generatePassphrase();
        String salt       = SecretKeyGenerator.generateRandomSalt();
        String password   = "Yash@001";

        System.out.println("Passphrase (first 20) : " + passphrase.substring(0, 20) + "...");
        System.out.println("Salt                  : " + salt);
        System.out.println("Plaintext             : " + password);
        System.out.println();

        // Encrypt twice — must differ (random IV each time)
        String ct1 = pbc.encryptWithRandomIv(password, passphrase, salt);
        String ct2 = pbc.encryptWithRandomIv(password, passphrase, salt);
        System.out.println("Encrypted-1 : " + ct1);
        System.out.println("Encrypted-2 : " + ct2);
        System.out.println("Unique      : " + (!ct1.equals(ct2) ? "PASS" : "FAIL"));

        String decrypted = pbc.decryptWithRandomIv(ct1, passphrase, salt);
        System.out.println("Decrypted   : " + decrypted);
        System.out.println("Match       : " + (password.equals(decrypted) ? "PASS" : "FAIL"));
    }

    // -----------------------------------------------------------------------
    // Section 6 — Encrypt with generated keys — encryptWithDateIv
    // -----------------------------------------------------------------------

    /**
     * Generates a fresh passphrase and user-specific salt, then encrypts/decrypts
     * using {@link PasswordBasedCrypto#encryptWithDateIv}.
     * Same date → same IV → deterministic ciphertext.
     */
    static void demoEncryptWithGeneratedKeysDateIv(PasswordBasedCrypto pbc, Date enrollDate)
            throws InvalidCiphertextException {

        String username   = "Yash@gmail.com";
        String passphrase = SecretKeyGenerator.generatePassphrase();
        String salt       = SecretKeyGenerator.generateUserSpecificSalt(username);
        String password   = "D$Pr^0@dm!n%)";

        System.out.println("Username              : " + username);
        System.out.println("Passphrase (first 20) : " + passphrase.substring(0, 20) + "...");
        System.out.println("Salt                  : " + salt);
        System.out.println("Date                  : " + enrollDate);
        System.out.println("Plaintext             : " + password);
        System.out.println();

        String ct1 = pbc.encryptWithDateIv(password, passphrase, salt, enrollDate);
        String ct2 = pbc.encryptWithDateIv(password, passphrase, salt, enrollDate);
        System.out.println("Encrypted-1 : " + ct1);
        System.out.println("Encrypted-2 : " + ct2);
        System.out.println("Deterministic (same date → same output): "
                + (ct1.equals(ct2) ? "PASS" : "FAIL"));

        String decrypted = pbc.decryptWithDateIv(ct1, passphrase, salt, enrollDate);
        System.out.println("Decrypted   : " + decrypted);
        System.out.println("Match       : " + (password.equals(decrypted) ? "PASS" : "FAIL"));
    }

    // -----------------------------------------------------------------------
    // Section 7 — Encrypt with generated keys — encryptWithSaltIvPrefix
    // -----------------------------------------------------------------------

    /**
     * Generates a fresh passphrase, then encrypts/decrypts using
     * {@link PasswordBasedCrypto#encryptWithSaltIvPrefix} — the full
     * {@code Base64(salt || IV || ciphertext)} format.
     * The date is embedded so decryption needs only the passphrase and salt.
     */
    static void demoEncryptWithGeneratedKeysSaltIvPrefix(PasswordBasedCrypto pbc, Date enrollDate)
            throws InvalidCiphertextException {

        String username   = "svallepu@innominds.com";
        String passphrase = SecretKeyGenerator.generatePassphrase();
        String password   = "D$Pr^0@dm!n%)";

        System.out.println("Username              : " + username);
        System.out.println("Passphrase (first 20) : " + passphrase.substring(0, 20) + "...");
        System.out.println("Date                  : " + enrollDate);
        System.out.println("Plaintext             : " + password);
        System.out.println();

        // Salt is the username itself here (as in the original CryptoService)
        String ct = pbc.encryptWithSaltIvPrefix(password, passphrase, username, enrollDate);
        System.out.println("Encrypted (full)  : " + ct);
        System.out.println("Format            : Base64( salt("
                + username.getBytes().length + "B) || IV(16B) || ciphertext )");

        // Decrypt — date NOT needed; IV is already in the buffer
        String decrypted = pbc.decryptWithSaltIvPrefix(ct, passphrase, username);
        System.out.println("Decrypted         : " + decrypted);
        System.out.println("Match             : " + (password.equals(decrypted) ? "PASS" : "FAIL"));

        // Determinism check
        String ct2 = pbc.encryptWithSaltIvPrefix(password, passphrase, username, enrollDate);
        System.out.println("Deterministic     : " + (ct.equals(ct2) ? "PASS" : "FAIL"));
    }

    // -----------------------------------------------------------------------
    // Section 8 — Full lifecycle
    // -----------------------------------------------------------------------

    /**
     * Full lifecycle: generate keys → save to file → load from file → encrypt → decrypt.
     *
     * <p>Simulates a real application startup: generate once, save to a key file,
     * then reload on every subsequent run.
     */
    static void demoFullLifecycle(PasswordBasedCrypto pbc, Date enrollDate) throws Exception {
        String username = "rbuyya@innominds.com";
        String password = "Yash@001";

        // ── Step 1: generate and persist ────────────────────────────────────
        String passphrase = SecretKeyGenerator.generatePassphrase();
        String salt       = SecretKeyGenerator.generateUserSpecificSalt(username);
        File   keyFile    = File.createTempFile("lifecycle-demo-", ".key");
        keyFile.deleteOnExit();

        SecretKeyGenerator.saveToFile(passphrase, salt, keyFile);
        System.out.println("Step 1 — Keys generated and saved to: " + keyFile.getName());

        // ── Step 2: reload (simulates next application startup) ──────────────
        String[] loaded = SecretKeyGenerator.loadFromFile(keyFile);
        String loadedPassphrase = loaded[0];
        String loadedSalt       = loaded[1];
        System.out.println("Step 2 — Keys loaded: "
                + loadedPassphrase.substring(0, 10) + "...  salt=" + loadedSalt);

        // ── Step 3: encrypt with loaded keys ─────────────────────────────────
        String ctRandom = pbc.encryptWithRandomIv(password, loadedPassphrase, loadedSalt);
        String ctDate   = pbc.encryptWithDateIv(password, loadedPassphrase, loadedSalt, enrollDate);
        String ctFull   = pbc.encryptWithSaltIvPrefix(password, loadedPassphrase, username, enrollDate);
        System.out.println("Step 3 — Encrypted:");
        System.out.println("  encryptWithRandomIv    : " + ctRandom);
        System.out.println("  encryptWithDateIv      : " + ctDate);
        System.out.println("  encryptWithSaltIvPrefix: " + ctFull);

        // ── Step 4: decrypt ──────────────────────────────────────────────────
        String ptRandom = pbc.decryptWithRandomIv(ctRandom, loadedPassphrase, loadedSalt);
        String ptDate   = pbc.decryptWithDateIv(ctDate, loadedPassphrase, loadedSalt, enrollDate);
        String ptFull   = pbc.decryptWithSaltIvPrefix(ctFull, loadedPassphrase, username);
        System.out.println("Step 4 — Decrypted:");
        System.out.println("  decryptWithRandomIv    : " + ptRandom
                + "  [" + (password.equals(ptRandom) ? "PASS" : "FAIL") + "]");
        System.out.println("  decryptWithDateIv      : " + ptDate
                + "  [" + (password.equals(ptDate) ? "PASS" : "FAIL") + "]");
        System.out.println("  decryptWithSaltIvPrefix: " + ptFull
                + "  [" + (password.equals(ptFull) ? "PASS" : "FAIL") + "]");
    }

    // -----------------------------------------------------------------------
    // Section 9 — derivePbkdf2Key (legacy SHA1 and recommended SHA256)
    // -----------------------------------------------------------------------
    
    /**
     * Derives an AES key from a passphrase and salt using PBKDF2, then uses it
     * to encrypt and decrypt a password — confirming that derivation is deterministic
     * (same inputs always produce the same key) across both SHA-1 (legacy) and
     * SHA-256 (recommended) variants.
     *
     * <p>Exercises:
     * <ul>
     *   <li>{@link SecretKeyGenerator#derivePbkdf2KeyLegacy} — SHA1 / 1024 iter / 128-bit</li>
     *   <li>{@link SecretKeyGenerator#derivePbkdf2Key(String, String)} — SHA256 / 65536 iter / 256-bit</li>
     *   <li>{@link PasswordBasedCrypto#encryptWithDateIv} / {@code decryptWithDateIv}</li>
     * </ul>
     *
     * @param pbc {@link PasswordBasedCrypto} instance configured for legacy mode
     * @throws Exception if key derivation or cipher operations fail
     */
    static void derivePbkdf2KeyAndEncrypt(PasswordBasedCrypto pbc) throws Exception {
        String passphrase = "B&^0QUV^?^SQ.{D|]C[[(+hm'^e7|FJ}Ga-4$T54:(bgpyD,)K{fpE8~M,YMzvu";
        String salt       = "Yash@gmail.com";
 
        // Legacy (SHA1 / 1024 iter / 128-bit) — matches original CryptoService
        SecretKey legacyKey1 = SecretKeyGenerator.derivePbkdf2KeyLegacy(passphrase, salt);
        SecretKey legacyKey2 = SecretKeyGenerator.derivePbkdf2KeyLegacy(passphrase, salt);
        String legacyB64 = SecretKeyGenerator.encodeKeyToBase64(legacyKey1);
 
        System.out.println("Legacy key (SHA1/1024/128)    : " + legacyB64);
        System.out.println("  Deterministic               : "
                + (legacyB64.equals(SecretKeyGenerator.encodeKeyToBase64(legacyKey2)) ? "PASS" : "FAIL"));
 
        // Recommended (SHA256 / 65536 iter / 256-bit)
        SecretKey sha256Key1 = SecretKeyGenerator.derivePbkdf2Key(passphrase, salt);
        SecretKey sha256Key2 = SecretKeyGenerator.derivePbkdf2Key(passphrase, salt);
        String sha256B64 = SecretKeyGenerator.encodeKeyToBase64(sha256Key1);
 
        System.out.println("Recommended key (SHA256/65536/256): " + sha256B64.substring(0, 16) + "...");
        System.out.println("  Deterministic               : "
                + (sha256B64.equals(SecretKeyGenerator.encodeKeyToBase64(sha256Key2)) ? "PASS" : "FAIL"));
 
        // SHA1 and SHA256 keys must differ
        System.out.println("  SHA1 vs SHA256 differ       : "
                + (!legacyB64.equals(sha256B64) ? "PASS" : "FAIL"));
 
        // Full round-trip: derive key → encrypt → decrypt
        Date enrollDate = new SimpleDateFormat(DATE_FORMAT).parse(CREATION_DATE_STRING);
        String password = "Yash@001";
        String ct = pbc.encryptWithDateIv(password, passphrase, salt, enrollDate);
        String pt = pbc.decryptWithDateIv(ct, passphrase, salt, enrollDate);
        System.out.println("  Encrypt/decrypt with derived key: "
                + (password.equals(pt) ? "PASS" : "FAIL") + " → " + pt);
    }
    
    // -----------------------------------------------------------------------
    // Section 10 — generateAesSymmetricKey (raw KeyGenerator)
    // -----------------------------------------------------------------------
    
    /**
     * Generates AES symmetric keys at 128, 192, and 256-bit strengths using
     * {@link SecretKeyGenerator#generateAesSymmetricKey(int)}, then encodes each
     * to Base64 and reconstructs the key to confirm the round-trip is lossless.
     *
     * <p>Symmetric encryption (AES) uses the same key for both encryption and
     * decryption — fast and suitable for bulk data. The raw keys produced here
     * are independent of any passphrase; store them securely (key file, vault).
     *
     * <p>Exercises:
     * <ul>
     *   <li>{@link SecretKeyGenerator#generateAesSymmetricKey(int)} — 128 / 192 / 256-bit</li>
     *   <li>{@link SecretKeyGenerator#encodeKeyToBase64}</li>
     *   <li>{@link SecretKeyGenerator#decodeKeyFromBase64}</li>
     * </ul>
     *
     * @throws Exception if {@link javax.crypto.KeyGenerator} is unavailable
     */
    static void generateAesKeyAndRoundTrip() throws Exception {

        int[] keySizes = { 128, 192, 256 };
 
        for (int bits : keySizes) {
            SecretKey key = SecretKeyGenerator.generateAesSymmetricKey(bits);
            String b64    = SecretKeyGenerator.encodeKeyToBase64(key);
 
            System.out.println("AES-" + bits + " key");
            System.out.println("  Algorithm : " + key.getAlgorithm());
            System.out.println("  Key bytes : " + key.getEncoded().length);
            System.out.println("  Base64    : " + b64);
 
            // Encode → decode round-trip
            SecretKey restored = SecretKeyGenerator.decodeKeyFromBase64(b64);
            boolean match = b64.equals(SecretKeyGenerator.encodeKeyToBase64(restored));
            System.out.println("  Base64 round-trip: " + (match ? "PASS" : "FAIL"));
        }
 
        // Two calls must produce different keys
        SecretKey k1 = SecretKeyGenerator.generateAesSymmetricKey(256);
        SecretKey k2 = SecretKeyGenerator.generateAesSymmetricKey(256);
        System.out.println("Uniqueness (two 256-bit keys differ): "
                + (!SecretKeyGenerator.encodeKeyToBase64(k1)
                        .equals(SecretKeyGenerator.encodeKeyToBase64(k2)) ? "PASS" : "FAIL"));
    }
    
    // -----------------------------------------------------------------------
    // Section 11 — AesCbcFixedKeyCipher
    // -----------------------------------------------------------------------
    
    /**
     * Encrypts and decrypts multiple plaintext strings using {@link AesCbcFixedKeyCipher},
     * which holds a pre-shared AES key and IV as instance state.
     *
     * <p>Also confirms the safe passthrough behaviour: if {@code decryptRawString}
     * receives a value that was never encrypted it returns the original string unchanged,
     * catching {@link javax.crypto.IllegalBlockSizeException} internally.
     *
     * <p>Use this pattern for internal service-to-service calls where both sides
     * share the same fixed credentials (OAuth bodies, JWT tokens, config values).
     *
     * <p>Exercises:
     * <ul>
     *   <li>{@link AesCbcFixedKeyCipher#encryptRawString}</li>
     *   <li>{@link AesCbcFixedKeyCipher#decryptRawString} — ciphertext and plain-text inputs</li>
     * </ul>
     */
    static void encryptDecryptWithFixedKeyIv() {
        // Pre-shared fixed credentials (same as the EncryptionUtils pattern)
        AesCbcFixedKeyCipher cipher = new AesCbcFixedKeyCipher(
                "aVhYZ2ZsbFdENmh6VlNFQ3BmUHhXZz09",   // 32-char AES key
                "E1SPRygLKfztpjec");                    // 16-char IV
 
        String[] plaintexts = {
            "grant_type=client_credentials",
            "Yash@001",
            "D$Pr^0@dm!n%)"
        };
 
        for (String plain : plaintexts) {
            String encrypted = cipher.encryptRawString(plain);
            String decrypted = cipher.decryptRawString(encrypted);
            System.out.println("Plain     : " + plain);
            System.out.println("Encrypted : " + encrypted);
            System.out.println("Decrypted : " + decrypted);
            System.out.println("Match     : " + (plain.equals(decrypted) ? "PASS" : "FAIL"));
            System.out.println();
        }
 
        // Plain-text passthrough — decryptRawString returns input unchanged if not encrypted
        String alreadyPlain = "not-encrypted-value";
        System.out.println("Passthrough (plain string → decryptRawString): "
                + cipher.decryptRawString(alreadyPlain)
                + " [returns input unchanged]");
    }
    
    // -----------------------------------------------------------------------
    // Section 12 — AesCryptoManager (GCM static) + RsaCryptoManager (RSA static)
    // -----------------------------------------------------------------------
    
    /**
     * Encrypts and decrypts a string using both {@link AesCryptoManager} (AES-GCM)
     * and {@link RsaCryptoManager} (RSA), confirming each round-trip recovers the original.
     *
     * <p><strong>Symmetric vs Asymmetric:</strong>
     * <ul>
     *   <li>{@link AesCryptoManager} — symmetric; the same AES key encrypts and decrypts.
     *       The caller generates and manages the 12-byte GCM nonce.</li>
     *   <li>{@link RsaCryptoManager} — asymmetric; the public key encrypts, the private key
     *       decrypts. Solves key distribution but limited to ~245 bytes of plaintext (RSA-2048).
     *       For larger payloads use {@link HybridCipher}.</li>
     * </ul>
     *
     * <p>Exercises:
     * <ul>
     *   <li>{@link AesCryptoManager#encrypt} / {@link AesCryptoManager#decrypt}</li>
     *   <li>{@link RsaCryptoManager#encrypt} / {@link RsaCryptoManager#decrypt}</li>
     * </ul>
     *
     * @throws Exception if any cipher or key-generation operation fails
     */
    static void encryptDecryptWithGcmAndRsa() throws Exception {
        String plaintext = "Hello from static managers!";
        
        // ── AesCryptoManager: AES-GCM static encrypt/decrypt ────────────────
        System.out.println("── AesCryptoManager (AES-GCM) ──");
        SecretKey aesKey = SecretKeyGenerator.generateAesSymmetricKey(256);
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);
 
        String gcmCt = AesCryptoManager.encrypt(plaintext, aesKey, iv);
        String gcmPt = AesCryptoManager.decrypt(gcmCt, aesKey, iv);
        System.out.println("Plaintext  : " + plaintext);
        System.out.println("Encrypted  : " + gcmCt);
        System.out.println("Decrypted  : " + gcmPt);
        System.out.println("Match      : " + (plaintext.equals(gcmPt) ? "PASS" : "FAIL"));
        System.out.println();
 
        // ── RsaCryptoManager: RSA static encrypt/decrypt ─────────────────────
        System.out.println("── RsaCryptoManager (RSA — asymmetric) ──");
        // Asymmetric: public key encrypts, private key decrypts
        java.security.KeyPair rsaKeyPair = com.github.yash777.securitycrypto.key.KeyManager.generateRsaKeyPair(2048);
 
        String rsaCt = RsaCryptoManager.encrypt(plaintext, rsaKeyPair.getPublic());
        String rsaPt = RsaCryptoManager.decrypt(rsaCt, rsaKeyPair.getPrivate());
        System.out.println("Plaintext  : " + plaintext);
        System.out.println("Encrypted  : " + rsaCt.substring(0, 32) + "...");
        System.out.println("Decrypted  : " + rsaPt);
        System.out.println("Match      : " + (plaintext.equals(rsaPt) ? "PASS" : "FAIL"));
 
        // Non-determinism: RSA with PKCS1 produces different ciphertexts per call
        String rsaCt2 = RsaCryptoManager.encrypt(plaintext, rsaKeyPair.getPublic());
        System.out.println("Non-deterministic: " + (!rsaCt.equals(rsaCt2) ? "PASS" : "note: same output"));
    }
    
    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    private static void separator(String title) {
        System.out.println("\n" + "───────────────────────────────────────────────────────────");
        System.out.println("  " + title);
        System.out.println("───────────────────────────────────────────────────────────");
    }
}